//! The `healthcheck` subcommand of the relay and the directory: one plain
//! `GET /healthz` to the server's own listener, for container health checks
//! in images that have no shell, `curl` or `wget`.

use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::Duration;

/// How long the probe waits to connect, and for each read and write.
pub const TIMEOUT: Duration = Duration::from_secs(3);

/// The most of the answer the probe reads.
const MAX_ANSWER: u64 = 64 * 1024;

/// Where a probe on this host reaches a server listening on `addr`: an
/// unspecified address (`0.0.0.0`, `[::]`) is reached on its loopback.
#[must_use]
pub fn target(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), addr.port())
        }
        _ => addr,
    }
}

/// `GET /healthz` on the server listening on `addr`.
///
/// # Errors
///
/// A one-line reason when the server can't be reached, or doesn't answer
/// `200` with `"status":"ok"`.
pub fn probe(addr: SocketAddr, timeout: Duration) -> Result<(), String> {
    let to = target(addr);
    let mut stream = TcpStream::connect_timeout(&to, timeout)
        .map_err(|e| format!("cannot connect to {to}: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|e| format!("cannot set a timeout: {e}"))?;
    let request = format!(
        "GET /healthz HTTP/1.1\r\nhost: {to}\r\naccept: application/json\r\nconnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("cannot send the request to {to}: {e}"))?;
    let mut answer = Vec::new();
    stream
        .take(MAX_ANSWER)
        .read_to_end(&mut answer)
        .map_err(|e| format!("no answer from {to}: {e}"))?;
    let text = String::from_utf8_lossy(&answer);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| format!("{to} didn't answer HTTP"))?;
    let status = head
        .lines()
        .next()
        .filter(|line| line.starts_with("HTTP/1."))
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| format!("{to} didn't answer HTTP"))?;
    if status != "200" {
        return Err(format!("/healthz on {to} answered {status}"));
    }
    if !body.contains(r#""status":"ok""#) {
        return Err(format!("/healthz on {to} didn't say ok"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead as _, BufReader, ErrorKind};
    use std::net::TcpListener;
    use std::thread::JoinHandle;
    use std::time::Instant;

    use super::*;

    /// The first connection to `listener`. When none comes it panics, which
    /// `join` turns into a failed test: a probe that never connects must fail
    /// its test, not hang it until a mutation run's timeout.
    fn accept_soon(listener: &TcpListener) -> TcpStream {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((conn, _)) => {
                    conn.set_nonblocking(false).unwrap();
                    return conn;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("the probe never connected: {e}"),
            }
        }
    }

    /// A server that takes one request and sends `answer`; the request line
    /// it got is what the thread returns. The probe may stop reading before
    /// the end of a long answer, so a failed write is not an error here.
    fn server(answer: impl AsRef<[u8]> + Send + 'static) -> (SocketAddr, JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let conn = accept_soon(&listener);
            let mut reader = BufReader::new(conn);
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() > 2 {
                line.clear();
            }
            let _ = reader.get_mut().write_all(answer.as_ref());
            request_line
        });
        (addr, thread)
    }

    const OK: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
        content-length: 30\r\n\r\n{\"status\":\"ok\",\"protocol\":\"0\"}";

    #[test]
    fn a_healthy_server_passes() {
        let (addr, thread) = server(OK);
        assert_eq!(probe(addr, TIMEOUT), Ok(()));
        assert_eq!(thread.join().unwrap(), "GET /healthz HTTP/1.1\r\n");
    }

    /// A `200` answer in which `"status":"ok"` comes after `pad` bytes of
    /// other JSON.
    fn padded(pad: usize) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n\
             {{\"note\":\"{}\",\"status\":\"ok\"}}",
            "x".repeat(pad)
        )
        .into_bytes()
    }

    #[test]
    fn an_answer_longer_than_a_kilobyte_is_read_to_its_ok() {
        for pad in [2_000, 4_096, 30_000] {
            let (addr, thread) = server(padded(pad));
            assert_eq!(probe(addr, TIMEOUT), Ok(()), "{pad} bytes of padding");
            thread.join().unwrap();
        }
    }

    #[test]
    fn the_answer_is_read_up_to_its_cap_and_no_further() {
        let cap = usize::try_from(MAX_ANSWER).unwrap();
        // The ok ends just inside the cap, and just outside it.
        let (addr, thread) = server(padded(cap - 200));
        assert_eq!(probe(addr, TIMEOUT), Ok(()));
        thread.join().unwrap();
        let (addr, thread) = server(padded(cap + 100));
        let err = probe(addr, TIMEOUT).unwrap_err();
        assert!(err.contains("didn't say ok"), "{err}");
        thread.join().unwrap();
    }

    #[test]
    fn anything_but_ok_fails() {
        for (answer, reason) in [
            (
                &b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n"[..],
                "answered 503",
            ),
            (
                b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}",
                "didn't say ok",
            ),
            (b"SSH-2.0-OpenSSH\r\n\r\n", "didn't answer HTTP"),
            (b"", "didn't answer HTTP"),
        ] {
            let (addr, thread) = server(answer);
            let err = probe(addr, TIMEOUT).unwrap_err();
            assert!(err.contains(reason), "{err}");
            thread.join().unwrap();
        }
    }

    #[test]
    fn nothing_listening_fails() {
        let addr = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap(); // the listener is closed again
        let err = probe(addr, TIMEOUT).unwrap_err();
        assert!(err.starts_with("cannot connect to 127.0.0.1:"), "{err}");
    }

    #[test]
    fn an_unspecified_address_is_reached_on_loopback() {
        let any4: SocketAddr = "0.0.0.0:9091".parse().unwrap();
        let any6: SocketAddr = "[::]:9091".parse().unwrap();
        let set: SocketAddr = "192.0.2.7:9091".parse().unwrap();
        let set6: SocketAddr = "[2001:db8::7]:9091".parse().unwrap();
        assert_eq!(target(any4), "127.0.0.1:9091".parse().unwrap());
        assert_eq!(target(any6), "[::1]:9091".parse().unwrap());
        assert_eq!(target(set), set);
        assert_eq!(target(set6), set6, "a set IPv6 address is probed as it is");
    }
}
