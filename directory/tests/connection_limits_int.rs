//! A client that sends part of a request head and stops, or opens more
//! connections than its share, can't hold the directory's descriptors: the
//! head has to arrive within `AC_DIRECTORY_HEADER_TIMEOUT_SECS`, a source
//! holds at most `AC_DIRECTORY_MAX_CONNECTIONS_PER_SOURCE` connections, and
//! at `AC_DIRECTORY_MAX_CONNECTIONS` a newcomer closes the oldest connection
//! of the source holding the most. Integration tier (`just test-int`): a
//! real process, real time, and loopback sources 127.0.0.1 and 127.0.0.2.

mod common;

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use agentconnect_core::encoding::b64;
use agentconnect_core::listing::DirectoryKey;
use common::{HOST, RELAY, rng};

/// The directory on the in-memory store, with `env` on top, once it
/// listens; and its address.
struct Directory {
    child: Child,
    addr: SocketAddr,
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(env: &[(&str, &str)]) -> Directory {
    let key = DirectoryKey::generate(&rng()).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_agentconnect-directory"));
    cmd.env("AC_DIRECTORY_ADDR", "127.0.0.1:0")
        .env("AC_DIRECTORY_HOST", HOST)
        .env("AC_DIRECTORY_RELAYS", RELAY)
        .env("AC_DIRECTORY_DB", "memory:")
        .env("AC_DIRECTORY_TOKEN_KEYS", b64(&key.public_key()))
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let addr = loop {
        let line = lines
            .next()
            .expect("directory exited before listening")
            .unwrap();
        if line.contains("directory listening") {
            let at = line.find("127.0.0.1:").expect("an address in the line");
            let text: String = line[at..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ':')
                .collect();
            break text.parse().unwrap();
        }
    };
    // Keep draining stdout so the directory never blocks on it.
    std::thread::spawn(move || for _ in lines {});
    Directory { child, addr }
}

/// A (blocking) connection from the loopback address `from`.
fn connect(dir: &Directory, from: Ipv4Addr) -> TcpStream {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket
                .bind(SocketAddr::V4(SocketAddrV4::new(from, 0)))
                .unwrap();
            let stream = socket.connect(dir.addr).await.unwrap();
            let stream = stream.into_std().unwrap();
            stream.set_nonblocking(false).unwrap();
            stream
        })
}

const A: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const B: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

/// The start of a request that never ends.
fn partial_head(stream: &mut TcpStream) {
    stream.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").unwrap();
}

/// Whether the directory closed `stream` within `within`: a read that ends
/// (EOF, a reset, or an error status followed by EOF) rather than waiting.
fn closed_within(stream: &mut TcpStream, within: Duration) -> bool {
    stream.set_read_timeout(Some(within)).unwrap();
    let mut buf = [0_u8; 512];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => return true,
            Ok(_) => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return false;
            }
            Err(_) => return true,
        }
    }
}

/// A full `GET /healthz` on a new connection from `from` gets an answer.
fn answers(dir: &Directory, from: Ipv4Addr) -> bool {
    let mut stream = connect(dir, from);
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut answer = String::new();
    let _ = BufReader::new(&stream).read_line(&mut answer);
    answer.starts_with("HTTP/1.1 200")
}

#[test]
#[ignore = "integration tier (just test-int): real process and time"]
fn a_partial_request_head_is_cut_off_after_the_header_timeout() {
    let dir = start(&[("AC_DIRECTORY_HEADER_TIMEOUT_SECS", "1")]);
    let mut held = connect(&dir, A);
    partial_head(&mut held);
    // Still open shortly before the timeout, closed shortly after it.
    assert!(!closed_within(&mut held, Duration::from_millis(400)));
    assert!(closed_within(&mut held, Duration::from_secs(4)));
    // A complete request is not affected.
    assert!(answers(&dir, A));
}

/// The 502s of a proxy that keeps upstream connections alive for longer than
/// the header timeout: an idle connection after a whole request is held to
/// the idle timeout, not the header timeout, which covers a request head only.
#[test]
#[ignore = "integration tier (just test-int): real process and time"]
fn an_idle_keep_alive_connection_outlives_the_header_timeout() {
    let dir = start(&[
        ("AC_DIRECTORY_HEADER_TIMEOUT_SECS", "1"),
        ("AC_DIRECTORY_IDLE_TIMEOUT_SECS", "4"),
    ]);
    let mut s = connect(&dir, A);
    s.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut answer = String::new();
    BufReader::new(&s).read_line(&mut answer).unwrap();
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    // Open after twice the header timeout, closed after the idle timeout.
    assert!(!closed_within(&mut s, Duration::from_millis(2200)));
    assert!(closed_within(&mut s, Duration::from_secs(5)));
}

#[test]
#[ignore = "integration tier (just test-int): real process and time"]
fn a_head_dripped_a_byte_at_a_time_is_cut_off_at_the_header_timeout() {
    let dir = start(&[("AC_DIRECTORY_HEADER_TIMEOUT_SECS", "2")]);
    let mut s = connect(&dir, A);
    let head = b"GET /healthz HTTP/1.1\r\nHost: x\r\nX-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n";
    let started = std::time::Instant::now();
    let mut cut_off = false;
    for b in head {
        if s.write_all(&[*b]).is_err() {
            cut_off = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
        if started.elapsed() > Duration::from_secs(8) {
            break;
        }
    }
    assert!(cut_off || closed_within(&mut s, Duration::from_millis(500)));
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "{:?}",
        started.elapsed()
    );
}

/// A whole head, then a body that never finishes: the request deadline
/// answers 408 and closes.
#[test]
#[ignore = "integration tier (just test-int): real process and time"]
fn a_body_dripped_past_the_request_timeout_is_answered_408() {
    let dir = start(&[
        ("AC_DIRECTORY_HEADER_TIMEOUT_SECS", "1"),
        ("AC_DIRECTORY_REQUEST_TIMEOUT_SECS", "2"),
    ]);
    let mut s = connect(&dir, A);
    s.write_all(
        b"POST /v0/listings HTTP/1.1\r\nHost: x\r\ncontent-type: application/json\r\ncontent-length: 400\r\n\r\n",
    )
    .unwrap();
    let started = std::time::Instant::now();
    s.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut got = Vec::new();
    let mut buf = [0_u8; 1024];
    while started.elapsed() < Duration::from_secs(8) {
        let _ = s.write_all(b" ");
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => break,
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    let text = String::from_utf8_lossy(&got);
    assert!(text.starts_with("HTTP/1.1 408"), "{text}");
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "{:?}",
        started.elapsed()
    );
}

/// Slow uploads are client-paced, so they don't shield their connections
/// from eviction: two sources holding eight each can't lock everybody else
/// out of a directory of 16.
#[test]
#[ignore = "integration tier (just test-int): real process and time"]
fn slow_uploads_from_a_few_sources_do_not_lock_everyone_out() {
    let dir = start(&[
        ("AC_DIRECTORY_MAX_CONNECTIONS", "16"),
        ("AC_DIRECTORY_MAX_CONNECTIONS_PER_SOURCE", "8"),
        ("AC_DIRECTORY_HEADER_TIMEOUT_SECS", "30"),
        ("AC_DIRECTORY_REQUEST_TIMEOUT_SECS", "30"),
    ]);
    let mut held = Vec::new();
    for source in 1..=2_u8 {
        for _ in 0..8 {
            let mut s = connect(&dir, Ipv4Addr::new(127, 0, 1, source));
            s.write_all(
                b"POST /v0/listings HTTP/1.1\r\nHost: x\r\ncontent-type: application/json\r\ncontent-length: 400\r\n\r\n{",
            )
            .unwrap();
            held.push(s);
        }
    }
    std::thread::sleep(Duration::from_millis(500));
    // Honest newcomers from five other sources are all answered.
    for i in 1..=5_u8 {
        assert!(
            answers(&dir, Ipv4Addr::new(127, 0, 2, i)),
            "newcomer {i} was not answered"
        );
    }
}

#[test]
#[ignore = "integration tier (just test-int): real process and time"]
fn a_source_past_its_cap_is_refused_while_another_source_still_connects() {
    let dir = start(&[
        ("AC_DIRECTORY_MAX_CONNECTIONS_PER_SOURCE", "2"),
        ("AC_DIRECTORY_HEADER_TIMEOUT_SECS", "60"),
    ]);
    let mut first = connect(&dir, A);
    partial_head(&mut first);
    let mut second = connect(&dir, A);
    partial_head(&mut second);
    // The third from the same source is closed at once; the first two stay.
    let mut third = connect(&dir, A);
    assert!(closed_within(&mut third, Duration::from_secs(3)));
    assert!(!closed_within(&mut first, Duration::from_millis(300)));
    assert!(!closed_within(&mut second, Duration::from_millis(300)));
    // Another source is not affected by the first one's connections.
    assert!(answers(&dir, B));
    // A slot that comes back is usable again.
    drop(first);
    std::thread::sleep(Duration::from_millis(300));
    assert!(answers(&dir, A));
}

#[test]
#[ignore = "integration tier (just test-int): real process and time"]
fn at_the_total_cap_a_newcomer_pushes_out_the_source_holding_the_most() {
    let dir = start(&[
        ("AC_DIRECTORY_MAX_CONNECTIONS", "3"),
        ("AC_DIRECTORY_MAX_CONNECTIONS_PER_SOURCE", "3"),
        ("AC_DIRECTORY_HEADER_TIMEOUT_SECS", "60"),
    ]);
    let mut held: Vec<TcpStream> = (0..3)
        .map(|_| {
            let mut s = connect(&dir, A);
            partial_head(&mut s);
            s
        })
        .collect();
    // The directory is full of one source's stalled connections; another
    // source's request is answered, and the oldest of the first is closed.
    assert!(answers(&dir, B));
    assert!(closed_within(&mut held[0], Duration::from_secs(3)));
    assert!(!closed_within(&mut held[1], Duration::from_millis(300)));
    assert!(!closed_within(&mut held[2], Duration::from_millis(300)));
}

#[test]
#[ignore = "integration tier (just test-int): real process and time"]
fn connections_from_a_trusted_proxy_have_no_per_source_cap() {
    let dir = start(&[
        ("AC_DIRECTORY_MAX_CONNECTIONS_PER_SOURCE", "1"),
        ("AC_DIRECTORY_CLIENT_IP_HEADER", "X-Forwarded-For"),
        ("AC_DIRECTORY_TRUSTED_PROXIES", "127.0.0.1/32"),
        ("AC_DIRECTORY_HEADER_TIMEOUT_SECS", "60"),
    ]);
    // Before its headers a proxy's connection can't be told from its other
    // clients': only the total applies to it.
    let mut held: Vec<TcpStream> = (0..3)
        .map(|_| {
            let mut s = connect(&dir, A);
            partial_head(&mut s);
            s
        })
        .collect();
    for s in &mut held {
        assert!(!closed_within(s, Duration::from_millis(300)));
    }
    // A source that is not the proxy keeps its cap of one.
    let mut b1 = connect(&dir, B);
    partial_head(&mut b1);
    let mut b2 = connect(&dir, B);
    assert!(closed_within(&mut b2, Duration::from_secs(3)));
}
