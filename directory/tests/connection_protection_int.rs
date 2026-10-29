//! What the connection limits do for a request being served and for a
//! client that stops reading: a request whose body is in and whose handler
//! is working is not pushed out by newcomers (up to two per source); a
//! source can't protect more than that; and a client that never reads its
//! response is cut off at the write timeout. In-process, with slow routes:
//! integration tier (`just test-int`), real time, loopback sources
//! 127.0.0.1 and 127.0.1.x.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use agentconnect_directory::conn::{self, Events, Limits};
use axum::Router;
use axum::body::Body;
use axum::routing::get;

const SLOW: Duration = Duration::from_secs(3);

fn limits(total: usize, per_source: usize) -> Limits {
    Limits {
        header_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(30),
        request_timeout: Duration::from_secs(30),
        write_timeout: Duration::from_secs(30),
        max_connections: total,
        max_per_source: per_source,
        shutdown_grace: Duration::from_secs(1),
    }
}

/// A server with a route that takes `SLOW` to answer and one that streams
/// 256 MiB; returns its address and how many times each event was counted.
async fn start(limits: Limits) -> (SocketAddr, Arc<[AtomicUsize; 2]>) {
    let router = Router::new()
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(SLOW).await;
                "done"
            }),
        )
        .route("/fast", get(|| async { "ok" }))
        .route(
            "/big",
            get(|| async {
                let chunk = vec![b'x'; 1 << 20];
                let stream = futures_util::stream::iter(
                    (0..256).map(move |_| Ok::<_, std::io::Error>(chunk.clone())),
                );
                Body::from_stream(stream)
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // [write_timeout events, every other event]
    let counts = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
    let seen = Arc::clone(&counts);
    let events: Events = Arc::new(move |_, outcome| {
        let slot = usize::from(outcome != "write_timeout");
        seen[slot].fetch_add(1, Ordering::Relaxed);
    });
    tokio::spawn(conn::serve(
        listener,
        router,
        limits,
        |_| false,
        events,
        std::future::pending(),
    ));
    (addr, counts)
}

/// A (blocking) connection from the loopback address `from`.
fn connect(addr: SocketAddr, from: Ipv4Addr) -> TcpStream {
    let socket = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket
                .bind(SocketAddr::V4(SocketAddrV4::new(from, 0)))
                .unwrap();
            socket.connect(addr).await.unwrap().into_std().unwrap()
        });
    socket.set_nonblocking(false).unwrap();
    socket
}

fn get_request(stream: &mut TcpStream, path: &str) {
    write!(stream, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
}

/// What the server answered, or `None` if it closed the connection first.
fn answer(stream: &mut TcpStream, within: Duration) -> Option<String> {
    stream.set_read_timeout(Some(within)).unwrap();
    let mut buf = [0_u8; 512];
    let n = stream.read(&mut buf).unwrap_or(0);
    (n > 0).then(|| String::from_utf8_lossy(&buf[..n]).into_owned())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "integration tier (just test-int): real time"]
async fn a_request_being_served_survives_sources_filling_the_directory() {
    let (addr, _) = start(limits(16, 8)).await;
    let honest = tokio::task::spawn_blocking(move || {
        let mut s = connect(addr, Ipv4Addr::new(127, 0, 0, 1));
        get_request(&mut s, "/slow");
        s
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Sixteen sources, one silent connection each: the directory is full.
    let attackers = tokio::task::spawn_blocking(move || {
        (1..=16_u8)
            .map(|i| {
                let s = connect(addr, Ipv4Addr::new(127, 0, 1, i));
                std::thread::sleep(Duration::from_millis(20));
                s
            })
            .collect::<Vec<_>>()
    })
    .await
    .unwrap();
    let (reply, pushed_out) = tokio::task::spawn_blocking(move || {
        let mut honest = honest;
        let reply = answer(&mut honest, SLOW + Duration::from_secs(3));
        let mut attackers = attackers;
        let pushed_out = attackers
            .iter_mut()
            .filter_map(|s| {
                answer(s, Duration::from_millis(100))
                    .is_none()
                    .then_some(())
            })
            .count();
        (reply, pushed_out)
    })
    .await
    .unwrap();
    let reply = reply.expect("the request being served was closed");
    assert!(
        reply.starts_with("HTTP/1.1 200") && reply.contains("done"),
        "{reply}"
    );
    assert!(pushed_out >= 1, "nothing was pushed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "integration tier (just test-int): real time"]
async fn a_source_protects_at_most_two_requests_being_served() {
    let (addr, _) = start(limits(8, 8)).await;
    // Eight slow requests in flight from one source fill the directory.
    let held = tokio::task::spawn_blocking(move || {
        (0..8)
            .map(|_| {
                let mut s = connect(addr, Ipv4Addr::new(127, 0, 0, 1));
                get_request(&mut s, "/slow");
                std::thread::sleep(Duration::from_millis(30));
                s
            })
            .collect::<Vec<_>>()
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    // A newcomer from another source is served: one of the first source's
    // unprotected requests made room.
    let fresh = tokio::task::spawn_blocking(move || {
        let mut s = connect(addr, Ipv4Addr::new(127, 0, 1, 1));
        get_request(&mut s, "/fast");
        answer(&mut s, Duration::from_secs(2))
    })
    .await
    .unwrap();
    assert!(
        fresh.is_some_and(|r| r.starts_with("HTTP/1.1 200")),
        "the newcomer was not served"
    );
    let replies = tokio::task::spawn_blocking(move || {
        let mut held = held;
        held.iter_mut()
            .map(|s| answer(s, SLOW + Duration::from_secs(3)))
            .collect::<Vec<_>>()
    })
    .await
    .unwrap();
    // The oldest was pushed out, the newest two still got their answers.
    assert!(replies[0].is_none(), "the oldest was answered");
    assert!(replies[6].as_deref().is_some_and(|r| r.contains("done")));
    assert!(replies[7].as_deref().is_some_and(|r| r.contains("done")));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "integration tier (just test-int): real time"]
async fn a_client_that_never_reads_is_cut_off_at_the_write_timeout() {
    let mut l = limits(16, 8);
    l.write_timeout = Duration::from_secs(2);
    let (addr, counts) = start(l).await;
    let stuck = tokio::task::spawn_blocking(move || {
        let mut s = connect(addr, Ipv4Addr::new(127, 0, 0, 1));
        get_request(&mut s, "/big");
        s
    })
    .await
    .unwrap();
    // The response is far larger than the socket buffers: it blocks, and is
    // cut off after the write timeout instead of holding the slot.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(counts[0].load(Ordering::Relaxed), 1, "no write timeout");
    drop(stuck);
}
