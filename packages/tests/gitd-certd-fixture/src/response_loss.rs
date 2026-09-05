//! Bounded test-only ciphertext relay for one tiny native protected push.
//! TLS remains end-to-end; this process has no CA/key/channel/token mounts.
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

fn record(stream: &mut TcpStream) -> Result<Vec<u8>, ()> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).map_err(|_| ())?;
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if length > 18432 || length == 0 || header[1] != 3 {
        return Err(());
    }
    let mut bytes = vec![0; length + 5];
    bytes[..5].copy_from_slice(&header);
    stream.read_exact(&mut bytes[5..]).map_err(|_| ())?;
    Ok(bytes)
}

fn relay(mut client: TcpStream, mut server: TcpStream, fault: bool) -> Result<(), ()> {
    for stream in [&client, &server] {
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .map_err(|_| ())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(15)))
            .map_err(|_| ())?;
    }
    let mut upstream = server.try_clone().map_err(|_| ())?;
    let mut downstream = client.try_clone().map_err(|_| ())?;
    let held = Arc::new(AtomicBool::new(false));
    let request_held = held.clone();
    let worker = std::thread::spawn(move || {
        let mut application_records = 0;
        let mut bytes = 0usize;
        while let Ok(record) = record(&mut client) {
            bytes += record.len();
            if bytes > 2 * 1024 * 1024 {
                break;
            }
            if record[0] == 23 {
                application_records += 1;
                // Exact native TLS/H2 sequence: Finished, preface/settings,
                // SETTINGS acknowledgment. Hold responses only after settings
                // negotiation; the tiny request fits the initial flow window.
                if fault && application_records == 3 {
                    request_held.store(true, Ordering::Release);
                }
            }
            if upstream.write_all(&record).is_err() {
                break;
            }
        }
        let _ = upstream.shutdown(Shutdown::Write);
    });
    let mut discarded = 0usize;
    let mut bytes = 0usize;
    while let Ok(record) = record(&mut server) {
        bytes += record.len();
        if bytes > 2 * 1024 * 1024 {
            break;
        }
        if fault && held.load(Ordering::Acquire) {
            discarded += record.len();
            // Let the real server durably finish; its receipt is never given
            // to the client. The client's exact-candidate reconciliation must
            // prove success. A premature/noncommitted operation cannot pass it.
            std::thread::sleep(Duration::from_secs(5));
            break;
        }
        if downstream.write_all(&record).is_err() {
            break;
        }
    }
    let _ = downstream.shutdown(Shutdown::Both);
    let _ = server.shutdown(Shutdown::Both);
    worker.join().map_err(|_| ())?;
    if fault && discarded == 0 {
        return Err(());
    }
    if fault {
        println!("response transport dropped encrypted_bytes={discarded}");
    }
    Ok(())
}

pub(super) fn run(args: &[String]) -> Result<(), ()> {
    let [_, listen, upstream] = args else {
        return Err(());
    };
    if listen != "0.0.0.0:8443" || upstream != "gitd:8443" {
        return Err(());
    }
    let listener = TcpListener::bind(listen).map_err(|_| ())?;
    listener.set_nonblocking(true).map_err(|_| ())?;
    let deadline = Instant::now() + Duration::from_secs(180);
    println!("bounded response-loss proxy ready");
    std::io::stdout().flush().map_err(|_| ())?;
    // Native push: upload discovery, refs, two receive discoveries, receive
    // POST, then automatic candidate-status lookup after the dropped reply.
    for connection in 1..=6 {
        let client = loop {
            if Instant::now() >= deadline {
                return Err(());
            }
            match listener.accept() {
                Ok((client, _)) => break client,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Err(_) => return Err(()),
            }
        };
        let server = TcpStream::connect(upstream).map_err(|_| ())?;
        relay(client, server, connection == 5)?;
        println!("completed relay connection={connection}");
    }
    Ok(())
}
