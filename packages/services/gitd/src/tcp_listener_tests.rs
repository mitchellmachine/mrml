//! Local real listener/worker tests with an empty backend and private auth policy.
//! This is not catalog admission, repository operations, or deployment evidence.
use crate::{GitdHttp2WorkerPool, GitdTlsConfigStore, TcpAdmissionController, TcpAdmissionLimits};
use std::{
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

fn limits() -> TcpAdmissionLimits {
    TcpAdmissionLimits {
        maximum_sources: 8,
        maximum_connections: 4,
        maximum_connections_per_source: 3,
        maximum_handshakes: 2,
        rate_capacity: 32,
        rate_refill_per_second: 32,
        source_retention_seconds: 10,
        maximum_queue_millis: 100,
    }
}
fn wait_until(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "bounded worker wait expired");
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn slow_listener_queue_expires_and_all_permits_return() {
    let listener = mrml_runtime::TcpListener::bind([127, 0, 0, 1], 0).unwrap();
    let port = listener.local_port().unwrap();
    let admission = TcpAdmissionController::new(limits()).unwrap();
    let service = crate::composition::empty_private_listener_test_service();
    let tls = Arc::new(
        GitdTlsConfigStore::new(
            1,
            [1; 32],
            (0, u64::MAX),
            mrml_tls::TlsServerConfig::from_der_chain(&[b"slow handshake sentinel"]).unwrap(),
        )
        .unwrap(),
    );
    let pool = GitdHttp2WorkerPool::new(&service, tls, 1, 1, 4, 1024 * 1024, 65536, 1000).unwrap();
    let first =
        std::net::TcpStream::connect(std::net::SocketAddr::from(([127, 0, 0, 1], port))).unwrap();
    pool.submit(admission.admit(listener.accept().unwrap()).unwrap())
        .unwrap();
    wait_until(|| admission.metrics().unwrap().active_handshakes == 1);
    let second =
        std::net::TcpStream::connect(std::net::SocketAddr::from(([127, 0, 0, 1], port))).unwrap();
    pool.submit(admission.admit(listener.accept().unwrap()).unwrap())
        .unwrap();
    let third =
        std::net::TcpStream::connect(std::net::SocketAddr::from(([127, 0, 0, 1], port))).unwrap();
    let queued = admission.admit(listener.accept().unwrap()).unwrap();
    let fourth =
        std::net::TcpStream::connect(std::net::SocketAddr::from(([127, 0, 0, 1], port))).unwrap();
    assert!(admission.admit(listener.accept().unwrap()).is_err());
    let started = Instant::now();
    pool.submit(queued).unwrap(); // Existing bounded channel applies backpressure.
    assert!(started.elapsed() >= Duration::from_millis(100));
    wait_until(|| admission.metrics().unwrap().active_connections == 0);
    let workers = pool.shutdown().unwrap();
    let metrics = admission.metrics().unwrap();
    assert_eq!(workers.accepted, 3);
    assert_eq!(workers.tls_failures, 1);
    assert_eq!(metrics.expired_queued, 2);
    assert_eq!(metrics.rejected_source_connections, 1);
    assert_eq!(metrics.active_handshakes, 0);
    assert_eq!(metrics.permit_release_errors, 0);
    drop((first, second, third, fourth));
}

struct OracleSigner(mrml_crypto::P256SecretKey);
impl mrml_tls::TlsServerSigningKey for OracleSigner {
    fn signature_scheme(&self) -> u16 {
        0x0403
    }
    fn sign_certificate_verify_transcript(
        &self,
        transcript: &[u8; 32],
        output: &mut [u8; mrml_tls::MAX_TLS13_SIGNATURE_BYTES],
    ) -> Result<usize, mrml_tls::TlsError> {
        let mut digest = mrml_crypto::Sha256::new();
        digest.update(&[0x20; 64]);
        digest.update(b"TLS 1.3, server CertificateVerify\0");
        digest.update(transcript);
        let mut raw = self
            .0
            .sign_digest_raw(&digest.finalize())
            .map_err(|_| mrml_tls::TlsError::AuthenticationFailed)?;
        let result = mrml_crypto::encode_der_signature(&raw, output)
            .map(|bytes| bytes.len())
            .map_err(|_| mrml_tls::TlsError::AuthenticationFailed);
        mrml_crypto::erase_secret_bytes(&mut raw);
        result
    }
}
const H2_CLIENT: &str = r#"
import os,socket,ssl,sys
import h2.connection,h2.events
port=int(sys.argv[1]); source=sys.argv[2]; count=int(sys.argv[3])
context=ssl.create_default_context(cafile=os.environ['MRML_CA_BUNDLE']);context.set_alpn_protocols(['h2'])
for i in range(count):
 sock=socket.socket();sock.settimeout(5);sock.bind((source,0));sock.connect(('127.0.0.1',port))
 with context.wrap_socket(sock,server_hostname='localhost') as stream:
  c=h2.connection.H2Connection();c.initiate_connection();stream.sendall(c.data_to_send())
  sid=c.get_next_available_stream_id();c.send_headers(sid,[(':method','GET'),(':scheme','https'),(':authority','localhost'),(':path','/owner/private.git/info/refs?service=git-upload-pack'),('git-protocol','version=2'),('authorization','Bearer invalid')],end_stream=True);stream.sendall(c.data_to_send())
  ended=False
  while not ended:
   data=stream.recv(65536)
   if not data: raise RuntimeError('closed before response')
   for event in c.receive_data(data):
    if isinstance(event,h2.events.ResponseReceived):
     for name,value in event.headers:
      if name==b':status': print(value.decode(),flush=True)
    if isinstance(event,h2.events.StreamEnded) and event.stream_id==sid: ended=True

"#;
#[test]
#[ignore = "explicit pinned Python h2/OpenSSL local TLS oracle with environment-selected test certificates"]
fn real_listener_two_ipv4_sources_repeated_invalid_credentials() {
    let fd_before = std::fs::read_dir("/proc/self/fd").unwrap().count();
    {
        let leaf = mrml_certificate::PemCertificateChain::parse(
            &std::fs::read(std::env::var_os("MRML_HTTP2_HOSTILE_CERT").unwrap()).unwrap(),
        )
        .unwrap();
        let issuer = mrml_certificate::PemCertificateChain::parse(
            &std::fs::read(std::env::var_os("MRML_HTTP2_HOSTILE_ISSUER").unwrap()).unwrap(),
        )
        .unwrap();
        let mut key = Command::new("openssl")
            .args(["ec", "-in"])
            .arg(std::env::var_os("MRML_HTTP2_HOSTILE_KEY").unwrap())
            .args(["-outform", "DER"])
            .output()
            .unwrap();
        assert!(key.status.success());
        let marker = [2, 1, 1, 4, 32];
        let offset = key
            .stdout
            .windows(5)
            .position(|bytes| bytes == marker)
            .unwrap()
            + 5;
        let signer = OracleSigner(
            mrml_crypto::P256SecretKey::from_bytes(
                key.stdout[offset..offset + 32].try_into().unwrap(),
            )
            .unwrap(),
        );
        mrml_crypto::erase_secret_bytes(&mut key.stdout);
        let config = mrml_tls::TlsServerConfig::from_der_chain(&[
            leaf.certificate(0).unwrap(),
            issuer.certificate(0).unwrap(),
        ])
        .unwrap()
        .require_server_name("localhost")
        .unwrap()
        .with_signing_key(signer)
        .with_protocols(&["h2"])
        .unwrap();
        let tls = Arc::new(GitdTlsConfigStore::new(1, [1; 32], (0, u64::MAX), config).unwrap());
        let listener = mrml_runtime::TcpListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        let admission = TcpAdmissionController::new(limits()).unwrap();
        let service = crate::composition::empty_private_listener_test_service();
        let pool =
            GitdHttp2WorkerPool::new(&service, tls, 2, 2, 4, 1024 * 1024, 65536, 5000).unwrap();
        let python = std::env::var_os("MRML_H2_ORACLE_PYTHON").unwrap();
        let mut children = Vec::new();
        for source in ["127.0.0.1", "127.0.0.2"] {
            children.push(
                Command::new(&python)
                    .args(["-c", H2_CLIENT, &port.to_string(), source, "12"])
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
        }
        let mut source_connections = [0; 2];
        for _ in 0..24 {
            let (done, waited) = std::sync::mpsc::channel();
            let watchdog = std::thread::spawn(move || {
                if waited.recv_timeout(Duration::from_secs(5)).is_err() {
                    let _ = std::net::TcpStream::connect(std::net::SocketAddr::from((
                        [127, 0, 0, 1],
                        port,
                    )));
                    true
                } else {
                    false
                }
            });
            let accepted = listener.accept().unwrap();
            match accepted.peer_address().unwrap().ip {
                [127, 0, 0, 1] => source_connections[0] += 1,
                [127, 0, 0, 2] => source_connections[1] += 1,
                other => panic!("unexpected observed source {other:?}"),
            }
            let _ = done.send(());
            assert!(
                !watchdog.join().unwrap(),
                "client failed to connect before deadline"
            );
            pool.submit(admission.admit(accepted).unwrap()).unwrap();
        }
        assert_eq!(source_connections, [12, 12]);
        for child in children {
            let result = child.wait_with_output().unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let output = String::from_utf8(result.stdout).unwrap();
            let statuses: Vec<u16> = output.lines().map(|line| line.parse().unwrap()).collect();
            assert_eq!(statuses.len(), 12);
            assert!(statuses.iter().all(|status| *status == 404), "{statuses:?}");
        }
        wait_until(|| admission.metrics().unwrap().active_connections == 0);
        let metrics = pool.shutdown().unwrap();
        assert_eq!(metrics.accepted, 24);
        assert_eq!(metrics.tls_failures, 0);
        assert_eq!(metrics.protocol_failures, 0);
        let permits = admission.metrics().unwrap();
        assert_eq!(permits.admitted, 24);
        assert_eq!(permits.active_handshakes, 0);
        assert_eq!(permits.permit_release_errors, 0);
        let operation_limits = service.operation_limits();
        for operation in [
            operation_limits.upload_metrics(),
            operation_limits.receive_metrics(),
        ] {
            assert_eq!(operation.current_usage, 0);
            assert_eq!(operation.permit_leak_assertion_failures, 0);
        }
        eprintln!(
            "local runtime listener: two IPv4 sources, 24 private credential denials, connection/handshake permits returned"
        );
    }
    assert_eq!(
        std::fs::read_dir("/proc/self/fd").unwrap().count(),
        fd_before
    );
}
