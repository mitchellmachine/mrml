//! Authenticated local Unix-channel refresh regressions, not production certd evidence.
use crate::{
    GitdCertdChannelClient, GitdCertdSigningRoute, GitdIdentityValidationError, GitdTlsConfigStore,
    GitdTlsRefreshError, refresh_certd_tls_config,
};
use mrml_certificate::{
    CERTD_CHANNEL_HEADER_BYTES, CertdChannelCapability, CertdChannelOperation, CertdChannelPolicy,
    CertdChannelRequest, CertdChannelRole, CertdPeerIdentity, CertdReplayWindow,
    MAX_CERTD_CHANNEL_PAYLOAD_BYTES, PemCertificateChain, UnixCertdListener,
    decode_certd_channel_request, encode_certd_channel_request,
};
use std::{
    fs,
    os::unix::{fs::MetadataExt, net::UnixStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[test]
fn unchanged_generation_requires_current_identity_and_signer_revalidation() {
    let root = std::env::temp_dir().join(format!("mrml-gitd-refresh-proof-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::write(
        root.join("root.pem"),
        include_bytes!("../../certificate/tests/fixtures/local-acme-root.pem"),
    )
    .unwrap();
    // Scope the extra test trust root to a fresh process, avoiding global
    // environment mutation while unrelated TLS tests execute concurrently.
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tls_refresh_tests::refresh_unchanged_generation_child",
            "--ignored",
            "--nocapture",
        ])
        .env("MRML_REFRESH_TEST_ROOT", &root)
        .env("MRML_CA_BUNDLE", root.join("root.pem"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "child with process-scoped local public certificate trust root"]
fn refresh_unchanged_generation_child() {
    let root = std::path::PathBuf::from(
        std::env::var_os("MRML_REFRESH_TEST_ROOT").expect("parent fixture only"),
    );
    let success = std::env::var_os("MRML_REFRESH_SUCCESS").is_some();
    for mode in if success { 5..6 } else { 0..5 } {
        let peer = {
            let metadata = fs::metadata(&root).unwrap();
            CertdPeerIdentity {
                uid: metadata.uid(),
                gid: metadata.gid(),
            }
        };
        let socket = root.join(format!("certd-{mode}.sock"));
        let policy = CertdChannelPolicy {
            role: CertdChannelRole::Gitd,
            peer,
        };
        let listener = UnixCertdListener::bind(&socket, 0o600, policy).unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let completed = std::thread::scope(|scope| {
            let stop = stopped.clone();
            let listener_ref = &listener;
            let root = &root;
            let server = scope.spawn(move || {
                let mut seen = Vec::new();
                let mut replay = CertdReplayWindow::new();
                loop {
                    let mut session = listener_ref.accept().unwrap();
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    let capability = CertdChannelCapability::new([0x73; 32]).unwrap();
                    let mut frame =
                        vec![0; CERTD_CHANNEL_HEADER_BYTES + MAX_CERTD_CHANNEL_PAYLOAD_BYTES];
                    let length = session.read_frame(&mut frame).unwrap();
                    let request = decode_certd_channel_request(
                        &frame[..length],
                        session.observed_peer(),
                        policy,
                        &capability,
                        &mut replay,
                    )
                    .unwrap();
                    let operation = request.operation;
                    let request_id = request.request_id;
                    seen.push(operation);
                    let payload = match operation {
                        CertdChannelOperation::WaitForIdentityGeneration => {
                            let mut result = b"MRGWAS01".to_vec();
                            result.extend_from_slice(&7u64.to_be_bytes());
                            result.push(0);
                            result
                        }
                        CertdChannelOperation::GetIdentitySnapshot => match mode {
                            0 => b"malformed current snapshot".to_vec(),
                            1 => identity_payload(false),
                            4 => identity_payload_with_expiry(true, true),
                            _ => identity_payload(true),
                        },
                        CertdChannelOperation::SignTls13CertificateVerify if mode == 5 => {
                            sign_refresh_fixture(request.payload, &root)
                        }
                        CertdChannelOperation::SignTls13CertificateVerify => break, // Authenticated request reaches unavailable signer.
                        _ => panic!("unexpected refresh operation {operation:?}"),
                    };
                    let length = encode_certd_channel_request(
                        CertdChannelRequest {
                            role: CertdChannelRole::Gitd,
                            operation,
                            request_id,
                            peer,
                            payload: &payload,
                        },
                        &capability,
                        &mut frame,
                    )
                    .unwrap();
                    session.write_frame(&frame[..length]).unwrap();
                }
                seen
            });
            let client = GitdCertdChannelClient::new(
                &socket,
                CertdChannelCapability::new([0x73; 32]).unwrap(),
                peer,
                peer,
                1,
            )
            .unwrap();
            let route = GitdCertdSigningRoute::new(client, 1).unwrap();
            let payload = identity_payload(true);
            let mut publication: [u8; 32] = payload[payload.len() - 33..payload.len() - 1]
                .try_into()
                .unwrap();
            if mode == 3 {
                publication[0] ^= 1;
            }
            let (validity, config) = if mode == 5 {
                let leaf =
                    PemCertificateChain::parse(&fs::read(root.join("leaf.pem")).unwrap()).unwrap();
                let issuer =
                    PemCertificateChain::parse(&fs::read(root.join("root.pem")).unwrap()).unwrap();
                let chain = vec![
                    leaf.certificate(0).unwrap().to_vec(),
                    issuer.certificate(0).unwrap().to_vec(),
                ];
                let certificate = mrml_tls::Certificate::parse(&chain[0]).unwrap();
                let validity = (certificate.not_before(), certificate.not_after());
                let snapshot = crate::GitdIdentitySnapshot {
                    server_name: "git.example".into(),
                    identity_generation: 7,
                    leaf_spki_sha256: certificate.spki_sha256(),
                    not_before_unix_seconds: validity.0,
                    not_after_unix_seconds: validity.1,
                    certificate_chain: chain,
                    signature_schemes: vec![0x0403],
                    publication_digest: publication,
                };
                let identity = crate::validate_identity_snapshot(snapshot, None).unwrap();
                (
                    validity,
                    crate::build_certd_tls_server_config_with_route(identity, &route).unwrap(),
                )
            } else {
                (
                    (0, u64::MAX),
                    mrml_tls::TlsServerConfig::from_der_chain(&[b"retained config fixture"])
                        .unwrap(),
                )
            };
            let store = GitdTlsConfigStore::new(7, publication, validity, config).unwrap();
            store.block_new_handshakes().unwrap();
            let descriptors = fs::read_dir("/proc/self/fd").unwrap().count();
            let started = std::time::Instant::now();
            let cpu_before = refresh_cpu_ticks();
            let mut result = refresh_certd_tls_config("git.example", &route, &store, 1, false);
            if mode == 5 {
                assert_eq!(result, Ok(false));
                assert_eq!(store.snapshot().unwrap().0, 7);
                let cadence_stop = AtomicBool::new(false);
                let mut attempt_started = started;
                for _ in 0..3 {
                    crate::wait_for_certificate_poll(&cadence_stop, attempt_started);
                    attempt_started = std::time::Instant::now();
                    result = refresh_certd_tls_config("git.example", &route, &store, 1, false);
                    assert_eq!(result, Ok(false));
                }
            }
            stopped.store(true, Ordering::Release);
            let _ = UnixStream::connect(&socket); // Wake an unused accept on the old faulty early-return path.
            let seen = server.join().unwrap();
            if mode == 5 {
                assert!(started.elapsed() >= std::time::Duration::from_secs(3));
                assert_eq!(seen.len(), 12);
                for operation in [
                    CertdChannelOperation::WaitForIdentityGeneration,
                    CertdChannelOperation::GetIdentitySnapshot,
                    CertdChannelOperation::SignTls13CertificateVerify,
                ] {
                    assert_eq!(seen.iter().filter(|op| **op == operation).count(), 4);
                }
                assert_eq!(fs::read_dir("/proc/self/fd").unwrap().count(), descriptors);
                let metrics = store.refresh_metrics();
                assert_eq!(metrics.attempts, 4);
                assert_eq!(metrics.timeouts, 4);
                assert_eq!(
                    metrics.activations + metrics.channel_failures + metrics.validation_failures,
                    0
                );
                eprintln!(
                    "local authenticated mock refresh: 4 polls, 12 RPCs, elapsed_ms={}, cpu_ticks={}, retained_fd_delta=0, server joined",
                    started.elapsed().as_millis(),
                    refresh_cpu_ticks() - cpu_before
                );
                return true;
            }
            assert!(
                store.snapshot().is_err(),
                "wait success alone must not reopen blocked TLS in mode {mode}"
            );
            assert!(
                result.is_err(),
                "unchanged invalid/unusable identity must fail: mode {mode}"
            );
            assert!(seen.contains(&CertdChannelOperation::GetIdentitySnapshot));
            if mode == 2 {
                assert!(seen.contains(&CertdChannelOperation::SignTls13CertificateVerify));
                assert_eq!(
                    result,
                    Err(GitdTlsRefreshError::Identity(
                        GitdIdentityValidationError::Signing
                    ))
                );
            }
            assert_eq!(
                seen.iter()
                    .filter(|op| **op == CertdChannelOperation::WaitForIdentityGeneration)
                    .count(),
                1
            );
            assert_eq!(
                seen.iter()
                    .filter(|op| **op == CertdChannelOperation::GetIdentitySnapshot)
                    .count(),
                1
            );
            if mode != 2 {
                assert!(!seen.contains(&CertdChannelOperation::SignTls13CertificateVerify));
            }
            if mode == 3 {
                assert_eq!(result, Err(GitdTlsRefreshError::Generation));
            }
            if mode == 4 {
                assert_eq!(
                    result,
                    Err(GitdTlsRefreshError::Identity(
                        GitdIdentityValidationError::Certificate(
                            mrml_tls::CertificateError::Expired
                        )
                    ))
                );
            }
            let metrics = store.refresh_metrics();
            assert_eq!(metrics.attempts, 1);
            assert_eq!(metrics.timeouts, 0);
            assert_eq!(metrics.activations, 0);
            assert_eq!(metrics.channel_failures + metrics.validation_failures, 1);
            true
        });
        assert!(completed);
        drop(listener);
        assert!(
            !socket.exists(),
            "owned certd listener removes its socket on drop"
        );
    }
}

fn identity_payload(valid_certificate: bool) -> Vec<u8> {
    identity_payload_with_expiry(valid_certificate, false)
}
fn identity_payload_with_expiry(valid_certificate: bool, expired: bool) -> Vec<u8> {
    let generated = std::env::var_os("MRML_REFRESH_SUCCESS").map(std::path::PathBuf::from);
    let leaf_bytes = generated
        .as_ref()
        .map(|root| fs::read(root.join("leaf.pem")).unwrap())
        .unwrap_or_else(|| {
            include_bytes!("../../certificate/tests/fixtures/local-acme-leaf.pem").to_vec()
        });
    let root_bytes = generated
        .as_ref()
        .map(|root| fs::read(root.join("root.pem")).unwrap())
        .unwrap_or_else(|| {
            include_bytes!("../../certificate/tests/fixtures/local-acme-root.pem").to_vec()
        });
    let leaf = PemCertificateChain::parse(&leaf_bytes).unwrap();
    let root = PemCertificateChain::parse(&root_bytes).unwrap();
    let mut chain = if valid_certificate {
        vec![
            leaf.certificate(0).unwrap().to_vec(),
            root.certificate(0).unwrap().to_vec(),
        ]
    } else {
        vec![vec![0x30, 0]]
    };
    if expired {
        // Negative time fixture: changing these signed bytes also invalidates
        // its issuer signature. Assert specifically that expiry rejects first;
        // this is not evidence for an authenticated expired PKIX chain.
        for (old, replacement) in [
            (b"260901150802Z", b"240901150802Z"),
            (b"270901150802Z", b"250901150802Z"),
        ] {
            let offset = chain[0]
                .windows(old.len())
                .position(|bytes| bytes == old)
                .unwrap();
            chain[0][offset..offset + old.len()].copy_from_slice(replacement);
        }
    }
    let (spki, before, after) = if valid_certificate {
        let certificate = mrml_tls::Certificate::parse(&chain[0]).unwrap();
        (
            certificate.spki_sha256(),
            certificate.not_before(),
            certificate.not_after(),
        )
    } else {
        ([1; 32], 1, 2)
    };
    let name = b"git.example";
    let mut digest = mrml_crypto::Sha256::new();
    digest.update(b"MRML-GITD-TLS-IDENTITY-PUBLICATION-V1\0");
    digest.update(&(name.len() as u16).to_be_bytes());
    digest.update(name);
    digest.update(&7u64.to_be_bytes());
    digest.update(&[chain.len() as u8]);
    for certificate in &chain {
        digest.update(&(certificate.len() as u32).to_be_bytes());
        digest.update(certificate);
    }
    digest.update(&spki);
    digest.update(&before.to_be_bytes());
    digest.update(&after.to_be_bytes());
    digest.update(&[1]);
    digest.update(&0x0403u16.to_be_bytes());
    let mut output = b"MRGIDS01".to_vec();
    output.extend_from_slice(&7u64.to_be_bytes());
    output.extend_from_slice(&(name.len() as u16).to_be_bytes());
    output.extend_from_slice(name);
    output.push(chain.len() as u8);
    for certificate in &chain {
        output.extend_from_slice(&(certificate.len() as u32).to_be_bytes());
        output.extend_from_slice(certificate);
    }
    output.extend_from_slice(&spki);
    output.extend_from_slice(&before.to_be_bytes());
    output.extend_from_slice(&after.to_be_bytes());
    output.push(1);
    output.extend_from_slice(&0x0403u16.to_be_bytes());
    output.extend_from_slice(&digest.finalize());
    output.push(1);
    output
}

fn refresh_cpu_ticks() -> u64 {
    let stat = fs::read_to_string("/proc/self/stat").unwrap();
    let fields: Vec<_> = stat
        .rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
}
fn sign_refresh_fixture(request: &[u8], root: &std::path::Path) -> Vec<u8> {
    assert_eq!(request.len(), 58);
    assert_eq!(&request[..8], b"MRGSGN01");
    assert_eq!(&request[8..16], &7u64.to_be_bytes());
    assert_eq!(&request[16..18], &0x0403u16.to_be_bytes());
    let mut der = fs::read(root.join("key.der")).unwrap();
    let marker = [2, 1, 1, 4, 32];
    let offset = der
        .windows(marker.len())
        .position(|bytes| bytes == marker)
        .unwrap()
        + marker.len();
    let key = mrml_crypto::P256SecretKey::from_bytes(der[offset..offset + 32].try_into().unwrap())
        .unwrap();
    mrml_crypto::erase_secret_bytes(&mut der);
    let mut digest = mrml_crypto::Sha256::new();
    digest.update(&[0x20; 64]);
    digest.update(b"TLS 1.3, server CertificateVerify\0");
    digest.update(&request[18..50]);
    let mut signature = key.sign_digest_raw(&digest.finalize()).unwrap();
    let mut output = [0; 72];
    let signature_der = mrml_crypto::encode_der_signature(&signature, &mut output).unwrap();
    let mut response = b"MRGSGS01".to_vec();
    response.extend_from_slice(&request[8..18]);
    response.extend_from_slice(&request[50..58]);
    response.extend_from_slice(&(signature_der.len() as u16).to_be_bytes());
    response.extend_from_slice(signature_der);
    mrml_crypto::erase_secret_bytes(&mut signature);
    mrml_crypto::erase_secret_bytes(&mut output);
    response
}

#[test]
#[ignore = "explicit local OpenSSL certificate-generation oracle; authenticated mock RPC only"]
fn successful_unchanged_refresh_with_ephemeral_openssl_identity() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("mrml-refresh-success-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let openssl = |args: &[&str]| {
        let output = std::process::Command::new("openssl")
            .current_dir(&root)
            .args(args)
            .output()
            .expect("explicit oracle requires OpenSSL");
        assert!(output.status.success(), "OpenSSL fixture generation failed");
    };
    openssl(&[
        "ecparam",
        "-name",
        "prime256v1",
        "-genkey",
        "-noout",
        "-out",
        "key.pem",
    ]);
    openssl(&["ec", "-in", "key.pem", "-outform", "DER", "-out", "key.der"]);
    openssl(&[
        "req",
        "-new",
        "-x509",
        "-key",
        "key.pem",
        "-sha256",
        "-days",
        "1",
        "-subj",
        "/CN=MRML local refresh test root",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-out",
        "root.pem",
    ]);
    openssl(&[
        "req",
        "-new",
        "-key",
        "key.pem",
        "-subj",
        "/CN=git.example",
        "-out",
        "leaf.csr",
    ]);
    fs::write(root.join("extensions"), "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:git.example\n").unwrap();
    openssl(&[
        "x509",
        "-req",
        "-in",
        "leaf.csr",
        "-CA",
        "root.pem",
        "-CAkey",
        "key.pem",
        "-set_serial",
        "2",
        "-days",
        "1",
        "-sha256",
        "-extfile",
        "extensions",
        "-out",
        "leaf.pem",
    ]);
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tls_refresh_tests::refresh_unchanged_generation_child",
            "--ignored",
            "--nocapture",
        ])
        .env("MRML_REFRESH_TEST_ROOT", &root)
        .env("MRML_REFRESH_SUCCESS", &root)
        .env("MRML_CA_BUNDLE", root.join("root.pem"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed"));
    eprintln!("{}", String::from_utf8_lossy(&result.stderr));
    fs::remove_dir_all(root).unwrap();
}
