//! Test-only public CSR/chain enrollment through the real certd ACME channel.
//! No fixture server or private TLS key is used by these commands.
use mrml_certificate::{
    CERTD_ACTIVATION_REQUEST_BYTES, CERTD_CHANNEL_HEADER_BYTES, CERTD_TLS_KEY_RESPONSE_BYTES,
    CertdActivationRequest, CertdCandidateRequest, CertdChannelCapability, CertdChannelOperation,
    CertdChannelPolicy, CertdChannelRequest, CertdChannelRole, CertdConfig, CertdDirectoryClass,
    CertdPeerIdentity, CertdReplayWindow, CertdTlsKeyRequest, MAX_CERTD_CHANNEL_PAYLOAD_BYTES,
    MAX_CERTD_CONFIG_BYTES, MAX_CERTIFICATE_CHAIN_BYTES, MAX_CSR_BYTES, PemCertificateChain,
    UnixCertdSession, decode_certd_channel_request, encode_certd_candidate_request,
    encode_certd_channel_request, encode_certd_tls_key_request, parse_certd_config,
};
use mrml_crypto::{Sha256, erase_secret_bytes};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path};

const CLIENT: CertdPeerIdentity = CertdPeerIdentity {
    uid: 21004,
    gid: 21004,
};
const SERVER: CertdPeerIdentity = CertdPeerIdentity {
    uid: 21003,
    gid: 21003,
};

pub(super) fn run(args: &[String]) -> Result<(), ()> {
    // Explicit request IDs must advance across all clients of this same role.
    let [
        command,
        socket,
        capability_path,
        owner,
        config_path,
        first,
        rest @ ..,
    ] = args
    else {
        return Err(());
    };
    if number(owner)? != u64::from(CLIENT.uid) {
        return Err(());
    }
    let first = number(first)?;
    let second = first.checked_add(1).ok_or(())?;
    let next = second.checked_add(1).ok_or(())?;
    let config_bytes = read_public(Path::new(config_path), MAX_CERTD_CONFIG_BYTES)?;
    let config =
        parse_certd_config(std::str::from_utf8(&config_bytes).map_err(|_| ())?).map_err(|_| ())?;
    if config.directory_class != CertdDirectoryClass::LocalTest {
        return Err(());
    }
    let mut key = super::read_capability(Path::new(capability_path), CLIENT.uid)?;
    let capability = CertdChannelCapability::new(key);
    erase_secret_bytes(&mut key);
    let capability = capability.map_err(|_| ())?;
    match (command.as_str(), rest) {
        ("enroll-csr", [output]) => {
            let payload = encode_certd_tls_key_request(CertdTlsKeyRequest {
                identity: config.identity,
                key_generation: config.key_generation,
                policy_generation: config.policy_generation,
                identifier_set_digest: config.identifier_set_digest,
            })
            .map_err(|_| ())?;
            let public = call(
                socket,
                &capability,
                first,
                CertdChannelOperation::CreateTlsKeyGeneration,
                &payload,
            )?;
            eprintln!("enrollment key response received");
            if public.len() != CERTD_TLS_KEY_RESPONSE_BYTES || public.iter().all(|b| *b == 0) {
                return Err(());
            }
            let csr = call(
                socket,
                &capability,
                second,
                CertdChannelOperation::CreateCertificateSigningRequest,
                &payload,
            )?;
            if csr.len() < 4 || csr.len() > MAX_CSR_BYTES || csr[0] != 0x30 {
                return Err(());
            }
            eprintln!("enrollment CSR response received");
            write_public_new(Path::new(output), &csr)?;
            println!("real-certd CSR exported next_request_id={next}");
        }
        ("enroll-activate", [generation, order_digest, chain]) => {
            let chain = PemCertificateChain::parse(&read_public(
                Path::new(chain),
                MAX_CERTIFICATE_CHAIN_BYTES,
            )?)
            .map_err(|_| ())?;
            let request = candidate(config, number(generation)?, digest(order_digest)?, chain);
            let chain_digest = request.chain.chain_digest();
            let mut payload = [0; MAX_CERTD_CHANNEL_PAYLOAD_BYTES];
            let length = encode_certd_candidate_request(&request, &mut payload).map_err(|_| ())?;
            let response = call(
                socket,
                &capability,
                first,
                CertdChannelOperation::StageCertificateCandidate,
                &payload[..length],
            )?;
            if response.as_slice() != chain_digest {
                return Err(());
            }
            let activation = CertdActivationRequest {
                identity: request.identity,
                directory_generation: request.directory_generation,
                account_generation: request.account_generation,
                key_generation: request.key_generation,
                identity_generation: request.identity_generation,
                policy_generation: request.policy_generation,
                chain_digest,
                request_digest: Sha256::digest(&payload[..length]),
            };
            let mut encoded = [0; CERTD_ACTIVATION_REQUEST_BYTES];
            let length = activation.encode(&mut encoded).map_err(|_| ())?;
            let response = call(
                socket,
                &capability,
                second,
                CertdChannelOperation::ActivateCertificateGeneration,
                &encoded[..length],
            )?;
            if response.as_slice() != chain_digest {
                return Err(());
            }
            println!(
                "real-certd activated identity_generation={} next_request_id={next}",
                request.identity_generation
            );
        }
        _ => return Err(()),
    }
    Ok(())
}

fn candidate(
    config: CertdConfig,
    generation: u64,
    order_url_digest: [u8; 32],
    chain: PemCertificateChain,
) -> CertdCandidateRequest {
    CertdCandidateRequest {
        identity: config.identity,
        directory_generation: config.directory_generation,
        account_generation: config.account_generation,
        key_generation: config.key_generation,
        identity_generation: generation,
        policy_generation: config.policy_generation,
        order_url_digest,
        profile: config.certificate_profile,
        chain,
    }
}

fn call(
    socket: &str,
    capability: &CertdChannelCapability,
    request_id: u64,
    operation: CertdChannelOperation,
    payload: &[u8],
) -> Result<Vec<u8>, ()> {
    let mut session = UnixCertdSession::connect(Path::new(socket)).map_err(|error| {
        eprintln!("enrollment connect failed: {error:?}");
    })?;
    if session.observed_peer() != SERVER {
        eprintln!("enrollment server peer mismatch");
        return Err(());
    }
    let mut frame = [0; CERTD_CHANNEL_HEADER_BYTES + MAX_CERTD_CHANNEL_PAYLOAD_BYTES];
    let length = encode_certd_channel_request(
        CertdChannelRequest {
            role: CertdChannelRole::Acmed,
            operation,
            request_id,
            peer: CLIENT,
            payload,
        },
        capability,
        &mut frame,
    )
    .map_err(|_| ())?;
    session.write_frame(&frame[..length]).map_err(|error| {
        eprintln!("enrollment request {operation:?} write failed: {error:?}");
    })?;
    let length = session.read_frame(&mut frame).map_err(|error| {
        eprintln!("enrollment request {operation:?} read failed: {error:?}");
    })?;
    let response = decode_certd_channel_request(
        &frame[..length],
        session.observed_peer(),
        CertdChannelPolicy {
            role: CertdChannelRole::Acmed,
            peer: SERVER,
        },
        capability,
        &mut CertdReplayWindow::new(),
    )
    .map_err(|_| ())?;
    if response.operation != operation || response.request_id != request_id {
        return Err(());
    }
    Ok(response.payload.to_vec())
}

fn number(value: &str) -> Result<u64, ()> {
    if value.is_empty() || value.starts_with('0') || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    value.parse().map_err(|_| ())
}

fn digest(value: &str) -> Result<[u8; 32], ()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(());
    }
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| ())?;
    }
    if result == [0; 32] {
        return Err(());
    }
    Ok(result)
}

fn path_valid(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

fn read_public(path: &Path, max: usize) -> Result<Vec<u8>, ()> {
    if !path_valid(path) {
        return Err(());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(super::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || ![0, CLIENT.uid].contains(&metadata.uid())
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > max as u64
    {
        return Err(());
    }
    let mut bytes = Vec::new();
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > max {
        return Err(());
    }
    Ok(bytes)
}

fn write_public_new(path: &Path, bytes: &[u8]) -> Result<(), ()> {
    if !path_valid(path) {
        return Err(());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(super::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ())?;
    file.write_all(bytes).map_err(|_| ())?;
    file.sync_all().map_err(|_| ())?;
    File::open(path.parent().ok_or(())?)
        .map_err(|_| ())?
        .sync_all()
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enrollment_context_numbers_and_digest_are_canonical() {
        for value in ["0", "01", "+1", "", "18446744073709551616"] {
            assert!(number(value).is_err());
        }
        assert_eq!(number("1"), Ok(1));
        assert!(digest(&"00".repeat(32)).is_err());
        assert!(digest(&"AB".repeat(32)).is_err());
        assert_eq!(digest(&"ab".repeat(32)), Ok([0xab; 32]));
    }
}
