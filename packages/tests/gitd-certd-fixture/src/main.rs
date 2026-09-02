use mrml_certificate::{
    decode_certd_channel_request, encode_certd_channel_request, CertdChannelCapability,
    CertdChannelOperation, CertdChannelPolicy, CertdChannelRequest, CertdChannelRole,
    CertdPeerIdentity, CertdReplayWindow, UnixCertdListener, CERTD_CHANNEL_HEADER_BYTES,
    MAX_CERTD_CHANNEL_PAYLOAD_BYTES,
};
use mrml_crypto::{encode_der_signature, erase_secret_bytes, P256SecretKey, Sha256};
use mrml_tls::Certificate;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

const O_NOFOLLOW: i32 = 0x20_000;
const IDENTITY_REQUEST_MAGIC: &[u8; 8] = b"MRGIDR01";
const IDENTITY_SNAPSHOT_MAGIC: &[u8; 8] = b"MRGIDS01";
const CERTIFICATE_VERIFY_REQUEST_MAGIC: &[u8; 8] = b"MRGSGN01";
const CERTIFICATE_VERIFY_RESPONSE_MAGIC: &[u8; 8] = b"MRGSGS01";
const GENERATION_WAIT_REQUEST_MAGIC: &[u8; 8] = b"MRGWAI01";
const GENERATION_WAIT_RESPONSE_MAGIC: &[u8; 8] = b"MRGWAS01";
const PUBLICATION_DOMAIN: &[u8] = b"MRML-GITD-TLS-IDENTITY-PUBLICATION-V1\0";
const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
const MAX_CERTIFICATE_DER_BYTES: usize = 8 * 1024;
const MAX_REQUESTS: usize = 4096;

struct Configuration {
    socket: PathBuf,
    capability_file: PathBuf,
    client: CertdPeerIdentity,
    fixture: CertdPeerIdentity,
    owner_uid: u32,
    server_name: String,
    generation: u64,
    leaf_file: PathBuf,
    issuer_file: PathBuf,
    key_file: PathBuf,
    request_limit: usize,
}

struct FixtureIdentity {
    server_name: String,
    generation: u64,
    leaf: Vec<u8>,
    issuer: Vec<u8>,
    spki_digest: [u8; 32],
    not_before: u64,
    not_after: u64,
    publication_digest: [u8; 32],
    key: P256SecretKey,
}

fn main() {
    if run().is_err() {
        eprintln!("mrml-gitd-certd-test-fixture: rejected configuration or request");
        std::process::exit(1);
    }
}

fn run() -> Result<(), ()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let config = parse_arguments(&arguments)?;
    validate_socket_parent(&config.socket, config.owner_uid)?;
    let mut capability_bytes =
        read_exact_file(&config.capability_file, 32, config.owner_uid, true)?;
    let mut capability_key: [u8; 32] = capability_bytes.as_slice().try_into().map_err(|_| ())?;
    let capability_result = CertdChannelCapability::new(capability_key).map_err(|_| ());
    erase_secret_bytes(&mut capability_key);
    erase_secret_bytes(&mut capability_bytes);
    let capability = capability_result?;
    let identity = load_identity(&config)?;
    let listener = UnixCertdListener::bind(
        &config.socket,
        0o600,
        CertdChannelPolicy {
            role: CertdChannelRole::Gitd,
            peer: config.client,
        },
    )
    .map_err(|_| ())?;
    let bound_socket_identity = socket_identity(&config.socket)?;
    println!(
        "mrml-gitd-certd-test-fixture ready generation={} request_limit={}",
        identity.generation, config.request_limit
    );
    let result = serve(
        &listener,
        &capability,
        config.client,
        config.fixture,
        &identity,
        config.request_limit,
    );
    if socket_identity(&config.socket).ok() == Some(bound_socket_identity) {
        let _ = fs::remove_file(&config.socket);
    }
    result
}

fn serve(
    listener: &UnixCertdListener,
    capability: &CertdChannelCapability,
    client: CertdPeerIdentity,
    fixture: CertdPeerIdentity,
    identity: &FixtureIdentity,
    request_limit: usize,
) -> Result<(), ()> {
    let mut replay = CertdReplayWindow::new();
    let mut frame = vec![0u8; CERTD_CHANNEL_HEADER_BYTES + MAX_CERTD_CHANNEL_PAYLOAD_BYTES];
    let mut response_payload = vec![0u8; MAX_CERTD_CHANNEL_PAYLOAD_BYTES];
    for _ in 0..request_limit {
        let mut session = listener.accept().map_err(|_| ())?;
        let received = session.read_frame(&mut frame).map_err(|_| ())?;
        let request = decode_certd_channel_request(
            &frame[..received],
            session.observed_peer(),
            CertdChannelPolicy {
                role: CertdChannelRole::Gitd,
                peer: client,
            },
            capability,
            &mut replay,
        )
        .map_err(|_| ())?;
        let length = dispatch(
            identity,
            request.operation,
            request.payload,
            &mut response_payload,
        )?;
        let written = encode_certd_channel_request(
            CertdChannelRequest {
                role: CertdChannelRole::Gitd,
                operation: request.operation,
                request_id: request.request_id,
                peer: fixture,
                payload: &response_payload[..length],
            },
            capability,
            &mut frame,
        )
        .map_err(|_| ())?;
        session.write_frame(&frame[..written]).map_err(|_| ())?;
        response_payload[..length].fill(0);
    }
    Ok(())
}

fn dispatch(
    identity: &FixtureIdentity,
    operation: CertdChannelOperation,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, ()> {
    match operation {
        CertdChannelOperation::Health if payload.is_empty() => {
            append(output, &mut 0, b"ready")?;
            Ok(5)
        }
        CertdChannelOperation::GetIdentitySnapshot => write_snapshot(identity, payload, output),
        CertdChannelOperation::SignTls13CertificateVerify => sign_verify(identity, payload, output),
        CertdChannelOperation::WaitForIdentityGeneration => write_wait(identity, payload, output),
        _ => Err(()),
    }
}

fn write_snapshot(
    identity: &FixtureIdentity,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, ()> {
    if payload.len() < 10 || payload.get(..8) != Some(IDENTITY_REQUEST_MAGIC) {
        return Err(());
    }
    let name_length = usize::from(u16::from_be_bytes(
        payload[8..10].try_into().map_err(|_| ())?,
    ));
    if payload.len() != 10usize.checked_add(name_length).ok_or(())?
        || payload.get(10..) != Some(identity.server_name.as_bytes())
    {
        return Err(());
    }
    let mut offset = 0;
    append(output, &mut offset, IDENTITY_SNAPSHOT_MAGIC)?;
    append(output, &mut offset, &identity.generation.to_be_bytes())?;
    append(output, &mut offset, &(name_length as u16).to_be_bytes())?;
    append(output, &mut offset, identity.server_name.as_bytes())?;
    append(output, &mut offset, &[2])?;
    for certificate in [&identity.leaf, &identity.issuer] {
        append(
            output,
            &mut offset,
            &(certificate.len() as u32).to_be_bytes(),
        )?;
        append(output, &mut offset, certificate)?;
    }
    append(output, &mut offset, &identity.spki_digest)?;
    append(output, &mut offset, &identity.not_before.to_be_bytes())?;
    append(output, &mut offset, &identity.not_after.to_be_bytes())?;
    append(output, &mut offset, &[1])?;
    append(output, &mut offset, &ECDSA_SECP256R1_SHA256.to_be_bytes())?;
    append(output, &mut offset, &identity.publication_digest)?;
    append(output, &mut offset, &[1])?;
    Ok(offset)
}

fn sign_verify(identity: &FixtureIdentity, payload: &[u8], output: &mut [u8]) -> Result<usize, ()> {
    if payload.len() != 58 || payload.get(..8) != Some(CERTIFICATE_VERIFY_REQUEST_MAGIC) {
        return Err(());
    }
    let generation = u64::from_be_bytes(payload[8..16].try_into().map_err(|_| ())?);
    let scheme = u16::from_be_bytes(payload[16..18].try_into().map_err(|_| ())?);
    let transcript_digest: [u8; 32] = payload[18..50].try_into().map_err(|_| ())?;
    let logical_request_id = u64::from_be_bytes(payload[50..58].try_into().map_err(|_| ())?);
    if generation != identity.generation
        || scheme != ECDSA_SECP256R1_SHA256
        || logical_request_id == 0
    {
        return Err(());
    }
    let mut signed = Sha256::new();
    signed.update(&[0x20; 64]);
    signed.update(b"TLS 1.3, server CertificateVerify\0");
    signed.update(&transcript_digest);
    let digest = signed.finalize();
    let mut raw = identity.key.sign_digest_raw(&digest).map_err(|_| ())?;
    let mut der_storage = [0u8; 72];
    let der_length = match encode_der_signature(&raw, &mut der_storage) {
        Ok(der) => der.len(),
        Err(_) => {
            erase_secret_bytes(&mut raw);
            return Err(());
        }
    };
    erase_secret_bytes(&mut raw);
    let der = &der_storage[..der_length];
    let mut offset = 0;
    append(output, &mut offset, CERTIFICATE_VERIFY_RESPONSE_MAGIC)?;
    append(output, &mut offset, &generation.to_be_bytes())?;
    append(output, &mut offset, &scheme.to_be_bytes())?;
    append(output, &mut offset, &logical_request_id.to_be_bytes())?;
    append(output, &mut offset, &(der.len() as u16).to_be_bytes())?;
    append(output, &mut offset, der)?;
    der_storage.fill(0);
    Ok(offset)
}

fn write_wait(identity: &FixtureIdentity, payload: &[u8], output: &mut [u8]) -> Result<usize, ()> {
    if payload.len() != 20 || payload.get(..8) != Some(GENERATION_WAIT_REQUEST_MAGIC) {
        return Err(());
    }
    let current = u64::from_be_bytes(payload[8..16].try_into().map_err(|_| ())?);
    let timeout = u32::from_be_bytes(payload[16..20].try_into().map_err(|_| ())?);
    if current == 0 || timeout == 0 || timeout > 30_000 || current > identity.generation {
        return Err(());
    }
    let mut offset = 0;
    append(output, &mut offset, GENERATION_WAIT_RESPONSE_MAGIC)?;
    append(output, &mut offset, &identity.generation.to_be_bytes())?;
    append(
        output,
        &mut offset,
        &[u8::from(current < identity.generation)],
    )?;
    Ok(offset)
}

fn load_identity(config: &Configuration) -> Result<FixtureIdentity, ()> {
    let leaf = read_exact_file(
        &config.leaf_file,
        MAX_CERTIFICATE_DER_BYTES,
        config.owner_uid,
        false,
    )?;
    let issuer = read_exact_file(
        &config.issuer_file,
        MAX_CERTIFICATE_DER_BYTES,
        config.owner_uid,
        false,
    )?;
    let mut secret = read_exact_file(&config.key_file, 32, config.owner_uid, true)?;
    let mut key_bytes: [u8; 32] = secret.as_slice().try_into().map_err(|_| ())?;
    let key_result = P256SecretKey::from_bytes(key_bytes).map_err(|_| ());
    erase_secret_bytes(&mut key_bytes);
    erase_secret_bytes(&mut secret);
    let key = key_result?;
    let certificate = Certificate::parse(&leaf).map_err(|_| ())?;
    certificate
        .verify_hostname(&config.server_name)
        .map_err(|_| ())?;
    certificate
        .require_p256_public_key(&key.public_key().map_err(|_| ())?)
        .map_err(|_| ())?;
    let spki_digest = certificate.spki_sha256();
    let not_before = certificate.not_before();
    let not_after = certificate.not_after();
    let publication_digest = publication_digest(
        &config.server_name,
        config.generation,
        [&leaf, &issuer],
        spki_digest,
        not_before,
        not_after,
    )?;
    Ok(FixtureIdentity {
        server_name: config.server_name.clone(),
        generation: config.generation,
        leaf,
        issuer,
        spki_digest,
        not_before,
        not_after,
        publication_digest,
        key,
    })
}

fn publication_digest(
    server_name: &str,
    generation: u64,
    chain: [&Vec<u8>; 2],
    spki_digest: [u8; 32],
    not_before: u64,
    not_after: u64,
) -> Result<[u8; 32], ()> {
    let name_length = u16::try_from(server_name.len()).map_err(|_| ())?;
    let mut digest = Sha256::new();
    digest.update(PUBLICATION_DOMAIN);
    digest.update(&name_length.to_be_bytes());
    digest.update(server_name.as_bytes());
    digest.update(&generation.to_be_bytes());
    digest.update(&[2]);
    for certificate in chain {
        let length = u32::try_from(certificate.len()).map_err(|_| ())?;
        digest.update(&length.to_be_bytes());
        digest.update(certificate);
    }
    digest.update(&spki_digest);
    digest.update(&not_before.to_be_bytes());
    digest.update(&not_after.to_be_bytes());
    digest.update(&[1]);
    digest.update(&ECDSA_SECP256R1_SHA256.to_be_bytes());
    Ok(digest.finalize())
}

fn parse_arguments(arguments: &[String]) -> Result<Configuration, ()> {
    let [command, socket, capability, client_uid, client_gid, fixture_uid, fixture_gid, owner_uid, server_name, generation, leaf, issuer, key, request_limit] =
        arguments
    else {
        return Err(());
    };
    if command != "serve" || !valid_server_name(server_name) {
        return Err(());
    }
    let nonzero = |value: &str| {
        value
            .parse::<u64>()
            .ok()
            .filter(|value| *value != 0)
            .ok_or(())
    };
    let request_limit = usize::try_from(nonzero(request_limit)?).map_err(|_| ())?;
    if request_limit > MAX_REQUESTS {
        return Err(());
    }
    Ok(Configuration {
        socket: socket.into(),
        capability_file: capability.into(),
        client: CertdPeerIdentity {
            uid: u32::try_from(nonzero(client_uid)?).map_err(|_| ())?,
            gid: u32::try_from(nonzero(client_gid)?).map_err(|_| ())?,
        },
        fixture: CertdPeerIdentity {
            uid: u32::try_from(nonzero(fixture_uid)?).map_err(|_| ())?,
            gid: u32::try_from(nonzero(fixture_gid)?).map_err(|_| ())?,
        },
        owner_uid: u32::try_from(nonzero(owner_uid)?).map_err(|_| ())?,
        server_name: server_name.clone(),
        generation: nonzero(generation)?,
        leaf_file: leaf.into(),
        issuer_file: issuer.into(),
        key_file: key.into(),
        request_limit,
    })
}

fn valid_server_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && !name.starts_with('.')
        && !name.ends_with('.')
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn read_exact_file(path: &Path, limit: usize, owner_uid: u32, secret: bool) -> Result<Vec<u8>, ()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    let length = usize::try_from(metadata.len()).map_err(|_| ())?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != owner_uid
        || length == 0
        || length > limit
        || (secret && !matches!(metadata.mode() & 0o777, 0o400 | 0o600))
        || (!secret && metadata.mode() & 0o022 != 0)
    {
        return Err(());
    }
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes).map_err(|_| ())?;
    Ok(bytes)
}

fn validate_socket_parent(path: &Path, owner_uid: u32) -> Result<(), ()> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > 107
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(());
    }
    let parent = path.parent().ok_or(())?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| ())?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(());
    }
    Ok(())
}

fn socket_identity(path: &Path) -> Result<(u64, u64), ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.file_type().is_socket() || metadata.file_type().is_symlink() {
        return Err(());
    }
    Ok((metadata.dev(), metadata.ino()))
}

fn append(output: &mut [u8], offset: &mut usize, bytes: &[u8]) -> Result<(), ()> {
    let end = offset.checked_add(bytes.len()).ok_or(())?;
    output
        .get_mut(*offset..end)
        .ok_or(())?
        .copy_from_slice(bytes);
    *offset = end;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_reject_production_ambiguity_and_unbounded_runs() {
        let valid = [
            "serve",
            "/tmp/certd.sock",
            "/tmp/cap",
            "1000",
            "1000",
            "1000",
            "1000",
            "1000",
            "git.example",
            "1",
            "/tmp/leaf",
            "/tmp/root",
            "/tmp/key",
            "32",
        ]
        .map(String::from);
        assert!(parse_arguments(&valid).is_ok());
        let mut uppercase = valid.clone();
        uppercase[8] = "Git.example".into();
        assert!(parse_arguments(&uppercase).is_err());
        let mut unlimited = valid;
        unlimited[13] = "4097".into();
        assert!(parse_arguments(&unlimited).is_err());
    }

    #[test]
    fn publication_digest_binds_chain_order_and_generation() {
        let leaf = vec![1, 2, 3];
        let issuer = vec![4, 5, 6];
        let first =
            publication_digest("git.example", 1, [&leaf, &issuer], [7; 32], 10, 20).unwrap();
        let next = publication_digest("git.example", 2, [&leaf, &issuer], [7; 32], 10, 20).unwrap();
        let swapped =
            publication_digest("git.example", 1, [&issuer, &leaf], [7; 32], 10, 20).unwrap();
        assert_ne!(first, next);
        assert_ne!(first, swapped);
    }
}
