//! Explicit hostile client for the disposable, authenticated H2 acceptance run.
use mrml_git::{
    CredentialAgentCapability, CredentialAgentPeer, DetachedCommitProofRecord, HttpsRemote,
    HttpsRemoteError, HttpsTransport, QuarantineTransactionId, Repository,
    UnixHttpsCredentialProvider,
};
use std::io::Write;
use std::path::Path;

pub(super) fn run(args: &[String]) -> Result<(), ()> {
    let [_, repository, url, socket, capability, output] = args else {
        return Err(());
    };
    let mut key = super::read_capability(Path::new(capability), 21005)?;
    let capability = CredentialAgentCapability::new(key).map_err(|_| ())?;
    mrml_crypto::erase_secret_bytes(&mut key);
    let mut credentials = UnixHttpsCredentialProvider::new(
        socket,
        CredentialAgentPeer {
            uid: 21009,
            gid: 21009,
        },
        capability,
        std::env::var("MRML_GIT_CREDENTIAL_GENERATION")
            .map_err(|_| ())?
            .parse()
            .map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    let remote = HttpsRemote::parse(url, HttpsTransport::Http2).map_err(|_| ())?;
    let before = remote
        .list_refs_authenticated(&mut credentials)
        .map_err(|_| ())?;
    let old = before
        .refs
        .iter()
        .find(|item| item.name == "refs/heads/main")
        .ok_or(())?
        .id;
    let repository = Repository::discover(repository).map_err(|_| ())?;
    let new = repository.resolve_revision("HEAD").map_err(|_| ())?;
    if new == old {
        return Err(());
    }
    // This command is only for a tiny acceptance commit. Its bounded pack must
    // contain real reachable objects, so missing-object rejection cannot stand
    // in for the malformed proof check.
    let pack = repository.pack_negotiated(&[new], &[old]).map_err(|_| ())?;
    if pack.len() > 8 * 1024 * 1024 || !Path::new(output).is_absolute() {
        return Err(());
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|_| ())?;
    file.write_all(&pack).map_err(|_| ())?;
    file.sync_all().map_err(|_| ())?;
    drop(file);
    let expected = remote
        .discover_receive_pack_authenticated(&mut credentials)
        .map_err(|_| ())?;
    let proof =
        DetachedCommitProofRecord::new(new, &[0xff], &[0; mrml_crypto::ML_DSA_65_SIGNATURE_BYTES])
            .map_err(|_| ())?;
    let result = remote.push_protected_pack_file_authenticated(
        old,
        new,
        "refs/heads/main",
        output,
        expected,
        QuarantineTransactionId([0xa5; 16]),
        &[proof],
        &mut credentials,
    );
    match result {
        Err(HttpsRemoteError::Protocol | HttpsRemoteError::HttpStatus) => {}
        Err(HttpsRemoteError::Transport(_)) => {
            // The production backend closes an ambiguous receive stream after
            // denying the proof. A transport close alone is NOT proof of that
            // denial: the outer acceptance runner must also require a fresh
            // authority_proof_verify_denied server event for this attempt.
            eprintln!(
                "receive connection closed; require matching server authority_proof_verify_denied evidence"
            );
        }
        other => {
            eprintln!("malformed proof unexpectedly accepted or not submitted: {other:?}");
            return Err(());
        }
    }
    let after = remote
        .list_refs_authenticated(&mut credentials)
        .map_err(|_| ())?;
    let generation = remote
        .discover_receive_pack_authenticated(&mut credentials)
        .map_err(|_| ())?;
    if before != after || expected != generation {
        return Err(());
    }
    println!("malformed attempt not activated; exact refs and authority generation unchanged");
    Ok(())
}
