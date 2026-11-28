use mrml_crypto::{LAMPORT_PUBLIC_KEY_BYTES, Sha3_512};
use mrml_error::{Result, anyhow};
use mrml_kernel::{BOOTSTRAP_STATE_BYTES, BootstrapState};
use mrml_runtime::{Text, mrml_println as println};

pub fn create(minimum_release: u64, output_path: &str, public_path: &str) -> Result<()> {
    if mrml_runtime::path_exists(output_path) {
        return Err(anyhow!("refusing to overwrite bootstrap state"));
    }
    let public = mrml_runtime::read_file_bounded(public_path, LAMPORT_PUBLIC_KEY_BYTES)?;
    let encoded = encode_genesis(&public, minimum_release)?;
    mrml_runtime::write_new_file(output_path, &encoded)?;
    println!(
        "wrote canonical owner-selected genesis state at minimum release {}",
        minimum_release
    );
    Ok(())
}

/// Prints only public, structural fields. Reading a file does not authenticate
/// it as TPM state and this command deliberately makes no such claim.
pub fn inspect(path: &str) -> Result<()> {
    let encoded = mrml_runtime::read_file_bounded(path, BOOTSTRAP_STATE_BYTES)?;
    let state = BootstrapState::decode_canonical(&encoded)
        .map_err(|_| anyhow!("invalid canonical bootstrap state"))?;
    println!("minimum-release={}", state.minimum_release());
    println!(
        "current-root.sha3-512={}",
        encode_hex(&state.current_root_digest())?
    );
    match state.installed_manifest_digest() {
        Some(digest) => println!("installed-manifest.sha3-512={}", encode_hex(&digest)?),
        None => println!("installed-manifest=none"),
    }
    println!("authentication=not-verified");
    Ok(())
}

pub fn prepare_slot(sequence: u64, state_path: &str, output_path: &str) -> Result<()> {
    if mrml_runtime::path_exists(output_path) {
        return Err(anyhow!("refusing to overwrite release journal slot"));
    }
    let encoded = mrml_runtime::read_file_bounded(state_path, BOOTSTRAP_STATE_BYTES)?;
    let state = BootstrapState::decode_canonical(&encoded)
        .map_err(|_| anyhow!("invalid canonical bootstrap state"))?;
    let (slot, bytes) = mrml_storage::encode_release_genesis_slot(sequence, state)
        .map_err(|_| anyhow!("a fresh release journal requires genesis bootstrap state"))?;
    mrml_runtime::write_new_file(output_path, &bytes)?;
    println!(
        "release-journal-slot|slot={}|sequence={}|authentication=not-verified|tpm-write=not-performed",
        slot, sequence
    );
    Ok(())
}

fn encode_genesis(public: &[u8], minimum_release: u64) -> Result<[u8; BOOTSTRAP_STATE_BYTES]> {
    if public.len() != LAMPORT_PUBLIC_KEY_BYTES {
        return Err(anyhow!("invalid public-key length"));
    }
    BootstrapState::genesis(Sha3_512::digest(public), minimum_release)
        .map(BootstrapState::encode)
        .map_err(|_| anyhow!("invalid genesis state"))
}

fn encode_hex(bytes: &[u8]) -> Result<Text> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let capacity = bytes
        .len()
        .checked_mul(2)
        .ok_or_else(|| anyhow!("hex output length overflow"))?;
    let mut output = Text::with_capacity(capacity).map_err(|_| anyhow!("allocation failed"))?;
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 15) as usize] as char);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_state_binds_exact_owner_key_and_rollback_floor() {
        let public = [0x5a; LAMPORT_PUBLIC_KEY_BYTES];
        let encoded = encode_genesis(&public, 7).unwrap();
        let decoded = BootstrapState::decode_canonical(&encoded).unwrap();
        assert_eq!(decoded.minimum_release(), 7);
        assert_eq!(decoded.current_root_digest(), Sha3_512::digest(&public));
        assert_eq!(decoded.installed_manifest_digest(), None);

        let changed = encode_genesis(&[0x6b; LAMPORT_PUBLIC_KEY_BYTES], 7).unwrap();
        assert_ne!(encoded, changed);
    }

    #[test]
    fn genesis_state_rejects_zero_floor_and_wrong_key_length() {
        assert!(encode_genesis(&[0x5a; LAMPORT_PUBLIC_KEY_BYTES], 0).is_err());
        assert!(encode_genesis(&[0x5a; LAMPORT_PUBLIC_KEY_BYTES - 1], 1).is_err());
    }
}
