use super::*;
#[test]
fn publication_digest_binds_exact_gitd_identity_fields() {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(IDENTITY_SNAPSHOT_MAGIC);
    encoded.extend_from_slice(&7u64.to_be_bytes());
    encoded.extend_from_slice(&11u16.to_be_bytes());
    encoded.extend_from_slice(b"git.example");
    encoded.push(1);
    encoded.extend_from_slice(&3u32.to_be_bytes());
    encoded.extend_from_slice(b"abc");
    encoded.extend_from_slice(&[0x55; 32]);
    encoded.extend_from_slice(&100u64.to_be_bytes());
    encoded.extend_from_slice(&200u64.to_be_bytes());
    encoded.extend_from_slice(&[1, 4, 3]);
    // Independent SHA-256 golden value for the versioned public protocol.
    let expected = [
        226, 199, 82, 3, 118, 218, 84, 110, 121, 64, 169, 242, 87, 80, 140, 6, 45, 17, 216, 186,
        160, 235, 242, 137, 101, 251, 255, 81, 64, 62, 190, 173,
    ];
    assert_eq!(
        identity_snapshot_publication_digest(&encoded).unwrap(),
        expected
    );
    // Generation, name, chain, SPKI, both times and signature scheme all bind.
    for index in [15, 18, 34, 37, 76, 84, 87] {
        let mut changed = encoded.clone();
        changed[index] ^= 1;
        assert_ne!(
            identity_snapshot_publication_digest(&changed).unwrap(),
            expected
        );
    }
    assert!(identity_snapshot_publication_digest(&encoded[..17]).is_err());
    let mut bad_name = encoded.clone();
    bad_name[16..18].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(identity_snapshot_publication_digest(&bad_name).is_err());
}
