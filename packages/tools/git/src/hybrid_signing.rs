//! MRML-native ML-DSA-65 framing for Git's nested hybrid signatures.

use mrml_crypto::{ML_DSA_65_SIGNATURE_BYTES, MlDsaError, ml_dsa_65_sign, ml_dsa_65_verify};
use mrml_runtime::{Text, Vector};

const BEGIN: &str = "-----BEGIN MRML ML-DSA-65 SIGNATURE-----";
const END: &str = "-----END MRML ML-DSA-65 SIGNATURE-----";
const CONTEXT: &[u8] = b"mrml.git.object.v1";
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn sign_ml_dsa_65_git_payload(
    secret_key: &[u8],
    payload: &[u8],
    randomizer: &[u8; 32],
) -> Result<Text, MlDsaError> {
    let mut signature = [0u8; ML_DSA_65_SIGNATURE_BYTES];
    ml_dsa_65_sign(secret_key, CONTEXT, payload, randomizer, &mut signature)?;
    Ok(armor(&signature))
}

pub fn verify_ml_dsa_65_git_payload(
    public_key: &[u8],
    payload: &[u8],
    armored_signature: &str,
) -> Result<(), MlDsaError> {
    let signature = dearmor(armored_signature).ok_or(MlDsaError::InvalidSignature)?;
    ml_dsa_65_verify(public_key, CONTEXT, payload, &signature)
}

fn armor(signature: &[u8; ML_DSA_65_SIGNATURE_BYTES]) -> Text {
    let mut output = Text::from(BEGIN);
    output.push('\n');
    let mut column = 0usize;
    for chunk in signature.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for shift in [18, 12, 6, 0] {
            output.push(ALPHABET[((value >> shift) & 63) as usize] as char);
            column += 1;
            if column == 64 {
                output.push('\n');
                column = 0;
            }
        }
    }
    if column != 0 {
        output.push('\n');
    }
    output.push_str(END);
    output.push('\n');
    output
}

fn dearmor(input: &str) -> Option<Vector<u8>> {
    let mut lines = input.lines();
    if lines.next()? != BEGIN || lines.next_back()? != END {
        return None;
    }
    let mut encoded = Vector::new();
    for line in lines {
        if line.is_empty() || line.len() > 64 || !line.bytes().all(|byte| value(byte).is_some()) {
            return None;
        }
        encoded.extend(line.bytes());
    }
    if encoded.len() != 4 * (ML_DSA_65_SIGNATURE_BYTES / 3) {
        return None;
    }
    let mut output = Vector::new();
    for group in encoded.chunks_exact(4) {
        let combined = (u32::from(value(group[0])?) << 18)
            | (u32::from(value(group[1])?) << 12)
            | (u32::from(value(group[2])?) << 6)
            | u32::from(value(group[3])?);
        output.push((combined >> 16) as u8);
        output.push((combined >> 8) as u8);
        output.push(combined as u8);
    }
    (output.len() == ML_DSA_65_SIGNATURE_BYTES).then_some(output)
}

fn value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_crypto::{ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SECRET_KEY_BYTES, ml_dsa_65_keygen};

    #[test]
    fn armor_round_trip_and_payload_binding() {
        let mut public = [0u8; ML_DSA_65_PUBLIC_KEY_BYTES];
        let mut secret = [0u8; ML_DSA_65_SECRET_KEY_BYTES];
        ml_dsa_65_keygen(&[17u8; 32], &mut public, &mut secret).unwrap();
        let armor = sign_ml_dsa_65_git_payload(&secret, b"tree payload\n", &[23u8; 32]).unwrap();
        verify_ml_dsa_65_git_payload(&public, b"tree payload\n", &armor).unwrap();
        assert_eq!(
            verify_ml_dsa_65_git_payload(&public, b"different\n", &armor),
            Err(MlDsaError::InvalidSignature)
        );
    }
}
