//! Bounded independently authenticated frames for streaming Git backups.

use mrml_crypto::{aes128_gcm_open, aes128_gcm_seal, erase_secret_bytes, hmac_sha256};

const MAGIC: &[u8; 8] = b"MRGBKP01";
const VERSION: u16 = 1;
const FRAME_HEADER_BYTES: usize = 16;
const TAG_BYTES: usize = 16;
const MAX_CHUNK_BYTES: u32 = 1024 * 1024;
const FINAL_FLAG: u8 = 1;
const KEY_DOMAIN: &[u8] = b"MRML Git backup frame key v1\0";

pub const BACKUP_STREAM_HEADER_BYTES: usize = 44;
pub const BACKUP_FRAME_OVERHEAD: usize = FRAME_HEADER_BYTES + TAG_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupStreamError {
    InvalidKey,
    InvalidHeader,
    InvalidFrame,
    Sequence,
    Resource,
    Authentication,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupStreamHeader {
    pub generation: u64,
    pub chunk_bytes: u32,
    pub salt: [u8; 16],
    pub nonce_prefix: [u8; 4],
}

pub fn encode_backup_stream_header(
    header: BackupStreamHeader,
) -> Result<[u8; BACKUP_STREAM_HEADER_BYTES], BackupStreamError> {
    if header.generation == 0
        || header.chunk_bytes == 0
        || header.chunk_bytes > MAX_CHUNK_BYTES
        || header.salt == [0; 16]
        || header.nonce_prefix == [0; 4]
    {
        return Err(BackupStreamError::InvalidHeader);
    }
    let mut encoded = [0u8; BACKUP_STREAM_HEADER_BYTES];
    encoded[..8].copy_from_slice(MAGIC);
    encoded[8..10].copy_from_slice(&VERSION.to_be_bytes());
    encoded[12..20].copy_from_slice(&header.generation.to_be_bytes());
    encoded[20..24].copy_from_slice(&header.chunk_bytes.to_be_bytes());
    encoded[24..40].copy_from_slice(&header.salt);
    encoded[40..44].copy_from_slice(&header.nonce_prefix);
    Ok(encoded)
}

pub fn parse_backup_stream_header(encoded: &[u8]) -> Result<BackupStreamHeader, BackupStreamError> {
    if encoded.len() != BACKUP_STREAM_HEADER_BYTES
        || &encoded[..8] != MAGIC
        || u16::from_be_bytes(encoded[8..10].try_into().unwrap()) != VERSION
        || encoded[10..12] != [0, 0]
    {
        return Err(BackupStreamError::InvalidHeader);
    }
    let header = BackupStreamHeader {
        generation: u64::from_be_bytes(encoded[12..20].try_into().unwrap()),
        chunk_bytes: u32::from_be_bytes(encoded[20..24].try_into().unwrap()),
        salt: encoded[24..40].try_into().unwrap(),
        nonce_prefix: encoded[40..44].try_into().unwrap(),
    };
    encode_backup_stream_header(header)?;
    Ok(header)
}

pub fn seal_backup_frame(
    backup_key: &[u8; 32],
    encoded_header: &[u8; BACKUP_STREAM_HEADER_BYTES],
    sequence: u64,
    final_frame: bool,
    plaintext: &[u8],
    output: &mut [u8],
) -> Result<usize, BackupStreamError> {
    let header = validate_key_and_header(backup_key, encoded_header)?;
    if (final_frame && !plaintext.is_empty()) || (!final_frame && plaintext.is_empty()) {
        return Err(BackupStreamError::InvalidFrame);
    }
    let length = u32::try_from(plaintext.len()).map_err(|_| BackupStreamError::Resource)?;
    if length > header.chunk_bytes {
        return Err(BackupStreamError::Resource);
    }
    let required = BACKUP_FRAME_OVERHEAD
        .checked_add(plaintext.len())
        .ok_or(BackupStreamError::Resource)?;
    if output.len() < required {
        return Err(BackupStreamError::Resource);
    }
    let frame_header = encode_frame_header(sequence, length, final_frame);
    output[..FRAME_HEADER_BYTES].copy_from_slice(&frame_header);
    let mut aad = [0u8; BACKUP_STREAM_HEADER_BYTES + FRAME_HEADER_BYTES];
    aad[..BACKUP_STREAM_HEADER_BYTES].copy_from_slice(encoded_header);
    aad[BACKUP_STREAM_HEADER_BYTES..].copy_from_slice(&frame_header);
    let mut key = derive_key(backup_key, encoded_header);
    let nonce = nonce(header.nonce_prefix, sequence);
    let ciphertext_end = FRAME_HEADER_BYTES + plaintext.len();
    let (prefix, suffix) = output[..required].split_at_mut(ciphertext_end);
    let ciphertext = &mut prefix[FRAME_HEADER_BYTES..];
    let tag: &mut [u8; TAG_BYTES] = suffix.try_into().unwrap();
    let sealed = aes128_gcm_seal(&key, &nonce, &aad, plaintext, ciphertext, tag);
    erase_secret_bytes(&mut key);
    if !sealed {
        output[..required].fill(0);
        return Err(BackupStreamError::Authentication);
    }
    Ok(required)
}

pub fn open_backup_frame(
    backup_key: &[u8; 32],
    encoded_header: &[u8; BACKUP_STREAM_HEADER_BYTES],
    expected_sequence: u64,
    frame: &[u8],
    plaintext: &mut [u8],
) -> Result<(usize, bool), BackupStreamError> {
    let header = validate_key_and_header(backup_key, encoded_header)?;
    if frame.len() < BACKUP_FRAME_OVERHEAD {
        return Err(BackupStreamError::InvalidFrame);
    }
    let sequence = u64::from_be_bytes(frame[..8].try_into().unwrap());
    let length = u32::from_be_bytes(frame[8..12].try_into().unwrap());
    let flags = frame[12];
    if sequence != expected_sequence {
        return Err(BackupStreamError::Sequence);
    }
    if frame[13..16] != [0, 0, 0] || flags & !FINAL_FLAG != 0 || length > header.chunk_bytes {
        return Err(BackupStreamError::InvalidFrame);
    }
    let final_frame = flags == FINAL_FLAG;
    if (final_frame && length != 0) || (!final_frame && length == 0) {
        return Err(BackupStreamError::InvalidFrame);
    }
    let length = usize::try_from(length).map_err(|_| BackupStreamError::Resource)?;
    let required = BACKUP_FRAME_OVERHEAD
        .checked_add(length)
        .ok_or(BackupStreamError::Resource)?;
    if frame.len() != required || plaintext.len() < length {
        return Err(BackupStreamError::InvalidFrame);
    }
    let mut aad = [0u8; BACKUP_STREAM_HEADER_BYTES + FRAME_HEADER_BYTES];
    aad[..BACKUP_STREAM_HEADER_BYTES].copy_from_slice(encoded_header);
    aad[BACKUP_STREAM_HEADER_BYTES..].copy_from_slice(&frame[..FRAME_HEADER_BYTES]);
    let ciphertext_end = FRAME_HEADER_BYTES + length;
    let tag: &[u8; TAG_BYTES] = frame[ciphertext_end..].try_into().unwrap();
    let mut key = derive_key(backup_key, encoded_header);
    let nonce = nonce(header.nonce_prefix, sequence);
    let opened = aes128_gcm_open(
        &key,
        &nonce,
        &aad,
        &frame[FRAME_HEADER_BYTES..ciphertext_end],
        tag,
        &mut plaintext[..length],
    );
    erase_secret_bytes(&mut key);
    if !opened {
        plaintext[..length].fill(0);
        return Err(BackupStreamError::Authentication);
    }
    Ok((length, final_frame))
}

fn validate_key_and_header(
    backup_key: &[u8; 32],
    encoded_header: &[u8; BACKUP_STREAM_HEADER_BYTES],
) -> Result<BackupStreamHeader, BackupStreamError> {
    if backup_key == &[0; 32] {
        return Err(BackupStreamError::InvalidKey);
    }
    parse_backup_stream_header(encoded_header)
}

fn encode_frame_header(sequence: u64, length: u32, final_frame: bool) -> [u8; 16] {
    let mut encoded = [0u8; 16];
    encoded[..8].copy_from_slice(&sequence.to_be_bytes());
    encoded[8..12].copy_from_slice(&length.to_be_bytes());
    encoded[12] = u8::from(final_frame);
    encoded
}

fn nonce(prefix: [u8; 4], sequence: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&prefix);
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

fn derive_key(
    backup_key: &[u8; 32],
    encoded_header: &[u8; BACKUP_STREAM_HEADER_BYTES],
) -> [u8; 16] {
    let mut derived = hmac_sha256(backup_key, &[KEY_DOMAIN, encoded_header]);
    let mut key = [0u8; 16];
    key.copy_from_slice(&derived[..16]);
    erase_secret_bytes(&mut derived);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> [u8; BACKUP_STREAM_HEADER_BYTES] {
        encode_backup_stream_header(BackupStreamHeader {
            generation: 7,
            chunk_bytes: 32,
            salt: [0x31; 16],
            nonce_prefix: [0x72; 4],
        })
        .unwrap()
    }

    fn frame(sequence: u64, final_frame: bool, plaintext: &[u8]) -> [u8; 64] {
        let mut output = [0u8; 64];
        let length = seal_backup_frame(
            &[0x19; 32],
            &header(),
            sequence,
            final_frame,
            plaintext,
            &mut output,
        )
        .unwrap();
        assert_eq!(length, BACKUP_FRAME_OVERHEAD + plaintext.len());
        output
    }

    #[test]
    fn frames_round_trip_with_authenticated_eof() {
        for (sequence, final_frame, input) in [
            (0, false, &b"inventory"[..]),
            (1, false, &b"repository bytes"[..]),
            (2, true, &b""[..]),
        ] {
            let encoded = frame(sequence, final_frame, input);
            let length = BACKUP_FRAME_OVERHEAD + input.len();
            let mut plaintext = [0u8; 32];
            assert_eq!(
                open_backup_frame(
                    &[0x19; 32],
                    &header(),
                    sequence,
                    &encoded[..length],
                    &mut plaintext,
                )
                .unwrap(),
                (input.len(), final_frame)
            );
            assert_eq!(&plaintext[..input.len()], input);
        }
    }

    #[test]
    fn wrong_key_header_sequence_tamper_and_truncation_fail_closed() {
        let encoded = frame(3, false, b"authority state");
        let length = BACKUP_FRAME_OVERHEAD + 15;
        let mut plaintext = [0xa5; 32];
        assert_eq!(
            open_backup_frame(
                &[0x19; 32],
                &header(),
                2,
                &encoded[..length],
                &mut plaintext,
            ),
            Err(BackupStreamError::Sequence)
        );
        assert!(
            open_backup_frame(
                &[0x18; 32],
                &header(),
                3,
                &encoded[..length],
                &mut plaintext,
            )
            .is_err()
        );
        let mut changed_header = header();
        changed_header[19] ^= 1;
        assert!(
            open_backup_frame(
                &[0x19; 32],
                &changed_header,
                3,
                &encoded[..length],
                &mut plaintext,
            )
            .is_err()
        );
        let mut changed = encoded;
        changed[FRAME_HEADER_BYTES] ^= 1;
        assert!(
            open_backup_frame(
                &[0x19; 32],
                &header(),
                3,
                &changed[..length],
                &mut plaintext,
            )
            .is_err()
        );
        assert!(
            open_backup_frame(
                &[0x19; 32],
                &header(),
                3,
                &encoded[..length - 1],
                &mut plaintext,
            )
            .is_err()
        );
        assert!(plaintext[..15].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn invalid_parameters_are_rejected_before_encryption() {
        assert!(
            encode_backup_stream_header(BackupStreamHeader {
                generation: 0,
                chunk_bytes: 1,
                salt: [1; 16],
                nonce_prefix: [1; 4],
            })
            .is_err()
        );
        let mut output = [0u8; 64];
        assert!(seal_backup_frame(&[0; 32], &header(), 0, false, b"x", &mut output).is_err());
        assert!(seal_backup_frame(&[1; 32], &header(), 0, true, b"x", &mut output).is_err());
        assert!(seal_backup_frame(&[1; 32], &header(), 0, false, b"", &mut output).is_err());
    }
}
