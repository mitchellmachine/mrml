use mrml_crypto::{
    aes128_encrypt_block, aes128_gcm_open, aes128_gcm_seal, hkdf_expand_label, hkdf_extract,
};
use mrml_runtime::Vector;

const V1: u32 = 1;
const V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const MAX_DATAGRAM: usize = 65_527;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicError {
    Truncated,
    InvalidInteger,
    InvalidPacket,
    InvalidFrame,
    Crypto,
    Allocation,
    Limit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicRole {
    Client,
    Server,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuicFrame {
    Padding,
    Ping,
    Ack {
        largest: u64,
        delay: u64,
        first_range: u64,
    },
    Crypto {
        offset: u64,
        data: Vector<u8>,
    },
    Stream {
        id: u64,
        offset: u64,
        fin: bool,
        data: Vector<u8>,
    },
    MaxData(u64),
    MaxStreamData {
        id: u64,
        maximum: u64,
    },
    PathChallenge([u8; 8]),
    PathResponse([u8; 8]),
    ConnectionClose {
        code: u64,
        frame_type: u64,
        reason: Vector<u8>,
    },
    HandshakeDone,
}

fn put_varint(out: &mut Vector<u8>, value: u64) -> Result<(), QuicError> {
    if value < (1 << 6) {
        out.try_push(value as u8).map_err(|_| QuicError::Allocation)
    } else if value < (1 << 14) {
        out.try_extend_from_slice(&((value as u16) | 0x4000).to_be_bytes())
            .map_err(|_| QuicError::Allocation)
    } else if value < (1 << 30) {
        out.try_extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes())
            .map_err(|_| QuicError::Allocation)
    } else if value < (1 << 62) {
        out.try_extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes())
            .map_err(|_| QuicError::Allocation)
    } else {
        Err(QuicError::InvalidInteger)
    }
}

fn take_varint(input: &[u8], at: &mut usize) -> Result<u64, QuicError> {
    let first = *input.get(*at).ok_or(QuicError::Truncated)?;
    let length = 1usize << (first >> 6);
    let end = at.checked_add(length).ok_or(QuicError::Limit)?;
    if end > input.len() {
        return Err(QuicError::Truncated);
    }
    let mut value = (first & 0x3f) as u64;
    for byte in &input[*at + 1..end] {
        value = (value << 8) | *byte as u64;
    }
    *at = end;
    Ok(value)
}

impl QuicFrame {
    pub fn encode(&self, out: &mut Vector<u8>) -> Result<(), QuicError> {
        match self {
            Self::Padding => out.try_push(0).map_err(|_| QuicError::Allocation),
            Self::Ping => out.try_push(1).map_err(|_| QuicError::Allocation),
            Self::Ack {
                largest,
                delay,
                first_range,
            } => {
                put_varint(out, 2)?;
                put_varint(out, *largest)?;
                put_varint(out, *delay)?;
                put_varint(out, 0)?;
                put_varint(out, *first_range)
            }
            Self::Crypto { offset, data } => {
                put_varint(out, 6)?;
                put_varint(out, *offset)?;
                put_varint(out, data.len() as u64)?;
                out.try_extend_from_slice(data)
                    .map_err(|_| QuicError::Allocation)
            }
            Self::Stream {
                id,
                offset,
                fin,
                data,
            } => {
                put_varint(out, 0x0a | u64::from(*offset != 0) * 4 | u64::from(*fin))?;
                put_varint(out, *id)?;
                if *offset != 0 {
                    put_varint(out, *offset)?;
                }
                put_varint(out, data.len() as u64)?;
                out.try_extend_from_slice(data)
                    .map_err(|_| QuicError::Allocation)
            }
            Self::MaxData(value) => {
                put_varint(out, 0x10)?;
                put_varint(out, *value)
            }
            Self::MaxStreamData { id, maximum } => {
                put_varint(out, 0x11)?;
                put_varint(out, *id)?;
                put_varint(out, *maximum)
            }
            Self::PathChallenge(value) => {
                put_varint(out, 0x1a)?;
                out.try_extend_from_slice(value)
                    .map_err(|_| QuicError::Allocation)
            }
            Self::PathResponse(value) => {
                put_varint(out, 0x1b)?;
                out.try_extend_from_slice(value)
                    .map_err(|_| QuicError::Allocation)
            }
            Self::ConnectionClose {
                code,
                frame_type,
                reason,
            } => {
                put_varint(out, 0x1c)?;
                put_varint(out, *code)?;
                put_varint(out, *frame_type)?;
                put_varint(out, reason.len() as u64)?;
                out.try_extend_from_slice(reason)
                    .map_err(|_| QuicError::Allocation)
            }
            Self::HandshakeDone => put_varint(out, 0x1e),
        }
    }

    pub fn decode(input: &[u8], at: &mut usize) -> Result<Self, QuicError> {
        let kind = take_varint(input, at)?;
        let bytes =
            |input: &[u8], at: &mut usize, length: usize| -> Result<Vector<u8>, QuicError> {
                let end = at.checked_add(length).ok_or(QuicError::Limit)?;
                if end > input.len() {
                    return Err(QuicError::Truncated);
                }
                let mut out = Vector::new();
                out.try_extend_from_slice(&input[*at..end])
                    .map_err(|_| QuicError::Allocation)?;
                *at = end;
                Ok(out)
            };
        match kind {
            0 => Ok(Self::Padding),
            1 => Ok(Self::Ping),
            2 => {
                let largest = take_varint(input, at)?;
                let delay = take_varint(input, at)?;
                if take_varint(input, at)? != 0 {
                    return Err(QuicError::InvalidFrame);
                }
                Ok(Self::Ack {
                    largest,
                    delay,
                    first_range: take_varint(input, at)?,
                })
            }
            6 => {
                let offset = take_varint(input, at)?;
                let n = usize::try_from(take_varint(input, at)?).map_err(|_| QuicError::Limit)?;
                Ok(Self::Crypto {
                    offset,
                    data: bytes(input, at, n)?,
                })
            }
            0x08..=0x0f => {
                let id = take_varint(input, at)?;
                let offset = if kind & 4 != 0 {
                    take_varint(input, at)?
                } else {
                    0
                };
                let n = if kind & 2 != 0 {
                    usize::try_from(take_varint(input, at)?).map_err(|_| QuicError::Limit)?
                } else {
                    input.len() - *at
                };
                Ok(Self::Stream {
                    id,
                    offset,
                    fin: kind & 1 != 0,
                    data: bytes(input, at, n)?,
                })
            }
            0x10 => Ok(Self::MaxData(take_varint(input, at)?)),
            0x11 => Ok(Self::MaxStreamData {
                id: take_varint(input, at)?,
                maximum: take_varint(input, at)?,
            }),
            0x1a | 0x1b => {
                let value = bytes(input, at, 8)?;
                let mut a = [0; 8];
                a.copy_from_slice(&value);
                Ok(if kind == 0x1a {
                    Self::PathChallenge(a)
                } else {
                    Self::PathResponse(a)
                })
            }
            0x1c => {
                let code = take_varint(input, at)?;
                let frame_type = take_varint(input, at)?;
                let n = usize::try_from(take_varint(input, at)?).map_err(|_| QuicError::Limit)?;
                Ok(Self::ConnectionClose {
                    code,
                    frame_type,
                    reason: bytes(input, at, n)?,
                })
            }
            0x1e => Ok(Self::HandshakeDone),
            _ => Err(QuicError::InvalidFrame),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicInitialKeys {
    pub key: [u8; 16],
    pub iv: [u8; 12],
    pub header: [u8; 16],
}
impl QuicInitialKeys {
    pub fn derive(destination_id: &[u8], role: QuicRole) -> Result<Self, QuicError> {
        if destination_id.len() > 20 {
            return Err(QuicError::Limit);
        }
        let initial = hkdf_extract(&V1_INITIAL_SALT, destination_id);
        let mut secret = [0; 32];
        let label = if role == QuicRole::Client {
            b"client in".as_slice()
        } else {
            b"server in".as_slice()
        };
        if !hkdf_expand_label(&initial, label, &[], &mut secret) {
            return Err(QuicError::Crypto);
        }
        let mut key = [0; 16];
        let mut iv = [0; 12];
        let mut header = [0; 16];
        if !hkdf_expand_label(&secret, b"quic key", &[], &mut key)
            || !hkdf_expand_label(&secret, b"quic iv", &[], &mut iv)
            || !hkdf_expand_label(&secret, b"quic hp", &[], &mut header)
        {
            return Err(QuicError::Crypto);
        }
        Ok(Self { key, iv, header })
    }
    fn nonce(&self, packet: u64) -> [u8; 12] {
        let mut n = self.iv;
        for (i, b) in packet.to_be_bytes().iter().enumerate() {
            n[4 + i] ^= *b
        }
        n
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialPacket {
    pub destination_id: Vector<u8>,
    pub source_id: Vector<u8>,
    pub packet_number: u64,
    pub payload: Vector<u8>,
}
impl InitialPacket {
    pub fn seal(&self, keys: &QuicInitialKeys) -> Result<Vector<u8>, QuicError> {
        if self.destination_id.len() > 20
            || self.source_id.len() > 20
            || self.payload.len() > MAX_DATAGRAM
        {
            return Err(QuicError::Limit);
        }
        let pn_len = 4usize;
        let mut out = Vector::new();
        out.try_push(0xc0 | (pn_len as u8 - 1))
            .map_err(|_| QuicError::Allocation)?;
        out.try_extend_from_slice(&V1.to_be_bytes())
            .map_err(|_| QuicError::Allocation)?;
        out.try_push(self.destination_id.len() as u8)
            .map_err(|_| QuicError::Allocation)?;
        out.try_extend_from_slice(&self.destination_id)
            .map_err(|_| QuicError::Allocation)?;
        out.try_push(self.source_id.len() as u8)
            .map_err(|_| QuicError::Allocation)?;
        out.try_extend_from_slice(&self.source_id)
            .map_err(|_| QuicError::Allocation)?;
        put_varint(&mut out, 0)?;
        put_varint(&mut out, (pn_len + self.payload.len() + 16) as u64)?;
        let pn_offset = out.len();
        out.try_extend_from_slice(&(self.packet_number as u32).to_be_bytes())
            .map_err(|_| QuicError::Allocation)?;
        let aad_len = out.len();
        let mut encrypted = Vector::new();
        encrypted
            .try_reserve(self.payload.len())
            .map_err(|_| QuicError::Allocation)?;
        for _ in 0..self.payload.len() {
            encrypted.push(0)
        }
        let mut tag = [0; 16];
        if !aes128_gcm_seal(
            &keys.key,
            &keys.nonce(self.packet_number),
            &out[..aad_len],
            &self.payload,
            &mut encrypted,
            &mut tag,
        ) {
            return Err(QuicError::Crypto);
        }
        out.try_extend_from_slice(&encrypted)
            .map_err(|_| QuicError::Allocation)?;
        out.try_extend_from_slice(&tag)
            .map_err(|_| QuicError::Allocation)?;
        if out.len() < pn_offset + 4 + 16 {
            return Err(QuicError::InvalidPacket);
        }
        let mut sample = [0; 16];
        sample.copy_from_slice(&out[pn_offset + 4..pn_offset + 20]);
        let mask = aes128_encrypt_block(&keys.header, &sample);
        out[0] ^= mask[0] & 0x0f;
        for i in 0..pn_len {
            out[pn_offset + i] ^= mask[i + 1]
        }
        Ok(out)
    }

    pub fn open(
        input: &[u8],
        keys: &QuicInitialKeys,
        expected_packet_number: u64,
    ) -> Result<(Self, usize), QuicError> {
        if input.len() < 7 || input[0] & 0xc0 != 0xc0 || input[0] & 0x30 != 0 {
            return Err(QuicError::InvalidPacket);
        }
        if u32::from_be_bytes([input[1], input[2], input[3], input[4]]) != V1 {
            return Err(QuicError::InvalidPacket);
        }
        let mut at = 5;
        let destination_length = *input.get(at).ok_or(QuicError::Truncated)? as usize;
        at += 1;
        if destination_length > 20 || input.len().saturating_sub(at) < destination_length + 1 {
            return Err(QuicError::InvalidPacket);
        }
        let mut destination_id = Vector::new();
        destination_id
            .try_extend_from_slice(&input[at..at + destination_length])
            .map_err(|_| QuicError::Allocation)?;
        at += destination_length;
        let source_length = input[at] as usize;
        at += 1;
        if source_length > 20 || input.len().saturating_sub(at) < source_length {
            return Err(QuicError::InvalidPacket);
        }
        let mut source_id = Vector::new();
        source_id
            .try_extend_from_slice(&input[at..at + source_length])
            .map_err(|_| QuicError::Allocation)?;
        at += source_length;
        let token_length =
            usize::try_from(take_varint(input, &mut at)?).map_err(|_| QuicError::Limit)?;
        if token_length != 0 || input.len().saturating_sub(at) < token_length {
            return Err(QuicError::InvalidPacket);
        }
        at += token_length;
        let protected_length =
            usize::try_from(take_varint(input, &mut at)?).map_err(|_| QuicError::Limit)?;
        let packet_end = at.checked_add(protected_length).ok_or(QuicError::Limit)?;
        if packet_end > input.len() || protected_length < 1 + 16 || at + 4 + 16 > packet_end {
            return Err(QuicError::Truncated);
        }
        let packet_number_offset = at;
        let mut sample = [0; 16];
        sample.copy_from_slice(&input[packet_number_offset + 4..packet_number_offset + 20]);
        let mask = aes128_encrypt_block(&keys.header, &sample);
        let first = input[0] ^ (mask[0] & 0x0f);
        if first & 0x0c != 0 {
            return Err(QuicError::InvalidPacket);
        }
        let packet_number_length = (first as usize & 3) + 1;
        if protected_length < packet_number_length + 16 {
            return Err(QuicError::Truncated);
        }
        let mut truncated = 0u64;
        let mut unprotected_number = [0u8; 4];
        for index in 0..packet_number_length {
            let byte = input[packet_number_offset + index] ^ mask[index + 1];
            unprotected_number[4 - packet_number_length + index] = byte;
            truncated = (truncated << 8) | byte as u64;
        }
        let packet_number =
            reconstruct_packet_number(truncated, packet_number_length, expected_packet_number)?;
        let aad_end = packet_number_offset + packet_number_length;
        let mut aad = Vector::new();
        aad.try_extend_from_slice(&input[..aad_end])
            .map_err(|_| QuicError::Allocation)?;
        aad[0] = first;
        aad[packet_number_offset..aad_end]
            .copy_from_slice(&unprotected_number[4 - packet_number_length..]);
        let encrypted_end = packet_end - 16;
        let encrypted = &input[aad_end..encrypted_end];
        let mut tag = [0; 16];
        tag.copy_from_slice(&input[encrypted_end..packet_end]);
        let mut payload = Vector::new();
        payload
            .try_reserve(encrypted.len())
            .map_err(|_| QuicError::Allocation)?;
        for _ in 0..encrypted.len() {
            payload.push(0);
        }
        if !aes128_gcm_open(
            &keys.key,
            &keys.nonce(packet_number),
            &aad,
            encrypted,
            &tag,
            &mut payload,
        ) {
            return Err(QuicError::Crypto);
        }
        Ok((
            Self {
                destination_id,
                source_id,
                packet_number,
                payload,
            },
            packet_end,
        ))
    }
}

fn reconstruct_packet_number(
    truncated: u64,
    encoded_bytes: usize,
    expected: u64,
) -> Result<u64, QuicError> {
    if !(1..=4).contains(&encoded_bytes) || expected >= (1 << 62) {
        return Err(QuicError::InvalidPacket);
    }
    let window = 1u64 << (encoded_bytes * 8);
    let half = window / 2;
    let mask = window - 1;
    let candidate = (expected & !mask) | truncated;
    if candidate + half <= expected && candidate < (1 << 62) - window {
        Ok(candidate + window)
    } else if candidate > expected + half && candidate >= window {
        Ok(candidate - window)
    } else {
        Ok(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(s: &str) -> Vector<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }
    #[test]
    fn rfc9001_initial_secrets() {
        let k = QuicInitialKeys::derive(&hex("8394c8f03e515708"), QuicRole::Client).unwrap();
        assert_eq!(&k.key[..], &hex("1f369613dd76d5467730efcbe3b1a22d")[..]);
        assert_eq!(&k.iv[..], &hex("fa044b2f42a3fd3b46fb255c")[..]);
        assert_eq!(&k.header[..], &hex("9f50449e04a0e810283a1e9933adedd2")[..])
    }
    #[test]
    fn frames_round_trip_and_reject_truncation() {
        let frames = [
            QuicFrame::Ping,
            QuicFrame::Crypto {
                offset: 4,
                data: [b't', b'l', b's'].into(),
            },
            QuicFrame::PathChallenge([7; 8]),
        ];
        let mut wire = Vector::new();
        for f in &frames {
            f.encode(&mut wire).unwrap()
        }
        let mut at = 0;
        for expected in frames {
            assert_eq!(QuicFrame::decode(&wire, &mut at).unwrap(), expected)
        }
        assert_eq!(at, wire.len());
        let mut at = 0;
        assert!(QuicFrame::decode(&[6, 0, 4, 1], &mut at).is_err())
    }
    #[test]
    fn initial_packet_seals_deterministically() {
        let keys = QuicInitialKeys::derive(&[1, 2, 3, 4], QuicRole::Client).unwrap();
        let p = InitialPacket {
            destination_id: [1, 2, 3, 4].into(),
            source_id: [9, 8, 7, 6].into(),
            packet_number: 7,
            payload: [1, 2, 3, 4, 5].into(),
        };
        let a = p.seal(&keys).unwrap();
        let b = p.seal(&keys).unwrap();
        assert_eq!(a, b);
        assert!(a.len() > p.payload.len() + 16);
        let (opened, used) = InitialPacket::open(&a, &keys, 7).unwrap();
        assert_eq!(used, a.len());
        assert_eq!(opened, p);
        let mut corrupted = a.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        assert_eq!(
            InitialPacket::open(&corrupted, &keys, 7),
            Err(QuicError::Crypto)
        );
    }
}
