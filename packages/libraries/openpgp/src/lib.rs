#![no_std]

//! Bounded, allocation-free OpenPGP detached signatures for MRML Git metadata.
//!
//! The implemented profile is deliberately narrow: version 4 Ed25519Legacy
//! primary keys and binary-document signatures with SHA-256, SHA-384, or
//! SHA-512.  The library parses untrusted packet and armor bytes without a
//! keyring, process, filesystem, network, or ambient trust database.  A pinned
//! fingerprint identifies an expected key; it does not grant authority.
//!
//! Public-key parsing extracts one pinned primary key. It does not authenticate
//! an OpenPGP certificate, self-certifications, subkeys, or revocation packets.
//! The caller's owner-controlled generational policy is authoritative for
//! revocation and key validity. This compatibility profile exists for the
//! project's current v4 key; new long-lived MRML trust roots should not be
//! created with it. The whole-message limit is suitable for Git commits and
//! annotated tags, not kernels, packages, or system images.

mod sha1;

use core::fmt;

use mrml_crypto::{
    Sha256, Sha384, Sha512, ed25519_public, ed25519_public_is_valid, ed25519_sign, ed25519_verify,
};
use sha1::Sha1;

pub const MAX_OPENPGP_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_OPENPGP_PUBLIC_KEY_BYTES: usize = 64 * 1024;
pub const MAX_OPENPGP_SIGNATURE_BYTES: usize = 1024;

const PUBLIC_KEY_BEGIN: &[u8] = b"-----BEGIN PGP PUBLIC KEY BLOCK-----";
const PUBLIC_KEY_END: &[u8] = b"-----END PGP PUBLIC KEY BLOCK-----";
const SIGNATURE_BEGIN: &[u8] = b"-----BEGIN PGP SIGNATURE-----";
const SIGNATURE_END: &[u8] = b"-----END PGP SIGNATURE-----";
const ED25519_LEGACY_OID: [u8; 9] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DigestAlgorithm {
    Sha256 = 8,
    Sha384 = 9,
    Sha512 = 10,
}

impl DigestAlgorithm {
    pub const fn from_openpgp_id(id: u8) -> Option<Self> {
        match id {
            8 => Some(Self::Sha256),
            9 => Some(Self::Sha384),
            10 => Some(Self::Sha512),
            _ => None,
        }
    }

    pub const fn v6_salt_bytes(self) -> usize {
        match self {
            Self::Sha256 => 16,
            Self::Sha384 => 24,
            Self::Sha512 => 32,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fingerprint([u8; 20]);

impl Fingerprint {
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    pub fn parse_hex(value: &str) -> Result<Self, Error> {
        let mut bytes = [0u8; 20];
        let mut nibble = None;
        let mut written = 0usize;
        for byte in value.bytes() {
            if matches!(byte, b' ' | b':') {
                continue;
            }
            let value = hex_value(byte).ok_or(Error::InvalidFingerprint)?;
            if let Some(high) = nibble.take() {
                if written == bytes.len() {
                    return Err(Error::InvalidFingerprint);
                }
                bytes[written] = (high << 4) | value;
                written += 1;
            } else {
                nibble = Some(value);
            }
        }
        if nibble.is_some() || written != bytes.len() {
            return Err(Error::InvalidFingerprint);
        }
        Ok(Self(bytes))
    }

    pub fn write_hex(&self, output: &mut [u8]) -> Result<usize, Error> {
        if output.len() < 40 {
            return Err(Error::OutputTooSmall);
        }
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        for (index, byte) in self.0.iter().copied().enumerate() {
            output[index * 2] = HEX[(byte >> 4) as usize];
            output[index * 2 + 1] = HEX[(byte & 0x0f) as usize];
        }
        Ok(40)
    }
}

/// Complete RFC 9580 version 6 fingerprint.
///
/// This is intentionally a different type from the legacy 20-byte v4
/// fingerprint so callers cannot truncate or silently substitute identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FingerprintV6([u8; 32]);

impl FingerprintV6 {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn parse_hex(value: &str) -> Result<Self, Error> {
        let mut bytes = [0u8; 32];
        let mut nibble = None;
        let mut written = 0usize;
        for byte in value.bytes() {
            if matches!(byte, b' ' | b':') {
                continue;
            }
            let value = hex_value(byte).ok_or(Error::InvalidFingerprint)?;
            if let Some(high) = nibble.take() {
                if written == bytes.len() {
                    return Err(Error::InvalidFingerprint);
                }
                bytes[written] = (high << 4) | value;
                written += 1;
            } else {
                nibble = Some(value);
            }
        }
        if nibble.is_some() || written != bytes.len() {
            return Err(Error::InvalidFingerprint);
        }
        Ok(Self(bytes))
    }

    pub fn write_hex(&self, output: &mut [u8]) -> Result<usize, Error> {
        if output.len() < 64 {
            return Err(Error::OutputTooSmall);
        }
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        for (index, byte) in self.0.iter().copied().enumerate() {
            output[index * 2] = HEX[(byte >> 4) as usize];
            output[index * 2 + 1] = HEX[(byte & 0x0f) as usize];
        }
        Ok(64)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicKeyV6 {
    created_at: u32,
    public: [u8; 32],
    fingerprint: FingerprintV6,
}

impl PublicKeyV6 {
    pub fn from_seed(seed: &[u8; 32], created_at: u32) -> Result<Self, Error> {
        Self::from_public(ed25519_public(seed), created_at)
    }

    pub fn from_public(public: [u8; 32], created_at: u32) -> Result<Self, Error> {
        if created_at == 0 {
            return Err(Error::InvalidTime);
        }
        if !ed25519_public_is_valid(&public) {
            return Err(Error::InvalidPublicKey);
        }
        let body = public_key_body_v6(public, created_at);
        Ok(Self {
            created_at,
            public,
            fingerprint: fingerprint_v6(&body),
        })
    }

    pub const fn created_at(&self) -> u32 {
        self.created_at
    }

    pub const fn public_bytes(&self) -> &[u8; 32] {
        &self.public
    }

    pub const fn fingerprint(&self) -> FingerprintV6 {
        self.fingerprint
    }
}

pub struct SigningKeyV6 {
    seed: [u8; 32],
    public: PublicKeyV6,
}

impl SigningKeyV6 {
    pub fn from_seed(mut seed: [u8; 32], created_at: u32) -> Result<Self, Error> {
        match PublicKeyV6::from_seed(&seed, created_at) {
            Ok(public) => Ok(Self { seed, public }),
            Err(error) => {
                wipe_sensitive(&mut seed);
                Err(error)
            }
        }
    }

    pub const fn public_key(&self) -> PublicKeyV6 {
        self.public
    }
}

impl Drop for SigningKeyV6 {
    fn drop(&mut self) {
        wipe_sensitive(&mut self.seed);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationPolicyV6 {
    pub expected_primary_fingerprint: FingerprintV6,
    pub validation_time: Option<u64>,
    pub key_not_after: Option<u64>,
    pub key_revoked: bool,
    pub enforce_signature_expiration: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedSignatureV6 {
    pub primary_fingerprint: FingerprintV6,
    pub digest_algorithm: DigestAlgorithm,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicKey {
    created_at: u32,
    public: [u8; 32],
    fingerprint: Fingerprint,
}

impl PublicKey {
    /// Reconstructs a selected v4 compatibility key from a seed.
    ///
    /// Do not use this profile to provision a new long-lived MRML trust root.
    pub fn from_seed(seed: &[u8; 32], created_at: u32) -> Result<Self, Error> {
        if created_at == 0 {
            return Err(Error::InvalidTime);
        }
        Self::from_public(ed25519_public(seed), created_at)
    }

    pub fn from_public(public: [u8; 32], created_at: u32) -> Result<Self, Error> {
        if created_at == 0 {
            return Err(Error::InvalidTime);
        }
        if !ed25519_public_is_valid(&public) {
            return Err(Error::InvalidPublicKey);
        }
        let body = public_key_body(public, created_at);
        Ok(Self {
            created_at,
            public,
            fingerprint: fingerprint_v4(&body),
        })
    }

    pub const fn created_at(&self) -> u32 {
        self.created_at
    }

    pub const fn public_bytes(&self) -> &[u8; 32] {
        &self.public
    }

    pub const fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    pub fn encode_ascii(&self, output: &mut [u8]) -> Result<usize, Error> {
        let body = public_key_body(self.public, self.created_at);
        let mut packet = [0u8; 53];
        packet[0] = 0x98;
        packet[1] = body.len() as u8;
        packet[2..].copy_from_slice(&body);
        encode_armor(PUBLIC_KEY_BEGIN, PUBLIC_KEY_END, &packet, output)
    }
}

/// In-memory secret use for host bootstrap and service implementations.
///
/// A deployed MRML service must expose use only through a separately delivered
/// capability-bound route. No method exports the seed, and dropping this value
/// performs best-effort volatile erasure of its owned copy. Isolated custody is
/// still required because compiler, register, cache, swap, and crash-dump copies
/// are outside this type.
pub struct SigningKey {
    seed: [u8; 32],
    public: PublicKey,
}

impl SigningKey {
    pub fn from_seed(mut seed: [u8; 32], created_at: u32) -> Result<Self, Error> {
        match PublicKey::from_seed(&seed, created_at) {
            Ok(public) => Ok(Self { seed, public }),
            Err(error) => {
                wipe_sensitive(&mut seed);
                Err(error)
            }
        }
    }

    pub fn from_seed_and_public_key(mut seed: [u8; 32], public: PublicKey) -> Result<Self, Error> {
        if !constant_time_equal(&ed25519_public(&seed), public.public_bytes()) {
            wipe_sensitive(&mut seed);
            return Err(Error::KeyMismatch);
        }
        Ok(Self { seed, public })
    }

    /// Imports one exact raw seed and best-effort wipes the caller's buffer on
    /// every success or error path.
    pub fn from_seed_bytes_and_public_key(
        seed_bytes: &mut [u8],
        public: PublicKey,
    ) -> Result<Self, Error> {
        if seed_bytes.len() != 32 {
            wipe_sensitive(seed_bytes);
            return Err(Error::InvalidSecretKey);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(seed_bytes);
        wipe_sensitive(seed_bytes);
        Self::from_seed_and_public_key(seed, public)
    }

    pub const fn public_key(&self) -> PublicKey {
        self.public
    }

    /// Encode a minimal transferable public key with one owner-selected user
    /// ID and a positive-certification self-signature. This is for stock
    /// OpenPGP tooling that refuses a bare primary key; the user ID identifies
    /// the key and grants no MRML authority.
    pub fn encode_transferable_public_key_ascii(
        &self,
        user_id: &str,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        if user_id.is_empty()
            || user_id.len() > 128
            || user_id.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        {
            return Err(Error::InvalidPublicKey);
        }
        let key_body = public_key_body(self.public.public, self.public.created_at);
        let mut signed = [0u8; 184];
        signed[0] = 0x99;
        signed[1..3].copy_from_slice(&(key_body.len() as u16).to_be_bytes());
        signed[3..54].copy_from_slice(&key_body);
        signed[54] = 0xb4;
        signed[55..59].copy_from_slice(&(user_id.len() as u32).to_be_bytes());
        signed[59..59 + user_id.len()].copy_from_slice(user_id.as_bytes());

        let mut signature_body = [0u8; 192];
        signature_body[0] = 4;
        signature_body[1] = 0x13;
        signature_body[2] = 22;
        signature_body[3] = DigestAlgorithm::Sha512 as u8;
        signature_body[4..6].copy_from_slice(&29u16.to_be_bytes());
        signature_body[6] = 22;
        signature_body[7] = 33;
        signature_body[8] = 4;
        signature_body[9..29].copy_from_slice(self.public.fingerprint.as_bytes());
        signature_body[29] = 5;
        signature_body[30] = 2;
        signature_body[31..35].copy_from_slice(&self.public.created_at.to_be_bytes());
        let digest = signature_digest(
            DigestAlgorithm::Sha512,
            &signed[..59 + user_id.len()],
            &signature_body[..35],
        )?;
        signature_body[35..37].copy_from_slice(&10u16.to_be_bytes());
        signature_body[37] = 9;
        signature_body[38] = 16;
        signature_body[39..47].copy_from_slice(&self.public.fingerprint.as_bytes()[12..]);
        signature_body[47..49].copy_from_slice(&digest.bytes[..2]);
        let signature = ed25519_sign(&self.seed, digest.as_slice());
        let mut signature_len = 49;
        signature_len += encode_mpi(&signature[..32], &mut signature_body[signature_len..])?;
        signature_len += encode_mpi(&signature[32..], &mut signature_body[signature_len..])?;

        let mut packets = [0u8; 512];
        packets[0] = 0x98;
        packets[1] = key_body.len() as u8;
        packets[2..53].copy_from_slice(&key_body);
        let mut used = 53;
        packets[used] = 0xcd;
        packets[used + 1] = user_id.len() as u8;
        packets[used + 2..used + 2 + user_id.len()].copy_from_slice(user_id.as_bytes());
        used += 2 + user_id.len();
        packets[used] = 0x88;
        packets[used + 1] = u8::try_from(signature_len).map_err(|_| Error::InvalidSignature)?;
        packets[used + 2..used + 2 + signature_len]
            .copy_from_slice(&signature_body[..signature_len]);
        used += 2 + signature_len;
        encode_armor(PUBLIC_KEY_BEGIN, PUBLIC_KEY_END, &packets[..used], output)
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        wipe_sensitive(&mut self.seed);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationPolicy {
    pub expected_primary_fingerprint: Fingerprint,
    /// Caller-selected trusted time.  Absence does not make expiry claims.
    pub validation_time: Option<u64>,
    /// Optional owner-policy cutoff for signatures made by the pinned key.
    pub key_not_after: Option<u64>,
    /// Revocation state from the owner-controlled generational trust policy.
    pub key_revoked: bool,
    /// Whether an authenticated signature-expiration subpacket is enforced.
    pub enforce_signature_expiration: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedSignature {
    pub primary_fingerprint: Fingerprint,
    pub digest_algorithm: DigestAlgorithm,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InputTooLarge,
    OutputTooSmall,
    InvalidArmor,
    InvalidPacket,
    InvalidPublicKey,
    InvalidSignature,
    InvalidFingerprint,
    InvalidSecretKey,
    UnsupportedVersion,
    UnsupportedAlgorithm,
    UnsupportedDigest,
    UnsupportedSignatureType,
    SecretKeyMaterial,
    AmbiguousKey,
    AmbiguousSignature,
    FingerprintMismatch,
    KeyMismatch,
    MissingIssuerFingerprint,
    UnknownCriticalSubpacket,
    InvalidTime,
    ExpiredKey,
    ExpiredSignature,
    RevokedKey,
    FutureSignature,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InputTooLarge => "OpenPGP input exceeds its bounded limit",
            Self::OutputTooSmall => "OpenPGP output buffer is too small",
            Self::InvalidArmor => "invalid OpenPGP ASCII armor",
            Self::InvalidPacket => "invalid or noncanonical OpenPGP packet",
            Self::InvalidPublicKey => "invalid OpenPGP public key",
            Self::InvalidSignature => "invalid OpenPGP signature",
            Self::InvalidFingerprint => "invalid OpenPGP fingerprint",
            Self::InvalidSecretKey => "OpenPGP private seed must contain exactly 32 raw bytes",
            Self::UnsupportedVersion => "unsupported OpenPGP version",
            Self::UnsupportedAlgorithm => "unsupported OpenPGP public-key algorithm",
            Self::UnsupportedDigest => "unsupported OpenPGP digest algorithm",
            Self::UnsupportedSignatureType => "unsupported OpenPGP signature type",
            Self::SecretKeyMaterial => "secret OpenPGP key material is not accepted here",
            Self::AmbiguousKey => "OpenPGP input contains an ambiguous primary key",
            Self::AmbiguousSignature => "OpenPGP input contains an ambiguous signature",
            Self::FingerprintMismatch => "OpenPGP fingerprint does not match owner policy",
            Self::KeyMismatch => "OpenPGP seed does not match the selected public key",
            Self::MissingIssuerFingerprint => "OpenPGP signature lacks a hashed issuer fingerprint",
            Self::UnknownCriticalSubpacket => "unsupported critical OpenPGP signature subpacket",
            Self::InvalidTime => "invalid OpenPGP signature time",
            Self::ExpiredKey => "OpenPGP key is expired under owner policy",
            Self::ExpiredSignature => "OpenPGP signature has expired",
            Self::RevokedKey => "OpenPGP key is revoked under owner policy",
            Self::FutureSignature => "OpenPGP signature is from the future",
        })
    }
}

impl core::error::Error for Error {}

pub fn parse_public_key_ascii(input: &[u8], scratch: &mut [u8]) -> Result<PublicKey, Error> {
    if input.is_empty() || input.len() > MAX_OPENPGP_PUBLIC_KEY_BYTES {
        return Err(Error::InputTooLarge);
    }
    let decoded = decode_armor(PUBLIC_KEY_BEGIN, PUBLIC_KEY_END, input, scratch)?;
    parse_public_key_packets(decoded)
}

/// Parses one RFC 9580 v6 Ed25519 primary key from a transferable public key.
/// Certificate signatures and subkeys are not treated as authorization here.
pub fn parse_public_key_v6_ascii(input: &[u8], scratch: &mut [u8]) -> Result<PublicKeyV6, Error> {
    if input.is_empty() || input.len() > MAX_OPENPGP_PUBLIC_KEY_BYTES {
        return Err(Error::InputTooLarge);
    }
    let decoded = decode_armor(PUBLIC_KEY_BEGIN, PUBLIC_KEY_END, input, scratch)?;
    let mut offset = 0usize;
    let mut primary = None;
    while offset < decoded.len() {
        let (tag, body, end) = parse_packet(decoded, offset)?;
        if offset == 0 && tag != 6 {
            return Err(Error::InvalidPublicKey);
        }
        match tag {
            5 | 7 => return Err(Error::SecretKeyMaterial),
            6 => {
                if primary.is_some() {
                    return Err(Error::AmbiguousKey);
                }
                primary = Some(parse_primary_key_v6(body)?);
            }
            2 | 13 | 14 | 17 | 21 => {}
            _ => return Err(Error::InvalidPublicKey),
        }
        offset = end;
    }
    primary.ok_or(Error::InvalidPublicKey)
}

fn parse_primary_key_v6(body: &[u8]) -> Result<PublicKeyV6, Error> {
    // version, creation time, algorithm, material length, Ed25519 public key
    if body.len() != 42 || body[0] != 6 {
        return Err(if body.first() == Some(&6) {
            Error::InvalidPublicKey
        } else {
            Error::UnsupportedVersion
        });
    }
    let created_at =
        u32::from_be_bytes(body[1..5].try_into().map_err(|_| Error::InvalidPublicKey)?);
    if created_at == 0 {
        return Err(Error::InvalidTime);
    }
    if body[5] != 27 {
        return Err(Error::UnsupportedAlgorithm);
    }
    if u32::from_be_bytes(
        body[6..10]
            .try_into()
            .map_err(|_| Error::InvalidPublicKey)?,
    ) != 32
    {
        return Err(Error::InvalidPublicKey);
    }
    let public: [u8; 32] = body[10..42]
        .try_into()
        .map_err(|_| Error::InvalidPublicKey)?;
    if !ed25519_public_is_valid(&public) {
        return Err(Error::InvalidPublicKey);
    }
    let mut fingerprint_input = [0u8; 47];
    fingerprint_input[0] = 0x9b;
    fingerprint_input[1..5].copy_from_slice(&42u32.to_be_bytes());
    fingerprint_input[5..].copy_from_slice(body);
    Ok(PublicKeyV6 {
        created_at,
        public,
        fingerprint: FingerprintV6(Sha256::digest(&fingerprint_input)),
    })
}

pub fn sign_detached_v6_ascii_with_salt(
    key: &SigningKeyV6,
    payload: &[u8],
    digest_algorithm: DigestAlgorithm,
    created_at: u64,
    salt: &[u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    if payload.len() > MAX_OPENPGP_PAYLOAD_BYTES {
        return Err(Error::InputTooLarge);
    }
    if salt.len() != digest_algorithm.v6_salt_bytes() {
        return Err(Error::InvalidSignature);
    }
    let created_at = u32::try_from(created_at).map_err(|_| Error::InvalidTime)?;
    if created_at == 0 || created_at < key.public.created_at {
        return Err(Error::InvalidTime);
    }
    let mut body = [0u8; 192];
    body[0] = 6;
    body[1] = 0;
    body[2] = 27;
    body[3] = digest_algorithm as u8;
    body[4..8].copy_from_slice(&41u32.to_be_bytes());
    body[8] = 5;
    body[9] = 2;
    body[10..14].copy_from_slice(&created_at.to_be_bytes());
    body[14] = 34;
    body[15] = 33;
    body[16] = 6;
    body[17..49].copy_from_slice(key.public.fingerprint.as_bytes());
    let hashed_end = 49;
    let digest = signature_digest_v6(digest_algorithm, salt, payload, &body[..hashed_end])?;
    body[49..53].copy_from_slice(&0u32.to_be_bytes());
    body[53..55].copy_from_slice(&digest.bytes[..2]);
    body[55] = salt.len() as u8;
    body[56..56 + salt.len()].copy_from_slice(salt);
    let signature = ed25519_sign(&key.seed, digest.as_slice());
    let used = 56 + salt.len() + signature.len();
    body[56 + salt.len()..used].copy_from_slice(&signature);
    let mut packet = [0u8; 194];
    packet[0] = 0xc2;
    packet[1] = u8::try_from(used).map_err(|_| Error::InvalidSignature)?;
    packet[2..2 + used].copy_from_slice(&body[..used]);
    encode_armor(SIGNATURE_BEGIN, SIGNATURE_END, &packet[..2 + used], output)
}

pub fn verify_detached_v6_ascii(
    public_key: &PublicKeyV6,
    payload: &[u8],
    signature: &[u8],
    policy: &VerificationPolicyV6,
    scratch: &mut [u8],
) -> Result<VerifiedSignatureV6, Error> {
    if payload.len() > MAX_OPENPGP_PAYLOAD_BYTES
        || signature.is_empty()
        || signature.len() > MAX_OPENPGP_SIGNATURE_BYTES
    {
        return Err(Error::InputTooLarge);
    }
    if public_key.fingerprint != policy.expected_primary_fingerprint {
        return Err(Error::FingerprintMismatch);
    }
    if policy.key_revoked {
        return Err(Error::RevokedKey);
    }
    let decoded = decode_armor(SIGNATURE_BEGIN, SIGNATURE_END, signature, scratch)?;
    let (tag, body, end) = parse_packet(decoded, 0)?;
    if tag != 2 || end != decoded.len() {
        return Err(Error::AmbiguousSignature);
    }
    let parsed = parse_signature_body_v6(body, &public_key.fingerprint)?;
    if parsed.created_at < u64::from(public_key.created_at) {
        return Err(Error::InvalidTime);
    }
    if policy
        .validation_time
        .is_some_and(|now| parsed.created_at > now)
    {
        return Err(Error::FutureSignature);
    }
    if policy
        .key_not_after
        .is_some_and(|not_after| parsed.created_at >= not_after)
    {
        return Err(Error::ExpiredKey);
    }
    if policy.enforce_signature_expiration
        && policy
            .validation_time
            .zip(parsed.expires_at)
            .is_some_and(|(now, expires)| now >= expires)
    {
        return Err(Error::ExpiredSignature);
    }
    let digest = signature_digest_v6(
        parsed.digest_algorithm,
        parsed.salt,
        payload,
        parsed.hashed_header,
    )?;
    if !constant_time_equal(&digest.bytes[..2], parsed.digest_prefix)
        || !ed25519_verify(
            public_key.public_bytes(),
            digest.as_slice(),
            &parsed.signature,
        )
    {
        return Err(Error::InvalidSignature);
    }
    Ok(VerifiedSignatureV6 {
        primary_fingerprint: public_key.fingerprint,
        digest_algorithm: parsed.digest_algorithm,
        created_at: parsed.created_at,
        expires_at: parsed.expires_at,
    })
}

struct ParsedSignatureV6<'a> {
    digest_algorithm: DigestAlgorithm,
    created_at: u64,
    expires_at: Option<u64>,
    hashed_header: &'a [u8],
    digest_prefix: &'a [u8],
    salt: &'a [u8],
    signature: [u8; 64],
}

fn parse_signature_body_v6<'a>(
    body: &'a [u8],
    expected_fingerprint: &FingerprintV6,
) -> Result<ParsedSignatureV6<'a>, Error> {
    if body.len() < 4 + 4 + 4 + 2 + 1 + 16 + 64 || body[0] != 6 {
        return Err(Error::UnsupportedVersion);
    }
    if body[1] != 0 {
        return Err(Error::UnsupportedSignatureType);
    }
    if body[2] != 27 {
        return Err(Error::UnsupportedAlgorithm);
    }
    let digest_algorithm =
        DigestAlgorithm::from_openpgp_id(body[3]).ok_or(Error::UnsupportedDigest)?;
    let hashed_length = usize::try_from(u32::from_be_bytes(
        body[4..8].try_into().map_err(|_| Error::InvalidSignature)?,
    ))
    .map_err(|_| Error::InvalidSignature)?;
    let hashed_end = 8usize
        .checked_add(hashed_length)
        .ok_or(Error::InvalidSignature)?;
    let hashed_bytes = body.get(8..hashed_end).ok_or(Error::InvalidSignature)?;
    let (created_at, expires_at) = parse_subpackets_v6(hashed_bytes, expected_fingerprint)?;
    let unhashed_length_end = hashed_end.checked_add(4).ok_or(Error::InvalidSignature)?;
    let unhashed_length = usize::try_from(u32::from_be_bytes(
        body.get(hashed_end..unhashed_length_end)
            .ok_or(Error::InvalidSignature)?
            .try_into()
            .map_err(|_| Error::InvalidSignature)?,
    ))
    .map_err(|_| Error::InvalidSignature)?;
    if unhashed_length != 0 {
        return Err(Error::InvalidSignature);
    }
    let prefix_start = unhashed_length_end;
    let salt_length_at = prefix_start.checked_add(2).ok_or(Error::InvalidSignature)?;
    let digest_prefix = body
        .get(prefix_start..salt_length_at)
        .ok_or(Error::InvalidSignature)?;
    let salt_length = usize::from(*body.get(salt_length_at).ok_or(Error::InvalidSignature)?);
    if salt_length != digest_algorithm.v6_salt_bytes() {
        return Err(Error::InvalidSignature);
    }
    let salt_start = salt_length_at + 1;
    let salt_end = salt_start
        .checked_add(salt_length)
        .ok_or(Error::InvalidSignature)?;
    let signature_end = salt_end.checked_add(64).ok_or(Error::InvalidSignature)?;
    if signature_end != body.len() {
        return Err(Error::InvalidSignature);
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&body[salt_end..signature_end]);
    Ok(ParsedSignatureV6 {
        digest_algorithm,
        created_at,
        expires_at,
        hashed_header: &body[..hashed_end],
        digest_prefix,
        salt: &body[salt_start..salt_end],
        signature,
    })
}

fn parse_subpackets_v6(
    input: &[u8],
    expected_fingerprint: &FingerprintV6,
) -> Result<(u64, Option<u64>), Error> {
    let mut offset = 0usize;
    let mut created_at = None;
    let mut expiration = None;
    let mut issuer = false;
    while offset < input.len() {
        let (length, length_bytes) = parse_subpacket_length(&input[offset..])?;
        offset = offset
            .checked_add(length_bytes)
            .ok_or(Error::InvalidSignature)?;
        let end = offset.checked_add(length).ok_or(Error::InvalidSignature)?;
        let packet = input.get(offset..end).ok_or(Error::InvalidSignature)?;
        let kind = *packet.first().ok_or(Error::InvalidSignature)?;
        let critical = kind & 0x80 != 0;
        let data = &packet[1..];
        match kind & 0x7f {
            2 => {
                if data.len() != 4 || created_at.is_some() {
                    return Err(Error::InvalidSignature);
                }
                created_at = Some(u64::from(u32::from_be_bytes(
                    data.try_into().map_err(|_| Error::InvalidSignature)?,
                )));
            }
            3 => {
                if data.len() != 4 || expiration.is_some() {
                    return Err(Error::InvalidSignature);
                }
                expiration = Some(u32::from_be_bytes(
                    data.try_into().map_err(|_| Error::InvalidSignature)?,
                ));
            }
            33 => {
                if data.len() != 33
                    || data[0] != 6
                    || issuer
                    || !constant_time_equal(&data[1..], expected_fingerprint.as_bytes())
                {
                    return Err(Error::FingerprintMismatch);
                }
                issuer = true;
            }
            _ if critical => return Err(Error::UnknownCriticalSubpacket),
            _ => {}
        }
        offset = end;
    }
    let created_at = created_at.ok_or(Error::InvalidTime)?;
    if !issuer {
        return Err(Error::MissingIssuerFingerprint);
    }
    let expires_at = match expiration {
        Some(0) | None => None,
        Some(seconds) => Some(
            created_at
                .checked_add(u64::from(seconds))
                .ok_or(Error::InvalidTime)?,
        ),
    };
    Ok((created_at, expires_at))
}

pub fn sign_detached_ascii(
    key: &SigningKey,
    payload: &[u8],
    digest_algorithm: DigestAlgorithm,
    created_at: u64,
    output: &mut [u8],
) -> Result<usize, Error> {
    if payload.len() > MAX_OPENPGP_PAYLOAD_BYTES {
        return Err(Error::InputTooLarge);
    }
    let created_at = u32::try_from(created_at).map_err(|_| Error::InvalidTime)?;
    if created_at < key.public.created_at || created_at == 0 {
        return Err(Error::InvalidTime);
    }

    let mut body = [0u8; 192];
    body[0] = 4;
    body[1] = 0;
    body[2] = 22;
    body[3] = digest_algorithm as u8;
    body[4..6].copy_from_slice(&29u16.to_be_bytes());
    body[6] = 22;
    body[7] = 33;
    body[8] = 4;
    body[9..29].copy_from_slice(key.public.fingerprint.as_bytes());
    body[29] = 5;
    body[30] = 2;
    body[31..35].copy_from_slice(&created_at.to_be_bytes());
    let hashed_end = 35usize;

    let digest = signature_digest(digest_algorithm, payload, &body[..hashed_end])?;
    body[35..37].copy_from_slice(&10u16.to_be_bytes());
    body[37] = 9;
    body[38] = 16;
    body[39..47].copy_from_slice(&key.public.fingerprint.as_bytes()[12..]);
    body[47..49].copy_from_slice(&digest.bytes[..2]);
    let signature = ed25519_sign(&key.seed, digest.as_slice());
    let mut used = 49usize;
    used += encode_mpi(&signature[..32], &mut body[used..])?;
    used += encode_mpi(&signature[32..], &mut body[used..])?;

    let mut packet = [0u8; 194];
    if used > u8::MAX as usize {
        return Err(Error::InvalidSignature);
    }
    packet[0] = 0x88;
    packet[1] = used as u8;
    packet[2..2 + used].copy_from_slice(&body[..used]);
    encode_armor(SIGNATURE_BEGIN, SIGNATURE_END, &packet[..2 + used], output)
}

pub fn verify_detached_ascii(
    public_key: &PublicKey,
    payload: &[u8],
    signature: &[u8],
    policy: &VerificationPolicy,
    scratch: &mut [u8],
) -> Result<VerifiedSignature, Error> {
    if payload.len() > MAX_OPENPGP_PAYLOAD_BYTES
        || signature.is_empty()
        || signature.len() > MAX_OPENPGP_SIGNATURE_BYTES
    {
        return Err(Error::InputTooLarge);
    }
    if public_key.fingerprint != policy.expected_primary_fingerprint {
        return Err(Error::FingerprintMismatch);
    }
    if policy.key_revoked {
        return Err(Error::RevokedKey);
    }
    if let Some(not_after) = policy.key_not_after {
        if not_after <= u64::from(public_key.created_at) {
            return Err(Error::InvalidTime);
        }
    }
    let decoded = decode_armor(SIGNATURE_BEGIN, SIGNATURE_END, signature, scratch)?;
    let (tag, body, end) = parse_packet(decoded, 0)?;
    if tag != 2 || end != decoded.len() {
        return Err(Error::AmbiguousSignature);
    }
    let parsed = parse_signature_body(body, 0, &public_key.fingerprint)?;
    if parsed.created_at < u64::from(public_key.created_at) {
        return Err(Error::InvalidTime);
    }
    if let Some(now) = policy.validation_time {
        if parsed.created_at > now {
            return Err(Error::FutureSignature);
        }
    }
    if policy
        .key_not_after
        .is_some_and(|not_after| parsed.created_at >= not_after)
    {
        return Err(Error::ExpiredKey);
    }
    if policy.enforce_signature_expiration
        && policy
            .validation_time
            .zip(parsed.expires_at)
            .is_some_and(|(now, expires_at)| now >= expires_at)
    {
        return Err(Error::ExpiredSignature);
    }
    let digest = signature_digest(parsed.digest_algorithm, payload, parsed.hashed_header)?;
    if !constant_time_equal(&digest.bytes[..2], parsed.digest_prefix) {
        return Err(Error::InvalidSignature);
    }
    if !ed25519_verify(&public_key.public, digest.as_slice(), &parsed.signature) {
        return Err(Error::InvalidSignature);
    }
    Ok(VerifiedSignature {
        primary_fingerprint: public_key.fingerprint,
        digest_algorithm: parsed.digest_algorithm,
        created_at: parsed.created_at,
        expires_at: parsed.expires_at,
    })
}

pub fn verify_detached_ascii_with_public_key(
    public_key_armor: &[u8],
    payload: &[u8],
    signature: &[u8],
    policy: &VerificationPolicy,
    public_key_scratch: &mut [u8],
    signature_scratch: &mut [u8],
) -> Result<VerifiedSignature, Error> {
    let public_key = parse_public_key_ascii(public_key_armor, public_key_scratch)?;
    verify_detached_ascii(&public_key, payload, signature, policy, signature_scratch)
}

fn public_key_body(public: [u8; 32], created_at: u32) -> [u8; 51] {
    let mut body = [0u8; 51];
    body[0] = 4;
    body[1..5].copy_from_slice(&created_at.to_be_bytes());
    body[5] = 22;
    body[6] = ED25519_LEGACY_OID.len() as u8;
    body[7..16].copy_from_slice(&ED25519_LEGACY_OID);
    body[16..18].copy_from_slice(&263u16.to_be_bytes());
    body[18] = 0x40;
    body[19..].copy_from_slice(&public);
    body
}

fn public_key_body_v6(public: [u8; 32], created_at: u32) -> [u8; 42] {
    let mut body = [0u8; 42];
    body[0] = 6;
    body[1..5].copy_from_slice(&created_at.to_be_bytes());
    body[5] = 27;
    body[6..10].copy_from_slice(&32u32.to_be_bytes());
    body[10..].copy_from_slice(&public);
    body
}

fn fingerprint_v6(body: &[u8; 42]) -> FingerprintV6 {
    let mut input = [0u8; 47];
    input[0] = 0x9b;
    input[1..5].copy_from_slice(&42u32.to_be_bytes());
    input[5..].copy_from_slice(body);
    FingerprintV6(Sha256::digest(&input))
}

fn fingerprint_v4(body: &[u8; 51]) -> Fingerprint {
    let mut hash = Sha1::new();
    hash.update(&[0x99]);
    hash.update(&(body.len() as u16).to_be_bytes());
    hash.update(body);
    Fingerprint(hash.finalize())
}

fn parse_public_key_packets(input: &[u8]) -> Result<PublicKey, Error> {
    let mut offset = 0usize;
    let mut primary = None;
    while offset < input.len() {
        let (tag, body, end) = parse_packet(input, offset)?;
        if offset == 0 && tag != 6 {
            return Err(Error::InvalidPublicKey);
        }
        match tag {
            5 | 7 => return Err(Error::SecretKeyMaterial),
            6 => {
                if primary.is_some() {
                    return Err(Error::AmbiguousKey);
                }
                primary = Some(parse_primary_key(body)?);
            }
            2 | 13 | 14 | 17 => {}
            _ => return Err(Error::InvalidPublicKey),
        }
        offset = end;
    }
    primary.ok_or(Error::InvalidPublicKey)
}

fn parse_primary_key(body: &[u8]) -> Result<PublicKey, Error> {
    if body.len() != 51 {
        return Err(Error::InvalidPublicKey);
    }
    if body[0] != 4 {
        return Err(Error::UnsupportedVersion);
    }
    if body[5] != 22 {
        return Err(Error::UnsupportedAlgorithm);
    }
    if body[6] != 9
        || body[7..16] != ED25519_LEGACY_OID
        || body[16..18] != 263u16.to_be_bytes()
        || body[18] != 0x40
    {
        return Err(Error::InvalidPublicKey);
    }
    let created_at = u32::from_be_bytes(body[1..5].try_into().unwrap());
    if created_at == 0 {
        return Err(Error::InvalidTime);
    }
    let mut public = [0u8; 32];
    public.copy_from_slice(&body[19..51]);
    let body: &[u8; 51] = body.try_into().unwrap();
    let key = PublicKey::from_public(public, created_at)?;
    if key.fingerprint != fingerprint_v4(body) {
        return Err(Error::InvalidPublicKey);
    }
    Ok(key)
}

#[derive(Debug)]
struct ParsedSignature<'a> {
    digest_algorithm: DigestAlgorithm,
    created_at: u64,
    expires_at: Option<u64>,
    hashed_header: &'a [u8],
    digest_prefix: &'a [u8],
    signature: [u8; 64],
}

fn parse_signature_body<'a>(
    body: &'a [u8],
    expected_type: u8,
    expected_fingerprint: &Fingerprint,
) -> Result<ParsedSignature<'a>, Error> {
    if body.len() < 12 || body[0] != 4 {
        return Err(Error::UnsupportedVersion);
    }
    if body[1] != expected_type {
        return Err(Error::UnsupportedSignatureType);
    }
    if body[2] != 22 {
        return Err(Error::UnsupportedAlgorithm);
    }
    let digest_algorithm =
        DigestAlgorithm::from_openpgp_id(body[3]).ok_or(Error::UnsupportedDigest)?;
    let hashed_length = usize::from(u16::from_be_bytes(body[4..6].try_into().unwrap()));
    let hashed_end = 6usize
        .checked_add(hashed_length)
        .ok_or(Error::InvalidSignature)?;
    if hashed_end + 2 > body.len() {
        return Err(Error::InvalidSignature);
    }
    let hashed = parse_subpackets(&body[6..hashed_end], true, expected_fingerprint)?;
    if hashed
        .issuer
        .is_some_and(|issuer| issuer != *expected_fingerprint)
    {
        return Err(Error::FingerprintMismatch);
    }
    let created_at = hashed.created_at.ok_or(Error::InvalidTime)?;
    let expires_at = match hashed.signature_expiration {
        Some(0) | None => None,
        Some(seconds) => Some(
            created_at
                .checked_add(u64::from(seconds))
                .ok_or(Error::InvalidTime)?,
        ),
    };

    let unhashed_length = usize::from(u16::from_be_bytes(
        body[hashed_end..hashed_end + 2].try_into().unwrap(),
    ));
    let unhashed_start = hashed_end + 2;
    let unhashed_end = unhashed_start
        .checked_add(unhashed_length)
        .ok_or(Error::InvalidSignature)?;
    if unhashed_end + 2 > body.len() {
        return Err(Error::InvalidSignature);
    }
    let unhashed = parse_subpackets(
        &body[unhashed_start..unhashed_end],
        false,
        expected_fingerprint,
    )?;
    if unhashed.issuer.is_some()
        || unhashed.created_at.is_some()
        || unhashed.signature_expiration.is_some()
    {
        return Err(Error::InvalidSignature);
    }
    let mut offset = unhashed_end + 2;
    let digest_prefix = &body[unhashed_end..unhashed_end + 2];
    let mut signature = [0u8; 64];
    offset += parse_mpi(&body[offset..], &mut signature[..32])?;
    offset += parse_mpi(&body[offset..], &mut signature[32..])?;
    if offset != body.len() {
        return Err(Error::InvalidSignature);
    }
    Ok(ParsedSignature {
        digest_algorithm,
        created_at,
        expires_at,
        hashed_header: &body[..hashed_end],
        digest_prefix,
        signature,
    })
}

#[derive(Default)]
struct SubpacketValues {
    issuer: Option<Fingerprint>,
    created_at: Option<u64>,
    signature_expiration: Option<u32>,
}

fn parse_subpackets(
    input: &[u8],
    hashed: bool,
    expected_fingerprint: &Fingerprint,
) -> Result<SubpacketValues, Error> {
    let mut values = SubpacketValues::default();
    let mut offset = 0usize;
    while offset < input.len() {
        let (length, length_bytes) = parse_subpacket_length(&input[offset..])?;
        offset = offset
            .checked_add(length_bytes)
            .ok_or(Error::InvalidSignature)?;
        let end = offset.checked_add(length).ok_or(Error::InvalidSignature)?;
        let subpacket = input.get(offset..end).ok_or(Error::InvalidSignature)?;
        if subpacket.is_empty() {
            return Err(Error::InvalidSignature);
        }
        let critical = subpacket[0] & 0x80 != 0;
        let kind = subpacket[0] & 0x7f;
        let data = &subpacket[1..];
        match kind {
            2 if hashed => {
                if data.len() != 4 || values.created_at.is_some() {
                    return Err(Error::InvalidSignature);
                }
                values.created_at = Some(u64::from(u32::from_be_bytes(data.try_into().unwrap())));
            }
            3 if hashed => {
                if data.len() != 4 || values.signature_expiration.is_some() {
                    return Err(Error::InvalidSignature);
                }
                values.signature_expiration = Some(u32::from_be_bytes(data.try_into().unwrap()));
            }
            16 if !hashed => {
                if data.len() != 8
                    || !constant_time_equal(data, &expected_fingerprint.as_bytes()[12..])
                {
                    return Err(Error::FingerprintMismatch);
                }
            }
            33 if hashed => {
                if data.len() != 21 || data[0] != 4 || values.issuer.is_some() {
                    return Err(Error::InvalidSignature);
                }
                let mut fingerprint = [0u8; 20];
                fingerprint.copy_from_slice(&data[1..]);
                values.issuer = Some(Fingerprint(fingerprint));
            }
            _ if critical && hashed => return Err(Error::UnknownCriticalSubpacket),
            _ => {}
        }
        offset = end;
    }
    Ok(values)
}

fn parse_subpacket_length(input: &[u8]) -> Result<(usize, usize), Error> {
    let first = *input.first().ok_or(Error::InvalidSignature)?;
    match first {
        0..=191 => {
            if first == 0 {
                Err(Error::InvalidSignature)
            } else {
                Ok((usize::from(first), 1))
            }
        }
        192..=223 => {
            let second = *input.get(1).ok_or(Error::InvalidSignature)?;
            Ok((
                ((usize::from(first) - 192) << 8) + usize::from(second) + 192,
                2,
            ))
        }
        255 => {
            let bytes: [u8; 4] = input
                .get(1..5)
                .ok_or(Error::InvalidSignature)?
                .try_into()
                .unwrap();
            let length =
                usize::try_from(u32::from_be_bytes(bytes)).map_err(|_| Error::InvalidSignature)?;
            Ok((length, 5))
        }
        _ => Err(Error::InvalidSignature),
    }
}

fn parse_mpi(input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    let bits = u16::from_be_bytes(
        input
            .get(..2)
            .ok_or(Error::InvalidSignature)?
            .try_into()
            .unwrap(),
    );
    if bits == 0 || usize::from(bits) > output.len() * 8 {
        return Err(Error::InvalidSignature);
    }
    let bytes = usize::from(bits).div_ceil(8);
    let value = input.get(2..2 + bytes).ok_or(Error::InvalidSignature)?;
    let leading = 8 - value[0].leading_zeros() as usize;
    if (bytes - 1) * 8 + leading != usize::from(bits) {
        return Err(Error::InvalidSignature);
    }
    output.fill(0);
    let start = output.len() - bytes;
    output[start..].copy_from_slice(value);
    Ok(2 + bytes)
}

fn encode_mpi(value: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    let first = value
        .iter()
        .position(|byte| *byte != 0)
        .ok_or(Error::InvalidSignature)?;
    let bytes = &value[first..];
    let bits = (bytes.len() - 1)
        .checked_mul(8)
        .and_then(|value| value.checked_add(8 - bytes[0].leading_zeros() as usize))
        .ok_or(Error::InvalidSignature)?;
    let bits = u16::try_from(bits).map_err(|_| Error::InvalidSignature)?;
    if output.len() < 2 + bytes.len() {
        return Err(Error::OutputTooSmall);
    }
    output[..2].copy_from_slice(&bits.to_be_bytes());
    output[2..2 + bytes.len()].copy_from_slice(bytes);
    Ok(2 + bytes.len())
}

struct DigestBytes {
    bytes: [u8; 64],
    length: usize,
}

impl DigestBytes {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

enum DigestState {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl DigestState {
    fn new(algorithm: DigestAlgorithm) -> Self {
        match algorithm {
            DigestAlgorithm::Sha256 => Self::Sha256(Sha256::new()),
            DigestAlgorithm::Sha384 => Self::Sha384(Sha384::new()),
            DigestAlgorithm::Sha512 => Self::Sha512(Sha512::new()),
        }
    }

    fn update(&mut self, input: &[u8]) {
        match self {
            Self::Sha256(hash) => hash.update(input),
            Self::Sha384(hash) => hash.update(input),
            Self::Sha512(hash) => hash.update(input),
        }
    }

    fn finalize(self) -> DigestBytes {
        let mut output = DigestBytes {
            bytes: [0; 64],
            length: 0,
        };
        match self {
            Self::Sha256(hash) => {
                output.bytes[..32].copy_from_slice(&hash.finalize());
                output.length = 32;
            }
            Self::Sha384(hash) => {
                output.bytes[..48].copy_from_slice(&hash.finalize());
                output.length = 48;
            }
            Self::Sha512(hash) => {
                output.bytes.copy_from_slice(&hash.finalize());
                output.length = 64;
            }
        }
        output
    }
}

fn signature_digest(
    algorithm: DigestAlgorithm,
    payload: &[u8],
    hashed_header: &[u8],
) -> Result<DigestBytes, Error> {
    let header_length = u32::try_from(hashed_header.len()).map_err(|_| Error::InvalidSignature)?;
    let mut hash = DigestState::new(algorithm);
    hash.update(payload);
    hash.update(hashed_header);
    hash.update(&[4, 0xff]);
    hash.update(&header_length.to_be_bytes());
    Ok(hash.finalize())
}

fn signature_digest_v6(
    algorithm: DigestAlgorithm,
    salt: &[u8],
    payload: &[u8],
    hashed_header: &[u8],
) -> Result<DigestBytes, Error> {
    if salt.len() != algorithm.v6_salt_bytes() || hashed_header.first() != Some(&6) {
        return Err(Error::InvalidSignature);
    }
    let header_length = u32::try_from(hashed_header.len()).map_err(|_| Error::InvalidSignature)?;
    let mut hash = DigestState::new(algorithm);
    hash.update(salt);
    hash.update(payload);
    hash.update(hashed_header);
    hash.update(&[6, 0xff]);
    hash.update(&header_length.to_be_bytes());
    Ok(hash.finalize())
}

fn parse_packet(input: &[u8], offset: usize) -> Result<(u8, &[u8], usize), Error> {
    let ctb = *input.get(offset).ok_or(Error::InvalidPacket)?;
    if ctb & 0x80 == 0 {
        return Err(Error::InvalidPacket);
    }
    let mut cursor = offset + 1;
    let (tag, length) = if ctb & 0x40 == 0 {
        let tag = (ctb >> 2) & 0x0f;
        let length = match ctb & 0x03 {
            0 => {
                let value = *input.get(cursor).ok_or(Error::InvalidPacket)?;
                cursor += 1;
                usize::from(value)
            }
            1 => {
                let bytes: [u8; 2] = input
                    .get(cursor..cursor + 2)
                    .ok_or(Error::InvalidPacket)?
                    .try_into()
                    .unwrap();
                cursor += 2;
                usize::from(u16::from_be_bytes(bytes))
            }
            2 => {
                let bytes: [u8; 4] = input
                    .get(cursor..cursor + 4)
                    .ok_or(Error::InvalidPacket)?
                    .try_into()
                    .unwrap();
                cursor += 4;
                usize::try_from(u32::from_be_bytes(bytes)).map_err(|_| Error::InvalidPacket)?
            }
            _ => return Err(Error::InvalidPacket),
        };
        (tag, length)
    } else {
        let tag = ctb & 0x3f;
        let first = *input.get(cursor).ok_or(Error::InvalidPacket)?;
        cursor += 1;
        let length = match first {
            0..=191 => usize::from(first),
            192..=223 => {
                let second = *input.get(cursor).ok_or(Error::InvalidPacket)?;
                cursor += 1;
                ((usize::from(first) - 192) << 8) + usize::from(second) + 192
            }
            255 => {
                let bytes: [u8; 4] = input
                    .get(cursor..cursor + 4)
                    .ok_or(Error::InvalidPacket)?
                    .try_into()
                    .unwrap();
                cursor += 4;
                usize::try_from(u32::from_be_bytes(bytes)).map_err(|_| Error::InvalidPacket)?
            }
            _ => return Err(Error::InvalidPacket),
        };
        (tag, length)
    };
    let end = cursor.checked_add(length).ok_or(Error::InvalidPacket)?;
    let body = input.get(cursor..end).ok_or(Error::InvalidPacket)?;
    Ok((tag, body, end))
}

fn decode_armor<'a>(
    begin: &[u8],
    end: &[u8],
    input: &[u8],
    output: &'a mut [u8],
) -> Result<&'a [u8], Error> {
    let mut position = 0usize;
    if next_line(input, &mut position) != Some(begin) {
        return Err(Error::InvalidArmor);
    }
    let mut saw_blank = false;
    while let Some(line) = next_line(input, &mut position) {
        if line.is_empty() {
            saw_blank = true;
            break;
        }
        if !line.is_ascii() || !line.contains(&b':') {
            return Err(Error::InvalidArmor);
        }
    }
    if !saw_blank {
        return Err(Error::InvalidArmor);
    }

    let mut quartet = [0u8; 4];
    let mut quartet_used = 0usize;
    let mut written = 0usize;
    let mut ended_data = false;
    let mut saw_end = false;
    while let Some(line) = next_line(input, &mut position) {
        if line == end {
            saw_end = true;
            break;
        }
        if line.is_empty() {
            continue;
        }
        if line[0] == b'=' {
            // RFC 9580 makes CRC24 advisory: absence, damage, or mismatch is
            // not a reason to reject otherwise cryptographically valid data.
            ended_data = true;
            continue;
        }
        if ended_data || !line.is_ascii() {
            return Err(Error::InvalidArmor);
        }
        for byte in line.iter().copied() {
            if byte.is_ascii_whitespace() {
                return Err(Error::InvalidArmor);
            }
            quartet[quartet_used] = byte;
            quartet_used += 1;
            if quartet_used == 4 {
                let count = decode_base64_quartet(quartet, &mut output[written..])?;
                written = written.checked_add(count).ok_or(Error::OutputTooSmall)?;
                if quartet[2] == b'=' || quartet[3] == b'=' {
                    ended_data = true;
                }
                quartet_used = 0;
            }
        }
    }
    if !saw_end || quartet_used != 0 || written == 0 {
        return Err(Error::InvalidArmor);
    }
    while let Some(line) = next_line(input, &mut position) {
        if !line.is_empty() {
            return Err(Error::InvalidArmor);
        }
    }
    Ok(&output[..written])
}

fn encode_armor(begin: &[u8], end: &[u8], input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    let mut writer = Writer::new(output);
    writer.write(begin)?;
    writer.write(b"\n\n")?;
    let mut column = 0usize;
    for chunk in input.chunks(3) {
        let encoded = encode_base64_chunk(chunk);
        let count = if chunk.len() == 1 {
            2
        } else if chunk.len() == 2 {
            3
        } else {
            4
        };
        for byte in encoded[..count].iter().copied() {
            writer.byte(byte)?;
            column += 1;
            if column == 64 {
                writer.byte(b'\n')?;
                column = 0;
            }
        }
        for _ in count..4 {
            writer.byte(b'=')?;
            column += 1;
            if column == 64 {
                writer.byte(b'\n')?;
                column = 0;
            }
        }
    }
    if column != 0 {
        writer.byte(b'\n')?;
    }
    let checksum = crc24(input).to_be_bytes();
    writer.byte(b'=')?;
    writer.write(&encode_base64_chunk(&checksum[1..]))?;
    writer.byte(b'\n')?;
    writer.write(end)?;
    writer.byte(b'\n')?;
    Ok(writer.written)
}

struct Writer<'a> {
    output: &'a mut [u8],
    written: usize,
}

impl<'a> Writer<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self { output, written: 0 }
    }

    fn byte(&mut self, byte: u8) -> Result<(), Error> {
        let slot = self
            .output
            .get_mut(self.written)
            .ok_or(Error::OutputTooSmall)?;
        *slot = byte;
        self.written += 1;
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self
            .written
            .checked_add(bytes.len())
            .ok_or(Error::OutputTooSmall)?;
        self.output
            .get_mut(self.written..end)
            .ok_or(Error::OutputTooSmall)?
            .copy_from_slice(bytes);
        self.written = end;
        Ok(())
    }
}

fn next_line<'a>(input: &'a [u8], position: &mut usize) -> Option<&'a [u8]> {
    if *position >= input.len() {
        return None;
    }
    let start = *position;
    let relative_end = input[start..].iter().position(|byte| *byte == b'\n');
    let end = relative_end.map_or(input.len(), |relative| start + relative);
    *position = if end < input.len() { end + 1 } else { end };
    let mut line = &input[start..end];
    if line.last() == Some(&b'\r') {
        line = &line[..line.len() - 1];
    }
    Some(line)
}

fn decode_base64_quartet(input: [u8; 4], output: &mut [u8]) -> Result<usize, Error> {
    let a = base64_value(input[0]).ok_or(Error::InvalidArmor)?;
    let b = base64_value(input[1]).ok_or(Error::InvalidArmor)?;
    let c = if input[2] == b'=' {
        if input[3] != b'=' || b & 0x0f != 0 {
            return Err(Error::InvalidArmor);
        }
        0
    } else {
        base64_value(input[2]).ok_or(Error::InvalidArmor)?
    };
    let d = if input[3] == b'=' {
        if input[2] != b'=' && c & 0x03 != 0 {
            return Err(Error::InvalidArmor);
        }
        0
    } else {
        if input[2] == b'=' {
            return Err(Error::InvalidArmor);
        }
        base64_value(input[3]).ok_or(Error::InvalidArmor)?
    };
    let count = if input[2] == b'=' {
        1
    } else if input[3] == b'=' {
        2
    } else {
        3
    };
    if output.len() < count {
        return Err(Error::OutputTooSmall);
    }
    output[0] = (a << 2) | (b >> 4);
    if count >= 2 {
        output[1] = (b << 4) | (c >> 2);
    }
    if count == 3 {
        output[2] = (c << 6) | d;
    }
    Ok(count)
}

fn encode_base64_chunk(input: &[u8]) -> [u8; 4] {
    const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let a = input.first().copied().unwrap_or(0);
    let b = input.get(1).copied().unwrap_or(0);
    let c = input.get(2).copied().unwrap_or(0);
    [
        BASE64[(a >> 2) as usize],
        BASE64[(((a & 0x03) << 4) | (b >> 4)) as usize],
        BASE64[(((b & 0x0f) << 2) | (c >> 6)) as usize],
        BASE64[(c & 0x3f) as usize],
    ]
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn crc24(input: &[u8]) -> u32 {
    let mut crc = 0x00b7_04ceu32;
    for byte in input {
        crc ^= u32::from(*byte) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= 0x0186_4cfb;
            }
        }
    }
    crc & 0x00ff_ffff
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

/// Best-effort non-elidable erasure for an owned secret copy.
///
/// This does not prove erasure of compiler-created copies, registers, caches,
/// swap, crash dumps, or hardware state; isolated key custody remains required.
fn wipe_sensitive(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: `byte` is a live, uniquely borrowed byte in `bytes`.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SEED: [u8; 32] = [
        0x1a, 0x8b, 0x1f, 0xf0, 0x5d, 0xed, 0x48, 0xe1, 0x8b, 0xf5, 0x01, 0x66, 0xc6, 0x64, 0xab,
        0x02, 0x3e, 0xa7, 0x00, 0x03, 0xd7, 0x8d, 0x9e, 0x41, 0xf5, 0x75, 0x8a, 0x91, 0xd8, 0x50,
        0xf8, 0xd2,
    ];
    const RFC_PUBLIC_KEY: &[u8] = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n\
xjMEU/NfCxYJKwYBBAHaRw8BAQdAPwmJlL3ZFu1AUxl5NOSofIBzOhKA1i+AEJku\n\
Q+47JAY=\n\
-----END PGP PUBLIC KEY BLOCK-----\n";
    const RFC_SIGNATURE: &[u8] = b"-----BEGIN PGP SIGNATURE-----\n\n\
iF4EABYIAAYFAlX5X5UACgkQjP3hIZeWWpr2IgD/VvkMypjiECY3vZg/2xbBMd/S\n\
ftgr9N3lYG4NdWrtM2YBANCcT6EVJ/A44PV/IgHYLy6iyQMyZfps60iehUuuYbQE\n\
-----END PGP SIGNATURE-----\n";
    const RFC_V6_CERTIFICATE: &[u8] = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n\
xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf\n\
GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy\n\
KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw\n\
gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE\n\
QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn\n\
+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh\n\
BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8\n\
j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805\n\
I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==\n\
-----END PGP PUBLIC KEY BLOCK-----\n";
    const MRML_PUBLIC_KEY: &[u8] =
        include_bytes!("../../../../docs/keys/mrml-commit-signing-key.asc");
    const MRML_SHA256_COMMIT_PAYLOAD: &[u8] =
        b"tree dad051572d21640565e0000568f1544ad4f17145bc327af0f21967b08203c659\n\
parent 8962abde488db543aad006d714b3344ee9dd0fcaab1f07d869166b04ea81b37b\n\
author Mitchell Renouf <mitchellrenouf@mrml.ca> 1788120706 -0230\n\
committer Mitchell Renouf <mitchellrenouf@mrml.ca> 1788120706 -0230\n\
\n\
compiler: pin option default errors\n";
    const MRML_SHA256_COMMIT_SIGNATURE: &[u8] = b"-----BEGIN PGP SIGNATURE-----\n\
\n\
iHUEABYKAB0WIQRu51SVsEJ6Tz+XuhwU1wQ0mQ8cqQUCapSOggAKCRAU1wQ0mQ8c\n\
qYcbAQDXiSIjQOcstmYwu/b+NdmB35ZFHeF+CP56h8ARPwae2AEAsT7eFl5mOCn6\n\
RrZBCWR8kCBbjsCcCxGvoS42kUhn7wg=\n\
=s+KS\n\
-----END PGP SIGNATURE-----\n";

    fn rfc_fingerprint() -> Fingerprint {
        Fingerprint::parse_hex("C959BDBAFA32A2F89A153B678CFDE12197965A9A").unwrap()
    }

    #[test]
    fn rfc_9580_public_key_and_signature_vector() {
        let mut public_scratch = [0u8; 1024];
        let public = parse_public_key_ascii(RFC_PUBLIC_KEY, &mut public_scratch).unwrap();
        assert_eq!(public.fingerprint(), rfc_fingerprint());
        assert_eq!(public.created_at(), 0x53f3_5f0b);
        let policy = VerificationPolicy {
            expected_primary_fingerprint: rfc_fingerprint(),
            validation_time: Some(0x55f9_5f95),
            key_not_after: None,
            key_revoked: false,
            enforce_signature_expiration: true,
        };
        let mut signature_scratch = [0u8; 1024];
        let verified = verify_detached_ascii(
            &public,
            b"OpenPGP",
            RFC_SIGNATURE,
            &policy,
            &mut signature_scratch,
        )
        .unwrap();
        assert_eq!(verified.digest_algorithm, DigestAlgorithm::Sha256);
        assert_eq!(verified.created_at, 0x55f9_5f95);
    }

    #[test]
    fn rfc_9580_v6_primary_key_uses_full_sha256_fingerprint() {
        let expected = FingerprintV6::parse_hex(
            "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9",
        )
        .unwrap();
        let mut scratch = [0u8; MAX_OPENPGP_PUBLIC_KEY_BYTES];
        let key = parse_public_key_v6_ascii(RFC_V6_CERTIFICATE, &mut scratch).unwrap();
        assert_eq!(key.created_at(), 0x6387_7fe3);
        assert_eq!(key.fingerprint(), expected);
        assert_eq!(
            key.public_bytes(),
            &[
                0xf9, 0x4d, 0xa7, 0xbb, 0x48, 0xd6, 0x0a, 0x61, 0xe5, 0x67, 0x70, 0x6a, 0x65, 0x87,
                0xd0, 0x33, 0x19, 0x99, 0xbb, 0x9d, 0x89, 0x1a, 0x08, 0x24, 0x2e, 0xad, 0x84, 0x54,
                0x3d, 0xf8, 0x95, 0xa3,
            ]
        );
    }

    #[test]
    fn v6_identity_rejects_v4_and_noncanonical_material_lengths() {
        let mut scratch = [0u8; MAX_OPENPGP_PUBLIC_KEY_BYTES];
        assert_eq!(
            parse_public_key_v6_ascii(RFC_PUBLIC_KEY, &mut scratch),
            Err(Error::UnsupportedVersion)
        );

        let public = [0x55; 32];
        let mut body = [0u8; 42];
        body[0] = 6;
        body[1..5].copy_from_slice(&1u32.to_be_bytes());
        body[5] = 27;
        body[6..10].copy_from_slice(&31u32.to_be_bytes());
        body[10..].copy_from_slice(&public);
        assert_eq!(parse_primary_key_v6(&body), Err(Error::InvalidPublicKey));
    }

    #[test]
    fn v6_detached_signatures_round_trip_with_exact_salt_sizes() {
        let key = SigningKeyV6::from_seed([0x42; 32], 1_700_000_000).unwrap();
        let public = key.public_key();
        for algorithm in [
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ] {
            let salt = [0x5a; 32];
            let salt = &salt[..algorithm.v6_salt_bytes()];
            let mut armor = [0u8; 512];
            let written = sign_detached_v6_ascii_with_salt(
                &key,
                b"MRML v6",
                algorithm,
                1_700_000_001,
                salt,
                &mut armor,
            )
            .unwrap();
            let mut scratch = [0u8; MAX_OPENPGP_SIGNATURE_BYTES];
            let verified = verify_detached_v6_ascii(
                &public,
                b"MRML v6",
                &armor[..written],
                &VerificationPolicyV6 {
                    expected_primary_fingerprint: public.fingerprint(),
                    validation_time: Some(1_700_000_001),
                    key_not_after: None,
                    key_revoked: false,
                    enforce_signature_expiration: true,
                },
                &mut scratch,
            )
            .unwrap();
            assert_eq!(verified.digest_algorithm, algorithm);
        }
    }

    #[test]
    fn v6_salt_is_hashed_first_and_cannot_be_omitted_or_misordered() {
        let header = [6, 0, 27, 8, 0, 0, 0, 0];
        let salt = [0x33; 16];
        let correct =
            signature_digest_v6(DigestAlgorithm::Sha256, &salt, b"payload", &header).unwrap();

        let mut omitted = DigestState::new(DigestAlgorithm::Sha256);
        omitted.update(b"payload");
        omitted.update(&header);
        omitted.update(&[6, 0xff]);
        omitted.update(&(header.len() as u32).to_be_bytes());
        let omitted = omitted.finalize();

        let mut misordered = DigestState::new(DigestAlgorithm::Sha256);
        misordered.update(b"payload");
        misordered.update(&salt);
        misordered.update(&header);
        misordered.update(&[6, 0xff]);
        misordered.update(&(header.len() as u32).to_be_bytes());
        let misordered = misordered.finalize();

        assert_ne!(correct.as_slice(), omitted.as_slice());
        assert_ne!(correct.as_slice(), misordered.as_slice());
        assert_eq!(
            signature_digest_v6(DigestAlgorithm::Sha256, &salt[..15], b"payload", &header).err(),
            Some(Error::InvalidSignature)
        );
    }

    #[test]
    fn checked_mrml_key_verifies_sha256_git_commit_fixture() {
        let expected = Fingerprint::parse_hex("6EE75495B0427A4F3F97BA1C14D70434990F1CA9").unwrap();
        let mut public_scratch = [0u8; MAX_OPENPGP_PUBLIC_KEY_BYTES];
        let public = parse_public_key_ascii(MRML_PUBLIC_KEY, &mut public_scratch).unwrap();
        assert_eq!(public.fingerprint(), expected);
        assert_eq!(public.created_at(), 1_788_039_680);
        let mut signature_scratch = [0u8; MAX_OPENPGP_SIGNATURE_BYTES];
        let verified = verify_detached_ascii(
            &public,
            MRML_SHA256_COMMIT_PAYLOAD,
            MRML_SHA256_COMMIT_SIGNATURE,
            &VerificationPolicy {
                expected_primary_fingerprint: expected,
                validation_time: Some(1_788_120_706),
                key_not_after: Some(1_851_111_680),
                key_revoked: false,
                enforce_signature_expiration: true,
            },
            &mut signature_scratch,
        )
        .unwrap();
        assert_eq!(verified.digest_algorithm, DigestAlgorithm::Sha512);
        assert_eq!(verified.created_at, 1_788_120_706);
    }

    #[test]
    fn seed_signing_round_trips_all_supported_digests() {
        let public = PublicKey::from_seed(&RFC_SEED, 0x53f3_5f0b).unwrap();
        assert_eq!(public.fingerprint(), rfc_fingerprint());
        let key = SigningKey::from_seed_and_public_key(RFC_SEED, public).unwrap();
        for digest in [
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ] {
            let mut armor = [0u8; 512];
            let written =
                sign_detached_ascii(&key, b"MRML", digest, 0x55f9_5f95, &mut armor).unwrap();
            let mut scratch = [0u8; 1024];
            let verified = verify_detached_ascii(
                &public,
                b"MRML",
                &armor[..written],
                &VerificationPolicy {
                    expected_primary_fingerprint: public.fingerprint(),
                    validation_time: Some(0x55f9_5f95),
                    key_not_after: None,
                    key_revoked: false,
                    enforce_signature_expiration: true,
                },
                &mut scratch,
            )
            .unwrap();
            assert_eq!(verified.digest_algorithm, digest);
        }
    }

    #[test]
    fn tampering_and_wrong_policy_fail_closed() {
        let mut public_scratch = [0u8; 1024];
        let public = parse_public_key_ascii(RFC_PUBLIC_KEY, &mut public_scratch).unwrap();
        let mut signature_scratch = [0u8; 1024];
        let policy = VerificationPolicy {
            expected_primary_fingerprint: rfc_fingerprint(),
            validation_time: Some(0x55f9_5f95),
            key_not_after: None,
            key_revoked: false,
            enforce_signature_expiration: true,
        };
        assert_eq!(
            verify_detached_ascii(
                &public,
                b"OpenPGp",
                RFC_SIGNATURE,
                &policy,
                &mut signature_scratch,
            ),
            Err(Error::InvalidSignature)
        );
        let wrong = VerificationPolicy {
            expected_primary_fingerprint: Fingerprint::from_bytes([0x55; 20]),
            ..policy
        };
        assert_eq!(
            verify_detached_ascii(
                &public,
                b"OpenPGP",
                RFC_SIGNATURE,
                &wrong,
                &mut signature_scratch,
            ),
            Err(Error::FingerprintMismatch)
        );
    }

    #[test]
    fn owner_revocation_and_signing_time_cutoff_are_explicit() {
        let mut public_scratch = [0u8; 1024];
        let public = parse_public_key_ascii(RFC_PUBLIC_KEY, &mut public_scratch).unwrap();
        let mut signature_scratch = [0u8; 1024];
        let historical = VerificationPolicy {
            expected_primary_fingerprint: rfc_fingerprint(),
            validation_time: Some(0x65f9_5f95),
            key_not_after: Some(0x55f9_5f96),
            key_revoked: false,
            enforce_signature_expiration: true,
        };
        assert!(
            verify_detached_ascii(
                &public,
                b"OpenPGP",
                RFC_SIGNATURE,
                &historical,
                &mut signature_scratch,
            )
            .is_ok()
        );
        assert_eq!(
            verify_detached_ascii(
                &public,
                b"OpenPGP",
                RFC_SIGNATURE,
                &VerificationPolicy {
                    key_revoked: true,
                    ..historical
                },
                &mut signature_scratch,
            ),
            Err(Error::RevokedKey)
        );
        assert_eq!(
            verify_detached_ascii(
                &public,
                b"OpenPGP",
                RFC_SIGNATURE,
                &VerificationPolicy {
                    key_not_after: Some(0x55f9_5f95),
                    ..historical
                },
                &mut signature_scratch,
            ),
            Err(Error::ExpiredKey)
        );
    }

    #[test]
    fn invalid_public_construction_and_signature_expiry_subpackets_fail_closed() {
        assert_eq!(
            PublicKey::from_public([0; 32], 1),
            Err(Error::InvalidPublicKey)
        );
        assert_eq!(
            PublicKey::from_public(ed25519_public(&RFC_SEED), 0),
            Err(Error::InvalidTime)
        );
        let parsed = parse_subpackets(&[5, 0x83, 0, 0, 0, 2], true, &rfc_fingerprint()).unwrap();
        assert_eq!(parsed.signature_expiration, Some(2));
        assert_eq!(
            parse_subpackets(
                &[5, 0x83, 0, 0, 0, 2, 5, 3, 0, 0, 0, 3],
                true,
                &rfc_fingerprint(),
            )
            .err(),
            Some(Error::InvalidSignature)
        );

        let public = PublicKey::from_seed(&RFC_SEED, 0x53f3_5f0b).unwrap();
        let mut imported = RFC_SEED;
        let key = SigningKey::from_seed_bytes_and_public_key(&mut imported, public).unwrap();
        assert_eq!(imported, [0; 32]);
        drop(key);
        let mut short = [0x55; 31];
        assert_eq!(
            SigningKey::from_seed_bytes_and_public_key(&mut short, public).err(),
            Some(Error::InvalidSecretKey)
        );
        assert_eq!(short, [0; 31]);
    }

    #[test]
    fn rejects_noncanonical_mpi_and_critical_subpacket() {
        let mut decoded = [0u8; 1024];
        let packet =
            decode_armor(SIGNATURE_BEGIN, SIGNATURE_END, RFC_SIGNATURE, &mut decoded).unwrap();
        let (_, body, _) = parse_packet(packet, 0).unwrap();
        let mut changed = [0u8; 192];
        changed[..body.len()].copy_from_slice(body);
        changed[7] = 0xff;
        assert_eq!(
            parse_signature_body(&changed[..body.len()], 0, &rfc_fingerprint()).unwrap_err(),
            Error::UnknownCriticalSubpacket
        );

        changed[..body.len()].copy_from_slice(body);
        let hashed_end = 6 + usize::from(u16::from_be_bytes(changed[4..6].try_into().unwrap()));
        let unhashed_length = usize::from(u16::from_be_bytes(
            changed[hashed_end..hashed_end + 2].try_into().unwrap(),
        ));
        let first_mpi = hashed_end + 2 + unhashed_length + 2;
        let bits = u16::from_be_bytes(changed[first_mpi..first_mpi + 2].try_into().unwrap());
        changed[first_mpi..first_mpi + 2].copy_from_slice(&(bits - 1).to_be_bytes());
        assert_eq!(
            parse_signature_body(&changed[..body.len()], 0, &rfc_fingerprint()).unwrap_err(),
            Error::InvalidSignature
        );
    }

    #[test]
    fn old_and_new_four_octet_packet_lengths_are_bounded_exactly() {
        let old = [0x9a, 0, 0, 0, 1, 0x42];
        let (old_tag, old_body, old_end) = parse_packet(&old, 0).unwrap();
        assert_eq!(old_tag, 6);
        assert_eq!(old_body, &[0x42]);
        assert_eq!(old_end, old.len());

        let new = [0xc6, 0xff, 0, 0, 0, 1, 0x42];
        let (new_tag, new_body, new_end) = parse_packet(&new, 0).unwrap();
        assert_eq!(new_tag, 6);
        assert_eq!(new_body, &[0x42]);
        assert_eq!(new_end, new.len());
    }

    #[test]
    fn armor_crc_is_advisory_but_trailing_data_is_rejected() {
        let public = PublicKey::from_seed(&RFC_SEED, 0x53f3_5f0b).unwrap();
        let key = SigningKey::from_seed_and_public_key(RFC_SEED, public).unwrap();
        let mut generated = [0u8; 512];
        let generated_len = sign_detached_ascii(
            &key,
            b"CRC",
            DigestAlgorithm::Sha256,
            0x55f9_5f95,
            &mut generated,
        )
        .unwrap();
        let mut damaged = [0u8; 512];
        damaged[..generated_len].copy_from_slice(&generated[..generated_len]);
        let checksum = generated[..generated_len]
            .windows(2)
            .position(|window| window == b"\n=")
            .unwrap()
            + 2;
        damaged[checksum] = b'A';
        let mut scratch = [0u8; 1024];
        assert!(
            decode_armor(
                SIGNATURE_BEGIN,
                SIGNATURE_END,
                &damaged[..generated_len],
                &mut scratch,
            )
            .is_ok()
        );
        let mut trailing = [0u8; 512];
        trailing[..generated_len].copy_from_slice(&generated[..generated_len]);
        trailing[generated_len..generated_len + 2].copy_from_slice(b"x\n");
        assert_eq!(
            decode_armor(
                SIGNATURE_BEGIN,
                SIGNATURE_END,
                &trailing[..generated_len + 2],
                &mut scratch,
            ),
            Err(Error::InvalidArmor)
        );
    }
}
