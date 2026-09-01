use crate::{AcmeUrl, ReplayNonce, encode_base64url};
use mrml_crypto::{Sha256, p256_public_key_is_valid};

pub const MAX_JWS_PAYLOAD: usize = 16 * 1024;
const MAX_PROTECTED_JSON: usize = 2300;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JoseError {
    OutputTooSmall,
    PayloadTooLarge,
    InvalidSignature,
    SigningUnavailable,
    LengthOverflow,
    InvalidPublicKey,
    InvalidJsonString,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct P256Jwk {
    x: [u8; 32],
    y: [u8; 32],
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct JwkThumbprint(pub [u8; 32]);
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Es256Signature([u8; 64]);
impl Es256Signature {
    pub fn from_raw(raw: [u8; 64]) -> Result<Self, JoseError> {
        if !valid_p256_scalar(&raw[..32]) || !valid_p256_scalar(&raw[32..]) {
            Err(JoseError::InvalidSignature)
        } else {
            Ok(Self(raw))
        }
    }
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

fn valid_p256_scalar(value: &[u8]) -> bool {
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    !value.iter().all(|byte| *byte == 0) && value < ORDER.as_slice()
}

impl P256Jwk {
    pub fn from_coordinates(x: [u8; 32], y: [u8; 32]) -> Result<Self, JoseError> {
        let mut encoded = [0u8; 65];
        encoded[0] = 4;
        encoded[1..33].copy_from_slice(&x);
        encoded[33..].copy_from_slice(&y);
        if !p256_public_key_is_valid(&encoded) {
            return Err(JoseError::InvalidPublicKey);
        }
        Ok(Self { x, y })
    }

    pub fn thumbprint(&self) -> Result<JwkThumbprint, JoseError> {
        let mut x = [0u8; 43];
        let mut y = [0u8; 43];
        let x = encode_base64url(&self.x, &mut x).map_err(|_| JoseError::OutputTooSmall)?;
        let y = encode_base64url(&self.y, &mut y).map_err(|_| JoseError::OutputTooSmall)?;
        let mut hash = Sha256::new();
        hash.update(b"{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"");
        hash.update(x.as_bytes());
        hash.update(b"\",\"y\":\"");
        hash.update(y.as_bytes());
        hash.update(b"\"}");
        Ok(JwkThumbprint(hash.finalize()))
    }

    pub fn sec1_uncompressed(&self) -> [u8; 65] {
        let mut output = [0u8; 65];
        output[0] = 4;
        output[1..33].copy_from_slice(&self.x);
        output[33..].copy_from_slice(&self.y);
        output
    }
}

pub enum ProtectedKey<'a> {
    Jwk(&'a P256Jwk),
    Kid(&'a AcmeUrl),
}

pub struct ApprovedAcmeJwsDigest {
    digest: [u8; 32],
    pub directory_generation: u64,
    pub account_generation: u64,
}
impl ApprovedAcmeJwsDigest {
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}
pub trait AcmeJwsSigner {
    fn sign_acme_jws(
        &mut self,
        approved: &ApprovedAcmeJwsDigest,
    ) -> Result<Es256Signature, JoseError>;
}

pub struct ApprovedEabMac {
    protected_and_payload_digest: [u8; 32],
    pub directory_generation: u64,
}

impl ApprovedEabMac {
    pub fn protected_and_payload_digest(&self) -> &[u8; 32] {
        &self.protected_and_payload_digest
    }
}

pub trait ExternalAccountMac {
    fn mac_external_account_binding(
        &mut self,
        approved: &ApprovedEabMac,
        signing_input: &[u8],
    ) -> Result<[u8; 32], JoseError>;
}

struct Writer<'a> {
    out: &'a mut [u8],
    len: usize,
}
impl<'a> Writer<'a> {
    fn new(out: &'a mut [u8]) -> Self {
        Self { out, len: 0 }
    }
    fn push(&mut self, bytes: &[u8]) -> Result<(), JoseError> {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(JoseError::LengthOverflow)?;
        let target = self
            .out
            .get_mut(self.len..end)
            .ok_or(JoseError::OutputTooSmall)?;
        target.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
    fn json_string(&mut self, value: &str) -> Result<(), JoseError> {
        self.push(b"\"")?;
        for b in value.bytes() {
            match b {
                b'\"' => self.push(b"\\\"")?,
                b'\\' => self.push(b"\\\\")?,
                0..=0x1f => return Err(JoseError::InvalidJsonString),
                _ => self.push(&[b])?,
            }
        }
        self.push(b"\"")
    }
}

fn protected_json(
    header_key: ProtectedKey<'_>,
    nonce: &ReplayNonce,
    url: &AcmeUrl,
    out: &mut [u8],
) -> Result<usize, JoseError> {
    let mut w = Writer::new(out);
    w.push(b"{\"alg\":\"ES256\",")?;
    match header_key {
        ProtectedKey::Jwk(jwk) => {
            let mut x = [0u8; 43];
            let mut y = [0u8; 43];
            let x = encode_base64url(&jwk.x, &mut x).map_err(|_| JoseError::OutputTooSmall)?;
            let y = encode_base64url(&jwk.y, &mut y).map_err(|_| JoseError::OutputTooSmall)?;
            w.push(b"\"jwk\":{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"")?;
            w.push(x.as_bytes())?;
            w.push(b"\",\"y\":\"")?;
            w.push(y.as_bytes())?;
            w.push(b"\"},")?
        }
        ProtectedKey::Kid(kid) => {
            w.push(b"\"kid\":")?;
            w.json_string(kid.as_str())?;
            w.push(b",")?
        }
    }
    w.push(b"\"nonce\":")?;
    w.json_string(nonce.as_str())?;
    w.push(b",\"url\":")?;
    w.json_string(url.as_str())?;
    w.push(b"}")?;
    Ok(w.len)
}

pub fn write_flattened_jws<'a>(
    key: ProtectedKey<'_>,
    nonce: &ReplayNonce,
    url: &AcmeUrl,
    payload: &[u8],
    directory_generation: u64,
    account_generation: u64,
    signer: &mut impl AcmeJwsSigner,
    output: &'a mut [u8],
) -> Result<&'a [u8], JoseError> {
    if payload.len() > MAX_JWS_PAYLOAD {
        return Err(JoseError::PayloadTooLarge);
    }
    let mut protected = [0u8; MAX_PROTECTED_JSON];
    let protected_len = protected_json(key, nonce, url, &mut protected)?;
    let mut protected64 = [0u8; MAX_PROTECTED_JSON * 2];
    let protected64 = encode_base64url(&protected[..protected_len], &mut protected64)
        .map_err(|_| JoseError::OutputTooSmall)?;
    let mut payload64 = [0u8; MAX_JWS_PAYLOAD * 2];
    let payload64 =
        encode_base64url(payload, &mut payload64).map_err(|_| JoseError::OutputTooSmall)?;
    let mut digest = Sha256::new();
    digest.update(protected64.as_bytes());
    digest.update(b".");
    digest.update(payload64.as_bytes());
    let approved = ApprovedAcmeJwsDigest {
        digest: digest.finalize(),
        directory_generation,
        account_generation,
    };
    let signature = signer.sign_acme_jws(&approved)?;
    let mut signature64 = [0u8; 86];
    let signature64 = encode_base64url(signature.as_bytes(), &mut signature64)
        .map_err(|_| JoseError::OutputTooSmall)?;
    let mut w = Writer::new(output);
    w.push(b"{\"protected\":\"")?;
    w.push(protected64.as_bytes())?;
    w.push(b"\",\"payload\":\"")?;
    w.push(payload64.as_bytes())?;
    w.push(b"\",\"signature\":\"")?;
    w.push(signature64.as_bytes())?;
    w.push(b"\"}")?;
    let len = w.len;
    Ok(&output[..len])
}

pub fn write_external_account_binding<'a>(
    key_identifier: &str,
    new_account_url: &AcmeUrl,
    account_key: &P256Jwk,
    directory_generation: u64,
    mac_provider: &mut impl ExternalAccountMac,
    output: &'a mut [u8],
) -> Result<&'a [u8], JoseError> {
    if key_identifier.is_empty() || key_identifier.len() > 256 {
        return Err(JoseError::InvalidJsonString);
    }
    let mut protected = [0u8; 2400];
    let mut protected_writer = Writer::new(&mut protected);
    protected_writer.push(b"{\"alg\":\"HS256\",\"kid\":")?;
    protected_writer.json_string(key_identifier)?;
    protected_writer.push(b",\"url\":")?;
    protected_writer.json_string(new_account_url.as_str())?;
    protected_writer.push(b"}")?;
    let protected_len = protected_writer.len;
    let mut protected64 = [0u8; 3200];
    let protected64 = encode_base64url(&protected[..protected_len], &mut protected64)
        .map_err(|_| JoseError::OutputTooSmall)?;

    let mut x = [0u8; 43];
    let mut y = [0u8; 43];
    let x = encode_base64url(&account_key.x, &mut x).map_err(|_| JoseError::OutputTooSmall)?;
    let y = encode_base64url(&account_key.y, &mut y).map_err(|_| JoseError::OutputTooSmall)?;
    let mut payload = [0u8; 192];
    let mut payload_writer = Writer::new(&mut payload);
    payload_writer.push(b"{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"")?;
    payload_writer.push(x.as_bytes())?;
    payload_writer.push(b"\",\"y\":\"")?;
    payload_writer.push(y.as_bytes())?;
    payload_writer.push(b"\"}")?;
    let payload_len = payload_writer.len;
    let mut payload64 = [0u8; 256];
    let payload64 = encode_base64url(&payload[..payload_len], &mut payload64)
        .map_err(|_| JoseError::OutputTooSmall)?;

    let signing_length = protected64
        .len()
        .checked_add(1)
        .and_then(|value| value.checked_add(payload64.len()))
        .ok_or(JoseError::LengthOverflow)?;
    let mut signing_input = [0u8; 3600];
    if signing_input.len() < signing_length {
        return Err(JoseError::OutputTooSmall);
    }
    signing_input[..protected64.len()].copy_from_slice(protected64.as_bytes());
    signing_input[protected64.len()] = b'.';
    signing_input[protected64.len() + 1..signing_length].copy_from_slice(payload64.as_bytes());
    let approved = ApprovedEabMac {
        protected_and_payload_digest: Sha256::digest(&signing_input[..signing_length]),
        directory_generation,
    };
    let mac =
        mac_provider.mac_external_account_binding(&approved, &signing_input[..signing_length])?;
    let mut mac64 = [0u8; 43];
    let mac64 = encode_base64url(&mac, &mut mac64).map_err(|_| JoseError::OutputTooSmall)?;
    let mut writer = Writer::new(output);
    writer.push(b"{\"protected\":\"")?;
    writer.push(protected64.as_bytes())?;
    writer.push(b"\",\"payload\":\"")?;
    writer.push(payload64.as_bytes())?;
    writer.push(b"\",\"signature\":\"")?;
    writer.push(mac64.as_bytes())?;
    writer.push(b"\"}")?;
    let length = writer.len;
    Ok(&output[..length])
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Signer {
        seen: Option<[u8; 32]>,
    }
    impl AcmeJwsSigner for Signer {
        fn sign_acme_jws(
            &mut self,
            a: &ApprovedAcmeJwsDigest,
        ) -> Result<Es256Signature, JoseError> {
            self.seen = Some(*a.digest());
            Es256Signature::from_raw([1u8; 64])
        }
    }
    struct Eab([u8; 32]);
    impl ExternalAccountMac for Eab {
        fn mac_external_account_binding(
            &mut self,
            approved: &ApprovedEabMac,
            input: &[u8],
        ) -> Result<[u8; 32], JoseError> {
            assert_eq!(
                approved.protected_and_payload_digest(),
                &Sha256::digest(input)
            );
            Ok(mrml_crypto::hmac_sha256(&self.0, &[input]))
        }
    }
    #[test]
    fn thumbprint_matches_independent_ec_fixture() {
        let jwk = P256Jwk::from_coordinates(
            [
                0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
                0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
                0xd8, 0x98, 0xc2, 0x96,
            ],
            [
                0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
                0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
                0x37, 0xbf, 0x51, 0xf5,
            ],
        )
        .unwrap();
        let mut encoded = [0u8; 43];
        assert_eq!(
            encode_base64url(&jwk.thumbprint().unwrap().0, &mut encoded).unwrap(),
            "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
        );
    }
    #[test]
    fn writes_jwk_then_kid_forms_without_both() {
        let jwk = P256Jwk::from_coordinates(
            [
                0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
                0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
                0xd8, 0x98, 0xc2, 0x96,
            ],
            [
                0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
                0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
                0x37, 0xbf, 0x51, 0xf5,
            ],
        )
        .unwrap();
        let nonce = ReplayNonce::parse("nonce-1").unwrap();
        let url = AcmeUrl::parse("https://ca.example/acme/new-order", false).unwrap();
        let mut signer = Signer { seen: None };
        let mut out = [0u8; 4096];
        let jws = write_flattened_jws(
            ProtectedKey::Jwk(&jwk),
            &nonce,
            &url,
            b"{}",
            7,
            3,
            &mut signer,
            &mut out,
        )
        .unwrap();
        let text = core::str::from_utf8(jws).unwrap();
        assert!(text.contains("protected"));
        assert!(!text.contains("kid"));
        assert!(signer.seen.is_some());

        let kid = AcmeUrl::parse("https://ca.example/acme/account/7", false).unwrap();
        let jws = write_flattened_jws(
            ProtectedKey::Kid(&kid),
            &nonce,
            &url,
            b"{}",
            7,
            3,
            &mut signer,
            &mut out,
        )
        .unwrap();
        let text = core::str::from_utf8(jws).unwrap();
        let encoded = text
            .strip_prefix("{\"protected\":\"")
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let mut decoded = [0u8; MAX_PROTECTED_JSON];
        let protected = crate::decode_base64url(encoded, &mut decoded).unwrap();
        let protected = core::str::from_utf8(protected).unwrap();
        assert!(protected.contains("\"kid\":"));
        assert!(!protected.contains("\"jwk\":"));
    }

    #[test]
    fn rejects_out_of_range_es256_scalars() {
        assert!(matches!(
            Es256Signature::from_raw([0; 64]),
            Err(JoseError::InvalidSignature)
        ));
        let mut at_order = [1u8; 64];
        at_order[..32].copy_from_slice(&[
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ]);
        assert!(matches!(
            Es256Signature::from_raw(at_order),
            Err(JoseError::InvalidSignature)
        ));
    }

    #[test]
    fn external_account_binding_uses_non_exporting_hs256_provider() {
        let jwk = P256Jwk::from_coordinates(
            [
                0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
                0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
                0xd8, 0x98, 0xc2, 0x96,
            ],
            [
                0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
                0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
                0x37, 0xbf, 0x51, 0xf5,
            ],
        )
        .unwrap();
        let url = AcmeUrl::parse("https://ca.example/new-account", false).unwrap();
        let mut output = [0u8; 4096];
        let eab = write_external_account_binding(
            "owner-key-7",
            &url,
            &jwk,
            3,
            &mut Eab([0x0b; 32]),
            &mut output,
        )
        .unwrap();
        let text = core::str::from_utf8(eab).unwrap();
        assert!(text.starts_with("{\"protected\":"));
        assert_eq!(text.matches("signature").count(), 1);
    }
}
