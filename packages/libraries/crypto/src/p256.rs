use crate::Sha256;
#[cfg(any(test, feature = "experimental-p256-signing"))]
use crate::{hmac_sha256, zeroize::volatile_zero};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P256Error {
    InvalidKey,
    InvalidSignature,
    EntropyUnavailable,
    SigningFailed,
    OutputTooSmall,
}

type U256 = [u64; 4];

const P: U256 = [
    0xffff_ffff_ffff_ffff,
    0x0000_0000_ffff_ffff,
    0x0000_0000_0000_0000,
    0xffff_ffff_0000_0001,
];
const N: U256 = [
    0xf3b9_cac2_fc63_2551,
    0xbce6_faad_a717_9e84,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_0000_0000,
];
const B: U256 = [
    0x3bce_3c3e_27d2_604b,
    0x651d_06b0_cc53_b0f6,
    0xb3eb_bd55_7698_86bc,
    0x5ac6_35d8_aa3a_93e7,
];
const GX: U256 = [
    0xf4a1_3945_d898_c296,
    0x7703_7d81_2deb_33a0,
    0xf8bc_e6e5_63a4_40f2,
    0x6b17_d1f2_e12c_4247,
];
const GY: U256 = [
    0xcbb6_4068_37bf_51f5,
    0x2bce_3357_6b31_5ece,
    0x8ee7_eb4a_7c0f_9e16,
    0x4fe3_42e2_fe1a_7f9b,
];

#[cfg(any(test, feature = "experimental-p256-signing"))]
const HALF_N: U256 = [
    0x79dc_e561_7e31_92a8,
    0xde73_7d56_d38b_cf42,
    0x7fff_ffff_ffff_ffff,
    0x7fff_ffff_8000_0000,
];

#[cfg(any(test, feature = "experimental-p256-signing"))]
fn to_be(value: U256) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (index, word) in value.iter().rev().enumerate() {
        out[index * 8..index * 8 + 8].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(any(test, feature = "experimental-p256-signing"))]
pub struct P256SecretKey {
    bytes: [u8; 32],
}

#[cfg(any(test, feature = "experimental-p256-signing"))]
impl Drop for P256SecretKey {
    fn drop(&mut self) {
        volatile_zero(&mut self.bytes);
    }
}

#[cfg(any(test, feature = "experimental-p256-signing"))]
impl P256SecretKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, P256Error> {
        let scalar = from_be(&bytes).ok_or(P256Error::InvalidKey)?;
        if scalar == [0; 4] || compare(scalar, N) != core::cmp::Ordering::Less {
            return Err(P256Error::InvalidKey);
        }
        Ok(Self { bytes })
    }

    pub fn generate_with(
        mut fill_entropy: impl FnMut(&mut [u8]) -> Result<(), P256Error>,
    ) -> Result<Self, P256Error> {
        let mut candidate = [0u8; 32];
        for _ in 0..128 {
            fill_entropy(&mut candidate)?;
            if let Ok(key) = Self::from_bytes(candidate) {
                volatile_zero(&mut candidate);
                return Ok(key);
            }
            volatile_zero(&mut candidate);
        }
        Err(P256Error::EntropyUnavailable)
    }

    #[cfg(feature = "runtime")]
    pub fn generate() -> Result<Self, P256Error> {
        Self::generate_with(|output| {
            mrml_runtime::fill_random(output).map_err(|_| P256Error::EntropyUnavailable)
        })
    }

    pub fn public_key(&self) -> Result<[u8; 65], P256Error> {
        let mut scalar_value = from_be(&self.bytes).ok_or(P256Error::InvalidKey)?;
        let point = scalar(Affine { x: GX, y: GY }, scalar_value)
            .affine()
            .ok_or(P256Error::InvalidKey)?;
        let mut output = [0u8; 65];
        output[0] = 4;
        output[1..33].copy_from_slice(&to_be(point.x));
        output[33..].copy_from_slice(&to_be(point.y));
        volatile_zero(&mut scalar_value);
        Ok(output)
    }

    pub fn sign_digest_raw(&self, digest: &[u8; 32]) -> Result<[u8; 64], P256Error> {
        let mut private = from_be(&self.bytes).ok_or(P256Error::InvalidKey)?;
        let mut z = from_be(digest).ok_or(P256Error::SigningFailed)?;
        if compare(z, N) != core::cmp::Ordering::Less {
            z = subtract_raw(z, N).0;
        }
        let mut nonce = deterministic_nonce(&self.bytes, digest)?;
        let result = (|| {
            let point = scalar(Affine { x: GX, y: GY }, nonce)
                .affine()
                .ok_or(P256Error::SigningFailed)?;
            let r = if compare(point.x, N) == core::cmp::Ordering::Less {
                point.x
            } else {
                subtract_raw(point.x, N).0
            };
            if r == [0; 4] {
                return Err(P256Error::SigningFailed);
            }
            let inverse = inverse(nonce, N).ok_or(P256Error::SigningFailed)?;
            let mut s = mul_mod(inverse, add_mod(z, mul_mod(r, private, N), N), N);
            if s == [0; 4] {
                return Err(P256Error::SigningFailed);
            }
            if compare(s, HALF_N) == core::cmp::Ordering::Greater {
                s = subtract_raw(N, s).0;
            }
            let mut signature = [0u8; 64];
            signature[..32].copy_from_slice(&to_be(r));
            signature[32..].copy_from_slice(&to_be(s));
            let public = self.public_key()?;
            ecdsa_p256_digest_verify_raw(&public, digest, &signature)?;
            Ok(signature)
        })();
        volatile_zero(&mut private);
        volatile_zero(&mut z);
        volatile_zero(&mut nonce);
        result
    }

    pub fn sign_digest_der<'a>(
        &self,
        digest: &[u8; 32],
        output: &'a mut [u8],
    ) -> Result<&'a [u8], P256Error> {
        let mut raw = self.sign_digest_raw(digest)?;
        let result = encode_der_signature(&raw, output);
        volatile_zero(&mut raw);
        result
    }
}

#[cfg(any(test, feature = "experimental-p256-signing"))]
fn deterministic_nonce(private: &[u8; 32], digest: &[u8; 32]) -> Result<U256, P256Error> {
    let mut v = [1u8; 32];
    let mut k = [0u8; 32];
    k = hmac_sha256(&k, &[&v, &[0], private, digest]);
    v = hmac_sha256(&k, &[&v]);
    k = hmac_sha256(&k, &[&v, &[1], private, digest]);
    v = hmac_sha256(&k, &[&v]);
    for _ in 0..128 {
        v = hmac_sha256(&k, &[&v]);
        let candidate = from_be(&v).ok_or(P256Error::SigningFailed)?;
        if candidate != [0; 4] && compare(candidate, N) == core::cmp::Ordering::Less {
            volatile_zero(&mut k);
            volatile_zero(&mut v);
            return Ok(candidate);
        }
        k = hmac_sha256(&k, &[&v, &[0]]);
        v = hmac_sha256(&k, &[&v]);
    }
    volatile_zero(&mut k);
    volatile_zero(&mut v);
    Err(P256Error::SigningFailed)
}

fn encode_der_integer<'a>(value: &[u8], output: &'a mut [u8]) -> Result<&'a [u8], P256Error> {
    let first = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len() - 1);
    let value = &value[first..];
    let prefix = usize::from(value[0] & 0x80 != 0);
    let length = value.len() + prefix;
    if output.len() < length + 2 {
        return Err(P256Error::OutputTooSmall);
    }
    output[0] = 2;
    output[1] = length as u8;
    if prefix == 1 {
        output[2] = 0;
    }
    output[2 + prefix..2 + length].copy_from_slice(value);
    Ok(&output[..2 + length])
}

pub fn encode_der_signature<'a>(
    raw: &[u8; 64],
    output: &'a mut [u8],
) -> Result<&'a [u8], P256Error> {
    let mut r = [0u8; 35];
    let mut s = [0u8; 35];
    let r_len = encode_der_integer(&raw[..32], &mut r)?.len();
    let s_len = encode_der_integer(&raw[32..], &mut s)?.len();
    let length = r_len + s_len;
    if output.len() < length + 2 {
        return Err(P256Error::OutputTooSmall);
    }
    output[0] = 0x30;
    output[1] = length as u8;
    output[2..2 + r_len].copy_from_slice(&r[..r_len]);
    output[2 + r_len..2 + length].copy_from_slice(&s[..s_len]);
    Ok(&output[..2 + length])
}

fn from_be(bytes: &[u8]) -> Option<U256> {
    if bytes.is_empty() || bytes.len() > 32 {
        return None;
    }
    let mut out = [0; 4];
    for (index, byte) in bytes.iter().rev().enumerate() {
        out[index / 8] |= u64::from(*byte) << (8 * (index & 7));
    }
    Some(out)
}

fn compare(a: U256, b: U256) -> core::cmp::Ordering {
    for index in (0..4).rev() {
        if a[index] != b[index] {
            return a[index].cmp(&b[index]);
        }
    }
    core::cmp::Ordering::Equal
}

fn subtract_raw(a: U256, b: U256) -> (U256, u64) {
    let mut out = [0; 4];
    let mut borrow = 0u128;
    for index in 0..4 {
        let subtrahend = u128::from(b[index]) + borrow;
        let value = (1u128 << 64) + u128::from(a[index]) - subtrahend;
        out[index] = value as u64;
        borrow = 1 - (value >> 64);
    }
    (out, borrow as u64)
}

fn add_mod(a: U256, b: U256, modulus: U256) -> U256 {
    let (threshold, _) = subtract_raw(modulus, b);
    if compare(a, threshold) != core::cmp::Ordering::Less {
        subtract_raw(a, threshold).0
    } else {
        let mut out = [0; 4];
        let mut carry = 0u128;
        for index in 0..4 {
            let value = u128::from(a[index]) + u128::from(b[index]) + carry;
            out[index] = value as u64;
            carry = value >> 64;
        }
        out
    }
}

fn sub_mod(a: U256, b: U256, modulus: U256) -> U256 {
    if compare(a, b) != core::cmp::Ordering::Less {
        subtract_raw(a, b).0
    } else {
        let difference = subtract_raw(b, a).0;
        subtract_raw(modulus, difference).0
    }
}

fn mul_mod(mut a: U256, b: U256, modulus: U256) -> U256 {
    let mut out = [0; 4];
    for bit in 0..256 {
        if (b[bit / 64] >> (bit & 63)) & 1 != 0 {
            out = add_mod(out, a, modulus);
        }
        a = add_mod(a, a, modulus);
    }
    out
}

fn pow_mod(mut base: U256, exponent: U256, modulus: U256) -> U256 {
    let mut out = [1, 0, 0, 0];
    for bit in 0..256 {
        if (exponent[bit / 64] >> (bit & 63)) & 1 != 0 {
            out = mul_mod(out, base, modulus);
        }
        base = mul_mod(base, base, modulus);
    }
    out
}

fn inverse(value: U256, modulus: U256) -> Option<U256> {
    if value == [0; 4] || compare(value, modulus) != core::cmp::Ordering::Less {
        return None;
    }
    let two = [2, 0, 0, 0];
    Some(pow_mod(value, subtract_raw(modulus, two).0, modulus))
}

#[derive(Clone, Copy)]
struct Affine {
    x: U256,
    y: U256,
}

#[derive(Clone, Copy)]
struct Jacobian {
    x: U256,
    y: U256,
    z: U256,
}

impl Jacobian {
    const fn infinity() -> Self {
        Self {
            x: [0; 4],
            y: [1, 0, 0, 0],
            z: [0; 4],
        }
    }

    fn from_affine(point: Affine) -> Self {
        Self {
            x: point.x,
            y: point.y,
            z: [1, 0, 0, 0],
        }
    }

    fn double(self) -> Self {
        if self.z == [0; 4] || self.y == [0; 4] {
            return Self::infinity();
        }
        let delta = mul_mod(self.z, self.z, P);
        let gamma = mul_mod(self.y, self.y, P);
        let beta = mul_mod(self.x, gamma, P);
        let mut alpha = mul_mod(sub_mod(self.x, delta, P), add_mod(self.x, delta, P), P);
        alpha = add_mod(alpha, add_mod(alpha, alpha, P), P);
        let eight_beta = add_mod(add_mod(beta, beta, P), add_mod(beta, beta, P), P);
        let eight_beta = add_mod(eight_beta, eight_beta, P);
        let x = sub_mod(mul_mod(alpha, alpha, P), eight_beta, P);
        let four_beta = add_mod(add_mod(beta, beta, P), add_mod(beta, beta, P), P);
        let gamma_squared = mul_mod(gamma, gamma, P);
        let eight_gamma_squared = add_mod(
            add_mod(
                add_mod(gamma_squared, gamma_squared, P),
                add_mod(gamma_squared, gamma_squared, P),
                P,
            ),
            add_mod(
                add_mod(gamma_squared, gamma_squared, P),
                add_mod(gamma_squared, gamma_squared, P),
                P,
            ),
            P,
        );
        let y = sub_mod(
            mul_mod(alpha, sub_mod(four_beta, x, P), P),
            eight_gamma_squared,
            P,
        );
        let z = sub_mod(
            sub_mod(
                mul_mod(add_mod(self.y, self.z, P), add_mod(self.y, self.z, P), P),
                gamma,
                P,
            ),
            delta,
            P,
        );
        Self { x, y, z }
    }

    fn add_affine(self, other: Affine) -> Self {
        if self.z == [0; 4] {
            return Self::from_affine(other);
        }
        let zz = mul_mod(self.z, self.z, P);
        let u = mul_mod(other.x, zz, P);
        let s = mul_mod(other.y, mul_mod(self.z, zz, P), P);
        if u == self.x {
            return if s == self.y {
                self.double()
            } else {
                Self::infinity()
            };
        }
        let h = sub_mod(u, self.x, P);
        let hh = mul_mod(h, h, P);
        let i = add_mod(add_mod(hh, hh, P), add_mod(hh, hh, P), P);
        let j = mul_mod(h, i, P);
        let r = add_mod(sub_mod(s, self.y, P), sub_mod(s, self.y, P), P);
        let v = mul_mod(self.x, i, P);
        let x = sub_mod(sub_mod(mul_mod(r, r, P), j, P), add_mod(v, v, P), P);
        let y = sub_mod(
            mul_mod(r, sub_mod(v, x, P), P),
            mul_mod(add_mod(self.y, self.y, P), j, P),
            P,
        );
        let z = sub_mod(
            sub_mod(
                mul_mod(add_mod(self.z, h, P), add_mod(self.z, h, P), P),
                zz,
                P,
            ),
            hh,
            P,
        );
        Self { x, y, z }
    }

    fn affine(self) -> Option<Affine> {
        let inverse = inverse(self.z, P)?;
        let inverse_squared = mul_mod(inverse, inverse, P);
        Some(Affine {
            x: mul_mod(self.x, inverse_squared, P),
            y: mul_mod(self.y, mul_mod(inverse_squared, inverse, P), P),
        })
    }
}

fn scalar(point: Affine, value: U256) -> Jacobian {
    let mut out = Jacobian::infinity();
    for bit in (0..256).rev() {
        out = out.double();
        if (value[bit / 64] >> (bit & 63)) & 1 != 0 {
            out = out.add_affine(point);
        }
    }
    out
}

fn integer(input: &[u8], at: &mut usize) -> Option<U256> {
    if input.get(*at) != Some(&2) {
        return None;
    }
    *at += 1;
    let length = usize::from(*input.get(*at)?);
    *at += 1;
    let end = at.checked_add(length)?;
    let mut bytes = input.get(*at..end)?;
    *at = end;
    if bytes.first() == Some(&0) {
        bytes = &bytes[1..];
    }
    let value = from_be(bytes)?;
    (value != [0; 4] && compare(value, N) == core::cmp::Ordering::Less).then_some(value)
}

pub fn ecdsa_p256_sha256_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), P256Error> {
    let public = public_point(public_key).ok_or(P256Error::InvalidKey)?;
    if signature.len() < 8
        || signature[0] != 0x30
        || usize::from(signature[1]) + 2 != signature.len()
    {
        return Err(P256Error::InvalidSignature);
    }
    let mut at = 2;
    let r = integer(signature, &mut at).ok_or(P256Error::InvalidSignature)?;
    let s = integer(signature, &mut at).ok_or(P256Error::InvalidSignature)?;
    if at != signature.len() {
        return Err(P256Error::InvalidSignature);
    }
    let digest = Sha256::digest(message);
    verify_digest_scalars(public, &digest, r, s)
}

fn verify_digest_scalars(
    public: Affine,
    digest: &[u8; 32],
    r: U256,
    s: U256,
) -> Result<(), P256Error> {
    let mut z = from_be(digest).ok_or(P256Error::InvalidSignature)?;
    if compare(z, N) != core::cmp::Ordering::Less {
        z = subtract_raw(z, N).0;
    }
    let inverse = inverse(s, N).ok_or(P256Error::InvalidSignature)?;
    let left = scalar(Affine { x: GX, y: GY }, mul_mod(z, inverse, N))
        .affine()
        .ok_or(P256Error::InvalidSignature)?;
    let right = scalar(public, mul_mod(r, inverse, N))
        .affine()
        .ok_or(P256Error::InvalidSignature)?;
    let point = Jacobian::from_affine(left)
        .add_affine(right)
        .affine()
        .ok_or(P256Error::InvalidSignature)?;
    let x = if compare(point.x, N) == core::cmp::Ordering::Less {
        point.x
    } else {
        subtract_raw(point.x, N).0
    };
    (x == r).then_some(()).ok_or(P256Error::InvalidSignature)
}

pub fn ecdsa_p256_digest_verify_raw(
    public_key: &[u8],
    digest: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), P256Error> {
    let public = public_point(public_key).ok_or(P256Error::InvalidKey)?;
    let r = from_be(&signature[..32]).ok_or(P256Error::InvalidSignature)?;
    let s = from_be(&signature[32..]).ok_or(P256Error::InvalidSignature)?;
    if r == [0; 4]
        || s == [0; 4]
        || compare(r, N) != core::cmp::Ordering::Less
        || compare(s, N) != core::cmp::Ordering::Less
    {
        return Err(P256Error::InvalidSignature);
    }
    verify_digest_scalars(public, digest, r, s)
}

fn public_point(public_key: &[u8]) -> Option<Affine> {
    if public_key.len() != 65 || public_key[0] != 4 {
        return None;
    }
    let public = Affine {
        x: from_be(&public_key[1..33])?,
        y: from_be(&public_key[33..])?,
    };
    (compare(public.x, P) == core::cmp::Ordering::Less
        && compare(public.y, P) == core::cmp::Ordering::Less
        && mul_mod(public.y, public.y, P)
            == add_mod(
                sub_mod(
                    mul_mod(mul_mod(public.x, public.x, P), public.x, P),
                    add_mod(public.x, add_mod(public.x, public.x, P), P),
                    P,
                ),
                B,
                P,
            ))
    .then_some(public)
}

pub fn p256_public_key_is_valid(public_key: &[u8]) -> bool {
    public_point(public_key).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), N * 2);
        let mut out = [0u8; N];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn rfc6979_p256_sha256_signature_is_deterministic_low_s_and_self_verified() {
        let key = P256SecretKey::from_bytes(hex(
            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
        ))
        .unwrap();
        let public = key.public_key().unwrap();
        let mut expected_public = [0u8; 65];
        expected_public[0] = 4;
        expected_public[1..33].copy_from_slice(&hex::<32>(
            "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
        ));
        expected_public[33..].copy_from_slice(&hex::<32>(
            "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
        ));
        assert_eq!(public, expected_public);
        let digest = Sha256::digest(b"sample");
        let signature = key.sign_digest_raw(&digest).unwrap();
        assert_eq!(
            signature[..32],
            hex::<32>("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716")
        );
        assert_eq!(
            signature[32..],
            hex::<32>("0834E36AD29A83BF2BC9385E491D6099C8FDF9D1ED67AA7EA5F51F93782857A9")
        );
        assert_eq!(
            ecdsa_p256_digest_verify_raw(&public, &digest, &signature),
            Ok(())
        );
        assert_eq!(signature, key.sign_digest_raw(&digest).unwrap());
        let mut der = [0u8; 72];
        let der = key.sign_digest_der(&digest, &mut der).unwrap();
        assert_eq!(ecdsa_p256_sha256_verify(&public, b"sample", der), Ok(()));
    }

    #[test]
    fn key_generation_rejects_invalid_draws_and_fails_closed() {
        let mut calls = 0usize;
        let key = P256SecretKey::generate_with(|output| {
            calls += 1;
            output.fill(0);
            if calls == 2 {
                output[31] = 1;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(key.public_key().unwrap()[1..33], to_be(GX));
        assert_eq!(
            P256SecretKey::generate_with(|_| Err(P256Error::EntropyUnavailable)).err(),
            Some(P256Error::EntropyUnavailable)
        );
    }

    #[test]
    fn validates_only_strict_uncompressed_curve_points() {
        let generator = [
            &[4][..],
            &[
                0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
                0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
                0xd8, 0x98, 0xc2, 0x96,
            ],
            &[
                0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
                0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
                0x37, 0xbf, 0x51, 0xf5,
            ],
        ]
        .concat();
        assert!(p256_public_key_is_valid(&generator));
        let mut invalid = generator;
        invalid[64] ^= 1;
        assert!(!p256_public_key_is_valid(&invalid));
        assert!(!p256_public_key_is_valid(&invalid[1..]));
    }

    #[test]
    fn verifies_independent_openssl_signature_when_configured() {
        let Some(public_path) = mrml_runtime::environment_variable("MRML_P256_TEST_PUBLIC_DER")
        else {
            return;
        };
        let Some(message_path) = mrml_runtime::environment_variable("MRML_P256_TEST_MESSAGE")
        else {
            return;
        };
        let Some(signature_path) = mrml_runtime::environment_variable("MRML_P256_TEST_SIGNATURE")
        else {
            return;
        };
        let public = mrml_runtime::read_file(&public_path).unwrap();
        let message = mrml_runtime::read_file(&message_path).unwrap();
        let mut signature = mrml_runtime::read_file(&signature_path).unwrap();
        let point = public.get(public.len().checked_sub(65).unwrap()..).unwrap();
        assert_eq!(
            ecdsa_p256_sha256_verify(point, &message, &signature),
            Ok(())
        );
        let last = signature.len() - 1;
        signature[last] ^= 1;
        assert_eq!(
            ecdsa_p256_sha256_verify(point, &message, &signature),
            Err(P256Error::InvalidSignature)
        );
    }
}
