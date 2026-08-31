//! Dependency-free RFC 8032 Ed25519 primitives.
//!
//! Secret scalar operations use fixed iteration counts and conditional selection
//! instead of secret-indexed tables. Verification accepts only canonical point
//! and scalar encodings, rejects small-order points, and checks the RFC 8032
//! cofactored equation. This is pure Ed25519, not Ed25519ph or Ed25519ctx.
//! Owned secret-derived temporary buffers are cleared with best-effort volatile
//! stores, but this does not guarantee erasure of compiler-created copies,
//! registers, caches, swap, or hardware traces.

use crate::{Sha512, zeroize::volatile_zero};

const FIELD_MASK: u64 = (1u64 << 51) - 1;
const FIELD_MODULUS_BYTES: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

#[derive(Clone, Copy)]
struct Field([u64; 5]);

impl Field {
    const ZERO: Self = Self([0; 5]);
    const ONE: Self = Self([1, 0, 0, 0, 0]);
    const D: Self = Self([
        929_955_233_495_203,
        466_365_720_129_213,
        1_662_059_464_998_953,
        2_033_849_074_728_123,
        1_442_794_654_840_575,
    ]);
    const SQRT_M1: Self = Self([
        1_718_705_420_411_056,
        234_908_883_556_509,
        2_233_514_472_574_048,
        2_117_202_627_021_982,
        765_476_049_583_133,
    ]);

    fn from_bytes_unchecked(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 5];
        for bit in 0..255 {
            limbs[bit / 51] |= (((bytes[bit / 8] >> (bit % 8)) & 1) as u64) << (bit % 51);
        }
        Self(limbs)
    }

    fn from_bytes_canonical(bytes: &[u8; 32]) -> Option<Self> {
        for index in (0..32).rev() {
            if bytes[index] < FIELD_MODULUS_BYTES[index] {
                return Some(Self::from_bytes_unchecked(bytes));
            }
            if bytes[index] > FIELD_MODULUS_BYTES[index] {
                return None;
            }
        }
        None
    }

    fn carry(&mut self) {
        for index in 0..4 {
            let carry = self.0[index] >> 51;
            self.0[index] &= FIELD_MASK;
            self.0[index + 1] += carry;
        }
        let carry = self.0[4] >> 51;
        self.0[4] &= FIELD_MASK;
        self.0[0] += carry * 19;
        let carry = self.0[0] >> 51;
        self.0[0] &= FIELD_MASK;
        self.0[1] += carry;
    }

    fn add(self, other: Self) -> Self {
        let mut output = Self([0; 5]);
        for index in 0..5 {
            output.0[index] = self.0[index] + other.0[index];
        }
        output.carry();
        output
    }

    fn sub(self, other: Self) -> Self {
        let mut output = Self([0; 5]);
        output.0[0] = self.0[0] + (1u64 << 52) - 38 - other.0[0];
        for index in 1..5 {
            output.0[index] = self.0[index] + (1u64 << 52) - 2 - other.0[index];
        }
        output.carry();
        output
    }

    fn negate(self) -> Self {
        Self::ZERO.sub(self)
    }

    fn mul(self, other: Self) -> Self {
        let a = self.0;
        let b = other.0;
        let mut wide = [0u128; 5];
        wide[0] = a[0] as u128 * b[0] as u128
            + 19 * (a[1] as u128 * b[4] as u128
                + a[2] as u128 * b[3] as u128
                + a[3] as u128 * b[2] as u128
                + a[4] as u128 * b[1] as u128);
        wide[1] = a[0] as u128 * b[1] as u128
            + a[1] as u128 * b[0] as u128
            + 19 * (a[2] as u128 * b[4] as u128
                + a[3] as u128 * b[3] as u128
                + a[4] as u128 * b[2] as u128);
        wide[2] = a[0] as u128 * b[2] as u128
            + a[1] as u128 * b[1] as u128
            + a[2] as u128 * b[0] as u128
            + 19 * (a[3] as u128 * b[4] as u128 + a[4] as u128 * b[3] as u128);
        wide[3] = a[0] as u128 * b[3] as u128
            + a[1] as u128 * b[2] as u128
            + a[2] as u128 * b[1] as u128
            + a[3] as u128 * b[0] as u128
            + 19 * a[4] as u128 * b[4] as u128;
        wide[4] = a[0] as u128 * b[4] as u128
            + a[1] as u128 * b[3] as u128
            + a[2] as u128 * b[2] as u128
            + a[3] as u128 * b[1] as u128
            + a[4] as u128 * b[0] as u128;
        for index in 0..4 {
            let carry = wide[index] >> 51;
            wide[index] &= FIELD_MASK as u128;
            wide[index + 1] += carry;
        }
        let carry = wide[4] >> 51;
        wide[4] &= FIELD_MASK as u128;
        wide[0] += carry * 19;
        let carry = wide[0] >> 51;
        wide[0] &= FIELD_MASK as u128;
        wide[1] += carry;
        let mut output = Self([
            wide[0] as u64,
            wide[1] as u64,
            wide[2] as u64,
            wide[3] as u64,
            wide[4] as u64,
        ]);
        output.carry();
        output
    }

    fn square(self) -> Self {
        self.mul(self)
    }

    fn pow(self, exponent: &[u8; 32], bits: usize) -> Self {
        let mut result = Self::ONE;
        for bit in (0..bits).rev() {
            result = result.square();
            if (exponent[bit / 8] >> (bit % 8)) & 1 != 0 {
                result = result.mul(self);
            }
        }
        result
    }

    fn invert(self) -> Self {
        const P_MINUS_TWO: [u8; 32] = [
            0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        self.pow(&P_MINUS_TWO, 255)
    }

    fn sqrt(self) -> Option<Self> {
        const P_PLUS_THREE_OVER_EIGHT: [u8; 32] = [
            0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x0f,
        ];
        let mut root = self.pow(&P_PLUS_THREE_OVER_EIGHT, 252);
        if !root.square().equals(self) {
            root = root.mul(Self::SQRT_M1);
        }
        root.square().equals(self).then_some(root)
    }

    fn to_bytes(mut self) -> [u8; 32] {
        self.carry();
        self.carry();
        let modulus = [
            FIELD_MASK - 18,
            FIELD_MASK,
            FIELD_MASK,
            FIELD_MASK,
            FIELD_MASK,
        ];
        let mut reduced = [0u64; 5];
        let mut borrow = 0u64;
        for (index, value) in reduced.iter_mut().enumerate() {
            let subtrahend = modulus[index] + borrow;
            *value = self.0[index].wrapping_sub(subtrahend) & FIELD_MASK;
            borrow = (self.0[index] < subtrahend) as u64;
        }
        let reduce_mask = 0u64.wrapping_sub(borrow ^ 1);
        for (value, reduced) in self.0.iter_mut().zip(reduced) {
            *value = (*value & !reduce_mask) | (reduced & reduce_mask);
        }
        let mut output = [0u8; 32];
        for bit in 0..255 {
            output[bit / 8] |= (((self.0[bit / 51] >> (bit % 51)) & 1) as u8) << (bit % 8);
        }
        output
    }

    fn equals(self, other: Self) -> bool {
        let left = self.to_bytes();
        let right = other.to_bytes();
        let mut difference = 0u8;
        for index in 0..32 {
            difference |= left[index] ^ right[index];
        }
        difference == 0
    }

    fn is_zero(self) -> bool {
        self.equals(Self::ZERO)
    }

    fn is_negative(self) -> u64 {
        (self.to_bytes()[0] & 1) as u64
    }

    fn select(left: Self, right: Self, choose_right: u64) -> Self {
        let mask = 0u64.wrapping_sub(choose_right);
        let mut output = [0u64; 5];
        for index in 0..5 {
            output[index] = (left.0[index] & !mask) | (right.0[index] & mask);
        }
        Self(output)
    }
}

#[derive(Clone, Copy)]
struct Point {
    x: Field,
    y: Field,
    z: Field,
    t: Field,
}

impl Point {
    const fn identity() -> Self {
        Self {
            x: Field::ZERO,
            y: Field::ONE,
            z: Field::ONE,
            t: Field::ZERO,
        }
    }

    fn base() -> Self {
        let x = Field([
            1_738_742_601_995_546,
            1_146_398_526_822_698,
            2_070_867_633_025_821,
            562_264_141_797_630,
            587_772_402_128_613,
        ]);
        let y = Field([
            1_801_439_850_948_184,
            1_351_079_888_211_148,
            450_359_962_737_049,
            900_719_925_474_099,
            1_801_439_850_948_198,
        ]);
        Self {
            x,
            y,
            z: Field::ONE,
            t: x.mul(y),
        }
    }

    fn add(self, other: Self) -> Self {
        let a = self.y.sub(self.x).mul(other.y.sub(other.x));
        let b = self.y.add(self.x).mul(other.y.add(other.x));
        let c = self.t.mul(other.t).mul(Field::D.add(Field::D));
        let d = self.z.mul(other.z).add(self.z.mul(other.z));
        let e = b.sub(a);
        let f = d.sub(c);
        let g = d.add(c);
        let h = b.add(a);
        Self {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }

    fn select(left: Self, right: Self, choose_right: u64) -> Self {
        Self {
            x: Field::select(left.x, right.x, choose_right),
            y: Field::select(left.y, right.y, choose_right),
            z: Field::select(left.z, right.z, choose_right),
            t: Field::select(left.t, right.t, choose_right),
        }
    }

    fn scalar_mul(self, scalar: Scalar) -> Self {
        let mut result = Self::identity();
        for bit in (0..256).rev() {
            let doubled = result.add(result);
            let with_point = doubled.add(self);
            result = Self::select(doubled, with_point, scalar.bit(bit));
        }
        result
    }

    fn mul_by_cofactor(self) -> Self {
        let twice = self.add(self);
        let four = twice.add(twice);
        four.add(four)
    }

    fn compress(self) -> [u8; 32] {
        let inverse = self.z.invert();
        let x = self.x.mul(inverse);
        let y = self.y.mul(inverse);
        let mut encoded = y.to_bytes();
        encoded[31] |= (x.is_negative() as u8) << 7;
        encoded
    }

    fn decode(encoded: &[u8; 32]) -> Option<Self> {
        let sign = (encoded[31] >> 7) as u64;
        let mut y_bytes = *encoded;
        y_bytes[31] &= 0x7f;
        let y = Field::from_bytes_canonical(&y_bytes)?;
        let y_squared = y.square();
        let denominator = Field::D.mul(y_squared).add(Field::ONE);
        if denominator.is_zero() {
            return None;
        }
        let x_squared = y_squared.sub(Field::ONE).mul(denominator.invert());
        let mut x = x_squared.sqrt()?;
        if x.is_zero() && sign != 0 {
            return None;
        }
        if x.is_negative() != sign {
            x = x.negate();
        }
        Some(Self {
            x,
            y,
            z: Field::ONE,
            t: x.mul(y),
        })
    }

    fn equals(self, other: Self) -> bool {
        self.x.mul(other.z).equals(other.x.mul(self.z))
            && self.y.mul(other.z).equals(other.y.mul(self.z))
    }

    fn is_identity(self) -> bool {
        self.x.is_zero() && self.y.equals(self.z)
    }

    fn has_small_order(self) -> bool {
        self.mul_by_cofactor().is_identity()
    }
}

const SCALAR_MODULUS: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0,
    0x1000_0000_0000_0000,
];

#[derive(Clone, Copy)]
struct Scalar([u64; 4]);

impl Scalar {
    const ZERO: Self = Self([0; 4]);

    fn from_wide(bytes: &[u8; 64]) -> Self {
        let mut output = Self::ZERO;
        for bit in (0..512).rev() {
            let incoming = ((bytes[bit / 8] >> (bit % 8)) & 1) as u64;
            let mut carry = incoming;
            for limb in &mut output.0 {
                let next = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = next;
            }
            output = output.reduce_once();
        }
        output
    }

    fn from_bytes_mod_order(bytes: &[u8; 32]) -> Self {
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(bytes);
        Self::from_wide(&wide)
    }

    fn from_canonical(bytes: &[u8; 32]) -> Option<Self> {
        let mut limbs = [0u64; 4];
        for (index, limb) in limbs.iter_mut().enumerate() {
            *limb = u64::from_le_bytes(
                bytes[index * 8..index * 8 + 8]
                    .try_into()
                    .expect("fixed Ed25519 scalar limb"),
            );
        }
        let scalar = Self(limbs);
        let (_, borrow) = scalar.subtract_modulus();
        (borrow != 0).then_some(scalar)
    }

    fn subtract_modulus(self) -> (Self, u64) {
        let mut output = [0u64; 4];
        let mut borrow = false;
        for index in 0..4 {
            let (difference, first_borrow) = self.0[index].overflowing_sub(SCALAR_MODULUS[index]);
            let (difference, second_borrow) = difference.overflowing_sub(borrow as u64);
            output[index] = difference;
            borrow = first_borrow | second_borrow;
        }
        (Self(output), borrow as u64)
    }

    fn reduce_once(self) -> Self {
        let (reduced, borrow) = self.subtract_modulus();
        Self::select(self, reduced, borrow ^ 1)
    }

    fn add(self, other: Self) -> Self {
        let mut output = [0u64; 4];
        let mut carry = 0u128;
        for index in 0..4 {
            let sum = self.0[index] as u128 + other.0[index] as u128 + carry;
            output[index] = sum as u64;
            carry = sum >> 64;
        }
        Self(output).reduce_once()
    }

    fn mul(self, other: Self) -> Self {
        let mut result = Self::ZERO;
        let mut addend = self;
        for bit in 0..256 {
            let with_addend = result.add(addend);
            result = Self::select(result, with_addend, other.bit(bit));
            addend = addend.add(addend);
        }
        result
    }

    fn bit(self, bit: usize) -> u64 {
        (self.0[bit / 64] >> (bit % 64)) & 1
    }

    fn select(left: Self, right: Self, choose_right: u64) -> Self {
        let mask = 0u64.wrapping_sub(choose_right);
        let mut output = [0u64; 4];
        for index in 0..4 {
            output[index] = (left.0[index] & !mask) | (right.0[index] & mask);
        }
        Self(output)
    }

    fn to_bytes(self) -> [u8; 32] {
        let mut output = [0u8; 32];
        for (index, limb) in self.0.iter().enumerate() {
            output[index * 8..index * 8 + 8].copy_from_slice(&limb.to_le_bytes());
        }
        output
    }

    fn wipe(&mut self) {
        volatile_zero(&mut self.0);
    }
}

fn expanded_secret(seed: &[u8; 32]) -> ([u8; 64], Scalar) {
    let expanded = Sha512::digest(seed);
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&expanded[..32]);
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 63;
    scalar_bytes[31] |= 64;
    let scalar = Scalar::from_bytes_mod_order(&scalar_bytes);
    volatile_zero(&mut scalar_bytes);
    (expanded, scalar)
}

/// Derives an RFC 8032 Ed25519 public key from a 32-byte private seed.
pub fn ed25519_public(seed: &[u8; 32]) -> [u8; 32] {
    let (mut expanded, mut scalar) = expanded_secret(seed);
    let public = Point::base().scalar_mul(scalar).compress();
    scalar.wipe();
    volatile_zero(&mut expanded);
    public
}

/// Checks whether an Ed25519 public key has the verifier's accepted encoding.
///
/// Acceptance requires a canonical compressed Edwards point that decodes on
/// the curve and is not a small-order point. This validates key material only;
/// it does not authorize the key, prove prime-subgroup membership, or provide
/// any trust or provenance decision.
pub fn ed25519_public_is_valid(public: &[u8; 32]) -> bool {
    Point::decode(public).is_some_and(|point| !point.has_small_order())
}

/// Creates a deterministic pure-Ed25519 signature from a 32-byte private seed.
pub fn ed25519_sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let (mut expanded, mut secret_scalar) = expanded_secret(seed);
    let public = Point::base().scalar_mul(secret_scalar).compress();

    let mut nonce_hash = Sha512::new();
    nonce_hash.update(&expanded[32..]);
    nonce_hash.update(message);
    let mut nonce_wide = nonce_hash.finalize();
    let mut nonce = Scalar::from_wide(&nonce_wide);
    let encoded_r = Point::base().scalar_mul(nonce).compress();

    let mut challenge_hash = Sha512::new();
    challenge_hash.update(&encoded_r);
    challenge_hash.update(&public);
    challenge_hash.update(message);
    let mut challenge_wide = challenge_hash.finalize();
    let challenge = Scalar::from_wide(&challenge_wide);
    let s = nonce.add(challenge.mul(secret_scalar));

    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&encoded_r);
    signature[32..].copy_from_slice(&s.to_bytes());
    secret_scalar.wipe();
    nonce.wipe();
    volatile_zero(&mut expanded);
    volatile_zero(&mut nonce_wide);
    volatile_zero(&mut challenge_wide);
    signature
}

/// Strictly verifies a pure-Ed25519 signature using the cofactored equation.
pub fn ed25519_verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Some(public_point) = Point::decode(public) else {
        return false;
    };
    if public_point.has_small_order() {
        return false;
    }

    let mut encoded_r = [0u8; 32];
    encoded_r.copy_from_slice(&signature[..32]);
    let Some(r_point) = Point::decode(&encoded_r) else {
        return false;
    };
    if r_point.has_small_order() {
        return false;
    }

    let mut encoded_s = [0u8; 32];
    encoded_s.copy_from_slice(&signature[32..]);
    let Some(s) = Scalar::from_canonical(&encoded_s) else {
        return false;
    };

    let mut challenge_hash = Sha512::new();
    challenge_hash.update(&encoded_r);
    challenge_hash.update(public);
    challenge_hash.update(message);
    let challenge = Scalar::from_wide(&challenge_hash.finalize());

    let left = Point::base().scalar_mul(s).mul_by_cofactor();
    let right = r_point
        .add(public_point.scalar_mul(challenge))
        .mul_by_cofactor();
    left.equals(right)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode<const N: usize>(hex: &str) -> [u8; N] {
        let mut output = [0u8; N];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        output
    }

    fn check_vector(seed: &str, public: &str, message: &[u8], signature: &str) {
        let seed = decode(seed);
        let public = decode(public);
        let signature = decode(signature);
        assert_eq!(ed25519_public(&seed), public);
        assert_eq!(ed25519_sign(&seed, message), signature);
        assert!(ed25519_verify(&public, message, &signature));
    }

    #[test]
    fn rfc_8032_vectors() {
        check_vector(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            b"",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        check_vector(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            &[0x72],
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        );
        check_vector(
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            &[0xaf, 0x82],
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        );
    }

    #[test]
    fn rejects_modified_message_and_signature() {
        let seed = [0x42; 32];
        let public = ed25519_public(&seed);
        let mut signature = ed25519_sign(&seed, b"bounded message");
        assert!(ed25519_verify(&public, b"bounded message", &signature));
        assert!(!ed25519_verify(&public, b"different message", &signature));
        signature[17] ^= 0x80;
        assert!(!ed25519_verify(&public, b"bounded message", &signature));
    }

    #[test]
    fn rejects_noncanonical_scalar() {
        let seed = [0x19; 32];
        let public = ed25519_public(&seed);
        let mut signature = ed25519_sign(&seed, b"message");
        let modulus = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        signature[32..].copy_from_slice(&modulus);
        assert!(!ed25519_verify(&public, b"message", &signature));
    }

    #[test]
    fn rejects_noncanonical_and_invalid_points() {
        let seed = [0x51; 32];
        let public = ed25519_public(&seed);
        let signature = ed25519_sign(&seed, b"message");

        let noncanonical_y = FIELD_MODULUS_BYTES;
        assert!(!ed25519_verify(&noncanonical_y, b"message", &signature));

        let mut negative_zero = [0u8; 32];
        negative_zero[0] = 1;
        negative_zero[31] = 0x80;
        assert!(!ed25519_verify(&negative_zero, b"message", &signature));

        let mut noncanonical_r = signature;
        noncanonical_r[..32].copy_from_slice(&FIELD_MODULUS_BYTES);
        assert!(!ed25519_verify(&public, b"message", &noncanonical_r));
    }

    #[test]
    fn rejects_small_order_points() {
        let identity = {
            let mut encoded = [0u8; 32];
            encoded[0] = 1;
            encoded
        };
        let mut signature = [0u8; 64];
        signature[0] = 1;
        assert!(!ed25519_verify(&identity, b"", &signature));

        let seed = [7u8; 32];
        let public = ed25519_public(&seed);
        let mut signature = ed25519_sign(&seed, b"message");
        signature[..32].copy_from_slice(&identity);
        assert!(!ed25519_verify(&public, b"message", &signature));

        let order_four = [0u8; 32];
        let signature = ed25519_sign(&seed, b"message");
        assert!(!ed25519_verify(&order_four, b"message", &signature));
        let mut small_order_r = signature;
        small_order_r[..32].copy_from_slice(&order_four);
        assert!(!ed25519_verify(&public, b"message", &small_order_r));
    }

    #[test]
    fn validates_public_key_encodings() {
        let valid = decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        assert!(ed25519_public_is_valid(&valid));
        assert!(ed25519_public_is_valid(&ed25519_public(&[0x42; 32])));

        assert!(!ed25519_public_is_valid(&FIELD_MODULUS_BYTES));

        let mut negative_zero = [0u8; 32];
        negative_zero[0] = 1;
        negative_zero[31] = 0x80;
        assert!(!ed25519_public_is_valid(&negative_zero));

        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(!ed25519_public_is_valid(&identity));
        assert!(!ed25519_public_is_valid(&[0u8; 32]));
    }
}
