use crate::Sha256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P256Error {
    InvalidKey,
    InvalidSignature,
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
    if public_key.len() != 65 || public_key[0] != 4 {
        return Err(P256Error::InvalidKey);
    }
    let public = Affine {
        x: from_be(&public_key[1..33]).ok_or(P256Error::InvalidKey)?,
        y: from_be(&public_key[33..]).ok_or(P256Error::InvalidKey)?,
    };
    if compare(public.x, P) != core::cmp::Ordering::Less
        || compare(public.y, P) != core::cmp::Ordering::Less
        || mul_mod(public.y, public.y, P)
            != add_mod(
                sub_mod(
                    mul_mod(mul_mod(public.x, public.x, P), public.x, P),
                    add_mod(public.x, add_mod(public.x, public.x, P), P),
                    P,
                ),
                B,
                P,
            )
    {
        return Err(P256Error::InvalidKey);
    }
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
    let z = from_be(&Sha256::digest(message)).ok_or(P256Error::InvalidSignature)?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
