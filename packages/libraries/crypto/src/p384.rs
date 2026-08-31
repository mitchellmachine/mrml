use crate::Sha384;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P384Error {
    InvalidKey,
    InvalidSignature,
}

type U384 = [u64; 6];
const P: U384 = [
    0x0000_0000_ffff_ffff,
    0xffff_ffff_0000_0000,
    0xffff_ffff_ffff_fffe,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
];
const N: U384 = [
    0xecec_196a_ccc5_2973,
    0x581a_0db2_48b0_a77a,
    0xc763_4d81_f437_2ddf,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
];
const B: U384 = [
    0x2a85_c8ed_d3ec_2aef,
    0xc656_398d_8a2e_d19d,
    0x0314_088f_5013_875a,
    0x181d_9c6e_fe81_4112,
    0x988e_056b_e3f8_2d19,
    0xb331_2fa7_e23e_e7e4,
];
const GX: U384 = [
    0x3a54_5e38_7276_0ab7,
    0x5502_f25d_bf55_296c,
    0x59f7_41e0_8254_2a38,
    0x6e1d_3b62_8ba7_9b98,
    0x8eb1_c71e_f320_ad74,
    0xaa87_ca22_be8b_0537,
];
const GY: U384 = [
    0x7a43_1d7c_90ea_0e5f,
    0x0a60_b1ce_1d7e_819d,
    0xe9da_3113_b5f0_b8c0,
    0xf8f4_1dbd_289a_147c,
    0x5d9e_98bf_9292_dc29,
    0x3617_de4a_9626_2c6f,
];

fn from_be(bytes: &[u8]) -> Option<U384> {
    if bytes.is_empty() || bytes.len() > 48 {
        return None;
    }
    let mut out = [0; 6];
    for (index, byte) in bytes.iter().rev().enumerate() {
        out[index / 8] |= u64::from(*byte) << (8 * (index & 7));
    }
    Some(out)
}

fn compare(a: U384, b: U384) -> core::cmp::Ordering {
    for index in (0..6).rev() {
        if a[index] != b[index] {
            return a[index].cmp(&b[index]);
        }
    }
    core::cmp::Ordering::Equal
}

fn subtract_raw(a: U384, b: U384) -> U384 {
    let mut out = [0; 6];
    let mut borrow = 0u128;
    for index in 0..6 {
        let value = (1u128 << 64) + u128::from(a[index]) - u128::from(b[index]) - borrow;
        out[index] = value as u64;
        borrow = 1 - (value >> 64);
    }
    out
}

fn add_mod(a: U384, b: U384, modulus: U384) -> U384 {
    let threshold = subtract_raw(modulus, b);
    if compare(a, threshold) != core::cmp::Ordering::Less {
        subtract_raw(a, threshold)
    } else {
        let mut out = [0; 6];
        let mut carry = 0u128;
        for index in 0..6 {
            let value = u128::from(a[index]) + u128::from(b[index]) + carry;
            out[index] = value as u64;
            carry = value >> 64;
        }
        out
    }
}

fn sub_mod(a: U384, b: U384, modulus: U384) -> U384 {
    if compare(a, b) != core::cmp::Ordering::Less {
        subtract_raw(a, b)
    } else {
        subtract_raw(modulus, subtract_raw(b, a))
    }
}

fn mul_mod(mut a: U384, b: U384, modulus: U384) -> U384 {
    let mut out = [0; 6];
    for bit in 0..384 {
        if (b[bit / 64] >> (bit & 63)) & 1 != 0 {
            out = add_mod(out, a, modulus);
        }
        a = add_mod(a, a, modulus);
    }
    out
}

fn inverse(value: U384, modulus: U384) -> Option<U384> {
    if value == [0; 6] || compare(value, modulus) != core::cmp::Ordering::Less {
        return None;
    }
    let exponent = subtract_raw(modulus, [2, 0, 0, 0, 0, 0]);
    let mut base = value;
    let mut out = [1, 0, 0, 0, 0, 0];
    for bit in 0..384 {
        if (exponent[bit / 64] >> (bit & 63)) & 1 != 0 {
            out = mul_mod(out, base, modulus);
        }
        base = mul_mod(base, base, modulus);
    }
    Some(out)
}

#[derive(Clone, Copy)]
struct Affine {
    x: U384,
    y: U384,
}
#[derive(Clone, Copy)]
struct Jacobian {
    x: U384,
    y: U384,
    z: U384,
}

impl Jacobian {
    const fn infinity() -> Self {
        Self {
            x: [0; 6],
            y: [1, 0, 0, 0, 0, 0],
            z: [0; 6],
        }
    }
    fn from_affine(point: Affine) -> Self {
        Self {
            x: point.x,
            y: point.y,
            z: [1, 0, 0, 0, 0, 0],
        }
    }
    fn double(self) -> Self {
        if self.z == [0; 6] || self.y == [0; 6] {
            return Self::infinity();
        }
        let delta = mul_mod(self.z, self.z, P);
        let gamma = mul_mod(self.y, self.y, P);
        let beta = mul_mod(self.x, gamma, P);
        let product = mul_mod(sub_mod(self.x, delta, P), add_mod(self.x, delta, P), P);
        let alpha = add_mod(product, add_mod(product, product, P), P);
        let two_beta = add_mod(beta, beta, P);
        let four_beta = add_mod(two_beta, two_beta, P);
        let eight_beta = add_mod(four_beta, four_beta, P);
        let x = sub_mod(mul_mod(alpha, alpha, P), eight_beta, P);
        let gamma2 = mul_mod(gamma, gamma, P);
        let eight_gamma2 = add_mod(
            add_mod(gamma2, gamma2, P),
            add_mod(
                add_mod(gamma2, gamma2, P),
                add_mod(add_mod(gamma2, gamma2, P), add_mod(gamma2, gamma2, P), P),
                P,
            ),
            P,
        );
        let y = sub_mod(mul_mod(alpha, sub_mod(four_beta, x, P), P), eight_gamma2, P);
        let yz = add_mod(self.y, self.z, P);
        let z = sub_mod(sub_mod(mul_mod(yz, yz, P), gamma, P), delta, P);
        Self { x, y, z }
    }
    fn add_affine(self, other: Affine) -> Self {
        if self.z == [0; 6] {
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
        let difference = sub_mod(s, self.y, P);
        let r = add_mod(difference, difference, P);
        let v = mul_mod(self.x, i, P);
        let x = sub_mod(sub_mod(mul_mod(r, r, P), j, P), add_mod(v, v, P), P);
        let y = sub_mod(
            mul_mod(r, sub_mod(v, x, P), P),
            mul_mod(add_mod(self.y, self.y, P), j, P),
            P,
        );
        let zh = add_mod(self.z, h, P);
        let z = sub_mod(sub_mod(mul_mod(zh, zh, P), zz, P), hh, P);
        Self { x, y, z }
    }
    fn affine(self) -> Option<Affine> {
        let inverse = inverse(self.z, P)?;
        let inverse2 = mul_mod(inverse, inverse, P);
        Some(Affine {
            x: mul_mod(self.x, inverse2, P),
            y: mul_mod(self.y, mul_mod(inverse2, inverse, P), P),
        })
    }
}

fn scalar(point: Affine, value: U384) -> Jacobian {
    let mut out = Jacobian::infinity();
    for bit in (0..384).rev() {
        out = out.double();
        if (value[bit / 64] >> (bit & 63)) & 1 != 0 {
            out = out.add_affine(point);
        }
    }
    out
}

fn integer(input: &[u8], at: &mut usize) -> Option<U384> {
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
    (value != [0; 6] && compare(value, N) == core::cmp::Ordering::Less).then_some(value)
}

pub fn ecdsa_p384_sha384_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), P384Error> {
    if public_key.len() != 97 || public_key[0] != 4 {
        return Err(P384Error::InvalidKey);
    }
    let public = Affine {
        x: from_be(&public_key[1..49]).ok_or(P384Error::InvalidKey)?,
        y: from_be(&public_key[49..]).ok_or(P384Error::InvalidKey)?,
    };
    let x3 = mul_mod(mul_mod(public.x, public.x, P), public.x, P);
    let three_x = add_mod(public.x, add_mod(public.x, public.x, P), P);
    if compare(public.x, P) != core::cmp::Ordering::Less
        || compare(public.y, P) != core::cmp::Ordering::Less
        || mul_mod(public.y, public.y, P) != add_mod(sub_mod(x3, three_x, P), B, P)
    {
        return Err(P384Error::InvalidKey);
    }
    if signature.len() < 8
        || signature[0] != 0x30
        || usize::from(signature[1]) + 2 != signature.len()
    {
        return Err(P384Error::InvalidSignature);
    }
    let mut at = 2;
    let r = integer(signature, &mut at).ok_or(P384Error::InvalidSignature)?;
    let s = integer(signature, &mut at).ok_or(P384Error::InvalidSignature)?;
    if at != signature.len() {
        return Err(P384Error::InvalidSignature);
    }
    let z = from_be(&Sha384::digest(message)).ok_or(P384Error::InvalidSignature)?;
    let w = inverse(s, N).ok_or(P384Error::InvalidSignature)?;
    let left = scalar(Affine { x: GX, y: GY }, mul_mod(z, w, N))
        .affine()
        .ok_or(P384Error::InvalidSignature)?;
    let right = scalar(public, mul_mod(r, w, N))
        .affine()
        .ok_or(P384Error::InvalidSignature)?;
    let point = Jacobian::from_affine(left)
        .add_affine(right)
        .affine()
        .ok_or(P384Error::InvalidSignature)?;
    let x = if compare(point.x, N) == core::cmp::Ordering::Less {
        point.x
    } else {
        subtract_raw(point.x, N)
    };
    (x == r).then_some(()).ok_or(P384Error::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verifies_independent_openssl_signature_when_configured() {
        let Some(public_path) = mrml_runtime::environment_variable("MRML_P384_TEST_PUBLIC_DER")
        else {
            return;
        };
        let Some(message_path) = mrml_runtime::environment_variable("MRML_P384_TEST_MESSAGE")
        else {
            return;
        };
        let Some(signature_path) = mrml_runtime::environment_variable("MRML_P384_TEST_SIGNATURE")
        else {
            return;
        };
        let public = mrml_runtime::read_file(&public_path).unwrap();
        let message = mrml_runtime::read_file(&message_path).unwrap();
        let mut signature = mrml_runtime::read_file(&signature_path).unwrap();
        let point = public.get(public.len() - 97..).unwrap();
        assert_eq!(
            ecdsa_p384_sha384_verify(point, &message, &signature),
            Ok(())
        );
        let last = signature.len() - 1;
        signature[last] ^= 1;
        assert_eq!(
            ecdsa_p384_sha384_verify(point, &message, &signature),
            Err(P384Error::InvalidSignature)
        );
    }
}
