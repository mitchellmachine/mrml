//! Original, allocation-free ML-DSA-65 implementation following FIPS 204.
//!
//! The API exposes deterministic seed expansion and an explicit 32-byte
//! per-signature randomizer. Callers that need hedged signing must fill that
//! randomizer from an approved source. Context strings are bounded by FIPS 204.

use crate::{Shake128, Shake256, zeroize::volatile_zero};

pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1952;
pub const ML_DSA_65_SECRET_KEY_BYTES: usize = 4032;
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;

const N: usize = 256;
const Q: i32 = 8_380_417;
const D: i32 = 13;
const K: usize = 6;
const L: usize = 5;
const ETA: i32 = 4;
const TAU: usize = 49;
const BETA: i32 = 196;
const GAMMA1: i32 = 1 << 19;
const GAMMA2: i32 = (Q - 1) / 32;
const OMEGA: usize = 55;
const CTILDE_BYTES: usize = 48;
const TR_BYTES: usize = 64;
const POLYT1_BYTES: usize = 320;
const POLYETA_BYTES: usize = 128;
const POLYT0_BYTES: usize = 416;
const POLYZ_BYTES: usize = 640;
const POLYW1_BYTES: usize = 128;
const MAX_REJECTIONS: usize = 4096;
const QINV: i64 = 58_728_449;
const MONT: i64 = 4_193_792;
const ROOT: i64 = 1753;

type Poly = [i32; N];
type VecL = [Poly; L];
type VecK = [Poly; K];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlDsaError {
    BufferLength,
    ContextTooLong,
    InvalidKey,
    InvalidSignature,
    RejectionLimit,
    SamplingLimit,
}

fn shake256(parts: &[&[u8]], output: &mut [u8]) {
    let mut state = Shake256::new();
    for part in parts {
        state.update(part);
    }
    state.finalize(output);
}

fn bit_reverse(mut value: usize) -> usize {
    let mut output = 0usize;
    for _ in 0..8 {
        output = (output << 1) | (value & 1);
        value >>= 1;
    }
    output
}

fn mod_pow(mut base: i64, mut exponent: usize) -> i64 {
    let mut output = 1i64;
    while exponent != 0 {
        if exponent & 1 != 0 {
            output = output * base % i64::from(Q);
        }
        base = base * base % i64::from(Q);
        exponent >>= 1;
    }
    output
}

fn zeta(index: usize) -> i32 {
    let mut value = mod_pow(ROOT, bit_reverse(index)) * MONT % i64::from(Q);
    if value > i64::from(Q / 2) {
        value -= i64::from(Q);
    }
    value as i32
}

fn montgomery_reduce(value: i64) -> i32 {
    let low = (value as i32).wrapping_mul(QINV as i32) as i64;
    ((value - low * i64::from(Q)) >> 32) as i32
}

fn reduce32(value: i32) -> i32 {
    let quotient = (value + (1 << 22)) >> 23;
    value - quotient * Q
}

fn freeze(value: i32) -> i32 {
    let reduced = reduce32(value);
    reduced + ((reduced >> 31) & Q)
}

fn ntt(poly: &mut Poly) {
    let mut index = 0usize;
    let mut length = 128usize;
    while length != 0 {
        let mut start = 0usize;
        while start < N {
            index += 1;
            let factor = zeta(index);
            for offset in start..start + length {
                let product =
                    montgomery_reduce(i64::from(factor) * i64::from(poly[offset + length]));
                poly[offset + length] = poly[offset] - product;
                poly[offset] += product;
            }
            start += 2 * length;
        }
        length >>= 1;
    }
}

fn inverse_ntt(poly: &mut Poly) {
    let mut index = 256usize;
    let mut length = 1usize;
    while length < N {
        let mut start = 0usize;
        while start < N {
            index -= 1;
            let factor = -zeta(index);
            for offset in start..start + length {
                let value = poly[offset];
                poly[offset] = value + poly[offset + length];
                poly[offset + length] = value - poly[offset + length];
                poly[offset + length] =
                    montgomery_reduce(i64::from(factor) * i64::from(poly[offset + length]));
            }
            start += 2 * length;
        }
        length <<= 1;
    }
    for coefficient in poly {
        *coefficient = montgomery_reduce(i64::from(*coefficient) * 41_978);
    }
}

fn pointwise_accumulate(left: &[Poly; L], right: &[Poly; L]) -> Poly {
    let mut output = [0i32; N];
    for vector in 0..L {
        for coefficient in 0..N {
            output[coefficient] += montgomery_reduce(
                i64::from(left[vector][coefficient]) * i64::from(right[vector][coefficient]),
            );
        }
    }
    for coefficient in &mut output {
        *coefficient = reduce32(*coefficient);
    }
    output
}

fn matrix_row(rho: &[u8; 32], row: usize) -> Result<[Poly; L], MlDsaError> {
    let mut output = [[0i32; N]; L];
    for column in 0..L {
        let nonce = [column as u8, row as u8];
        let mut bytes = [0u8; 4096];
        let mut state = Shake128::new();
        state.update(rho);
        state.update(&nonce);
        state.finalize(&mut bytes);
        let mut used = 0usize;
        let mut written = 0usize;
        while written < N && used + 3 <= bytes.len() {
            let candidate = (u32::from(bytes[used])
                | (u32::from(bytes[used + 1]) << 8)
                | (u32::from(bytes[used + 2]) << 16))
                & 0x7f_ffff;
            used += 3;
            if candidate < Q as u32 {
                output[column][written] = candidate as i32;
                written += 1;
            }
        }
        if written != N {
            volatile_zero(&mut bytes);
            for poly in &mut output {
                volatile_zero(poly);
            }
            return Err(MlDsaError::SamplingLimit);
        }
        volatile_zero(&mut bytes);
    }
    Ok(output)
}

fn sample_eta(seed: &[u8; 64], nonce: u16) -> Result<Poly, MlDsaError> {
    let mut bytes = [0u8; 1024];
    let mut state = Shake256::new();
    state.update(seed);
    state.update(&nonce.to_le_bytes());
    state.finalize(&mut bytes);
    let mut output = [0i32; N];
    let mut written = 0usize;
    for byte in &bytes {
        for value in [byte & 0x0f, byte >> 4] {
            if value < 9 && written < N {
                output[written] = ETA - i32::from(value);
                written += 1;
            }
        }
    }
    volatile_zero(&mut bytes);
    if written != N {
        volatile_zero(&mut output);
        return Err(MlDsaError::SamplingLimit);
    }
    Ok(output)
}

fn pack_bits(values: &[u32], bits: usize, output: &mut [u8]) {
    output.fill(0);
    let mut bit = 0usize;
    for value in values {
        for shift in 0..bits {
            output[bit / 8] |= (((value >> shift) & 1) as u8) << (bit % 8);
            bit += 1;
        }
    }
}

fn unpack_bits(input: &[u8], bits: usize, values: &mut [u32]) {
    let mut bit = 0usize;
    for value in values {
        *value = 0;
        for shift in 0..bits {
            *value |= u32::from((input[bit / 8] >> (bit % 8)) & 1) << shift;
            bit += 1;
        }
    }
}

fn power2round(value: i32) -> (i32, i32) {
    let high = (value + (1 << (D - 1)) - 1) >> D;
    (high, value - (high << D))
}

fn decompose(value: i32) -> (i32, i32) {
    let value = freeze(value);
    let mut high = (value + 127) >> 7;
    high = (high * 1025 + (1 << 21)) >> 22;
    high &= 15;
    let mut low = value - high * 2 * GAMMA2;
    if low > (Q - 1) / 2 {
        low -= Q;
    }
    (high, low)
}

fn make_hint(low: i32, high: i32) -> bool {
    low > GAMMA2 || low < -GAMMA2 || (low == -GAMMA2 && high != 0)
}

fn use_hint(value: i32, hint: bool) -> i32 {
    let (high, low) = decompose(value);
    if !hint {
        high
    } else if low > 0 {
        (high + 1) & 15
    } else {
        (high - 1) & 15
    }
}

fn check_norm(poly: &Poly, bound: i32) -> bool {
    poly.iter().all(|value| value.abs() < bound)
}

fn encode_eta(poly: &Poly, output: &mut [u8]) {
    let mut values = [0u32; N];
    for index in 0..N {
        values[index] = (ETA - poly[index]) as u32;
    }
    pack_bits(&values, 4, output);
}

fn decode_eta(input: &[u8], output: &mut Poly) -> bool {
    let mut values = [0u32; N];
    unpack_bits(input, 4, &mut values);
    for index in 0..N {
        if values[index] > 8 {
            return false;
        }
        output[index] = ETA - values[index] as i32;
    }
    true
}

fn encode_t1(poly: &Poly, output: &mut [u8]) {
    let mut values = [0u32; N];
    for index in 0..N {
        values[index] = poly[index] as u32;
    }
    pack_bits(&values, 10, output);
}

fn decode_t1(input: &[u8], output: &mut Poly) {
    let mut values = [0u32; N];
    unpack_bits(input, 10, &mut values);
    for index in 0..N {
        output[index] = values[index] as i32;
    }
}

fn encode_t0(poly: &Poly, output: &mut [u8]) {
    let mut values = [0u32; N];
    for index in 0..N {
        values[index] = ((1 << (D - 1)) - poly[index]) as u32;
    }
    pack_bits(&values, 13, output);
}

fn decode_t0(input: &[u8], output: &mut Poly) {
    let mut values = [0u32; N];
    unpack_bits(input, 13, &mut values);
    for index in 0..N {
        output[index] = (1 << (D - 1)) - values[index] as i32;
    }
}

fn encode_z(poly: &Poly, output: &mut [u8]) {
    let mut values = [0u32; N];
    for index in 0..N {
        values[index] = (GAMMA1 - poly[index]) as u32;
    }
    pack_bits(&values, 20, output);
}

fn decode_z(input: &[u8], output: &mut Poly) -> bool {
    let mut values = [0u32; N];
    unpack_bits(input, 20, &mut values);
    for index in 0..N {
        if values[index] > (2 * GAMMA1 - 1) as u32 {
            return false;
        }
        output[index] = GAMMA1 - values[index] as i32;
    }
    true
}

fn encode_w1(vector: &VecK, output: &mut [u8]) {
    for row in 0..K {
        let mut values = [0u32; N];
        for index in 0..N {
            values[index] = decompose(vector[row][index]).0 as u32;
        }
        pack_bits(
            &values,
            4,
            &mut output[row * POLYW1_BYTES..(row + 1) * POLYW1_BYTES],
        );
    }
}

fn encode_w1_values(vector: &VecK, output: &mut [u8]) {
    for row in 0..K {
        let mut values = [0u32; N];
        for index in 0..N {
            values[index] = vector[row][index] as u32;
        }
        pack_bits(
            &values,
            4,
            &mut output[row * POLYW1_BYTES..(row + 1) * POLYW1_BYTES],
        );
    }
}

fn sample_gamma1(seed: &[u8; 64], nonce: u16) -> Poly {
    let mut bytes = [0u8; POLYZ_BYTES];
    let mut state = Shake256::new();
    state.update(seed);
    state.update(&nonce.to_le_bytes());
    state.finalize(&mut bytes);
    let mut output = [0i32; N];
    let _ = decode_z(&bytes, &mut output);
    output
}

fn challenge(seed: &[u8; CTILDE_BYTES]) -> Result<Poly, MlDsaError> {
    let mut bytes = [0u8; 4096];
    Shake256::digest(seed, &mut bytes);
    let mut signs = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let mut cursor = 8usize;
    let mut output = [0i32; N];
    for index in N - TAU..N {
        let selected = loop {
            let Some(&candidate) = bytes.get(cursor) else {
                volatile_zero(&mut bytes);
                volatile_zero(&mut output);
                return Err(MlDsaError::SamplingLimit);
            };
            let candidate = candidate as usize;
            cursor += 1;
            if candidate <= index {
                break candidate;
            }
        };
        output[index] = output[selected];
        output[selected] = if signs & 1 == 0 { 1 } else { -1 };
        signs >>= 1;
    }
    volatile_zero(&mut bytes);
    Ok(output)
}

fn message_representative(
    tr: &[u8; TR_BYTES],
    context: &[u8],
    message: &[u8],
) -> Result<[u8; 64], MlDsaError> {
    if context.len() > u8::MAX as usize {
        return Err(MlDsaError::ContextTooLong);
    }
    let prefix = [0u8, context.len() as u8];
    let mut output = [0u8; 64];
    shake256(&[tr, &prefix, context, message], &mut output);
    Ok(output)
}

pub fn ml_dsa_65_keygen(
    seed: &[u8; 32],
    public_key: &mut [u8],
    secret_key: &mut [u8],
) -> Result<(), MlDsaError> {
    volatile_zero(public_key);
    volatile_zero(secret_key);
    if public_key.len() != ML_DSA_65_PUBLIC_KEY_BYTES
        || secret_key.len() != ML_DSA_65_SECRET_KEY_BYTES
    {
        return Err(MlDsaError::BufferLength);
    }
    let parameters = [K as u8, L as u8];
    let mut expanded = [0u8; 128];
    shake256(&[seed, &parameters], &mut expanded);
    let rho: &[u8; 32] = expanded[..32].try_into().unwrap();
    let rho_prime: &[u8; 64] = expanded[32..96].try_into().unwrap();
    let key: &[u8; 32] = expanded[96..].try_into().unwrap();
    let mut s1 = [[0i32; N]; L];
    let mut s2 = [[0i32; N]; K];
    for index in 0..L {
        match sample_eta(rho_prime, index as u16) {
            Ok(poly) => s1[index] = poly,
            Err(error) => {
                volatile_zero(&mut expanded);
                for poly in &mut s1 {
                    volatile_zero(poly);
                }
                for poly in &mut s2 {
                    volatile_zero(poly);
                }
                return Err(error);
            }
        }
    }
    for index in 0..K {
        match sample_eta(rho_prime, (L + index) as u16) {
            Ok(poly) => s2[index] = poly,
            Err(error) => {
                volatile_zero(&mut expanded);
                for poly in &mut s1 {
                    volatile_zero(poly);
                }
                for poly in &mut s2 {
                    volatile_zero(poly);
                }
                return Err(error);
            }
        }
    }
    let mut s1_ntt = s1;
    for poly in &mut s1_ntt {
        ntt(poly);
    }
    let mut t0 = [[0i32; N]; K];
    let mut t1 = [[0i32; N]; K];
    for row in 0..K {
        let matrix = match matrix_row(rho, row) {
            Ok(matrix) => matrix,
            Err(error) => {
                volatile_zero(&mut expanded);
                for vector in [&mut s1[..], &mut s1_ntt[..]] {
                    for poly in vector {
                        volatile_zero(poly);
                    }
                }
                for vector in [&mut s2[..], &mut t0[..], &mut t1[..]] {
                    for poly in vector {
                        volatile_zero(poly);
                    }
                }
                return Err(error);
            }
        };
        let mut value = pointwise_accumulate(&matrix, &s1_ntt);
        inverse_ntt(&mut value);
        for index in 0..N {
            value[index] = freeze(value[index] + s2[row][index]);
            (t1[row][index], t0[row][index]) = power2round(value[index]);
        }
    }
    public_key[..32].copy_from_slice(rho);
    for row in 0..K {
        encode_t1(
            &t1[row],
            &mut public_key[32 + row * POLYT1_BYTES..32 + (row + 1) * POLYT1_BYTES],
        );
    }
    let mut tr = [0u8; TR_BYTES];
    Shake256::digest(public_key, &mut tr);
    secret_key[..32].copy_from_slice(rho);
    secret_key[32..64].copy_from_slice(key);
    secret_key[64..128].copy_from_slice(&tr);
    let mut offset = 128usize;
    for poly in &s1 {
        encode_eta(poly, &mut secret_key[offset..offset + POLYETA_BYTES]);
        offset += POLYETA_BYTES;
    }
    for poly in &s2 {
        encode_eta(poly, &mut secret_key[offset..offset + POLYETA_BYTES]);
        offset += POLYETA_BYTES;
    }
    for poly in &t0 {
        encode_t0(poly, &mut secret_key[offset..offset + POLYT0_BYTES]);
        offset += POLYT0_BYTES;
    }
    volatile_zero(&mut expanded);
    volatile_zero(&mut tr);
    for vector in [&mut s1[..], &mut s1_ntt[..]] {
        for poly in vector {
            volatile_zero(poly);
        }
    }
    for vector in [&mut s2[..], &mut t0[..], &mut t1[..]] {
        for poly in vector {
            volatile_zero(poly);
        }
    }
    Ok(())
}

fn decode_secret(
    secret_key: &[u8],
    rho: &mut [u8; 32],
    key: &mut [u8; 32],
    tr: &mut [u8; 64],
    s1: &mut VecL,
    s2: &mut VecK,
    t0: &mut VecK,
) -> bool {
    if secret_key.len() != ML_DSA_65_SECRET_KEY_BYTES {
        return false;
    }
    rho.copy_from_slice(&secret_key[..32]);
    key.copy_from_slice(&secret_key[32..64]);
    tr.copy_from_slice(&secret_key[64..128]);
    let mut offset = 128usize;
    for poly in s1 {
        if !decode_eta(&secret_key[offset..offset + POLYETA_BYTES], poly) {
            return false;
        }
        offset += POLYETA_BYTES;
    }
    for poly in s2 {
        if !decode_eta(&secret_key[offset..offset + POLYETA_BYTES], poly) {
            return false;
        }
        offset += POLYETA_BYTES;
    }
    for poly in t0 {
        decode_t0(&secret_key[offset..offset + POLYT0_BYTES], poly);
        offset += POLYT0_BYTES;
    }
    true
}

fn public_from_secret_polynomials(
    rho: &[u8; 32],
    s1: &VecL,
    s2: &VecK,
    public_key: &mut [u8; ML_DSA_65_PUBLIC_KEY_BYTES],
) -> Result<(), MlDsaError> {
    let mut s1_ntt = *s1;
    for poly in &mut s1_ntt {
        ntt(poly);
    }
    public_key[..32].copy_from_slice(rho);
    for row in 0..K {
        let matrix = match matrix_row(rho, row) {
            Ok(matrix) => matrix,
            Err(error) => {
                for poly in &mut s1_ntt {
                    volatile_zero(poly);
                }
                volatile_zero(public_key);
                return Err(error);
            }
        };
        let mut value = pointwise_accumulate(&matrix, &s1_ntt);
        inverse_ntt(&mut value);
        let mut t1 = [0i32; N];
        for index in 0..N {
            (t1[index], _) = power2round(freeze(value[index] + s2[row][index]));
        }
        encode_t1(
            &t1,
            &mut public_key[32 + row * POLYT1_BYTES..32 + (row + 1) * POLYT1_BYTES],
        );
        volatile_zero(&mut value);
        volatile_zero(&mut t1);
    }
    for poly in &mut s1_ntt {
        volatile_zero(poly);
    }
    Ok(())
}

fn wipe_signing_state(
    rho: &mut [u8; 32],
    key: &mut [u8; 32],
    tr: &mut [u8; 64],
    rho_prime: &mut [u8; 64],
    s1: &mut VecL,
    s2: &mut VecK,
    t0: &mut VecK,
) {
    volatile_zero(rho);
    volatile_zero(key);
    volatile_zero(tr);
    volatile_zero(rho_prime);
    for poly in s1 {
        volatile_zero(poly);
    }
    for poly in s2 {
        volatile_zero(poly);
    }
    for poly in t0 {
        volatile_zero(poly);
    }
}

pub fn ml_dsa_65_sign(
    secret_key: &[u8],
    context: &[u8],
    message: &[u8],
    randomizer: &[u8; 32],
    signature: &mut [u8],
) -> Result<(), MlDsaError> {
    volatile_zero(signature);
    if signature.len() != ML_DSA_65_SIGNATURE_BYTES {
        return Err(MlDsaError::BufferLength);
    }
    let mut rho = [0u8; 32];
    let mut key = [0u8; 32];
    let mut tr = [0u8; 64];
    let mut s1 = [[0i32; N]; L];
    let mut s2 = [[0i32; N]; K];
    let mut t0 = [[0i32; N]; K];
    if !decode_secret(
        secret_key, &mut rho, &mut key, &mut tr, &mut s1, &mut s2, &mut t0,
    ) {
        let mut empty = [0u8; 64];
        wipe_signing_state(
            &mut rho, &mut key, &mut tr, &mut empty, &mut s1, &mut s2, &mut t0,
        );
        return Err(MlDsaError::InvalidKey);
    }
    let mut public_key = [0u8; ML_DSA_65_PUBLIC_KEY_BYTES];
    if let Err(error) = public_from_secret_polynomials(&rho, &s1, &s2, &mut public_key) {
        let mut empty = [0u8; 64];
        wipe_signing_state(
            &mut rho, &mut key, &mut tr, &mut empty, &mut s1, &mut s2, &mut t0,
        );
        volatile_zero(&mut public_key);
        return Err(error);
    }
    let mut expected_tr = [0u8; TR_BYTES];
    Shake256::digest(&public_key, &mut expected_tr);
    let mut tr_difference = 0u8;
    for index in 0..TR_BYTES {
        tr_difference |= tr[index] ^ expected_tr[index];
    }
    volatile_zero(&mut expected_tr);
    if tr_difference != 0 {
        let mut empty = [0u8; 64];
        wipe_signing_state(
            &mut rho, &mut key, &mut tr, &mut empty, &mut s1, &mut s2, &mut t0,
        );
        return Err(MlDsaError::InvalidKey);
    }
    let mu = match message_representative(&tr, context, message) {
        Ok(mu) => mu,
        Err(error) => {
            let mut empty = [0u8; 64];
            wipe_signing_state(
                &mut rho, &mut key, &mut tr, &mut empty, &mut s1, &mut s2, &mut t0,
            );
            return Err(error);
        }
    };
    let mut rho_prime = [0u8; 64];
    shake256(&[&key, randomizer, &mu], &mut rho_prime);
    for poly in &mut s1 {
        ntt(poly);
    }
    for poly in &mut s2 {
        ntt(poly);
    }
    for poly in &mut t0 {
        ntt(poly);
    }
    for attempt in 0..MAX_REJECTIONS {
        let base = (attempt * L) as u16;
        let mut y = [[0i32; N]; L];
        for column in 0..L {
            y[column] = sample_gamma1(&rho_prime, base + column as u16);
        }
        let mut y_ntt = y;
        for poly in &mut y_ntt {
            ntt(poly);
        }
        let mut w = [[0i32; N]; K];
        for row in 0..K {
            let matrix = match matrix_row(&rho, row) {
                Ok(matrix) => matrix,
                Err(error) => {
                    wipe_signing_state(
                        &mut rho,
                        &mut key,
                        &mut tr,
                        &mut rho_prime,
                        &mut s1,
                        &mut s2,
                        &mut t0,
                    );
                    volatile_zero(signature);
                    return Err(error);
                }
            };
            w[row] = pointwise_accumulate(&matrix, &y_ntt);
            inverse_ntt(&mut w[row]);
            for value in &mut w[row] {
                *value = freeze(*value);
            }
        }
        let mut encoded_w1 = [0u8; K * POLYW1_BYTES];
        encode_w1(&w, &mut encoded_w1);
        let mut ctilde = [0u8; CTILDE_BYTES];
        shake256(&[&mu, &encoded_w1], &mut ctilde);
        let mut c = match challenge(&ctilde) {
            Ok(challenge) => challenge,
            Err(error) => {
                wipe_signing_state(
                    &mut rho,
                    &mut key,
                    &mut tr,
                    &mut rho_prime,
                    &mut s1,
                    &mut s2,
                    &mut t0,
                );
                volatile_zero(signature);
                return Err(error);
            }
        };
        ntt(&mut c);
        let mut z = y;
        let mut low = [[0i32; N]; K];
        let mut ct0 = [[0i32; N]; K];
        let mut rejected = false;
        for column in 0..L {
            let mut product = [0i32; N];
            for index in 0..N {
                product[index] =
                    montgomery_reduce(i64::from(c[index]) * i64::from(s1[column][index]));
            }
            inverse_ntt(&mut product);
            for index in 0..N {
                z[column][index] = reduce32(z[column][index] + product[index]);
            }
            if !check_norm(&z[column], GAMMA1 - BETA) {
                rejected = true;
            }
        }
        if rejected {
            continue;
        }
        for row in 0..K {
            let mut cs2 = [0i32; N];
            for index in 0..N {
                cs2[index] = montgomery_reduce(i64::from(c[index]) * i64::from(s2[row][index]));
                ct0[row][index] =
                    montgomery_reduce(i64::from(c[index]) * i64::from(t0[row][index]));
            }
            inverse_ntt(&mut cs2);
            inverse_ntt(&mut ct0[row]);
            for index in 0..N {
                cs2[index] = reduce32(cs2[index]);
                ct0[row][index] = reduce32(ct0[row][index]);
                low[row][index] = reduce32(decompose(w[row][index]).1 - cs2[index]);
            }
            if !check_norm(&low[row], GAMMA2 - BETA) || !check_norm(&ct0[row], GAMMA2) {
                rejected = true;
            }
        }
        if rejected {
            continue;
        }
        signature[..CTILDE_BYTES].copy_from_slice(&ctilde);
        let mut offset = CTILDE_BYTES;
        for poly in &z {
            encode_z(poly, &mut signature[offset..offset + POLYZ_BYTES]);
            offset += POLYZ_BYTES;
        }
        let hint_start = offset;
        signature[hint_start..].fill(0);
        let mut count = 0usize;
        for row in 0..K {
            for index in 0..N {
                let adjusted = reduce32(low[row][index] + ct0[row][index]);
                let high = decompose(w[row][index]).0;
                if make_hint(adjusted, high) {
                    if count == OMEGA {
                        rejected = true;
                        break;
                    }
                    signature[hint_start + count] = index as u8;
                    count += 1;
                }
            }
            signature[hint_start + OMEGA + row] = count as u8;
            if rejected {
                break;
            }
        }
        if rejected {
            volatile_zero(signature);
            continue;
        }
        let verified = ml_dsa_65_verify(&public_key, context, message, signature).is_ok();
        wipe_signing_state(
            &mut rho,
            &mut key,
            &mut tr,
            &mut rho_prime,
            &mut s1,
            &mut s2,
            &mut t0,
        );
        if verified {
            return Ok(());
        }
        volatile_zero(signature);
        return Err(MlDsaError::InvalidSignature);
    }
    wipe_signing_state(
        &mut rho,
        &mut key,
        &mut tr,
        &mut rho_prime,
        &mut s1,
        &mut s2,
        &mut t0,
    );
    volatile_zero(signature);
    Err(MlDsaError::RejectionLimit)
}

fn decode_signature(
    signature: &[u8],
    ctilde: &mut [u8; CTILDE_BYTES],
    z: &mut VecL,
    hints: &mut [[bool; N]; K],
) -> bool {
    if signature.len() != ML_DSA_65_SIGNATURE_BYTES {
        return false;
    }
    ctilde.copy_from_slice(&signature[..CTILDE_BYTES]);
    let mut offset = CTILDE_BYTES;
    for poly in z {
        if !decode_z(&signature[offset..offset + POLYZ_BYTES], poly) {
            return false;
        }
        offset += POLYZ_BYTES;
    }
    let indexes = &signature[offset..offset + OMEGA];
    let counts = &signature[offset + OMEGA..];
    let mut previous = 0usize;
    for row in 0..K {
        let count = counts[row] as usize;
        if count < previous || count > OMEGA {
            return false;
        }
        let mut last = None;
        for &index in &indexes[previous..count] {
            if last.is_some_and(|value| index <= value) {
                return false;
            }
            hints[row][index as usize] = true;
            last = Some(index);
        }
        previous = count;
    }
    indexes[previous..].iter().all(|byte| *byte == 0)
}

pub fn ml_dsa_65_verify(
    public_key: &[u8],
    context: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), MlDsaError> {
    if public_key.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
        return Err(MlDsaError::BufferLength);
    }
    let mut ctilde = [0u8; CTILDE_BYTES];
    let mut z = [[0i32; N]; L];
    let mut hints = [[false; N]; K];
    if !decode_signature(signature, &mut ctilde, &mut z, &mut hints)
        || z.iter().any(|poly| !check_norm(poly, GAMMA1 - BETA))
    {
        return Err(MlDsaError::InvalidSignature);
    }
    let rho: &[u8; 32] = public_key[..32].try_into().unwrap();
    let mut tr = [0u8; TR_BYTES];
    Shake256::digest(public_key, &mut tr);
    let mu = message_representative(&tr, context, message)?;
    let mut c = challenge(&ctilde)?;
    ntt(&mut c);
    for poly in &mut z {
        ntt(poly);
    }
    let mut w1 = [[0i32; N]; K];
    for row in 0..K {
        let matrix = matrix_row(rho, row)?;
        let mut value = pointwise_accumulate(&matrix, &z);
        let mut t1 = [0i32; N];
        decode_t1(
            &public_key[32 + row * POLYT1_BYTES..32 + (row + 1) * POLYT1_BYTES],
            &mut t1,
        );
        for coefficient in &mut t1 {
            *coefficient <<= D;
        }
        ntt(&mut t1);
        for index in 0..N {
            value[index] -= montgomery_reduce(i64::from(c[index]) * i64::from(t1[index]));
            value[index] = reduce32(value[index]);
        }
        inverse_ntt(&mut value);
        for index in 0..N {
            w1[row][index] = use_hint(freeze(value[index]), hints[row][index]);
        }
    }
    let mut encoded = [0u8; K * POLYW1_BYTES];
    encode_w1_values(&w1, &mut encoded);
    let mut expected = [0u8; CTILDE_BYTES];
    shake256(&[&mu, &encoded], &mut expected);
    let mut difference = 0u8;
    for index in 0..CTILDE_BYTES {
        difference |= expected[index] ^ ctilde[index];
    }
    if difference == 0 {
        Ok(())
    } else {
        Err(MlDsaError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independently_generated_openssl_vector_when_configured() {
        let Some(directory) = mrml_runtime::environment_variable("MRML_ML_DSA_65_OPENSSL") else {
            return;
        };
        let read = |name: &str| {
            mrml_runtime::read_file(&mrml_runtime::join_path(&directory, name)).unwrap()
        };
        let expected_public = read("public.raw");
        let expected_secret = read("secret.raw");
        let expected_signature = read("signature.bin");
        let message = read("message.bin");
        assert_eq!(expected_public.len(), ML_DSA_65_PUBLIC_KEY_BYTES);
        assert_eq!(expected_secret.len(), ML_DSA_65_SECRET_KEY_BYTES);
        assert_eq!(expected_signature.len(), ML_DSA_65_SIGNATURE_BYTES);

        let mut seed = [0u8; 32];
        let mut randomizer = [0u8; 32];
        for index in 0..32 {
            seed[index] = index as u8;
            randomizer[index] = (index + 32) as u8;
        }
        let mut public = [0u8; ML_DSA_65_PUBLIC_KEY_BYTES];
        let mut secret = [0u8; ML_DSA_65_SECRET_KEY_BYTES];
        ml_dsa_65_keygen(&seed, &mut public, &mut secret).unwrap();
        assert_eq!(&public, &expected_public[..]);
        assert_eq!(&secret, &expected_secret[..]);

        let mut signature = [0u8; ML_DSA_65_SIGNATURE_BYTES];
        ml_dsa_65_sign(
            &secret,
            b"mrml-oracle",
            &message,
            &randomizer,
            &mut signature,
        )
        .unwrap();
        assert_eq!(&signature, &expected_signature[..]);
        assert_eq!(
            ml_dsa_65_verify(&public, b"mrml-oracle", &message, &expected_signature),
            Ok(())
        );
    }

    #[test]
    fn round_trip_and_rejects_tampering() {
        let seed = [7u8; 32];
        let randomizer = [9u8; 32];
        let mut public = [0u8; ML_DSA_65_PUBLIC_KEY_BYTES];
        let mut secret = [0u8; ML_DSA_65_SECRET_KEY_BYTES];
        ml_dsa_65_keygen(&seed, &mut public, &mut secret).unwrap();
        let mut signature = [0u8; ML_DSA_65_SIGNATURE_BYTES];
        ml_dsa_65_sign(
            &secret,
            b"git",
            b"commit payload",
            &randomizer,
            &mut signature,
        )
        .unwrap();
        assert_eq!(
            ml_dsa_65_verify(&public, b"git", b"commit payload", &signature),
            Ok(())
        );
        assert_eq!(
            ml_dsa_65_verify(&public, b"git", b"changed", &signature),
            Err(MlDsaError::InvalidSignature)
        );
        signature[100] ^= 1;
        assert_eq!(
            ml_dsa_65_verify(&public, b"git", b"commit payload", &signature),
            Err(MlDsaError::InvalidSignature)
        );

        let mut corrupt_secret = secret;
        corrupt_secret[64] ^= 1;
        signature.fill(0xa5);
        assert_eq!(
            ml_dsa_65_sign(
                &corrupt_secret,
                b"git",
                b"commit payload",
                &randomizer,
                &mut signature,
            ),
            Err(MlDsaError::InvalidKey)
        );
        assert!(signature.iter().all(|byte| *byte == 0));

        let mut short_output = [0xa5u8; 17];
        assert_eq!(
            ml_dsa_65_sign(
                &secret,
                b"git",
                b"commit payload",
                &randomizer,
                &mut short_output,
            ),
            Err(MlDsaError::BufferLength)
        );
        assert_eq!(short_output, [0u8; 17]);

        let mut context_255_signature = [0u8; ML_DSA_65_SIGNATURE_BYTES];
        let context_255 = [3u8; 255];
        ml_dsa_65_sign(
            &secret,
            &context_255,
            b"boundary",
            &randomizer,
            &mut context_255_signature,
        )
        .unwrap();
        assert_eq!(
            ml_dsa_65_verify(&public, &context_255, b"boundary", &context_255_signature,),
            Ok(())
        );
        let context_256 = [3u8; 256];
        context_255_signature.fill(0xa5);
        assert_eq!(
            ml_dsa_65_sign(
                &secret,
                &context_256,
                b"boundary",
                &randomizer,
                &mut context_255_signature,
            ),
            Err(MlDsaError::ContextTooLong)
        );
        assert!(context_255_signature.iter().all(|byte| *byte == 0));

        let mut noncanonical_signature = [0u8; ML_DSA_65_SIGNATURE_BYTES];
        ml_dsa_65_sign(
            &secret,
            b"git",
            b"commit payload",
            &randomizer,
            &mut noncanonical_signature,
        )
        .unwrap();
        let hint_start = CTILDE_BYTES + L * POLYZ_BYTES;
        noncanonical_signature[hint_start] = 9;
        noncanonical_signature[hint_start + 1] = 8;
        noncanonical_signature[hint_start + OMEGA] = 2;
        assert_eq!(
            ml_dsa_65_verify(&public, b"git", b"commit payload", &noncanonical_signature,),
            Err(MlDsaError::InvalidSignature)
        );
    }
}
