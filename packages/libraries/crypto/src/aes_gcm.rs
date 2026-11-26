//! AES-128-GCM authenticated encryption for TLS 1.3.

#[cfg(target_arch = "x86_64")]
use core::sync::atomic::{AtomicU8, Ordering};

fn xtime(x: u8) -> u8 {
    (x << 1) ^ (0x1b & (0u8.wrapping_sub(x >> 7)))
}

fn inverse(x: u8) -> u8 {
    if x == 0 {
        return 0;
    }
    let mut result = 1u8;
    let mut base = x;
    let mut exponent = 254u8;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exponent >>= 1;
    }
    result
}

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0;
    for _ in 0..8 {
        result ^= a & 0u8.wrapping_sub(b & 1);
        a = xtime(a);
        b >>= 1;
    }
    result
}

fn sbox(x: u8) -> u8 {
    let y = inverse(x);
    y ^ y.rotate_left(1) ^ y.rotate_left(2) ^ y.rotate_left(3) ^ y.rotate_left(4) ^ 0x63
}

fn expand_key(key: &[u8; 16]) -> [u8; 176] {
    let mut expanded = [0u8; 176];
    expanded[..16].copy_from_slice(key);
    let mut position = 16;
    let mut rcon = 1u8;
    while position < expanded.len() {
        let mut word = [
            expanded[position - 4],
            expanded[position - 3],
            expanded[position - 2],
            expanded[position - 1],
        ];
        if position & 15 == 0 {
            word = [
                sbox(word[1]) ^ rcon,
                sbox(word[2]),
                sbox(word[3]),
                sbox(word[0]),
            ];
            rcon = xtime(rcon);
        }
        for byte in word {
            expanded[position] = expanded[position - 16] ^ byte;
            position += 1;
        }
    }
    expanded
}

fn aes128_encrypt_software(keys: &[u8; 176], input: &[u8; 16]) -> [u8; 16] {
    let mut state = *input;
    add_round_key(&mut state, &keys[..16]);
    for round in 1..=10 {
        for byte in &mut state {
            *byte = sbox(*byte);
        }
        let old = state;
        for row in 0..4 {
            for column in 0..4 {
                state[4 * column + row] = old[4 * ((column + row) & 3) + row];
            }
        }
        if round != 10 {
            for column in 0..4 {
                let i = 4 * column;
                let a = [state[i], state[i + 1], state[i + 2], state[i + 3]];
                state[i] = xtime(a[0]) ^ (xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3];
                state[i + 1] = a[0] ^ xtime(a[1]) ^ (xtime(a[2]) ^ a[2]) ^ a[3];
                state[i + 2] = a[0] ^ a[1] ^ xtime(a[2]) ^ (xtime(a[3]) ^ a[3]);
                state[i + 3] = (xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ xtime(a[3]);
            }
        }
        add_round_key(&mut state, &keys[16 * round..16 * (round + 1)]);
    }
    state
}

#[cfg(target_arch = "x86_64")]
fn aes_instructions_available() -> bool {
    static AVAILABLE: AtomicU8 = AtomicU8::new(0);
    match AVAILABLE.load(Ordering::Relaxed) {
        1 => false,
        2 => true,
        _ => {
            let available = core::arch::x86_64::__cpuid(1).ecx & (1 << 25) != 0;
            AVAILABLE.store(if available { 2 } else { 1 }, Ordering::Relaxed);
            available
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes")]
unsafe fn aes128_encrypt_instructions(keys: &[u8; 176], input: &[u8; 16]) -> [u8; 16] {
    use core::arch::x86_64::{
        __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_loadu_si128, _mm_storeu_si128,
        _mm_xor_si128,
    };

    // SAFETY: callers below provide pointers to at least 16 in-bounds bytes;
    // the intrinsic explicitly permits unaligned loads.
    let load = |bytes: *const u8| unsafe { _mm_loadu_si128(bytes.cast::<__m128i>()) };
    let mut state = _mm_xor_si128(load(input.as_ptr()), load(keys.as_ptr()));
    for round in 1..10 {
        state = _mm_aesenc_si128(state, load(keys[16 * round..].as_ptr()));
    }
    state = _mm_aesenclast_si128(state, load(keys[160..].as_ptr()));
    let mut output = [0u8; 16];
    // SAFETY: output provides exactly 16 writable bytes and the store permits
    // unaligned destinations.
    unsafe { _mm_storeu_si128(output.as_mut_ptr().cast::<__m128i>(), state) };
    output
}

fn aes128_encrypt_expanded(keys: &[u8; 176], input: &[u8; 16]) -> [u8; 16] {
    #[cfg(target_arch = "x86_64")]
    if aes_instructions_available() {
        // SAFETY: CPUID above proves AES instruction support. The intrinsic
        // implementation performs only unaligned fixed-width loads/stores
        // within the supplied arrays.
        return unsafe { aes128_encrypt_instructions(keys, input) };
    }
    aes128_encrypt_software(keys, input)
}

fn aes128_encrypt(key: &[u8; 16], input: &[u8; 16]) -> [u8; 16] {
    aes128_encrypt_expanded(&expand_key(key), input)
}

/// Encrypt one AES-128 block. QUIC uses this primitive for header protection.
pub fn aes128_encrypt_block(key: &[u8; 16], input: &[u8; 16]) -> [u8; 16] {
    aes128_encrypt(key, input)
}

/// Applies AES-128 in counter mode using a big-endian 128-bit counter.
/// Encryption and decryption are the same operation. The counter advances
/// once per block and wrapping is rejected before any output is changed.
pub fn aes128_ctr_xor(
    key: &[u8; 16],
    initial_counter: [u8; 16],
    input: &[u8],
    output: &mut [u8],
) -> Result<[u8; 16], ()> {
    if output.len() != input.len() {
        return Err(());
    }
    let blocks = input.len().div_ceil(16) as u128;
    let start = u128::from_be_bytes(initial_counter);
    if start.checked_add(blocks).is_none() {
        return Err(());
    }
    let mut counter = start;
    let keys = expand_key(key);
    for (source, target) in input.chunks(16).zip(output.chunks_mut(16)) {
        let stream = aes128_encrypt_expanded(&keys, &counter.to_be_bytes());
        for (index, byte) in source.iter().enumerate() {
            target[index] = *byte ^ stream[index];
        }
        counter += 1;
    }
    Ok(counter.to_be_bytes())
}

fn add_round_key(state: &mut [u8; 16], key: &[u8]) {
    for i in 0..16 {
        state[i] ^= key[i];
    }
}

fn ghash_mul_software(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut v = y;
    for bit in 0..128 {
        z ^= v & 0u128.wrapping_sub((x >> (127 - bit)) & 1);
        let low = v & 1;
        v = (v >> 1) ^ (0xe1000000000000000000000000000000u128 & 0u128.wrapping_sub(low));
    }
    z
}

#[cfg(target_arch = "x86_64")]
fn pclmulqdq_available() -> bool {
    static AVAILABLE: AtomicU8 = AtomicU8::new(0);
    match AVAILABLE.load(Ordering::Relaxed) {
        1 => false,
        2 => true,
        _ => {
            let available = core::arch::x86_64::__cpuid(1).ecx & (1 << 1) != 0;
            AVAILABLE.store(if available { 2 } else { 1 }, Ordering::Relaxed);
            available
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq")]
unsafe fn ghash_mul_instructions(x: u128, y: u128) -> u128 {
    use core::arch::x86_64::{
        __m128i, _mm_clmulepi64_si128, _mm_set_epi64x, _mm_storeu_si128, _mm_xor_si128,
    };

    // Reverse the GHASH bit order, then pass the two halves by value.
    // The intrinsic takes the high lane first and keeps the low lane in bits 0..63.
    let x = x.reverse_bits();
    let y = y.reverse_bits();
    let left = _mm_set_epi64x((x >> 64) as i64, x as i64);
    let right = _mm_set_epi64x((y >> 64) as i64, y as i64);
    let low = _mm_clmulepi64_si128(left, right, 0x00);
    let high = _mm_clmulepi64_si128(left, right, 0x11);
    let cross = _mm_xor_si128(
        _mm_clmulepi64_si128(left, right, 0x01),
        _mm_clmulepi64_si128(left, right, 0x10),
    );
    let mut low_bytes = [0u8; 16];
    let mut high_bytes = [0u8; 16];
    let mut cross_bytes = [0u8; 16];
    // SAFETY: each destination contains exactly 16 writable bytes and the
    // stores explicitly permit unaligned destinations.
    unsafe {
        _mm_storeu_si128(low_bytes.as_mut_ptr().cast::<__m128i>(), low);
        _mm_storeu_si128(high_bytes.as_mut_ptr().cast::<__m128i>(), high);
        _mm_storeu_si128(cross_bytes.as_mut_ptr().cast::<__m128i>(), cross);
    }
    let cross = u128::from_le_bytes(cross_bytes);
    let mut low = u128::from_le_bytes(low_bytes) ^ (cross << 64);
    let high = u128::from_le_bytes(high_bytes) ^ (cross >> 64);
    low ^= high ^ (high << 1) ^ (high << 2) ^ (high << 7);
    let overflow = (high >> 127) ^ (high >> 126) ^ (high >> 121);
    low ^= overflow ^ (overflow << 1) ^ (overflow << 2) ^ (overflow << 7);
    low.reverse_bits()
}

fn ghash_mul(x: u128, y: u128) -> u128 {
    #[cfg(target_arch = "x86_64")]
    if pclmulqdq_available() {
        // SAFETY: CPUID above proves PCLMULQDQ support. The helper builds
        // operands by value and uses complete fixed-width output arrays.
        return unsafe { ghash_mul_instructions(x, y) };
    }
    ghash_mul_software(x, y)
}

fn ghash(h: u128, aad: &[u8], data: &[u8]) -> u128 {
    let mut state = 0u128;
    for source in [aad, data] {
        for block in source.chunks(16) {
            let mut padded = [0u8; 16];
            padded[..block.len()].copy_from_slice(block);
            state = ghash_mul(state ^ u128::from_be_bytes(padded), h);
        }
    }
    let lengths = ((aad.len() as u128 * 8) << 64) | (data.len() as u128 * 8);
    ghash_mul(state ^ lengths, h)
}

fn counter_block(nonce: &[u8; 12], counter: u32) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[..12].copy_from_slice(nonce);
    block[12..].copy_from_slice(&counter.to_be_bytes());
    block
}

fn crypt(keys: &[u8; 176], nonce: &[u8; 12], input: &[u8], output: &mut [u8]) {
    for (index, (source, target)) in input.chunks(16).zip(output.chunks_mut(16)).enumerate() {
        let stream = aes128_encrypt_expanded(keys, &counter_block(nonce, 2 + index as u32));
        for i in 0..source.len() {
            target[i] = source[i] ^ stream[i];
        }
    }
}

pub fn aes128_gcm_seal(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
    tag: &mut [u8; 16],
) -> bool {
    if ciphertext.len() != plaintext.len() {
        return false;
    }
    let keys = expand_key(key);
    crypt(&keys, nonce, plaintext, ciphertext);
    let h = u128::from_be_bytes(aes128_encrypt_expanded(&keys, &[0; 16]));
    *tag = (ghash(h, aad, ciphertext)
        ^ u128::from_be_bytes(aes128_encrypt_expanded(&keys, &counter_block(nonce, 1))))
    .to_be_bytes();
    true
}

pub fn aes128_gcm_open(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
    plaintext: &mut [u8],
) -> bool {
    if plaintext.len() != ciphertext.len() {
        return false;
    }
    let keys = expand_key(key);
    let h = u128::from_be_bytes(aes128_encrypt_expanded(&keys, &[0; 16]));
    let expected = (ghash(h, aad, ciphertext)
        ^ u128::from_be_bytes(aes128_encrypt_expanded(&keys, &counter_block(nonce, 1))))
    .to_be_bytes();
    let mut difference = 0u8;
    for i in 0..16 {
        difference |= expected[i] ^ tag[i];
    }
    if difference != 0 {
        return false;
    }
    crypt(&keys, nonce, ciphertext, plaintext);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0; N];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn aes_instructions_match_constant_time_software_fallback() {
        if !aes_instructions_available() {
            return;
        }
        let key = hex::<16>("000102030405060708090a0b0c0d0e0f");
        let input = hex::<16>("00112233445566778899aabbccddeeff");
        let keys = expand_key(&key);
        let software = aes128_encrypt_software(&keys, &input);
        // SAFETY: the availability check above proves the required CPU
        // feature, and both arguments are complete fixed-size arrays.
        let accelerated = unsafe { aes128_encrypt_instructions(&keys, &input) };
        assert_eq!(accelerated, software);
        assert_eq!(accelerated, hex("69c4e0d86a7b0430d8cdb78070b4c55a"));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn pclmulqdq_ghash_matches_constant_time_software_fallback() {
        if !pclmulqdq_available() {
            return;
        }
        let mut left = 0x66e9_4bd4_ef8a_2c3b_884c_fa59_ca34_2b2eu128;
        let mut right = 0x0388_dace_60b6_a392_f328_c2b9_71b2_fe78u128;
        let expect_equal = |left, right| {
            // SAFETY: the availability check above proves the required CPU
            // feature; the operation accepts two by-value fixed-width words.
            let accelerated = unsafe { ghash_mul_instructions(left, right) };
            assert_eq!(accelerated, ghash_mul_software(left, right));
        };
        let boundaries = [0, 1, 1 << 63, 1 << 64, 1 << 127, u128::MAX];
        for a in boundaries {
            for b in boundaries {
                expect_equal(a, b);
            }
        }
        for _ in 0..256 {
            expect_equal(left, right);
            left = left
                .wrapping_mul(0xda94_2042_e4dd_58b5_9e37_79b9_7f4a_7c15)
                .rotate_left(29)
                ^ right;
            right = right
                .wrapping_add(0x9e37_79b9_7f4a_7c15_6a09_e667_f3bc_c909)
                .rotate_right(17)
                ^ left;
        }
    }
    #[test]
    fn nist_empty_and_single_block_vectors() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let mut tag = [0u8; 16];
        assert!(aes128_gcm_seal(&key, &nonce, &[], &[], &mut [], &mut tag));
        assert_eq!(
            tag,
            [
                0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
                0x45, 0x5a
            ]
        );
        let plain = [0u8; 16];
        let mut encrypted = [0u8; 16];
        aes128_gcm_seal(&key, &nonce, &[], &plain, &mut encrypted, &mut tag);
        assert_eq!(
            encrypted,
            [
                0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
                0xfe, 0x78
            ]
        );
        assert_eq!(
            tag,
            [
                0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57,
                0xbd, 0xdf
            ]
        );
        let mut opened = [0u8; 16];
        assert!(aes128_gcm_open(
            &key,
            &nonce,
            &[],
            &encrypted,
            &tag,
            &mut opened
        ));
        assert_eq!(opened, plain);
        tag[0] ^= 1;
        assert!(!aes128_gcm_open(
            &key,
            &nonce,
            &[],
            &encrypted,
            &tag,
            &mut opened
        ));
    }
    #[test]
    fn nist_aad_and_partial_block_vector() {
        let key = hex("feffe9928665731c6d6a8f9467308308");
        let nonce = hex("cafebabefacedbaddecaf888");
        let aad = hex::<20>("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plain = hex::<60>(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let expected = hex::<60>(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        );
        let mut encrypted = [0; 60];
        let mut tag = [0; 16];
        assert!(aes128_gcm_seal(
            &key,
            &nonce,
            &aad,
            &plain,
            &mut encrypted,
            &mut tag
        ));
        assert_eq!(encrypted, expected);
        assert_eq!(tag, hex("5bc94fbc3221a5db94fae95ae7121a47"));
    }
    #[test]
    fn nist_ctr_vector_and_counter_progression() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let counter = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let plain = hex::<32>("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        let expected =
            hex::<32>("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff");
        let mut encrypted = [0u8; 32];
        let next = aes128_ctr_xor(&key, counter, &plain, &mut encrypted).unwrap();
        assert_eq!(encrypted, expected);
        assert_eq!(u128::from_be_bytes(next), u128::from_be_bytes(counter) + 2);
        let mut opened = [0u8; 32];
        aes128_ctr_xor(&key, counter, &encrypted, &mut opened).unwrap();
        assert_eq!(opened, plain);
    }
}
