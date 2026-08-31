use crate::zeroize::volatile_zero;

const SHA512_INITIAL: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SHA384_INITIAL: [u64; 8] = [
    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4,
];

const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

#[derive(Clone)]
struct Sha512Core {
    state: [u64; 8],
    block: [u8; 128],
    used: usize,
    length: u128,
}

impl Sha512Core {
    const fn new(state: [u64; 8]) -> Self {
        Self {
            state,
            block: [0; 128],
            used: 0,
            length: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.length = self.length.wrapping_add(input.len() as u128);
        if self.used != 0 {
            let take = input.len().min(128 - self.used);
            self.block[self.used..self.used + take].copy_from_slice(&input[..take]);
            self.used += take;
            input = &input[take..];
            if self.used == 128 {
                let mut block = self.block;
                self.compress(&block);
                volatile_zero(&mut block);
                volatile_zero(&mut self.block);
                self.used = 0;
            } else {
                return;
            }
        }
        while input.len() >= 128 {
            let block: &[u8; 128] = input[..128].try_into().expect("fixed SHA-512 block");
            self.compress(block);
            input = &input[128..];
        }
        self.block[..input.len()].copy_from_slice(input);
        self.used = input.len();
    }

    fn compress(&mut self, block: &[u8; 128]) {
        let mut words = [0u64; 80];
        for (index, word) in words[..16].iter_mut().enumerate() {
            let offset = index * 8;
            *word = u64::from_be_bytes(
                block[offset..offset + 8]
                    .try_into()
                    .expect("fixed SHA-512 word"),
            );
        }
        for index in 16..80 {
            let s0 = words[index - 15].rotate_right(1)
                ^ words[index - 15].rotate_right(8)
                ^ (words[index - 15] >> 7);
            let s1 = words[index - 2].rotate_right(19)
                ^ words[index - 2].rotate_right(61)
                ^ (words[index - 2] >> 6);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for index in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let choice = (e & f) ^ ((!e) & g);
            let first = h
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let second = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(first);
            d = c;
            c = b;
            b = a;
            a = first.wrapping_add(second);
        }
        for (state, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *state = state.wrapping_add(value);
        }
        volatile_zero(&mut words);
    }

    fn finalize(mut self) -> [u8; 64] {
        let bit_length = self.length.wrapping_mul(8);
        self.block[self.used] = 0x80;
        self.used += 1;
        if self.used > 112 {
            self.block[self.used..].fill(0);
            let mut block = self.block;
            self.compress(&block);
            volatile_zero(&mut block);
            volatile_zero(&mut self.block);
            self.used = 0;
        }
        self.block[self.used..112].fill(0);
        self.block[112..].copy_from_slice(&bit_length.to_be_bytes());
        let mut block = self.block;
        self.compress(&block);
        volatile_zero(&mut block);

        let mut output = [0u8; 64];
        for (index, word) in self.state.iter().enumerate() {
            output[index * 8..index * 8 + 8].copy_from_slice(&word.to_be_bytes());
        }
        output
    }
}

impl Drop for Sha512Core {
    fn drop(&mut self) {
        volatile_zero(&mut self.state);
        volatile_zero(&mut self.block);
        self.used = 0;
        self.length = 0;
    }
}

/// Incremental SHA-512 as specified by FIPS 180-4.
///
/// Owned state is cleared with best-effort volatile stores on drop. This does
/// not guarantee erasure of compiler-created copies, registers, caches, swap,
/// or hardware traces.
#[derive(Clone)]
pub struct Sha512(Sha512Core);

impl Sha512 {
    pub const fn new() -> Self {
        Self(Sha512Core::new(SHA512_INITIAL))
    }

    pub fn update(&mut self, input: &[u8]) {
        self.0.update(input);
    }

    pub fn finalize(self) -> [u8; 64] {
        self.0.finalize()
    }

    pub fn digest(input: &[u8]) -> [u8; 64] {
        let mut hash = Self::new();
        hash.update(input);
        hash.finalize()
    }
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

/// Incremental SHA-384 as specified by FIPS 180-4.
///
/// Owned state is cleared with best-effort volatile stores on drop. This does
/// not guarantee erasure of compiler-created copies, registers, caches, swap,
/// or hardware traces.
#[derive(Clone)]
pub struct Sha384(Sha512Core);

impl Sha384 {
    pub const fn new() -> Self {
        Self(Sha512Core::new(SHA384_INITIAL))
    }

    pub fn update(&mut self, input: &[u8]) {
        self.0.update(input);
    }

    pub fn finalize(self) -> [u8; 48] {
        let full = self.0.finalize();
        let mut output = [0u8; 48];
        output.copy_from_slice(&full[..48]);
        output
    }

    pub fn digest(input: &[u8]) -> [u8; 48] {
        let mut hash = Self::new();
        hash.update(input);
        hash.finalize()
    }
}

impl Default for Sha384 {
    fn default() -> Self {
        Self::new()
    }
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

    #[test]
    fn sha512_standard_vectors() {
        assert_eq!(
            Sha512::digest(b""),
            decode(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            )
        );
        assert_eq!(
            Sha512::digest(b"abc"),
            decode(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
    }

    #[test]
    fn sha384_standard_vectors() {
        assert_eq!(
            Sha384::digest(b""),
            decode(
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
            )
        );
        assert_eq!(
            Sha384::digest(b"abc"),
            decode(
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
            )
        );
    }

    #[test]
    fn split_blocks_match_one_shot() {
        let input = [0xa5; 300];
        let mut sha512 = Sha512::new();
        sha512.update(&input[..17]);
        sha512.update(&input[17..191]);
        sha512.update(&input[191..]);
        assert_eq!(sha512.finalize(), Sha512::digest(&input));

        let mut sha384 = Sha384::new();
        sha384.update(&input[..127]);
        sha384.update(&input[127..128]);
        sha384.update(&input[128..]);
        assert_eq!(sha384.finalize(), Sha384::digest(&input));
    }
}
