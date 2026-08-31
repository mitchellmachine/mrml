//! SHA-1 solely for the mandatory OpenPGP v4 fingerprint encoding.
//!
//! SHA-1 is not exported and is never accepted as a signature digest.

const INITIAL: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

#[derive(Clone)]
pub(crate) struct Sha1 {
    state: [u32; 5],
    block: [u8; 64],
    used: usize,
    length: u64,
}

impl Sha1 {
    pub(crate) const fn new() -> Self {
        Self {
            state: INITIAL,
            block: [0; 64],
            used: 0,
            length: 0,
        }
    }

    pub(crate) fn update(&mut self, mut input: &[u8]) {
        self.length = self.length.wrapping_add(input.len() as u64);
        if self.used != 0 {
            let take = input.len().min(64 - self.used);
            self.block[self.used..self.used + take].copy_from_slice(&input[..take]);
            self.used += take;
            input = &input[take..];
            if self.used != 64 {
                return;
            }
            let block = self.block;
            self.compress(&block);
            self.used = 0;
        }
        while input.len() >= 64 {
            let block: &[u8; 64] = input[..64].try_into().expect("fixed SHA-1 block");
            self.compress(block);
            input = &input[64..];
        }
        self.block[..input.len()].copy_from_slice(input);
        self.used = input.len();
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut words = [0u32; 80];
        for (word, bytes) in words[..16].iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_be_bytes(*bytes);
        }
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = self.state;
        for (index, word) in words.iter().enumerate() {
            let (function, constant) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(function)
                .wrapping_add(e)
                .wrapping_add(constant)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        for (state, value) in self.state.iter_mut().zip([a, b, c, d, e]) {
            *state = state.wrapping_add(value);
        }
    }

    pub(crate) fn finalize(mut self) -> [u8; 20] {
        let bit_length = self.length.wrapping_mul(8);
        self.block[self.used] = 0x80;
        self.used += 1;
        if self.used > 56 {
            self.block[self.used..].fill(0);
            let block = self.block;
            self.compress(&block);
            self.used = 0;
        }
        self.block[self.used..56].fill(0);
        self.block[56..].copy_from_slice(&bit_length.to_be_bytes());
        let block = self.block;
        self.compress(&block);
        let mut output = [0u8; 20];
        for (bytes, word) in output.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_vector() {
        let mut hash = Sha1::new();
        hash.update(b"abc");
        assert_eq!(
            hash.finalize(),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
            ]
        );
    }
}
