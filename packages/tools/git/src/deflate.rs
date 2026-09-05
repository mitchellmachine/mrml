use mrml_runtime::Vector;

mod incremental;
pub(crate) use incremental::{DeflateOutput, stream_zlib};

// Two tables, input/output buffers including growth, and a sideband copy.
// Conservative on both supported host pointer widths; excludes caller input.
pub(crate) const STREAM_SCRATCH_BYTES: u64 = 768 * 1024;

const WINDOW: usize = 32 * 1024;
const HASH_SIZE: usize = 1 << 15;
// Compatibility profile also has a bounded, non-maximum-effort search.
const MAX_CHAIN: usize = 32;
const MAX_MATCH: usize = 258;
const MIN_MATCH: usize = 3;

struct Bits {
    bytes: Vector<u8>,
    pending: u32,
    count: u8,
}

#[derive(Clone, Copy)]
enum HuffmanProfile {
    Fixed,
    Dynamic,
}

impl Bits {
    fn new() -> Self {
        Self {
            bytes: Vector::new(),
            pending: 0,
            count: 0,
        }
    }

    fn write(&mut self, value: u32, count: u8) {
        self.pending |= (value & ((1u32 << count) - 1)) << self.count;
        self.count += count;
        while self.count >= 8 {
            self.bytes.push(self.pending as u8);
            self.pending >>= 8;
            self.count -= 8;
        }
    }

    fn finish(mut self) -> Vector<u8> {
        if self.count != 0 {
            self.bytes.push(self.pending as u8);
        }
        self.bytes
    }
}

/// Collects the bounded incremental encoder's single zlib stream.
pub(crate) fn encode_zlib(source: &[u8]) -> Vector<u8> {
    let mut output = Vector::new();
    match stream_zlib(&[source], &mut output) {
        Ok(()) => output,
        Err(never) => match never {},
    }
}

/// First-party fixed-Huffman compatibility profile. Canonical pack storage
/// uses [`encode_zlib`]; this entry point exists for exact interoperability
/// coverage and never selects a profile from workload characteristics.
#[allow(dead_code)]
pub(crate) fn encode_zlib_fixed(source: &[u8]) -> Vector<u8> {
    encode_zlib_with_profile(source, HuffmanProfile::Fixed)
}

fn encode_zlib_with_profile(source: &[u8], profile: HuffmanProfile) -> Vector<u8> {
    let mut bits = Bits::new();
    bits.write(1, 1);
    match profile {
        HuffmanProfile::Fixed => bits.write(1, 2),
        HuffmanProfile::Dynamic => {
            bits.write(2, 2);
            write_dynamic_header(&mut bits);
        }
    }
    let mut heads = Vector::new();
    heads.resize(HASH_SIZE, usize::MAX);
    let mut previous = Vector::new();
    previous.resize(WINDOW, usize::MAX);
    let mut cursor = 0usize;
    while cursor < source.len() {
        let (length, distance) = find_match(source, cursor, &heads, &previous);
        if length >= MIN_MATCH {
            write_length(&mut bits, length, profile);
            write_distance(&mut bits, distance, profile);
            for position in cursor..cursor + length {
                insert(source, position, &mut heads, &mut previous);
            }
            cursor += length;
        } else {
            write_symbol(&mut bits, source[cursor] as usize, profile);
            insert(source, cursor, &mut heads, &mut previous);
            cursor += 1;
        }
    }
    write_symbol(&mut bits, 256, profile);
    // CMF/FLG advertises a 32 KiB window and the maximum-compression profile.
    let mut output = Vector::from([0x78, 0xda]);
    output.extend(bits.finish());
    output.extend(adler32(source).to_be_bytes());
    output
}

fn hash(source: &[u8], position: usize) -> Option<usize> {
    let bytes = source.get(position..position.checked_add(3)?)?;
    Some(
        ((bytes[0] as usize * 251) ^ (bytes[1] as usize * 31) ^ bytes[2] as usize)
            & (HASH_SIZE - 1),
    )
}

fn insert(source: &[u8], position: usize, heads: &mut [usize], previous: &mut [usize]) {
    let Some(hash) = hash(source, position) else {
        return;
    };
    previous[position & (WINDOW - 1)] = heads[hash];
    heads[hash] = position;
}

fn find_match(
    source: &[u8],
    position: usize,
    heads: &[usize],
    previous: &[usize],
) -> (usize, usize) {
    let Some(hash) = hash(source, position) else {
        return (0, 0);
    };
    let mut candidate = heads[hash];
    let mut best = (0usize, 0usize);
    let limit = source.len().saturating_sub(position).min(MAX_MATCH);
    for _ in 0..MAX_CHAIN {
        if candidate == usize::MAX || candidate >= position {
            break;
        }
        let distance = position - candidate;
        if distance > WINDOW {
            break;
        }
        if best.0 != 0 && best.0 < limit && source[candidate + best.0] != source[position + best.0]
        {
            let next = previous[candidate & (WINDOW - 1)];
            if next >= candidate {
                break;
            }
            candidate = next;
            continue;
        }
        let mut length = 0usize;
        while length < limit && source[candidate + length] == source[position + length] {
            length += 1;
        }
        if length > best.0 {
            best = (length, distance);
            if length == limit {
                break;
            }
        }
        let next = previous[candidate & (WINDOW - 1)];
        if next >= candidate {
            break;
        }
        candidate = next;
    }
    best
}

fn reverse(value: u32, count: u8) -> u32 {
    value.reverse_bits() >> (u32::BITS - u32::from(count))
}

fn literal_length_code_length(symbol: usize) -> u8 {
    match symbol {
        0..=147 => 8,
        148..=255 => 9,
        256..=279 => 7,
        280..=285 => 8,
        _ => unreachable!(),
    }
}

fn dynamic_symbol(bits: &mut Bits, symbol: usize) {
    let (code, count) = match symbol {
        0..=147 => (0x30 + symbol as u32, 8),
        148..=255 => (0x194 + (symbol - 148) as u32, 9),
        256..=279 => ((symbol - 256) as u32, 7),
        280..=285 => (0xc4 + (symbol - 280) as u32, 8),
        _ => unreachable!(),
    };
    bits.write(reverse(code, count), count);
}

fn fixed_symbol(bits: &mut Bits, symbol: usize) {
    let (code, count) = match symbol {
        0..=143 => (0x30 + symbol as u32, 8),
        144..=255 => (0x190 + (symbol - 144) as u32, 9),
        256..=279 => ((symbol - 256) as u32, 7),
        280..=287 => (0xc0 + (symbol - 280) as u32, 8),
        _ => unreachable!(),
    };
    bits.write(reverse(code, count), count);
}

fn write_symbol(bits: &mut Bits, symbol: usize, profile: HuffmanProfile) {
    match profile {
        HuffmanProfile::Fixed => fixed_symbol(bits, symbol),
        HuffmanProfile::Dynamic => dynamic_symbol(bits, symbol),
    }
}

fn write_dynamic_header(bits: &mut Bits) {
    // Include all RFC 1951 literal/length and distance symbols. The code-length
    // alphabet deliberately uses the simple complete 0..=15 four-bit tree;
    // this makes the emitted table deterministic and keeps its decoder surface
    // auditable without changing the LZ77 decisions by workload.
    bits.write(29, 5); // HLIT: 286 literal/length codes.
    bits.write(29, 5); // HDIST: 30 distance codes.
    bits.write(15, 4); // HCLEN: all 19 code-length-code lengths follow.
    const ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    for symbol in ORDER {
        bits.write(if symbol <= 15 { 4 } else { 0 }, 3);
    }
    for symbol in 0..286 {
        let length = literal_length_code_length(symbol);
        bits.write(reverse(u32::from(length), 4), 4);
    }
    for symbol in 0..30 {
        let length = if symbol < 2 { 4 } else { 5 };
        bits.write(reverse(length, 4), 4);
    }
}

const LENGTH_BASE: [usize; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DISTANCE_BASE: [usize; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DISTANCE_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

fn write_length(bits: &mut Bits, length: usize, profile: HuffmanProfile) {
    let index = LENGTH_BASE
        .iter()
        .rposition(|base| *base <= length)
        .unwrap();
    write_symbol(bits, 257 + index, profile);
    bits.write((length - LENGTH_BASE[index]) as u32, LENGTH_EXTRA[index]);
}

fn write_distance(bits: &mut Bits, distance: usize, profile: HuffmanProfile) {
    let index = DISTANCE_BASE
        .iter()
        .rposition(|base| *base <= distance)
        .unwrap();
    match profile {
        HuffmanProfile::Fixed => bits.write(reverse(index as u32, 5), 5),
        HuffmanProfile::Dynamic => {
            let (code, count) = distance_code(index);
            bits.write(reverse(code, count), count);
        }
    }
    bits.write(
        (distance - DISTANCE_BASE[index]) as u32,
        DISTANCE_EXTRA[index],
    );
}

fn distance_code(symbol: usize) -> (u32, u8) {
    match symbol {
        0..=1 => (symbol as u32, 4),
        2..=29 => ((symbol + 2) as u32, 5),
        _ => unreachable!(),
    }
}

fn adler32(source: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in source.chunks(5552) {
        for byte in chunk {
            a += *byte as u32;
            b += a;
        }
        a %= 65_521;
        b %= 65_521;
    }
    b << 16 | a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inflate::inflate_zlib;

    #[test]
    fn stream_round_trips_boundaries_and_empty_input() {
        for input in [&b""[..], &b"a"[..], &b"abc"[..], &b"abcdabcdabcd"[..]] {
            let encoded = encode_zlib(input);
            assert_eq!(&encoded[..2], &[0x78, 0x01]);
            assert_eq!(&*inflate_zlib(&encoded).unwrap(), input);
        }
    }

    #[test]
    fn fixed_huffman_stream_uses_the_same_bounded_lz77_profile() {
        for input in [
            &b""[..],
            &b"fixed literals"[..],
            &b"fixed fixed fixed fixed fixed fixed"[..],
        ] {
            let encoded = encode_zlib_fixed(input);
            assert_eq!(&encoded[..2], &[0x78, 0xda]);
            assert_eq!(encoded[2] & 7, 3);
            assert_eq!(&*inflate_zlib(&encoded).unwrap(), input);
        }
    }

    #[test]
    fn dynamic_profile_is_exact_and_complete() {
        assert_eq!(reverse(0b1101, 4), 0b1011);
        assert_eq!(reverse(0b1_0010_1101, 9), 0b1_0110_1001);
        assert_eq!(MAX_CHAIN, 32);
        assert_eq!(literal_length_code_length(0), 8);
        assert_eq!(literal_length_code_length(147), 8);
        assert_eq!(literal_length_code_length(148), 9);
        assert_eq!(literal_length_code_length(255), 9);
        assert_eq!(literal_length_code_length(256), 7);
        assert_eq!(literal_length_code_length(279), 7);
        assert_eq!(literal_length_code_length(280), 8);
        assert_eq!(literal_length_code_length(285), 8);
        assert_eq!(distance_code(0), (0, 4));
        assert_eq!(distance_code(1), (1, 4));
        assert_eq!(distance_code(2), (4, 5));
        assert_eq!(distance_code(29), (31, 5));

        let literal_kraft: usize = (0..286)
            .map(|symbol| 1usize << (15 - literal_length_code_length(symbol)))
            .sum();
        let distance_kraft: usize = (0..30)
            .map(|symbol| 1usize << (15 - distance_code(symbol).1))
            .sum();
        assert_eq!(literal_kraft, 1 << 15);
        assert_eq!(distance_kraft, 1 << 15);
    }

    #[test]
    fn repetitive_input_is_compressed_and_deterministic() {
        let input = Vector::from([b'x'; 70_000]);
        let first = encode_zlib(&input);
        assert_eq!(first, encode_zlib(&input));
        assert!(first.len() < input.len() / 10);
        assert_eq!(inflate_zlib(&first).unwrap(), input);
    }

    #[test]
    fn incompressible_bytes_round_trip() {
        let input: Vector<u8> = (0..4096)
            .map(|value| (value * 73 + value / 17) as u8)
            .collect();
        assert_eq!(inflate_zlib(&encode_zlib(&input)).unwrap(), input);
    }

    #[test]
    fn match_can_use_full_window_distance() {
        let mut input: Vector<u8> = (0..WINDOW).map(|value| value as u8).collect();
        input.extend([0, 1, 2]);
        assert_eq!(inflate_zlib(&encode_zlib(&input)).unwrap(), input);
    }

    #[test]
    fn large_compressible_inputs_remain_compressed() {
        for length in [1024 * 1024 + 1, 32 * 1024 * 1024] {
            let input: Vector<u8> = core::iter::repeat_n(b'x', length).collect();
            let encoded = encode_zlib(&input);
            assert!(encoded.len() < input.len() / 10);
            assert_eq!(inflate_zlib(&encoded).unwrap(), input);
        }
    }

    #[test]
    fn best_boundary_skip_preserves_exhaustive_match_selection() {
        let input: Vector<u8> = (0..16_384)
            .map(|position| {
                let block = position / 64;
                ((position % 31) ^ (block * 17) ^ (block / 7)) as u8
            })
            .collect();
        let mut heads = Vector::new();
        heads.resize(HASH_SIZE, usize::MAX);
        let mut previous = Vector::new();
        previous.resize(WINDOW, usize::MAX);
        for position in 0..input.len() {
            assert_eq!(
                find_match(&input, position, &heads, &previous),
                find_match_exhaustive(&input, position, &heads, &previous),
                "position {position}"
            );
            insert(&input, position, &mut heads, &mut previous);
        }
    }

    fn find_match_exhaustive(
        source: &[u8],
        position: usize,
        heads: &[usize],
        previous: &[usize],
    ) -> (usize, usize) {
        let Some(hash) = hash(source, position) else {
            return (0, 0);
        };
        let mut candidate = heads[hash];
        let mut best = (0usize, 0usize);
        let limit = source.len().saturating_sub(position).min(MAX_MATCH);
        for _ in 0..MAX_CHAIN {
            if candidate == usize::MAX || candidate >= position {
                break;
            }
            let distance = position - candidate;
            if distance > WINDOW {
                break;
            }
            let mut length = 0usize;
            while length < limit && source[candidate + length] == source[position + length] {
                length += 1;
            }
            if length > best.0 {
                best = (length, distance);
                if length == limit {
                    break;
                }
            }
            let next = previous[candidate & (WINDOW - 1)];
            if next >= candidate {
                break;
            }
            candidate = next;
        }
        best
    }
}
