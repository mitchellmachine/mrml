use mrml_runtime::Vector;

const WINDOW: usize = 32 * 1024;
const HASH_SIZE: usize = 1 << 15;
const MAX_CHAIN: usize = 256;
const MAX_MATCH: usize = 258;
const MIN_MATCH: usize = 3;

struct Bits {
    bytes: Vector<u8>,
    pending: u32,
    count: u8,
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

/// Encodes one deterministic zlib stream with a bounded LZ77 search and a
/// fixed-Huffman DEFLATE block. Only the 32 KiB DEFLATE window is retained and
/// at most `MAX_CHAIN` candidates are inspected at each input position.
pub(crate) fn encode_zlib(source: &[u8]) -> Vector<u8> {
    let mut bits = Bits::new();
    bits.write(1, 1);
    bits.write(1, 2);
    let mut heads = Vector::new();
    heads.resize(HASH_SIZE, usize::MAX);
    let mut previous = Vector::new();
    previous.resize(WINDOW, usize::MAX);
    let mut cursor = 0usize;
    while cursor < source.len() {
        let (length, distance) = find_match(source, cursor, &heads, &previous);
        if length >= MIN_MATCH {
            write_length(&mut bits, length);
            write_distance(&mut bits, distance);
            for position in cursor..cursor + length {
                insert(source, position, &mut heads, &mut previous);
            }
            cursor += length;
        } else {
            fixed_symbol(&mut bits, source[cursor] as usize);
            insert(source, cursor, &mut heads, &mut previous);
            cursor += 1;
        }
    }
    fixed_symbol(&mut bits, 256);
    let mut output = Vector::from([0x78, 0x01]);
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

fn reverse(mut value: u32, count: u8) -> u32 {
    let mut reversed = 0;
    for _ in 0..count {
        reversed = (reversed << 1) | (value & 1);
        value >>= 1;
    }
    reversed
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

fn write_length(bits: &mut Bits, length: usize) {
    let index = LENGTH_BASE
        .iter()
        .rposition(|base| *base <= length)
        .unwrap();
    fixed_symbol(bits, 257 + index);
    bits.write((length - LENGTH_BASE[index]) as u32, LENGTH_EXTRA[index]);
}

fn write_distance(bits: &mut Bits, distance: usize) {
    let index = DISTANCE_BASE
        .iter()
        .rposition(|base| *base <= distance)
        .unwrap();
    bits.write(reverse(index as u32, 5), 5);
    bits.write(
        (distance - DISTANCE_BASE[index]) as u32,
        DISTANCE_EXTRA[index],
    );
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
    fn fixed_stream_round_trips_boundaries_and_empty_input() {
        for input in [&b""[..], &b"a"[..], &b"abc"[..], &b"abcdabcdabcd"[..]] {
            let encoded = encode_zlib(input);
            assert_eq!(encoded[2] & 7, 3);
            assert_eq!(&*inflate_zlib(&encoded).unwrap(), input);
        }
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
}
