use mrml_runtime::Vector;

const LB: [usize; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LE: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DB: [usize; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DE: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InflateError {
    Truncated,
    Header,
    Block,
    Code,
    Distance,
    TooLarge,
    Checksum,
}
pub(crate) trait InflateByteReader {
    fn read_byte(&mut self) -> Result<u8, InflateError>;
    fn consumed(&self) -> usize;
}

struct SliceReader<'a> {
    source: &'a [u8],
    position: usize,
}

impl InflateByteReader for SliceReader<'_> {
    fn read_byte(&mut self) -> Result<u8, InflateError> {
        let byte = *self
            .source
            .get(self.position)
            .ok_or(InflateError::Truncated)?;
        self.position += 1;
        Ok(byte)
    }

    fn consumed(&self) -> usize {
        self.position
    }
}

struct Bits<'a, R> {
    reader: &'a mut R,
    v: u64,
    n: u8,
}
impl<'a, R: InflateByteReader> Bits<'a, R> {
    fn new(reader: &'a mut R) -> Self {
        Self { reader, v: 0, n: 0 }
    }
    fn read(&mut self, n: u8) -> Result<usize, InflateError> {
        while self.n < n {
            let b = self.reader.read_byte()?;
            self.v |= (b as u64) << self.n;
            self.n += 8
        }
        let m = if n == 0 { 0 } else { (1u64 << n) - 1 };
        let r = (self.v & m) as usize;
        self.v >>= n;
        self.n -= n;
        Ok(r)
    }
    fn align(&mut self) {
        self.v = 0;
        self.n = 0
    }
}
struct Huff {
    count: [u16; 16],
    symbols: Vector<u16>,
}
impl Huff {
    fn build(lengths: &[u8]) -> Result<Self, InflateError> {
        let mut count = [0u16; 16];
        for &n in lengths {
            if n > 15 {
                return Err(InflateError::Code);
            }
            count[n as usize] += 1
        }
        if count[0] as usize == lengths.len() {
            return Err(InflateError::Code);
        }
        let mut left = 1i32;
        for &n in &count[1..] {
            left = (left << 1) - n as i32;
            if left < 0 {
                return Err(InflateError::Code);
            }
        }
        let mut off = [0u16; 16];
        for n in 1..15 {
            off[n + 1] = off[n] + count[n]
        }
        let mut symbols = Vector::new();
        symbols.resize(lengths.len() - count[0] as usize, 0);
        for (i, &n) in lengths.iter().enumerate() {
            if n != 0 {
                symbols[off[n as usize] as usize] = i as u16;
                off[n as usize] += 1
            }
        }
        Ok(Self { count, symbols })
    }
    fn decode<R: InflateByteReader>(&self, b: &mut Bits<'_, R>) -> Result<usize, InflateError> {
        let (mut code, mut first, mut index) = (0, 0, 0);
        for n in 1..=15 {
            code |= b.read(1)?;
            let count = self.count[n] as usize;
            if code < first + count {
                return self
                    .symbols
                    .get(index + code - first)
                    .copied()
                    .map(|v| v as usize)
                    .ok_or(InflateError::Code);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1
        }
        Err(InflateError::Code)
    }
}

pub fn inflate_zlib(source: &[u8]) -> Result<Vector<u8>, InflateError> {
    let (output, consumed) = inflate_zlib_prefix(source)?;
    if consumed != source.len() {
        return Err(InflateError::Header);
    }
    Ok(output)
}

pub(crate) fn inflate_zlib_prefix(source: &[u8]) -> Result<(Vector<u8>, usize), InflateError> {
    let mut reader = SliceReader {
        source,
        position: 0,
    };
    let output = inflate_zlib_reader(&mut reader, 512 * 1024 * 1024)?;
    Ok((output, reader.consumed()))
}

pub(crate) fn inflate_zlib_reader<R: InflateByteReader>(
    reader: &mut R,
    max_output: usize,
) -> Result<Vector<u8>, InflateError> {
    let cmf = reader.read_byte()?;
    let flg = reader.read_byte()?;
    let h = u16::from_be_bytes([cmf, flg]);
    if h % 31 != 0 || cmf & 15 != 8 || cmf >> 4 > 7 || flg & 0x20 != 0 {
        return Err(InflateError::Header);
    }
    let out = inflate_raw_reader(reader, max_output)?;
    let checksum = u32::from_be_bytes([
        reader.read_byte()?,
        reader.read_byte()?,
        reader.read_byte()?,
        reader.read_byte()?,
    ]);
    if adler(&out) != checksum {
        return Err(InflateError::Checksum);
    }
    Ok(out)
}

fn inflate_raw_reader<R: InflateByteReader>(
    reader: &mut R,
    max_output: usize,
) -> Result<Vector<u8>, InflateError> {
    let mut b = Bits::new(reader);
    let mut out = Vector::new();
    loop {
        let last = b.read(1)? != 0;
        match b.read(2)? {
            0 => stored(&mut b, &mut out, max_output)?,
            1 => {
                let (l, d) = fixed()?;
                compressed(&mut b, &mut out, &l, &d, max_output)?
            }
            2 => {
                let (l, d) = dynamic(&mut b)?;
                compressed(&mut b, &mut out, &l, &d, max_output)?
            }
            _ => return Err(InflateError::Block),
        }
        if last {
            break;
        }
    }
    Ok(out)
}
fn room(out: &Vector<u8>, n: usize, max_output: usize) -> Result<(), InflateError> {
    out.len()
        .checked_add(n)
        .filter(|v| *v <= max_output)
        .map(|_| ())
        .ok_or(InflateError::TooLarge)
}
fn stored<R: InflateByteReader>(
    b: &mut Bits<'_, R>,
    out: &mut Vector<u8>,
    max_output: usize,
) -> Result<(), InflateError> {
    b.align();
    let n = b.read(16)?;
    if b.read(16)? != (!n & 65535) {
        return Err(InflateError::Block);
    }
    room(out, n, max_output)?;
    for _ in 0..n {
        out.push(b.read(8)? as u8)
    }
    Ok(())
}
fn fixed() -> Result<(Huff, Huff), InflateError> {
    let mut l = [0u8; 288];
    l[..144].fill(8);
    l[144..256].fill(9);
    l[256..280].fill(7);
    l[280..].fill(8);
    Ok((Huff::build(&l)?, Huff::build(&[5u8; 32])?))
}
fn dynamic<R: InflateByteReader>(b: &mut Bits<'_, R>) -> Result<(Huff, Huff), InflateError> {
    let nl = b.read(5)? + 257;
    let nd = b.read(5)? + 1;
    let nc = b.read(4)? + 4;
    if nl > 286 || nd > 30 {
        return Err(InflateError::Code);
    }
    let order = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let mut cl = [0u8; 19];
    for i in 0..nc {
        cl[order[i]] = b.read(3)? as u8
    }
    let ch = Huff::build(&cl)?;
    let total = nl + nd;
    let mut lengths = Vector::new();
    while lengths.len() < total {
        match ch.decode(b)? {
            v @ 0..=15 => lengths.push(v as u8),
            16 => {
                let p = *lengths.last().ok_or(InflateError::Code)?;
                repeat(&mut lengths, p, b.read(2)? + 3, total)?
            }
            17 => {
                let n = b.read(3)? + 3;
                repeat(&mut lengths, 0, n, total)?
            }
            18 => {
                let n = b.read(7)? + 11;
                repeat(&mut lengths, 0, n, total)?
            }
            _ => return Err(InflateError::Code),
        }
    }
    if lengths[256] == 0 {
        return Err(InflateError::Code);
    }
    Ok((Huff::build(&lengths[..nl])?, Huff::build(&lengths[nl..])?))
}
fn repeat(v: &mut Vector<u8>, x: u8, n: usize, total: usize) -> Result<(), InflateError> {
    if v.len() + n > total {
        return Err(InflateError::Code);
    }
    for _ in 0..n {
        v.push(x)
    }
    Ok(())
}
fn compressed(
    b: &mut Bits<'_, impl InflateByteReader>,
    out: &mut Vector<u8>,
    l: &Huff,
    d: &Huff,
    max_output: usize,
) -> Result<(), InflateError> {
    loop {
        match l.decode(b)? {
            v @ 0..=255 => {
                room(out, 1, max_output)?;
                out.push(v as u8)
            }
            256 => return Ok(()),
            v @ 257..=285 => {
                let i = v - 257;
                let n = LB[i] + b.read(LE[i])?;
                let ds = d.decode(b)?;
                if ds >= 30 {
                    return Err(InflateError::Distance);
                }
                let distance = DB[ds] + b.read(DE[ds])?;
                if distance == 0 || distance > out.len() {
                    return Err(InflateError::Distance);
                }
                room(out, n, max_output)?;
                for _ in 0..n {
                    out.push(out[out.len() - distance])
                }
            }
            _ => return Err(InflateError::Code),
        }
    }
}
fn adler(s: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for c in s.chunks(5552) {
        for x in c {
            a += *x as u32;
            b += a
        }
        a %= 65521;
        b %= 65521
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deflate::encode_zlib;
    #[test]
    fn decodes_dynamic_huffman_stream() {
        let hex = "789CEDD3DB6DC3301403D055EE04DD49B1E558492CB9969C47A72FD029FA71262041F08C35C7F759A67B5C8EF6AAB1B477DCCE6DEFD19EF988B1E678A49F4FCCEDFA15358DF2CCD12EB73C8D1E475E7A8C23E71E53DBB6327A943AE777F4BE462FD75AEA35C6916ADFDB31624FD33DE6FC1829D67359B654E355EADC5E3D1EA59EEFE8793A8F323E91CEB98CBF6CD5ACE66B1860800106186080010618608001061860800106186080010618608001061860800106186080010618608001061860800106186080010618608001061860800106186080010618608001061860800106186080010618608001061860800106186080010618608001061860800106186080010618608001061860800106186080010618608001061860800106186080010618608001061860800106CBFF61F00B25056C6C";
        let mut bytes = Vector::new();
        for pair in hex.as_bytes().chunks(2) {
            let d = |x: u8| if x <= b'9' { x - b'0' } else { x - b'A' + 10 };
            bytes.push(d(pair[0]) * 16 + d(pair[1]));
        }
        for _ in 0..10 {
            bytes.remove(291);
        }
        let out = inflate_zlib(&bytes).unwrap();
        assert_eq!(out.len(), 31000);
        assert!(out.starts_with(b"the quick brown fox"));
        assert!(out.ends_with(b"security audit "));
    }
    #[test]
    fn rejects_checksum_corruption() {
        let mut bytes = Vector::from([0x78, 0x01, 1, 0, 0, 0xff, 0xff, 0, 0, 0, 1]);
        bytes[10] ^= 1;
        assert_eq!(inflate_zlib(&bytes), Err(InflateError::Checksum));
    }

    #[test]
    fn reader_boundary_reports_exact_consumption_and_enforces_output_limit() {
        let mut encoded = encode_zlib(b"bounded reader");
        let exact = encoded.len();
        encoded.extend(*b"next");
        let (decoded, consumed) = inflate_zlib_prefix(&encoded).unwrap();
        assert_eq!(&*decoded, b"bounded reader");
        assert_eq!(consumed, exact);

        let mut reader = SliceReader {
            source: &encoded,
            position: 0,
        };
        assert_eq!(
            inflate_zlib_reader(&mut reader, 3),
            Err(InflateError::TooLarge)
        );
    }
}
