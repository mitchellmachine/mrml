use super::*;

/// A sink may reject a work reservation or write before the next block is
/// compressed. Input processing reserves eight units per byte before copying
/// or checksumming: traversal/insertion and at most four match-search steps
/// per byte. Dictionary setup and block overhead are reserved separately.
pub(crate) trait DeflateOutput {
    type Error;
    fn charge(&mut self, units: u64) -> Result<(), Self::Error>;
    fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
}

impl DeflateOutput for Vector<u8> {
    type Error = core::convert::Infallible;
    fn charge(&mut self, _: u64) -> Result<(), Self::Error> {
        Ok(())
    }
    fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.extend(bytes.iter().copied());
        Ok(())
    }
}

/// One zlib stream across all input slices, with a 32 KiB block/dictionary,
/// bounded output scratch and synchronous backpressure. Dictionary reset at
/// block boundaries deliberately limits search and recovery complexity.
pub(crate) fn stream_zlib<O: DeflateOutput>(
    parts: &[&[u8]],
    output: &mut O,
) -> Result<(), O::Error> {
    output.charge(1)?;
    output.write(&[0x78, 0x01])?;
    let mut block = Vector::new();
    let mut heads = Vector::new();
    let mut previous = Vector::new();
    let (mut a, mut b) = (1u32, 0u32);
    for part in parts {
        let mut source = *part;
        while !source.is_empty() {
            if block.len() == WINDOW {
                write_block(&block, false, &mut heads, &mut previous, output)?;
                block.clear();
            }
            let count = source.len().min(WINDOW - block.len());
            output.charge(count as u64 * 8)?;
            let bytes = &source[..count];
            for chunk in bytes.chunks(5552) {
                for byte in chunk {
                    a += u32::from(*byte);
                    b += a;
                }
                a %= 65_521;
                b %= 65_521;
            }
            block.extend(bytes.iter().copied());
            source = &source[count..];
        }
    }
    write_block(&block, true, &mut heads, &mut previous, output)?;
    output.write(&(b << 16 | a).to_be_bytes())
}

fn write_block<O: DeflateOutput>(
    source: &[u8],
    final_block: bool,
    heads: &mut Vector<usize>,
    previous: &mut Vector<usize>,
    output: &mut O,
) -> Result<(), O::Error> {
    output.charge(8)?;
    // The fixed dynamic table costs more than these short blocks can usefully
    // save. Avoid allocating/clearing match tables for tiny objects entirely.
    if source.len() <= 256 {
        return write_stored(source, final_block, output);
    }
    output.charge((HASH_SIZE + WINDOW) as u64)?;
    if heads.is_empty() {
        heads.resize(HASH_SIZE, usize::MAX);
        previous.resize(WINDOW, usize::MAX);
    } else {
        heads.fill(usize::MAX);
        previous.fill(usize::MAX);
    }
    let mut bits = Bits::new();
    bits.write(u32::from(final_block), 1);
    bits.write(2, 2);
    write_dynamic_header(&mut bits);
    let mut search_remaining = source.len() * 4;
    let mut cursor = 0;
    while cursor < source.len() {
        let (length, distance) =
            bounded_match(source, cursor, heads, previous, &mut search_remaining);
        if length >= MIN_MATCH {
            write_length(&mut bits, length, HuffmanProfile::Dynamic);
            write_distance(&mut bits, distance, HuffmanProfile::Dynamic);
            for position in cursor..cursor + length {
                insert(source, position, heads, previous);
            }
            cursor += length;
        } else {
            write_symbol(
                &mut bits,
                usize::from(source[cursor]),
                HuffmanProfile::Dynamic,
            );
            insert(source, cursor, heads, previous);
            cursor += 1;
        }
    }
    write_symbol(&mut bits, 256, HuffmanProfile::Dynamic);
    if !final_block {
        // An empty non-final stored block aligns the next block to a byte.
        // This is inside the same DEFLATE/zlib stream, not a new zlib member.
        bits.write(0, 3);
    }
    let mut compressed = bits.finish();
    if !final_block {
        compressed.extend([0, 0, 255, 255]);
    }
    if compressed.len() < source.len() + 5 {
        output.write(&compressed)
    } else {
        write_stored(source, final_block, output)
    }
}

fn write_stored<O: DeflateOutput>(
    source: &[u8],
    final_block: bool,
    output: &mut O,
) -> Result<(), O::Error> {
    output.write(&[u8::from(final_block)])?;
    output.write(&(source.len() as u16).to_le_bytes())?;
    output.write(&(!(source.len() as u16)).to_le_bytes())?;
    output.write(source)
}

fn bounded_match(
    source: &[u8],
    position: usize,
    heads: &[usize],
    previous: &[usize],
    remaining: &mut usize,
) -> (usize, usize) {
    let Some(hash) = hash(source, position) else {
        return (0, 0);
    };
    let mut candidate = heads[hash];
    let mut best = (0, 0);
    let limit = (source.len() - position).min(MAX_MATCH);
    for _ in 0..MAX_CHAIN {
        if candidate == usize::MAX || candidate >= position || *remaining == 0 {
            break;
        }
        *remaining -= 1;
        let mut length = 0;
        while length < limit && *remaining != 0 {
            *remaining -= 1;
            if source[candidate + length] != source[position + length] {
                break;
            }
            length += 1;
        }
        if length > best.0 {
            best = (length, position - candidate);
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
