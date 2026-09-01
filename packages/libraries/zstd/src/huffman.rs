use crate::bits::{ReverseBitWriter, ReverseBits};
use crate::fse::{
    CompressionPath, State as FseState, Table as FseTable, parse_table, serialize_probabilities,
};
use crate::{Error, Result};
use mrml_runtime::Vector;

const MAX_BITS: u8 = 11;

#[derive(Clone, Copy, Default)]
struct Slot {
    symbol: u8,
    bits: u8,
}

#[derive(Clone, Copy, Default)]
#[allow(dead_code)] // Consumed when the compressed-literals block encoder is integrated.
struct Code {
    value: u16,
    bits: u8,
}

/// Deterministic bounded Huffman table used by the staged compressed-block
/// encoder. Direct Zstandard tree descriptions can carry at most 128 explicit
/// weights plus the implicit final symbol, so this foundation rejects larger
/// alphabets rather than silently selecting a different representation.
#[allow(dead_code)] // Consumed when the compressed-literals block encoder is integrated.
pub(crate) struct EncoderTable {
    table: Table,
    codes: [Code; 256],
    explicit_weights: Vector<u8>,
}

#[allow(dead_code)]
impl EncoderTable {
    pub(crate) fn from_frequencies(frequencies: &[u32]) -> Result<Self> {
        if frequencies.len() > 256 {
            return Err(Error::InvalidHuffmanTree);
        }
        let mut active = Vector::new();
        for (symbol, frequency) in frequencies.iter().copied().enumerate() {
            if frequency != 0 {
                active
                    .try_push((symbol as u8, frequency))
                    .map_err(|_| Error::Allocation)?;
            }
        }
        if !(2..=129).contains(&active.len()) {
            return Err(Error::InvalidHuffmanTree);
        }
        // `mrml_runtime::Vector` deliberately exposes a smaller collection
        // surface than `alloc::Vec`; bounded insertion sorting also keeps the
        // tie-breaking rule explicit for this at-most-129-symbol table.
        for index in 1..active.len() {
            let mut position = index;
            while position != 0 {
                let left = active[position - 1];
                let right = active[position];
                if left.1 > right.1 || (left.1 == right.1 && left.0 < right.0) {
                    break;
                }
                active.swap(position - 1, position);
                position -= 1;
            }
        }

        // A complete, length-limited prefix tree for N leaves consists of
        // 2^ceil(log2(N))-N leaves one level shorter and the remainder at the
        // ceiling. Assigning the shorter codes to the most frequent symbols is
        // deterministic and keeps every code within the format's 11-bit cap.
        let maximum_bits = (usize::BITS - (active.len() - 1).leading_zeros()) as u8;
        if maximum_bits == 0 || maximum_bits > MAX_BITS {
            return Err(Error::InvalidHuffmanTree);
        }
        let shorter = (1usize << maximum_bits) - active.len();
        let mut lengths = [0u8; 256];
        for (index, (symbol, _)) in active.iter().enumerate() {
            lengths[*symbol as usize] = if index < shorter {
                maximum_bits - 1
            } else {
                maximum_bits
            };
        }
        let final_symbol = active
            .iter()
            .map(|(symbol, _)| *symbol as usize)
            .max()
            .ok_or(Error::InvalidHuffmanTree)?;
        if final_symbol == 0 || final_symbol > 128 {
            return Err(Error::InvalidHuffmanTree);
        }
        let table = Table::from_lengths(&lengths[..=final_symbol])?;
        let mut explicit_weights =
            Vector::with_capacity(final_symbol).map_err(|_| Error::Allocation)?;
        for length in &lengths[..final_symbol] {
            explicit_weights.push(if *length == 0 {
                0
            } else {
                maximum_bits + 1 - *length
            });
        }

        let mut counts = [0u16; MAX_BITS as usize + 1];
        for length in &lengths[..=final_symbol] {
            if *length != 0 {
                counts[*length as usize] += 1;
            }
        }
        let mut next = [0u16; MAX_BITS as usize + 1];
        for bits in (1..maximum_bits).rev() {
            next[bits as usize] = (next[bits as usize + 1] + counts[bits as usize + 1]) >> 1;
        }
        let mut codes = [Code::default(); 256];
        for bits in (1..=maximum_bits).rev() {
            for (symbol, length) in lengths[..=final_symbol].iter().enumerate() {
                if *length == bits {
                    codes[symbol] = Code {
                        value: next[bits as usize],
                        bits,
                    };
                    next[bits as usize] += 1;
                }
            }
        }
        Ok(Self {
            table,
            codes,
            explicit_weights,
        })
    }

    pub(crate) fn serialize_direct_tree(&self) -> Result<Vector<u8>> {
        if self.explicit_weights.is_empty() || self.explicit_weights.len() > 128 {
            return Err(Error::InvalidHuffmanTree);
        }
        let mut output = Vector::with_capacity(1 + self.explicit_weights.len().div_ceil(2))
            .map_err(|_| Error::Allocation)?;
        output.push((127 + self.explicit_weights.len()) as u8);
        for weights in self.explicit_weights.chunks(2) {
            let high = weights[0];
            let low = weights.get(1).copied().unwrap_or(0);
            output.push((high << 4) | low);
        }
        Ok(output)
    }

    fn serialize_fse_tree(&self) -> Result<Vector<u8>> {
        // The existing bounded decoder retires the two interleaved FSE states
        // as a pair, so an odd weight count cannot be represented by this
        // profile. Direct weights remain the deterministic fallback.
        if self.explicit_weights.len() < 2 || self.explicit_weights.len() & 1 != 0 {
            return Err(Error::InvalidFseTable);
        }
        let mut occurrences = [0u16; MAX_BITS as usize + 1];
        for weight in &self.explicit_weights {
            if *weight > MAX_BITS {
                return Err(Error::InvalidHuffmanTree);
            }
            occurrences[*weight as usize] += 1;
        }
        let active = occurrences.iter().filter(|count| **count != 0).count();
        if active < 2 || active > 12 {
            return Err(Error::InvalidFseTable);
        }

        // Accuracy 5 is the smallest RFC-defined Huffman-weight FSE table.
        // A near-uniform normalization keeps every transition at least one bit,
        // which makes the decoder's bounded two-state termination unambiguous.
        let mut probabilities = [0i16; MAX_BITS as usize + 1];
        let base = 32 / active;
        let mut remainder = 32 % active;
        for (symbol, count) in occurrences.iter().enumerate() {
            if *count == 0 {
                continue;
            }
            probabilities[symbol] = (base + usize::from(remainder != 0)) as i16;
            remainder = remainder.saturating_sub(1);
        }
        let last = occurrences
            .iter()
            .rposition(|count| *count != 0)
            .ok_or(Error::InvalidFseTable)?;
        let probabilities = &probabilities[..=last];
        let table = FseTable::from_probabilities(probabilities, 5)?;
        let header = serialize_probabilities(probabilities, 5)?;

        let mut first_symbols = Vector::with_capacity(self.explicit_weights.len() / 2)
            .map_err(|_| Error::Allocation)?;
        let mut second_symbols = Vector::with_capacity(self.explicit_weights.len() / 2)
            .map_err(|_| Error::Allocation)?;
        for pair in self.explicit_weights.chunks(2) {
            first_symbols.push(pair[0] as u16);
            second_symbols.push(pair[1] as u16);
        }
        let first = CompressionPath::for_symbols(&table, &first_symbols)?;
        let second = CompressionPath::for_symbols(&table, &second_symbols)?;
        let maximum_bits = self
            .explicit_weights
            .len()
            .checked_mul(table.accuracy as usize)
            .ok_or(Error::BlockTooLarge)?;
        let mut writer = ReverseBitWriter::new(maximum_bits);
        writer.write(first.initial() as u32, table.accuracy)?;
        writer.write(second.initial() as u32, table.accuracy)?;
        for index in 0..first_symbols.len().saturating_sub(1) {
            let (value, bits) = first.transition(&table, index)?;
            writer.write(value, bits)?;
            let (value, bits) = second.transition(&table, index)?;
            writer.write(value, bits)?;
        }
        let stream = writer.finish()?;
        let payload_length = header
            .len()
            .checked_add(stream.len())
            .ok_or(Error::BlockTooLarge)?;
        if payload_length >= 128 {
            return Err(Error::BlockTooLarge);
        }
        let mut output =
            Vector::with_capacity(payload_length + 1).map_err(|_| Error::Allocation)?;
        output.push(payload_length as u8);
        output
            .try_extend_from_slice(&header)
            .map_err(|_| Error::Allocation)?;
        output
            .try_extend_from_slice(&stream)
            .map_err(|_| Error::Allocation)?;
        Ok(output)
    }

    /// Select the shorter standards-conformant tree representation. Equal-size
    /// encodings prefer direct weights to keep the simpler form canonical.
    pub(crate) fn serialize_tree(&self) -> Result<Vector<u8>> {
        let direct = self.serialize_direct_tree()?;
        match self.serialize_fse_tree() {
            Ok(compressed) if compressed.len() < direct.len() => Ok(compressed),
            Ok(_) | Err(Error::InvalidFseTable | Error::BlockTooLarge) => Ok(direct),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn encode_stream(&self, input: &[u8]) -> Result<Vector<u8>> {
        let maximum_bits = input
            .len()
            .checked_mul(MAX_BITS as usize)
            .ok_or(Error::BlockTooLarge)?;
        let mut writer = ReverseBitWriter::new(maximum_bits);
        for symbol in input {
            let code = self.codes[*symbol as usize];
            if code.bits == 0 {
                return Err(Error::InvalidHuffmanStream);
            }
            writer.write(code.value as u32, code.bits)?;
        }
        writer.finish()
    }
}

#[derive(Clone)]
pub(crate) struct Table {
    maximum_bits: u8,
    lookup: Vector<Slot>,
}

impl Table {
    fn from_weights(weights: &[u8]) -> Result<Self> {
        let mut total = 0u32;
        for weight in weights {
            if *weight > MAX_BITS {
                return Err(Error::InvalidHuffmanTree);
            }
            if *weight != 0 {
                total = total
                    .checked_add(1u32 << (*weight - 1))
                    .ok_or(Error::InvalidHuffmanTree)?;
            }
        }
        if total == 0 {
            return Err(Error::InvalidHuffmanTree);
        }
        // Zstandard reserves one implicit final symbol. Consequently the
        // table log is floor(log2(explicit weight total)) + 1 even when the
        // explicit total is already a power of two.
        let maximum_bits = (32 - total.leading_zeros()) as u8;
        if maximum_bits > MAX_BITS {
            return Err(Error::InvalidHuffmanTree);
        }
        let missing = (1u32 << maximum_bits)
            .checked_sub(total)
            .ok_or(Error::InvalidHuffmanTree)?;
        if !missing.is_power_of_two() {
            return Err(Error::InvalidHuffmanTree);
        }
        let final_weight = missing.trailing_zeros() as u8 + 1;
        let count = weights
            .len()
            .checked_add(1)
            .ok_or(Error::InvalidHuffmanTree)?;
        if count > 256 {
            return Err(Error::InvalidHuffmanTree);
        }
        let mut lengths = Vector::with_capacity(count).map_err(|_| Error::Allocation)?;
        for weight in weights
            .iter()
            .copied()
            .chain(core::iter::once(final_weight))
        {
            lengths.push(if weight == 0 {
                0
            } else {
                maximum_bits + 1 - weight
            });
        }
        Self::from_lengths(&lengths)
    }

    fn from_lengths(lengths: &[u8]) -> Result<Self> {
        let maximum_bits = *lengths.iter().max().ok_or(Error::InvalidHuffmanTree)?;
        if maximum_bits == 0 || maximum_bits > MAX_BITS {
            return Err(Error::InvalidHuffmanTree);
        }
        let mut counts = [0u16; MAX_BITS as usize + 1];
        for length in lengths {
            if *length != 0 {
                counts[*length as usize] += 1;
            }
        }
        let kraft: u32 = (1..=maximum_bits)
            .map(|bits| (counts[bits as usize] as u32) << (maximum_bits - bits))
            .sum();
        if kraft != 1u32 << maximum_bits {
            return Err(Error::InvalidHuffmanTree);
        }
        let mut next = [0u16; MAX_BITS as usize + 1];
        for bits in (1..maximum_bits).rev() {
            next[bits as usize] = (next[bits as usize + 1] + counts[bits as usize + 1]) >> 1;
        }
        let size = 1usize << maximum_bits;
        let mut lookup = Vector::with_capacity(size).map_err(|_| Error::Allocation)?;
        lookup.resize(size, Slot::default());
        for bits in (1..=maximum_bits).rev() {
            for (symbol, length) in lengths.iter().enumerate() {
                if *length != bits {
                    continue;
                }
                let code = next[bits as usize] as usize;
                next[bits as usize] += 1;
                let shift = maximum_bits - bits;
                let start = code << shift;
                let end = start + (1usize << shift);
                if end > lookup.len() {
                    return Err(Error::InvalidHuffmanTree);
                }
                for slot in &mut lookup[start..end] {
                    *slot = Slot {
                        symbol: symbol as u8,
                        bits,
                    };
                }
            }
        }
        Ok(Self {
            maximum_bits,
            lookup,
        })
    }

    fn decode_symbol(&self, bits: &mut ReverseBits<'_>) -> Result<u8> {
        let slot = self.lookup[bits.peek_padded(self.maximum_bits) as usize];
        if slot.bits == 0 {
            return Err(Error::InvalidHuffmanStream);
        }
        if slot.bits as usize > bits.remaining() {
            return Err(Error::HuffmanSymbolTruncated(slot.bits, bits.remaining()));
        }
        bits.consume(slot.bits)?;
        Ok(slot.symbol)
    }
}

pub(crate) fn parse_tree(bytes: &[u8]) -> Result<(Table, usize)> {
    let header = *bytes.first().ok_or(Error::InvalidHuffmanTree)?;
    let (weights, consumed) = if header >= 128 {
        let count = header as usize - 127;
        let packed = count.div_ceil(2);
        let data = bytes.get(1..1 + packed).ok_or(Error::InvalidHuffmanTree)?;
        let mut weights = Vector::with_capacity(count).map_err(|_| Error::Allocation)?;
        for index in 0..count {
            weights.push(if index & 1 == 0 {
                data[index / 2] >> 4
            } else {
                data[index / 2] & 15
            });
        }
        (weights, 1 + packed)
    } else {
        let length = header as usize;
        let payload = bytes.get(1..1 + length).ok_or(Error::InvalidHuffmanTree)?;
        (decode_fse_weights(payload)?, 1 + length)
    };
    let table = Table::from_weights(&weights)?;
    Ok((table, consumed))
}

fn decode_fse_weights(payload: &[u8]) -> Result<Vector<u8>> {
    let (table, header_bytes) = parse_table(payload, 6, MAX_BITS as u16)?;
    let stream = payload
        .get(header_bytes..)
        .ok_or(Error::InvalidHuffmanTree)?;
    let mut bits = ReverseBits::new(stream)?;
    let mut first = FseState::new(&table, &mut bits)?;
    let mut second = FseState::new(&table, &mut bits)?;
    let mut output = Vector::with_capacity(32).map_err(|_| Error::Allocation)?;
    loop {
        if output.len() >= 255 {
            return Err(Error::InvalidHuffmanTree);
        }
        output.push(first.symbol(&table) as u8);
        let entry = first.entry(&table);
        if bits.remaining() < entry.bits as usize {
            output.push(second.symbol(&table) as u8);
            break;
        }
        first.advance(&table, &mut bits)?;
        if output.len() >= 255 {
            return Err(Error::InvalidHuffmanTree);
        }
        output.push(second.symbol(&table) as u8);
        let entry = second.entry(&table);
        if bits.remaining() < entry.bits as usize {
            output.push(first.symbol(&table) as u8);
            break;
        }
        second.advance(&table, &mut bits)?;
    }
    Ok(output)
}

pub(crate) fn decode_stream(
    bytes: &[u8],
    table: &Table,
    count: usize,
    output: &mut Vector<u8>,
) -> Result<()> {
    if count == 0 {
        return Ok(());
    }
    let mut bits = ReverseBits::new(bytes)?;
    for _ in 0..count {
        output.push(table.decode_symbol(&mut bits)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_direct_tree_from_spec_example() {
        let (table, consumed) = parse_tree(&[132, 0x43, 0x20, 0x10]).unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(table.maximum_bits, 4);
    }

    #[test]
    fn canonical_encoder_serializes_direct_weights_and_round_trips() {
        let input = b"abracadabra abracadabra";
        let mut frequencies = [0u32; 256];
        for symbol in input {
            frequencies[*symbol as usize] += 1;
        }
        let encoder = EncoderTable::from_frequencies(&frequencies).unwrap();
        let description = encoder.serialize_direct_tree().unwrap();
        let (decoder, consumed) = parse_tree(&description).unwrap();
        assert_eq!(consumed, description.len());
        assert_eq!(decoder.maximum_bits, encoder.table.maximum_bits);
        let encoded = encoder.encode_stream(input).unwrap();
        let mut decoded = Vector::new();
        decode_stream(&encoded, &decoder, input.len(), &mut decoded).unwrap();
        assert_eq!(&decoded[..], input);
    }

    #[test]
    fn canonical_encoder_obeys_code_and_direct_alphabet_limits() {
        let mut frequencies = [0u32; 256];
        frequencies[..129].fill(1);
        let encoder = EncoderTable::from_frequencies(&frequencies).unwrap();
        assert!(encoder.table.maximum_bits <= MAX_BITS);
        assert_eq!(encoder.serialize_direct_tree().unwrap()[0], 255);

        frequencies[129] = 1;
        assert!(matches!(
            EncoderTable::from_frequencies(&frequencies),
            Err(Error::InvalidHuffmanTree)
        ));
    }

    #[test]
    fn canonical_encoder_rejects_absent_symbols() {
        let frequencies = [1, 1];
        let encoder = EncoderTable::from_frequencies(&frequencies).unwrap();
        assert_eq!(
            encoder.encode_stream(&[2]),
            Err(Error::InvalidHuffmanStream)
        );
    }

    #[test]
    fn canonical_encoder_fse_compresses_weights_and_round_trips_tree() {
        let mut frequencies = [0u32; 256];
        for symbol in 0..=96 {
            frequencies[symbol] = (97 - symbol) as u32;
        }
        let encoder = EncoderTable::from_frequencies(&frequencies).unwrap();
        assert_eq!(encoder.explicit_weights.len(), 96);
        let compressed = encoder.serialize_fse_tree().unwrap();
        assert!(compressed[0] < 128);
        let (decoded, consumed) = parse_tree(&compressed).unwrap();
        assert_eq!(consumed, compressed.len());
        assert_eq!(decoded.maximum_bits, encoder.table.maximum_bits);
        assert_eq!(decoded.lookup.len(), encoder.table.lookup.len());
        let mut input = Vector::new();
        for symbol in 0..=96 {
            input.push(symbol as u8);
        }
        let stream = encoder.encode_stream(&input).unwrap();
        let mut round_trip = Vector::new();
        decode_stream(&stream, &decoded, input.len(), &mut round_trip).unwrap();
        assert_eq!(round_trip, input);
    }

    #[test]
    fn canonical_encoder_selects_only_strictly_smaller_fse_tree() {
        let mut frequencies = [0u32; 256];
        for symbol in 0..=96 {
            frequencies[symbol] = (symbol % 7 + 1) as u32;
        }
        let encoder = EncoderTable::from_frequencies(&frequencies).unwrap();
        let direct = encoder.serialize_direct_tree().unwrap();
        let compressed = encoder.serialize_fse_tree().unwrap();
        let selected = encoder.serialize_tree().unwrap();
        assert_eq!(selected.len(), direct.len().min(compressed.len()));
        assert_eq!(selected[0] < 128, compressed.len() < direct.len());
        parse_tree(&selected).unwrap();
    }
}
