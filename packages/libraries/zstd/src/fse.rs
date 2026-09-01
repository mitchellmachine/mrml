use crate::bits::{ForwardBitWriter, ForwardBits, ReverseBits};
use crate::{Error, Result};
use mrml_runtime::Vector;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Entry {
    pub(crate) symbol: u16,
    pub(crate) bits: u8,
    pub(crate) baseline: u16,
}

#[derive(Clone, Debug)]
pub(crate) struct Table {
    pub(crate) accuracy: u8,
    pub(crate) entries: Vector<Entry>,
}

impl Table {
    pub(crate) fn from_probabilities(probabilities: &[i16], accuracy: u8) -> Result<Self> {
        if !(5..=9).contains(&accuracy) {
            return Err(Error::InvalidFseTable);
        }
        let size = 1usize << accuracy;
        let mut symbols = Vector::with_capacity(size).map_err(|_| Error::Allocation)?;
        symbols.resize(size, u16::MAX);
        let mut high = size;
        for (symbol, probability) in probabilities.iter().enumerate() {
            if *probability == -1 {
                high = high.checked_sub(1).ok_or(Error::InvalidFseTable)?;
                symbols[high] = symbol as u16;
            }
        }
        let step = (size >> 1) + (size >> 3) + 3;
        let mut position = 0usize;
        for (symbol, probability) in probabilities.iter().enumerate() {
            if *probability <= 0 {
                continue;
            }
            for _ in 0..*probability as usize {
                while symbols[position] != u16::MAX {
                    position = (position + step) & (size - 1);
                }
                symbols[position] = symbol as u16;
                position = (position + step) & (size - 1);
            }
        }
        if symbols.iter().any(|symbol| *symbol == u16::MAX) {
            return Err(Error::InvalidFseTable);
        }
        let mut next = Vector::with_capacity(probabilities.len()).map_err(|_| Error::Allocation)?;
        next.resize(probabilities.len(), 0u32);
        for (symbol, probability) in probabilities.iter().enumerate() {
            next[symbol] = if *probability == -1 {
                1
            } else {
                (*probability).max(0) as u32
            };
        }
        let mut entries = Vector::with_capacity(size).map_err(|_| Error::Allocation)?;
        entries.resize(size, Entry::default());
        for state in 0..size {
            let symbol = symbols[state] as usize;
            if probabilities[symbol] == -1 {
                entries[state] = Entry {
                    symbol: symbol as u16,
                    bits: accuracy,
                    baseline: 0,
                };
                continue;
            }
            let value = next[symbol];
            next[symbol] += 1;
            if value == 0 {
                return Err(Error::InvalidFseTable);
            }
            let bits = accuracy - (31 - value.leading_zeros()) as u8;
            let baseline = (value << bits) as i32 - size as i32;
            if !(0..size as i32).contains(&baseline) {
                return Err(Error::InvalidFseTable);
            }
            entries[state] = Entry {
                symbol: symbol as u16,
                bits,
                baseline: baseline as u16,
            };
        }
        Ok(Self { accuracy, entries })
    }
}

/// A deterministic inverse walk through an FSE decoding table.
///
/// `states[0]` is the state serialized at the head of the reverse bitstream.
/// Each following state is reached by serializing the corresponding transition
/// returned by [`CompressionPath::transition`].
#[derive(Clone, Debug)]
#[allow(dead_code)] // Consumed by the staged sequence encoder after code selection lands.
pub(crate) struct CompressionPath {
    states: Vector<u16>,
}

#[allow(dead_code)]
impl CompressionPath {
    pub(crate) fn for_symbols(table: &Table, symbols: &[u16]) -> Result<Self> {
        let size = table.entries.len();
        if symbols.is_empty() || size != 1usize << table.accuracy {
            return Err(Error::InvalidFseState);
        }
        let maximum_symbol = table
            .entries
            .iter()
            .map(|entry| entry.symbol as usize)
            .max()
            .ok_or(Error::InvalidFseState)?;
        let inverse_len = (maximum_symbol + 1)
            .checked_mul(size)
            .ok_or(Error::Allocation)?;
        let mut inverse = Vector::with_capacity(inverse_len).map_err(|_| Error::Allocation)?;
        inverse.resize(inverse_len, u16::MAX);

        for (state, entry) in table.entries.iter().enumerate() {
            let width = 1usize << entry.bits;
            let end = (entry.baseline as usize)
                .checked_add(width)
                .ok_or(Error::InvalidFseTable)?;
            if end > size {
                return Err(Error::InvalidFseTable);
            }
            let row = entry.symbol as usize * size;
            for next in entry.baseline as usize..end {
                let slot = row + next;
                if inverse[slot] != u16::MAX {
                    return Err(Error::InvalidFseTable);
                }
                inverse[slot] = state as u16;
            }
        }

        let mut states = Vector::with_capacity(symbols.len()).map_err(|_| Error::Allocation)?;
        states.resize(symbols.len(), 0);
        let last_symbol = *symbols.last().ok_or(Error::InvalidFseState)? as usize;
        states[symbols.len() - 1] = table
            .entries
            .iter()
            .position(|entry| entry.symbol as usize == last_symbol)
            .ok_or(Error::InvalidFseState)? as u16;
        for index in (0..symbols.len() - 1).rev() {
            let symbol = symbols[index] as usize;
            if symbol > maximum_symbol {
                return Err(Error::InvalidFseState);
            }
            let state = inverse[symbol * size + states[index + 1] as usize];
            if state == u16::MAX {
                return Err(Error::InvalidFseState);
            }
            states[index] = state;
        }
        Ok(Self { states })
    }

    pub(crate) fn initial(&self) -> u16 {
        self.states[0]
    }

    pub(crate) fn transition(&self, table: &Table, index: usize) -> Result<(u32, u8)> {
        let current = *self.states.get(index).ok_or(Error::InvalidFseState)? as usize;
        let next = *self.states.get(index + 1).ok_or(Error::InvalidFseState)? as u32;
        let entry = *table.entries.get(current).ok_or(Error::InvalidFseState)?;
        let value = next
            .checked_sub(entry.baseline as u32)
            .ok_or(Error::InvalidFseState)?;
        if value >= 1u32 << entry.bits {
            return Err(Error::InvalidFseState);
        }
        Ok((value, entry.bits))
    }
}

pub(crate) fn parse_table(
    bytes: &[u8],
    maximum_accuracy: u8,
    maximum_symbol: u16,
) -> Result<(Table, usize)> {
    let mut bits = ForwardBits::new(bytes);
    let accuracy = bits.read(4)? as u8 + 5;
    if accuracy > maximum_accuracy {
        return Err(Error::InvalidFseTable);
    }
    let mut remaining = (1i32 << accuracy) + 1;
    let mut probabilities =
        Vector::with_capacity(maximum_symbol as usize + 1).map_err(|_| Error::Allocation)?;
    let mut symbol = 0usize;
    let mut repeat_zero = false;
    while remaining > 1 {
        if symbol > maximum_symbol as usize {
            return Err(Error::InvalidFseTable);
        }
        if repeat_zero {
            let mut zeros = 0usize;
            loop {
                let count = bits.read(2)? as usize;
                zeros += count;
                if count != 3 {
                    break;
                }
            }
            for _ in 0..zeros {
                if symbol > maximum_symbol as usize {
                    return Err(Error::InvalidFseTable);
                }
                probabilities.push(0);
                symbol += 1;
            }
            repeat_zero = false;
            continue;
        }
        let rem = remaining as u32;
        let width = (32 - rem.leading_zeros()) as u8;
        let threshold = (1u32 << width) - 1 - rem;
        let peek = bits.peek(width)?;
        let low = peek & ((1u32 << (width - 1)) - 1);
        let (value, consumed) = if low < threshold {
            (low, width - 1)
        } else {
            (
                if peek >= 1u32 << (width - 1) {
                    peek - threshold
                } else {
                    peek
                },
                width,
            )
        };
        bits.consume(consumed)?;
        let probability = value as i16 - 1;
        probabilities.push(probability);
        symbol += 1;
        repeat_zero = probability == 0;
        if probability != 0 {
            remaining -= if probability < 0 {
                1
            } else {
                probability as i32
            };
            if remaining < 1 {
                return Err(Error::InvalidFseTable);
            }
        }
    }
    let table = Table::from_probabilities(&probabilities, accuracy)?;
    Ok((table, bits.consumed_bytes()))
}

#[allow(dead_code)] // Wired into compressed sequence mode after CTable encoding lands.
pub(crate) fn serialize_probabilities(probabilities: &[i16], accuracy: u8) -> Result<Vector<u8>> {
    if !(5..=9).contains(&accuracy) || probabilities.is_empty() {
        return Err(Error::InvalidFseTable);
    }
    let mut remaining = (1i32 << accuracy) + 1;
    let mut writer = ForwardBitWriter::new(probabilities.len().saturating_mul(16).max(32));
    writer.write((accuracy - 5) as u32, 4)?;
    let mut symbol = 0usize;
    while remaining > 1 {
        let probability = *probabilities.get(symbol).ok_or(Error::InvalidFseTable)?;
        if probability < -1 {
            return Err(Error::InvalidFseTable);
        }
        let value = (probability as i32 + 1) as u32;
        let rem = remaining as u32;
        let width = (32 - rem.leading_zeros()) as u8;
        let threshold = (1u32 << width) - 1 - rem;
        if value < threshold {
            writer.write(value, width - 1)?;
        } else {
            writer.write(
                value.checked_add(threshold).ok_or(Error::InvalidFseTable)?,
                width,
            )?;
        }
        symbol += 1;
        if probability == 0 {
            let mut additional = 0usize;
            while probabilities.get(symbol + additional) == Some(&0) {
                additional += 1;
            }
            while additional >= 3 {
                writer.write(3, 2)?;
                additional -= 3;
                symbol += 3;
            }
            writer.write(additional as u32, 2)?;
            symbol += additional;
        } else {
            remaining -= if probability == -1 {
                1
            } else {
                probability as i32
            };
            if remaining < 1 {
                return Err(Error::InvalidFseTable);
            }
        }
    }
    let table = Table::from_probabilities(&probabilities[..symbol], accuracy)?;
    if table.entries.len() != 1usize << accuracy {
        return Err(Error::InvalidFseTable);
    }
    Ok(writer.finish())
}

#[cfg(test)]
mod encode_tests {
    use super::*;
    use crate::bits::{ReverseBitWriter, ReverseBits};

    #[test]
    fn normalized_counts_serialize_and_parse_exactly() {
        for probabilities in [
            &[18, 9, 5][..],
            &[16, 0, 0, 0, 0, 8, 4, 4][..],
            &[15, -1, 8, 4, 4][..],
        ] {
            let bytes = serialize_probabilities(probabilities, 5).unwrap();
            let (table, used) = parse_table(&bytes, 9, 255).unwrap();
            assert_eq!(used, bytes.len());
            assert_eq!(table.entries.len(), 32);
            let expected = Table::from_probabilities(probabilities, 5).unwrap();
            assert_eq!(table.entries, expected.entries);
        }
    }

    #[test]
    fn normalized_counts_reject_invalid_totals_and_bounds() {
        assert_eq!(
            serialize_probabilities(&[31], 4),
            Err(Error::InvalidFseTable)
        );
        assert_eq!(
            serialize_probabilities(&[31], 5),
            Err(Error::InvalidFseTable)
        );
        assert_eq!(
            serialize_probabilities(&[-2, 34], 5),
            Err(Error::InvalidFseTable)
        );
    }

    #[test]
    fn compression_path_round_trips_through_decoder_state_machine() {
        let table = Table::from_probabilities(&[18, 9, 5], 5).unwrap();
        let symbols = [0, 1, 0, 2, 1, 0, 0, 2];
        let path = CompressionPath::for_symbols(&table, &symbols).unwrap();
        let mut writer = ReverseBitWriter::new(128);
        writer.write(path.initial() as u32, table.accuracy).unwrap();
        for index in 0..symbols.len() - 1 {
            let (value, bits) = path.transition(&table, index).unwrap();
            writer.write(value, bits).unwrap();
        }
        let bytes = writer.finish().unwrap();
        let mut bits = ReverseBits::new(&bytes).unwrap();
        let mut state = State::new(&table, &mut bits).unwrap();
        for (index, expected) in symbols.iter().enumerate() {
            assert_eq!(state.symbol(&table), *expected);
            if index + 1 != symbols.len() {
                state.advance(&table, &mut bits).unwrap();
            }
        }
        assert_eq!(bits.remaining(), 0);
    }

    #[test]
    fn compression_path_rejects_empty_and_absent_symbols() {
        let table = Table::from_probabilities(&[24, 8], 5).unwrap();
        assert!(matches!(
            CompressionPath::for_symbols(&table, &[]),
            Err(Error::InvalidFseState)
        ));
        assert!(matches!(
            CompressionPath::for_symbols(&table, &[2]),
            Err(Error::InvalidFseState)
        ));
    }
}

pub(crate) struct State {
    value: u16,
}

impl State {
    pub(crate) const fn from_value(value: u16) -> Self {
        Self { value }
    }
    pub(crate) fn new(table: &Table, bits: &mut ReverseBits<'_>) -> Result<Self> {
        let value = bits.read(table.accuracy)? as u16;
        if value as usize >= table.entries.len() {
            return Err(Error::InvalidFseState);
        }
        Ok(Self { value })
    }
    pub(crate) fn symbol(&self, table: &Table) -> u16 {
        table.entries[self.value as usize].symbol
    }
    pub(crate) fn entry(&self, table: &Table) -> Entry {
        table.entries[self.value as usize]
    }
    pub(crate) fn advance(&mut self, table: &Table, bits: &mut ReverseBits<'_>) -> Result<()> {
        let entry = table.entries[self.value as usize];
        let value = entry.baseline as u32 + bits.read(entry.bits)?;
        if value as usize >= table.entries.len() {
            return Err(Error::InvalidFseState);
        }
        self.value = value as u16;
        Ok(())
    }
}
