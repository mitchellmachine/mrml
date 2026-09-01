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
