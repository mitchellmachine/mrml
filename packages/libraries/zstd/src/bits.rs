use crate::{Error, Result};
use mrml_runtime::Vector;

#[allow(dead_code)] // Consumed by normalized-count and entropy encoders as they are staged.
pub(crate) struct ForwardBitWriter {
    bytes: Vector<u8>,
    position: usize,
    maximum_bits: usize,
}

#[allow(dead_code)]
impl ForwardBitWriter {
    pub(crate) fn new(maximum_bits: usize) -> Self {
        Self {
            bytes: Vector::new(),
            position: 0,
            maximum_bits,
        }
    }

    pub(crate) fn write(&mut self, value: u32, count: u8) -> Result<()> {
        if count > 24
            || self
                .position
                .checked_add(count as usize)
                .is_none_or(|end| end > self.maximum_bits)
        {
            return Err(Error::BlockTooLarge);
        }
        let end = self.position + count as usize;
        self.bytes
            .try_resize(end.div_ceil(8), 0)
            .map_err(|_| Error::Allocation)?;
        for bit in 0..count as usize {
            if value & (1 << bit) != 0 {
                let target = self.position + bit;
                self.bytes[target / 8] |= 1 << (target & 7);
            }
        }
        self.position = end;
        Ok(())
    }

    pub(crate) fn finish(self) -> Vector<u8> {
        self.bytes
    }
}

#[allow(dead_code)] // Consumed by the staged FSE/Huffman encoder in the next gate.
pub(crate) struct ReverseBitWriter {
    read_order: Vector<u8>,
    maximum_bits: usize,
}

#[allow(dead_code)]
impl ReverseBitWriter {
    pub(crate) fn new(maximum_bits: usize) -> Self {
        Self {
            read_order: Vector::new(),
            maximum_bits,
        }
    }

    pub(crate) fn write(&mut self, value: u32, count: u8) -> Result<()> {
        if count > 24
            || self
                .read_order
                .len()
                .checked_add(count as usize)
                .is_none_or(|end| end > self.maximum_bits)
        {
            return Err(Error::BlockTooLarge);
        }
        for shift in (0..count).rev() {
            self.read_order
                .try_push(((value >> shift) & 1) as u8)
                .map_err(|_| Error::Allocation)?;
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<Vector<u8>> {
        let payload_bits = self.read_order.len();
        let mut bytes = Vector::new();
        bytes
            .try_resize((payload_bits + 1).div_ceil(8), 0)
            .map_err(|_| Error::Allocation)?;
        for (index, bit) in self.read_order.into_iter().enumerate() {
            if bit != 0 {
                let target = payload_bits - 1 - index;
                bytes[target / 8] |= 1 << (target & 7);
            }
        }
        bytes[payload_bits / 8] |= 1 << (payload_bits & 7);
        Ok(bytes)
    }
}

pub(crate) struct ForwardBits<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> ForwardBits<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    pub(crate) fn consumed_bytes(&self) -> usize {
        self.position.div_ceil(8)
    }
    pub(crate) fn peek(&self, count: u8) -> Result<u32> {
        if count > 24 || self.position + count as usize > self.bytes.len() * 8 {
            return Err(Error::Truncated);
        }
        let mut value = 0u32;
        for bit in 0..count as usize {
            let source = self.position + bit;
            value |= (((self.bytes[source / 8] >> (source & 7)) & 1) as u32) << bit;
        }
        Ok(value)
    }
    pub(crate) fn read(&mut self, count: u8) -> Result<u32> {
        let value = self.peek(count)?;
        self.position += count as usize;
        Ok(value)
    }
    pub(crate) fn consume(&mut self, count: u8) -> Result<()> {
        if self.position + count as usize > self.bytes.len() * 8 {
            return Err(Error::Truncated);
        }
        self.position += count as usize;
        Ok(())
    }
}

pub(crate) struct ReverseBits<'a> {
    bytes: &'a [u8],
    remaining: usize,
}

impl<'a> ReverseBits<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Result<Self> {
        let last = *bytes.last().ok_or(Error::Truncated)?;
        if last == 0 {
            return Err(Error::InvalidBitstream);
        }
        let marker = 7usize - last.leading_zeros() as usize;
        Ok(Self {
            bytes,
            remaining: (bytes.len() - 1) * 8 + marker,
        })
    }
    pub(crate) fn remaining(&self) -> usize {
        self.remaining
    }
    pub(crate) fn peek_padded(&self, count: u8) -> u32 {
        let available = core::cmp::min(count as usize, self.remaining);
        let mut value = 0u32;
        for bit in 0..available {
            let source = self.remaining - 1 - bit;
            value = (value << 1) | ((self.bytes[source / 8] >> (source & 7)) & 1) as u32;
        }
        value << (count as usize - available)
    }
    pub(crate) fn consume(&mut self, count: u8) -> Result<()> {
        if count as usize > self.remaining {
            return Err(Error::Truncated);
        }
        self.remaining -= count as usize;
        Ok(())
    }
    pub(crate) fn read(&mut self, count: u8) -> Result<u32> {
        let count = count as usize;
        if count > 24 || count > self.remaining {
            return Err(Error::Truncated);
        }
        let value = self.peek_padded(count as u8);
        self.remaining -= count;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_reader_skips_end_marker() {
        let mut bits = ReverseBits::new(&[0xab, 0x01]).unwrap();
        assert_eq!(bits.remaining(), 8);
        assert_eq!(bits.read(4).unwrap(), 0x0a);
        assert_eq!(bits.read(4).unwrap(), 0x0b);
    }

    #[test]
    fn forward_reader_is_little_endian() {
        let mut bits = ForwardBits::new(&[0b1011_0100, 0b10]);
        assert_eq!(bits.read(4).unwrap(), 4);
        assert_eq!(bits.read(6).unwrap(), 0b10_1011);
    }

    #[test]
    fn forward_writer_round_trips_and_enforces_budget() {
        let mut writer = ForwardBitWriter::new(10);
        writer.write(4, 4).unwrap();
        writer.write(0b10_1011, 6).unwrap();
        assert_eq!(&writer.finish()[..], &[0b1011_0100, 0b10]);
        let mut bounded = ForwardBitWriter::new(3);
        assert_eq!(bounded.write(0, 4), Err(Error::BlockTooLarge));
    }

    #[test]
    fn reverse_writer_round_trips_mixed_width_values() {
        let mut writer = ReverseBitWriter::new(24);
        writer.write(0x0a, 4).unwrap();
        writer.write(0x0b, 4).unwrap();
        writer.write(0x12, 5).unwrap();
        let bytes = writer.finish().unwrap();
        let mut reader = ReverseBits::new(&bytes).unwrap();
        assert_eq!(reader.read(4).unwrap(), 0x0a);
        assert_eq!(reader.read(4).unwrap(), 0x0b);
        assert_eq!(reader.read(5).unwrap(), 0x12);
        assert_eq!(reader.remaining(), 0);
    }
}
