//! Bounded packet-line framing shared by Smart Git protocol handlers.

use mrml_runtime::Vector;

use crate::{BoundedRead, BoundedWrite, GitdCoreError, WorkBudget};

/// Git's four-byte hexadecimal length includes the header itself. Although the
/// wire format can spell `ffff`, protocol payloads are limited to 65,516 bytes.
pub const MAX_PKT_LINE_BYTES: usize = 65_520;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PktLine {
    Data(Vector<u8>),
    Flush,
    Delimiter,
    ResponseEnd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolBudget {
    input_remaining: u64,
    output_remaining: u64,
    work_remaining: u64,
}

impl ProtocolBudget {
    pub const fn new(budget: WorkBudget) -> Self {
        Self {
            input_remaining: budget.max_input_bytes,
            output_remaining: budget.max_output_bytes,
            work_remaining: budget.max_work_units,
        }
    }

    pub const fn input_remaining(self) -> u64 {
        self.input_remaining
    }

    pub const fn output_remaining(self) -> u64 {
        self.output_remaining
    }

    pub const fn work_remaining(self) -> u64 {
        self.work_remaining
    }

    fn consume_input(&mut self, amount: usize) -> Result<(), GitdCoreError> {
        self.input_remaining = self
            .input_remaining
            .checked_sub(amount as u64)
            .ok_or(GitdCoreError::Resource)?;
        self.consume_work(amount)
    }

    fn consume_output(&mut self, amount: usize) -> Result<(), GitdCoreError> {
        self.output_remaining = self
            .output_remaining
            .checked_sub(amount as u64)
            .ok_or(GitdCoreError::Resource)?;
        self.consume_work(amount)
    }

    fn consume_work(&mut self, amount: usize) -> Result<(), GitdCoreError> {
        self.work_remaining = self
            .work_remaining
            .checked_sub(amount as u64)
            .ok_or(GitdCoreError::Resource)?;
        Ok(())
    }
}

pub fn read_pkt_line(
    input: &mut dyn BoundedRead,
    budget: &mut ProtocolBudget,
) -> Result<PktLine, GitdCoreError> {
    let mut header = [0u8; 4];
    read_exact(input, &mut header, budget)?;
    let length = parse_hex_header(header)?;
    match length {
        0 => return Ok(PktLine::Flush),
        1 => return Ok(PktLine::Delimiter),
        2 => return Ok(PktLine::ResponseEnd),
        3 => return Err(GitdCoreError::MalformedInput),
        _ => {}
    }
    if !(4..=MAX_PKT_LINE_BYTES).contains(&length) {
        return Err(GitdCoreError::MalformedInput);
    }
    let payload_length = length - 4;
    if payload_length as u64 > input.remaining()
        || payload_length as u64 > budget.input_remaining
        || payload_length as u64 > budget.work_remaining
    {
        return Err(GitdCoreError::Resource);
    }
    let mut payload = Vector::new();
    payload
        .try_reserve_exact(payload_length)
        .map_err(|_| GitdCoreError::Resource)?;
    payload.resize(payload_length, 0);
    read_exact(input, &mut payload, budget)?;
    Ok(PktLine::Data(payload))
}

pub fn write_pkt_line(
    output: &mut dyn BoundedWrite,
    packet: &PktLine,
    budget: &mut ProtocolBudget,
) -> Result<(), GitdCoreError> {
    let control = match packet {
        PktLine::Flush => Some(*b"0000"),
        PktLine::Delimiter => Some(*b"0001"),
        PktLine::ResponseEnd => Some(*b"0002"),
        PktLine::Data(_) => None,
    };
    if let Some(header) = control {
        return write_exact(output, &header, budget);
    }
    let PktLine::Data(payload) = packet else {
        return Err(GitdCoreError::MalformedInput);
    };
    let length = payload
        .len()
        .checked_add(4)
        .ok_or(GitdCoreError::Resource)?;
    if length > MAX_PKT_LINE_BYTES {
        return Err(GitdCoreError::Resource);
    }
    let header = hex_header(length);
    if length as u64 > output.remaining()
        || length as u64 > budget.output_remaining
        || length as u64 > budget.work_remaining
    {
        return Err(GitdCoreError::Resource);
    }
    write_exact(output, &header, budget)?;
    write_exact(output, payload, budget)
}

fn read_exact(
    input: &mut dyn BoundedRead,
    mut output: &mut [u8],
    budget: &mut ProtocolBudget,
) -> Result<(), GitdCoreError> {
    while !output.is_empty() {
        if output.len() as u64 > input.remaining()
            || output.len() as u64 > budget.input_remaining
            || output.len() as u64 > budget.work_remaining
        {
            return Err(GitdCoreError::Resource);
        }
        let count = input.read(output)?;
        if count == 0 || count > output.len() {
            return Err(GitdCoreError::MalformedInput);
        }
        budget.consume_input(count)?;
        output = &mut output[count..];
    }
    Ok(())
}

fn write_exact(
    output: &mut dyn BoundedWrite,
    input: &[u8],
    budget: &mut ProtocolBudget,
) -> Result<(), GitdCoreError> {
    if input.len() as u64 > output.remaining()
        || input.len() as u64 > budget.output_remaining
        || input.len() as u64 > budget.work_remaining
    {
        return Err(GitdCoreError::Resource);
    }
    output.write(input)?;
    budget.consume_output(input.len())
}

fn parse_hex_header(header: [u8; 4]) -> Result<usize, GitdCoreError> {
    let mut value = 0usize;
    for byte in header {
        value = value
            .checked_mul(16)
            .and_then(|current| hex_value(byte).map(|digit| current + digit))
            .ok_or(GitdCoreError::MalformedInput)?;
    }
    Ok(value)
}

fn hex_value(byte: u8) -> Option<usize> {
    match byte {
        b'0'..=b'9' => Some((byte - b'0') as usize),
        b'a'..=b'f' => Some((byte - b'a' + 10) as usize),
        _ => None,
    }
}

fn hex_header(mut value: usize) -> [u8; 4] {
    let mut output = [b'0'; 4];
    for byte in output.iter_mut().rev() {
        let digit = (value & 15) as u8;
        *byte = if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        };
        value >>= 4;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Reader {
        bytes: Vector<u8>,
        offset: usize,
        chunk: usize,
    }

    impl BoundedRead for Reader {
        fn remaining(&self) -> u64 {
            (self.bytes.len() - self.offset) as u64
        }

        fn read(&mut self, output: &mut [u8]) -> Result<usize, GitdCoreError> {
            let count = output
                .len()
                .min(self.chunk)
                .min(self.bytes.len() - self.offset);
            output[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
            self.offset += count;
            Ok(count)
        }
    }

    struct Writer {
        bytes: Vector<u8>,
        limit: usize,
    }

    impl BoundedWrite for Writer {
        fn remaining(&self) -> u64 {
            (self.limit - self.bytes.len()) as u64
        }

        fn write(&mut self, input: &[u8]) -> Result<(), GitdCoreError> {
            if input.len() > self.limit - self.bytes.len() {
                return Err(GitdCoreError::Resource);
            }
            self.bytes
                .try_extend_from_slice(input)
                .map_err(|_| GitdCoreError::Resource)?;
            Ok(())
        }
    }

    fn budget(bytes: u64) -> ProtocolBudget {
        ProtocolBudget::new(WorkBudget {
            max_input_bytes: bytes,
            max_output_bytes: bytes,
            max_memory_bytes: bytes,
            max_work_units: bytes,
        })
    }

    #[test]
    fn fragmented_data_and_control_packets_round_trip() {
        let mut reader = Reader {
            bytes: Vector::from(*b"0009hello00010002"),
            offset: 0,
            chunk: 2,
        };
        let mut input_budget = budget(18);
        assert_eq!(
            read_pkt_line(&mut reader, &mut input_budget),
            Ok(PktLine::Data(Vector::from(*b"hello")))
        );
        assert_eq!(
            read_pkt_line(&mut reader, &mut input_budget),
            Ok(PktLine::Delimiter)
        );
        assert_eq!(
            read_pkt_line(&mut reader, &mut input_budget),
            Ok(PktLine::ResponseEnd)
        );

        let mut writer = Writer {
            bytes: Vector::new(),
            limit: 18,
        };
        let mut output_budget = budget(18);
        write_pkt_line(
            &mut writer,
            &PktLine::Data(Vector::from(*b"hello")),
            &mut output_budget,
        )
        .unwrap();
        write_pkt_line(&mut writer, &PktLine::Delimiter, &mut output_budget).unwrap();
        write_pkt_line(&mut writer, &PktLine::ResponseEnd, &mut output_budget).unwrap();
        assert_eq!(&writer.bytes[..], b"0009hello00010002");
    }

    #[test]
    fn malformed_lengths_and_uppercase_hex_fail_closed() {
        for bytes in [b"0003".as_slice(), b"000g", b"000A"] {
            let mut reader = Reader {
                bytes: bytes.iter().copied().collect(),
                offset: 0,
                chunk: 4,
            };
            assert_eq!(
                read_pkt_line(&mut reader, &mut budget(16)),
                Err(GitdCoreError::MalformedInput)
            );
        }
    }

    #[test]
    fn truncated_and_budget_exhausted_inputs_do_not_allocate_payload() {
        let mut truncated = Reader {
            bytes: Vector::from(*b"0008ab"),
            offset: 0,
            chunk: 6,
        };
        assert_eq!(
            read_pkt_line(&mut truncated, &mut budget(32)),
            Err(GitdCoreError::Resource)
        );

        let mut bounded = Reader {
            bytes: Vector::from(*b"0008data"),
            offset: 0,
            chunk: 8,
        };
        assert_eq!(
            read_pkt_line(&mut bounded, &mut budget(7)),
            Err(GitdCoreError::Resource)
        );
    }
}
