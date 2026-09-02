use core::fmt;
use mrml_http::{HttpError, ResponseBodySink};
use mrml_runtime::{File, Vector};

const MAX_PACKET_PAYLOAD: usize = 65_516;

pub trait PackOutput {
    fn write(&mut self, bytes: &[u8]) -> Result<(), HttpsPackError>;
    fn finish(&mut self) -> Result<(), HttpsPackError>;
}

pub struct FilePackOutput {
    file: File,
    bytes: u64,
    maximum: u64,
}

impl FilePackOutput {
    pub fn create_new(path: &str, maximum: u64) -> Result<Self, HttpsPackError> {
        if maximum == 0 || maximum > 1024 * 1024 * 1024 {
            return Err(HttpsPackError::TooLarge);
        }
        Ok(Self {
            file: File::create_new(path).map_err(|_| HttpsPackError::Storage)?,
            bytes: 0,
            maximum,
        })
    }

    pub const fn bytes_written(&self) -> u64 {
        self.bytes
    }
}

impl PackOutput for FilePackOutput {
    fn write(&mut self, bytes: &[u8]) -> Result<(), HttpsPackError> {
        let next = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|value| *value <= self.maximum)
            .ok_or(HttpsPackError::TooLarge)?;
        self.file
            .write_all(bytes)
            .map_err(|_| HttpsPackError::Storage)?;
        self.bytes = next;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), HttpsPackError> {
        self.file.sync().map_err(|_| HttpsPackError::Storage)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Packfile,
    Sideband,
    Done,
    Failed,
}

pub struct V2PackResponseDecoder<O> {
    output: O,
    phase: Phase,
    header: [u8; 4],
    header_used: usize,
    payload: Vector<u8>,
    expected_payload: usize,
    pack_bytes: u64,
}

impl<O: PackOutput> V2PackResponseDecoder<O> {
    pub fn new(output: O) -> Self {
        Self {
            output,
            phase: Phase::Packfile,
            header: [0; 4],
            header_used: 0,
            payload: Vector::new(),
            expected_payload: 0,
            pack_bytes: 0,
        }
    }

    pub fn finish(mut self) -> Result<(O, u64), HttpsPackError> {
        if self.phase != Phase::Done
            || self.header_used != 0
            || self.expected_payload != 0
            || !self.payload.is_empty()
            || self.pack_bytes == 0
        {
            return Err(HttpsPackError::Truncated);
        }
        self.output.finish()?;
        Ok((self.output, self.pack_bytes))
    }

    fn accept(&mut self, mut input: &[u8]) -> Result<(), HttpsPackError> {
        if matches!(self.phase, Phase::Done | Phase::Failed) && !input.is_empty() {
            self.phase = Phase::Failed;
            return Err(HttpsPackError::TrailingData);
        }
        while !input.is_empty() {
            if self.header_used < self.header.len() {
                let copied = (self.header.len() - self.header_used).min(input.len());
                self.header[self.header_used..self.header_used + copied]
                    .copy_from_slice(&input[..copied]);
                self.header_used += copied;
                input = &input[copied..];
                if self.header_used != self.header.len() {
                    continue;
                }
                let length = parse_header(self.header)?;
                if length == 0 {
                    self.header_used = 0;
                    if self.phase != Phase::Sideband {
                        self.phase = Phase::Failed;
                        return Err(HttpsPackError::Protocol);
                    }
                    self.phase = Phase::Done;
                    if !input.is_empty() {
                        self.phase = Phase::Failed;
                        return Err(HttpsPackError::TrailingData);
                    }
                    continue;
                }
                if length < 4 {
                    self.phase = Phase::Failed;
                    return Err(HttpsPackError::Protocol);
                }
                self.expected_payload = length - 4;
                if self.expected_payload > MAX_PACKET_PAYLOAD {
                    self.phase = Phase::Failed;
                    return Err(HttpsPackError::TooLarge);
                }
                self.payload
                    .try_reserve_exact(self.expected_payload)
                    .map_err(|_| HttpsPackError::TooLarge)?;
            }
            let copied = (self.expected_payload - self.payload.len()).min(input.len());
            self.payload
                .try_extend_from_slice(&input[..copied])
                .map_err(|_| HttpsPackError::TooLarge)?;
            input = &input[copied..];
            if self.payload.len() == self.expected_payload {
                self.process_packet()?;
                self.payload.clear();
                self.expected_payload = 0;
                self.header_used = 0;
            }
        }
        Ok(())
    }

    fn process_packet(&mut self) -> Result<(), HttpsPackError> {
        let result = match self.phase {
            Phase::Packfile if &self.payload[..] == b"packfile\n" => {
                self.phase = Phase::Sideband;
                Ok(())
            }
            Phase::Sideband => {
                let (&band, bytes) = self.payload.split_first().ok_or(HttpsPackError::Protocol)?;
                match band {
                    1 => {
                        self.output.write(bytes)?;
                        self.pack_bytes = self
                            .pack_bytes
                            .checked_add(bytes.len() as u64)
                            .ok_or(HttpsPackError::TooLarge)?;
                        Ok(())
                    }
                    2 => Ok(()),
                    3 => Err(HttpsPackError::Remote),
                    _ => Err(HttpsPackError::Protocol),
                }
            }
            _ => Err(HttpsPackError::Protocol),
        };
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }
}

impl<O: PackOutput> ResponseBodySink for V2PackResponseDecoder<O> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), HttpError> {
        self.accept(bytes).map_err(|error| match error {
            HttpsPackError::TooLarge => HttpError::BodyTooLarge,
            _ => HttpError::InvalidResponse,
        })
    }
}

fn parse_header(header: [u8; 4]) -> Result<usize, HttpsPackError> {
    let mut value = 0usize;
    for byte in header {
        value = value
            .checked_mul(16)
            .and_then(|current| match byte {
                b'0'..=b'9' => current.checked_add((byte - b'0') as usize),
                b'a'..=b'f' => current.checked_add((byte - b'a' + 10) as usize),
                _ => None,
            })
            .ok_or(HttpsPackError::Protocol)?;
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpsPackError {
    Protocol,
    Remote,
    TooLarge,
    Truncated,
    TrailingData,
    Storage,
}

impl fmt::Display for HttpsPackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Protocol => "invalid protocol-v2 packfile response",
            Self::Remote => "remote upload-pack failed",
            Self::TooLarge => "packfile response exceeds its bound",
            Self::Truncated => "packfile response is truncated",
            Self::TrailingData => "packfile response has trailing data",
            Self::Storage => "pack quarantine storage failed",
        })
    }
}

impl core::error::Error for HttpsPackError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct CountingOutput {
        bytes: u64,
        finished: bool,
    }
    impl PackOutput for CountingOutput {
        fn write(&mut self, bytes: &[u8]) -> Result<(), HttpsPackError> {
            self.bytes += bytes.len() as u64;
            Ok(())
        }
        fn finish(&mut self) -> Result<(), HttpsPackError> {
            self.finished = true;
            Ok(())
        }
    }

    fn packet(payload: &[u8], output: &mut Vector<u8>) {
        crate::encode_packet(payload, output).unwrap();
    }

    #[test]
    fn fragmented_sideband_streams_only_pack_band() {
        let mut wire = Vector::new();
        packet(b"packfile\n", &mut wire);
        packet(b"\x02bounded progress", &mut wire);
        packet(b"\x01PACKpayload", &mut wire);
        crate::encode_flush(&mut wire);
        let mut decoder = V2PackResponseDecoder::new(CountingOutput::default());
        for byte in wire {
            ResponseBodySink::write(&mut decoder, &[byte]).unwrap();
            assert!(decoder.payload.len() <= MAX_PACKET_PAYLOAD);
        }
        let (output, bytes) = decoder.finish().unwrap();
        assert_eq!(bytes, 11);
        assert_eq!(output.bytes, 11);
        assert!(output.finished);
    }

    #[test]
    fn malformed_band_truncation_trailing_and_uppercase_length_fail_closed() {
        for wire in [
            Vector::from(*b"000dpackfile\n0006\x04x0000"),
            Vector::from(*b"000dpackfile\n0007\x01PA"),
            Vector::from(*b"000dpackfile\n0006\x01x0000x"),
            Vector::from(*b"000Dpackfile\n0000"),
        ] {
            let mut decoder = V2PackResponseDecoder::new(CountingOutput::default());
            let write = ResponseBodySink::write(&mut decoder, &wire);
            assert!(write.is_err() || decoder.finish().is_err());
        }
    }

    #[test]
    fn decoder_memory_is_packet_bounded_across_many_pack_bytes() {
        let payload = [9u8; 60_000];
        let mut band = Vector::new();
        band.push(1);
        band.extend(payload);
        let mut packet_bytes = Vector::new();
        packet(&band, &mut packet_bytes);
        let mut decoder = V2PackResponseDecoder::new(CountingOutput::default());
        let mut preamble = Vector::new();
        packet(b"packfile\n", &mut preamble);
        ResponseBodySink::write(&mut decoder, &preamble).unwrap();
        for _ in 0..512 {
            ResponseBodySink::write(&mut decoder, &packet_bytes).unwrap();
            assert!(decoder.payload.capacity() <= MAX_PACKET_PAYLOAD);
        }
        ResponseBodySink::write(&mut decoder, b"0000").unwrap();
        let (output, bytes) = decoder.finish().unwrap();
        assert_eq!(bytes, 512 * 60_000);
        assert_eq!(output.bytes, bytes);
    }

    #[test]
    fn file_output_is_create_new_bounded_and_synced() {
        let root = mrml_runtime::join_path(
            &mrml_runtime::temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-https-pack-{}", mrml_runtime::process_id()),
        );
        let _ = mrml_runtime::remove_dir_all(&root);
        mrml_runtime::create_dir_all(&root).unwrap();
        let path = mrml_runtime::join_path(&root, "candidate.pack");
        let mut output = FilePackOutput::create_new(&path, 4).unwrap();
        output.write(b"PACK").unwrap();
        assert_eq!(output.write(b"x"), Err(HttpsPackError::TooLarge));
        output.finish().unwrap();
        assert_eq!(&mrml_runtime::read_file(&path).unwrap()[..], b"PACK");
        assert!(FilePackOutput::create_new(&path, 4).is_err());
        mrml_runtime::remove_dir_all(&root).unwrap();
    }
}
