//! Original, allocation-free RFC 6716 Opus packet implementation.
//!
//! Packet framing, DTX, SILK coding, and CELT decoding are implemented through
//! allocation-free clean-room paths. Hybrid packets share the same entropy
//! stream across their SILK and CELT layers.

#![no_std]
#![forbid(unsafe_code)]

use core::fmt;

pub mod bands;
pub mod celt;
pub mod celt_allocation;
pub mod celt_anticollapse;
pub mod celt_energy;
pub mod celt_frame;
pub mod celt_laplace;
pub mod celt_partition;
pub mod celt_synthesis;
pub mod celt_theta;
mod entropy;
pub mod pvq;
pub mod silk;
pub mod silk_codec;
pub mod silk_entropy;
pub mod silk_frame;
pub mod silk_lsf;
pub mod silk_packet;
pub mod silk_pitch;
pub mod silk_stereo;
mod transition;
pub use entropy::{RangeDecoder, RangeEncoder};

pub const MAX_FRAMES: usize = 48;
pub const MAX_FRAME_BYTES: usize = 1275;
pub const MAX_PACKET_DURATION_MS: u16 = 120;
const MAX_SILK_FRAME_SAMPLES_AT_48_KHZ: usize = 2_880;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Silk,
    Hybrid,
    Celt,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bandwidth {
    Narrow,
    Medium,
    Wide,
    SuperWide,
    Full,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    EmptyPacket,
    InvalidPacket,
    InvalidFrameSize,
    BufferTooSmall,
    UnsupportedAudioMode,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyPacket => "empty Opus packet",
            Self::InvalidPacket => "invalid RFC 6716 Opus packet",
            Self::InvalidFrameSize => "invalid Opus frame size",
            Self::BufferTooSmall => "output buffer too small",
            Self::UnsupportedAudioMode => "the requested Opus coding mode is not implemented",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame {
    pub offset: u16,
    pub len: u16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Packet {
    pub config: u8,
    pub stereo: bool,
    pub mode: Mode,
    pub bandwidth: Bandwidth,
    pub frame_duration_us: u32,
    pub frame_count: u8,
    pub frames: [Frame; MAX_FRAMES],
}

impl Packet {
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        let &toc = data.first().ok_or(Error::EmptyPacket)?;
        let config = toc >> 3;
        let stereo = toc & 4 != 0;
        let code = toc & 3;
        let (mode, bandwidth, frame_duration_us) = configuration(config);
        let mut frames = [Frame { offset: 0, len: 0 }; MAX_FRAMES];
        let count;
        match code {
            0 => {
                count = 1;
                set_frame(&mut frames, 0, 1, data.len() - 1)?;
            }
            1 => {
                let payload = data.len() - 1;
                if payload & 1 != 0 {
                    return Err(Error::InvalidPacket);
                }
                count = 2;
                set_frame(&mut frames, 0, 1, payload / 2)?;
                set_frame(&mut frames, 1, 1 + payload / 2, payload / 2)?;
            }
            2 => {
                if data.len() < 2 {
                    return Err(Error::InvalidPacket);
                }
                let (first, used) = frame_length(&data[1..])?;
                let start = 1 + used;
                if first > data.len() - start {
                    return Err(Error::InvalidPacket);
                }
                count = 2;
                set_frame(&mut frames, 0, start, first)?;
                set_frame(&mut frames, 1, start + first, data.len() - start - first)?;
            }
            3 => {
                if data.len() < 2 {
                    return Err(Error::InvalidPacket);
                }
                let control = data[1];
                count = control & 63;
                if count == 0
                    || usize::from(count) > MAX_FRAMES
                    || u32::from(count) * frame_duration_us > 120_000
                {
                    return Err(Error::InvalidPacket);
                }
                let vbr = control & 0x80 != 0;
                let mut pos = 2usize;
                let mut padding = 0usize;
                if control & 0x40 != 0 {
                    loop {
                        let &byte = data.get(pos).ok_or(Error::InvalidPacket)?;
                        pos += 1;
                        padding = padding
                            .checked_add(if byte == 255 { 254 } else { usize::from(byte) })
                            .ok_or(Error::InvalidPacket)?;
                        if byte != 255 {
                            break;
                        }
                    }
                }
                if padding > data.len() - pos {
                    return Err(Error::InvalidPacket);
                }
                let payload_end = data.len() - padding;
                if vbr {
                    let mut lengths = [0usize; MAX_FRAMES];
                    let mut sum = 0usize;
                    for length in lengths.iter_mut().take(usize::from(count) - 1) {
                        let (value, used) =
                            frame_length(data.get(pos..payload_end).ok_or(Error::InvalidPacket)?)?;
                        pos += used;
                        sum = sum.checked_add(value).ok_or(Error::InvalidPacket)?;
                        *length = value;
                    }
                    if sum > payload_end - pos {
                        return Err(Error::InvalidPacket);
                    }
                    lengths[usize::from(count) - 1] = payload_end - pos - sum;
                    for (index, &length) in lengths.iter().take(usize::from(count)).enumerate() {
                        set_frame(&mut frames, index, pos, length)?;
                        pos += length;
                    }
                } else {
                    let bytes = payload_end - pos;
                    if !bytes.is_multiple_of(usize::from(count)) {
                        return Err(Error::InvalidPacket);
                    }
                    let length = bytes / usize::from(count);
                    for index in 0..usize::from(count) {
                        set_frame(&mut frames, index, pos, length)?;
                        pos += length;
                    }
                }
            }
            _ => unreachable!(),
        }
        Ok(Self {
            config,
            stereo,
            mode,
            bandwidth,
            frame_duration_us,
            frame_count: count,
            frames,
        })
    }
}

fn set_frame(
    frames: &mut [Frame; MAX_FRAMES],
    index: usize,
    offset: usize,
    len: usize,
) -> Result<(), Error> {
    if len > MAX_FRAME_BYTES || offset > u16::MAX as usize {
        return Err(Error::InvalidPacket);
    }
    frames[index] = Frame {
        offset: offset as u16,
        len: len as u16,
    };
    Ok(())
}
fn frame_length(data: &[u8]) -> Result<(usize, usize), Error> {
    let &first = data.first().ok_or(Error::InvalidPacket)?;
    if first < 252 {
        Ok((usize::from(first), 1))
    } else {
        let &second = data.get(1).ok_or(Error::InvalidPacket)?;
        Ok((usize::from(second) * 4 + usize::from(first), 2))
    }
}
fn configuration(config: u8) -> (Mode, Bandwidth, u32) {
    match config {
        0..=3 => (
            Mode::Silk,
            Bandwidth::Narrow,
            [10, 20, 40, 60][config as usize] * 1000,
        ),
        4..=7 => (
            Mode::Silk,
            Bandwidth::Medium,
            [10, 20, 40, 60][config as usize - 4] * 1000,
        ),
        8..=11 => (
            Mode::Silk,
            Bandwidth::Wide,
            [10, 20, 40, 60][config as usize - 8] * 1000,
        ),
        12..=13 => (
            Mode::Hybrid,
            Bandwidth::SuperWide,
            [10, 20][config as usize - 12] * 1000,
        ),
        14..=15 => (
            Mode::Hybrid,
            Bandwidth::Full,
            [10, 20][config as usize - 14] * 1000,
        ),
        16..=31 => {
            let band = [
                Bandwidth::Narrow,
                Bandwidth::Wide,
                Bandwidth::SuperWide,
                Bandwidth::Full,
            ][(config as usize - 16) / 4];
            (
                Mode::Celt,
                band,
                [2500, 5000, 10000, 20000][config as usize & 3],
            )
        }
        _ => unreachable!(),
    }
}

fn encoded_frame_length_size(length: usize) -> Result<usize, Error> {
    if length > MAX_FRAME_BYTES {
        Err(Error::InvalidPacket)
    } else if length < 252 {
        Ok(1)
    } else {
        Ok(2)
    }
}

fn write_frame_length(length: usize, output: &mut [u8], position: &mut usize) -> Result<(), Error> {
    let used = encoded_frame_length_size(length)?;
    if output.len().saturating_sub(*position) < used {
        return Err(Error::BufferTooSmall);
    }
    if used == 1 {
        output[*position] = length as u8;
    } else {
        let first = 252 + (length & 3);
        output[*position] = first as u8;
        output[*position + 1] = ((length - first) / 4) as u8;
    }
    *position += used;
    Ok(())
}

/// Packs one to 48 already encoded frames into an RFC 6716 Opus packet.
/// `padding` is the number of trailing padding octets, excluding its header.
pub fn packetize(
    config: u8,
    stereo: bool,
    frames: &[&[u8]],
    padding: usize,
    output: &mut [u8],
) -> Result<usize, Error> {
    if config > 31 || frames.is_empty() || frames.len() > MAX_FRAMES {
        return Err(Error::InvalidPacket);
    }
    let (_, _, duration_us) = configuration(config);
    if duration_us * frames.len() as u32 > 120_000
        || frames.iter().any(|frame| frame.len() > MAX_FRAME_BYTES)
    {
        return Err(Error::InvalidPacket);
    }
    let equal = frames.windows(2).all(|pair| pair[0].len() == pair[1].len());
    let code = match frames.len() {
        1 if padding == 0 => 0,
        2 if padding == 0 && equal => 1,
        2 if padding == 0 => 2,
        _ => 3,
    };
    let vbr = !equal;
    let payload = frames.iter().try_fold(0usize, |sum, frame| {
        sum.checked_add(frame.len()).ok_or(Error::InvalidPacket)
    })?;
    let length_bytes = if code == 2 {
        encoded_frame_length_size(frames[0].len())?
    } else if code == 3 && vbr {
        frames[..frames.len() - 1]
            .iter()
            .try_fold(0usize, |sum, frame| {
                sum.checked_add(encoded_frame_length_size(frame.len())?)
                    .ok_or(Error::InvalidPacket)
            })?
    } else {
        0
    };
    let padding_header = if code == 3 && padding > 0 {
        padding / 254 + 1
    } else {
        0
    };
    let header = 1usize
        .checked_add(usize::from(code == 3))
        .and_then(|value| value.checked_add(length_bytes))
        .and_then(|value| value.checked_add(padding_header))
        .ok_or(Error::InvalidPacket)?;
    let required = header
        .checked_add(payload)
        .and_then(|value| value.checked_add(padding))
        .ok_or(Error::InvalidPacket)?;
    if output.len() < required {
        return Err(Error::BufferTooSmall);
    }
    output[0] = config << 3 | u8::from(stereo) << 2 | code;
    let mut position = 1;
    if code == 2 {
        write_frame_length(frames[0].len(), output, &mut position)?;
    } else if code == 3 {
        output[position] = u8::from(vbr) << 7
            | u8::from(padding > 0) << 6
            | u8::try_from(frames.len()).map_err(|_| Error::InvalidPacket)?;
        position += 1;
        if padding > 0 {
            let mut remaining = padding;
            while remaining >= 254 {
                output[position] = 255;
                position += 1;
                remaining -= 254;
            }
            output[position] = remaining as u8;
            position += 1;
        }
        if vbr {
            for frame in &frames[..frames.len() - 1] {
                write_frame_length(frame.len(), output, &mut position)?;
            }
        }
    }
    for frame in frames {
        let end = position + frame.len();
        output[position..end].copy_from_slice(frame);
        position = end;
    }
    output[position..position + padding].fill(0);
    Ok(required)
}

/// Emits a standards-compliant one-frame Opus DTX packet.
pub fn encode_dtx(config: u8, stereo: bool, output: &mut [u8]) -> Result<usize, Error> {
    if config > 31 || output.is_empty() {
        return Err(if output.is_empty() {
            Error::BufferTooSmall
        } else {
            Error::InvalidPacket
        });
    }
    output[0] = config << 3 | u8::from(stereo) << 2;
    Ok(1)
}

fn payload_bytes_for_bitrate(bitrate: u32) -> Result<usize, Error> {
    let packet_bytes = usize::try_from(bitrate.div_ceil(400)).map_err(|_| Error::InvalidPacket)?;
    packet_bytes
        .checked_sub(1)
        .filter(|payload| (2..=MAX_FRAME_BYTES).contains(payload))
        .ok_or(Error::InvalidPacket)
}

fn hybrid_geometry(
    bandwidth: Bandwidth,
    duration_us: u32,
) -> Result<(u8, u8, u8, usize, usize, bool), Error> {
    let config_base = match bandwidth {
        Bandwidth::SuperWide => 12,
        Bandwidth::Full => 14,
        Bandwidth::Narrow | Bandwidth::Medium | Bandwidth::Wide => {
            return Err(Error::UnsupportedAudioMode);
        }
    };
    match duration_us {
        10_000 => Ok((10, 2, config_base, 160, 480, false)),
        20_000 => Ok((20, 3, config_base + 1, 320, 960, true)),
        _ => Err(Error::InvalidFrameSize),
    }
}

/// Stateful allocation-free PCM encoder.
///
/// Supports 20 ms SILK, CELT, and hybrid analysis for mono or stereo input.
pub struct Encoder {
    channels: u8,
    silk: silk_packet::MonoPayloadEncoder,
    silk_stereo: silk_packet::StereoPayloadEncoder,
    seed: u8,
    celt_energies: celt_energy::LogEnergies,
    celt_seed: u32,
    preemphasis_memory: [f32; 2],
    last_encoded_mode: Option<Mode>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncoderMode {
    Auto,
    Silk,
    Hybrid,
    Celt,
}

impl Encoder {
    pub fn new(channels: u8) -> Result<Self, Error> {
        if !(1..=2).contains(&channels) {
            return Err(Error::InvalidPacket);
        }
        Ok(Self {
            channels,
            silk: silk_packet::MonoPayloadEncoder::new(),
            silk_stereo: silk_packet::StereoPayloadEncoder::new(),
            seed: 0,
            celt_energies: celt_energy::LogEnergies::new(),
            celt_seed: 0,
            preemphasis_memory: [0.0; 2],
            last_encoded_mode: None,
        })
    }

    /// Selects a coding mode from a target aggregate bitrate and encodes one
    /// 20 ms frame. Explicit modes bypass the automatic thresholds.
    pub fn encode_mode(
        &mut self,
        mode: EncoderMode,
        bitrate: u32,
        input: &[i16],
        sample_rate: u32,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        if !(6_000..=510_000).contains(&bitrate) {
            return Err(Error::InvalidPacket);
        }
        if !matches!(sample_rate, 8_000 | 12_000 | 16_000 | 24_000 | 48_000) {
            return Err(Error::InvalidFrameSize);
        }
        let required_samples = sample_rate as usize / 50 * usize::from(self.channels);
        if input.len() != required_samples {
            return Err(Error::InvalidFrameSize);
        }
        let automatic = mode == EncoderMode::Auto;
        let selected = if automatic {
            let per_channel = bitrate / u32::from(self.channels);
            if per_channel < 20_000 {
                EncoderMode::Silk
            } else if per_channel < 64_000 {
                EncoderMode::Hybrid
            } else {
                EncoderMode::Celt
            }
        } else {
            mode
        };
        let result = match selected {
            EncoderMode::Silk => {
                if automatic && self.last_encoded_mode == Some(Mode::Celt) {
                    self.encode_silk_transition_with_bitrate(input, sample_rate, output, bitrate)
                } else {
                    self.encode_silk_with_bitrate(input, sample_rate, output, bitrate)
                }
            }
            EncoderMode::Hybrid => {
                let payload = payload_bytes_for_bitrate(bitrate)?;
                if automatic && self.last_encoded_mode == Some(Mode::Celt) {
                    let redundancy_len = 16usize.min(payload.saturating_sub(16));
                    if redundancy_len >= 2 {
                        let transition_frames = sample_rate as usize / 200;
                        let transition_samples = transition_frames * usize::from(self.channels);
                        let mut transition_input = [0i16; 480];
                        transition_input[..transition_samples]
                            .copy_from_slice(&input[..transition_samples]);
                        let mut redundant_packet = [0u8; 258];
                        let redundant_size = Encoder::new(self.channels)?
                            .encode_celt_with_payload(
                                &transition_input[..transition_samples],
                                sample_rate,
                                &mut redundant_packet,
                                redundancy_len,
                                1,
                                Bandwidth::Full,
                            )?;
                        self.encode_hybrid_with_payload(
                            input,
                            sample_rate,
                            output,
                            payload,
                            Some((
                                &redundant_packet[1..redundant_size],
                                transition::RedundancyPosition::Beginning,
                            )),
                            Bandwidth::Full,
                            20_000,
                        )
                    } else {
                        self.encode_hybrid_with_payload(
                            input,
                            sample_rate,
                            output,
                            payload,
                            None,
                            Bandwidth::Full,
                            20_000,
                        )
                    }
                } else {
                    self.encode_hybrid_with_payload(
                        input,
                        sample_rate,
                        output,
                        payload,
                        None,
                        Bandwidth::Full,
                        20_000,
                    )
                }
            }
            EncoderMode::Celt => {
                let payload = payload_bytes_for_bitrate(bitrate)?;
                self.encode_celt_with_payload(
                    input,
                    sample_rate,
                    output,
                    payload,
                    3,
                    Bandwidth::Full,
                )
            }
            EncoderMode::Auto => Err(Error::InvalidPacket),
        };
        if result.is_ok() {
            self.last_encoded_mode = Some(match selected {
                EncoderMode::Silk => Mode::Silk,
                EncoderMode::Hybrid => Mode::Hybrid,
                EncoderMode::Celt => Mode::Celt,
                EncoderMode::Auto => unreachable!(),
            });
        }
        result
    }

    /// Encodes exactly 20 ms of interleaved PCM as narrowband SILK.
    pub fn encode(
        &mut self,
        input: &[i16],
        sample_rate: u32,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        self.encode_silk_duration(input, sample_rate, 20_000, output)
    }

    /// Encodes one narrowband SILK packet at any RFC 6716 SILK duration.
    pub fn encode_silk_duration(
        &mut self,
        input: &[i16],
        sample_rate: u32,
        duration_us: u32,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        self.encode_silk_bandwidth_duration(
            input,
            sample_rate,
            Bandwidth::Narrow,
            duration_us,
            output,
        )
    }

    /// Encodes one SILK packet at any RFC 6716 SILK bandwidth and duration.
    pub fn encode_silk_bandwidth_duration(
        &mut self,
        input: &[i16],
        sample_rate: u32,
        bandwidth: Bandwidth,
        duration_us: u32,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        self.encode_silk_bandwidth_duration_impl(
            input,
            sample_rate,
            bandwidth,
            duration_us,
            output,
            None,
        )
    }

    /// Encodes a SILK-only packet with a caller-supplied, TOC-less 5 ms CELT
    /// transition frame in the implicit byte-aligned redundancy tail.
    #[allow(clippy::too_many_arguments)]
    pub fn encode_silk_with_redundancy(
        &mut self,
        input: &[i16],
        sample_rate: u32,
        bandwidth: Bandwidth,
        duration_us: u32,
        redundant_celt: &[u8],
        at_beginning: bool,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let position = if at_beginning {
            transition::RedundancyPosition::Beginning
        } else {
            transition::RedundancyPosition::End
        };
        self.encode_silk_bandwidth_duration_impl(
            input,
            sample_rate,
            bandwidth,
            duration_us,
            output,
            Some((redundant_celt, position)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn encode_silk_bandwidth_duration_impl(
        &mut self,
        input: &[i16],
        sample_rate: u32,
        bandwidth: Bandwidth,
        duration_us: u32,
        output: &mut [u8],
        redundancy: Option<(&[u8], transition::RedundancyPosition)>,
    ) -> Result<usize, Error> {
        if !matches!(sample_rate, 8_000 | 12_000 | 16_000 | 24_000 | 48_000) {
            return Err(Error::InvalidFrameSize);
        }
        let (native_rate, config_base, lsf_order) = match bandwidth {
            Bandwidth::Narrow => (8_000usize, 0u8, 10u8),
            Bandwidth::Medium => (12_000, 4, 10),
            Bandwidth::Wide => (16_000, 8, 16),
            Bandwidth::SuperWide | Bandwidth::Full => {
                return Err(Error::UnsupportedAudioMode);
            }
        };
        let (duration_ms, intervals, interval_duration_ms, duration_index) = match duration_us {
            10_000 => (10, 1usize, 10usize, 0u8),
            20_000 => (20, 1, 20, 1),
            40_000 => (40, 2, 20, 2),
            60_000 => (60, 3, 20, 3),
            _ => return Err(Error::InvalidFrameSize),
        };
        let interval_samples = native_rate * interval_duration_ms / 1_000;
        let config = config_base + duration_index;
        let input_frames = sample_rate as usize * duration_us as usize / 1_000_000;
        let required = input_frames
            .checked_mul(usize::from(self.channels))
            .ok_or(Error::InvalidFrameSize)?;
        if input.len() != required {
            return Err(Error::InvalidFrameSize);
        }
        if input.iter().all(|&sample| sample == 0) {
            return encode_dtx(config, self.channels == 2, output);
        }
        if output.len() < 2 {
            return Err(Error::BufferTooSmall);
        }
        if self.channels == 2 {
            return self.encode_silk_stereo_duration(
                input,
                sample_rate,
                duration_ms,
                intervals,
                interval_samples,
                config,
                bandwidth,
                lsf_order,
                interval_duration_ms == 20,
                output,
                redundancy,
            );
        }
        let mut source = [0.0f32; 2880];
        for frame in 0..input_frames {
            let sample = if self.channels == 1 {
                input[frame] as f32
            } else {
                (input[frame * 2] as f32 + input[frame * 2 + 1] as f32) * 0.5
            };
            source[frame] = sample / 32_768.0;
        }
        let narrow_count = intervals * interval_samples;
        let mut narrow = [0.0f32; 960];
        silk::resample_linear(&source[..input_frames], &mut narrow[..narrow_count])?;
        let base_parameters = silk_codec::MonoFrameParameters {
            signal: silk::SignalType::Unvoiced,
            quantization: silk::QuantizationOffset::Low,
            gain_symbols: [20, 4, 4, 4],
            lsf: silk_lsf::LsfIndices {
                stage1: 3,
                stage2: silk_lsf::Stage2 {
                    order: lsf_order,
                    index: [0; 16],
                },
                interpolation_q2: (interval_duration_ms == 20).then_some(4),
            },
            primary_pitch: None,
            contour_index: 0,
            ltp: None,
            seed: self.seed,
            rate_level: 0,
            excitation: [0; silk_entropy::MAX_EXCITATION_SAMPLES],
        };
        let mut parameters = [base_parameters; 3];
        for (interval, parameter) in parameters[..intervals].iter_mut().enumerate() {
            let start = interval * interval_samples;
            for (target, &sample) in parameter.excitation[..interval_samples]
                .iter_mut()
                .zip(&narrow[start..start + interval_samples])
            {
                *target = mrml_math::round(sample * 8.0).clamp(-8.0, 7.0) as i32;
            }
            parameter.seed = (self.seed + interval as u8) & 3;
        }
        let vad_mask = (1u8 << intervals) - 1;
        let header = silk_frame::LayerHeader {
            channels: 1,
            frames: intervals as u8,
            channel: [
                silk_frame::ChannelHeader {
                    vad: vad_mask,
                    lbrr: 0,
                },
                silk_frame::ChannelHeader { vad: 0, lbrr: 0 },
            ],
        };
        output[0] = config << 3;
        let no_fec = [None; 3];
        let payload = if let Some((redundant, position)) = redundancy {
            encode_silk_mono_transition(
                &mut self.silk,
                &mut output[1..],
                bandwidth,
                duration_ms,
                header,
                &parameters[..intervals],
                &no_fec[..intervals],
                redundant,
                position,
            )?
        } else {
            self.silk.encode(
                &mut output[1..],
                bandwidth,
                duration_ms,
                header,
                &parameters[..intervals],
                &no_fec[..intervals],
            )?
        };
        if payload > MAX_FRAME_BYTES {
            return Err(Error::BufferTooSmall);
        }
        self.seed = (self.seed + intervals as u8) & 3;
        Ok(payload + 1)
    }

    #[allow(clippy::too_many_arguments)]
    fn encode_silk_stereo_duration(
        &mut self,
        input: &[i16],
        sample_rate: u32,
        duration_ms: u8,
        intervals: usize,
        interval_samples: usize,
        config: u8,
        bandwidth: Bandwidth,
        lsf_order: u8,
        interpolate_lsf: bool,
        output: &mut [u8],
        redundancy: Option<(&[u8], transition::RedundancyPosition)>,
    ) -> Result<usize, Error> {
        let input_frames = sample_rate as usize * usize::from(duration_ms) / 1000;
        let narrow_count = intervals * interval_samples;
        let mut source = [[0.0f32; 2880]; 2];
        let mut narrow = [[0.0f32; 960]; 2];
        for channel in 0..2 {
            for frame in 0..input_frames {
                source[channel][frame] = input[frame * 2 + channel] as f32 / 32_768.0;
            }
            silk::resample_linear(
                &source[channel][..input_frames],
                &mut narrow[channel][..narrow_count],
            )?;
        }
        let make_parameters = |excitation| silk_codec::MonoFrameParameters {
            signal: silk::SignalType::Unvoiced,
            quantization: silk::QuantizationOffset::Low,
            gain_symbols: [20, 4, 4, 4],
            lsf: silk_lsf::LsfIndices {
                stage1: 3,
                stage2: silk_lsf::Stage2 {
                    order: lsf_order,
                    index: [0; 16],
                },
                interpolation_q2: interpolate_lsf.then_some(4),
            },
            primary_pitch: None,
            contour_index: 0,
            ltp: None,
            seed: self.seed,
            rate_level: 0,
            excitation,
        };
        let empty = [0; silk_entropy::MAX_EXCITATION_SAMPLES];
        let mut mid = [make_parameters(empty); 3];
        let mut side = [make_parameters(empty); 3];
        for interval in 0..intervals {
            let start = interval * interval_samples;
            for index in 0..interval_samples {
                let left = narrow[0][start + index];
                let right = narrow[1][start + index];
                mid[interval].excitation[index] =
                    mrml_math::round(0.5 * (left + right) * 8.0).clamp(-8.0, 7.0) as i32;
                side[interval].excitation[index] =
                    mrml_math::round(0.5 * (left - right) * 8.0).clamp(-8.0, 7.0) as i32;
            }
            mid[interval].seed = (self.seed + interval as u8) & 3;
            side[interval].seed = mid[interval].seed;
        }
        let prediction = silk_stereo::prediction_from_indices(12, 1, 2, 1, 2)?;
        let regular = core::array::from_fn::<_, 3, _>(|index| silk_packet::StereoFrameParameters {
            prediction: Some(&prediction),
            mid_only: None,
            mid: Some(&mid[index]),
            side: Some(&side[index]),
        });
        let empty_fec = silk_packet::StereoFrameParameters {
            prediction: None,
            mid_only: None,
            mid: None,
            side: None,
        };
        let header = silk_frame::LayerHeader {
            channels: 2,
            frames: intervals as u8,
            channel: [
                silk_frame::ChannelHeader {
                    vad: (1 << intervals) - 1,
                    lbrr: 0,
                },
                silk_frame::ChannelHeader {
                    vad: (1 << intervals) - 1,
                    lbrr: 0,
                },
            ],
        };
        output[0] = config << 3 | 1 << 2;
        let empty_fec = [empty_fec; 3];
        let payload = if let Some((redundant, position)) = redundancy {
            encode_silk_stereo_transition(
                &mut self.silk_stereo,
                &mut output[1..],
                bandwidth,
                duration_ms,
                header,
                &regular[..intervals],
                &empty_fec[..intervals],
                redundant,
                position,
            )?
        } else {
            self.silk_stereo.encode(
                &mut output[1..],
                bandwidth,
                duration_ms,
                header,
                &regular[..intervals],
                &empty_fec[..intervals],
            )?
        };
        if payload > MAX_FRAME_BYTES {
            return Err(Error::BufferTooSmall);
        }
        self.seed = (self.seed + intervals as u8) & 3;
        Ok(payload + 1)
    }

    fn encode_silk_with_bitrate(
        &mut self,
        input: &[i16],
        sample_rate: u32,
        output: &mut [u8],
        bitrate: u32,
    ) -> Result<usize, Error> {
        let target = usize::try_from(bitrate.div_ceil(400)).map_err(|_| Error::InvalidPacket)?;
        let target = target.clamp(2, MAX_FRAME_BYTES + 1);
        let mut unpadded = [0u8; MAX_FRAME_BYTES + 1];
        let encoded = self.encode(input, sample_rate, &mut unpadded)?;
        if target <= encoded {
            if output.len() < encoded {
                return Err(Error::BufferTooSmall);
            }
            output[..encoded].copy_from_slice(&unpadded[..encoded]);
            return Ok(encoded);
        }
        // A one-frame padding wrapper needs three bytes. Never place a one-
        // or two-byte gap inside SILK: that can cross the 17-bit implicit
        // redundancy threshold. Return the nearest smaller valid packet.
        if target > encoded && target - encoded <= 2 {
            if output.len() < encoded {
                return Err(Error::BufferTooSmall);
            }
            output[..encoded].copy_from_slice(&unpadded[..encoded]);
            return Ok(encoded);
        }
        if output.len() < target {
            return Err(Error::BufferTooSmall);
        }
        let config = unpadded[0] >> 3;
        let stereo = unpadded[0] & 4 != 0;
        let frame = &unpadded[1..encoded];
        for padding in 1..target {
            let size = packetize(config, stereo, &[frame], padding, output)?;
            if size == target {
                return Ok(size);
            }
            if size > target {
                break;
            }
        }
        Err(Error::InvalidPacket)
    }

    fn encode_silk_transition_with_bitrate(
        &mut self,
        input: &[i16],
        sample_rate: u32,
        output: &mut [u8],
        bitrate: u32,
    ) -> Result<usize, Error> {
        let target = usize::try_from(bitrate.div_ceil(400))
            .map_err(|_| Error::InvalidPacket)?
            .clamp(2, MAX_FRAME_BYTES + 1);
        let transition_frames = sample_rate as usize / 200;
        let transition_samples = transition_frames * usize::from(self.channels);
        let mut transition_input = [0i16; 480];
        transition_input[..transition_samples].copy_from_slice(&input[..transition_samples]);
        let redundancy_bytes = if self.channels == 2 { 32 } else { 16 };
        let mut redundant_packet = [0u8; 65];
        let redundant = Encoder::new(self.channels)?.encode_celt_with_payload(
            &transition_input[..transition_samples],
            sample_rate,
            &mut redundant_packet,
            redundancy_bytes,
            1,
            Bandwidth::Full,
        );
        if let Ok(redundant_size) = redundant {
            let mut transitioned = [0u8; MAX_FRAME_BYTES + 1];
            let mut trial = Encoder::new(self.channels)?;
            trial.seed = self.seed;
            if let Ok(size) = trial.encode_silk_with_redundancy(
                input,
                sample_rate,
                Bandwidth::Narrow,
                20_000,
                &redundant_packet[1..redundant_size],
                true,
                &mut transitioned,
            ) && size <= target
                && output.len() >= size
            {
                output[..size].copy_from_slice(&transitioned[..size]);
                self.silk = trial.silk;
                self.silk_stereo = trial.silk_stereo;
                self.seed = trial.seed;
                return Ok(size);
            }
        }
        self.encode_silk_with_bitrate(input, sample_rate, output, bitrate)
    }

    /// Encodes exactly 20 ms as a fullband CELT packet.
    pub fn encode_celt(
        &mut self,
        input: &[i16],
        sample_rate: u32,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        self.encode_celt_duration(input, sample_rate, 20_000, output)
    }

    /// Encodes one fullband CELT frame at any RFC 6716 CELT duration.
    pub fn encode_celt_duration(
        &mut self,
        input: &[i16],
        sample_rate: u32,
        duration_us: u32,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        self.encode_celt_bandwidth_duration(
            input,
            sample_rate,
            Bandwidth::Full,
            duration_us,
            output,
        )
    }

    /// Encodes one CELT frame at any RFC 6716 CELT bandwidth and duration.
    /// CELT has no medium-bandwidth TOC configurations.
    pub fn encode_celt_bandwidth_duration(
        &mut self,
        input: &[i16],
        sample_rate: u32,
        bandwidth: Bandwidth,
        duration_us: u32,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let lm = match duration_us {
            2_500 => 0,
            5_000 => 1,
            10_000 => 2,
            20_000 => 3,
            _ => return Err(Error::InvalidFrameSize),
        };
        let payload_bytes = if self.channels == 1 {
            128usize << lm
        } else {
            (160usize << lm).min(MAX_FRAME_BYTES)
        };
        self.encode_celt_with_payload(input, sample_rate, output, payload_bytes, lm, bandwidth)
    }

    /// Encodes exactly 5 ms as a TOC-less fullband CELT frame suitable for
    /// RFC 6716 transition redundancy.
    pub fn encode_celt_redundancy(
        &mut self,
        input: &[i16],
        sample_rate: u32,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let payload_bytes = if self.channels == 2 { 128 } else { 64 };
        if output.len() < payload_bytes {
            return Err(Error::BufferTooSmall);
        }
        let mut packet = [0u8; 129];
        let size = self.encode_celt_with_payload(
            input,
            sample_rate,
            &mut packet,
            payload_bytes,
            1,
            Bandwidth::Full,
        )?;
        if size != payload_bytes + 1 {
            return Err(Error::InvalidPacket);
        }
        output[..payload_bytes].copy_from_slice(&packet[1..size]);
        Ok(payload_bytes)
    }

    fn encode_celt_with_payload(
        &mut self,
        input: &[i16],
        sample_rate: u32,
        output: &mut [u8],
        payload_bytes: usize,
        lm: u8,
        bandwidth: Bandwidth,
    ) -> Result<usize, Error> {
        if !(2..=MAX_FRAME_BYTES).contains(&payload_bytes) {
            return Err(Error::InvalidPacket);
        }
        if !matches!(sample_rate, 8_000 | 12_000 | 16_000 | 24_000 | 48_000) {
            return Err(Error::InvalidFrameSize);
        }
        if lm > 3 {
            return Err(Error::InvalidFrameSize);
        }
        let (config_base, end_band) = match bandwidth {
            Bandwidth::Narrow => (16, 13),
            Bandwidth::Wide => (20, 17),
            Bandwidth::SuperWide => (24, 19),
            Bandwidth::Full => (28, bands::BAND_COUNT),
            Bandwidth::Medium => return Err(Error::UnsupportedAudioMode),
        };
        let native_count = 120usize << lm;
        let duration_us = 2_500u32 << lm;
        let input_frames = sample_rate as usize * duration_us as usize / 1_000_000;
        if input.len() != input_frames * usize::from(self.channels) {
            return Err(Error::InvalidFrameSize);
        }
        if output.len() < payload_bytes + 1 {
            return Err(Error::BufferTooSmall);
        }
        if input.iter().all(|&sample| sample == 0) {
            return encode_dtx(config_base + lm, self.channels == 2, output);
        }
        let channels = usize::from(self.channels);
        let mut source = [[0.0f32; 960]; 2];
        let mut pcm = [[0.0f32; 960]; 2];
        for channel in 0..channels {
            for frame in 0..input_frames {
                source[channel][frame] = input[frame * channels + channel] as f32 / 32_768.0;
            }
            silk::resample_linear(
                &source[channel][..input_frames],
                &mut pcm[channel][..native_count],
            )?;
            for sample in &mut pcm[channel][..native_count] {
                let current = *sample;
                *sample = current - 0.850_006_1 * self.preemphasis_memory[channel];
                self.preemphasis_memory[channel] = current;
            }
        }
        let blocks = 1usize << lm;
        let mut block_energy = [0.0f32; 8];
        for (block, energy) in block_energy[..blocks].iter_mut().enumerate() {
            for channel_pcm in &pcm[..channels] {
                *energy += channel_pcm[block * 120..(block + 1) * 120]
                    .iter()
                    .fold(0.0, |sum, sample| sum + sample * sample);
            }
        }
        let total_energy = block_energy[..blocks].iter().sum::<f32>();
        let peak_energy = block_energy[..blocks]
            .iter()
            .copied()
            .fold(0.0f32, f32::max);
        let transient = lm > 0 && peak_energy * blocks as f32 > total_energy * 4.0;
        let mut coefficients = [[0.0f32; 960]; 2];
        let mut amplitudes = [[0.0f32; bands::BAND_COUNT]; 2];
        let mut normalized = [0.0f32; 1_920];
        let mut target = celt_energy::LogEnergies::new();
        for channel in 0..channels {
            if transient {
                celt::forward_short_blocks(
                    &pcm[channel][..native_count],
                    &mut coefficients[channel][..native_count],
                )?;
            } else {
                let mut transform_input = [0.0f32; 1_920];
                transform_input[..native_count].copy_from_slice(&pcm[channel][..native_count]);
                transform_input[native_count..2 * native_count]
                    .copy_from_slice(&pcm[channel][..native_count]);
                celt::forward_mdct(
                    &transform_input[..2 * native_count],
                    &mut coefficients[channel][..native_count],
                )?;
            }
            bands::normalize_bands(
                &coefficients[channel][..native_count],
                lm,
                &mut amplitudes[channel],
                &mut normalized[channel * native_count..(channel + 1) * native_count],
            )?;
            for (band, &amplitude) in amplitudes[channel].iter().enumerate() {
                target.values_mut()[channel][band] =
                    mrml_math::log2(amplitude.max(1.0e-12)) - bands::ENERGY_MEANS[band];
            }
        }
        let frame_config = celt_frame::FrameConfig {
            frame_bytes: payload_bytes,
            channels: self.channels,
            lm,
            start: 0,
            end: end_band,
        };
        let coarse = celt_energy::CoarseConfig {
            channels: self.channels,
            lm,
            intra: true,
            start: 0,
            end: end_band,
            frame_bytes: payload_bytes,
        };
        let mut residuals = [[0i16; bands::BAND_COUNT]; 2];
        celt_energy::residuals_for_target(coarse, &self.celt_energies, &target, &mut residuals)?;
        let request = celt_frame::EncodeRequest {
            silence: false,
            post_filter: None,
            transient,
            intra_energy: true,
            tf_flags: [false; bands::BAND_COUNT],
            tf_select: false,
            spread: 2,
            residuals,
            boosts: [0; bands::BAND_COUNT],
            trim: 5,
            coded_bands: 0,
            intensity: end_band,
            dual_stereo: false,
        };
        let mut coded_residuals = [[0i16; bands::BAND_COUNT]; 2];
        let mut pulse_workspace = [0i32; 1_920];
        let mut recurrence = [0u32; pvq::MAX_PULSES + 1];
        output[0] = (config_base + lm) << 3 | u8::from(self.channels == 2) << 2;
        let result = {
            let mut range = RangeEncoder::new(&mut output[1..payload_bytes + 1]);
            let plan = celt_frame::encode_plan(
                &mut range,
                frame_config,
                &request,
                &target,
                &mut self.celt_energies,
                &mut coded_residuals,
            )?;
            let result = if self.channels == 1 {
                celt_frame::encode_shapes_mono(
                    &mut range,
                    frame_config,
                    &plan,
                    &normalized[..native_count],
                    &mut pulse_workspace,
                    &mut recurrence,
                    &target,
                    &mut self.celt_energies,
                    self.celt_seed,
                )?
            } else {
                celt_frame::encode_shapes_stereo(
                    &mut range,
                    frame_config,
                    &plan,
                    &normalized[..native_count * channels],
                    &mut pulse_workspace,
                    &mut recurrence,
                    &target,
                    &mut self.celt_energies,
                    self.celt_seed,
                )?
            };
            range.finish()?;
            result
        };
        self.celt_seed = result.seed;
        Ok(payload_bytes + 1)
    }

    /// Encodes exactly 20 ms as a mono fullband hybrid SILK+CELT packet.
    pub fn encode_hybrid(
        &mut self,
        input: &[i16],
        sample_rate: u32,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let payload_bytes = if self.channels == 2 { 1_275 } else { 512 };
        self.encode_hybrid_with_payload(
            input,
            sample_rate,
            output,
            payload_bytes,
            None,
            Bandwidth::Full,
            20_000,
        )
    }

    /// Encodes a Hybrid SILK+CELT packet at either legal Hybrid bandwidth and
    /// frame duration.
    pub fn encode_hybrid_bandwidth_duration(
        &mut self,
        input: &[i16],
        sample_rate: u32,
        bandwidth: Bandwidth,
        duration_us: u32,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let payload_bytes = if self.channels == 2 { 1_275 } else { 512 };
        self.encode_hybrid_with_payload(
            input,
            sample_rate,
            output,
            payload_bytes,
            None,
            bandwidth,
            duration_us,
        )
    }

    /// Encodes a 20 ms Hybrid packet with a caller-supplied, TOC-less 5 ms
    /// CELT transition frame in its byte-aligned redundancy tail.
    pub fn encode_hybrid_with_redundancy(
        &mut self,
        input: &[i16],
        sample_rate: u32,
        redundant_celt: &[u8],
        at_beginning: bool,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let payload_bytes = if self.channels == 2 { 1_275 } else { 512 };
        let position = if at_beginning {
            transition::RedundancyPosition::Beginning
        } else {
            transition::RedundancyPosition::End
        };
        self.encode_hybrid_with_payload(
            input,
            sample_rate,
            output,
            payload_bytes,
            Some((redundant_celt, position)),
            Bandwidth::Full,
            20_000,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn encode_hybrid_with_payload(
        &mut self,
        input: &[i16],
        sample_rate: u32,
        output: &mut [u8],
        payload_bytes: usize,
        redundancy: Option<(&[u8], transition::RedundancyPosition)>,
        bandwidth: Bandwidth,
        duration_us: u32,
    ) -> Result<usize, Error> {
        if !(16..=MAX_FRAME_BYTES).contains(&payload_bytes) {
            return Err(Error::InvalidPacket);
        }
        if self.channels == 2 {
            return self.encode_hybrid_stereo(
                input,
                sample_rate,
                output,
                payload_bytes,
                redundancy,
                bandwidth,
                duration_us,
            );
        }
        let (duration_ms, lm, config, silk_count, celt_count, interpolate_lsf) =
            hybrid_geometry(bandwidth, duration_us)?;
        let redundancy_len = redundancy.map_or(0, |(payload, _)| payload.len());
        if redundancy_len > 257 || (redundancy.is_some() && redundancy_len < 2) {
            return Err(Error::InvalidPacket);
        }
        let main_bytes = payload_bytes
            .checked_sub(redundancy_len)
            .filter(|&bytes| bytes >= 2)
            .ok_or(Error::InvalidPacket)?;
        if !matches!(sample_rate, 8_000 | 12_000 | 16_000 | 24_000 | 48_000) {
            return Err(Error::InvalidFrameSize);
        }
        let input_frames = sample_rate as usize * duration_us as usize / 1_000_000;
        let channels = usize::from(self.channels);
        if input.len() != input_frames * channels {
            return Err(Error::InvalidFrameSize);
        }
        if output.len() < payload_bytes + 1 {
            return Err(Error::BufferTooSmall);
        }
        if input.iter().all(|&sample| sample == 0) {
            return encode_dtx(config, false, output);
        }
        let mut source = [0.0f32; 960];
        for frame in 0..input_frames {
            let mut sum = 0.0;
            for channel in 0..channels {
                sum += input[frame * channels + channel] as f32;
            }
            source[frame] = sum / (32_768.0 * channels as f32);
        }
        let mut silk_pcm = [0.0f32; 320];
        let mut celt_pcm = [0.0f32; 960];
        silk::resample_linear(&source[..input_frames], &mut silk_pcm[..silk_count])?;
        silk::resample_linear(&source[..input_frames], &mut celt_pcm[..celt_count])?;
        let mut excitation = [0i32; silk_entropy::MAX_EXCITATION_SAMPLES];
        for (target, &sample) in excitation[..silk_count]
            .iter_mut()
            .zip(&silk_pcm[..silk_count])
        {
            *target = if payload_bytes < 512 {
                0
            } else {
                mrml_math::round(sample * 8.0).clamp(-8.0, 7.0) as i32
            };
        }
        let silk_parameters = silk_codec::MonoFrameParameters {
            signal: silk::SignalType::Unvoiced,
            quantization: silk::QuantizationOffset::Low,
            gain_symbols: [20, 4, 4, 4],
            lsf: silk_lsf::LsfIndices {
                stage1: 4,
                stage2: silk_lsf::Stage2 {
                    order: 16,
                    index: [0; 16],
                },
                interpolation_q2: interpolate_lsf.then_some(4),
            },
            primary_pitch: None,
            contour_index: 0,
            ltp: None,
            seed: self.seed,
            rate_level: 0,
            excitation,
        };
        let header = silk_frame::LayerHeader {
            channels: 1,
            frames: 1,
            channel: [
                silk_frame::ChannelHeader { vad: 1, lbrr: 0 },
                silk_frame::ChannelHeader { vad: 0, lbrr: 0 },
            ],
        };
        for sample in &mut celt_pcm[..celt_count] {
            let current = *sample;
            *sample = current - 0.850_006_1 * self.preemphasis_memory[0];
            self.preemphasis_memory[0] = current;
        }
        let mut transform_input = [0.0f32; 1_920];
        transform_input[..celt_count].copy_from_slice(&celt_pcm[..celt_count]);
        transform_input[celt_count..2 * celt_count].copy_from_slice(&celt_pcm[..celt_count]);
        let mut coefficients = [0.0f32; 960];
        celt::forward_mdct(
            &transform_input[..2 * celt_count],
            &mut coefficients[..celt_count],
        )?;
        let mut amplitudes = [0.0f32; bands::BAND_COUNT];
        let mut normalized = [0.0f32; 960];
        bands::normalize_bands(
            &coefficients[..celt_count],
            lm,
            &mut amplitudes,
            &mut normalized[..celt_count],
        )?;
        let mut target = celt_energy::LogEnergies::new();
        let end = if bandwidth == Bandwidth::SuperWide {
            19
        } else {
            bands::BAND_COUNT
        };
        for (band, &amplitude) in amplitudes.iter().enumerate().take(end).skip(17) {
            target.values_mut()[0][band] =
                mrml_math::log2(amplitude.max(1.0e-12)) - bands::ENERGY_MEANS[band];
        }
        let frame_config = celt_frame::FrameConfig {
            frame_bytes: main_bytes,
            channels: 1,
            lm,
            start: 17,
            end,
        };
        let mut residuals = [[0i16; bands::BAND_COUNT]; 2];
        celt_energy::residuals_for_target(
            celt_energy::CoarseConfig {
                channels: 1,
                lm,
                intra: true,
                start: 17,
                end,
                frame_bytes: main_bytes,
            },
            &self.celt_energies,
            &target,
            &mut residuals,
        )?;
        let request = celt_frame::EncodeRequest {
            silence: false,
            post_filter: None,
            transient: false,
            intra_energy: true,
            tf_flags: [false; bands::BAND_COUNT],
            tf_select: false,
            spread: 2,
            residuals,
            boosts: [0; bands::BAND_COUNT],
            trim: 5,
            coded_bands: 0,
            intensity: end,
            dual_stereo: false,
        };
        let mut coded_residuals = [[0i16; bands::BAND_COUNT]; 2];
        let mut pulse_workspace = [0i32; 960];
        let mut recurrence = [0u32; pvq::MAX_PULSES + 1];
        output[0] = config << 3;
        let result = {
            let mut range = RangeEncoder::new(&mut output[1..main_bytes + 1]);
            self.silk.reset();
            self.silk.encode_range(
                &mut range,
                Bandwidth::Wide,
                duration_ms,
                header,
                &[silk_parameters],
                &[None],
            )?;
            if let Some((payload, position)) = redundancy {
                transition::encode_header(
                    &mut range,
                    Mode::Hybrid,
                    payload_bytes,
                    position,
                    payload.len(),
                )?;
            } else {
                transition::encode_absence(&mut range, Mode::Hybrid, payload_bytes)?;
            }
            let plan = celt_frame::encode_plan(
                &mut range,
                frame_config,
                &request,
                &target,
                &mut self.celt_energies,
                &mut coded_residuals,
            )?;
            let result = celt_frame::encode_shapes_mono(
                &mut range,
                frame_config,
                &plan,
                &normalized[..celt_count],
                &mut pulse_workspace,
                &mut recurrence,
                &target,
                &mut self.celt_energies,
                self.celt_seed,
            )?;
            range.finish()?;
            result
        };
        if let Some((payload, _)) = redundancy {
            output[1 + main_bytes..1 + payload_bytes].copy_from_slice(payload);
        }
        self.seed = (self.seed + 1) & 3;
        self.celt_seed = result.seed;
        Ok(payload_bytes + 1)
    }

    #[allow(clippy::too_many_arguments)]
    fn encode_hybrid_stereo(
        &mut self,
        input: &[i16],
        sample_rate: u32,
        output: &mut [u8],
        payload_bytes: usize,
        redundancy: Option<(&[u8], transition::RedundancyPosition)>,
        bandwidth: Bandwidth,
        duration_us: u32,
    ) -> Result<usize, Error> {
        let (duration_ms, lm, config, silk_count, celt_count, interpolate_lsf) =
            hybrid_geometry(bandwidth, duration_us)?;
        let redundancy_len = redundancy.map_or(0, |(payload, _)| payload.len());
        if redundancy_len > 257 || (redundancy.is_some() && redundancy_len < 2) {
            return Err(Error::InvalidPacket);
        }
        let main_bytes = payload_bytes
            .checked_sub(redundancy_len)
            .filter(|&bytes| bytes >= 2)
            .ok_or(Error::InvalidPacket)?;
        if !matches!(sample_rate, 8_000 | 12_000 | 16_000 | 24_000 | 48_000) {
            return Err(Error::InvalidFrameSize);
        }
        let input_frames = sample_rate as usize * duration_us as usize / 1_000_000;
        if input.len() != input_frames * 2 {
            return Err(Error::InvalidFrameSize);
        }
        if output.len() < payload_bytes + 1 {
            return Err(Error::BufferTooSmall);
        }
        if input.iter().all(|&sample| sample == 0) {
            return encode_dtx(config, true, output);
        }
        let mut source = [[0.0f32; 960]; 2];
        let mut silk_pcm = [[0.0f32; 320]; 2];
        let mut celt_pcm = [[0.0f32; 960]; 2];
        for channel in 0..2 {
            for frame in 0..input_frames {
                source[channel][frame] = input[frame * 2 + channel] as f32 / 32_768.0;
            }
            silk::resample_linear(
                &source[channel][..input_frames],
                &mut silk_pcm[channel][..silk_count],
            )?;
            silk::resample_linear(
                &source[channel][..input_frames],
                &mut celt_pcm[channel][..celt_count],
            )?;
        }
        let mut mid_excitation = [0i32; silk_entropy::MAX_EXCITATION_SAMPLES];
        let mut side_excitation = [0i32; silk_entropy::MAX_EXCITATION_SAMPLES];
        for index in 0..silk_count {
            let mid = 0.5 * (silk_pcm[0][index] + silk_pcm[1][index]);
            let side = 0.5 * (silk_pcm[0][index] - silk_pcm[1][index]);
            if payload_bytes >= 1_024 {
                mid_excitation[index] = mrml_math::round(mid * 8.0).clamp(-8.0, 7.0) as i32;
                side_excitation[index] = mrml_math::round(side * 8.0).clamp(-8.0, 7.0) as i32;
            }
        }
        let make_parameters = |excitation| silk_codec::MonoFrameParameters {
            signal: silk::SignalType::Unvoiced,
            quantization: silk::QuantizationOffset::Low,
            gain_symbols: [20, 4, 4, 4],
            lsf: silk_lsf::LsfIndices {
                stage1: 4,
                stage2: silk_lsf::Stage2 {
                    order: 16,
                    index: [0; 16],
                },
                interpolation_q2: interpolate_lsf.then_some(4),
            },
            primary_pitch: None,
            contour_index: 0,
            ltp: None,
            seed: self.seed,
            rate_level: 0,
            excitation,
        };
        let mid_parameters = make_parameters(mid_excitation);
        let side_parameters = make_parameters(side_excitation);
        let prediction = silk_stereo::prediction_from_indices(12, 1, 2, 1, 2)?;
        let regular = silk_packet::StereoFrameParameters {
            prediction: Some(&prediction),
            mid_only: None,
            mid: Some(&mid_parameters),
            side: Some(&side_parameters),
        };
        let empty_fec = silk_packet::StereoFrameParameters {
            prediction: None,
            mid_only: None,
            mid: None,
            side: None,
        };
        let header = silk_frame::LayerHeader {
            channels: 2,
            frames: 1,
            channel: [
                silk_frame::ChannelHeader { vad: 1, lbrr: 0 },
                silk_frame::ChannelHeader { vad: 1, lbrr: 0 },
            ],
        };
        let mut normalized = [0.0f32; 1_920];
        let mut target = celt_energy::LogEnergies::new();
        for channel in 0..2 {
            for sample in &mut celt_pcm[channel][..celt_count] {
                let current = *sample;
                *sample = current - 0.850_006_1 * self.preemphasis_memory[channel];
                self.preemphasis_memory[channel] = current;
            }
            let mut transform_input = [0.0f32; 1_920];
            transform_input[..celt_count].copy_from_slice(&celt_pcm[channel][..celt_count]);
            transform_input[celt_count..2 * celt_count]
                .copy_from_slice(&celt_pcm[channel][..celt_count]);
            let mut coefficients = [0.0f32; 960];
            celt::forward_mdct(
                &transform_input[..2 * celt_count],
                &mut coefficients[..celt_count],
            )?;
            let mut amplitudes = [0.0f32; bands::BAND_COUNT];
            bands::normalize_bands(
                &coefficients[..celt_count],
                lm,
                &mut amplitudes,
                &mut normalized[channel * celt_count..(channel + 1) * celt_count],
            )?;
            let end = if bandwidth == Bandwidth::SuperWide {
                19
            } else {
                bands::BAND_COUNT
            };
            for (band, &amplitude) in amplitudes.iter().enumerate().take(end).skip(17) {
                target.values_mut()[channel][band] =
                    mrml_math::log2(amplitude.max(1.0e-12)) - bands::ENERGY_MEANS[band];
            }
        }
        let end = if bandwidth == Bandwidth::SuperWide {
            19
        } else {
            bands::BAND_COUNT
        };
        let frame_config = celt_frame::FrameConfig {
            frame_bytes: main_bytes,
            channels: 2,
            lm,
            start: 17,
            end,
        };
        let mut residuals = [[0i16; bands::BAND_COUNT]; 2];
        celt_energy::residuals_for_target(
            celt_energy::CoarseConfig {
                channels: 2,
                lm,
                intra: true,
                start: 17,
                end,
                frame_bytes: main_bytes,
            },
            &self.celt_energies,
            &target,
            &mut residuals,
        )?;
        let request = celt_frame::EncodeRequest {
            silence: false,
            post_filter: None,
            transient: false,
            intra_energy: true,
            tf_flags: [false; bands::BAND_COUNT],
            tf_select: false,
            spread: 2,
            residuals,
            boosts: [0; bands::BAND_COUNT],
            trim: 5,
            coded_bands: 0,
            intensity: end,
            dual_stereo: false,
        };
        let mut coded_residuals = [[0i16; bands::BAND_COUNT]; 2];
        let mut pulse_workspace = [0i32; 1_920];
        let mut recurrence = [0u32; pvq::MAX_PULSES + 1];
        output[0] = config << 3 | 1 << 2;
        let result = {
            let mut range = RangeEncoder::new(&mut output[1..main_bytes + 1]);
            self.silk_stereo.reset();
            self.silk_stereo.encode_range(
                &mut range,
                Bandwidth::Wide,
                duration_ms,
                header,
                &[regular],
                &[empty_fec],
            )?;
            if let Some((payload, position)) = redundancy {
                transition::encode_header(
                    &mut range,
                    Mode::Hybrid,
                    payload_bytes,
                    position,
                    payload.len(),
                )?;
            } else {
                transition::encode_absence(&mut range, Mode::Hybrid, payload_bytes)?;
            }
            let plan = celt_frame::encode_plan(
                &mut range,
                frame_config,
                &request,
                &target,
                &mut self.celt_energies,
                &mut coded_residuals,
            )?;
            let result = celt_frame::encode_shapes_stereo(
                &mut range,
                frame_config,
                &plan,
                &normalized[..celt_count * 2],
                &mut pulse_workspace,
                &mut recurrence,
                &target,
                &mut self.celt_energies,
                self.celt_seed,
            )?;
            range.finish()?;
            result
        };
        if let Some((payload, _)) = redundancy {
            output[1 + main_bytes..1 + payload_bytes].copy_from_slice(payload);
        }
        self.seed = (self.seed + 1) & 3;
        self.celt_seed = result.seed;
        Ok(payload_bytes + 1)
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_silk_mono_transition(
    encoder: &mut silk_packet::MonoPayloadEncoder,
    output: &mut [u8],
    bandwidth: Bandwidth,
    duration_ms: u8,
    header: silk_frame::LayerHeader,
    regular: &[silk_codec::MonoFrameParameters],
    fec: &[Option<&silk_codec::MonoFrameParameters>],
    redundant: &[u8],
    position: transition::RedundancyPosition,
) -> Result<usize, Error> {
    if !(2..=257).contains(&redundant.len()) {
        return Err(Error::InvalidPacket);
    }
    let mut probe_bytes = [0u8; MAX_FRAME_BYTES];
    let mut probe = RangeEncoder::new(&mut probe_bytes);
    silk_packet::MonoPayloadEncoder::new().encode_range(
        &mut probe,
        bandwidth,
        duration_ms,
        header,
        regular,
        fec,
    )?;
    probe.encode_bit_logp(position == transition::RedundancyPosition::Beginning, 1)?;
    let main_bytes = usize::try_from(probe.tell().div_ceil(8)).map_err(|_| Error::InvalidPacket)?;
    let total = main_bytes
        .checked_add(redundant.len())
        .filter(|&size| size <= MAX_FRAME_BYTES)
        .ok_or(Error::BufferTooSmall)?;
    if output.len() < total {
        return Err(Error::BufferTooSmall);
    }
    {
        let mut range = RangeEncoder::new(&mut output[..total]);
        range.reserve_tail(redundant.len())?;
        encoder.encode_range(&mut range, bandwidth, duration_ms, header, regular, fec)?;
        transition::encode_header(&mut range, Mode::Silk, total, position, redundant.len())?;
        range.finish()?;
    }
    output[main_bytes..total].copy_from_slice(redundant);
    Ok(total)
}

#[allow(clippy::too_many_arguments)]
fn encode_silk_stereo_transition(
    encoder: &mut silk_packet::StereoPayloadEncoder,
    output: &mut [u8],
    bandwidth: Bandwidth,
    duration_ms: u8,
    header: silk_frame::LayerHeader,
    regular: &[silk_packet::StereoFrameParameters<'_>],
    fec: &[silk_packet::StereoFrameParameters<'_>],
    redundant: &[u8],
    position: transition::RedundancyPosition,
) -> Result<usize, Error> {
    if !(2..=257).contains(&redundant.len()) {
        return Err(Error::InvalidPacket);
    }
    let mut probe_bytes = [0u8; MAX_FRAME_BYTES];
    let mut probe = RangeEncoder::new(&mut probe_bytes);
    silk_packet::StereoPayloadEncoder::new().encode_range(
        &mut probe,
        bandwidth,
        duration_ms,
        header,
        regular,
        fec,
    )?;
    probe.encode_bit_logp(position == transition::RedundancyPosition::Beginning, 1)?;
    let main_bytes = usize::try_from(probe.tell().div_ceil(8)).map_err(|_| Error::InvalidPacket)?;
    let total = main_bytes
        .checked_add(redundant.len())
        .filter(|&size| size <= MAX_FRAME_BYTES)
        .ok_or(Error::BufferTooSmall)?;
    if output.len() < total {
        return Err(Error::BufferTooSmall);
    }
    {
        let mut range = RangeEncoder::new(&mut output[..total]);
        range.reserve_tail(redundant.len())?;
        encoder.encode_range(&mut range, bandwidth, duration_ms, header, regular, fec)?;
        transition::encode_header(&mut range, Mode::Silk, total, position, redundant.len())?;
        range.finish()?;
    }
    output[main_bytes..total].copy_from_slice(redundant);
    Ok(total)
}

/// Allocation-free one-frame-lookahead encoder for normative transitions
/// whose redundancy belongs in the packet before a CELT mode switch.
///
/// The first call to push buffers a 20 ms frame and subsequent calls return
/// the completed previous packet. Call flush to retrieve the final packet.
pub struct LookaheadEncoder {
    encoder: Encoder,
    channels: u8,
    pending: [i16; 1_920],
    pending_len: usize,
    pending_sample_rate: u32,
    pending_mode: EncoderMode,
    pending_bitrate: u32,
    has_pending: bool,
    packet: [u8; MAX_FRAME_BYTES + 1],
    packet_len: usize,
}

impl LookaheadEncoder {
    pub fn new(channels: u8) -> Result<Self, Error> {
        Ok(Self {
            encoder: Encoder::new(channels)?,
            channels,
            pending: [0; 1_920],
            pending_len: 0,
            pending_sample_rate: 48_000,
            pending_mode: EncoderMode::Auto,
            pending_bitrate: 6_000,
            has_pending: false,
            packet: [0; MAX_FRAME_BYTES + 1],
            packet_len: 0,
        })
    }

    /// Buffers a 20 ms frame and returns the previously buffered packet.
    pub fn push(
        &mut self,
        mode: EncoderMode,
        bitrate: u32,
        input: &[i16],
        sample_rate: u32,
    ) -> Result<Option<&[u8]>, Error> {
        validate_encoder_frame(self.channels, bitrate, input, sample_rate)?;
        let next_mode = selected_mode(mode, bitrate, self.channels)?;
        if self.has_pending {
            self.packet_len = self.encode_pending(Some(next_mode))?;
        }
        self.pending[..input.len()].copy_from_slice(input);
        self.pending_len = input.len();
        self.pending_sample_rate = sample_rate;
        self.pending_mode = mode;
        self.pending_bitrate = bitrate;
        let had_packet = self.has_pending;
        self.has_pending = true;
        Ok(had_packet.then_some(&self.packet[..self.packet_len]))
    }

    /// Encodes and removes the final buffered frame.
    pub fn flush(&mut self) -> Result<Option<&[u8]>, Error> {
        if !self.has_pending {
            return Ok(None);
        }
        self.packet_len = self.encode_pending(None)?;
        self.has_pending = false;
        Ok(Some(&self.packet[..self.packet_len]))
    }

    fn encode_pending(&mut self, next_mode: Option<Mode>) -> Result<usize, Error> {
        let pending_mode = selected_mode(self.pending_mode, self.pending_bitrate, self.channels)?;
        if next_mode == Some(Mode::Celt) && matches!(pending_mode, Mode::Silk | Mode::Hybrid) {
            let transition_frames = self.pending_sample_rate as usize / 200;
            let transition_samples = transition_frames * usize::from(self.channels);
            let start = self.pending_len - transition_samples;
            let redundancy_bytes = if self.channels == 2 { 32 } else { 16 };
            let mut redundant_packet = [0u8; 65];
            if let Ok(redundant_size) = Encoder::new(self.channels)?.encode_celt_with_payload(
                &self.pending[start..self.pending_len],
                self.pending_sample_rate,
                &mut redundant_packet,
                redundancy_bytes,
                1,
                Bandwidth::Full,
            ) {
                let redundant = &redundant_packet[1..redundant_size];
                let result = match pending_mode {
                    Mode::Silk => self.encoder.encode_silk_with_redundancy(
                        &self.pending[..self.pending_len],
                        self.pending_sample_rate,
                        Bandwidth::Narrow,
                        20_000,
                        redundant,
                        false,
                        &mut self.packet,
                    ),
                    Mode::Hybrid => {
                        let payload = payload_bytes_for_bitrate(self.pending_bitrate)?;
                        self.encoder.encode_hybrid_with_payload(
                            &self.pending[..self.pending_len],
                            self.pending_sample_rate,
                            &mut self.packet,
                            payload,
                            Some((redundant, transition::RedundancyPosition::End)),
                            Bandwidth::Full,
                            20_000,
                        )
                    }
                    Mode::Celt => unreachable!(),
                };
                if let Ok(size) = result {
                    self.encoder.last_encoded_mode = Some(pending_mode);
                    return Ok(size);
                }
            }
        }
        self.encoder.encode_mode(
            self.pending_mode,
            self.pending_bitrate,
            &self.pending[..self.pending_len],
            self.pending_sample_rate,
            &mut self.packet,
        )
    }
}

fn validate_encoder_frame(
    channels: u8,
    bitrate: u32,
    input: &[i16],
    sample_rate: u32,
) -> Result<(), Error> {
    if !(6_000..=510_000).contains(&bitrate) {
        return Err(Error::InvalidPacket);
    }
    if !matches!(sample_rate, 8_000 | 12_000 | 16_000 | 24_000 | 48_000) {
        return Err(Error::InvalidFrameSize);
    }
    let required = sample_rate as usize / 50 * usize::from(channels);
    if input.len() != required {
        return Err(Error::InvalidFrameSize);
    }
    Ok(())
}

fn selected_mode(mode: EncoderMode, bitrate: u32, channels: u8) -> Result<Mode, Error> {
    if !(6_000..=510_000).contains(&bitrate) {
        return Err(Error::InvalidPacket);
    }
    let selected = if mode == EncoderMode::Auto {
        let per_channel = bitrate / u32::from(channels);
        if per_channel < 20_000 {
            EncoderMode::Silk
        } else if per_channel < 64_000 {
            EncoderMode::Hybrid
        } else {
            EncoderMode::Celt
        }
    } else {
        mode
    };
    Ok(match selected {
        EncoderMode::Silk => Mode::Silk,
        EncoderMode::Hybrid => Mode::Hybrid,
        EncoderMode::Celt => Mode::Celt,
        EncoderMode::Auto => unreachable!(),
    })
}

pub struct Decoder {
    channels: u8,
    silk_mono: silk_packet::MonoPayloadDecoder,
    silk_stereo: silk_packet::StereoPayloadDecoder,
    previous_stereo: Option<bool>,
    celt_energies: celt_energy::LogEnergies,
    celt_previous_energies: celt_energy::LogEnergies,
    celt_older_energies: celt_energy::LogEnergies,
    celt_synthesis: celt_synthesis::SynthesisState,
    celt_seed: u32,
    celt_plc: [celt::CeltPlc; 2],
    celt_transition_ready: bool,
    last_frame: Option<LastFrame>,
    last_stateful_mode: Option<Mode>,
    final_range: u32,
}

#[derive(Clone, Copy)]
struct LastFrame {
    mode: Mode,
    bandwidth: Bandwidth,
    duration_us: u32,
    stereo: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FecDecodeResult {
    pub frames: usize,
    /// Total output-rate frames reconstructed from in-band LBRR data; the
    /// protected intervals need not be contiguous. Stereo intervals carrying
    /// only side data update decoder state but cannot reconstruct PCM without
    /// a protected mid channel, so they are not counted.
    pub fec_frames: usize,
}
impl Decoder {
    pub fn new(channels: u8) -> Result<Self, Error> {
        if !(1..=2).contains(&channels) {
            return Err(Error::InvalidPacket);
        }
        Ok(Self {
            channels,
            silk_mono: silk_packet::MonoPayloadDecoder::new(),
            silk_stereo: silk_packet::StereoPayloadDecoder::new(),
            previous_stereo: None,
            celt_energies: celt_energy::LogEnergies::new(),
            celt_previous_energies: celt_energy::LogEnergies::new(),
            celt_older_energies: celt_energy::LogEnergies::new(),
            celt_synthesis: celt_synthesis::SynthesisState::new(),
            celt_seed: 0,
            celt_plc: [const { celt::CeltPlc::new() }; 2],
            celt_transition_ready: false,
            last_frame: None,
            last_stateful_mode: None,
            final_range: 0,
        })
    }
    /// Returns the final entropy range of the most recently decoded packet's
    /// final constituent frame, matching `OPUS_GET_FINAL_RANGE`.
    pub const fn final_range(&self) -> u32 {
        self.final_range
    }

    fn reset_celt(&mut self) {
        self.celt_energies = celt_energy::LogEnergies::new();
        self.celt_previous_energies = celt_energy::LogEnergies::new();
        self.celt_older_energies = celt_energy::LogEnergies::new();
        self.celt_synthesis.reset();
        self.celt_seed = 0;
        self.celt_plc = [const { celt::CeltPlc::new() }; 2];
    }

    fn prepare_silk_decode(&mut self, stereo: bool) {
        if self.previous_stereo != Some(stereo) || self.last_stateful_mode == Some(Mode::Celt) {
            self.silk_mono.reset();
            self.silk_stereo.reset();
            self.previous_stereo = Some(stereo);
        }
        self.celt_transition_ready = false;
    }

    fn prepare_dtx_decode(&mut self, mode: Mode, stereo: bool) {
        let previous_mode = self.last_stateful_mode;
        let stereo_changed = self.previous_stereo != Some(stereo);
        let celt_transition_ready = self.celt_transition_ready;
        self.celt_transition_ready = false;
        match mode {
            Mode::Silk => {
                if stereo_changed || previous_mode == Some(Mode::Celt) {
                    self.silk_mono.reset();
                    self.silk_stereo.reset();
                }
            }
            Mode::Celt => {
                if stereo_changed || (previous_mode != Some(Mode::Celt) && !celt_transition_ready) {
                    self.reset_celt();
                }
            }
            Mode::Hybrid => {
                if stereo_changed || previous_mode == Some(Mode::Celt) {
                    self.silk_mono.reset();
                    self.silk_stereo.reset();
                }
                if stereo_changed || previous_mode != Some(Mode::Hybrid) {
                    self.reset_celt();
                }
            }
        }
        self.previous_stereo = Some(stereo);
        self.last_stateful_mode = Some(mode);
    }

    /// Decodes SILK, CELT, hybrid, and DTX packets.
    pub fn decode(
        &mut self,
        packet: &[u8],
        output: &mut [i16],
        sample_rate: u32,
    ) -> Result<usize, Error> {
        if !matches!(sample_rate, 8_000 | 12_000 | 16_000 | 24_000 | 48_000) {
            return Err(Error::InvalidFrameSize);
        }
        let parsed = Packet::parse(packet)?;
        let all_dtx = parsed.frames[..usize::from(parsed.frame_count)]
            .iter()
            .all(|frame| frame.len <= 1);
        let frames = (u64::from(sample_rate)
            * u64::from(parsed.frame_duration_us)
            * u64::from(parsed.frame_count)
            / 1_000_000) as usize;
        let samples = frames
            .checked_mul(usize::from(self.channels))
            .ok_or(Error::BufferTooSmall)?;
        if output.len() < samples {
            return Err(Error::BufferTooSmall);
        }
        if all_dtx {
            self.prepare_dtx_decode(parsed.mode, parsed.stereo);
            let geometry = LastFrame {
                mode: parsed.mode,
                bandwidth: parsed.bandwidth,
                duration_us: parsed.frame_duration_us,
                stereo: parsed.stereo,
            };
            let constituent_samples = samples / usize::from(parsed.frame_count);
            for index in 0..usize::from(parsed.frame_count) {
                let start = index * constituent_samples;
                self.conceal_frame(
                    geometry,
                    &mut output[start..start + constituent_samples],
                    sample_rate,
                )?;
            }
            self.last_frame = Some(geometry);
            self.final_range = 0;
            return Ok(frames);
        }
        if parsed.mode == Mode::Celt {
            return self.decode_celt_packet(packet, &parsed, output, sample_rate);
        }
        if parsed.mode == Mode::Hybrid {
            return self.decode_hybrid_packet(packet, &parsed, output, sample_rate);
        }
        self.prepare_silk_decode(parsed.stereo);
        let duration_ms = (parsed.frame_duration_us / 1_000) as u8;
        let native_rate = match parsed.bandwidth {
            Bandwidth::Narrow => 8_000usize,
            Bandwidth::Medium => 12_000,
            Bandwidth::Wide => 16_000,
            _ => return Err(Error::InvalidPacket),
        };
        let native_count = native_rate * usize::from(duration_ms) / 1_000;
        let output_count = sample_rate as usize * usize::from(duration_ms) / 1_000;
        if output_count > MAX_SILK_FRAME_SAMPLES_AT_48_KHZ {
            return Err(Error::InvalidFrameSize);
        }
        let mut native_left = [0.0f32; 960];
        let mut native_right = [0.0f32; 960];
        let mut fec_left = [0.0f32; 960];
        let mut fec_right = [0.0f32; 960];
        let mut converted_left = [0.0f32; MAX_SILK_FRAME_SAMPLES_AT_48_KHZ];
        let mut converted_right = [0.0f32; MAX_SILK_FRAME_SAMPLES_AT_48_KHZ];
        let mut main_48k = [[0.0f32; MAX_SILK_FRAME_SAMPLES_AT_48_KHZ]; 2];
        let mut redundant = [[0.0f32; 240]; 2];
        let main_48k_count = 48 * usize::from(duration_ms);
        let redundancy_end_band = match parsed.bandwidth {
            Bandwidth::Narrow => 13,
            Bandwidth::Medium | Bandwidth::Wide => 17,
            _ => return Err(Error::InvalidPacket),
        };
        let mut packet_range = 0u32;
        let geometry = LastFrame {
            mode: parsed.mode,
            bandwidth: parsed.bandwidth,
            duration_us: parsed.frame_duration_us,
            stereo: parsed.stereo,
        };
        for index in 0..usize::from(parsed.frame_count) {
            let frame = parsed.frames[index];
            let start = usize::from(frame.offset);
            let end = start + usize::from(frame.len);
            if frame.len <= 1 {
                let output_start = index * output_count * usize::from(self.channels);
                let output_end = output_start + output_count * usize::from(self.channels);
                self.celt_transition_ready = false;
                self.conceal_frame(geometry, &mut output[output_start..output_end], sample_rate)?;
                packet_range = 0;
                continue;
            }
            let mut range = RangeDecoder::new(&packet[start..end]);
            if parsed.stereo {
                self.silk_stereo.decode_range(
                    &mut range,
                    parsed.bandwidth,
                    duration_ms,
                    &mut native_left[..native_count],
                    &mut native_right[..native_count],
                    &mut fec_left[..native_count],
                    &mut fec_right[..native_count],
                )?;
            } else {
                self.silk_mono.decode_range(
                    &mut range,
                    parsed.bandwidth,
                    duration_ms,
                    &mut native_left[..native_count],
                    &mut fec_left[..native_count],
                )?;
                native_right[..native_count].copy_from_slice(&native_left[..native_count]);
            }
            let info = transition::decode_header(&mut range, Mode::Silk, usize::from(frame.len))?;
            packet_range = range.range();
            let redundancy = info.map(|info| {
                let payload_start = start + info.offset;
                (
                    &packet[payload_start..payload_start + info.len],
                    info.position,
                )
            });
            silk::resample_linear(
                &native_left[..native_count],
                &mut main_48k[0][..main_48k_count],
            )?;
            silk::resample_linear(
                &native_right[..native_count],
                &mut main_48k[1][..main_48k_count],
            )?;
            if let Some((payload, position)) = redundancy {
                if position == transition::RedundancyPosition::End {
                    self.reset_celt();
                }
                let redundant_range = self.decode_redundant_celt(
                    payload,
                    if parsed.stereo { 2 } else { 1 },
                    redundancy_end_band,
                    &mut redundant,
                )?;
                packet_range ^= redundant_range;
                cross_lap_redundancy(&mut main_48k, &redundant, main_48k_count, position)?;
                self.celt_transition_ready = position == transition::RedundancyPosition::End;
            }
            silk::resample_linear(
                &main_48k[0][..main_48k_count],
                &mut converted_left[..output_count],
            )?;
            silk::resample_linear(
                &main_48k[1][..main_48k_count],
                &mut converted_right[..output_count],
            )?;
            let output_start = index * output_count * usize::from(self.channels);
            for sample in 0..output_count {
                let left = converted_left[sample];
                let right = converted_right[sample];
                if self.channels == 1 {
                    output[output_start + sample] = float_to_i16((left + right) * 0.5);
                } else {
                    output[output_start + sample * 2] = float_to_i16(left);
                    output[output_start + sample * 2 + 1] = float_to_i16(right);
                }
            }
        }
        self.last_frame = Some(geometry);
        self.last_stateful_mode = Some(Mode::Silk);
        self.final_range = packet_range;
        Ok(frames)
    }

    fn conceal_frame(
        &mut self,
        geometry: LastFrame,
        output: &mut [i16],
        sample_rate: u32,
    ) -> Result<usize, Error> {
        let output_count = sample_rate as usize * geometry.duration_us as usize / 1_000_000;
        if output_count > MAX_SILK_FRAME_SAMPLES_AT_48_KHZ {
            return Err(Error::InvalidFrameSize);
        }
        let needed = output_count * usize::from(self.channels);
        if output.len() < needed {
            return Err(Error::BufferTooSmall);
        }
        let mut native = [[0.0f32; 960]; 2];
        let mut converted = [[0.0f32; MAX_SILK_FRAME_SAMPLES_AT_48_KHZ]; 2];
        match geometry.mode {
            Mode::Silk => {
                let native_rate = match geometry.bandwidth {
                    Bandwidth::Narrow => 8_000usize,
                    Bandwidth::Medium => 12_000,
                    Bandwidth::Wide => 16_000,
                    _ => return Err(Error::InvalidPacket),
                };
                let count = native_rate * geometry.duration_us as usize / 1_000_000;
                if geometry.stereo {
                    let [left, right] = &mut native;
                    self.silk_stereo
                        .conceal(native_rate as u32, count, left, right)?;
                } else {
                    self.silk_mono.conceal(count, &mut native[0])?;
                    let [left, right] = &mut native;
                    right[..count].copy_from_slice(&left[..count]);
                }
                for channel in 0..2 {
                    silk::resample_linear(
                        &native[channel][..count],
                        &mut converted[channel][..output_count],
                    )?;
                }
            }
            Mode::Celt | Mode::Hybrid => {
                let count = 48_000usize * geometry.duration_us as usize / 1_000_000;
                if count > 960 {
                    return Err(Error::InvalidFrameSize);
                }
                self.celt_plc[0].conceal(&mut native[0][..count]);
                if geometry.stereo {
                    self.celt_plc[1].conceal(&mut native[1][..count]);
                } else {
                    let [left, right] = &mut native;
                    right[..count].copy_from_slice(&left[..count]);
                }
                for channel in 0..2 {
                    silk::resample_linear(
                        &native[channel][..count],
                        &mut converted[channel][..output_count],
                    )?;
                }
            }
        }
        for sample in 0..output_count {
            if self.channels == 1 {
                output[sample] = float_to_i16((converted[0][sample] + converted[1][sample]) * 0.5);
            } else {
                output[sample * 2] = float_to_i16(converted[0][sample]);
                output[sample * 2 + 1] = float_to_i16(converted[1][sample]);
            }
        }
        Ok(output_count)
    }

    /// Conceals one frame using the most recently decoded packet geometry.
    pub fn decode_loss(&mut self, output: &mut [i16], sample_rate: u32) -> Result<usize, Error> {
        if !matches!(sample_rate, 8_000 | 12_000 | 16_000 | 24_000 | 48_000) {
            return Err(Error::InvalidFrameSize);
        }
        let last = self.last_frame.ok_or(Error::InvalidPacket)?;
        let output_count = self.conceal_frame(last, output, sample_rate)?;
        self.final_range = 0;
        Ok(output_count)
    }

    /// Decodes one SILK packet and its optional in-band LBRR copy in one state
    /// transition. `fec_output` is zero-filled where reconstructible protection
    /// is absent; zero- or one-byte DTX constituents conceal the regular output
    /// while leaving the FEC output zero-filled.
    pub fn decode_with_fec(
        &mut self,
        packet: &[u8],
        output: &mut [i16],
        fec_output: &mut [i16],
        sample_rate: u32,
    ) -> Result<FecDecodeResult, Error> {
        if !matches!(sample_rate, 8_000 | 12_000 | 16_000 | 24_000 | 48_000) {
            return Err(Error::InvalidFrameSize);
        }
        let parsed = Packet::parse(packet)?;
        if parsed.mode != Mode::Silk {
            return Err(Error::UnsupportedAudioMode);
        }
        let all_dtx = parsed.frames[..usize::from(parsed.frame_count)]
            .iter()
            .all(|frame| frame.len <= 1);
        let frames = sample_rate as usize
            * parsed.frame_duration_us as usize
            * usize::from(parsed.frame_count)
            / 1_000_000;
        let needed = frames
            .checked_mul(usize::from(self.channels))
            .ok_or(Error::BufferTooSmall)?;
        if output.len() < needed || fec_output.len() < needed {
            return Err(Error::BufferTooSmall);
        }
        output[..needed].fill(0);
        fec_output[..needed].fill(0);
        if all_dtx {
            self.prepare_dtx_decode(parsed.mode, parsed.stereo);
            let geometry = LastFrame {
                mode: parsed.mode,
                bandwidth: parsed.bandwidth,
                duration_us: parsed.frame_duration_us,
                stereo: parsed.stereo,
            };
            let constituent_samples = needed / usize::from(parsed.frame_count);
            for index in 0..usize::from(parsed.frame_count) {
                let start = index * constituent_samples;
                self.conceal_frame(
                    geometry,
                    &mut output[start..start + constituent_samples],
                    sample_rate,
                )?;
            }
            self.last_frame = Some(geometry);
            self.final_range = 0;
            return Ok(FecDecodeResult {
                frames,
                fec_frames: 0,
            });
        }
        self.prepare_silk_decode(parsed.stereo);
        let duration_ms = (parsed.frame_duration_us / 1_000) as u8;
        let native_rate = match parsed.bandwidth {
            Bandwidth::Narrow => 8_000usize,
            Bandwidth::Medium => 12_000,
            Bandwidth::Wide => 16_000,
            _ => return Err(Error::InvalidPacket),
        };
        let native_count = native_rate * usize::from(duration_ms) / 1_000;
        let output_count = sample_rate as usize * usize::from(duration_ms) / 1_000;
        if output_count > MAX_SILK_FRAME_SAMPLES_AT_48_KHZ {
            return Err(Error::InvalidFrameSize);
        }
        let interval_count = match duration_ms {
            10 | 20 => 1,
            40 => 2,
            60 => 3,
            _ => return Err(Error::InvalidFrameSize),
        };
        let native_interval_count = native_count / interval_count;
        let output_interval_count = output_count / interval_count;
        let mut native_left = [0.0f32; 960];
        let mut native_right = [0.0f32; 960];
        let mut fec_left = [0.0f32; 960];
        let mut fec_right = [0.0f32; 960];
        let mut converted_left = [0.0f32; MAX_SILK_FRAME_SAMPLES_AT_48_KHZ];
        let mut converted_right = [0.0f32; MAX_SILK_FRAME_SAMPLES_AT_48_KHZ];
        let mut converted_fec_left = [0.0f32; MAX_SILK_FRAME_SAMPLES_AT_48_KHZ];
        let mut converted_fec_right = [0.0f32; MAX_SILK_FRAME_SAMPLES_AT_48_KHZ];
        let mut fec_frames = 0usize;
        let mut packet_range = 0u32;
        let geometry = LastFrame {
            mode: parsed.mode,
            bandwidth: parsed.bandwidth,
            duration_us: parsed.frame_duration_us,
            stereo: parsed.stereo,
        };
        for index in 0..usize::from(parsed.frame_count) {
            let frame = parsed.frames[index];
            let start = usize::from(frame.offset);
            let end = start + usize::from(frame.len);
            if frame.len <= 1 {
                let base = index * output_count * usize::from(self.channels);
                let end = base + output_count * usize::from(self.channels);
                self.conceal_frame(geometry, &mut output[base..end], sample_rate)?;
                packet_range = 0;
                continue;
            }
            let fec_mask = if parsed.stereo {
                let mut range = RangeDecoder::new(&packet[start..end]);
                let result = self.silk_stereo.decode_range(
                    &mut range,
                    parsed.bandwidth,
                    duration_ms,
                    &mut native_left[..native_count],
                    &mut native_right[..native_count],
                    &mut fec_left[..native_count],
                    &mut fec_right[..native_count],
                )?;
                packet_range = range.range();
                result.mid_fec_mask
            } else {
                let mut range = RangeDecoder::new(&packet[start..end]);
                let result = self.silk_mono.decode_range(
                    &mut range,
                    parsed.bandwidth,
                    duration_ms,
                    &mut native_left[..native_count],
                    &mut fec_left[..native_count],
                )?;
                packet_range = range.range();
                native_right[..native_count].copy_from_slice(&native_left[..native_count]);
                fec_right[..native_count].copy_from_slice(&fec_left[..native_count]);
                result.fec_mask
            };
            silk::resample_linear(
                &native_left[..native_count],
                &mut converted_left[..output_count],
            )?;
            silk::resample_linear(
                &native_right[..native_count],
                &mut converted_right[..output_count],
            )?;
            converted_fec_left[..output_count].fill(0.0);
            converted_fec_right[..output_count].fill(0.0);
            let fec_samples = native_interval_count
                .checked_mul(fec_mask.count_ones() as usize)
                .ok_or(Error::InvalidFrameSize)?;
            let mut interval = 0usize;
            while interval < interval_count {
                if fec_mask & (1 << interval) == 0 {
                    interval += 1;
                    continue;
                }
                let run_start = interval;
                interval += 1;
                while interval < interval_count && fec_mask & (1 << interval) != 0 {
                    interval += 1;
                }
                let run_intervals = interval - run_start;
                let native_start = run_start * native_interval_count;
                let native_run_count = run_intervals * native_interval_count;
                let output_start = run_start * output_interval_count;
                let output_run_count = run_intervals * output_interval_count;
                silk::resample_linear(
                    &fec_left[native_start..native_start + native_run_count],
                    &mut converted_fec_left[output_start..output_start + output_run_count],
                )?;
                silk::resample_linear(
                    &fec_right[native_start..native_start + native_run_count],
                    &mut converted_fec_right[output_start..output_start + output_run_count],
                )?;
            }
            let scaled_fec_samples = fec_samples
                .checked_mul(sample_rate as usize)
                .ok_or(Error::InvalidFrameSize)?;
            if scaled_fec_samples % native_rate != 0 {
                return Err(Error::InvalidFrameSize);
            }
            let output_fec_samples = scaled_fec_samples / native_rate;
            fec_frames = fec_frames
                .checked_add(output_fec_samples)
                .ok_or(Error::InvalidFrameSize)?;
            let base = index * output_count * usize::from(self.channels);
            for sample in 0..output_count {
                if self.channels == 1 {
                    output[base + sample] =
                        float_to_i16((converted_left[sample] + converted_right[sample]) * 0.5);
                    fec_output[base + sample] = float_to_i16(
                        (converted_fec_left[sample] + converted_fec_right[sample]) * 0.5,
                    );
                } else {
                    output[base + sample * 2] = float_to_i16(converted_left[sample]);
                    output[base + sample * 2 + 1] = float_to_i16(converted_right[sample]);
                    fec_output[base + sample * 2] = float_to_i16(converted_fec_left[sample]);
                    fec_output[base + sample * 2 + 1] = float_to_i16(converted_fec_right[sample]);
                }
            }
        }
        self.last_frame = Some(geometry);
        self.last_stateful_mode = Some(Mode::Silk);
        self.final_range = packet_range;
        Ok(FecDecodeResult { frames, fec_frames })
    }

    fn decode_celt_packet(
        &mut self,
        packet: &[u8],
        parsed: &Packet,
        output: &mut [i16],
        sample_rate: u32,
    ) -> Result<usize, Error> {
        let lm = match parsed.frame_duration_us {
            2_500 => 0,
            5_000 => 1,
            10_000 => 2,
            20_000 => 3,
            _ => return Err(Error::InvalidFrameSize),
        };
        let coded_channels = if parsed.stereo { 2 } else { 1 };
        let end_band = match parsed.bandwidth {
            Bandwidth::Narrow => 13,
            Bandwidth::Wide => 17,
            Bandwidth::SuperWide => 19,
            Bandwidth::Full => bands::BAND_COUNT,
            Bandwidth::Medium => return Err(Error::InvalidPacket),
        };
        let stereo_changed = self.previous_stereo != Some(parsed.stereo);
        let mode_changed = self
            .last_stateful_mode
            .is_some_and(|mode| mode != Mode::Celt);
        if stereo_changed || (mode_changed && !self.celt_transition_ready) {
            self.reset_celt();
        }
        self.celt_transition_ready = false;
        self.previous_stereo = Some(parsed.stereo);
        let native_count = 120usize << lm;
        let output_count = sample_rate as usize * parsed.frame_duration_us as usize / 1_000_000;
        let mut spectra = [0.0f32; 1_920];
        let mut pulses = [0i32; 1_920];
        let mut tf_scratch = [0.0f32; 176];
        let mut recurrence = [0u32; pvq::MAX_PULSES + 1];
        let mut spectral = [0.0f32; 960];
        let mut transform = [0.0f32; 1_080];
        let mut native = [[0.0f32; 960]; 2];
        let mut converted = [[0.0f32; 960]; 2];
        let mut packet_range = 0u32;
        let geometry = LastFrame {
            mode: parsed.mode,
            bandwidth: parsed.bandwidth,
            duration_us: parsed.frame_duration_us,
            stereo: parsed.stereo,
        };
        for frame_index in 0..usize::from(parsed.frame_count) {
            let frame = parsed.frames[frame_index];
            if frame.len <= 1 {
                let output_start = frame_index * output_count * usize::from(self.channels);
                let output_end = output_start + output_count * usize::from(self.channels);
                self.conceal_frame(geometry, &mut output[output_start..output_end], sample_rate)?;
                packet_range = 0;
                continue;
            }
            let start = usize::from(frame.offset);
            let end = start + usize::from(frame.len);
            let mut decoder = RangeDecoder::new(&packet[start..end]);
            let config = celt_frame::FrameConfig {
                frame_bytes: usize::from(frame.len),
                channels: coded_channels,
                lm,
                start: 0,
                end: end_band,
            };
            let mut residuals = [[0i16; bands::BAND_COUNT]; 2];
            let plan = celt_frame::decode_plan(
                &mut decoder,
                config,
                &mut self.celt_energies,
                &mut residuals,
            )?;
            let shapes = celt_frame::decode_shapes(
                &mut decoder,
                config,
                &plan,
                &mut self.celt_energies,
                &self.celt_previous_energies,
                &self.celt_older_energies,
                &mut spectra,
                &mut pulses,
                &mut tf_scratch,
                &mut recurrence,
                self.celt_seed,
            )?;
            packet_range = decoder.range();
            self.celt_seed = shapes.seed;
            for channel in 0..usize::from(coded_channels) {
                self.celt_synthesis.synthesize_channel(
                    channel,
                    &spectra[channel * native_count..(channel + 1) * native_count],
                    lm,
                    plan.transient,
                    0,
                    end_band,
                    &self.celt_energies.values()[channel],
                    &mut spectral,
                    &mut transform,
                    &mut native[channel][..native_count],
                )?;
                silk::resample_linear(
                    &native[channel][..native_count],
                    &mut converted[channel][..output_count],
                )?;
            }
            if coded_channels == 1 {
                let [left, right] = &mut converted;
                right[..output_count].copy_from_slice(&left[..output_count]);
            }
            self.celt_plc[0].push(&native[0][..native_count]);
            if coded_channels == 2 {
                self.celt_plc[1].push(&native[1][..native_count]);
            } else {
                self.celt_plc[1].push(&native[0][..native_count]);
            }
            let output_start = frame_index * output_count * usize::from(self.channels);
            for sample in 0..output_count {
                if self.channels == 1 {
                    output[output_start + sample] =
                        float_to_i16((converted[0][sample] + converted[1][sample]) * 0.5);
                } else {
                    output[output_start + sample * 2] = float_to_i16(converted[0][sample]);
                    output[output_start + sample * 2 + 1] = float_to_i16(converted[1][sample]);
                }
            }
            self.celt_older_energies = self.celt_previous_energies;
            self.celt_previous_energies = self.celt_energies;
        }
        self.last_frame = Some(geometry);
        self.last_stateful_mode = Some(Mode::Celt);
        self.final_range = packet_range;
        Ok(output_count * usize::from(parsed.frame_count))
    }

    fn decode_hybrid_packet(
        &mut self,
        packet: &[u8],
        parsed: &Packet,
        output: &mut [i16],
        sample_rate: u32,
    ) -> Result<usize, Error> {
        let lm = match parsed.frame_duration_us {
            10_000 => 2,
            20_000 => 3,
            _ => return Err(Error::InvalidFrameSize),
        };
        let duration_ms = (parsed.frame_duration_us / 1_000) as u8;
        let coded_channels = if parsed.stereo { 2 } else { 1 };
        let end_band = match parsed.bandwidth {
            Bandwidth::SuperWide => 19,
            Bandwidth::Full => bands::BAND_COUNT,
            _ => return Err(Error::InvalidPacket),
        };
        let stereo_changed = self.previous_stereo != Some(parsed.stereo);
        let previous_mode = self.last_stateful_mode;
        self.celt_transition_ready = false;
        if stereo_changed || previous_mode == Some(Mode::Celt) {
            self.silk_mono.reset();
            self.silk_stereo.reset();
        }
        if stereo_changed {
            self.reset_celt();
        }
        self.previous_stereo = Some(parsed.stereo);
        let mut celt_transition_pending =
            previous_mode.is_some_and(|mode| mode != Mode::Hybrid) && !stereo_changed;
        let silk_count = 16_000 * usize::from(duration_ms) / 1_000;
        let native_count = 120usize << lm;
        let output_count = sample_rate as usize * usize::from(duration_ms) / 1_000;
        let mut silk_left = [0.0f32; 320];
        let mut silk_right = [0.0f32; 320];
        let mut fec_left = [0.0f32; 320];
        let mut fec_right = [0.0f32; 320];
        let mut low = [[0.0f32; 960]; 2];
        let mut spectra = [0.0f32; 1_920];
        let mut pulses = [0i32; 1_920];
        let mut tf_scratch = [0.0f32; 176];
        let mut recurrence = [0u32; pvq::MAX_PULSES + 1];
        let mut spectral = [0.0f32; 960];
        let mut transform = [0.0f32; 1_080];
        let mut high = [[0.0f32; 960]; 2];
        let mut converted = [[0.0f32; 960]; 2];
        let mut redundant = [[0.0f32; 240]; 2];
        let mut packet_range = 0u32;
        let geometry = LastFrame {
            mode: parsed.mode,
            bandwidth: parsed.bandwidth,
            duration_us: parsed.frame_duration_us,
            stereo: parsed.stereo,
        };
        for frame_index in 0..usize::from(parsed.frame_count) {
            let frame = parsed.frames[frame_index];
            if frame.len <= 1 {
                let output_start = frame_index * output_count * usize::from(self.channels);
                let output_end = output_start + output_count * usize::from(self.channels);
                if celt_transition_pending {
                    self.reset_celt();
                    celt_transition_pending = false;
                }
                self.conceal_frame(geometry, &mut output[output_start..output_end], sample_rate)?;
                self.celt_transition_ready = false;
                packet_range = 0;
                continue;
            }
            let start = usize::from(frame.offset);
            let end = start + usize::from(frame.len);
            let mut range = RangeDecoder::new(&packet[start..end]);
            if parsed.stereo {
                self.silk_stereo.decode_range(
                    &mut range,
                    Bandwidth::Wide,
                    duration_ms,
                    &mut silk_left[..silk_count],
                    &mut silk_right[..silk_count],
                    &mut fec_left[..silk_count],
                    &mut fec_right[..silk_count],
                )?;
            } else {
                self.silk_mono.decode_range(
                    &mut range,
                    Bandwidth::Wide,
                    duration_ms,
                    &mut silk_left[..silk_count],
                    &mut fec_left[..silk_count],
                )?;
                silk_right[..silk_count].copy_from_slice(&silk_left[..silk_count]);
            }
            let redundancy =
                transition::decode_header(&mut range, Mode::Hybrid, usize::from(frame.len))?;
            if celt_transition_pending {
                let continues_celt = redundancy
                    .is_some_and(|info| info.position == transition::RedundancyPosition::Beginning);
                if !continues_celt {
                    self.reset_celt();
                }
                celt_transition_pending = false;
            }
            let redundant_payload = redundancy.map(|info| {
                let payload_start = start + info.offset;
                (
                    &packet[payload_start..payload_start + info.len],
                    info.position,
                )
            });
            let mut redundant_range = 0u32;
            if let Some((payload, transition::RedundancyPosition::Beginning)) = redundant_payload {
                redundant_range =
                    self.decode_redundant_celt(payload, coded_channels, end_band, &mut redundant)?;
            }
            silk::resample_linear(&silk_left[..silk_count], &mut low[0][..native_count])?;
            silk::resample_linear(&silk_right[..silk_count], &mut low[1][..native_count])?;
            let config = celt_frame::FrameConfig {
                frame_bytes: range.storage_len(),
                channels: coded_channels,
                lm,
                start: 17,
                end: end_band,
            };
            let mut residuals = [[0i16; bands::BAND_COUNT]; 2];
            let plan = celt_frame::decode_plan(
                &mut range,
                config,
                &mut self.celt_energies,
                &mut residuals,
            )?;
            let shapes = celt_frame::decode_shapes(
                &mut range,
                config,
                &plan,
                &mut self.celt_energies,
                &self.celt_previous_energies,
                &self.celt_older_energies,
                &mut spectra,
                &mut pulses,
                &mut tf_scratch,
                &mut recurrence,
                self.celt_seed,
            )?;
            packet_range = range.range();
            self.celt_seed = shapes.seed;
            for channel in 0..usize::from(coded_channels) {
                self.celt_synthesis.synthesize_channel(
                    channel,
                    &spectra[channel * native_count..(channel + 1) * native_count],
                    lm,
                    plan.transient,
                    17,
                    end_band,
                    &self.celt_energies.values()[channel],
                    &mut spectral,
                    &mut transform,
                    &mut high[channel][..native_count],
                )?;
            }
            if coded_channels == 1 {
                let [left, right] = &mut high;
                right[..native_count].copy_from_slice(&left[..native_count]);
            }
            for channel in 0..2 {
                for sample in 0..native_count {
                    high[channel][sample] += low[channel][sample];
                }
            }
            if let Some((payload, transition::RedundancyPosition::End)) = redundant_payload {
                redundant_range =
                    self.decode_redundant_celt(payload, coded_channels, end_band, &mut redundant)?;
                self.celt_transition_ready = true;
            }
            packet_range ^= redundant_range;
            if let Some((_, position)) = redundant_payload {
                cross_lap_redundancy(&mut high, &redundant, native_count, position)?;
            }
            for channel in 0..2 {
                silk::resample_linear(
                    &high[channel][..native_count],
                    &mut converted[channel][..output_count],
                )?;
                self.celt_plc[channel].push(&high[channel][..native_count]);
            }
            let output_start = frame_index * output_count * usize::from(self.channels);
            for sample in 0..output_count {
                if self.channels == 1 {
                    output[output_start + sample] =
                        float_to_i16((converted[0][sample] + converted[1][sample]) * 0.5);
                } else {
                    output[output_start + sample * 2] = float_to_i16(converted[0][sample]);
                    output[output_start + sample * 2 + 1] = float_to_i16(converted[1][sample]);
                }
            }
            self.celt_older_energies = self.celt_previous_energies;
            self.celt_previous_energies = self.celt_energies;
        }
        self.last_frame = Some(geometry);
        self.last_stateful_mode = Some(Mode::Hybrid);
        self.final_range = packet_range;
        Ok(output_count * usize::from(parsed.frame_count))
    }

    fn decode_redundant_celt(
        &mut self,
        payload: &[u8],
        coded_channels: u8,
        end_band: usize,
        output: &mut [[f32; 240]; 2],
    ) -> Result<u32, Error> {
        let config = celt_frame::FrameConfig {
            frame_bytes: payload.len(),
            channels: coded_channels,
            lm: 1,
            start: 0,
            end: end_band,
        };
        let mut decoder = RangeDecoder::new(payload);
        let mut residuals = [[0i16; bands::BAND_COUNT]; 2];
        let plan = celt_frame::decode_plan(
            &mut decoder,
            config,
            &mut self.celt_energies,
            &mut residuals,
        )?;
        let mut spectra = [0.0f32; 480];
        let mut pulses = [0i32; 480];
        let mut tf_scratch = [0.0f32; 176];
        let mut recurrence = [0u32; pvq::MAX_PULSES + 1];
        let shapes = celt_frame::decode_shapes(
            &mut decoder,
            config,
            &plan,
            &mut self.celt_energies,
            &self.celt_previous_energies,
            &self.celt_older_energies,
            &mut spectra,
            &mut pulses,
            &mut tf_scratch,
            &mut recurrence,
            self.celt_seed,
        )?;
        self.celt_seed = shapes.seed;
        let mut spectral = [0.0f32; 240];
        let mut transform = [0.0f32; 360];
        for channel in 0..usize::from(coded_channels) {
            self.celt_synthesis.synthesize_channel(
                channel,
                &spectra[channel * 240..(channel + 1) * 240],
                1,
                plan.transient,
                0,
                end_band,
                &self.celt_energies.values()[channel],
                &mut spectral,
                &mut transform,
                &mut output[channel],
            )?;
        }
        if coded_channels == 1 {
            let [left, right] = output;
            right.copy_from_slice(left);
        }
        Ok(decoder.range())
    }
}

fn cross_lap_redundancy<const N: usize>(
    main: &mut [[f32; N]; 2],
    redundant: &[[f32; 240]; 2],
    main_len: usize,
    position: transition::RedundancyPosition,
) -> Result<(), Error> {
    if main_len < 240 {
        return Err(Error::InvalidFrameSize);
    }
    let mut window = [0.0f32; 120];
    celt::make_window(&mut window)?;
    for channel in 0..2 {
        match position {
            transition::RedundancyPosition::Beginning => {
                main[channel][..120].copy_from_slice(&redundant[channel][..120]);
                for index in 0..120 {
                    main[channel][120 + index] = redundant[channel][120 + index]
                        * window[119 - index]
                        + main[channel][120 + index] * window[index];
                }
            }
            transition::RedundancyPosition::End => {
                let start = main_len - 120;
                for index in 0..120 {
                    main[channel][start + index] = main[channel][start + index]
                        * window[119 - index]
                        + redundant[channel][120 + index] * window[index];
                }
            }
        }
    }
    Ok(())
}

fn float_to_i16(sample: f32) -> i16 {
    (sample.clamp(-1.0, 1.0) * 32_767.0) as i16
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        silk::{QuantizationOffset, SignalType},
        silk_codec::MonoFrameParameters,
        silk_entropy::MAX_EXCITATION_SAMPLES,
        silk_frame::{ChannelHeader, LayerHeader},
        silk_lsf::{LsfIndices, Stage2},
        silk_packet::{
            MonoPayloadDecoder, MonoPayloadEncoder, StereoFrameParameters, StereoPayloadEncoder,
        },
        silk_stereo::prediction_from_indices,
    };

    #[test]
    fn dtx_round_trip() {
        let mut bytes = [0; 1];
        assert_eq!(encode_dtx(31, true, &mut bytes), Ok(1));
        let p = Packet::parse(&bytes).unwrap();
        assert_eq!(
            (p.mode, p.bandwidth, p.frame_duration_us, p.stereo),
            (Mode::Celt, Bandwidth::Full, 20_000, true)
        );
        let mut pcm = [1; 1920];
        assert_eq!(
            Decoder::new(2).unwrap().decode(&bytes, &mut pcm, 48_000),
            Ok(960)
        );
        assert_eq!(pcm, [0; 1920]);
    }

    #[test]
    fn one_byte_frames_are_dtx_in_every_coding_mode() {
        for toc in [0x00, 0x78, 0x80, 0x88, 0xf8] {
            for payload in [0x00, 0x7f, 0xff] {
                let mut decoder = Decoder::new(2).unwrap();
                let mut output = [1i16; 5_760];
                let samples = decoder
                    .decode(&[toc, payload], &mut output, 48_000)
                    .unwrap();
                assert!(samples > 0);
                assert!(output[..samples * 2].iter().all(|&sample| sample == 0));
                assert_eq!(decoder.final_range(), 0);
            }
        }
    }

    #[test]
    fn any_valid_one_byte_packet_is_treated_as_dtx_range_zero() {
        for toc in u8::MIN..=u8::MAX {
            let packet = [toc, 0x00];
            let Ok(parsed) = Packet::parse(&packet) else {
                continue;
            };
            if !parsed.frames[..usize::from(parsed.frame_count)]
                .iter()
                .all(|frame| frame.len <= 1)
            {
                continue;
            }
            let mut decoder = Decoder::new(2).unwrap();
            let samples = 48_000usize
                .checked_mul(parsed.frame_duration_us as usize)
                .and_then(|value| value.checked_div(1_000_000))
                .and_then(|value| value.checked_mul(usize::from(parsed.frame_count)))
                .unwrap();
            let mut output = [0i16; 23_040];
            let samples = decoder
                .decode(&packet, &mut output[..samples * 2], 48_000)
                .unwrap();
            assert!(samples > 0);
            assert!(output[..samples * 2].iter().all(|&sample| sample == 0));
            assert_eq!(decoder.final_range(), 0);
        }
    }

    #[test]
    fn mixed_packets_match_sequential_stateful_dtx_in_every_mode() {
        let mut input = [0i16; 960];
        for (index, sample) in input.iter_mut().enumerate() {
            *sample = (((index % 43) as i32 - 21) * 900) as i16;
        }
        let mut silk_packet = [0u8; MAX_FRAME_BYTES + 1];
        let silk_len = Encoder::new(1)
            .unwrap()
            .encode(&input, 48_000, &mut silk_packet)
            .unwrap();
        let mut celt_packet = [0u8; MAX_FRAME_BYTES + 1];
        let celt_len = Encoder::new(1)
            .unwrap()
            .encode_celt(&input, 48_000, &mut celt_packet)
            .unwrap();
        let mut hybrid_packet = [0u8; MAX_FRAME_BYTES + 1];
        let hybrid_len = Encoder::new(1)
            .unwrap()
            .encode_hybrid(&input, 48_000, &mut hybrid_packet)
            .unwrap();

        for (mode, active_packet, supports_fec) in [
            ("silk", &silk_packet[..silk_len], true),
            ("celt", &celt_packet[..celt_len], false),
            ("hybrid", &hybrid_packet[..hybrid_len], false),
        ] {
            let config = active_packet[0] >> 3;
            let active_payload = &active_packet[1..];

            for dtx_byte in [0x00u8, 0x7f, 0xff] {
                let dtx = [dtx_byte];
                let dtx_packet = [config << 3, dtx_byte];
                for dtx_first in [true, false] {
                    let frame_payloads: [&[u8]; 2] = if dtx_first {
                        [&dtx, active_payload]
                    } else {
                        [active_payload, &dtx]
                    };
                    let mut mixed_packet = [0u8; 2_560];
                    let mixed_len =
                        packetize(config, false, &frame_payloads, 0, &mut mixed_packet).unwrap();
                    let sequential_packets = if dtx_first {
                        [&dtx_packet[..], active_packet]
                    } else {
                        [active_packet, &dtx_packet[..]]
                    };
                    let mut expected = [0i16; 1_920];
                    let mut expected_decoder = Decoder::new(1).unwrap();
                    for (index, sequential_packet) in sequential_packets.iter().enumerate() {
                        assert_eq!(
                            expected_decoder.decode(
                                sequential_packet,
                                &mut expected[index * 960..(index + 1) * 960],
                                48_000,
                            ),
                            Ok(960),
                        );
                    }
                    let expected_range = expected_decoder.final_range();
                    let mut output = [1i16; 1_920];
                    let mut decoder = Decoder::new(1).unwrap();
                    assert_eq!(
                        decoder.decode(&mixed_packet[..mixed_len], &mut output, 48_000),
                        Ok(1_920),
                        "mode={mode} dtx_byte={dtx_byte:#04x} dtx_first={dtx_first}",
                    );
                    assert_eq!(output, expected);
                    assert_eq!(decoder.final_range(), expected_range);
                    if !dtx_first {
                        assert!(output[960..].iter().any(|&sample| sample != 0));
                    }

                    if supports_fec {
                        let mut expected_regular = [0i16; 1_920];
                        let mut expected_fec = [0i16; 1_920];
                        let mut expected_fec_frames = 0usize;
                        let mut sequential_decoder = Decoder::new(1).unwrap();
                        for (index, sequential_packet) in sequential_packets.iter().enumerate() {
                            let result = sequential_decoder
                                .decode_with_fec(
                                    sequential_packet,
                                    &mut expected_regular[index * 960..(index + 1) * 960],
                                    &mut expected_fec[index * 960..(index + 1) * 960],
                                    48_000,
                                )
                                .unwrap();
                            assert_eq!(result.frames, 960);
                            expected_fec_frames += result.fec_frames;
                        }
                        let expected_range = sequential_decoder.final_range();
                        let mut regular = [1i16; 1_920];
                        let mut fec = [1i16; 1_920];
                        let mut fec_decoder = Decoder::new(1).unwrap();
                        assert_eq!(
                            fec_decoder.decode_with_fec(
                                &mixed_packet[..mixed_len],
                                &mut regular,
                                &mut fec,
                                48_000,
                            ),
                            Ok(FecDecodeResult {
                                frames: 1_920,
                                fec_frames: expected_fec_frames,
                            }),
                            "mode={mode} dtx_byte={dtx_byte:#04x} dtx_first={dtx_first}",
                        );
                        assert_eq!(regular, expected_regular);
                        assert_eq!(fec, expected_fec);
                        assert_eq!(fec_decoder.final_range(), expected_range);
                    }
                }
            }
        }
    }

    #[test]
    fn one_byte_dtx_matches_explicit_loss_and_advances_state() {
        let mut input = [0i16; 960];
        for (index, sample) in input.iter_mut().enumerate() {
            *sample = (((index % 43) as i32 - 21) * 900) as i16;
        }
        let mut silk_packet = [0u8; MAX_FRAME_BYTES + 1];
        let silk_len = Encoder::new(1)
            .unwrap()
            .encode(&input, 48_000, &mut silk_packet)
            .unwrap();
        let mut celt_packet = [0u8; MAX_FRAME_BYTES + 1];
        let celt_len = Encoder::new(1)
            .unwrap()
            .encode_celt(&input, 48_000, &mut celt_packet)
            .unwrap();
        let mut hybrid_packet = [0u8; MAX_FRAME_BYTES + 1];
        let hybrid_len = Encoder::new(1)
            .unwrap()
            .encode_hybrid(&input, 48_000, &mut hybrid_packet)
            .unwrap();

        for (mode, active_packet) in [
            ("silk", &silk_packet[..silk_len]),
            ("celt", &celt_packet[..celt_len]),
            ("hybrid", &hybrid_packet[..hybrid_len]),
        ] {
            let dtx_packet = [(active_packet[0] >> 3) << 3, 0x7f];
            let mut dtx_decoder = Decoder::new(1).unwrap();
            let mut loss_decoder = Decoder::new(1).unwrap();
            let mut scratch = [0i16; 960];
            dtx_decoder
                .decode(active_packet, &mut scratch, 48_000)
                .unwrap();
            loss_decoder
                .decode(active_packet, &mut scratch, 48_000)
                .unwrap();
            let mut dtx = [0i16; 960];
            let mut loss = [0i16; 960];
            assert_eq!(
                dtx_decoder.decode(&dtx_packet, &mut dtx, 48_000),
                Ok(960),
                "mode={mode}",
            );
            assert_eq!(loss_decoder.decode_loss(&mut loss, 48_000), Ok(960));
            assert_eq!(dtx, loss, "mode={mode}");
            assert!(dtx.iter().any(|&sample| sample != 0), "mode={mode}");

            let mut after_dtx = [0i16; 960];
            let mut after_loss = [0i16; 960];
            dtx_decoder
                .decode(active_packet, &mut after_dtx, 48_000)
                .unwrap();
            loss_decoder
                .decode(active_packet, &mut after_loss, 48_000)
                .unwrap();
            assert_eq!(after_dtx, after_loss, "mode={mode}");
            assert_eq!(dtx_decoder.final_range(), loss_decoder.final_range());
        }

        let active_packet = &silk_packet[..silk_len];
        let dtx_packet = [(active_packet[0] >> 3) << 3, 0x7f];
        let mut dtx_decoder = Decoder::new(1).unwrap();
        let mut loss_decoder = Decoder::new(1).unwrap();
        let mut scratch = [0i16; 960];
        let mut fec_scratch = [0i16; 960];
        dtx_decoder
            .decode_with_fec(active_packet, &mut scratch, &mut fec_scratch, 48_000)
            .unwrap();
        loss_decoder
            .decode_with_fec(active_packet, &mut scratch, &mut fec_scratch, 48_000)
            .unwrap();
        let mut dtx = [0i16; 960];
        let mut dtx_fec = [1i16; 960];
        assert_eq!(
            dtx_decoder.decode_with_fec(&dtx_packet, &mut dtx, &mut dtx_fec, 48_000),
            Ok(FecDecodeResult {
                frames: 960,
                fec_frames: 0,
            }),
        );
        let mut loss = [0i16; 960];
        assert_eq!(loss_decoder.decode_loss(&mut loss, 48_000), Ok(960));
        assert_eq!(dtx, loss);
        assert!(dtx_fec.iter().all(|&sample| sample == 0));

        let mut after_dtx = [0i16; 960];
        let mut after_dtx_fec = [0i16; 960];
        let mut after_loss = [0i16; 960];
        let mut after_loss_fec = [0i16; 960];
        let dtx_result = dtx_decoder
            .decode_with_fec(active_packet, &mut after_dtx, &mut after_dtx_fec, 48_000)
            .unwrap();
        let loss_result = loss_decoder
            .decode_with_fec(active_packet, &mut after_loss, &mut after_loss_fec, 48_000)
            .unwrap();
        assert_eq!(dtx_result, loss_result);
        assert_eq!(after_dtx, after_loss);
        assert_eq!(after_dtx_fec, after_loss_fec);
        assert_eq!(dtx_decoder.final_range(), loss_decoder.final_range());
    }

    #[test]
    fn celt_dtx_framing_preserves_end_redundancy_transition_state() {
        let mut transition_input = [0i16; 240];
        let mut silk_input = [0i16; 960];
        let mut celt_input = [0i16; 960];
        for (index, sample) in transition_input.iter_mut().enumerate() {
            *sample = (((index % 29) as i32 - 14) * 500) as i16;
        }
        for (index, sample) in silk_input.iter_mut().enumerate() {
            *sample = (((index % 37) as i32 - 18) * 700) as i16;
        }
        for (index, sample) in celt_input.iter_mut().enumerate() {
            *sample = (((index % 43) as i32 - 21) * 900) as i16;
        }

        let mut redundant = [0u8; 64];
        let redundant_len = Encoder::new(1)
            .unwrap()
            .encode_celt_redundancy(&transition_input, 48_000, &mut redundant)
            .unwrap();
        let mut priming_packet = [0u8; MAX_FRAME_BYTES + 1];
        let priming_len = Encoder::new(1)
            .unwrap()
            .encode_silk_with_redundancy(
                &silk_input,
                48_000,
                Bandwidth::Narrow,
                20_000,
                &redundant[..redundant_len],
                false,
                &mut priming_packet,
            )
            .unwrap();
        let mut active_packet = [0u8; MAX_FRAME_BYTES + 1];
        let active_len = Encoder::new(1)
            .unwrap()
            .encode_celt(&celt_input, 48_000, &mut active_packet)
            .unwrap();
        let active_packet = &active_packet[..active_len];
        let config = active_packet[0] >> 3;
        let dtx_payload = [0x7fu8];
        let dtx_packet = [config << 3, dtx_payload[0]];
        let mut mixed_packet = [0u8; 2_560];
        let mixed_len = packetize(
            config,
            false,
            &[&dtx_payload, &active_packet[1..]],
            0,
            &mut mixed_packet,
        )
        .unwrap();

        let mut split = Decoder::new(1).unwrap();
        let mut combined = Decoder::new(1).unwrap();
        let mut scratch = [0i16; 960];
        split
            .decode(&priming_packet[..priming_len], &mut scratch, 48_000)
            .unwrap();
        combined
            .decode(&priming_packet[..priming_len], &mut scratch, 48_000)
            .unwrap();
        let mut expected = [0i16; 1_920];
        split
            .decode(&dtx_packet, &mut expected[..960], 48_000)
            .unwrap();
        split
            .decode(active_packet, &mut expected[960..], 48_000)
            .unwrap();
        let mut actual = [0i16; 1_920];
        assert_eq!(
            combined.decode(&mixed_packet[..mixed_len], &mut actual, 48_000),
            Ok(1_920),
        );
        assert_eq!(actual, expected);
        assert_eq!(combined.final_range(), split.final_range());
    }

    #[test]
    fn transition_cross_lap_uses_redundant_halves_at_the_requested_edge() {
        let mut main = [[1.0f32; 960]; 2];
        let redundant = [[0.0f32; 240]; 2];
        cross_lap_redundancy(
            &mut main,
            &redundant,
            960,
            transition::RedundancyPosition::Beginning,
        )
        .unwrap();
        assert!(main[0][..120].iter().all(|&sample| sample == 0.0));
        assert!(main[0][120] < main[0][239]);

        let mut main = [[1.0f32; 960]; 2];
        cross_lap_redundancy(
            &mut main,
            &redundant,
            960,
            transition::RedundancyPosition::End,
        )
        .unwrap();
        assert!(main[0][840] > main[0][959]);
        assert!(main[0][..840].iter().all(|&sample| sample == 1.0));
    }
    #[test]
    fn parses_all_packet_codes() {
        assert_eq!(Packet::parse(&[0, 1, 2]).unwrap().frame_count, 1);
        assert_eq!(Packet::parse(&[1, 1, 2, 3, 4]).unwrap().frame_count, 2);
        assert_eq!(Packet::parse(&[2, 1, 9, 8]).unwrap().frames[0].len, 1);
        assert_eq!(Packet::parse(&[3, 2, 9, 8]).unwrap().frame_count, 2);
    }
    #[test]
    fn packetizer_round_trips_every_framing_code_and_padding() {
        let a = [1u8, 2, 3];
        let b = [4u8, 5, 6];
        let c = [7u8; 260];
        let cases: &[(&[&[u8]], usize, u8)] = &[
            (&[&a], 0, 0),
            (&[&a, &b], 0, 1),
            (&[&a, &c], 0, 2),
            (&[&a, &b, &c], 300, 3),
        ];
        for &(frames, padding, code) in cases {
            let mut bytes = [0u8; 2_048];
            let size = packetize(31, true, frames, padding, &mut bytes).unwrap();
            assert_eq!(bytes[0] & 3, code);
            let parsed = Packet::parse(&bytes[..size]).unwrap();
            assert_eq!(usize::from(parsed.frame_count), frames.len());
            assert!(parsed.stereo);
            for (index, expected) in frames.iter().enumerate() {
                let frame = parsed.frames[index];
                let start = usize::from(frame.offset);
                let end = start + usize::from(frame.len);
                assert_eq!(&bytes[start..end], *expected);
            }
        }
    }

    #[test]
    fn public_decoder_decodes_and_resamples_a_silk_packet() {
        let parameters = MonoFrameParameters {
            signal: SignalType::Unvoiced,
            quantization: QuantizationOffset::Low,
            gain_symbols: [20, 4, 4, 4],
            lsf: LsfIndices {
                stage1: 3,
                stage2: Stage2 {
                    order: 10,
                    index: [0; 16],
                },
                interpolation_q2: Some(4),
            },
            primary_pitch: None,
            contour_index: 0,
            ltp: None,
            seed: 1,
            rate_level: 0,
            excitation: [0; MAX_EXCITATION_SAMPLES],
        };
        let header = LayerHeader {
            channels: 1,
            frames: 1,
            channel: [
                ChannelHeader { vad: 1, lbrr: 0 },
                ChannelHeader { vad: 0, lbrr: 0 },
            ],
        };
        let mut packet = [0u8; MAX_FRAME_BYTES + 1];
        packet[0] = 1 << 3;
        let payload = MonoPayloadEncoder::new()
            .encode(
                &mut packet[1..],
                Bandwidth::Narrow,
                20,
                header,
                &[parameters],
                &[None],
            )
            .unwrap();
        assert!(payload <= MAX_FRAME_BYTES);
        let mut native = [0.0; 160];
        let mut fec = [0.0; 160];
        assert!(
            silk_packet::MonoPayloadDecoder::new()
                .decode(
                    &packet[1..payload + 1],
                    Bandwidth::Narrow,
                    20,
                    &mut native,
                    &mut fec,
                )
                .is_ok()
        );
        let mut pcm = [0i16; 1_920];
        assert_eq!(
            Decoder::new(2)
                .unwrap()
                .decode(&packet[..payload + 1], &mut pcm, 48_000),
            Ok(960)
        );
        assert!(pcm.as_chunks::<2>().0.iter().all(|pair| pair[0] == pair[1]));
        assert!(pcm.iter().any(|sample| *sample != 0));
    }

    #[test]
    fn public_pcm_encoder_produces_a_decodable_packet() {
        let mut input = [0i16; 960];
        for (index, sample) in input.iter_mut().enumerate() {
            *sample = (((index % 48) as i32 - 24) * 900) as i16;
        }
        let mut packet = [0u8; MAX_FRAME_BYTES + 1];
        let size = Encoder::new(1)
            .unwrap()
            .encode(&input, 48_000, &mut packet)
            .unwrap();
        assert!(size > 1);
        let parsed = Packet::parse(&packet[..size]).unwrap();
        assert_eq!(
            (parsed.mode, parsed.bandwidth),
            (Mode::Silk, Bandwidth::Narrow)
        );
        let mut output = [0i16; 960];
        assert_eq!(
            Decoder::new(1)
                .unwrap()
                .decode(&packet[..size], &mut output, 48_000),
            Ok(960)
        );
        assert!(output.iter().any(|&sample| sample != 0));
    }

    #[test]
    fn automatic_encoder_mode_tracks_per_channel_bitrate() {
        let mut input = [0i16; 960];
        input[100] = 20_000;
        for (bitrate, expected) in [
            (16_000, Mode::Silk),
            (32_000, Mode::Hybrid),
            (96_000, Mode::Celt),
        ] {
            let mut encoder = Encoder::new(1).unwrap();
            let mut packet = [0u8; MAX_FRAME_BYTES + 1];
            let size = encoder
                .encode_mode(EncoderMode::Auto, bitrate, &input, 48_000, &mut packet)
                .unwrap_or_else(|error| panic!("bitrate {bitrate}: {error:?}"));
            assert_eq!(Packet::parse(&packet[..size]).unwrap().mode, expected);
            if expected != Mode::Silk {
                assert_eq!(size, bitrate.div_ceil(400) as usize);
            }
        }
    }

    #[test]
    fn automatic_stereo_hybrid_honors_the_requested_aggregate_bitrate() {
        let mut input = [0i16; 1_920];
        input[200] = 20_000;
        let bitrate = 40_000;
        let mut packet = [0u8; MAX_FRAME_BYTES + 1];
        let size = Encoder::new(2)
            .unwrap()
            .encode_mode(EncoderMode::Auto, bitrate, &input, 48_000, &mut packet)
            .unwrap();
        assert_eq!(size, bitrate.div_ceil(400) as usize);
        assert_eq!(Packet::parse(&packet[..size]).unwrap().mode, Mode::Hybrid);
        let mut decoded = [0i16; 1_920];
        assert_eq!(
            Decoder::new(2)
                .unwrap()
                .decode(&packet[..size], &mut decoded, 48_000),
            Ok(960)
        );
    }

    #[test]
    fn automatic_low_rate_silk_reports_a_valid_overshoot_instead_of_buffer_failure() {
        let mut input = [0i16; 960];
        for (index, sample) in input.iter_mut().enumerate() {
            *sample = (((index % 43) as i32 - 21) * 500) as i16;
        }
        let mut packet = [0u8; MAX_FRAME_BYTES + 1];
        let size = Encoder::new(1)
            .unwrap()
            .encode_mode(EncoderMode::Auto, 8_000, &input, 48_000, &mut packet)
            .unwrap();
        assert!(size >= 8_000u32.div_ceil(400) as usize);
        assert_eq!(Packet::parse(&packet[..size]).unwrap().mode, Mode::Silk);
        let mut decoded = [0i16; 960];
        assert_eq!(
            Decoder::new(1)
                .unwrap()
                .decode(&packet[..size], &mut decoded, 48_000),
            Ok(960)
        );
    }

    #[test]
    fn bitrate_control_sets_celt_packet_size() {
        let mut input = [0i16; 960];
        input[100] = 20_000;
        for bitrate in [
            8_000, 12_000, 16_000, 24_000, 32_000, 40_000, 48_000, 64_000, 80_000, 96_000, 128_000,
            192_000, 256_000, 320_000, 400_000,
        ] {
            let mut packet = [0u8; MAX_FRAME_BYTES + 1];
            let size = Encoder::new(1)
                .unwrap()
                .encode_mode(EncoderMode::Celt, bitrate, &input, 48_000, &mut packet)
                .unwrap_or_else(|error| panic!("bitrate {bitrate}: {error:?}"));
            assert_eq!(size, bitrate.div_ceil(400) as usize);
            assert_eq!(Packet::parse(&packet[..size]).unwrap().mode, Mode::Celt);
            let mut decoded = [0i16; 960];
            assert_eq!(
                Decoder::new(1)
                    .unwrap()
                    .decode(&packet[..size], &mut decoded, 48_000),
                Ok(960)
            );
            assert!(decoded.iter().any(|&sample| sample != 0));
        }
    }

    #[test]
    fn bitrate_bounds_are_exact_and_rejected_before_state_changes() {
        let mut input = [0i16; 960];
        input[100] = 20_000;
        let mut packet = [0u8; MAX_FRAME_BYTES + 1];
        let mut encoder = Encoder::new(1).unwrap();
        assert_eq!(
            encoder.encode_mode(EncoderMode::Celt, 5_999, &input, 48_000, &mut packet),
            Err(Error::InvalidPacket)
        );
        assert_eq!(
            encoder.encode_mode(EncoderMode::Celt, 510_001, &input, 48_000, &mut packet),
            Err(Error::InvalidPacket)
        );

        let size = encoder
            .encode_mode(EncoderMode::Celt, 510_000, &input, 48_000, &mut packet)
            .unwrap();
        assert_eq!(size, 1_275);
        let mut decoded = [0i16; 960];
        assert_eq!(
            Decoder::new(1)
                .unwrap()
                .decode(&packet[..size], &mut decoded, 48_000),
            Ok(960)
        );
    }

    #[test]
    fn stereo_celt_bitrate_control_uses_requested_packet_size() {
        let mut input = [0i16; 1_920];
        input[200] = 20_000;
        input[201] = -12_000;
        for bitrate in [
            12_000, 20_000, 40_000, 64_000, 80_000, 96_000, 128_000, 160_000, 192_000, 256_000,
            320_000, 400_000, 480_000,
        ] {
            let mut packet = [0u8; MAX_FRAME_BYTES + 1];
            let size = Encoder::new(2)
                .unwrap()
                .encode_mode(EncoderMode::Celt, bitrate, &input, 48_000, &mut packet)
                .unwrap_or_else(|error| panic!("bitrate {bitrate}: {error:?}"));
            assert_eq!(size, bitrate.div_ceil(400) as usize);
            let mut decoded = [0i16; 1_920];
            assert_eq!(
                Decoder::new(2)
                    .unwrap()
                    .decode(&packet[..size], &mut decoded, 48_000),
                Ok(960)
            );
            assert!(
                decoded
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .any(|pair| pair[0] != pair[1])
            );
        }
    }

    #[test]
    fn bitrate_control_sets_silk_packet_size() {
        let mut input = [0i16; 960];
        input[100] = 20_000;
        for bitrate in [6_000, 8_000, 12_000, 16_000, 24_000, 32_000, 64_000, 80_000] {
            let mut packet = [0u8; MAX_FRAME_BYTES + 1];
            let size = Encoder::new(1)
                .unwrap()
                .encode_mode(EncoderMode::Silk, bitrate, &input, 48_000, &mut packet)
                .unwrap();
            assert_eq!(size, bitrate.div_ceil(400) as usize);
            let parsed = Packet::parse(&packet[..size]).unwrap();
            assert_eq!(parsed.mode, Mode::Silk);
            let mut decoded = [0i16; 960];
            assert_eq!(
                Decoder::new(1)
                    .unwrap()
                    .decode(&packet[..size], &mut decoded, 48_000),
                Ok(960)
            );
            assert!(decoded.iter().any(|&sample| sample != 0));
        }
    }

    #[test]
    fn stereo_silk_preserves_channel_count_and_requested_size() {
        let mut input = [0i16; 1_920];
        input[200] = 20_000;
        input[201] = -12_000;
        for bitrate in [6_000, 8_000, 12_000, 24_000, 48_000, 80_000] {
            let mut packet = [0u8; MAX_FRAME_BYTES + 1];
            let size = Encoder::new(2)
                .unwrap()
                .encode_mode(EncoderMode::Silk, bitrate, &input, 48_000, &mut packet)
                .unwrap_or_else(|error| panic!("bitrate {bitrate}: {error:?}"));
            let target = bitrate.div_ceil(400) as usize;
            assert!(size <= target && target - size <= 2);
            let parsed = Packet::parse(&packet[..size]).unwrap();
            assert_eq!((parsed.mode, parsed.stereo), (Mode::Silk, true));
            let mut decoded = [0i16; 1_920];
            assert_eq!(
                Decoder::new(2)
                    .unwrap()
                    .decode(&packet[..size], &mut decoded, 48_000),
                Ok(960)
            );
            assert!(
                decoded
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .any(|pair| pair[0] != pair[1])
            );
        }

        let mut dtx = [0u8; 2];
        assert_eq!(
            Encoder::new(2)
                .unwrap()
                .encode(&[0; 1_920], 48_000, &mut dtx),
            Ok(1)
        );
        assert!(Packet::parse(&dtx[..1]).unwrap().stereo);
    }

    #[test]
    fn bitrate_control_sets_hybrid_packet_size() {
        let mut input = [0i16; 960];
        input[100] = 20_000;
        for bitrate in [
            8_000, 12_000, 16_000, 20_000, 24_000, 32_000, 48_000, 64_000, 96_000, 116_000,
            128_000, 160_000, 192_000,
        ] {
            let mut packet = [0u8; 512];
            let size = Encoder::new(1)
                .unwrap()
                .encode_mode(EncoderMode::Hybrid, bitrate, &input, 48_000, &mut packet)
                .unwrap_or_else(|error| panic!("bitrate {bitrate}: {error:?}"));
            assert_eq!(size, bitrate.div_ceil(400) as usize);
            assert_eq!(Packet::parse(&packet[..size]).unwrap().mode, Mode::Hybrid);
            let mut decoded = [0i16; 960];
            assert_eq!(
                Decoder::new(1)
                    .unwrap()
                    .decode(&packet[..size], &mut decoded, 48_000),
                Ok(960)
            );
        }
    }

    #[test]
    fn stereo_hybrid_bitrate_control_covers_low_rate_packets() {
        let mut input = [0i16; 1_920];
        for (index, sample) in input.iter_mut().enumerate() {
            *sample = (((index % 43) as i32 - 21) * 500) as i16;
        }
        for bitrate in [12_000, 20_000, 40_000, 64_000] {
            let mut packet = [0u8; MAX_FRAME_BYTES + 1];
            let size = Encoder::new(2)
                .unwrap()
                .encode_mode(EncoderMode::Hybrid, bitrate, &input, 48_000, &mut packet)
                .unwrap_or_else(|error| panic!("bitrate {bitrate}: {error:?}"));
            assert_eq!(size, bitrate.div_ceil(400) as usize);
            let mut decoded = [0i16; 1_920];
            assert_eq!(
                Decoder::new(2)
                    .unwrap()
                    .decode(&packet[..size], &mut decoded, 48_000),
                Ok(960)
            );
        }
    }

    #[test]
    fn public_celt_encoder_reaches_the_complete_decoder_path() {
        let mut input = [0i16; 960];
        for (index, sample) in input.iter_mut().enumerate() {
            *sample = (((index % 80) as i32 - 40) * 600) as i16;
        }
        let mut packet = [0u8; 1_025];
        let size = Encoder::new(1)
            .unwrap()
            .encode_celt(&input, 48_000, &mut packet)
            .unwrap();
        assert_eq!(size, packet.len());
        let parsed = Packet::parse(&packet).unwrap();
        assert_eq!(
            (parsed.mode, parsed.bandwidth),
            (Mode::Celt, Bandwidth::Full)
        );
        let mut decoded = [0i16; 960];
        assert_eq!(
            Decoder::new(1)
                .unwrap()
                .decode(&packet, &mut decoded, 48_000),
            Ok(960)
        );
        assert!(decoded.iter().any(|&sample| sample != 0));
    }

    #[test]
    fn public_celt_encoder_handles_detected_transients() {
        let mut input = [0i16; 960];
        input[420] = 30_000;
        input[421] = -20_000;
        let mut packet = [0u8; 1_025];
        assert_eq!(
            Encoder::new(1)
                .unwrap()
                .encode_celt(&input, 48_000, &mut packet),
            Ok(packet.len())
        );
        let mut decoded = [0i16; 960];
        assert_eq!(
            Decoder::new(1)
                .unwrap()
                .decode(&packet, &mut decoded, 48_000),
            Ok(960)
        );
        assert!(decoded.iter().any(|&sample| sample != 0));
    }

    #[test]
    fn public_celt_encoder_supports_every_rfc_frame_duration() {
        for duration_us in [2_500u32, 5_000, 10_000, 20_000] {
            let frames = 48_000usize * duration_us as usize / 1_000_000;
            let mut input = [0i16; 960];
            for (index, sample) in input[..frames].iter_mut().enumerate() {
                *sample = (((index % 31) as i32 - 15) * 700) as i16;
            }
            let mut packet = [0u8; MAX_FRAME_BYTES + 1];
            let size = Encoder::new(1)
                .unwrap()
                .encode_celt_duration(&input[..frames], 48_000, duration_us, &mut packet)
                .unwrap_or_else(|error| panic!("duration {duration_us}: {error:?}"));
            let parsed = Packet::parse(&packet[..size]).unwrap();
            assert_eq!(parsed.frame_duration_us, duration_us);
            let mut decoded = [0i16; 960];
            assert_eq!(
                Decoder::new(1)
                    .unwrap()
                    .decode(&packet[..size], &mut decoded, 48_000),
                Ok(frames)
            );
            assert!(decoded[..frames].iter().any(|&sample| sample != 0));
        }
    }

    #[test]
    fn public_celt_encoder_supports_every_rfc_bandwidth_for_mono_and_stereo() {
        for channels in [1u8, 2] {
            for bandwidth in [
                Bandwidth::Narrow,
                Bandwidth::Wide,
                Bandwidth::SuperWide,
                Bandwidth::Full,
            ] {
                for duration_us in [2_500u32, 5_000, 10_000, 20_000] {
                    let frames = 48_000usize * duration_us as usize / 1_000_000;
                    let samples = frames * usize::from(channels);
                    let mut input = [0i16; 1_920];
                    for (index, sample) in input[..samples].iter_mut().enumerate() {
                        *sample = (((index % 31) as i32 - 15) * 700) as i16;
                    }
                    let mut packet = [0u8; MAX_FRAME_BYTES + 1];
                    let size = Encoder::new(channels)
                        .unwrap()
                        .encode_celt_bandwidth_duration(
                            &input[..samples],
                            48_000,
                            bandwidth,
                            duration_us,
                            &mut packet,
                        )
                        .unwrap_or_else(|error| {
                            panic!("{channels:?} {bandwidth:?} {duration_us}: {error:?}")
                        });
                    let parsed = Packet::parse(&packet[..size]).unwrap();
                    assert_eq!(
                        (parsed.mode, parsed.bandwidth, parsed.frame_duration_us),
                        (Mode::Celt, bandwidth, duration_us)
                    );
                    let mut decoded = [0i16; 1_920];
                    assert_eq!(
                        Decoder::new(channels).unwrap().decode(
                            &packet[..size],
                            &mut decoded,
                            48_000,
                        ),
                        Ok(frames)
                    );
                }
            }
        }

        let mut packet = [0u8; MAX_FRAME_BYTES + 1];
        assert_eq!(
            Encoder::new(1).unwrap().encode_celt_bandwidth_duration(
                &[1; 120],
                48_000,
                Bandwidth::Medium,
                2_500,
                &mut packet,
            ),
            Err(Error::UnsupportedAudioMode)
        );
    }

    #[test]
    fn public_silk_encoder_supports_every_rfc_frame_duration() {
        for channels in [1u8, 2] {
            for duration_us in [10_000u32, 20_000, 40_000, 60_000] {
                let frames = 48_000usize * duration_us as usize / 1_000_000;
                let samples = frames * usize::from(channels);
                let mut input = [0i16; 5_760];
                for frame in 0..frames {
                    input[frame * usize::from(channels)] =
                        (((frame % 31) as i32 - 15) * 500) as i16;
                    if channels == 2 {
                        input[frame * 2 + 1] = (((frame % 23) as i32 - 11) * -600) as i16;
                    }
                }
                let mut packet = [0u8; MAX_FRAME_BYTES + 1];
                let size = Encoder::new(channels)
                    .unwrap()
                    .encode_silk_duration(&input[..samples], 48_000, duration_us, &mut packet)
                    .unwrap_or_else(|error| {
                        panic!("channels {channels}, duration {duration_us}: {error:?}")
                    });
                let parsed = Packet::parse(&packet[..size]).unwrap();
                assert_eq!(
                    (parsed.mode, parsed.frame_duration_us),
                    (Mode::Silk, duration_us)
                );
                assert_eq!(parsed.stereo, channels == 2);
                let mut decoded = [0i16; 5_760];
                assert_eq!(
                    Decoder::new(channels).unwrap().decode(
                        &packet[..size],
                        &mut decoded[..samples],
                        48_000,
                    ),
                    Ok(frames)
                );
                assert!(decoded[..samples].iter().any(|&sample| sample != 0));

                let mut dtx = [0u8; 1];
                let silence = [0i16; 5_760];
                assert_eq!(
                    Encoder::new(channels).unwrap().encode_silk_duration(
                        &silence[..samples],
                        48_000,
                        duration_us,
                        &mut dtx,
                    ),
                    Ok(1)
                );
                assert_eq!(Packet::parse(&dtx).unwrap().frame_duration_us, duration_us);
            }
        }
    }

    #[test]
    fn public_silk_encoder_supports_all_bandwidths_for_mono_and_stereo() {
        for channels in [1u8, 2] {
            for bandwidth in [Bandwidth::Narrow, Bandwidth::Medium, Bandwidth::Wide] {
                for duration_us in [10_000u32, 20_000, 40_000, 60_000] {
                    let frames = 48_000usize * duration_us as usize / 1_000_000;
                    let samples = frames * usize::from(channels);
                    let mut input = [0i16; 5_760];
                    for (index, sample) in input[..samples].iter_mut().enumerate() {
                        *sample = (((index % 31) as i32 - 15) * 500) as i16;
                    }
                    let mut packet = [0u8; MAX_FRAME_BYTES + 1];
                    let size = Encoder::new(channels)
                        .unwrap()
                        .encode_silk_bandwidth_duration(
                            &input[..samples],
                            48_000,
                            bandwidth,
                            duration_us,
                            &mut packet,
                        )
                        .unwrap_or_else(|error| {
                            panic!("{channels:?} {bandwidth:?} {duration_us}: {error:?}")
                        });
                    let parsed = Packet::parse(&packet[..size]).unwrap();
                    assert_eq!(
                        (parsed.mode, parsed.bandwidth, parsed.frame_duration_us),
                        (Mode::Silk, bandwidth, duration_us)
                    );
                    let mut decoded = [0i16; 5_760];
                    assert_eq!(
                        Decoder::new(channels).unwrap().decode(
                            &packet[..size],
                            &mut decoded,
                            48_000,
                        ),
                        Ok(frames)
                    );
                }
            }
        }

        let mut packet = [0u8; MAX_FRAME_BYTES + 1];
        assert_eq!(
            Encoder::new(1).unwrap().encode_silk_bandwidth_duration(
                &[1; 480],
                48_000,
                Bandwidth::SuperWide,
                10_000,
                &mut packet,
            ),
            Err(Error::UnsupportedAudioMode)
        );
    }

    #[test]
    fn public_hybrid_encoder_supports_every_rfc_configuration() {
        for channels in [1u8, 2] {
            for bandwidth in [Bandwidth::SuperWide, Bandwidth::Full] {
                for duration_us in [10_000u32, 20_000] {
                    let frames = 48_000usize * duration_us as usize / 1_000_000;
                    let samples = frames * usize::from(channels);
                    let mut input = [0i16; 1_920];
                    for (index, sample) in input[..samples].iter_mut().enumerate() {
                        *sample = (((index % 37) as i32 - 18) * 420) as i16;
                    }
                    let mut packet = [0u8; MAX_FRAME_BYTES + 1];
                    let size = Encoder::new(channels)
                        .unwrap()
                        .encode_hybrid_bandwidth_duration(
                            &input[..samples],
                            48_000,
                            bandwidth,
                            duration_us,
                            &mut packet,
                        )
                        .unwrap_or_else(|error| {
                            panic!("{channels:?} {bandwidth:?} {duration_us}: {error:?}")
                        });
                    let parsed = Packet::parse(&packet[..size]).unwrap();
                    assert_eq!(
                        (parsed.mode, parsed.bandwidth, parsed.frame_duration_us),
                        (Mode::Hybrid, bandwidth, duration_us)
                    );
                    assert_eq!(parsed.stereo, channels == 2);
                    let mut decoded = [0i16; 1_920];
                    assert_eq!(
                        Decoder::new(channels).unwrap().decode(
                            &packet[..size],
                            &mut decoded[..samples],
                            48_000,
                        ),
                        Ok(frames)
                    );
                    assert!(decoded[..samples].iter().any(|&sample| sample != 0));
                }
            }
        }

        let mut packet = [0u8; MAX_FRAME_BYTES + 1];
        let input = [1i16; 960];
        assert_eq!(
            Encoder::new(1).unwrap().encode_hybrid_bandwidth_duration(
                &input,
                48_000,
                Bandwidth::Wide,
                20_000,
                &mut packet,
            ),
            Err(Error::UnsupportedAudioMode)
        );
        assert_eq!(
            Encoder::new(1).unwrap().encode_hybrid_bandwidth_duration(
                &input,
                48_000,
                Bandwidth::Full,
                40_000,
                &mut packet,
            ),
            Err(Error::InvalidFrameSize)
        );
    }

    #[test]
    fn silk_only_encoder_emits_transition_redundancy_for_every_configuration() {
        for channels in [1u8, 2] {
            let transition_frames = 48_000usize / 200;
            let mut transition_input = [0i16; 480];
            for (index, sample) in transition_input[..transition_frames * usize::from(channels)]
                .iter_mut()
                .enumerate()
            {
                *sample = (((index % 29) as i32 - 14) * 310) as i16;
            }
            let mut transition_packet = [0u8; 65];
            let transition_size = Encoder::new(channels)
                .unwrap()
                .encode_celt_with_payload(
                    &transition_input[..transition_frames * usize::from(channels)],
                    48_000,
                    &mut transition_packet,
                    64,
                    1,
                    Bandwidth::Full,
                )
                .unwrap();
            let redundant = &transition_packet[1..transition_size];

            for bandwidth in [Bandwidth::Narrow, Bandwidth::Medium, Bandwidth::Wide] {
                for duration_us in [10_000u32, 20_000, 40_000, 60_000] {
                    for at_beginning in [false, true] {
                        let frames = 48_000usize * duration_us as usize / 1_000_000;
                        let samples = frames * usize::from(channels);
                        let mut input = [0i16; 5_760];
                        for (index, sample) in input[..samples].iter_mut().enumerate() {
                            *sample = (((index % 41) as i32 - 20) * 360) as i16;
                        }
                        let mut packet = [0u8; MAX_FRAME_BYTES + 1];
                        let size = Encoder::new(channels)
                            .unwrap()
                            .encode_silk_with_redundancy(
                                &input[..samples],
                                48_000,
                                bandwidth,
                                duration_us,
                                redundant,
                                at_beginning,
                                &mut packet,
                            )
                            .unwrap_or_else(|error| {
                                panic!(
                                    "{channels:?} {bandwidth:?} {duration_us} {at_beginning}: {error:?}"
                                )
                            });
                        assert_eq!(&packet[size - redundant.len()..size], redundant);
                        let parsed = Packet::parse(&packet[..size]).unwrap();
                        assert_eq!(
                            (parsed.mode, parsed.bandwidth, parsed.frame_duration_us),
                            (Mode::Silk, bandwidth, duration_us)
                        );
                        let mut decoded = [0i16; 5_760];
                        assert_eq!(
                            Decoder::new(channels).unwrap().decode(
                                &packet[..size],
                                &mut decoded[..samples],
                                48_000,
                            ),
                            Ok(frames)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn public_celt_encoder_preserves_coded_stereo_channels() {
        let mut input = [0i16; 1_920];
        for frame in 0..960 {
            input[frame * 2] = (((frame % 64) as i32 - 32) * 500) as i16;
            input[frame * 2 + 1] = (((frame % 37) as i32 - 18) * -700) as i16;
        }
        let mut packet = [0u8; 1_276];
        assert_eq!(
            Encoder::new(2)
                .unwrap()
                .encode_celt(&input, 48_000, &mut packet),
            Ok(packet.len())
        );
        assert!(Packet::parse(&packet).unwrap().stereo);
        let mut decoded = [0i16; 1_920];
        assert_eq!(
            Decoder::new(2)
                .unwrap()
                .decode(&packet, &mut decoded, 48_000),
            Ok(960)
        );
        assert!(
            decoded
                .as_chunks::<2>()
                .0
                .iter()
                .any(|frame| frame[0] != frame[1])
        );
    }

    #[test]
    fn public_hybrid_encoder_uses_one_shared_range_stream() {
        let mut input = [0i16; 960];
        for (index, sample) in input.iter_mut().enumerate() {
            *sample = (((index % 53) as i32 - 26) * 800) as i16;
        }
        let mut packet = [0u8; 513];
        assert_eq!(
            Encoder::new(1)
                .unwrap()
                .encode_hybrid(&input, 48_000, &mut packet),
            Ok(packet.len())
        );
        let parsed = Packet::parse(&packet).unwrap();
        assert_eq!(
            (parsed.mode, parsed.bandwidth),
            (Mode::Hybrid, Bandwidth::Full)
        );
        let mut decoded = [0i16; 960];
        assert_eq!(
            Decoder::new(1)
                .unwrap()
                .decode(&packet, &mut decoded, 48_000),
            Ok(960)
        );
        assert!(decoded.iter().any(|&sample| sample != 0));
    }

    #[test]
    fn hybrid_encoder_embeds_explicit_redundancy_tail_and_reduces_main_storage() {
        let mut input = [0i16; 960];
        input[120] = 18_000;
        let mut transition_input = [0i16; 240];
        transition_input[30] = 12_000;
        let mut redundant = [0u8; 64];
        assert_eq!(
            Encoder::new(1).unwrap().encode_celt_redundancy(
                &transition_input,
                48_000,
                &mut redundant,
            ),
            Ok(redundant.len())
        );
        let mut packet = [0u8; MAX_FRAME_BYTES + 1];
        let size = Encoder::new(1)
            .unwrap()
            .encode_hybrid_with_redundancy(&input, 48_000, &redundant, true, &mut packet)
            .unwrap();
        let parsed = Packet::parse(&packet[..size]).unwrap();
        let frame = parsed.frames[0];
        let start = usize::from(frame.offset);
        let end = start + usize::from(frame.len);
        let mut range = RangeDecoder::new(&packet[start..end]);
        let mut silk = [0.0f32; 320];
        let mut fec = [0.0f32; 320];
        silk_packet::MonoPayloadDecoder::new()
            .decode_range(&mut range, Bandwidth::Wide, 20, &mut silk, &mut fec)
            .unwrap();
        let info = transition::decode_header(&mut range, Mode::Hybrid, usize::from(frame.len))
            .unwrap()
            .unwrap();
        assert_eq!(info.position, transition::RedundancyPosition::Beginning);
        assert_eq!(info.len, redundant.len());
        assert_eq!(&packet[start + info.offset..end], &redundant);
        assert_eq!(
            range.storage_len(),
            usize::from(frame.len) - redundant.len()
        );
        let mut decoded = [0i16; 960];
        assert_eq!(
            Decoder::new(1)
                .unwrap()
                .decode(&packet[..size], &mut decoded, 48_000),
            Ok(960)
        );
    }

    #[test]
    fn automatic_celt_to_hybrid_transition_inserts_beginning_redundancy() {
        let mut input = [0i16; 960];
        for (index, sample) in input.iter_mut().enumerate() {
            *sample = (((index % 43) as i32 - 21) * 500) as i16;
        }
        let mut encoder = Encoder::new(1).unwrap();
        let mut celt_packet = [0u8; MAX_FRAME_BYTES + 1];
        let celt_size = encoder
            .encode_mode(EncoderMode::Auto, 64_000, &input, 48_000, &mut celt_packet)
            .unwrap();
        assert_eq!(
            Packet::parse(&celt_packet[..celt_size]).unwrap().mode,
            Mode::Celt
        );

        let mut hybrid_packet = [0u8; MAX_FRAME_BYTES + 1];
        let hybrid_size = encoder
            .encode_mode(
                EncoderMode::Auto,
                32_000,
                &input,
                48_000,
                &mut hybrid_packet,
            )
            .unwrap();
        assert_eq!(hybrid_size, 32_000u32.div_ceil(400) as usize);
        let parsed = Packet::parse(&hybrid_packet[..hybrid_size]).unwrap();
        assert_eq!(parsed.mode, Mode::Hybrid);
        let frame = parsed.frames[0];
        let start = usize::from(frame.offset);
        let end = start + usize::from(frame.len);
        let mut range = RangeDecoder::new(&hybrid_packet[start..end]);
        let mut silk = [0.0f32; 320];
        let mut fec = [0.0f32; 320];
        silk_packet::MonoPayloadDecoder::new()
            .decode_range(&mut range, Bandwidth::Wide, 20, &mut silk, &mut fec)
            .unwrap();
        let info = transition::decode_header(&mut range, Mode::Hybrid, usize::from(frame.len))
            .unwrap()
            .unwrap();
        assert_eq!(info.position, transition::RedundancyPosition::Beginning);
        assert_eq!(info.len, 16);

        let mut decoder = Decoder::new(1).unwrap();
        let mut decoded = [0i16; 960];
        decoder
            .decode(&celt_packet[..celt_size], &mut decoded, 48_000)
            .unwrap();
        assert_eq!(
            decoder.decode(&hybrid_packet[..hybrid_size], &mut decoded, 48_000),
            Ok(960)
        );
    }

    #[test]
    fn automatic_celt_to_silk_transition_inserts_beginning_redundancy() {
        let mut input = [0i16; 960];
        input[100] = 12_000;
        let mut encoder = Encoder::new(1).unwrap();
        let mut celt_packet = [0u8; MAX_FRAME_BYTES + 1];
        let celt_size = encoder
            .encode_mode(EncoderMode::Auto, 64_000, &input, 48_000, &mut celt_packet)
            .unwrap();
        assert_eq!(
            Packet::parse(&celt_packet[..celt_size]).unwrap().mode,
            Mode::Celt
        );

        let mut silk_packet = [0u8; MAX_FRAME_BYTES + 1];
        let silk_size = encoder
            .encode_mode(EncoderMode::Auto, 19_000, &input, 48_000, &mut silk_packet)
            .unwrap();
        assert!(silk_size <= 19_000u32.div_ceil(400) as usize);
        let parsed = Packet::parse(&silk_packet[..silk_size]).unwrap();
        assert_eq!(parsed.mode, Mode::Silk);
        let frame = parsed.frames[0];
        let start = usize::from(frame.offset);
        let end = start + usize::from(frame.len);
        let mut range = RangeDecoder::new(&silk_packet[start..end]);
        let mut silk = [0.0f32; 160];
        let mut fec = [0.0f32; 160];
        silk_packet::MonoPayloadDecoder::new()
            .decode_range(&mut range, Bandwidth::Narrow, 20, &mut silk, &mut fec)
            .unwrap();
        let info = transition::decode_header(&mut range, Mode::Silk, usize::from(frame.len))
            .unwrap()
            .unwrap();
        assert_eq!(info.position, transition::RedundancyPosition::Beginning);
        assert_eq!(info.len, 16);

        let mut decoder = Decoder::new(1).unwrap();
        let mut decoded = [0i16; 960];
        assert_eq!(
            decoder.decode(&celt_packet[..celt_size], &mut decoded, 48_000),
            Ok(960)
        );
        assert_eq!(
            decoder.decode(&silk_packet[..silk_size], &mut decoded, 48_000),
            Ok(960)
        );
    }

    #[test]
    fn lookahead_encoder_inserts_end_redundancy_before_celt_switches() {
        for (first_bitrate, first_mode) in [(19_000u32, Mode::Silk), (32_000u32, Mode::Hybrid)] {
            let mut first_input = [0i16; 960];
            let mut second_input = [0i16; 960];
            first_input[840] = 11_000;
            second_input[80] = -13_000;
            let mut encoder = LookaheadEncoder::new(1).unwrap();
            assert_eq!(
                encoder
                    .push(EncoderMode::Auto, first_bitrate, &first_input, 48_000,)
                    .unwrap(),
                None
            );
            let first = encoder
                .push(EncoderMode::Auto, 64_000, &second_input, 48_000)
                .unwrap()
                .unwrap();
            let mut first_packet = [0u8; MAX_FRAME_BYTES + 1];
            first_packet[..first.len()].copy_from_slice(first);
            let first_size = first.len();
            let second = encoder.flush().unwrap().unwrap();
            let mut second_packet = [0u8; MAX_FRAME_BYTES + 1];
            second_packet[..second.len()].copy_from_slice(second);
            let second_size = second.len();
            assert!(encoder.flush().unwrap().is_none());

            let parsed = Packet::parse(&first_packet[..first_size]).unwrap();
            assert_eq!(parsed.mode, first_mode);
            let frame = parsed.frames[0];
            let start = usize::from(frame.offset);
            let end = start + usize::from(frame.len);
            let mut range = RangeDecoder::new(&first_packet[start..end]);
            if first_mode == Mode::Silk {
                let mut silk = [0.0f32; 160];
                let mut fec = [0.0f32; 160];
                silk_packet::MonoPayloadDecoder::new()
                    .decode_range(&mut range, Bandwidth::Narrow, 20, &mut silk, &mut fec)
                    .unwrap();
            } else {
                let mut silk = [0.0f32; 320];
                let mut fec = [0.0f32; 320];
                silk_packet::MonoPayloadDecoder::new()
                    .decode_range(&mut range, Bandwidth::Wide, 20, &mut silk, &mut fec)
                    .unwrap();
            }
            let info = transition::decode_header(&mut range, first_mode, usize::from(frame.len))
                .unwrap()
                .unwrap();
            assert_eq!(info.position, transition::RedundancyPosition::End);
            assert_eq!(info.len, 16);
            assert_eq!(
                Packet::parse(&second_packet[..second_size]).unwrap().mode,
                Mode::Celt
            );

            let mut decoder = Decoder::new(1).unwrap();
            let mut decoded = [0i16; 960];
            assert_eq!(
                decoder.decode(&first_packet[..first_size], &mut decoded, 48_000),
                Ok(960)
            );
            assert_eq!(
                decoder.decode(&second_packet[..second_size], &mut decoded, 48_000),
                Ok(960)
            );
        }
    }

    #[test]
    fn public_stereo_hybrid_encoder_combines_mid_side_and_joint_celt() {
        let mut input = [0i16; 1_920];
        for frame in 0..960 {
            input[frame * 2] = (((frame % 47) as i32 - 23) * 850) as i16;
            input[frame * 2 + 1] = (((frame % 71) as i32 - 35) * -550) as i16;
        }
        let mut packet = [0u8; 1_276];
        assert_eq!(
            Encoder::new(2)
                .unwrap()
                .encode_hybrid(&input, 48_000, &mut packet),
            Ok(packet.len())
        );
        let parsed = Packet::parse(&packet).unwrap();
        assert_eq!(parsed.mode, Mode::Hybrid);
        assert!(parsed.stereo);
        let mut decoded = [0i16; 1_920];
        assert_eq!(
            Decoder::new(2)
                .unwrap()
                .decode(&packet, &mut decoded, 48_000),
            Ok(960)
        );
        assert!(
            decoded
                .as_chunks::<2>()
                .0
                .iter()
                .any(|frame| frame[0] != frame[1])
        );
    }

    #[test]
    fn public_loss_concealment_tracks_silk_and_celt_state() {
        let mut decoder = Decoder::new(1).unwrap();
        let mut concealed = [0i16; 960];
        assert_eq!(
            decoder.decode_loss(&mut concealed, 48_000),
            Err(Error::InvalidPacket)
        );
        let mut input = [0i16; 960];
        for (index, sample) in input.iter_mut().enumerate() {
            *sample = (((index % 41) as i32 - 20) * 1_000) as i16;
        }
        let mut silk_packet = [0u8; MAX_FRAME_BYTES + 1];
        let silk_size = Encoder::new(1)
            .unwrap()
            .encode(&input, 48_000, &mut silk_packet)
            .unwrap();
        let mut decoded = [0i16; 960];
        decoder
            .decode(&silk_packet[..silk_size], &mut decoded, 48_000)
            .unwrap();
        assert_eq!(decoder.decode_loss(&mut concealed, 48_000), Ok(960));
        assert!(concealed.iter().any(|&sample| sample != 0));

        let mut celt_packet = [0u8; 1_025];
        Encoder::new(1)
            .unwrap()
            .encode_celt(&input, 48_000, &mut celt_packet)
            .unwrap();
        decoder.decode(&celt_packet, &mut decoded, 48_000).unwrap();
        concealed.fill(0);
        assert_eq!(decoder.decode_loss(&mut concealed, 48_000), Ok(960));
        assert!(concealed.iter().any(|&sample| sample != 0));
    }

    #[test]
    fn loss_concealment_covers_every_silk_duration_rate_and_channel_geometry() {
        for coded_channels in [1u8, 2] {
            for bandwidth in [Bandwidth::Narrow, Bandwidth::Medium, Bandwidth::Wide] {
                for duration_us in [10_000usize, 20_000, 40_000, 60_000] {
                    let input_frames = 48_000 * duration_us / 1_000_000;
                    let input_samples = input_frames * usize::from(coded_channels);
                    let mut input = [0i16; 5_760];
                    for (index, sample) in input[..input_samples].iter_mut().enumerate() {
                        *sample = (((index % 37) as i32 - 18) * 1_200) as i16;
                    }
                    let mut packet = [0u8; MAX_FRAME_BYTES + 1];
                    let packet_len = Encoder::new(coded_channels)
                        .unwrap()
                        .encode_silk_bandwidth_duration(
                            &input[..input_samples],
                            48_000,
                            bandwidth,
                            duration_us as u32,
                            &mut packet,
                        )
                        .unwrap();

                    for output_channels in [1u8, 2] {
                        for sample_rate in [8_000usize, 12_000, 16_000, 24_000, 48_000] {
                            let frames = sample_rate * duration_us / 1_000_000;
                            let samples = frames * usize::from(output_channels);
                            let mut decoded = [1i16; 5_760];
                            let mut decoder = Decoder::new(output_channels).unwrap();
                            assert_eq!(
                                decoder.decode(
                                    &packet[..packet_len],
                                    &mut decoded[..samples],
                                    sample_rate as u32,
                                ),
                                Ok(frames)
                            );

                            let mut guarded = [0x35a7i16; 5_762];
                            assert_eq!(
                                decoder
                                    .decode_loss(&mut guarded[1..samples + 1], sample_rate as u32,),
                                Ok(frames),
                                "coded_channels={coded_channels} output_channels={output_channels} bandwidth={bandwidth:?} duration_us={duration_us} sample_rate={sample_rate}",
                            );
                            assert_eq!((guarded[0], guarded[samples + 1]), (0x35a7, 0x35a7));
                            assert!(guarded[1..samples + 1].iter().any(|&sample| sample != 0));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn public_decoder_reports_deterministic_final_entropy_ranges() {
        let mut input = [0i16; 960];
        for (index, sample) in input.iter_mut().enumerate() {
            *sample = (((index % 43) as i32 - 21) * 900) as i16;
        }
        let mut output = [0i16; 960];

        let mut silk_packet = [0u8; MAX_FRAME_BYTES + 1];
        let silk_size = Encoder::new(1)
            .unwrap()
            .encode(&input, 48_000, &mut silk_packet)
            .unwrap();
        let mut first = Decoder::new(1).unwrap();
        first
            .decode(&silk_packet[..silk_size], &mut output, 48_000)
            .unwrap();
        let silk_range = first.final_range();
        assert_ne!(silk_range, 0);
        let mut second = Decoder::new(1).unwrap();
        second
            .decode(&silk_packet[..silk_size], &mut output, 48_000)
            .unwrap();
        assert_eq!(second.final_range(), silk_range);

        let mut celt_packet = [0u8; 1_025];
        Encoder::new(1)
            .unwrap()
            .encode_celt(&input, 48_000, &mut celt_packet)
            .unwrap();
        first = Decoder::new(1).unwrap();
        first.decode(&celt_packet, &mut output, 48_000).unwrap();
        assert_ne!(first.final_range(), 0);

        let mut hybrid_packet = [0u8; 513];
        Encoder::new(1)
            .unwrap()
            .encode_hybrid(&input, 48_000, &mut hybrid_packet)
            .unwrap();
        first = Decoder::new(1).unwrap();
        first.decode(&hybrid_packet, &mut output, 48_000).unwrap();
        assert_ne!(first.final_range(), 0);

        first.decode_loss(&mut output, 48_000).unwrap();
        assert_eq!(first.final_range(), 0);
        first.decode(&[31 << 3], &mut output, 48_000).unwrap();
        assert_eq!(first.final_range(), 0);
    }

    #[test]
    fn multi_frame_final_range_comes_from_last_frame() {
        let mut first_input = [0i16; 960];
        let mut last_input = [0i16; 960];
        for index in 0..960 {
            first_input[index] = (((index % 31) as i32 - 15) * 700) as i16;
            last_input[index] = (((index % 47) as i32 - 23) * 500) as i16;
        }
        let mut encoder = Encoder::new(1).unwrap();
        let mut first_packet = [0u8; 1_025];
        let mut last_packet = [0u8; 1_025];
        let first_len = encoder
            .encode_celt(&first_input, 48_000, &mut first_packet)
            .unwrap();
        let last_len = encoder
            .encode_celt(&last_input, 48_000, &mut last_packet)
            .unwrap();
        let config = first_packet[0] >> 3;
        assert_eq!(last_packet[0] >> 3, config);

        let mut packet = [0u8; 2_055];
        let packet_len = packetize(
            config,
            false,
            &[&first_packet[1..first_len], &last_packet[1..last_len]],
            0,
            &mut packet,
        )
        .unwrap();
        let mut pcm = [0i16; 1_920];
        let mut combined = Decoder::new(1).unwrap();
        assert_eq!(
            combined.decode(&packet[..packet_len], &mut pcm, 48_000),
            Ok(1_920)
        );

        let mut last_only = Decoder::new(1).unwrap();
        last_only
            .decode(&last_packet[..last_len], &mut pcm[..960], 48_000)
            .unwrap();
        assert_eq!(combined.final_range(), last_only.final_range());
    }

    fn fec_test_parameters() -> MonoFrameParameters {
        let mut excitation = [0i32; MAX_EXCITATION_SAMPLES];
        excitation[0] = 2;
        excitation[20] = -1;
        MonoFrameParameters {
            signal: SignalType::Unvoiced,
            quantization: QuantizationOffset::Low,
            gain_symbols: [20, 4, 4, 4],
            lsf: LsfIndices {
                stage1: 3,
                stage2: Stage2 {
                    order: 10,
                    index: [0; 16],
                },
                interpolation_q2: Some(4),
            },
            primary_pitch: None,
            contour_index: 0,
            ltp: None,
            seed: 1,
            rate_level: 0,
            excitation,
        }
    }

    #[test]
    fn public_fec_decode_returns_regular_and_lbrr_audio_once() {
        let parameters = fec_test_parameters();
        let header = LayerHeader {
            channels: 1,
            frames: 1,
            channel: [
                ChannelHeader { vad: 1, lbrr: 1 },
                ChannelHeader { vad: 0, lbrr: 0 },
            ],
        };
        let mut packet = [0u8; MAX_FRAME_BYTES + 1];
        packet[0] = 1 << 3;
        let payload = MonoPayloadEncoder::new()
            .encode(
                &mut packet[1..],
                Bandwidth::Narrow,
                20,
                header,
                &[parameters],
                &[Some(&parameters)],
            )
            .unwrap();
        let mut regular = [0i16; 960];
        let mut fec = [0i16; 960];
        assert_eq!(
            Decoder::new(1).unwrap().decode_with_fec(
                &packet[..payload + 1],
                &mut regular,
                &mut fec,
                48_000,
            ),
            Ok(FecDecodeResult {
                frames: 960,
                fec_frames: 960,
            })
        );
        assert!(regular.iter().any(|&sample| sample != 0));
        assert!(fec.iter().any(|&sample| sample != 0));
    }

    #[test]
    fn partial_mono_lbrr_counts_and_zero_fills_only_protected_intervals() {
        let parameters = fec_test_parameters();
        let regular_parameters = [parameters; 3];
        let fec_parameters = [Some(&parameters), None, Some(&parameters)];
        for (duration_ms, interval_count, mask) in [(40u8, 2usize, 0b01u8), (60, 3, 0b101)] {
            let header = LayerHeader {
                channels: 1,
                frames: interval_count as u8,
                channel: [
                    ChannelHeader {
                        vad: (1 << interval_count) - 1,
                        lbrr: mask,
                    },
                    ChannelHeader { vad: 0, lbrr: 0 },
                ],
            };
            let mut packet = [0u8; MAX_FRAME_BYTES + 1];
            packet[0] = (duration_ms / 20) << 3;
            let payload = MonoPayloadEncoder::new()
                .encode(
                    &mut packet[1..],
                    Bandwidth::Narrow,
                    duration_ms,
                    header,
                    &regular_parameters[..interval_count],
                    &fec_parameters[..interval_count],
                )
                .unwrap();

            for sample_rate in [8_000usize, 12_000, 16_000, 24_000, 48_000] {
                let output_frames = sample_rate * usize::from(duration_ms) / 1_000;
                let interval_frames = sample_rate / 50;
                let mut regular = [0i16; 2_880];
                let mut fec = [0i16; 2_880];
                assert_eq!(
                    Decoder::new(1).unwrap().decode_with_fec(
                        &packet[..payload + 1],
                        &mut regular[..output_frames],
                        &mut fec[..output_frames],
                        sample_rate as u32,
                    ),
                    Ok(FecDecodeResult {
                        frames: output_frames,
                        fec_frames: interval_frames * mask.count_ones() as usize,
                    }),
                    "duration_ms={duration_ms} sample_rate={sample_rate}",
                );
                for interval in 0..interval_count {
                    let span = &fec[interval * interval_frames..(interval + 1) * interval_frames];
                    if mask & (1 << interval) == 0 {
                        assert!(span.iter().all(|&sample| sample == 0));
                    } else {
                        assert!(span.iter().any(|&sample| sample != 0));
                    }
                }
            }
        }
    }

    #[test]
    fn contiguous_mono_lbrr_intervals_keep_one_resampling_grid() {
        let parameters = fec_test_parameters();
        let regular_parameters = [parameters; 3];
        let fec_parameters = [Some(&parameters); 3];
        for (duration_ms, interval_count) in [(40u8, 2usize), (60, 3)] {
            let mask = (1u8 << interval_count) - 1;
            let header = LayerHeader {
                channels: 1,
                frames: interval_count as u8,
                channel: [
                    ChannelHeader {
                        vad: mask,
                        lbrr: mask,
                    },
                    ChannelHeader { vad: 0, lbrr: 0 },
                ],
            };
            let mut packet = [0u8; MAX_FRAME_BYTES + 1];
            packet[0] = (duration_ms / 20) << 3;
            let payload = MonoPayloadEncoder::new()
                .encode(
                    &mut packet[1..],
                    Bandwidth::Narrow,
                    duration_ms,
                    header,
                    &regular_parameters[..interval_count],
                    &fec_parameters[..interval_count],
                )
                .unwrap();
            let native_frames = 8 * usize::from(duration_ms);
            let mut native_regular = [0.0f32; 480];
            let mut native_fec = [0.0f32; 480];
            MonoPayloadDecoder::new()
                .decode(
                    &packet[1..payload + 1],
                    Bandwidth::Narrow,
                    duration_ms,
                    &mut native_regular[..native_frames],
                    &mut native_fec[..native_frames],
                )
                .unwrap();

            for sample_rate in [12_000usize, 16_000, 24_000, 48_000] {
                let output_frames = sample_rate * usize::from(duration_ms) / 1_000;
                let mut expected_float = [0.0f32; 2_880];
                silk::resample_linear(
                    &native_fec[..native_frames],
                    &mut expected_float[..output_frames],
                )
                .unwrap();
                let mut expected = [0i16; 2_880];
                for frame in 0..output_frames {
                    expected[frame] = float_to_i16(expected_float[frame]);
                }
                let mut regular = [0i16; 2_880];
                let mut fec = [0i16; 2_880];
                assert_eq!(
                    Decoder::new(1).unwrap().decode_with_fec(
                        &packet[..payload + 1],
                        &mut regular[..output_frames],
                        &mut fec[..output_frames],
                        sample_rate as u32,
                    ),
                    Ok(FecDecodeResult {
                        frames: output_frames,
                        fec_frames: output_frames,
                    }),
                    "duration_ms={duration_ms} sample_rate={sample_rate}",
                );
                assert_eq!(
                    &fec[..output_frames],
                    &expected[..output_frames],
                    "duration_ms={duration_ms} sample_rate={sample_rate}",
                );
            }
        }
    }

    #[test]
    fn asymmetric_stereo_lbrr_preserves_unprotected_interval_boundaries() {
        let parameters = fec_test_parameters();
        let prediction = prediction_from_indices(12, 1, 2, 1, 2).unwrap();
        let coded = StereoFrameParameters {
            prediction: Some(&prediction),
            mid_only: None,
            mid: Some(&parameters),
            side: Some(&parameters),
        };
        let absent = StereoFrameParameters {
            prediction: None,
            mid_only: None,
            mid: None,
            side: None,
        };
        let mid_only = StereoFrameParameters {
            prediction: Some(&prediction),
            mid_only: Some(true),
            mid: Some(&parameters),
            side: None,
        };
        let side_only = StereoFrameParameters {
            prediction: None,
            mid_only: None,
            mid: None,
            side: Some(&parameters),
        };
        let regular_parameters = [coded; 3];
        let standalone_header = LayerHeader {
            channels: 2,
            frames: 1,
            channel: [
                ChannelHeader {
                    vad: 0b1,
                    lbrr: 0b1,
                },
                ChannelHeader { vad: 0b1, lbrr: 0 },
            ],
        };
        let mut standalone_packet = [0u8; MAX_FRAME_BYTES + 1];
        standalone_packet[0] = 1 << 3 | 1 << 2;
        let standalone_payload = StereoPayloadEncoder::new()
            .encode(
                &mut standalone_packet[1..],
                Bandwidth::Narrow,
                20,
                standalone_header,
                &[coded],
                &[mid_only],
            )
            .unwrap();
        for (fec_parameters, mid_mask, side_mask) in [
            ([coded, absent, mid_only], 0b101u8, 0b001u8),
            ([coded, absent, side_only], 0b001, 0b101),
        ] {
            let header = LayerHeader {
                channels: 2,
                frames: 3,
                channel: [
                    ChannelHeader {
                        vad: 0b111,
                        lbrr: mid_mask,
                    },
                    ChannelHeader {
                        vad: 0b111,
                        lbrr: side_mask,
                    },
                ],
            };
            let mut packet = [0u8; MAX_FRAME_BYTES + 1];
            packet[0] = 3 << 3 | 1 << 2;
            let payload = StereoPayloadEncoder::new()
                .encode(
                    &mut packet[1..],
                    Bandwidth::Narrow,
                    60,
                    header,
                    &regular_parameters,
                    &fec_parameters,
                )
                .unwrap();

            for sample_rate in [8_000usize, 12_000, 16_000, 24_000, 48_000] {
                let interval_frames = sample_rate / 50;
                let output_frames = interval_frames * 3;
                let interval_samples = interval_frames * 2;
                let mut regular = [0i16; 5_760];
                let mut fec = [0i16; 5_760];
                assert_eq!(
                    Decoder::new(2).unwrap().decode_with_fec(
                        &packet[..payload + 1],
                        &mut regular[..output_frames * 2],
                        &mut fec[..output_frames * 2],
                        sample_rate as u32,
                    ),
                    Ok(FecDecodeResult {
                        frames: output_frames,
                        fec_frames: interval_frames * mid_mask.count_ones() as usize,
                    }),
                    "mid_mask={mid_mask:#05b} side_mask={side_mask:#05b} sample_rate={sample_rate}",
                );
                for interval in 0..3 {
                    let start = interval * interval_samples;
                    let span = &fec[start..start + interval_samples];
                    if mid_mask & (1 << interval) == 0 {
                        assert!(span.iter().all(|&sample| sample == 0));
                    } else {
                        assert!(span.iter().any(|&sample| sample != 0));
                    }
                }
                if mid_mask == 0b101 {
                    let mut standalone_regular = [0i16; 1_920];
                    let mut standalone_fec = [0i16; 1_920];
                    assert_eq!(
                        Decoder::new(2).unwrap().decode_with_fec(
                            &standalone_packet[..standalone_payload + 1],
                            &mut standalone_regular[..interval_samples],
                            &mut standalone_fec[..interval_samples],
                            sample_rate as u32,
                        ),
                        Ok(FecDecodeResult {
                            frames: interval_frames,
                            fec_frames: interval_frames,
                        }),
                    );
                    assert_eq!(
                        &fec[2 * interval_samples..3 * interval_samples],
                        &standalone_fec[..interval_samples],
                        "later mid-only FEC retained hidden pre-gap stereo history at sample_rate={sample_rate}",
                    );
                }
            }
        }
    }

    #[test]
    fn silk_entry_points_reset_state_after_celt_even_through_dtx() {
        let make_pcm = |scale: i32| {
            let mut pcm = [0i16; 960];
            for (index, sample) in pcm.iter_mut().enumerate() {
                *sample = (((index % 43) as i32 - 21) * scale) as i16;
            }
            pcm
        };
        let first_pcm = make_pcm(350);
        let next_pcm = make_pcm(700);
        let celt_pcm = make_pcm(1_100);
        let mut first_silk = [0u8; MAX_FRAME_BYTES + 1];
        let first_silk_len = Encoder::new(1)
            .unwrap()
            .encode(&first_pcm, 48_000, &mut first_silk)
            .unwrap();
        let mut next_silk = [0u8; MAX_FRAME_BYTES + 1];
        let next_silk_len = Encoder::new(1)
            .unwrap()
            .encode(&next_pcm, 48_000, &mut next_silk)
            .unwrap();
        let mut celt = [0u8; MAX_FRAME_BYTES + 1];
        let celt_len = Encoder::new(1)
            .unwrap()
            .encode_celt(&celt_pcm, 48_000, &mut celt)
            .unwrap();
        let dtx = [1 << 3, 0x7f];

        let mut scratch = [0i16; 960];
        let mut fec = [0i16; 960];
        let mut transitioned = Decoder::new(1).unwrap();
        transitioned
            .decode(&first_silk[..first_silk_len], &mut scratch, 48_000)
            .unwrap();
        transitioned
            .decode(&celt[..celt_len], &mut scratch, 48_000)
            .unwrap();
        let mut actual = [0i16; 960];
        transitioned
            .decode_with_fec(&next_silk[..next_silk_len], &mut actual, &mut fec, 48_000)
            .unwrap();
        let mut expected = [0i16; 960];
        Decoder::new(1)
            .unwrap()
            .decode_with_fec(&next_silk[..next_silk_len], &mut expected, &mut fec, 48_000)
            .unwrap();
        assert_eq!(actual, expected);

        let mut fec_transitioned = Decoder::new(1).unwrap();
        fec_transitioned
            .decode(&first_silk[..first_silk_len], &mut scratch, 48_000)
            .unwrap();
        fec_transitioned
            .decode(&celt[..celt_len], &mut scratch, 48_000)
            .unwrap();
        fec_transitioned
            .decode_with_fec(&dtx, &mut scratch, &mut fec, 48_000)
            .unwrap();
        let mut after_fec_dtx = [0i16; 960];
        fec_transitioned
            .decode_with_fec(
                &next_silk[..next_silk_len],
                &mut after_fec_dtx,
                &mut fec,
                48_000,
            )
            .unwrap();
        let mut fresh_after_fec_dtx = Decoder::new(1).unwrap();
        fresh_after_fec_dtx
            .decode_with_fec(&dtx, &mut scratch, &mut fec, 48_000)
            .unwrap();
        fresh_after_fec_dtx
            .decode_with_fec(&next_silk[..next_silk_len], &mut expected, &mut fec, 48_000)
            .unwrap();
        assert_eq!(after_fec_dtx, expected);

        let mut regular_transitioned = Decoder::new(1).unwrap();
        regular_transitioned
            .decode(&first_silk[..first_silk_len], &mut scratch, 48_000)
            .unwrap();
        regular_transitioned
            .decode(&celt[..celt_len], &mut scratch, 48_000)
            .unwrap();
        regular_transitioned
            .decode(&dtx, &mut scratch, 48_000)
            .unwrap();
        let mut after_regular_dtx = [0i16; 960];
        regular_transitioned
            .decode(&next_silk[..next_silk_len], &mut after_regular_dtx, 48_000)
            .unwrap();
        let mut fresh_after_regular_dtx = Decoder::new(1).unwrap();
        fresh_after_regular_dtx
            .decode(&dtx, &mut scratch, 48_000)
            .unwrap();
        fresh_after_regular_dtx
            .decode(&next_silk[..next_silk_len], &mut expected, 48_000)
            .unwrap();
        assert_eq!(after_regular_dtx, expected);
    }

    #[test]
    fn target_mode_dtx_does_not_hide_celt_or_hybrid_state_transitions() {
        let make_pcm = |scale: i32| {
            let mut pcm = [0i16; 960];
            for (index, sample) in pcm.iter_mut().enumerate() {
                *sample = (((index % 47) as i32 - 23) * scale) as i16;
            }
            pcm
        };
        let first_pcm = make_pcm(300);
        let middle_pcm = make_pcm(700);
        let target_pcm = make_pcm(1_100);
        let mut first_celt = [0u8; MAX_FRAME_BYTES + 1];
        let first_celt_len = Encoder::new(1)
            .unwrap()
            .encode_celt(&first_pcm, 48_000, &mut first_celt)
            .unwrap();
        let mut target_celt = [0u8; MAX_FRAME_BYTES + 1];
        let target_celt_len = Encoder::new(1)
            .unwrap()
            .encode_celt(&target_pcm, 48_000, &mut target_celt)
            .unwrap();
        let mut silk = [0u8; MAX_FRAME_BYTES + 1];
        let silk_len = Encoder::new(1)
            .unwrap()
            .encode(&middle_pcm, 48_000, &mut silk)
            .unwrap();
        let celt_dtx = [31 << 3, 0x7f];
        let mut scratch = [0i16; 960];
        let mut stale_celt = Decoder::new(1).unwrap();
        stale_celt
            .decode(&first_celt[..first_celt_len], &mut scratch, 48_000)
            .unwrap();
        stale_celt
            .decode(&silk[..silk_len], &mut scratch, 48_000)
            .unwrap();
        stale_celt.decode(&celt_dtx, &mut scratch, 48_000).unwrap();
        let mut actual_celt = [0i16; 960];
        stale_celt
            .decode(&target_celt[..target_celt_len], &mut actual_celt, 48_000)
            .unwrap();
        let mut fresh_celt = Decoder::new(1).unwrap();
        fresh_celt
            .decode(&silk[..silk_len], &mut scratch, 48_000)
            .unwrap();
        fresh_celt.decode(&celt_dtx, &mut scratch, 48_000).unwrap();
        let mut expected_celt = [0i16; 960];
        fresh_celt
            .decode(&target_celt[..target_celt_len], &mut expected_celt, 48_000)
            .unwrap();
        assert_eq!(actual_celt, expected_celt);

        let mut first_hybrid = [0u8; MAX_FRAME_BYTES + 1];
        let first_hybrid_len = Encoder::new(1)
            .unwrap()
            .encode_hybrid(&first_pcm, 48_000, &mut first_hybrid)
            .unwrap();
        let mut target_hybrid = [0u8; MAX_FRAME_BYTES + 1];
        let target_hybrid_len = Encoder::new(1)
            .unwrap()
            .encode_hybrid(&target_pcm, 48_000, &mut target_hybrid)
            .unwrap();
        let hybrid_dtx = [15 << 3, 0x7f];
        let mut stale_hybrid = Decoder::new(1).unwrap();
        stale_hybrid
            .decode(&first_hybrid[..first_hybrid_len], &mut scratch, 48_000)
            .unwrap();
        stale_hybrid
            .decode(&first_celt[..first_celt_len], &mut scratch, 48_000)
            .unwrap();
        stale_hybrid
            .decode(&hybrid_dtx, &mut scratch, 48_000)
            .unwrap();
        let mut actual_hybrid = [0i16; 960];
        stale_hybrid
            .decode(
                &target_hybrid[..target_hybrid_len],
                &mut actual_hybrid,
                48_000,
            )
            .unwrap();
        let mut fresh_hybrid = Decoder::new(1).unwrap();
        fresh_hybrid
            .decode(&first_celt[..first_celt_len], &mut scratch, 48_000)
            .unwrap();
        fresh_hybrid
            .decode(&hybrid_dtx, &mut scratch, 48_000)
            .unwrap();
        let mut expected_hybrid = [0i16; 960];
        fresh_hybrid
            .decode(
                &target_hybrid[..target_hybrid_len],
                &mut expected_hybrid,
                48_000,
            )
            .unwrap();
        assert_eq!(actual_hybrid, expected_hybrid);
    }

    #[test]
    fn mode_switching_dtx_prepares_target_state_for_loss_concealment() {
        let make_pcm = |scale: i32| {
            let mut pcm = [0i16; 960];
            for (index, sample) in pcm.iter_mut().enumerate() {
                *sample = (((index % 41) as i32 - 20) * scale) as i16;
            }
            pcm
        };
        let first_pcm = make_pcm(400);
        let middle_pcm = make_pcm(900);
        let mut first_silk = [0u8; MAX_FRAME_BYTES + 1];
        let first_silk_len = Encoder::new(1)
            .unwrap()
            .encode(&first_pcm, 48_000, &mut first_silk)
            .unwrap();
        let mut middle_silk = [0u8; MAX_FRAME_BYTES + 1];
        let middle_silk_len = Encoder::new(1)
            .unwrap()
            .encode(&middle_pcm, 48_000, &mut middle_silk)
            .unwrap();
        let mut first_celt = [0u8; MAX_FRAME_BYTES + 1];
        let first_celt_len = Encoder::new(1)
            .unwrap()
            .encode_celt(&first_pcm, 48_000, &mut first_celt)
            .unwrap();
        let mut middle_celt = [0u8; MAX_FRAME_BYTES + 1];
        let middle_celt_len = Encoder::new(1)
            .unwrap()
            .encode_celt(&middle_pcm, 48_000, &mut middle_celt)
            .unwrap();
        let silk_dtx = [1 << 3, 0x7f];
        let celt_dtx = [31 << 3, 0x7f];
        let mut scratch = [0i16; 960];

        let mut stale_silk = Decoder::new(1).unwrap();
        stale_silk
            .decode(&first_silk[..first_silk_len], &mut scratch, 48_000)
            .unwrap();
        stale_silk
            .decode(&middle_celt[..middle_celt_len], &mut scratch, 48_000)
            .unwrap();
        stale_silk.decode(&silk_dtx, &mut scratch, 48_000).unwrap();
        let mut actual_silk_loss = [0i16; 960];
        stale_silk
            .decode_loss(&mut actual_silk_loss, 48_000)
            .unwrap();
        let mut fresh_silk = Decoder::new(1).unwrap();
        fresh_silk
            .decode(&middle_celt[..middle_celt_len], &mut scratch, 48_000)
            .unwrap();
        fresh_silk.decode(&silk_dtx, &mut scratch, 48_000).unwrap();
        let mut expected_silk_loss = [0i16; 960];
        fresh_silk
            .decode_loss(&mut expected_silk_loss, 48_000)
            .unwrap();
        assert_eq!(actual_silk_loss, expected_silk_loss);
        assert!(actual_silk_loss.iter().all(|&sample| sample == 0));

        let mut stale_celt = Decoder::new(1).unwrap();
        stale_celt
            .decode(&first_celt[..first_celt_len], &mut scratch, 48_000)
            .unwrap();
        stale_celt
            .decode(&middle_silk[..middle_silk_len], &mut scratch, 48_000)
            .unwrap();
        stale_celt.decode(&celt_dtx, &mut scratch, 48_000).unwrap();
        let mut actual_celt_loss = [0i16; 960];
        stale_celt
            .decode_loss(&mut actual_celt_loss, 48_000)
            .unwrap();
        let mut fresh_celt = Decoder::new(1).unwrap();
        fresh_celt
            .decode(&middle_silk[..middle_silk_len], &mut scratch, 48_000)
            .unwrap();
        fresh_celt.decode(&celt_dtx, &mut scratch, 48_000).unwrap();
        let mut expected_celt_loss = [0i16; 960];
        fresh_celt
            .decode_loss(&mut expected_celt_loss, 48_000)
            .unwrap();
        assert_eq!(actual_celt_loss, expected_celt_loss);
        assert!(actual_celt_loss.iter().all(|&sample| sample == 0));
    }

    #[test]
    fn decode_with_fec_regular_path_covers_every_silk_duration_rate_and_channel_geometry() {
        for coded_channels in [1u8, 2] {
            for bandwidth in [Bandwidth::Narrow, Bandwidth::Medium, Bandwidth::Wide] {
                for duration_us in [10_000usize, 20_000, 40_000, 60_000] {
                    let input_frames = 48_000 * duration_us / 1_000_000;
                    let input_samples = input_frames * usize::from(coded_channels);
                    let mut input = [0i16; 5_760];
                    for (index, sample) in input[..input_samples].iter_mut().enumerate() {
                        *sample = (((index % 37) as i32 - 18) * 1_200) as i16;
                    }
                    let mut packet = [0u8; MAX_FRAME_BYTES + 1];
                    let packet_len = Encoder::new(coded_channels)
                        .unwrap()
                        .encode_silk_bandwidth_duration(
                            &input[..input_samples],
                            48_000,
                            bandwidth,
                            duration_us as u32,
                            &mut packet,
                        )
                        .unwrap();
                    assert!(packet_len > 2);

                    for output_channels in [1u8, 2] {
                        for sample_rate in [8_000usize, 12_000, 16_000, 24_000, 48_000] {
                            let frames = sample_rate * duration_us / 1_000_000;
                            let samples = frames * usize::from(output_channels);
                            let mut regular = [0x35a7i16; 5_762];
                            let mut fec = [0x6b19i16; 5_762];
                            assert_eq!(
                                Decoder::new(output_channels).unwrap().decode_with_fec(
                                    &packet[..packet_len],
                                    &mut regular[1..samples + 1],
                                    &mut fec[1..samples + 1],
                                    sample_rate as u32,
                                ),
                                Ok(FecDecodeResult {
                                    frames,
                                    fec_frames: 0,
                                }),
                                "coded_channels={coded_channels} output_channels={output_channels} bandwidth={bandwidth:?} duration_us={duration_us} sample_rate={sample_rate}",
                            );
                            assert_eq!((regular[0], regular[samples + 1]), (0x35a7, 0x35a7));
                            assert_eq!((fec[0], fec[samples + 1]), (0x6b19, 0x6b19));
                            assert!(fec[1..samples + 1].iter().all(|&sample| sample == 0));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn fec_decode_treats_every_one_byte_silk_frame_as_dtx() {
        for config in 0u8..12 {
            for stereo in [false, true] {
                for payload in [0x00u8, 0x7f, 0xff] {
                    let packet = [config << 3 | u8::from(stereo) << 2, payload];
                    let parsed = Packet::parse(&packet).unwrap();
                    let frames = 48_000 * parsed.frame_duration_us as usize / 1_000_000;
                    let samples = frames * 2;
                    let mut regular = [1i16; 5_760];
                    let mut fec = [1i16; 5_760];
                    let mut decoder = Decoder::new(2).unwrap();
                    assert_eq!(
                        decoder.decode_with_fec(
                            &packet,
                            &mut regular[..samples],
                            &mut fec[..samples],
                            48_000,
                        ),
                        Ok(FecDecodeResult {
                            frames,
                            fec_frames: 0,
                        }),
                        "config={config} stereo={stereo} payload={payload:#04x}",
                    );
                    assert!(regular[..samples].iter().all(|&sample| sample == 0));
                    assert!(fec[..samples].iter().all(|&sample| sample == 0));
                    assert_eq!(decoder.final_range(), 0);
                }
            }
        }
    }

    #[test]
    fn exhaustive_short_packets_preserve_all_parser_bounds() {
        for first in 0u16..=255 {
            for second in 0u16..=255 {
                let bytes = [first as u8, second as u8];
                if let Ok(packet) = Packet::parse(&bytes) {
                    assert!((1..=MAX_FRAMES as u8).contains(&packet.frame_count));
                    assert!(packet.frame_duration_us * u32::from(packet.frame_count) <= 120_000);
                    for frame in &packet.frames[..usize::from(packet.frame_count)] {
                        let start = usize::from(frame.offset);
                        let end = start + usize::from(frame.len);
                        assert!(start <= bytes.len());
                        assert!(end <= bytes.len());
                    }
                }
            }
        }
    }

    #[test]
    fn deterministic_malformed_packets_never_escape_output_bounds() {
        let mut seed = 0x91e1_0da5u32;
        for length in 1..=16 {
            let mut packet = [0u8; 16];
            for byte in &mut packet[..length] {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                *byte = seed as u8;
            }
            let mut guarded = [0x5a5ai16; 11_522];
            let result =
                Decoder::new(2)
                    .unwrap()
                    .decode(&packet[..length], &mut guarded[1..11_521], 48_000);
            assert_eq!(guarded[0], 0x5a5a);
            assert_eq!(guarded[11_521], 0x5a5a);
            if let Ok(frames) = result {
                assert!(frames <= 5_760);
            }
        }
    }

    #[test]
    fn valid_mode_packets_survive_every_single_bit_flip_and_truncation_safely() {
        let mut input = [0i16; 960];
        for (index, sample) in input.iter_mut().enumerate() {
            *sample = (((index % 43) as i32 - 21) * 390) as i16;
        }
        for (mode, bitrate) in [
            (EncoderMode::Silk, 6_000u32),
            (EncoderMode::Hybrid, 32_000),
            (EncoderMode::Celt, 48_000),
        ] {
            let mut original = [0u8; MAX_FRAME_BYTES + 1];
            let size = Encoder::new(1)
                .unwrap()
                .encode_mode(mode, bitrate, &input, 48_000, &mut original)
                .unwrap();

            for length in 0..size {
                let mut guarded = [0x35a7i16; 962];
                let result = Decoder::new(1).unwrap().decode(
                    &original[..length],
                    &mut guarded[1..961],
                    48_000,
                );
                assert_eq!((guarded[0], guarded[961]), (0x35a7, 0x35a7));
                if let Ok(frames) = result {
                    assert!(frames <= 960);
                }
            }

            for byte in 0..size {
                for bit in 0..8 {
                    let mut mutated = original;
                    mutated[byte] ^= 1 << bit;
                    let mut guarded = [0x6b19i16; 962];
                    let result = Decoder::new(1).unwrap().decode(
                        &mutated[..size],
                        &mut guarded[1..961],
                        48_000,
                    );
                    assert_eq!((guarded[0], guarded[961]), (0x6b19, 0x6b19));
                    if let Ok(frames) = result {
                        assert!(frames <= 960);
                    }
                }
            }
        }
    }
}
