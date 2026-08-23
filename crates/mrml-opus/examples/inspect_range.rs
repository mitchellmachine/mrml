//! Print MRML Opus decoder final-range values for one or more packet hex strings.

use mrml_opus::{Decoder, Packet};

fn main() -> Result<(), String> {
    let mut arguments = std::env::args_os().skip(1);
    let first = arguments.next().ok_or_else(|| {
        "usage: inspect_range <packet-hex> [<packet-hex> ...]".to_owned()
    })?;
    let mut packets = vec![first];
    packets.extend(arguments);
    for argument in packets {
        let hex = argument.to_string_lossy().to_uppercase();
        let packet = parse_hex(&hex)?;
        let mut decoder = Decoder::new(2).map_err(|error| format!("decoder: {error}"))?;
        let mut pcm = [0i16; 11_520];
        let parsed = Packet::parse(&packet).map_err(|error| format!("parse: {error}"))?;
        let samples = 48_000usize
            .checked_mul(parsed.frame_duration_us as usize)
            .and_then(|value| value.checked_div(1_000_000))
            .and_then(|value| value.checked_mul(usize::from(parsed.frame_count)))
            .ok_or_else(|| "sample count overflow".to_owned())?;
        decoder
            .decode(&packet, &mut pcm[..samples * 2], 48_000)
            .map_err(|error| format!("decode: {error}"))?;
        println!("{hex} final_range={:08x}", decoder.final_range());
    }
    Ok(())
}

fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("hex input must contain complete bytes".to_owned());
    }
    (0..text.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&text[offset..offset + 2], 16)
                .map_err(|_| format!("invalid hex at character {offset}"))
        })
        .collect()
}
