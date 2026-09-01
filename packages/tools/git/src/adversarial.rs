//! Deterministic structured-random parser probes.
//!
//! These complement byte-exact unit vectors. Inputs and iteration counts are
//! fixed so CI exercises the same bounded hostile corpus on every target.

use crate::{
    FullRefName, ObjectFormat, RepositoryPath, decode_loose_object, decode_packets,
    parse_active_ref_state, parse_advertisement, parse_audit_receipt, parse_pack_index_v2,
    parse_pack_with_format, parse_receive_journal, parse_trust_policy,
};
use mrml_runtime::Vector;

fn next(state: &mut u64) -> u8 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    (*state >> 24) as u8
}

#[test]
fn bounded_binary_parsers_survive_deterministic_hostile_corpus() {
    let mut state = 0x4d52_4d4c_4749_5444u64;
    for case in 0..512usize {
        let length = (case * 67 + usize::from(next(&mut state))) % 2049;
        let mut input = Vector::new();
        for _ in 0..length {
            input.push(next(&mut state));
        }
        for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
            let _ = parse_pack_with_format(&input, format);
            let _ = parse_pack_index_v2(format, &input, 4096);
        }
        let _ = decode_loose_object(&input);
        let _ = decode_packets(&input);
        let _ = parse_advertisement(&input);
        let _ = parse_audit_receipt(&input);
        let _ = parse_receive_journal(&input);
        let _ = parse_active_ref_state(&input);
        let _ = parse_trust_policy(&input);
    }
}

#[test]
fn bounded_name_parsers_survive_deterministic_hostile_corpus() {
    let mut state = 0x5245_464e_414d_4553u64;
    for case in 0..1024usize {
        let length = (case * 29 + usize::from(next(&mut state))) % 513;
        let mut input = Vector::new();
        for _ in 0..length {
            input.push(next(&mut state));
        }
        if let Ok(text) = core::str::from_utf8(&input) {
            let _ = FullRefName::parse(text);
            let _ = RepositoryPath::parse(text);
        }
    }
}
