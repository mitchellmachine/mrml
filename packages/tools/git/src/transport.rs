use crate::{ObjectFormat, ObjectId};
use core::fmt;
use mrml_runtime::{Text, Vector};

const MAX_PACKET: usize = 65_520;
const MAX_REFS: usize = 1_000_000;
const MAX_CAPABILITIES: usize = 4096;
const MAX_CAPABILITY_BYTES: usize = 256 * 1024;
const MAX_RESPONSE: usize = 1024 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteRef {
    pub name: Text,
    pub id: ObjectId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Advertisement {
    pub refs: Vector<RemoteRef>,
    pub capabilities: Vector<Text>,
    pub object_format: ObjectFormat,
    pub object_format_explicit: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    Truncated,
    PacketLength,
    InvalidHex,
    InvalidUtf8,
    InvalidObjectId,
    InvalidReference,
    TooManyRefs,
    TooLarge,
    RemoteError,
    MissingPack,
}

pub fn encode_packet(payload: &[u8], output: &mut Vector<u8>) -> Result<(), TransportError> {
    let length = payload
        .len()
        .checked_add(4)
        .ok_or(TransportError::TooLarge)?;
    if !(4..=MAX_PACKET).contains(&length) {
        return Err(TransportError::PacketLength);
    }
    let hex = hex4(length as u16);
    output.extend(hex);
    output.extend(payload.iter().copied());
    Ok(())
}

pub fn encode_flush(output: &mut Vector<u8>) {
    output.extend(*b"0000");
}

pub fn decode_packets(source: &[u8]) -> Result<Vector<Option<Vector<u8>>>, TransportError> {
    let mut cursor = 0usize;
    let mut packets = Vector::new();
    while cursor < source.len() {
        let header = source
            .get(cursor..cursor + 4)
            .ok_or(TransportError::Truncated)?;
        cursor += 4;
        let length = parse_hex4(header)?;
        if length == 0 {
            packets.push(None);
            continue;
        }
        if length < 4 {
            return Err(TransportError::PacketLength);
        }
        let payload = length - 4;
        if payload > MAX_PACKET - 4 {
            return Err(TransportError::PacketLength);
        }
        let end = cursor
            .checked_add(payload)
            .ok_or(TransportError::TooLarge)?;
        let bytes = source.get(cursor..end).ok_or(TransportError::Truncated)?;
        let mut owned = Vector::new();
        owned.extend(bytes.iter().copied());
        packets.push(Some(owned));
        cursor = end;
    }
    Ok(packets)
}

pub fn parse_advertisement(source: &[u8]) -> Result<Advertisement, TransportError> {
    let packets = decode_packets(source)?;
    let flush = packets
        .iter()
        .position(Option::is_none)
        .ok_or(TransportError::Truncated)?;
    if flush + 1 != packets.len() {
        return Err(TransportError::InvalidReference);
    }
    let mut refs: Vector<RemoteRef> = Vector::new();
    let mut capabilities = Vector::new();
    let mut first = true;
    let mut object_format = None;
    let mut object_format_explicit = false;
    let mut capability_bytes = 0usize;
    let mut protocol_header = false;
    let mut last_was_peeled = false;
    for packet in packets {
        let Some(bytes) = packet else { break };
        let text = core::str::from_utf8(&bytes)
            .map_err(|_| TransportError::InvalidUtf8)?
            .trim_end_matches('\n');
        if text.starts_with("ERR ") {
            return Err(TransportError::RemoteError);
        }
        if first && text == "version 1" {
            if protocol_header {
                return Err(TransportError::InvalidReference);
            }
            protocol_header = true;
            continue;
        }
        let (reference, caps) = if first {
            match text.split_once('\0') {
                Some((left, right)) => (left, Some(right)),
                None => (text, None),
            }
        } else {
            (text, None)
        };
        if let Some(caps) = caps {
            for cap in caps.split_whitespace() {
                if cap.chars().any(char::is_control) {
                    return Err(TransportError::InvalidReference);
                }
                capability_bytes = capability_bytes
                    .checked_add(cap.len())
                    .ok_or(TransportError::TooLarge)?;
                if capabilities.len() >= MAX_CAPABILITIES || capability_bytes > MAX_CAPABILITY_BYTES
                {
                    return Err(TransportError::TooLarge);
                }
                if let Some(name) = cap.strip_prefix("object-format=") {
                    let parsed =
                        parse_object_format(name).ok_or(TransportError::InvalidObjectId)?;
                    if object_format.is_some_and(|selected| selected != parsed) {
                        return Err(TransportError::InvalidObjectId);
                    }
                    object_format = Some(parsed);
                    object_format_explicit = true;
                }
                capabilities.push(cap.into());
            }
        }
        let selected = object_format.unwrap_or(ObjectFormat::Sha1);
        let (id, name) = reference
            .split_once(' ')
            .ok_or(TransportError::InvalidReference)?;
        let id = ObjectId::parse_for(selected, id).ok_or(TransportError::InvalidObjectId)?;
        if name == "capabilities^{}" {
            if !id.is_zero() {
                return Err(TransportError::InvalidReference);
            }
            last_was_peeled = false;
        } else if let Some(tag) = name.strip_suffix("^{}") {
            if !tag.starts_with("refs/tags/")
                || last_was_peeled
                || refs.last().is_none_or(|reference| reference.name != tag)
                || id.is_zero()
            {
                return Err(TransportError::InvalidReference);
            }
            validate_ref(tag)?;
            last_was_peeled = true;
        } else {
            validate_ref(name)?;
            if refs.len() >= MAX_REFS {
                return Err(TransportError::TooManyRefs);
            }
            refs.push(RemoteRef {
                name: name.into(),
                id,
            });
            last_was_peeled = false;
        }
        first = false;
    }
    Ok(Advertisement {
        refs,
        capabilities,
        object_format: object_format.unwrap_or(ObjectFormat::Sha1),
        object_format_explicit,
    })
}

pub fn fetch_request(
    wants: &[ObjectId],
    have: &[ObjectId],
    capabilities: &[&str],
) -> Result<Vector<u8>, TransportError> {
    if wants.is_empty() {
        return Err(TransportError::InvalidObjectId);
    }
    let object_format = wants[0].format();
    if wants
        .iter()
        .chain(have)
        .any(|id| id.format() != object_format)
    {
        return Err(TransportError::InvalidObjectId);
    }
    let mut negotiated_object_format = false;
    for capability in capabilities {
        if let Some(name) = capability.strip_prefix("object-format=") {
            if negotiated_object_format || parse_object_format(name) != Some(object_format) {
                return Err(TransportError::InvalidObjectId);
            }
            negotiated_object_format = true;
        }
    }
    if object_format == ObjectFormat::Sha256 && !negotiated_object_format {
        return Err(TransportError::InvalidObjectId);
    }
    let mut output = Vector::new();
    for (index, id) in wants.iter().enumerate() {
        let mut line = mrml_runtime::mrml_format!("want {id}");
        if index == 0 {
            for capability in capabilities {
                if capability.is_empty()
                    || capability
                        .chars()
                        .any(|c| c.is_control() || c.is_whitespace())
                {
                    return Err(TransportError::InvalidReference);
                }
                line.push(' ');
                line.push_str(capability);
            }
        }
        line.push('\n');
        encode_packet(line.as_bytes(), &mut output)?;
    }
    encode_flush(&mut output);
    for id in have {
        encode_packet(
            mrml_runtime::mrml_format!("have {id}\n").as_bytes(),
            &mut output,
        )?;
    }
    encode_packet(b"done\n", &mut output)?;
    Ok(output)
}

pub fn extract_pack_response(source: &[u8], side_band: bool) -> Result<Vector<u8>, TransportError> {
    if !side_band {
        let mut start = 0usize;
        while !source
            .get(start..)
            .is_some_and(|remaining| remaining.starts_with(b"PACK"))
        {
            let header = source
                .get(start..start + 4)
                .ok_or(TransportError::Truncated)?;
            let length = parse_hex4(header)?;
            if length == 0 {
                start = start.checked_add(4).ok_or(TransportError::TooLarge)?;
                continue;
            }
            if length < 4 {
                return Err(TransportError::PacketLength);
            }
            let end = start.checked_add(length).ok_or(TransportError::TooLarge)?;
            let payload = source
                .get(start + 4..end)
                .ok_or(TransportError::Truncated)?;
            let text = core::str::from_utf8(payload).map_err(|_| TransportError::InvalidUtf8)?;
            if text != "NAK\n" && !text.starts_with("ACK ") {
                return Err(TransportError::InvalidReference);
            }
            start = end;
        }
        let mut pack = Vector::new();
        pack.extend(source[start..].iter().copied());
        return Ok(pack);
    }
    let packets = decode_packets(source)?;
    let mut pack = Vector::new();
    for packet in packets {
        let Some(bytes) = packet else { continue };
        if bytes.is_empty() {
            continue;
        }
        match bytes[0] {
            1 => {
                if pack
                    .len()
                    .checked_add(bytes.len() - 1)
                    .is_none_or(|n| n > MAX_RESPONSE)
                {
                    return Err(TransportError::TooLarge);
                }
                pack.extend(bytes[1..].iter().copied());
            }
            2 => {}
            3 => return Err(TransportError::RemoteError),
            _ => {
                let text = core::str::from_utf8(&bytes).unwrap_or("");
                if !matches!(text, "NAK\n") && !text.starts_with("ACK ") {
                    return Err(TransportError::InvalidReference);
                }
            }
        }
    }
    if pack.starts_with(b"PACK") {
        Ok(pack)
    } else {
        Err(TransportError::MissingPack)
    }
}

pub fn push_request(
    old: ObjectId,
    new: ObjectId,
    reference: &str,
    pack: &[u8],
) -> Result<Vector<u8>, TransportError> {
    push_request_mode(old, new, reference, pack, true)
}

pub fn push_request_mode(
    old: ObjectId,
    new: ObjectId,
    reference: &str,
    pack: &[u8],
    side_band: bool,
) -> Result<Vector<u8>, TransportError> {
    push_request_mode_negotiated(
        old,
        new,
        reference,
        pack,
        side_band,
        new.format() == ObjectFormat::Sha256,
    )
}

pub fn push_request_mode_negotiated(
    old: ObjectId,
    new: ObjectId,
    reference: &str,
    pack: &[u8],
    side_band: bool,
    object_format_explicit: bool,
) -> Result<Vector<u8>, TransportError> {
    validate_ref(reference)?;
    if old == new || old.format() != new.format() {
        return Err(TransportError::InvalidObjectId);
    }
    let mut capabilities = Text::from("report-status");
    if side_band {
        capabilities.push_str(" side-band-64k");
    }
    if object_format_explicit {
        capabilities.push_str(" object-format=");
        capabilities.push_str(new.format().name());
    }
    let line = mrml_runtime::mrml_format!("{old} {new} {reference}\0{capabilities}\n");
    let mut output = Vector::new();
    encode_packet(line.as_bytes(), &mut output)?;
    encode_flush(&mut output);
    if output
        .len()
        .checked_add(pack.len())
        .is_none_or(|n| n > MAX_RESPONSE)
    {
        return Err(TransportError::TooLarge);
    }
    output.extend(pack.iter().copied());
    Ok(output)
}

/// Builds only the bounded command section for MRML's protected receive-pack
/// profile. The caller streams the pack immediately after this prefix.
pub fn protected_push_command_prefix(
    old: ObjectId,
    new: ObjectId,
    reference: &str,
) -> Result<Vector<u8>, TransportError> {
    validate_ref(reference)?;
    if old == new || old.format() != ObjectFormat::Sha256 || new.format() != ObjectFormat::Sha256 {
        return Err(TransportError::InvalidObjectId);
    }
    let line = mrml_runtime::mrml_format!(
        "{old} {new} {reference}\0report-status-v2 atomic side-band-64k ofs-delta mrml-proof-v1 mrml-receipt-v1 object-format=sha256\n"
    );
    let mut output = Vector::new();
    encode_packet(line.as_bytes(), &mut output)?;
    encode_flush(&mut output);
    if output.len() > 1024 {
        return Err(TransportError::TooLarge);
    }
    Ok(output)
}

pub fn protected_push_command_with_proofs(
    old: ObjectId,
    new: ObjectId,
    reference: &str,
    proofs: &[crate::DetachedCommitProofRecord],
) -> Result<Vector<u8>, TransportError> {
    if proofs.is_empty()
        || proofs.len() > crate::MAX_DETACHED_COMMIT_PROOFS
        || !proofs
            .windows(2)
            .all(|pair| pair[0].commit() < pair[1].commit())
    {
        return Err(TransportError::TooLarge);
    }
    let mut output = protected_push_command_prefix(old, new, reference)?;
    output.truncate(output.len() - 4);
    output
        .try_extend_from_slice(b"0001")
        .map_err(|_| TransportError::TooLarge)?;
    for proof in proofs {
        let mut payload = Vector::new();
        payload
            .try_extend_from_slice(crate::smart_protocol::RECEIVE_PROOF_MAGIC)
            .map_err(|_| TransportError::TooLarge)?;
        payload
            .try_extend_from_slice(proof.commit().as_bytes())
            .map_err(|_| TransportError::TooLarge)?;
        payload
            .try_extend_from_slice(&(proof.openpgp_signature().len() as u16).to_be_bytes())
            .map_err(|_| TransportError::TooLarge)?;
        payload
            .try_extend_from_slice(&(proof.ml_dsa_signature().len() as u16).to_be_bytes())
            .map_err(|_| TransportError::TooLarge)?;
        payload
            .try_extend_from_slice(proof.openpgp_signature())
            .map_err(|_| TransportError::TooLarge)?;
        payload
            .try_extend_from_slice(proof.ml_dsa_signature())
            .map_err(|_| TransportError::TooLarge)?;
        encode_packet(&payload, &mut output)?;
    }
    output
        .try_extend_from_slice(b"0000")
        .map_err(|_| TransportError::TooLarge)?;
    Ok(output)
}

pub fn parse_push_response(source: &[u8], reference: &str) -> Result<(), TransportError> {
    parse_push_response_mode(source, reference, true)
}

pub fn parse_push_response_mode(
    source: &[u8],
    reference: &str,
    side_band: bool,
) -> Result<(), TransportError> {
    validate_ref(reference)?;
    let report = if side_band {
        let outer = decode_packets(source)?;
        let mut report = Vector::new();
        for packet in outer {
            let Some(bytes) = packet else { continue };
            if bytes.is_empty() {
                continue;
            }
            match bytes[0] {
                1 => report.extend(bytes[1..].iter().copied()),
                2 => {}
                3 => return Err(TransportError::RemoteError),
                _ => return Err(TransportError::InvalidReference),
            }
        }
        report
    } else {
        let mut report = Vector::new();
        report.extend(source.iter().copied());
        report
    };
    let packets = decode_packets(&report)?;
    let mut unpack = false;
    let expected = mrml_runtime::mrml_format!("ok {reference}");
    for packet in packets {
        let Some(bytes) = packet else { continue };
        let line = core::str::from_utf8(&bytes)
            .map_err(|_| TransportError::InvalidUtf8)?
            .trim_end_matches('\n');
        if line == "unpack ok" {
            unpack = true;
        } else if expected == line && unpack {
            return Ok(());
        } else if line.starts_with("ng ") || line.starts_with("unpack ") {
            return Err(TransportError::RemoteError);
        }
    }
    Err(TransportError::RemoteError)
}

pub fn parse_protected_push_response_mode(
    source: &[u8],
    reference: &str,
    side_band: bool,
) -> Result<Vector<u8>, TransportError> {
    validate_ref(reference)?;
    let report = if side_band {
        let outer = decode_packets(source)?;
        let mut report = Vector::new();
        for packet in outer {
            let Some(bytes) = packet else { continue };
            if bytes.is_empty() {
                continue;
            }
            match bytes[0] {
                1 => report.extend(bytes[1..].iter().copied()),
                2 => {}
                3 => return Err(TransportError::RemoteError),
                _ => return Err(TransportError::InvalidReference),
            }
        }
        report
    } else {
        source.iter().copied().collect()
    };
    let expected = mrml_runtime::mrml_format!("ok {reference}");
    let mut unpack = false;
    let mut updated = false;
    let mut receipt = None;
    for packet in decode_packets(&report)? {
        let Some(bytes) = packet else { continue };
        if let Some(encoded) = bytes.strip_prefix(b"mrml-receipt-v1 ") {
            if receipt.is_some()
                || crate::parse_authenticated_audit_receipt(encoded).is_err()
            {
                return Err(TransportError::RemoteError);
            }
            receipt = Some(encoded.iter().copied().collect());
            continue;
        }
        let line = core::str::from_utf8(&bytes)
            .map_err(|_| TransportError::InvalidUtf8)?
            .trim_end_matches('\n');
        if line == "unpack ok" && !unpack {
            unpack = true;
        } else if expected == line && unpack && !updated {
            updated = true;
        } else if line.starts_with("ng ") || line.starts_with("unpack ") {
            return Err(TransportError::RemoteError);
        } else {
            return Err(TransportError::RemoteError);
        }
    }
    if unpack && updated {
        receipt.ok_or(TransportError::RemoteError)
    } else {
        Err(TransportError::RemoteError)
    }
}

fn validate_ref(name: &str) -> Result<(), TransportError> {
    if !name.starts_with("refs/") && name != "HEAD" {
        return Err(TransportError::InvalidReference);
    }
    if name.is_empty()
        || name.contains("..")
        || name.contains("@{")
        || name.contains(['\\', ' ', '~', '^', ':', '?', '*', '['])
        || name.chars().any(char::is_control)
    {
        Err(TransportError::InvalidReference)
    } else {
        Ok(())
    }
}
fn parse_object_format(name: &str) -> Option<ObjectFormat> {
    match name {
        "sha1" => Some(ObjectFormat::Sha1),
        "sha256" => Some(ObjectFormat::Sha256),
        _ => None,
    }
}
fn parse_hex4(bytes: &[u8]) -> Result<usize, TransportError> {
    if bytes.len() != 4 {
        return Err(TransportError::Truncated);
    }
    let mut value = 0usize;
    for byte in bytes {
        value = value * 16
            + match byte {
                b'0'..=b'9' => (*byte - b'0') as usize,
                b'a'..=b'f' => (*byte - b'a' + 10) as usize,
                b'A'..=b'F' => (*byte - b'A' + 10) as usize,
                _ => return Err(TransportError::InvalidHex),
            };
    }
    Ok(value)
}
fn hex4(value: u16) -> [u8; 4] {
    const H: &[u8; 16] = b"0123456789abcdef";
    [
        H[((value >> 12) & 15) as usize],
        H[((value >> 8) & 15) as usize],
        H[((value >> 4) & 15) as usize],
        H[(value & 15) as usize],
    ]
}
impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated Git protocol response",
            Self::PacketLength => "invalid Git pkt-line length",
            Self::InvalidHex => "invalid Git pkt-line hexadecimal length",
            Self::InvalidUtf8 => "Git protocol text is not UTF-8",
            Self::InvalidObjectId => "invalid advertised object ID",
            Self::InvalidReference => "invalid advertised reference or capability",
            Self::TooManyRefs => "too many advertised references",
            Self::TooLarge => "Git protocol response exceeds limit",
            Self::RemoteError => "remote Git service reported an error",
            Self::MissingPack => "Git response did not contain a pack",
        })
    }
}
impl core::error::Error for TransportError {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_capability_advertisement() {
        let id = "1111111111111111111111111111111111111111";
        let line = mrml_runtime::mrml_format!("{id} refs/heads/main\0multi_ack side-band-64k\n");
        let mut wire = Vector::new();
        encode_packet(line.as_bytes(), &mut wire).unwrap();
        encode_flush(&mut wire);
        let ad = parse_advertisement(&wire).unwrap();
        assert_eq!(ad.refs[0].name, "refs/heads/main");
        assert_eq!(ad.capabilities[1], "side-band-64k");
        assert_eq!(ad.object_format, ObjectFormat::Sha1);
    }
    #[test]
    fn negotiates_sha256_and_rejects_mixed_advertisements() {
        let id = "1111111111111111111111111111111111111111111111111111111111111111";
        let line = mrml_runtime::mrml_format!(
            "{id} refs/heads/main\0object-format=sha256 side-band-64k\n"
        );
        let mut wire = Vector::new();
        encode_packet(line.as_bytes(), &mut wire).unwrap();
        encode_flush(&mut wire);
        let advertisement = parse_advertisement(&wire).unwrap();
        assert_eq!(advertisement.object_format, ObjectFormat::Sha256);
        assert!(advertisement.object_format_explicit);
        assert_eq!(advertisement.refs[0].id.to_hex().len(), 64);

        let mut version_one = Vector::new();
        encode_packet(b"version 1\n", &mut version_one).unwrap();
        let repeated = mrml_runtime::mrml_format!(
            "{id} refs/heads/main\0object-format=sha256 object-format=sha1\n"
        );
        encode_packet(repeated.as_bytes(), &mut version_one).unwrap();
        encode_flush(&mut version_one);
        assert_eq!(
            parse_advertisement(&version_one),
            Err(TransportError::InvalidObjectId)
        );

        let missing_capability = mrml_runtime::mrml_format!("{id} refs/heads/main\n");
        let mut wire = Vector::new();
        encode_packet(missing_capability.as_bytes(), &mut wire).unwrap();
        encode_flush(&mut wire);
        assert_eq!(
            parse_advertisement(&wire),
            Err(TransportError::InvalidObjectId)
        );
    }

    #[test]
    fn accepts_only_well_formed_sha256_peeled_tag_advertisements() {
        let tag = "1111111111111111111111111111111111111111111111111111111111111111";
        let target = "2222222222222222222222222222222222222222222222222222222222222222";
        let mut wire = Vector::new();
        encode_packet(
            mrml_runtime::mrml_format!("{tag} refs/tags/v1\0object-format=sha256 side-band-64k\n")
                .as_bytes(),
            &mut wire,
        )
        .unwrap();
        encode_packet(
            mrml_runtime::mrml_format!("{target} refs/tags/v1^{{}}\n").as_bytes(),
            &mut wire,
        )
        .unwrap();
        encode_flush(&mut wire);
        let advertisement = parse_advertisement(&wire).unwrap();
        assert_eq!(advertisement.object_format, ObjectFormat::Sha256);
        assert_eq!(advertisement.refs.len(), 1);
        assert_eq!(advertisement.refs[0].name, "refs/tags/v1");
        assert_eq!(advertisement.refs[0].id.format(), ObjectFormat::Sha256);

        let mut orphan = Vector::new();
        encode_packet(
            mrml_runtime::mrml_format!("{target} refs/tags/v1^{{}}\0object-format=sha256\n")
                .as_bytes(),
            &mut orphan,
        )
        .unwrap();
        encode_flush(&mut orphan);
        assert_eq!(
            parse_advertisement(&orphan),
            Err(TransportError::InvalidReference)
        );

        let mut foreign_width = Vector::new();
        encode_packet(
            mrml_runtime::mrml_format!("{tag} refs/tags/v1\0object-format=sha256\n").as_bytes(),
            &mut foreign_width,
        )
        .unwrap();
        encode_packet(
            b"2222222222222222222222222222222222222222 refs/tags/v1^{}\n",
            &mut foreign_width,
        )
        .unwrap();
        encode_flush(&mut foreign_width);
        assert_eq!(
            parse_advertisement(&foreign_width),
            Err(TransportError::InvalidObjectId)
        );
    }
    #[test]
    fn builds_fetch_and_extracts_sideband_pack() {
        let id = ObjectId::parse("2222222222222222222222222222222222222222").unwrap();
        let request = fetch_request(&[id], &[], &["side-band-64k"]).unwrap();
        assert!(request.windows(5).any(|v| v == b"want "));
        let mut response = Vector::new();
        encode_packet(b"NAK\n", &mut response).unwrap();
        encode_packet(b"\x01PACKdata", &mut response).unwrap();
        encode_flush(&mut response);
        assert_eq!(
            &*extract_pack_response(&response, true).unwrap(),
            b"PACKdata"
        );
    }
    #[test]
    fn sha256_fetch_and_push_requests_bind_the_object_format() {
        let id = ObjectId::parse_for(
            ObjectFormat::Sha256,
            "2222222222222222222222222222222222222222222222222222222222222222",
        )
        .unwrap();
        assert_eq!(
            fetch_request(
                &[id],
                &[],
                &[
                    "side-band-64k",
                    "object-format=sha256",
                    "object-format=sha1",
                ],
            ),
            Err(TransportError::InvalidObjectId)
        );
        let fetch = fetch_request(&[id], &[], &["side-band-64k", "object-format=sha256"]).unwrap();
        assert!(
            fetch
                .windows(b"object-format=".len())
                .any(|bytes| bytes == b"object-format=")
        );
        assert_eq!(
            fetch_request(&[id], &[], &["side-band-64k"]),
            Err(TransportError::InvalidObjectId)
        );
        let push = push_request_mode(
            ObjectId::zero(ObjectFormat::Sha256),
            id,
            "refs/heads/main",
            b"PACK",
            false,
        )
        .unwrap();
        assert!(
            push.windows(b"object-format=sha256".len())
                .any(|bytes| bytes == b"object-format=sha256")
        );
    }
    #[test]
    fn rejects_malformed_lengths_and_error_band() {
        assert_eq!(decode_packets(b"0003"), Err(TransportError::PacketLength));
        let mut response = Vector::new();
        encode_packet(b"\x03denied", &mut response).unwrap();
        assert_eq!(
            extract_pack_response(&response, true),
            Err(TransportError::RemoteError)
        );
        let mut injected = Vector::new();
        encode_packet(b"ERR contains PACK bytes\n", &mut injected).unwrap();
        assert_eq!(
            extract_pack_response(&injected, false),
            Err(TransportError::InvalidReference)
        );
    }
    #[test]
    fn builds_push_and_authenticates_report_status() {
        let old = ObjectId::zero(ObjectFormat::Sha1);
        let new = ObjectId::blob(b"tip");
        let request = push_request(old, new, "refs/heads/main", b"PACK").unwrap();
        assert!(request.ends_with(b"PACK"));
        let mut report = Vector::new();
        encode_packet(b"unpack ok\n", &mut report).unwrap();
        encode_packet(b"ok refs/heads/main\n", &mut report).unwrap();
        encode_flush(&mut report);
        let mut response = Vector::new();
        let mut band = Vector::from([1]);
        band.extend(report.clone());
        encode_packet(&band, &mut response).unwrap();
        encode_flush(&mut response);
        assert_eq!(parse_push_response(&response, "refs/heads/main"), Ok(()));
        let plain = push_request_mode(old, new, "refs/heads/main", b"PACK", false).unwrap();
        let packet_length = parse_hex4(&plain[..4]).unwrap();
        assert_eq!(
            &plain[4..packet_length],
            mrml_runtime::mrml_format!("{old} {new} refs/heads/main\0report-status\n").as_bytes()
        );
        assert!(!plain.windows(13).any(|bytes| bytes == b"side-band-64"));
        assert_eq!(
            parse_push_response_mode(&report, "refs/heads/main", false),
            Ok(())
        );
    }
    #[test]
    fn protected_push_prefix_is_atomic_sha256_and_pack_free() {
        let old = ObjectId::Sha256([1; 32]);
        let new = ObjectId::Sha256([2; 32]);
        let prefix = protected_push_command_prefix(old, new, "refs/heads/main").unwrap();
        let packets = crate::decode_packets(&prefix).unwrap();
        assert_eq!(packets.len(), 2);
        let command = core::str::from_utf8(packets[0].as_deref().unwrap()).unwrap();
        let expected = mrml_runtime::mrml_format!("{old} {new} refs/heads/main\0");
        assert!(command.starts_with(expected.as_str()));
        assert!(command.contains("report-status-v2"));
        assert!(command.contains(" atomic "));
        assert!(command.contains("object-format=sha256"));
        assert!(!prefix.windows(4).any(|bytes| bytes == b"PACK"));
        assert_eq!(packets[1], None);
        assert!(
            protected_push_command_prefix(
                ObjectId::Sha1([1; 20]),
                ObjectId::Sha1([2; 20]),
                "refs/heads/main"
            )
            .is_err()
        );
    }
}
