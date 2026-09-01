use mrml_acme::{DnsIdentifier, encode_base64url};

pub const MAX_DNS_PACKET: usize = 1232;
pub const MAX_DNS_TXT_RECORDS: usize = 32;
const MAX_DNS_POINTERS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsChallengeError {
    Malformed,
    Oversized,
    MultipleQuestions,
    NameTooLong,
    CompressionLoop,
    WrongZone,
    Capacity,
    StaleGeneration,
    Duplicate,
    NotFound,
    OutputTooSmall,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct TxtRecord {
    identifier: DnsIdentifier,
    digest: [u8; 32],
    generation: u64,
    expires_unix: u64,
}

pub struct AuthoritativeChallengeZone {
    zone: DnsIdentifier,
    nameserver: DnsIdentifier,
    ipv4: [u8; 4],
    serial: u32,
    policy_generation: u64,
    records: [Option<TxtRecord>; MAX_DNS_TXT_RECORDS],
}

impl AuthoritativeChallengeZone {
    pub const fn new(
        zone: DnsIdentifier,
        nameserver: DnsIdentifier,
        ipv4: [u8; 4],
        serial: u32,
        policy_generation: u64,
    ) -> Self {
        Self {
            zone,
            nameserver,
            ipv4,
            serial,
            policy_generation,
            records: [None; MAX_DNS_TXT_RECORDS],
        }
    }

    pub fn insert_txt(
        &mut self,
        identifier: DnsIdentifier,
        digest: [u8; 32],
        generation: u64,
        expires_unix: u64,
        policy_generation: u64,
    ) -> Result<(), DnsChallengeError> {
        if policy_generation != self.policy_generation {
            return Err(DnsChallengeError::StaleGeneration);
        }
        if !is_within_zone(&identifier, &self.zone) {
            return Err(DnsChallengeError::WrongZone);
        }
        if self
            .records
            .iter()
            .flatten()
            .any(|record| record.identifier == identifier && record.digest == digest)
        {
            return Err(DnsChallengeError::Duplicate);
        }
        let slot = self
            .records
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(DnsChallengeError::Capacity)?;
        *slot = Some(TxtRecord {
            identifier,
            digest,
            generation,
            expires_unix,
        });
        Ok(())
    }

    pub fn remove_txt(
        &mut self,
        identifier: DnsIdentifier,
        digest: [u8; 32],
        generation: u64,
    ) -> Result<(), DnsChallengeError> {
        let slot = self
            .records
            .iter_mut()
            .find(|slot| {
                slot.is_some_and(|record| {
                    record.identifier == identifier && record.digest == digest
                })
            })
            .ok_or(DnsChallengeError::NotFound)?;
        if slot.is_some_and(|record| record.generation != generation) {
            return Err(DnsChallengeError::StaleGeneration);
        }
        *slot = None;
        Ok(())
    }

    pub fn expire(&mut self, now_unix: u64) {
        for slot in &mut self.records {
            if slot.is_some_and(|record| now_unix >= record.expires_unix) {
                *slot = None;
            }
        }
    }

    pub fn answer_udp(
        &self,
        request: &[u8],
        now_unix: u64,
        output: &mut [u8],
    ) -> Result<usize, DnsChallengeError> {
        match self.answer_udp_inner(request, now_unix, output) {
            Err(DnsChallengeError::OutputTooSmall) if request.len() >= 12 && output.len() >= 12 => {
                output[..12].copy_from_slice(&request[..12]);
                let request_flags = u16::from_be_bytes([request[2], request[3]]);
                output[2..4].copy_from_slice(&(0x8600 | (request_flags & 0x0100)).to_be_bytes());
                output[4..12].fill(0);
                Ok(12)
            }
            result => result,
        }
    }

    pub fn answer_tcp(
        &self,
        framed_request: &[u8],
        now_unix: u64,
        output: &mut [u8],
    ) -> Result<usize, DnsChallengeError> {
        if framed_request.len() < 2 || output.len() < 2 {
            return Err(DnsChallengeError::Malformed);
        }
        let declared = usize::from(u16::from_be_bytes([framed_request[0], framed_request[1]]));
        if declared != framed_request.len() - 2 || declared > MAX_DNS_PACKET {
            return Err(DnsChallengeError::Malformed);
        }
        let written = self.answer_udp_inner(&framed_request[2..], now_unix, &mut output[2..])?;
        output[..2].copy_from_slice(&(written as u16).to_be_bytes());
        Ok(written + 2)
    }

    fn answer_udp_inner(
        &self,
        request: &[u8],
        now_unix: u64,
        output: &mut [u8],
    ) -> Result<usize, DnsChallengeError> {
        if request.len() > MAX_DNS_PACKET {
            return Err(DnsChallengeError::Oversized);
        }
        if request.len() < 12 {
            return Err(DnsChallengeError::Malformed);
        }
        let qdcount = u16::from_be_bytes([request[4], request[5]]);
        if qdcount != 1 {
            return Err(DnsChallengeError::MultipleQuestions);
        }
        let mut name = [0u8; 253];
        let (name_len, after_name) = decode_name(request, 12, &mut name)?;
        let end = after_name
            .checked_add(4)
            .ok_or(DnsChallengeError::Malformed)?;
        let question_tail = request
            .get(after_name..end)
            .ok_or(DnsChallengeError::Malformed)?;
        let qtype = u16::from_be_bytes([question_tail[0], question_tail[1]]);
        let qclass = u16::from_be_bytes([question_tail[2], question_tail[3]]);
        if qclass != 1 {
            return self.header_and_question(request, end, 4, 0, false, output);
        }
        let query_name =
            core::str::from_utf8(&name[..name_len]).map_err(|_| DnsChallengeError::Malformed)?;
        let zone_match = eq_name(query_name, self.zone.as_str());
        let ns_match = eq_name(query_name, self.nameserver.as_str());
        let challenge_identifier = strip_challenge_name(query_name);

        let mut answer_count = 0u16;
        if qtype == 16 {
            if let Some(identifier) = challenge_identifier {
                answer_count = self
                    .records
                    .iter()
                    .flatten()
                    .filter(|record| {
                        record.expires_unix > now_unix
                            && eq_name(record.identifier.as_str(), identifier)
                    })
                    .count() as u16;
            }
        } else if (qtype == 6 || qtype == 2) && zone_match {
            answer_count = 1;
        } else if qtype == 1 && ns_match {
            answer_count = 1;
        }
        let authoritative = zone_match
            || ns_match
            || challenge_identifier
                .is_some_and(|identifier| is_text_within_zone(identifier, self.zone.as_str()));
        let rcode = if authoritative { 0 } else { 5 };
        let mut len =
            self.header_and_question(request, end, rcode, answer_count, authoritative, output)?;
        if answer_count == 0 {
            return Ok(len);
        }
        match qtype {
            16 => {
                let identifier = challenge_identifier.ok_or(DnsChallengeError::WrongZone)?;
                for record in self.records.iter().flatten().filter(|record| {
                    record.expires_unix > now_unix
                        && eq_name(record.identifier.as_str(), identifier)
                }) {
                    let mut encoded = [0u8; 43];
                    let value = encode_base64url(&record.digest, &mut encoded)
                        .map_err(|_| DnsChallengeError::Malformed)?;
                    len = write_rr(output, len, 16, 30, &[value.len() as u8], value.as_bytes())?;
                }
            }
            1 => len = write_rr(output, len, 1, 60, &[], &self.ipv4)?,
            2 => {
                let mut rdata = [0u8; 255];
                let rlen = encode_name(self.nameserver.as_str(), &mut rdata)?;
                len = write_rr(output, len, 2, 60, &[], &rdata[..rlen])?;
            }
            6 => {
                let mut rdata = [0u8; 600];
                let mut rlen = encode_name(self.nameserver.as_str(), &mut rdata)?;
                rlen += encode_name("hostmaster.invalid", &mut rdata[rlen..])?;
                for value in [self.serial, 300, 60, 3600, 60] {
                    rdata[rlen..rlen + 4].copy_from_slice(&value.to_be_bytes());
                    rlen += 4;
                }
                len = write_rr(output, len, 6, 60, &[], &rdata[..rlen])?;
            }
            _ => {}
        }
        Ok(len)
    }

    fn header_and_question(
        &self,
        request: &[u8],
        question_end: usize,
        rcode: u8,
        answers: u16,
        authoritative: bool,
        output: &mut [u8],
    ) -> Result<usize, DnsChallengeError> {
        if output.len() < question_end {
            return Err(DnsChallengeError::OutputTooSmall);
        }
        output[..question_end].copy_from_slice(&request[..question_end]);
        let request_flags = u16::from_be_bytes([request[2], request[3]]);
        let mut flags = 0x8000 | (request_flags & 0x0100) | u16::from(rcode);
        if authoritative {
            flags |= 0x0400;
        }
        output[2..4].copy_from_slice(&flags.to_be_bytes());
        output[6..8].copy_from_slice(&answers.to_be_bytes());
        output[8..12].fill(0);
        Ok(question_end)
    }
}

fn is_within_zone(identifier: &DnsIdentifier, zone: &DnsIdentifier) -> bool {
    is_text_within_zone(identifier.as_str(), zone.as_str())
}
fn is_text_within_zone(name: &str, zone: &str) -> bool {
    eq_name(name, zone)
        || name.len() > zone.len()
            && name.as_bytes()[name.len() - zone.len() - 1] == b'.'
            && name[name.len() - zone.len()..].eq_ignore_ascii_case(zone)
}
fn eq_name(left: &str, right: &str) -> bool {
    left.trim_end_matches('.')
        .eq_ignore_ascii_case(right.trim_end_matches('.'))
}
fn strip_challenge_name(name: &str) -> Option<&str> {
    const PREFIX: &str = "_acme-challenge.";
    name.get(..PREFIX.len())
        .filter(|candidate| candidate.eq_ignore_ascii_case(PREFIX))
        .and_then(|_| name.get(PREFIX.len()..))
}

fn decode_name(
    packet: &[u8],
    start: usize,
    output: &mut [u8],
) -> Result<(usize, usize), DnsChallengeError> {
    let mut cursor = start;
    let mut resume = None;
    let mut out = 0usize;
    let mut pointers = 0usize;
    loop {
        let length = *packet.get(cursor).ok_or(DnsChallengeError::Malformed)?;
        if length & 0xc0 == 0xc0 {
            let low = *packet.get(cursor + 1).ok_or(DnsChallengeError::Malformed)?;
            let offset = usize::from(u16::from(length & 0x3f) << 8 | u16::from(low));
            if offset >= packet.len() || offset >= cursor || pointers >= MAX_DNS_POINTERS {
                return Err(DnsChallengeError::CompressionLoop);
            }
            resume.get_or_insert(cursor + 2);
            cursor = offset;
            pointers += 1;
            continue;
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(DnsChallengeError::Malformed);
        }
        cursor += 1;
        if length == 0 {
            return Ok((out, resume.unwrap_or(cursor)));
        }
        if out != 0 {
            *output.get_mut(out).ok_or(DnsChallengeError::NameTooLong)? = b'.';
            out += 1;
        }
        let end = cursor
            .checked_add(usize::from(length))
            .ok_or(DnsChallengeError::Malformed)?;
        let label = packet
            .get(cursor..end)
            .ok_or(DnsChallengeError::Malformed)?;
        output
            .get_mut(out..out + label.len())
            .ok_or(DnsChallengeError::NameTooLong)?
            .copy_from_slice(label);
        out += label.len();
        cursor = end;
    }
}

fn encode_name(name: &str, output: &mut [u8]) -> Result<usize, DnsChallengeError> {
    let mut len = 0usize;
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 || len + 1 + label.len() >= output.len() {
            return Err(DnsChallengeError::NameTooLong);
        }
        output[len] = label.len() as u8;
        len += 1;
        output[len..len + label.len()].copy_from_slice(label.as_bytes());
        len += label.len();
    }
    *output
        .get_mut(len)
        .ok_or(DnsChallengeError::OutputTooSmall)? = 0;
    Ok(len + 1)
}

fn write_rr(
    output: &mut [u8],
    offset: usize,
    record_type: u16,
    ttl: u32,
    prefix: &[u8],
    value: &[u8],
) -> Result<usize, DnsChallengeError> {
    let rdata_len = prefix
        .len()
        .checked_add(value.len())
        .ok_or(DnsChallengeError::OutputTooSmall)?;
    let end = offset
        .checked_add(12)
        .and_then(|value| value.checked_add(rdata_len))
        .ok_or(DnsChallengeError::OutputTooSmall)?;
    if end > output.len() || rdata_len > usize::from(u16::MAX) {
        return Err(DnsChallengeError::OutputTooSmall);
    }
    output[offset..offset + 2].copy_from_slice(&[0xc0, 0x0c]);
    output[offset + 2..offset + 4].copy_from_slice(&record_type.to_be_bytes());
    output[offset + 4..offset + 6].copy_from_slice(&1u16.to_be_bytes());
    output[offset + 6..offset + 10].copy_from_slice(&ttl.to_be_bytes());
    output[offset + 10..offset + 12].copy_from_slice(&(rdata_len as u16).to_be_bytes());
    output[offset + 12..offset + 12 + prefix.len()].copy_from_slice(prefix);
    output[offset + 12 + prefix.len()..end].copy_from_slice(value);
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn query(name: &str, qtype: u16) -> ([u8; 512], usize) {
        let mut q = [0u8; 512];
        q[..12].copy_from_slice(&[0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        let mut len = 12 + encode_name(name, &mut q[12..]).unwrap();
        q[len..len + 2].copy_from_slice(&qtype.to_be_bytes());
        q[len + 2..len + 4].copy_from_slice(&1u16.to_be_bytes());
        len += 4;
        (q, len)
    }
    fn zone() -> AuthoritativeChallengeZone {
        AuthoritativeChallengeZone::new(
            DnsIdentifier::parse("example", false).unwrap(),
            DnsIdentifier::parse("ns.example", false).unwrap(),
            [192, 0, 2, 1],
            7,
            1,
        )
    }
    #[test]
    fn serves_multiple_txt_and_refuses_recursion_outside_zone() {
        let mut z = zone();
        let id = DnsIdentifier::parse("git.example", false).unwrap();
        z.insert_txt(id, [1; 32], 1, 100, 1).unwrap();
        z.insert_txt(id, [2; 32], 2, 100, 1).unwrap();
        let (q, n) = query("_acme-challenge.git.example", 16);
        let mut out = [0u8; MAX_DNS_PACKET];
        let len = z.answer_udp(&q[..n], 1, &mut out).unwrap();
        assert!(len > n);
        assert_eq!(u16::from_be_bytes([out[6], out[7]]), 2);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]) & 0x0480, 0x0400);
        let (q, n) = query("outside.invalid", 16);
        z.answer_udp(&q[..n], 1, &mut out).unwrap();
        assert_eq!(u16::from_be_bytes([out[2], out[3]]) & 0xf, 5);
    }
    #[test]
    fn rejects_compression_loop_and_stale_removal() {
        let mut z = zone();
        let id = DnsIdentifier::parse("git.example", false).unwrap();
        z.insert_txt(id, [3; 32], 4, 100, 1).unwrap();
        assert_eq!(
            z.remove_txt(id, [3; 32], 3),
            Err(DnsChallengeError::StaleGeneration)
        );
        let mut q = [0u8; 18];
        q[..12].copy_from_slice(&[0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        q[12..].copy_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1]);
        let mut out = [0u8; MAX_DNS_PACKET];
        assert_eq!(
            z.answer_udp(&q, 1, &mut out),
            Err(DnsChallengeError::CompressionLoop)
        );
    }

    #[test]
    fn tcp_is_framed_and_small_udp_output_is_truncated() {
        let z = zone();
        let (q, n) = query("example", 6);
        let mut framed = [0u8; 514];
        framed[..2].copy_from_slice(&(n as u16).to_be_bytes());
        framed[2..n + 2].copy_from_slice(&q[..n]);
        let mut out = [0u8; MAX_DNS_PACKET + 2];
        let written = z.answer_tcp(&framed[..n + 2], 1, &mut out).unwrap();
        assert_eq!(
            usize::from(u16::from_be_bytes([out[0], out[1]])),
            written - 2
        );
        let mut tiny = [0u8; 12];
        assert_eq!(z.answer_udp(&q[..n], 1, &mut tiny), Ok(12));
        assert_ne!(u16::from_be_bytes([tiny[2], tiny[3]]) & 0x0200, 0);
    }
}
