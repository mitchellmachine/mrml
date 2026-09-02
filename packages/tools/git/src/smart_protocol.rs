//! Bounded packet-line framing shared by Smart Git protocol handlers.

use mrml_runtime::{Text, Vector};

use crate::{
    BoundedRead, BoundedWrite, CandidateRefTransaction, CandidateRefUpdate, FullRefName,
    GitdCoreError, ObjectFormat, ObjectId, RepositoryGeneration, RepositoryIdentity,
    RevocationGeneration, TrustGeneration, WorkBudget,
};

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

pub const MAX_V2_ARGUMENTS: usize = 8_192;
pub const MAX_V2_REF_PREFIXES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolV2Request {
    LsRefs {
        peel: bool,
        symrefs: bool,
        unborn: bool,
        prefixes: Vector<Vector<u8>>,
    },
    Fetch {
        wants: Vector<ObjectId>,
        haves: Vector<ObjectId>,
        done: bool,
        thin_pack: bool,
        ofs_delta: bool,
        sideband_all: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivePackRequest {
    pub candidate: CandidateRefTransaction,
    pub proofs: Vector<crate::DetachedCommitProofRecord>,
    pub report_status_v2: bool,
    pub atomic: bool,
    pub delete_refs: bool,
    pub side_band_64k: bool,
    pub ofs_delta: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveRefStatus {
    pub name: FullRefName,
    pub error: Option<Text>,
}

/// Emit the standard report-status-v2 result. MRML does not implement
/// proc-receive rewriting, so no option lines are emitted. Atomic requests may
/// report either every ref successful or every ref failed, never a mixed state.
pub fn write_receive_pack_report(
    output: &mut dyn BoundedWrite,
    request: &ReceivePackRequest,
    unpack_error: Option<&str>,
    statuses: &[ReceiveRefStatus],
    budget: &mut ProtocolBudget,
) -> Result<(), GitdCoreError> {
    if !request.report_status_v2
        || !request.atomic
        || statuses.len() != request.candidate.updates.len()
        || statuses
            .iter()
            .zip(&request.candidate.updates)
            .any(|(status, update)| status.name != update.name)
    {
        return Err(GitdCoreError::Policy);
    }
    let successes = statuses
        .iter()
        .filter(|status| status.error.is_none())
        .count();
    if successes != 0 && successes != statuses.len() {
        return Err(GitdCoreError::Policy);
    }
    if unpack_error.is_some() && successes != 0 {
        return Err(GitdCoreError::Policy);
    }

    let mut report = Vector::new();
    let unpack = match unpack_error {
        None => b"unpack ok\n".as_slice(),
        Some(error) => {
            validate_protocol_error(error)?;
            let mut line = Text::from("unpack ");
            line.push_str(error);
            line.push('\n');
            append_raw_pkt(&mut report, line.as_bytes())?;
            &[]
        }
    };
    if !unpack.is_empty() {
        append_raw_pkt(&mut report, unpack)?;
    }
    for status in statuses {
        let mut line = if status.error.is_some() {
            Text::from("ng ")
        } else {
            Text::from("ok ")
        };
        line.push_str(status.name.as_str());
        if let Some(error) = &status.error {
            validate_protocol_error(error)?;
            line.push(' ');
            line.push_str(error);
        }
        line.push('\n');
        append_raw_pkt(&mut report, line.as_bytes())?;
    }
    report
        .try_extend_from_slice(b"0000")
        .map_err(|_| GitdCoreError::Resource)?;

    if request.side_band_64k {
        for chunk in report.chunks(MAX_PKT_LINE_BYTES - 5) {
            let mut payload = Vector::new();
            payload
                .try_reserve_exact(chunk.len() + 1)
                .map_err(|_| GitdCoreError::Resource)?;
            payload.push(1);
            payload
                .try_extend_from_slice(chunk)
                .map_err(|_| GitdCoreError::Resource)?;
            write_pkt_line(output, &PktLine::Data(payload), budget)?;
        }
        write_pkt_line(output, &PktLine::Flush, budget)
    } else {
        write_exact(output, &report, budget)
    }
}

fn validate_protocol_error(error: &str) -> Result<(), GitdCoreError> {
    if error.is_empty()
        || error == "ok"
        || error.len() > 512
        || error.bytes().any(|byte| !(b' '..=b'~').contains(&byte))
    {
        return Err(GitdCoreError::MalformedInput);
    }
    Ok(())
}

fn append_raw_pkt(output: &mut Vector<u8>, payload: &[u8]) -> Result<(), GitdCoreError> {
    let length = payload
        .len()
        .checked_add(4)
        .ok_or(GitdCoreError::Resource)?;
    if length > MAX_PKT_LINE_BYTES {
        return Err(GitdCoreError::Resource);
    }
    output
        .try_extend_from_slice(&hex_header(length))
        .map_err(|_| GitdCoreError::Resource)?;
    output
        .try_extend_from_slice(payload)
        .map_err(|_| GitdCoreError::Resource)
}

/// Parse the command section of a receive-pack request and stop exactly after
/// its flush packet, leaving the following pack stream unread. Ref deletion is
/// represented by `proposed_new == None`; this parser does not authorize it.
pub fn read_receive_pack_commands(
    input: &mut dyn BoundedRead,
    repository: RepositoryIdentity,
    repository_generation: RepositoryGeneration,
    trust_generation: TrustGeneration,
    revocation_generation: RevocationGeneration,
    format: ObjectFormat,
    allow_delete_candidates: bool,
    budget: &mut ProtocolBudget,
) -> Result<ReceivePackRequest, GitdCoreError> {
    let mut updates = Vector::new();
    let mut capabilities = ReceiveCapabilities::default();
    for index in 0..crate::gitd_core::MAX_REFS_PER_TRANSACTION {
        let line = match read_pkt_line(input, budget)? {
            PktLine::Flush => {
                if updates.is_empty() || !capabilities.report_status_v2 || !capabilities.atomic {
                    return Err(GitdCoreError::Unsupported);
                }
                return Ok(ReceivePackRequest {
                    candidate: CandidateRefTransaction {
                        repository,
                        repository_generation,
                        trust_generation,
                        revocation_generation,
                        updates,
                    },
                    proofs: Vector::new(),
                    report_status_v2: capabilities.report_status_v2,
                    atomic: capabilities.atomic,
                    delete_refs: allow_delete_candidates,
                    side_band_64k: capabilities.side_band_64k,
                    ofs_delta: capabilities.ofs_delta,
                });
            }
            PktLine::Delimiter => {
                if updates.is_empty()
                    || !capabilities.report_status_v2
                    || !capabilities.atomic
                    || !capabilities.mrml_proof_v1
                {
                    return Err(GitdCoreError::Unsupported);
                }
                let proofs = read_receive_proofs(input, budget)?;
                return Ok(ReceivePackRequest {
                    candidate: CandidateRefTransaction {
                        repository,
                        repository_generation,
                        trust_generation,
                        revocation_generation,
                        updates,
                    },
                    proofs,
                    report_status_v2: capabilities.report_status_v2,
                    atomic: capabilities.atomic,
                    delete_refs: allow_delete_candidates,
                    side_band_64k: capabilities.side_band_64k,
                    ofs_delta: capabilities.ofs_delta,
                });
            }
            PktLine::Data(line) => line,
            _ => return Err(GitdCoreError::MalformedInput),
        };
        let line = strip_lf_optional(&line)?;
        let (command, capability_bytes) = if index == 0 {
            let split = line
                .iter()
                .position(|byte| *byte == 0)
                .ok_or(GitdCoreError::MalformedInput)?;
            (&line[..split], Some(&line[split + 1..]))
        } else {
            if line.contains(&0) {
                return Err(GitdCoreError::MalformedInput);
            }
            (line, None)
        };
        if let Some(values) = capability_bytes {
            capabilities = parse_receive_capabilities(values, format)?;
        }
        let update = parse_receive_command(command, format)?;
        if updates
            .iter()
            .any(|existing: &CandidateRefUpdate| existing.name == update.name)
        {
            return Err(GitdCoreError::MalformedRef);
        }
        if update.proposed_new.is_none() && !allow_delete_candidates {
            return Err(GitdCoreError::Unsupported);
        }
        updates.push(update);
    }
    // A full command budget must be terminated by flush, never truncated or
    // silently accepted as a partial atomic transaction.
    Err(GitdCoreError::Resource)
}

pub const RECEIVE_PROOF_MAGIC: &[u8; 8] = b"MRGPUSH1";

fn read_receive_proofs(
    input: &mut dyn BoundedRead,
    budget: &mut ProtocolBudget,
) -> Result<Vector<crate::DetachedCommitProofRecord>, GitdCoreError> {
    let mut proofs = Vector::new();
    for _ in 0..crate::MAX_DETACHED_COMMIT_PROOFS {
        let payload = match read_pkt_line(input, budget)? {
            PktLine::Flush if !proofs.is_empty() => return Ok(proofs),
            PktLine::Data(payload) => payload,
            _ => return Err(GitdCoreError::MalformedInput),
        };
        let fixed = RECEIVE_PROOF_MAGIC.len() + 32 + 2 + 2;
        if payload.len() < fixed || &payload[..8] != RECEIVE_PROOF_MAGIC {
            return Err(GitdCoreError::MalformedInput);
        }
        let commit = ObjectId::from_bytes(ObjectFormat::Sha256, &payload[8..40])
            .filter(|commit| !commit.is_zero())
            .ok_or(GitdCoreError::MalformedInput)?;
        let openpgp_length = usize::from(u16::from_be_bytes([payload[40], payload[41]]));
        let ml_dsa_length = usize::from(u16::from_be_bytes([payload[42], payload[43]]));
        let openpgp_end = fixed
            .checked_add(openpgp_length)
            .ok_or(GitdCoreError::Resource)?;
        let end = openpgp_end
            .checked_add(ml_dsa_length)
            .ok_or(GitdCoreError::Resource)?;
        if end != payload.len() {
            return Err(GitdCoreError::MalformedInput);
        }
        let proof = crate::DetachedCommitProofRecord::new(
            commit,
            &payload[fixed..openpgp_end],
            &payload[openpgp_end..end],
        )
        .map_err(|_| GitdCoreError::Authorization)?;
        if proofs
            .last()
            .is_some_and(|previous: &crate::DetachedCommitProofRecord| {
                previous.commit() >= proof.commit()
            })
        {
            return Err(GitdCoreError::MalformedInput);
        }
        proofs.push(proof);
    }
    Err(GitdCoreError::Resource)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ReceiveCapabilities {
    report_status_v2: bool,
    atomic: bool,
    side_band_64k: bool,
    ofs_delta: bool,
    mrml_proof_v1: bool,
}

fn parse_receive_capabilities(
    bytes: &[u8],
    format: ObjectFormat,
) -> Result<ReceiveCapabilities, GitdCoreError> {
    if bytes.is_empty() || bytes.len() > 1_024 || !bytes.is_ascii() {
        return Err(GitdCoreError::MalformedInput);
    }
    let mut output = ReceiveCapabilities::default();
    let mut saw_object_format = false;
    for capability in bytes.split(|byte| *byte == b' ') {
        match capability {
            b"report-status-v2" => set_once(&mut output.report_status_v2)?,
            b"atomic" => set_once(&mut output.atomic)?,
            b"side-band-64k" => set_once(&mut output.side_band_64k)?,
            b"ofs-delta" => set_once(&mut output.ofs_delta)?,
            b"mrml-proof-v1" => set_once(&mut output.mrml_proof_v1)?,
            _ if capability.starts_with(b"object-format=") => {
                set_once(&mut saw_object_format)?;
                let expected = match format {
                    ObjectFormat::Sha1 => b"object-format=sha1".as_slice(),
                    ObjectFormat::Sha256 => b"object-format=sha256".as_slice(),
                };
                if capability != expected {
                    return Err(GitdCoreError::MalformedInput);
                }
            }
            _ => return Err(GitdCoreError::Unsupported),
        }
    }
    if format == ObjectFormat::Sha256 && !saw_object_format {
        return Err(GitdCoreError::MalformedInput);
    }
    Ok(output)
}

fn parse_receive_command(
    command: &[u8],
    format: ObjectFormat,
) -> Result<CandidateRefUpdate, GitdCoreError> {
    let mut fields = command.split(|byte| *byte == b' ');
    let old = fields.next().ok_or(GitdCoreError::MalformedInput)?;
    let new = fields.next().ok_or(GitdCoreError::MalformedInput)?;
    let name = fields.next().ok_or(GitdCoreError::MalformedInput)?;
    if fields.next().is_some() {
        return Err(GitdCoreError::MalformedInput);
    }
    let name = core::str::from_utf8(name).map_err(|_| GitdCoreError::MalformedRef)?;
    Ok(CandidateRefUpdate {
        name: FullRefName::parse(name)?,
        expected_old: parse_nullable_wire_id(format, old)?,
        proposed_new: parse_nullable_wire_id(format, new)?,
    })
}

fn parse_nullable_wire_id(
    format: ObjectFormat,
    bytes: &[u8],
) -> Result<Option<ObjectId>, GitdCoreError> {
    if bytes.len()
        == format
            .hash_len()
            .checked_mul(2)
            .ok_or(GitdCoreError::Resource)?
        && bytes.iter().all(|byte| *byte == b'0')
    {
        return Ok(None);
    }
    parse_wire_id(format, bytes).map(Some)
}

fn strip_lf_optional(line: &[u8]) -> Result<&[u8], GitdCoreError> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    if line.contains(&b'\r') {
        return Err(GitdCoreError::MalformedInput);
    }
    Ok(line)
}

/// Advertise only the server-core features implemented by this parser. In
/// particular, shallow, filter, ref-in-want, packfile-uris and push options are
/// deliberately absent.
pub fn write_v2_capability_advertisement(
    output: &mut dyn BoundedWrite,
    format: ObjectFormat,
    budget: &mut ProtocolBudget,
) -> Result<(), GitdCoreError> {
    for line in [
        b"version 2\n".as_slice(),
        b"ls-refs=unborn\n".as_slice(),
        b"fetch=ofs-delta\n".as_slice(),
    ] {
        write_pkt_line(output, &PktLine::Data(copy_bytes(line)?), budget)?;
    }
    let object_format = match format {
        ObjectFormat::Sha1 => b"object-format=sha1\n".as_slice(),
        ObjectFormat::Sha256 => b"object-format=sha256\n".as_slice(),
    };
    write_pkt_line(output, &PktLine::Data(copy_bytes(object_format)?), budget)?;
    write_pkt_line(output, &PktLine::Flush, budget)
}

/// Advertises only the receive capabilities implemented by the protected
/// production backend. It does not expose refs before authentication.
pub fn write_v2_receive_capability_advertisement(
    output: &mut dyn BoundedWrite,
    format: ObjectFormat,
    budget: &mut ProtocolBudget,
) -> Result<(), GitdCoreError> {
    if format != ObjectFormat::Sha256 {
        return Err(GitdCoreError::Unsupported);
    }
    for line in [
        b"version 2\n".as_slice(),
        b"object-format=sha256\n",
        b"receive=report-status-v2 atomic side-band-64k ofs-delta mrml-proof-v1\n",
    ] {
        write_pkt_line(output, &PktLine::Data(copy_bytes(line)?), budget)?;
    }
    write_pkt_line(output, &PktLine::Flush, budget)
}

pub fn write_v2_protected_receive_capability_advertisement(
    output: &mut dyn BoundedWrite,
    format: ObjectFormat,
    repository_generation: crate::RepositoryGeneration,
    trust_generation: crate::TrustGeneration,
    revocation_generation: crate::RevocationGeneration,
    budget: &mut ProtocolBudget,
) -> Result<(), GitdCoreError> {
    if format != ObjectFormat::Sha256
        || repository_generation.0 == 0
        || trust_generation.0 == 0
        || revocation_generation.0 == 0
    {
        return Err(GitdCoreError::Unsupported);
    }
    for line in [
        b"version 2\n".as_slice(),
        b"object-format=sha256\n",
        b"receive=report-status-v2 atomic side-band-64k ofs-delta mrml-proof-v1\n",
    ] {
        write_pkt_line(output, &PktLine::Data(copy_bytes(line)?), budget)?;
    }
    let context = mrml_runtime::mrml_format!(
        "mrml-receive-context={}:{}:{}\n",
        repository_generation.0,
        trust_generation.0,
        revocation_generation.0
    );
    write_pkt_line(output, &PktLine::Data(copy_bytes(context.as_bytes())?), budget)?;
    write_pkt_line(output, &PktLine::Flush, budget)
}

/// Parse one protocol-v2 command. The transport must already have selected the
/// exact repository and object format. Unknown command capabilities and
/// unsupported arguments fail closed instead of being ignored.
pub fn read_v2_request(
    input: &mut dyn BoundedRead,
    format: ObjectFormat,
    budget: &mut ProtocolBudget,
) -> Result<ProtocolV2Request, GitdCoreError> {
    let command = data_line(read_pkt_line(input, budget)?)?;
    let command = strip_lf(&command)?;
    let command_name = command
        .strip_prefix(b"command=")
        .ok_or(GitdCoreError::MalformedInput)?;

    let mut capability_count = 0usize;
    let mut saw_agent = false;
    let mut saw_object_format = false;
    loop {
        match read_pkt_line(input, budget)? {
            PktLine::Delimiter => break,
            PktLine::Data(line) => {
                capability_count = capability_count
                    .checked_add(1)
                    .ok_or(GitdCoreError::Resource)?;
                if capability_count > 16 {
                    return Err(GitdCoreError::Resource);
                }
                let capability = strip_lf(&line)?;
                if let Some(agent) = capability.strip_prefix(b"agent=") {
                    if saw_agent
                        || agent.is_empty()
                        || agent.len() > 256
                        || agent.iter().any(|byte| !byte.is_ascii_graphic())
                    {
                        return Err(GitdCoreError::MalformedInput);
                    }
                    saw_agent = true;
                } else if let Some(value) = capability.strip_prefix(b"object-format=") {
                    if saw_object_format
                        || value
                            != match format {
                                ObjectFormat::Sha1 => b"sha1".as_slice(),
                                ObjectFormat::Sha256 => b"sha256".as_slice(),
                            }
                    {
                        return Err(GitdCoreError::MalformedInput);
                    }
                    saw_object_format = true;
                } else {
                    return Err(GitdCoreError::Unsupported);
                }
            }
            _ => return Err(GitdCoreError::MalformedInput),
        }
    }

    match command_name {
        b"ls-refs" => read_ls_refs(input, budget),
        b"fetch" => read_fetch(input, format, budget),
        _ => Err(GitdCoreError::Unsupported),
    }
}

fn read_ls_refs(
    input: &mut dyn BoundedRead,
    budget: &mut ProtocolBudget,
) -> Result<ProtocolV2Request, GitdCoreError> {
    let mut peel = false;
    let mut symrefs = false;
    let mut unborn = false;
    let mut prefixes = Vector::new();
    for _ in 0..MAX_V2_ARGUMENTS {
        let line = match read_pkt_line(input, budget)? {
            PktLine::Flush => {
                return Ok(ProtocolV2Request::LsRefs {
                    peel,
                    symrefs,
                    unborn,
                    prefixes,
                });
            }
            PktLine::Data(line) => line,
            _ => return Err(GitdCoreError::MalformedInput),
        };
        let argument = strip_lf(&line)?;
        match argument {
            b"peel" => set_once(&mut peel)?,
            b"symrefs" => set_once(&mut symrefs)?,
            b"unborn" => set_once(&mut unborn)?,
            _ if argument.starts_with(b"ref-prefix ") => {
                if prefixes.len() >= MAX_V2_REF_PREFIXES {
                    return Err(GitdCoreError::Resource);
                }
                let prefix = &argument[11..];
                if prefix.is_empty()
                    || prefix.len() > crate::gitd_core::MAX_REF_NAME_BYTES
                    || prefix.iter().any(|byte| *byte == 0 || !byte.is_ascii())
                {
                    return Err(GitdCoreError::MalformedRef);
                }
                prefixes.push(copy_bytes(prefix)?);
            }
            _ => return Err(GitdCoreError::Unsupported),
        }
    }
    Err(GitdCoreError::Resource)
}

fn read_fetch(
    input: &mut dyn BoundedRead,
    format: ObjectFormat,
    budget: &mut ProtocolBudget,
) -> Result<ProtocolV2Request, GitdCoreError> {
    let mut wants = Vector::new();
    let mut haves = Vector::new();
    let mut done = false;
    let mut thin_pack = false;
    let mut ofs_delta = false;
    let mut sideband_all = false;
    for _ in 0..MAX_V2_ARGUMENTS {
        let line = match read_pkt_line(input, budget)? {
            PktLine::Flush => {
                if wants.is_empty() {
                    return Err(GitdCoreError::MalformedInput);
                }
                return Ok(ProtocolV2Request::Fetch {
                    wants,
                    haves,
                    done,
                    thin_pack,
                    ofs_delta,
                    sideband_all,
                });
            }
            PktLine::Data(line) => line,
            _ => return Err(GitdCoreError::MalformedInput),
        };
        let argument = strip_lf(&line)?;
        if let Some(hex) = argument.strip_prefix(b"want ") {
            wants.push(parse_wire_id(format, hex)?);
        } else if let Some(hex) = argument.strip_prefix(b"have ") {
            haves.push(parse_wire_id(format, hex)?);
        } else {
            match argument {
                b"done" => set_once(&mut done)?,
                b"thin-pack" => set_once(&mut thin_pack)?,
                b"ofs-delta" => set_once(&mut ofs_delta)?,
                b"sideband-all" => set_once(&mut sideband_all)?,
                // Includes shallow/deepen/filter/want-ref/packfile-uris and
                // every future feature until implemented and tested.
                _ => return Err(GitdCoreError::Unsupported),
            }
        }
        if wants
            .len()
            .checked_add(haves.len())
            .ok_or(GitdCoreError::Resource)?
            > MAX_V2_ARGUMENTS
        {
            return Err(GitdCoreError::Resource);
        }
    }
    Err(GitdCoreError::Resource)
}

fn data_line(packet: PktLine) -> Result<Vector<u8>, GitdCoreError> {
    match packet {
        PktLine::Data(line) => Ok(line),
        _ => Err(GitdCoreError::MalformedInput),
    }
}

fn strip_lf(line: &[u8]) -> Result<&[u8], GitdCoreError> {
    line.strip_suffix(b"\n")
        .filter(|line| !line.contains(&b'\r') && !line.contains(&0))
        .ok_or(GitdCoreError::MalformedInput)
}

fn set_once(value: &mut bool) -> Result<(), GitdCoreError> {
    if *value {
        return Err(GitdCoreError::MalformedInput);
    }
    *value = true;
    Ok(())
}

fn parse_wire_id(format: ObjectFormat, bytes: &[u8]) -> Result<ObjectId, GitdCoreError> {
    let text = core::str::from_utf8(bytes).map_err(|_| GitdCoreError::MalformedInput)?;
    ObjectId::parse_for(format, text).ok_or(GitdCoreError::MalformedInput)
}

fn copy_bytes(bytes: &[u8]) -> Result<Vector<u8>, GitdCoreError> {
    let mut output = Vector::new();
    output
        .try_extend_from_slice(bytes)
        .map_err(|_| GitdCoreError::Resource)?;
    Ok(output)
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

    pub(crate) fn consume_external_input(&mut self, amount: u64) -> Result<(), GitdCoreError> {
        let amount = usize::try_from(amount).map_err(|_| GitdCoreError::Resource)?;
        self.consume_input(amount)
    }

    pub(crate) fn consume_external_work(&mut self, amount: u64) -> Result<(), GitdCoreError> {
        let amount = usize::try_from(amount).map_err(|_| GitdCoreError::Resource)?;
        self.consume_work(amount)
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

    fn request(lines: &[&[u8]]) -> Reader {
        let mut writer = Writer {
            bytes: Vector::new(),
            limit: 16_384,
        };
        let mut output_budget = budget(16_384);
        for line in lines {
            if *line == b"DELIM" {
                write_pkt_line(&mut writer, &PktLine::Delimiter, &mut output_budget).unwrap();
            } else if *line == b"FLUSH" {
                write_pkt_line(&mut writer, &PktLine::Flush, &mut output_budget).unwrap();
            } else {
                write_pkt_line(
                    &mut writer,
                    &PktLine::Data(copy_bytes(line).unwrap()),
                    &mut output_budget,
                )
                .unwrap();
            }
        }
        Reader {
            bytes: writer.bytes,
            offset: 0,
            chunk: 7,
        }
    }

    #[test]
    fn v2_advertisement_is_exact_and_does_not_claim_unsupported_features() {
        let mut writer = Writer {
            bytes: Vector::new(),
            limit: 512,
        };
        write_v2_capability_advertisement(&mut writer, ObjectFormat::Sha256, &mut budget(512))
            .unwrap();
        let text = core::str::from_utf8(&writer.bytes).unwrap();
        assert!(text.contains("object-format=sha256"));
        assert!(text.contains("fetch=ofs-delta"));
        assert!(!text.contains("thin-pack"));
        assert!(!text.contains("sideband-all"));
        assert!(!text.contains("filter"));
        assert!(!text.contains("shallow"));
        assert!(!text.contains("packfile-uris"));

        let mut receive = Writer {
            bytes: Vector::new(),
            limit: 512,
        };
        write_v2_receive_capability_advertisement(
            &mut receive,
            ObjectFormat::Sha256,
            &mut budget(512),
        )
        .unwrap();
        let receive = core::str::from_utf8(&receive.bytes).unwrap();
        assert!(receive.contains("report-status-v2"));
        assert!(receive.contains(" atomic "));
        assert!(receive.contains("side-band-64k"));
        assert!(receive.contains("ofs-delta"));
        assert!(receive.contains("mrml-proof-v1"));
        assert!(!receive.contains("push-options"));
        assert!(
            write_v2_receive_capability_advertisement(
                &mut writer,
                ObjectFormat::Sha1,
                &mut budget(512)
            )
            .is_err()
        );
    }

    #[test]
    fn v2_ls_refs_and_sha256_fetch_are_strictly_parsed() {
        let mut ls_refs = request(&[
            b"command=ls-refs\n",
            b"agent=mrml\n",
            b"DELIM",
            b"peel\n",
            b"symrefs\n",
            b"ref-prefix refs/heads/\n",
            b"FLUSH",
        ]);
        assert_eq!(
            read_v2_request(&mut ls_refs, ObjectFormat::Sha256, &mut budget(16_384)),
            Ok(ProtocolV2Request::LsRefs {
                peel: true,
                symrefs: true,
                unborn: false,
                prefixes: [Vector::from(*b"refs/heads/")].into(),
            })
        );

        let want = b"want 1111111111111111111111111111111111111111111111111111111111111111\n";
        let have = b"have 2222222222222222222222222222222222222222222222222222222222222222\n";
        let mut fetch = request(&[
            b"command=fetch\n",
            b"DELIM",
            want,
            have,
            b"thin-pack\n",
            b"ofs-delta\n",
            b"sideband-all\n",
            b"done\n",
            b"FLUSH",
        ]);
        let parsed =
            read_v2_request(&mut fetch, ObjectFormat::Sha256, &mut budget(16_384)).unwrap();
        let ProtocolV2Request::Fetch {
            wants,
            haves,
            done,
            thin_pack,
            ofs_delta,
            sideband_all,
        } = parsed
        else {
            panic!("expected fetch");
        };
        assert_eq!(wants.len(), 1);
        assert_eq!(haves.len(), 1);
        assert!(done && thin_pack && ofs_delta && sideband_all);
    }

    #[test]
    fn v2_rejects_unadvertised_features_duplicates_and_wrong_object_ids() {
        for argument in [
            b"filter blob:none\n".as_slice(),
            b"deepen 1\n",
            b"want-ref refs/heads/main\n",
        ] {
            let mut reader = request(&[
                b"command=fetch\n",
                b"DELIM",
                b"want 1111111111111111111111111111111111111111111111111111111111111111\n",
                argument,
                b"FLUSH",
            ]);
            assert_eq!(
                read_v2_request(&mut reader, ObjectFormat::Sha256, &mut budget(16_384)),
                Err(GitdCoreError::Unsupported)
            );
        }

        let mut duplicate = request(&[
            b"command=ls-refs\n",
            b"DELIM",
            b"peel\n",
            b"peel\n",
            b"FLUSH",
        ]);
        assert_eq!(
            read_v2_request(&mut duplicate, ObjectFormat::Sha256, &mut budget(16_384)),
            Err(GitdCoreError::MalformedInput)
        );

        let mut sha1_for_sha256 = request(&[
            b"command=fetch\n",
            b"DELIM",
            b"want 1111111111111111111111111111111111111111\n",
            b"FLUSH",
        ]);
        assert_eq!(
            read_v2_request(
                &mut sha1_for_sha256,
                ObjectFormat::Sha256,
                &mut budget(16_384)
            ),
            Err(GitdCoreError::MalformedInput)
        );
    }

    fn receive(reader: &mut Reader) -> Result<ReceivePackRequest, GitdCoreError> {
        read_receive_pack_commands(
            reader,
            RepositoryIdentity::parse("owner/repository").unwrap(),
            RepositoryGeneration(7),
            TrustGeneration(8),
            RevocationGeneration(9),
            ObjectFormat::Sha256,
            true,
            &mut budget(16_384),
        )
    }

    #[test]
    fn receive_pack_parses_atomic_sha256_commands_and_leaves_pack_unread() {
        let mut reader = request(&[
            b"1111111111111111111111111111111111111111111111111111111111111111 2222222222222222222222222222222222222222222222222222222222222222 refs/heads/main\0report-status-v2 atomic side-band-64k ofs-delta object-format=sha256\n",
            b"3333333333333333333333333333333333333333333333333333333333333333 0000000000000000000000000000000000000000000000000000000000000000 refs/heads/obsolete\n",
            b"FLUSH",
        ]);
        reader.bytes.try_extend_from_slice(b"PACKtrailing").unwrap();
        let parsed = receive(&mut reader).unwrap();
        assert!(parsed.atomic && parsed.report_status_v2 && parsed.delete_refs);
        assert!(parsed.side_band_64k && parsed.ofs_delta);
        assert_eq!(parsed.candidate.updates.len(), 2);
        assert!(parsed.candidate.updates[1].proposed_new.is_none());
        assert_eq!(
            &reader.bytes[reader.offset..],
            b"PACKtrailing",
            "the pack body belongs to quarantine validation, not command parsing"
        );
    }

    #[test]
    fn receive_pack_parses_ordered_proofs_and_leaves_pack_unread() {
        let old = ObjectId::from_bytes(ObjectFormat::Sha256, &[1; 32]).unwrap();
        let new = ObjectId::from_bytes(ObjectFormat::Sha256, &[2; 32]).unwrap();
        let proof = crate::DetachedCommitProofRecord::new(
            new,
            &[3; 64],
            &[4; mrml_crypto::ML_DSA_65_SIGNATURE_BYTES],
        )
        .unwrap();
        let mut bytes = crate::protected_push_command_with_proofs(
            old,
            new,
            "refs/heads/main",
            core::slice::from_ref(&proof),
        )
        .unwrap();
        bytes.try_extend_from_slice(b"PACKtrailing").unwrap();
        let mut reader = Reader {
            bytes,
            offset: 0,
            chunk: 7,
        };
        let parsed = receive(&mut reader).unwrap();
        assert_eq!(&parsed.proofs[..], &[proof]);
        assert_eq!(&reader.bytes[reader.offset..], b"PACKtrailing");
    }

    #[test]
    fn receive_pack_rejects_non_atomic_delete_duplicate_ref_and_unknown_capability() {
        let valid = b"1111111111111111111111111111111111111111111111111111111111111111 2222222222222222222222222222222222222222222222222222222222222222 refs/heads/main";
        for capabilities in [
            b"report-status-v2 object-format=sha256\n".as_slice(),
            b"report-status-v2 atomic push-options object-format=sha256\n",
        ] {
            let mut first = copy_bytes(valid).unwrap();
            first.push(0);
            first.try_extend_from_slice(capabilities).unwrap();
            let mut reader = request(&[&first, b"FLUSH"]);
            assert!(matches!(
                receive(&mut reader),
                Err(GitdCoreError::Unsupported)
            ));
        }

        let mut duplicate = request(&[
            b"1111111111111111111111111111111111111111111111111111111111111111 2222222222222222222222222222222222222222222222222222222222222222 refs/heads/main\0report-status-v2 atomic object-format=sha256\n",
            b"2222222222222222222222222222222222222222222222222222222222222222 3333333333333333333333333333333333333333333333333333333333333333 refs/heads/main\n",
            b"FLUSH",
        ]);
        assert_eq!(receive(&mut duplicate), Err(GitdCoreError::MalformedRef));

        let mut deletion = request(&[
            b"1111111111111111111111111111111111111111111111111111111111111111 0000000000000000000000000000000000000000000000000000000000000000 refs/heads/main\0report-status-v2 atomic object-format=sha256\n",
            b"FLUSH",
        ]);
        assert!(receive(&mut deletion).is_ok());
        let mut deletion = request(&[
            b"1111111111111111111111111111111111111111111111111111111111111111 0000000000000000000000000000000000000000000000000000000000000000 refs/heads/main\0report-status-v2 atomic object-format=sha256\n",
            b"FLUSH",
        ]);
        assert_eq!(
            read_receive_pack_commands(
                &mut deletion,
                RepositoryIdentity::parse("owner/repository").unwrap(),
                RepositoryGeneration(7),
                TrustGeneration(8),
                RevocationGeneration(9),
                ObjectFormat::Sha256,
                false,
                &mut budget(16_384),
            ),
            Err(GitdCoreError::Unsupported)
        );
    }

    #[test]
    fn receive_report_v2_round_trips_plain_and_sideband_client_parsers() {
        let mut commands = request(&[
            b"1111111111111111111111111111111111111111111111111111111111111111 2222222222222222222222222222222222222222222222222222222222222222 refs/heads/main\0report-status-v2 atomic side-band-64k object-format=sha256\n",
            b"FLUSH",
        ]);
        let parsed = receive(&mut commands).unwrap();
        let statuses = [ReceiveRefStatus {
            name: FullRefName::parse("refs/heads/main").unwrap(),
            error: None,
        }];
        let mut sideband = Writer {
            bytes: Vector::new(),
            limit: 4096,
        };
        write_receive_pack_report(&mut sideband, &parsed, None, &statuses, &mut budget(4096))
            .unwrap();
        assert_eq!(
            crate::transport::parse_push_response_mode(&sideband.bytes, "refs/heads/main", true),
            Ok(())
        );

        let mut plain_request = parsed;
        plain_request.side_band_64k = false;
        let mut plain = Writer {
            bytes: Vector::new(),
            limit: 4096,
        };
        write_receive_pack_report(
            &mut plain,
            &plain_request,
            None,
            &statuses,
            &mut budget(4096),
        )
        .unwrap();
        assert_eq!(
            crate::transport::parse_push_response_mode(&plain.bytes, "refs/heads/main", false),
            Ok(())
        );
        assert_eq!(
            &plain.bytes[..],
            b"000eunpack ok\n0017ok refs/heads/main\n0000"
        );
    }

    #[test]
    fn atomic_report_rejects_mixed_results_and_sanitizes_errors() {
        let mut commands = request(&[
            b"1111111111111111111111111111111111111111111111111111111111111111 2222222222222222222222222222222222222222222222222222222222222222 refs/heads/main\0report-status-v2 atomic object-format=sha256\n",
            b"3333333333333333333333333333333333333333333333333333333333333333 4444444444444444444444444444444444444444444444444444444444444444 refs/heads/next\n",
            b"FLUSH",
        ]);
        let parsed = receive(&mut commands).unwrap();
        let mixed = [
            ReceiveRefStatus {
                name: FullRefName::parse("refs/heads/main").unwrap(),
                error: None,
            },
            ReceiveRefStatus {
                name: FullRefName::parse("refs/heads/next").unwrap(),
                error: Some("stale old id".into()),
            },
        ];
        let mut writer = Writer {
            bytes: Vector::new(),
            limit: 4096,
        };
        assert_eq!(
            write_receive_pack_report(&mut writer, &parsed, None, &mixed, &mut budget(4096)),
            Err(GitdCoreError::Policy)
        );
        let failed = [
            ReceiveRefStatus {
                name: FullRefName::parse("refs/heads/main").unwrap(),
                error: Some("stale old id\nforged".into()),
            },
            ReceiveRefStatus {
                name: FullRefName::parse("refs/heads/next").unwrap(),
                error: Some("atomic transaction rejected".into()),
            },
        ];
        assert_eq!(
            write_receive_pack_report(&mut writer, &parsed, None, &failed, &mut budget(4096)),
            Err(GitdCoreError::MalformedInput)
        );
        assert!(writer.bytes.is_empty());
    }
}
