use crate::abi::InterfaceIdentity;
use std::collections::BTreeSet;
use std::fmt::Write;

pub const INTERFACE_SCHEMA_VERSION: u16 = 1;
pub const MAX_INTERFACE_SCHEMA_BYTES: usize = 64 * 1024;
pub const MAX_INTERFACE_OPERATIONS: usize = 64;
pub const MAX_OPERATION_ARGUMENTS: usize = 16;
pub const MAX_INTERFACE_ERRORS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbiValueKind {
    U32,
    U64,
    I32,
    BorrowedRead,
    BorrowedWrite,
    OpaqueHandle,
}

impl AbiValueKind {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "u32" => Some(Self::U32),
            "u64" => Some(Self::U64),
            "i32" => Some(Self::I32),
            "borrowed-read" => Some(Self::BorrowedRead),
            "borrowed-write" => Some(Self::BorrowedWrite),
            "opaque-handle" => Some(Self::OpaqueHandle),
            _ => None,
        }
    }

    fn rust_type(self) -> &'static str {
        match self {
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::I32 => "i32",
            Self::BorrowedRead => "BorrowedReadView",
            Self::BorrowedWrite => "BorrowedWriteView",
            Self::OpaqueHandle => "OpaqueHandle",
        }
    }

    fn is_view(self) -> bool {
        matches!(self, Self::BorrowedRead | Self::BorrowedWrite)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbiArgument {
    name: String,
    kind: AbiValueKind,
    max_bytes: u64,
}

impl AbiArgument {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn kind(&self) -> AbiValueKind {
        self.kind
    }

    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbiOperation {
    id: u32,
    name: String,
    arguments: Vec<AbiArgument>,
    result: Option<AbiArgument>,
}

impl AbiOperation {
    pub const fn id(&self) -> u32 {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn arguments(&self) -> &[AbiArgument] {
        &self.arguments
    }

    pub fn result(&self) -> Option<&AbiArgument> {
        self.result.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbiErrorCode {
    operation: u32,
    code: u32,
    name: String,
}

impl AbiErrorCode {
    pub const fn operation(&self) -> u32 {
        self.operation
    }

    pub const fn code(&self) -> u32 {
        self.code
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceSchema {
    identity: InterfaceIdentity,
    operations: Vec<AbiOperation>,
    errors: Vec<AbiErrorCode>,
    fingerprint: [u8; 32],
}

impl InterfaceSchema {
    pub fn parse(input: &[u8]) -> Result<Self, SchemaError> {
        if input.is_empty() || input.len() > MAX_INTERFACE_SCHEMA_BYTES {
            return Err(SchemaError::InvalidLength);
        }
        let text = std::str::from_utf8(input).map_err(|_| SchemaError::InvalidUtf8)?;
        if text.contains('\r') || !text.ends_with('\n') || text.contains("\n\n") {
            return Err(SchemaError::NonCanonical);
        }
        let mut lines = text.lines();
        if lines.next() != Some("mrml-interface-schema|1") {
            return Err(SchemaError::InvalidHeader);
        }
        let interface = lines.next().ok_or(SchemaError::MissingInterface)?;
        let fields: Vec<_> = interface.split('|').collect();
        if fields.len() != 9
            || fields[0] != "interface"
            || fields[3] != "mrml-call-v1"
            || fields[4] != "parallel"
            || fields[5] != "fail-closed"
            || fields[6] != "none"
            || fields[7] != "none"
            || fields[8] != "no-capability-transfer"
        {
            return Err(SchemaError::UnsupportedPolicy);
        }
        let generation = canonical_u32(fields[2])?;
        let identity = InterfaceIdentity::new(fields[1].to_owned(), generation)
            .map_err(|_| SchemaError::InvalidInterface)?;
        let mut operations = Vec::new();
        let mut errors = Vec::new();
        let mut operation_ids = BTreeSet::new();
        let mut operation_names = BTreeSet::new();
        let mut error_keys = BTreeSet::new();
        let mut saw_end = false;
        for line in lines {
            if line == "end" {
                saw_end = true;
                continue;
            }
            if saw_end {
                return Err(SchemaError::TrailingData);
            }
            let fields: Vec<_> = line.split('|').collect();
            match fields.first().copied() {
                Some("operation") if fields.len() == 5 => {
                    if operations.len() == MAX_INTERFACE_OPERATIONS {
                        return Err(SchemaError::CapacityExceeded);
                    }
                    let id = canonical_u32(fields[1])?;
                    if id == 0
                        || !identifier(fields[2])
                        || !operation_ids.insert(id)
                        || !operation_names.insert(fields[2])
                    {
                        return Err(SchemaError::DuplicateOrInvalidIdentity);
                    }
                    let arguments = parse_arguments(fields[3])?;
                    let result = if fields[4] == "none" {
                        None
                    } else {
                        Some(parse_argument(fields[4])?)
                    };
                    operations.push(AbiOperation {
                        id,
                        name: fields[2].to_owned(),
                        arguments,
                        result,
                    });
                }
                Some("error") if fields.len() == 4 => {
                    if errors.len() == MAX_INTERFACE_ERRORS {
                        return Err(SchemaError::CapacityExceeded);
                    }
                    let operation = canonical_u32(fields[1])?;
                    let code = canonical_u32(fields[2])?;
                    if operation == 0
                        || code == 0
                        || !identifier(fields[3])
                        || !error_keys.insert((operation, code))
                    {
                        return Err(SchemaError::DuplicateOrInvalidIdentity);
                    }
                    errors.push(AbiErrorCode {
                        operation,
                        code,
                        name: fields[3].to_owned(),
                    });
                }
                _ => return Err(SchemaError::InvalidRecord),
            }
        }
        if !saw_end || operations.is_empty() {
            return Err(SchemaError::MissingEndOrOperation);
        }
        if !operations.windows(2).all(|pair| pair[0].id < pair[1].id)
            || !errors
                .windows(2)
                .all(|pair| (pair[0].operation, pair[0].code) < (pair[1].operation, pair[1].code))
            || errors
                .iter()
                .any(|error| !operation_ids.contains(&error.operation))
        {
            return Err(SchemaError::NonCanonicalOrder);
        }
        Ok(Self {
            identity,
            operations,
            errors,
            fingerprint: sha3_256(input),
        })
    }

    pub fn identity(&self) -> &InterfaceIdentity {
        &self.identity
    }

    pub fn operations(&self) -> &[AbiOperation] {
        &self.operations
    }

    pub fn errors(&self) -> &[AbiErrorCode] {
        &self.errors
    }

    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    pub fn generate_rust(&self) -> String {
        let mut output = String::new();
        writeln!(output, "// @generated by mrml; do not edit.").unwrap();
        output.push_str(
            "#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n\
pub struct BorrowedReadView { offset: u64, length: u64 }\n\
impl BorrowedReadView {\n\
    pub const fn within(offset: u64, length: u64, object_length: u64) -> Option<Self> {\n\
        match offset.checked_add(length) { Some(end) if end <= object_length => Some(Self { offset, length }), _ => None }\n\
    }\n\
    pub const fn offset(self) -> u64 { self.offset }\n\
    pub const fn length(self) -> u64 { self.length }\n\
}\n\
#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n\
pub struct BorrowedWriteView { offset: u64, length: u64 }\n\
impl BorrowedWriteView {\n\
    pub const fn within(offset: u64, length: u64, object_length: u64) -> Option<Self> {\n\
        match offset.checked_add(length) { Some(end) if end <= object_length => Some(Self { offset, length }), _ => None }\n\
    }\n\
    pub const fn offset(self) -> u64 { self.offset }\n\
    pub const fn length(self) -> u64 { self.length }\n\
}\n\
#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n\
pub struct OpaqueHandle { index: u32, generation: u32 }\n\
impl OpaqueHandle {\n\
    pub const fn new(index: u32, generation: u32) -> Option<Self> {\n\
        if generation == 0 { None } else { Some(Self { index, generation }) }\n\
    }\n\
    pub const fn index(self) -> u32 { self.index }\n\
    pub const fn generation(self) -> u32 { self.generation }\n\
}\n",
        );
        writeln!(
            output,
            "pub const INTERFACE_NAME: &str = {:?};",
            self.identity.name()
        )
        .unwrap();
        writeln!(
            output,
            "pub const INTERFACE_GENERATION: u32 = {};",
            self.identity.generation()
        )
        .unwrap();
        writeln!(
            output,
            "pub const INTERFACE_FINGERPRINT: [u8; 32] = {:?};",
            self.fingerprint
        )
        .unwrap();
        for operation in &self.operations {
            writeln!(
                output,
                "pub const OP_{}: u32 = {};",
                screaming(&operation.name),
                operation.id
            )
            .unwrap();
            writeln!(output, "#[derive(Clone, Copy, Debug, Eq, PartialEq)]").unwrap();
            writeln!(output, "pub struct {}Request {{", pascal(&operation.name)).unwrap();
            for argument in &operation.arguments {
                writeln!(
                    output,
                    "    pub {}: {},",
                    argument.name,
                    argument.kind.rust_type()
                )
                .unwrap();
            }
            writeln!(output, "}}").unwrap();
            writeln!(output, "impl {}Request {{", pascal(&operation.name)).unwrap();
            writeln!(output, "    pub fn validate(&self) -> bool {{").unwrap();
            let checks: Vec<String> = operation
                .arguments
                .iter()
                .filter(|argument| argument.kind.is_view())
                .map(|argument| {
                    format!("self.{}.length() <= {}", argument.name, argument.max_bytes)
                })
                .collect();
            writeln!(
                output,
                "        {}",
                if checks.is_empty() {
                    "true".to_owned()
                } else {
                    checks.join(" && ")
                }
            )
            .unwrap();
            writeln!(output, "    }}").unwrap();
            writeln!(output, "}}").unwrap();
            if let Some(result) = &operation.result {
                writeln!(
                    output,
                    "pub type {}Response = {};",
                    pascal(&operation.name),
                    result.kind.rust_type()
                )
                .unwrap();
            } else {
                writeln!(output, "pub type {}Response = ();", pascal(&operation.name)).unwrap();
            }
            let operation_errors: Vec<_> = self
                .errors
                .iter()
                .filter(|error| error.operation == operation.id)
                .collect();
            if !operation_errors.is_empty() {
                writeln!(output, "#[repr(u32)]").unwrap();
                writeln!(output, "#[derive(Clone, Copy, Debug, Eq, PartialEq)]").unwrap();
                writeln!(output, "pub enum {}Error {{", pascal(&operation.name)).unwrap();
                for error in operation_errors {
                    writeln!(output, "    {} = {},", pascal(&error.name), error.code).unwrap();
                }
                writeln!(output, "}}").unwrap();
            }
        }
        output
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaError {
    InvalidLength,
    InvalidUtf8,
    NonCanonical,
    InvalidHeader,
    MissingInterface,
    UnsupportedPolicy,
    InvalidInterface,
    InvalidInteger,
    InvalidRecord,
    DuplicateOrInvalidIdentity,
    InvalidArgument,
    CapacityExceeded,
    MissingEndOrOperation,
    NonCanonicalOrder,
    TrailingData,
}

fn parse_arguments(value: &str) -> Result<Vec<AbiArgument>, SchemaError> {
    if value == "none" {
        return Ok(Vec::new());
    }
    let arguments: Vec<_> = value
        .split(',')
        .map(parse_argument)
        .collect::<Result<_, _>>()?;
    if arguments.is_empty() || arguments.len() > MAX_OPERATION_ARGUMENTS {
        return Err(SchemaError::CapacityExceeded);
    }
    let mut names = BTreeSet::new();
    if arguments
        .iter()
        .any(|argument| !names.insert(argument.name.as_str()))
    {
        return Err(SchemaError::DuplicateOrInvalidIdentity);
    }
    Ok(arguments)
}

fn parse_argument(value: &str) -> Result<AbiArgument, SchemaError> {
    let fields: Vec<_> = value.split(':').collect();
    if fields.len() != 3 || !identifier(fields[0]) {
        return Err(SchemaError::InvalidArgument);
    }
    let kind = AbiValueKind::parse(fields[1]).ok_or(SchemaError::InvalidArgument)?;
    let max_bytes = canonical_u64(fields[2])?;
    if kind.is_view() != (max_bytes != 0) {
        return Err(SchemaError::InvalidArgument);
    }
    Ok(AbiArgument {
        name: fields[0].to_owned(),
        kind,
        max_bytes,
    })
}

fn canonical_u32(value: &str) -> Result<u32, SchemaError> {
    let parsed: u32 = value.parse().map_err(|_| SchemaError::InvalidInteger)?;
    if parsed.to_string() != value {
        return Err(SchemaError::InvalidInteger);
    }
    Ok(parsed)
}

fn canonical_u64(value: &str) -> Result<u64, SchemaError> {
    let parsed: u64 = value.parse().map_err(|_| SchemaError::InvalidInteger)?;
    if parsed.to_string() != value {
        return Err(SchemaError::InvalidInteger);
    }
    Ok(parsed)
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn screaming(value: &str) -> String {
    value.to_ascii_uppercase()
}

fn pascal(value: &str) -> String {
    let mut output = String::new();
    for word in value.split('_') {
        let mut bytes = word.bytes();
        if let Some(first) = bytes.next() {
            output.push(first.to_ascii_uppercase() as char);
            output.extend(bytes.map(char::from));
        }
    }
    output
}

fn sha3_256(input: &[u8]) -> [u8; 32] {
    const RATE: usize = 136;
    let mut state = [0_u64; 25];
    let (chunks, remainder) = input.as_chunks::<RATE>();
    for chunk in chunks {
        absorb(&mut state, chunk);
        keccak_f1600(&mut state);
    }
    let mut final_block = [0_u8; RATE];
    final_block[..remainder.len()].copy_from_slice(remainder);
    final_block[remainder.len()] = 0x06;
    final_block[RATE - 1] |= 0x80;
    absorb(&mut state, &final_block);
    keccak_f1600(&mut state);
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = (state[index / 8] >> ((index % 8) * 8)) as u8;
    }
    output
}

fn absorb(state: &mut [u64; 25], block: &[u8]) {
    for (index, byte) in block.iter().enumerate() {
        state[index / 8] ^= u64::from(*byte) << ((index % 8) * 8);
    }
}

fn keccak_f1600(state: &mut [u64; 25]) {
    const RC: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];
    const ROT: [u32; 25] = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56,
        14,
    ];
    for round in RC {
        let mut c = [0_u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= d;
            }
        }
        let mut b = [0_u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = state[x + 5 * y].rotate_left(ROT[x + 5 * y]);
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] =
                    b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }
        state[0] ^= round;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZSTD_SCHEMA: &str = "mrml-interface-schema|1\ninterface|org.mrml.interface.compression.zstd|3|mrml-call-v1|parallel|fail-closed|none|none|no-capability-transfer\noperation|1|decompress|input:borrowed-read:16777216,output:borrowed-write:536870912|written:u64:0\nerror|1|1|invalid_frame\nerror|1|2|output_too_small\nend\n";

    #[test]
    fn sha3_256_matches_fips_empty_vector() {
        assert_eq!(
            sha3_256(b""),
            [
                0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61,
                0xd6, 0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b,
                0x80, 0xf8, 0x43, 0x4a,
            ]
        );
    }

    #[test]
    fn canonical_schema_generates_pointer_free_bounded_rust() {
        let schema = InterfaceSchema::parse(ZSTD_SCHEMA.as_bytes()).unwrap();
        assert_eq!(schema.identity().generation(), 3);
        assert_eq!(schema.operations().len(), 1);
        assert_eq!(schema.errors().len(), 2);
        let rust = schema.generate_rust();
        assert!(rust.contains("pub struct DecompressRequest"));
        assert!(rust.contains("pub input: BorrowedReadView"));
        assert!(rust.contains("pub output: BorrowedWriteView"));
        assert!(rust.contains("self.input.length() <= 16777216"));
        assert!(rust.contains("self.output.length() <= 536870912"));
        assert!(rust.contains("pub enum DecompressError"));
        assert!(!rust.contains("*const"));
        assert!(!rust.contains("*mut"));
        assert!(!rust.contains("extern \"C\""));
    }

    #[test]
    fn malformed_ambiguous_and_reordered_schemas_fail_closed() {
        let crlf = ZSTD_SCHEMA.replace('\n', "\r\n");
        assert_eq!(
            InterfaceSchema::parse(crlf.as_bytes()),
            Err(SchemaError::NonCanonical)
        );
        let leading_zero = ZSTD_SCHEMA.replace("operation|1|", "operation|01|");
        assert_eq!(
            InterfaceSchema::parse(leading_zero.as_bytes()),
            Err(SchemaError::InvalidInteger)
        );
        let duplicate = ZSTD_SCHEMA.replace(
            "error|1|2|output_too_small\n",
            "error|1|1|output_too_small\n",
        );
        assert_eq!(
            InterfaceSchema::parse(duplicate.as_bytes()),
            Err(SchemaError::DuplicateOrInvalidIdentity)
        );
        let unbounded =
            ZSTD_SCHEMA.replace("input:borrowed-read:16777216", "input:borrowed-read:0");
        assert_eq!(
            InterfaceSchema::parse(unbounded.as_bytes()),
            Err(SchemaError::InvalidArgument)
        );
    }

    #[test]
    fn any_schema_change_changes_the_fingerprint() {
        let original = InterfaceSchema::parse(ZSTD_SCHEMA.as_bytes()).unwrap();
        let changed = ZSTD_SCHEMA.replace("536870912", "536870911");
        let changed = InterfaceSchema::parse(changed.as_bytes()).unwrap();
        assert_ne!(original.fingerprint(), changed.fingerprint());
    }
}
