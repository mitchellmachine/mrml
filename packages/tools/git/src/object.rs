use core::fmt;
use mrml_runtime::{Text, Vector};

use crate::inflate::inflate_zlib;
use crate::{ObjectFormat, ObjectId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectKind {
    Blob,
    Tree,
    Commit,
    Tag,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Object {
    pub kind: ObjectKind,
    pub contents: Vector<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commit {
    pub tree: ObjectId,
    pub parents: Vector<ObjectId>,
    pub author: Text,
    pub message: Text,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeEntry {
    pub mode: u32,
    pub name: Text,
    pub id: ObjectId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectError {
    Truncated,
    UnsupportedCompression,
    InvalidBlock,
    InvalidChecksum,
    InvalidHeader,
    SizeMismatch,
}

impl ObjectKind {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Tree => "tree",
            Self::Commit => "commit",
            Self::Tag => "tag",
        }
    }
}

/// Produces a Git loose object with bounded incremental DEFLATE. Canonical
/// headers and content determine identity independently of storage compression.
pub fn encode_loose_object(kind: ObjectKind, contents: &[u8]) -> (ObjectId, Vector<u8>) {
    encode_loose_object_with_format(ObjectFormat::Sha1, kind, contents)
}

pub fn encode_loose_object_with_format(
    format: ObjectFormat,
    kind: ObjectKind,
    contents: &[u8],
) -> (ObjectId, Vector<u8>) {
    let header = mrml_runtime::mrml_format!("{} {}\0", kind.name(), contents.len());
    let id = crate::pack::hash_object(format, kind, contents);
    let mut output = Vector::new();
    match crate::deflate::stream_zlib(&[header.as_bytes(), contents], &mut output) {
        Ok(()) => (id, output),
        Err(never) => match never {},
    }
}

pub fn decode_loose_object(source: &[u8]) -> Result<Object, ObjectError> {
    let plain = inflate_zlib(source).map_err(|_| ObjectError::InvalidBlock)?;
    let nul = plain
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(ObjectError::InvalidHeader)?;
    let header = core::str::from_utf8(&plain[..nul]).map_err(|_| ObjectError::InvalidHeader)?;
    let (kind, size) = header.split_once(' ').ok_or(ObjectError::InvalidHeader)?;
    let kind = match kind {
        "blob" => ObjectKind::Blob,
        "tree" => ObjectKind::Tree,
        "commit" => ObjectKind::Commit,
        "tag" => ObjectKind::Tag,
        _ => return Err(ObjectError::InvalidHeader),
    };
    let size: usize = size.parse().map_err(|_| ObjectError::InvalidHeader)?;
    if size != plain.len() - nul - 1 {
        return Err(ObjectError::SizeMismatch);
    }
    let mut contents = Vector::new();
    contents.extend(plain[nul + 1..].iter().copied());
    Ok(Object { kind, contents })
}

impl fmt::Display for ObjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "truncated loose object",
            Self::UnsupportedCompression => "unsupported loose-object compression",
            Self::InvalidBlock => "invalid DEFLATE stored block",
            Self::InvalidChecksum => "loose-object checksum mismatch",
            Self::InvalidHeader => "invalid Git object header",
            Self::SizeMismatch => "Git object size mismatch",
        })
    }
}
impl core::error::Error for ObjectError {}

impl Commit {
    pub fn parse(contents: &[u8]) -> Result<Self, ObjectError> {
        Self::parse_with_format(contents, ObjectFormat::Sha1)
    }

    pub fn parse_with_format(contents: &[u8], format: ObjectFormat) -> Result<Self, ObjectError> {
        let text = core::str::from_utf8(contents).map_err(|_| ObjectError::InvalidHeader)?;
        let (headers, message) = text.split_once("\n\n").ok_or(ObjectError::InvalidHeader)?;
        let mut tree = None;
        let mut parents = Vector::new();
        let mut author = None;
        for line in headers.lines() {
            if let Some(value) = line.strip_prefix("tree ") {
                if tree.is_some() {
                    return Err(ObjectError::InvalidHeader);
                }
                tree = Some(ObjectId::parse_for(format, value).ok_or(ObjectError::InvalidHeader)?);
            } else if let Some(value) = line.strip_prefix("parent ") {
                parents.push(ObjectId::parse_for(format, value).ok_or(ObjectError::InvalidHeader)?);
            } else if let Some(value) = line.strip_prefix("author ") {
                author = Some(Text::from(value));
            }
        }
        Ok(Self {
            tree: tree.ok_or(ObjectError::InvalidHeader)?,
            parents,
            author: author.ok_or(ObjectError::InvalidHeader)?,
            message: message.into(),
        })
    }
}

pub fn parse_tree(contents: &[u8]) -> Result<Vector<TreeEntry>, ObjectError> {
    parse_tree_with_format(contents, ObjectFormat::Sha1)
}

pub fn parse_tree_with_format(
    contents: &[u8],
    format: ObjectFormat,
) -> Result<Vector<TreeEntry>, ObjectError> {
    let mut entries = Vector::new();
    let mut cursor = 0usize;
    while cursor < contents.len() {
        let space = contents[cursor..]
            .iter()
            .position(|byte| *byte == b' ')
            .map(|offset| cursor + offset)
            .ok_or(ObjectError::InvalidHeader)?;
        let mode_text = core::str::from_utf8(&contents[cursor..space])
            .map_err(|_| ObjectError::InvalidHeader)?;
        if mode_text.is_empty() || !mode_text.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
            return Err(ObjectError::InvalidHeader);
        }
        let mut mode = 0u32;
        for byte in mode_text.bytes() {
            mode = mode
                .checked_mul(8)
                .and_then(|value| value.checked_add((byte - b'0') as u32))
                .ok_or(ObjectError::InvalidHeader)?;
        }
        cursor = space + 1;
        let nul = contents[cursor..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| cursor + offset)
            .ok_or(ObjectError::Truncated)?;
        let name =
            core::str::from_utf8(&contents[cursor..nul]).map_err(|_| ObjectError::InvalidHeader)?;
        if name.is_empty()
            || matches!(name, "." | "..")
            || name.contains(['/', '\\'])
            || name.chars().any(char::is_control)
        {
            return Err(ObjectError::InvalidHeader);
        }
        cursor = nul + 1;
        let hash_len = format.hash_len();
        let id = ObjectId::from_bytes(
            format,
            contents
                .get(cursor..cursor + hash_len)
                .ok_or(ObjectError::Truncated)?,
        )
        .ok_or(ObjectError::InvalidHeader)?;
        cursor += hash_len;
        if !matches!(mode, 0o40000 | 0o100644 | 0o100755 | 0o120000 | 0o160000) {
            return Err(ObjectError::InvalidHeader);
        }
        entries.push(TreeEntry {
            mode,
            name: name.into(),
            id,
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_loose_object_compresses_without_changing_identity() {
        let input: Vector<u8> = core::iter::repeat_n(b'x', 1024 * 1024 + 1).collect();
        let (id, encoded) =
            encode_loose_object_with_format(ObjectFormat::Sha256, ObjectKind::Blob, &input);
        assert_eq!(id, ObjectId::blob_with_format(ObjectFormat::Sha256, &input));
        assert!(encoded.len() < input.len() / 10);
        assert_eq!(decode_loose_object(&encoded).unwrap().contents, input);
    }

    #[test]
    fn loose_blob_has_git_id_and_valid_stored_stream() {
        let (id, bytes) = encode_loose_object(ObjectKind::Blob, b"");
        assert_eq!(id.to_hex(), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
        assert_eq!(&bytes[..7], &[0x78, 0x01, 1, 7, 0, 0xf8, 0xff]);
        assert_eq!(&bytes[7..14], b"blob 0\0");
    }

    #[test]
    fn splits_large_objects_into_deflate_blocks() {
        let (_, bytes) = encode_loose_object(ObjectKind::Blob, &[42; 70_000]);
        assert!(bytes.len() < 7000);
        assert_eq!(
            &*decode_loose_object(&bytes).unwrap().contents,
            &[42; 70_000]
        );
    }

    #[test]
    fn native_loose_objects_round_trip() {
        let (_, encoded) = encode_loose_object(ObjectKind::Commit, b"tree deadbeef\n\nmessage\n");
        assert_eq!(
            decode_loose_object(&encoded).unwrap(),
            Object {
                kind: ObjectKind::Commit,
                contents: Vector::from(*b"tree deadbeef\n\nmessage\n")
            }
        );
    }

    #[test]
    fn parses_commit_graph_metadata() {
        let tree = "1111111111111111111111111111111111111111";
        let parent = "2222222222222222222222222222222222222222";
        let text = mrml_runtime::mrml_format!(
            "tree {tree}\nparent {parent}\nauthor MRML <mrml@example.invalid> 1 +0000\ncommitter MRML <mrml@example.invalid> 1 +0000\n\nmessage\n"
        );
        let commit = Commit::parse(text.as_bytes()).unwrap();
        assert_eq!(commit.tree, ObjectId::parse(tree).unwrap());
        assert_eq!(commit.parents[0], ObjectId::parse(parent).unwrap());
        assert_eq!(commit.message, "message\n");
    }

    #[test]
    fn sha256_loose_commit_and_tree_use_exact_format() {
        let tree = ObjectId::blob_with_format(ObjectFormat::Sha256, b"tree");
        let parent = ObjectId::blob_with_format(ObjectFormat::Sha256, b"parent");
        let commit_text = mrml_runtime::mrml_format!(
            "tree {tree}\nparent {parent}\nauthor MRML <mrml@example.invalid> 1 +0000\ncommitter MRML <mrml@example.invalid> 1 +0000\n\nmessage\n"
        );
        let (commit_id, encoded) = encode_loose_object_with_format(
            ObjectFormat::Sha256,
            ObjectKind::Commit,
            commit_text.as_bytes(),
        );
        assert_eq!(commit_id.format(), ObjectFormat::Sha256);
        assert_eq!(
            decode_loose_object(&encoded).unwrap().contents,
            commit_text.as_bytes()
        );
        let commit =
            Commit::parse_with_format(commit_text.as_bytes(), ObjectFormat::Sha256).unwrap();
        assert_eq!(commit.tree, tree);
        assert_eq!(&*commit.parents, &[parent]);
        assert_eq!(
            Commit::parse(commit_text.as_bytes()),
            Err(ObjectError::InvalidHeader)
        );

        let mut tree_bytes = Vector::from(*b"100644 file\0");
        tree_bytes.extend(tree.as_bytes().iter().copied());
        let entries = parse_tree_with_format(&tree_bytes, ObjectFormat::Sha256).unwrap();
        assert_eq!(entries[0].id, tree);
        assert_eq!(parse_tree(&tree_bytes), Err(ObjectError::InvalidHeader));
    }

    #[test]
    fn rejects_duplicate_or_foreign_width_commit_references() {
        let sha1 = "1111111111111111111111111111111111111111";
        let sha256 = "2222222222222222222222222222222222222222222222222222222222222222";
        let duplicate_tree = mrml_runtime::mrml_format!(
            "tree {sha256}\ntree {sha256}\nauthor MRML <mrml@example.invalid> 1 +0000\ncommitter MRML <mrml@example.invalid> 1 +0000\n\nmessage\n"
        );
        assert_eq!(
            Commit::parse_with_format(duplicate_tree.as_bytes(), ObjectFormat::Sha256),
            Err(ObjectError::InvalidHeader)
        );

        let foreign_tree_then_valid = mrml_runtime::mrml_format!(
            "tree {sha1}\ntree {sha256}\nauthor MRML <mrml@example.invalid> 1 +0000\ncommitter MRML <mrml@example.invalid> 1 +0000\n\nmessage\n"
        );
        assert_eq!(
            Commit::parse_with_format(foreign_tree_then_valid.as_bytes(), ObjectFormat::Sha256),
            Err(ObjectError::InvalidHeader)
        );

        let foreign_parent = mrml_runtime::mrml_format!(
            "tree {sha256}\nparent {sha1}\nauthor MRML <mrml@example.invalid> 1 +0000\ncommitter MRML <mrml@example.invalid> 1 +0000\n\nmessage\n"
        );
        assert_eq!(
            Commit::parse_with_format(foreign_parent.as_bytes(), ObjectFormat::Sha256),
            Err(ObjectError::InvalidHeader)
        );
    }
}
