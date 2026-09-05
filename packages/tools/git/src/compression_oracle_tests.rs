//! Independent local compression oracles. External tools are test-only and opt-in.
extern crate std;

use crate::{
    ObjectFormat, ObjectKind, PackError, PackObject, PackStreamEncoder, PackStreamOutput,
    decode_loose_object, encode_loose_object_with_format, parse_pack_with_format,
};
use mrml_runtime::Vector;
use std::{format, fs, process::Command, vec, vec::Vec};

struct Sink {
    bytes: Vector<u8>,
    writes: usize,
    charges: usize,
    fail_write: usize,
    deny_charge: bool,
}
impl Sink {
    fn accepting() -> Self {
        Self {
            bytes: Vector::new(),
            writes: 0,
            charges: 0,
            fail_write: usize::MAX,
            deny_charge: false,
        }
    }
}
impl PackStreamOutput for Sink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), PackError> {
        self.writes += 1;
        if self.writes >= self.fail_write {
            return Err(PackError::Compression);
        }
        self.bytes
            .try_extend_from_slice(bytes)
            .map_err(|_| PackError::Compression)
    }
    fn charge_compression(&mut self, units: u64) -> Result<(), PackError> {
        assert!(units > 0);
        self.charges += 1;
        if self.deny_charge {
            Err(PackError::Compression)
        } else {
            Ok(())
        }
    }
}
fn object(bytes: &[u8]) -> PackObject {
    PackObject {
        id: encode_loose_object_with_format(ObjectFormat::Sha256, ObjectKind::Blob, bytes).0,
        kind: ObjectKind::Blob,
        contents: bytes.iter().copied().collect(),
    }
}
fn stream(objects: &[PackObject]) -> Vector<u8> {
    let mut output = Sink::accepting();
    let mut encoder =
        PackStreamEncoder::new(objects.len(), ObjectFormat::Sha256, &mut output).unwrap();
    for object in objects {
        encoder.write_object(object).unwrap();
    }
    encoder.finish().unwrap();
    output.bytes
}
#[test]
fn compression_stream_cancellation_and_charge_denial_are_terminal() {
    let object = object(&vec![b'x'; 65537]);
    for (fail_write, deny_charge) in [(5, false), (usize::MAX, true)] {
        let mut sink = Sink::accepting();
        sink.fail_write = fail_write;
        sink.deny_charge = deny_charge;
        let mut encoder = PackStreamEncoder::new(1, ObjectFormat::Sha256, &mut sink).unwrap();
        assert!(encoder.write_object(&object).is_err());
        assert!(encoder.write_object(&object).is_err());
        assert!(encoder.finish().is_err());
        assert!(parse_pack_with_format(&sink.bytes, ObjectFormat::Sha256).is_err());
        if deny_charge {
            assert_eq!(sink.charges, 1);
        } else {
            assert_eq!(sink.writes, fail_write);
        }
    }
}
#[test]
fn compression_stream_rejects_truncation_and_corrupt_trailers() {
    let bytes = b"related payload related payload related payload";
    let (_, loose) = encode_loose_object_with_format(ObjectFormat::Sha256, ObjectKind::Blob, bytes);
    for length in [0, 1, 2, loose.len() / 2, loose.len() - 1] {
        assert!(decode_loose_object(&loose[..length]).is_err());
    }
    let mut corrupt = loose.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(decode_loose_object(&corrupt).is_err());
    let pack = stream(&[object(bytes)]);
    for length in [0, 1, 11, pack.len() / 2, pack.len() - 1] {
        assert!(parse_pack_with_format(&pack[..length], ObjectFormat::Sha256).is_err());
    }
    let mut corrupt = pack.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(parse_pack_with_format(&corrupt, ObjectFormat::Sha256).is_err());
}

#[test]
fn compression_charge_denial_precedes_zlib_header_even_for_tiny_input() {
    struct Denied {
        writes: usize,
        charges: usize,
    }
    impl crate::deflate::DeflateOutput for Denied {
        type Error = ();
        fn charge(&mut self, _: u64) -> Result<(), ()> {
            self.charges += 1;
            Err(())
        }
        fn write(&mut self, _: &[u8]) -> Result<(), ()> {
            self.writes += 1;
            Ok(())
        }
    }
    for input in [b"".as_slice(), b"x"] {
        let mut sink = Denied {
            writes: 0,
            charges: 0,
        };
        assert_eq!(crate::deflate::stream_zlib(&[input], &mut sink), Err(()));
        assert_eq!(sink.charges, 1);
        assert_eq!(sink.writes, 0);
    }
}

// Python is only a standard-library codec adapter; Rust owns every test assertion.
const PYTHON_INFLATE: &str = r#"
import pathlib,sys,zlib
source=pathlib.Path(sys.argv[1]).read_bytes()
d=zlib.decompressobj(); plain=d.decompress(source); plain+=d.flush()
pathlib.Path(sys.argv[2]).write_bytes(plain)
print(int(d.eof),len(source)-len(d.unused_data),len(d.unconsumed_tail))
"#;
fn oracle_inflate(directory: &std::path::Path, source: &[u8]) -> Option<(Vec<u8>, usize, bool)> {
    let input = directory.join("codec-input");
    let output = directory.join("codec-output");
    fs::write(&input, source).unwrap();
    let result = Command::new("python3")
        .args(["-c", PYTHON_INFLATE])
        .arg(input)
        .arg(&output)
        .output()
        .unwrap();
    if !result.status.success() {
        return None;
    }
    let metadata = std::string::String::from_utf8(result.stdout).unwrap();
    let values: Vec<usize> = metadata
        .split_whitespace()
        .map(|v| v.parse().unwrap())
        .collect();
    assert_eq!(values.len(), 3);
    assert_eq!(values[2], 0);
    Some((fs::read(output).unwrap(), values[1], values[0] == 1))
}

#[test]
#[ignore = "explicit local Python zlib oracle; set MRML_COMPRESSION_GIT_ORACLE=1 for Git index-pack too"]
fn compression_external_zlib_and_git_oracle_matrix() {
    let root = std::env::temp_dir().join(format!("mrml-compression-oracle-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let mut cases: Vec<Vec<Vec<u8>>> = Vec::new();
    cases.push(
        [0, 1, 32767, 32768, 32769]
            .iter()
            .map(|size| vec![b'a'; *size])
            .collect(),
    );
    let mut random = vec![0; 65537];
    let mut state = 0x94c5_6821_77b9_324fu64;
    for byte in &mut random {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }
    fs::write(root.join("random"), &random).unwrap();
    let compressed = Command::new("python3").args(["-c", "import pathlib,sys,zlib; p=pathlib.Path(sys.argv[1]); p.with_suffix('.zlib').write_bytes(zlib.compress(p.read_bytes()))"])
        .arg(root.join("random")).output().expect("explicit oracle requires python3");
    assert!(
        compressed.status.success(),
        "{}",
        std::string::String::from_utf8_lossy(&compressed.stderr)
    );
    let mut mixed = random[..32768].to_vec();
    mixed.extend_from_slice(&vec![b'q'; 32768]);
    mixed.extend_from_slice(&random[..137]);
    cases.push(vec![mixed]);
    cases.push(vec![random, fs::read(root.join("random.zlib")).unwrap()]);
    cases.push(
        (0..128)
            .map(|i| {
                format!("related source fixture {i:04}: repeated payload repeated payload\n")
                    .repeat(16)
                    .into_bytes()
            })
            .collect(),
    );
    for (index, raws) in cases.into_iter().enumerate() {
        run_case(&root, index, &raws);
    }
    // Hold only one large boundary case at a time; the corpus and oracle remain bounded.
    for (index, size) in [32 * 1024 * 1024 - 1, 32 * 1024 * 1024, 32 * 1024 * 1024 + 1]
        .into_iter()
        .enumerate()
    {
        let mut bytes = vec![0; size];
        for (offset, byte) in bytes.iter_mut().enumerate() {
            *byte = b"large related content\n"[offset % 22];
        }
        run_case(&root, index + 4, &[bytes]);
    }
    fs::remove_dir_all(root).unwrap();
}
fn run_case(root: &std::path::Path, index: usize, raws: &[Vec<u8>]) {
    let directory = root.join(format!("case-{index}"));
    fs::create_dir(&directory).unwrap();
    let mut objects = Vec::new();
    for (i, raw) in raws.iter().enumerate() {
        let (id, loose) =
            encode_loose_object_with_format(ObjectFormat::Sha256, ObjectKind::Blob, raw);
        fs::write(directory.join(format!("{i}.raw")), raw).unwrap();
        let mut split = Vector::new();
        let first = raw.len().min(32767);
        let second = raw.len().min(32769);
        crate::deflate::stream_zlib(
            &[&raw[..first], &[], &raw[first..second], &raw[second..]],
            &mut split,
        )
        .unwrap();
        fs::write(directory.join(format!("{i}.split")), &split).unwrap();
        fs::write(directory.join(format!("{i}.loose")), &loose).unwrap();
        fs::write(directory.join(format!("{i}.id")), id.to_hex().as_bytes()).unwrap();
        let (plain, consumed, eof) = oracle_inflate(&directory, &split).unwrap();
        assert!(eof);
        assert_eq!(
            consumed,
            split.len(),
            "split slices must form exactly one stream"
        );
        assert_eq!(&plain, raw);
        let (plain, consumed, eof) = oracle_inflate(&directory, &loose).unwrap();
        assert!(eof);
        assert_eq!(consumed, loose.len());
        let mut expected = format!("blob {}\0", raw.len()).into_bytes();
        expected.extend_from_slice(raw);
        assert_eq!(plain, expected);
        if i == 0 {
            let truncated = oracle_inflate(&directory, &loose[..loose.len() - 1]);
            assert!(truncated.is_none_or(|(_, _, eof)| !eof));
            let mut corrupt = loose.clone();
            let last = corrupt.len() - 1;
            corrupt[last] ^= 1;
            assert!(oracle_inflate(&directory, &corrupt).is_none());
        }

        objects.push(PackObject {
            id,
            kind: ObjectKind::Blob,
            contents: raw.iter().copied().collect(),
        });
    }
    let pack = stream(&objects);
    fs::write(directory.join("objects.pack"), &pack).unwrap();
    assert_eq!(&pack[..4], b"PACK");
    assert_eq!(u32::from_be_bytes(pack[4..8].try_into().unwrap()), 2);
    assert_eq!(
        u32::from_be_bytes(pack[8..12].try_into().unwrap()) as usize,
        raws.len()
    );
    let mut position = 12;
    for raw in raws {
        let mut byte = pack[position];
        position += 1;
        assert_eq!((byte >> 4) & 7, 3);
        let mut size = usize::from(byte & 15);
        let mut shift = 4;
        while byte & 128 != 0 {
            byte = pack[position];
            position += 1;
            size |= usize::from(byte & 127) << shift;
            shift += 7;
        }
        assert_eq!(size, raw.len());
        let (plain, consumed, eof) =
            oracle_inflate(&directory, &pack[position..pack.len() - 32]).unwrap();
        assert!(eof);
        assert_eq!(&plain, raw);
        position += consumed;
    }
    assert_eq!(
        position,
        pack.len() - 32,
        "extra or concatenated zlib stream"
    );
    assert_eq!(
        parse_pack_with_format(&pack, ObjectFormat::Sha256).unwrap(),
        objects.iter().cloned().collect::<Vector<_>>()
    );
    std::eprintln!(
        "independent zlib decoded case {index}, {} objects",
        raws.len()
    );
    if std::env::var_os("MRML_COMPRESSION_GIT_ORACLE").is_some() {
        let git = directory.join("git");
        let result = Command::new("git")
            .args(["init", "--bare", "--object-format=sha256"])
            .arg(&git)
            .output()
            .expect("Git oracle explicitly requested");
        assert!(
            result.status.success(),
            "{}",
            std::string::String::from_utf8_lossy(&result.stderr)
        );
        let result = Command::new("git")
            .arg("-C")
            .arg(&git)
            .args(["index-pack", "--strict"])
            .arg(directory.join("objects.pack"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "case {index}: {}",
            std::string::String::from_utf8_lossy(&result.stderr)
        );
    }
    if index == 3 && std::env::var_os("MRML_COMPRESSION_GIT_ORACLE").is_some() {
        git_generated_related_pack(&directory, &objects);
    }
    fs::remove_dir_all(directory).unwrap();
}

fn git_generated_related_pack(directory: &std::path::Path, objects: &[PackObject]) {
    let paths = directory.join("paths");
    let ids = directory.join("ids");
    let mut names = std::string::String::new();
    for i in 0..objects.len() {
        names.push_str(directory.join(format!("{i}.raw")).to_str().unwrap());
        names.push('\n');
    }
    fs::write(&paths, names).unwrap();
    let result = Command::new("git")
        .arg("-C")
        .arg(directory.join("git"))
        .args(["hash-object", "-w", "--stdin-paths"])
        .stdin(fs::File::open(paths).unwrap())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        std::string::String::from_utf8_lossy(&result.stderr)
    );
    let text = std::string::String::from_utf8(result.stdout.clone()).unwrap();
    assert_eq!(text.lines().count(), objects.len());
    for (line, object) in text.lines().zip(objects) {
        assert_eq!(line, object.id.to_hex().as_str());
    }
    fs::write(&ids, result.stdout).unwrap();
    let result = Command::new("git")
        .arg("-C")
        .arg(directory.join("git"))
        .args([
            "pack-objects",
            "--stdout",
            "--window=64",
            "--depth=50",
            "--no-reuse-delta",
            "--no-reuse-object",
        ])
        .stdin(fs::File::open(ids).unwrap())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        std::string::String::from_utf8_lossy(&result.stderr)
    );
    let decoded = parse_pack_with_format(&result.stdout, ObjectFormat::Sha256).unwrap();
    assert_eq!(decoded.len(), objects.len());
    for expected in objects {
        assert!(decoded.iter().any(|actual| actual == expected));
    }
    std::eprintln!(
        "independent Git generated related pack decoded: {} exact objects",
        objects.len()
    );
}

#[test]
fn bounded_file_decoder_accepts_depth50_and_rejects_depth51() {
    use core::cell::RefCell;
    let root = std::env::temp_dir().join(format!("mrml-compression-depth-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    for depth in [50, 51] {
        let mut pack = Vector::from(*b"PACK");
        pack.extend(2u32.to_be_bytes());
        pack.extend(((depth + 1) as u32).to_be_bytes());
        let mut previous = Vector::from([b'a']);
        pack.push(0x31); // One-byte base blob.
        pack.extend(crate::deflate::encode_zlib(&previous));
        for index in 1..=depth {
            let next_byte = index as u8;
            let delta = [
                previous.len() as u8,
                previous.len() as u8 + 1,
                0x90,
                previous.len() as u8,
                1,
                next_byte,
            ];
            pack.push(0x76); // Six-byte REF_DELTA: copy base and insert one byte.
            pack.extend(
                crate::ObjectId::blob_with_format(ObjectFormat::Sha256, &previous)
                    .as_bytes()
                    .iter()
                    .copied(),
            );
            pack.extend(crate::deflate::encode_zlib(&delta));
            previous.push(next_byte);
        }
        let hash = ObjectFormat::Sha256.hash_bytes(&pack);
        pack.extend(hash.as_bytes().iter().copied());
        let path = root.join(format!("depth-{depth}.pack"));
        fs::write(&path, &pack).unwrap();
        let accepted = RefCell::new(Vector::<PackObject>::new());
        let result = crate::pack_file::validate_pack_file_with_bases(
            path.to_str().unwrap(),
            ObjectFormat::Sha256,
            pack.len() as u64,
            52,
            16384,
            128,
            1_000_000,
            &mut |id, kind, bytes| {
                accepted.borrow_mut().push(PackObject {
                    id,
                    kind,
                    contents: bytes.iter().copied().collect(),
                });
                Ok(())
            },
            |id, _| {
                Ok(accepted
                    .borrow()
                    .iter()
                    .find(|object| object.id == id)
                    .map(|object| (object.kind, object.contents.clone())))
            },
        );
        if depth == 50 {
            assert!(result.is_ok());
            assert_eq!(accepted.borrow().len(), 51);
        } else {
            assert!(matches!(result, Err(PackError::Delta)));
        }
    }
    fs::remove_dir_all(root).unwrap();
}
