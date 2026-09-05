use mrml_git::{
    ObjectFormat, ObjectId, ObjectKind, PackError, PackObject, PackStreamEncoder, PackStreamOutput,
    encode_loose_object_with_format,
};
use mrml_runtime::Vector;
use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
    time::Instant,
};
struct Sink {
    file: File,
    bytes: usize,
}
impl PackStreamOutput for Sink {
    fn write(&mut self, bytes: &[u8]) -> Result<(), PackError> {
        self.file
            .write_all(bytes)
            .map_err(|_| PackError::TooLarge)?;
        self.bytes += bytes.len();
        Ok(())
    }
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 4);
    let output = PathBuf::from(&args[3]);
    fs::create_dir(&output).unwrap();
    let mut data = Vector::new();
    let mut random = 0x12a4b6c8d0e2f579u64;
    for i in 0..32 * 1024 * 1024 {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        data.push(if args[2] == "random" {
            random as u8
        } else {
            b"fn bounded() { exact_bytes(); }\n"[i % 31]
        });
    }
    let start = Instant::now();
    let mut ids = File::create(output.join("ids.txt")).unwrap();
    let mut sink = Sink {
        file: File::create(output.join("pack.bin")).unwrap(),
        bytes: 0,
    };
    let mut encoder = if args[1] == "pack" {
        Some(PackStreamEncoder::new(8, ObjectFormat::Sha256, &mut sink).unwrap())
    } else {
        None
    };
    let mut loose_bytes = 0;
    for index in 0..8 {
        data[0] = index;
        let id = ObjectId::blob_with_format(ObjectFormat::Sha256, &data);
        writeln!(ids, "{}", id.to_hex()).unwrap();
        if let Some(encoder) = &mut encoder {
            let object = PackObject {
                id,
                kind: ObjectKind::Blob,
                contents: data,
            };
            encoder.write_object(&object).unwrap();
            data = object.contents;
        } else {
            let (actual, bytes) =
                encode_loose_object_with_format(ObjectFormat::Sha256, ObjectKind::Blob, &data);
            assert_eq!(actual, id);
            fs::write(output.join(id.to_hex().as_str()), &*bytes).unwrap();
            loose_bytes += bytes.len();
        }
    }
    if let Some(encoder) = encoder {
        encoder.finish().unwrap();
    }
    let stored = if args[1] == "pack" {
        sink.bytes
    } else {
        loose_bytes
    };
    println!(
        "mode={} corpus={} input_bytes=268435456 output_bytes={} ratio={:.6} elapsed_seconds={:.6}",
        args[1],
        args[2],
        stored,
        stored as f64 / 268435456.0,
        start.elapsed().as_secs_f64()
    );
    for path in ["/proc/self/status", "/proc/self/io", "/proc/self/stat"] {
        let text = fs::read_to_string(path).unwrap();
        if path.ends_with("status") {
            for line in text
                .lines()
                .filter(|line| line.starts_with("VmHWM:") || line.starts_with("VmRSS:"))
            {
                println!("{line}");
            }
        } else {
            println!("{path}: {text}");
        }
    }
}
