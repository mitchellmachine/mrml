//! Deterministic, bounded acceptance data, never repository implementation.
use mrml_crypto::Sha256;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

pub(super) fn run(arguments: &[String]) -> Result<(), ()> {
    let [command, destination, profile] = arguments else {
        return Err(());
    };
    if command != "fixture-create" || !matches!(profile.as_str(), "text" | "random") {
        return Err(());
    }
    let destination = Path::new(destination);
    if !destination.is_absolute() {
        return Err(());
    }
    // A fresh directory and create_new keep prior fixture/repository data intact.
    fs::create_dir(destination).map_err(|_| ())?;
    const BUFFER_BYTES: usize = 64 * 1024;
    let mut buffer = [0u8; BUFFER_BYTES];
    let mut state = 0x6d72_6d6c_2560_0001u64;
    const LINE: &[u8] = b"MRML bounded incremental compression acceptance source line\n";
    for index in 0..8 {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination.join(format!("object-{index:02}.bin")))
            .map_err(|_| ())?;
        let mut hash = Sha256::new();
        for block in 0..512 {
            if profile == "random" {
                // Reproducible incompressible fixture, not cryptographic entropy.
                for chunk in buffer.chunks_exact_mut(8) {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    chunk.copy_from_slice(&state.to_le_bytes());
                }
            } else {
                for (position, byte) in buffer.iter_mut().enumerate() {
                    *byte = LINE[(block * BUFFER_BYTES + position) % LINE.len()];
                }
                // Keep all eight objects distinct so codec measurements do not
                // silently become a whole-object deduplication benchmark.
                buffer[0] = b'0' + index;
            }
            file.write_all(&buffer).map_err(|_| ())?;
            hash.update(&buffer);
        }
        file.sync_all().map_err(|_| ())?;
        let digest = hash.finalize();
        for byte in digest {
            print!("{byte:02x}");
        }
        println!("  object-{index:02}.bin");
    }
    Ok(())
}
