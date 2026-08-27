#![no_std]

#[cfg(test)]
mod tests {
    use mrml_runtime::{Text, join_path, process_id, remove_file, temporary_directory, write_file};

    const MAX_SEED_BYTES: usize = 128;

    fn mutate(seed: &[u8], mut visit: impl FnMut(&[u8])) {
        assert!(seed.len() <= MAX_SEED_BYTES);
        visit(seed);
        for length in 0..seed.len() {
            visit(&seed[..length]);
        }
        let mut changed = [0u8; MAX_SEED_BYTES];
        changed[..seed.len()].copy_from_slice(seed);
        for index in 0..seed.len() {
            for bit in 0..8 {
                changed[index] ^= 1 << bit;
                visit(&changed[..seed.len()]);
                changed[index] ^= 1 << bit;
            }
        }
        for index in 0..seed.len() {
            let original = changed[index];
            for poison in [0, 0x7f, 0x80, 0xff] {
                changed[index] = poison;
                visit(&changed[..seed.len()]);
            }
            changed[index] = original;
        }
    }

    fn corpus_path(name: &str) -> Text {
        join_path(
            &temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-security-fuzz-{name}-{}", process_id()),
        )
    }

    #[test]
    fn gguf_mutation_corpus_never_panics() {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(b"GGUF");
        seed[4..8].copy_from_slice(&3u32.to_le_bytes());
        let path = corpus_path("gguf.bin");
        mutate(&seed, |bytes| {
            write_file(&path, bytes).unwrap();
            let _ = mrml_tensor::GgufFile::open(&path);
        });
        remove_file(&path).unwrap();
    }

    #[test]
    fn zim_mutation_corpus_never_panics() {
        let mut seed = [0u8; 97];
        seed[..4].copy_from_slice(&mrml_zim::ZIM_MAGIC.to_le_bytes());
        seed[4..6].copy_from_slice(&6u16.to_le_bytes());
        seed[32..40].copy_from_slice(&80u64.to_le_bytes());
        seed[40..48].copy_from_slice(&80u64.to_le_bytes());
        seed[48..56].copy_from_slice(&80u64.to_le_bytes());
        seed[56..64].copy_from_slice(&80u64.to_le_bytes());
        seed[64..68].copy_from_slice(&u32::MAX.to_le_bytes());
        seed[68..72].copy_from_slice(&u32::MAX.to_le_bytes());
        seed[72..80].copy_from_slice(&81u64.to_le_bytes());
        let path = corpus_path("zim.bin");
        mutate(&seed, |bytes| {
            write_file(&path, bytes).unwrap();
            let _ = mrml_zim::Archive::open(&path);
        });
        remove_file(&path).unwrap();
    }

    #[test]
    fn x509_der_mutation_corpus_never_panics() {
        const SEEDS: &[&[u8]] = &[
            &[0x30, 0x00],
            &[0x30, 0x81, 0x80],
            &[0x30, 0x82, 0xff, 0xff],
            &[0x30, 0x80, 0x00, 0x00],
        ];
        for seed in SEEDS {
            mutate(seed, |bytes| {
                let _ = mrml_tls::Certificate::parse(bytes);
            });
        }
    }
}
