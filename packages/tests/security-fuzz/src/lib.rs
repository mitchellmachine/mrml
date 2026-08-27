#![no_std]

#[cfg(test)]
mod tests {
    use mrml_runtime::{Text, join_path, process_id, remove_file, temporary_directory, write_file};

    const MAX_CASE_BYTES: usize = 256;
    const RANDOM_CASES_PER_SEED: usize = 128;

    fn visit_structural_mutations(seed: &[u8], mut visit: impl FnMut(&[u8])) {
        assert!(seed.len() <= MAX_CASE_BYTES);
        visit(seed);
        for length in 0..seed.len() {
            visit(&seed[..length]);
        }

        let mut changed = [0u8; MAX_CASE_BYTES];
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
            for poison in [0, 1, 0x7f, 0x80, 0xfe, 0xff] {
                changed[index] = poison;
                visit(&changed[..seed.len()]);
            }
            changed[index] = original;
        }

        for split in 0..seed.len() {
            let suffix = seed.len() - split;
            if seed.len() + suffix <= MAX_CASE_BYTES {
                changed[..seed.len()].copy_from_slice(seed);
                changed[seed.len()..seed.len() + suffix].copy_from_slice(&seed[split..]);
                visit(&changed[..seed.len() + suffix]);
            }
        }
    }

    fn visit_deterministic_random_mutations(seed: &[u8], mut visit: impl FnMut(&[u8])) {
        assert!(seed.len() <= MAX_CASE_BYTES);
        let mut state = 0x9e37_79b9_7f4a_7c15_u64 ^ seed.len() as u64;
        for (index, byte) in seed.iter().enumerate() {
            state ^= u64::from(*byte) << ((index % 8) * 8);
            state = state.rotate_left(17).wrapping_mul(0xd6e8_feb8_6659_fd93);
        }
        for _ in 0..RANDOM_CASES_PER_SEED {
            let mut case = [0u8; MAX_CASE_BYTES];
            case[..seed.len()].copy_from_slice(seed);
            state = xorshift64(state);
            let mut length = seed.len();
            let edits = 1 + (state as usize & 7);
            for _ in 0..edits {
                state = xorshift64(state);
                match state & 3 {
                    0 if length != 0 => {
                        let index = state as usize % length;
                        case[index] ^= 1 << ((state >> 8) & 7);
                    }
                    1 if length != 0 => {
                        let index = state as usize % length;
                        case[index] = (state >> 16) as u8;
                    }
                    2 if length < MAX_CASE_BYTES => {
                        let index = if length == 0 {
                            0
                        } else {
                            state as usize % (length + 1)
                        };
                        case.copy_within(index..length, index + 1);
                        case[index] = (state >> 24) as u8;
                        length += 1;
                    }
                    _ if length != 0 => {
                        let index = state as usize % length;
                        case.copy_within(index + 1..length, index);
                        length -= 1;
                    }
                    _ => {}
                }
            }
            visit(&case[..length]);
        }
    }

    fn visit_corpus(seeds: &[&[u8]], mut visit: impl FnMut(&[u8])) {
        for seed in seeds {
            visit_structural_mutations(seed, &mut visit);
            visit_deterministic_random_mutations(seed, &mut visit);
        }
        for left in seeds {
            for right in seeds {
                if left.len() + right.len() <= MAX_CASE_BYTES {
                    let mut joined = [0u8; MAX_CASE_BYTES];
                    joined[..left.len()].copy_from_slice(left);
                    joined[left.len()..left.len() + right.len()].copy_from_slice(right);
                    visit(&joined[..left.len() + right.len()]);
                }
            }
        }
    }

    const fn xorshift64(mut value: u64) -> u64 {
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        value
    }

    fn corpus_path(name: &str) -> Text {
        join_path(
            &temporary_directory(),
            &mrml_runtime::mrml_format!("mrml-security-fuzz-{name}-{}", process_id()),
        )
    }

    #[test]
    fn gguf_corpus_and_deterministic_mutations_never_panic() {
        let mut version_three = [0u8; 32];
        version_three[..4].copy_from_slice(b"GGUF");
        version_three[4..8].copy_from_slice(&3u32.to_le_bytes());
        let minimized_regressions: &[&[u8]] = &[
            b"",
            b"GGU",
            b"GGUF\x03\0\0\0",
            b"GGUF\xff\xff\xff\xff",
            &version_three,
        ];
        let path = corpus_path("gguf.bin");
        visit_corpus(minimized_regressions, |bytes| {
            write_file(&path, bytes).unwrap();
            let _ = mrml_tensor::GgufFile::open(&path);
        });
        remove_file(&path).unwrap();
    }

    #[test]
    fn zim_corpus_and_deterministic_mutations_never_panic() {
        let mut version_six = [0u8; 97];
        version_six[..4].copy_from_slice(&mrml_zim::ZIM_MAGIC.to_le_bytes());
        version_six[4..6].copy_from_slice(&6u16.to_le_bytes());
        version_six[32..40].copy_from_slice(&80u64.to_le_bytes());
        version_six[40..48].copy_from_slice(&80u64.to_le_bytes());
        version_six[48..56].copy_from_slice(&80u64.to_le_bytes());
        version_six[56..64].copy_from_slice(&80u64.to_le_bytes());
        version_six[64..68].copy_from_slice(&u32::MAX.to_le_bytes());
        version_six[68..72].copy_from_slice(&u32::MAX.to_le_bytes());
        version_six[72..80].copy_from_slice(&81u64.to_le_bytes());
        let zim_magic = mrml_zim::ZIM_MAGIC.to_le_bytes();
        let minimized_regressions: &[&[u8]] =
            &[b"", &zim_magic, &version_six[..16], &version_six];
        let path = corpus_path("zim.bin");
        visit_corpus(minimized_regressions, |bytes| {
            write_file(&path, bytes).unwrap();
            let _ = mrml_zim::Archive::open(&path);
        });
        remove_file(&path).unwrap();
    }

    #[test]
    fn x509_der_corpus_and_deterministic_mutations_never_panic() {
        const MINIMIZED_REGRESSIONS: &[&[u8]] = &[
            &[],
            &[0x30, 0x00],
            &[0x30, 0x81, 0x80],
            &[0x30, 0x82, 0xff, 0xff],
            &[0x30, 0x80, 0x00, 0x00],
            &[0x30, 0x03, 0x30, 0x01, 0xff],
        ];
        visit_corpus(MINIMIZED_REGRESSIONS, |bytes| {
            let _ = mrml_tls::Certificate::parse(bytes);
        });
    }

    #[test]
    fn minimized_invalid_inputs_remain_rejected() {
        let gguf = corpus_path("gguf-minimized.bin");
        write_file(&gguf, b"GGUF\xff\xff\xff\xff").unwrap();
        assert!(mrml_tensor::GgufFile::open(&gguf).is_err());
        remove_file(&gguf).unwrap();

        let zim = corpus_path("zim-minimized.bin");
        let zim_magic = mrml_zim::ZIM_MAGIC.to_le_bytes();
        write_file(&zim, &zim_magic).unwrap();
        assert!(mrml_zim::Archive::open(&zim).is_err());
        remove_file(&zim).unwrap();

        assert!(mrml_tls::Certificate::parse(&[0x30, 0x82, 0xff, 0xff]).is_err());
    }
}
