#![no_std]

#[cfg(test)]
mod tests {
    use mrml_acme::{
        decode_base64url, parse_account_response, parse_authorization_response,
        parse_order_response, validate_http01_request, AcmeDirectory, AcmeIdentifier, AcmeProblem,
        AcmeUrl, ChallengeToken, DnsIdentifier, RenewalInfo,
    };
    use mrml_certificate::{
        verify_backup, AuthoritativeChallengeZone, DurableAuthenticator, DurableError,
        DurableRecord, PemCertificateChain,
    };
    use mrml_runtime::{join_path, process_id, remove_file, temporary_directory, write_file, Text};

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
        let minimized_regressions: &[&[u8]] = &[b"", &zim_magic, &version_six[..16], &version_six];
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
    fn acme_json_url_base64_and_ari_corpora_never_panic() {
        let directory_url = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let json: &[&[u8]] = &[
            b"",
            b"{}",
            br#"{"type":"urn:ietf:params:acme:error:badNonce","status":400}"#,
            br#"{"newNonce":"https://ca.example/nonce","newAccount":"https://ca.example/account","newOrder":"https://ca.example/order"}"#,
            br#"{"suggestedWindow":{"start":"2030-01-01T00:00:00Z","end":"2030-01-02T00:00:00Z"}}"#,
        ];
        visit_corpus(json, |bytes| {
            if let Ok(text) = core::str::from_utf8(bytes) {
                let _ = AcmeDirectory::parse(text, &directory_url, 7);
                let _ = AcmeProblem::parse(text);
                let _ = RenewalInfo::parse(text, 1_800_000_000, 60);
                let _ = AcmeUrl::parse(text, false);
                let mut decoded = [0u8; MAX_CASE_BYTES];
                let _ = decode_base64url(text, &mut decoded);
            }
        });
    }

    #[test]
    fn acme_account_order_and_authorization_response_corpora_never_panic() {
        let directory_url = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let origin = directory_url.origin();
        let identifier = AcmeIdentifier::Dns(DnsIdentifier::parse("git.example", false).unwrap());
        let responses: &[&[u8]] = &[
            b"",
            b"{}",
            br#"{"status":"valid","contact":["mailto:owner@example.com"],"orders":"https://ca.example/orders/1"}"#,
            br#"{"status":"pending","identifiers":[{"type":"dns","value":"git.example"}],"authorizations":["https://ca.example/authz/1"],"finalize":"https://ca.example/finalize/1","profile":"classic"}"#,
            br#"{"identifier":{"type":"dns","value":"git.example"},"status":"pending","challenges":[{"type":"http-01","url":"https://ca.example/challenge/1","status":"pending","token":"token"}]}"#,
            br#"{"status":"valid","status":"revoked"}"#,
        ];
        visit_corpus(responses, |bytes| {
            if let Ok(text) = core::str::from_utf8(bytes) {
                let _ = parse_account_response(text, origin);
                let _ = parse_order_response(text, origin, &[identifier], "classic");
                let _ = parse_authorization_response(text, origin, identifier);
            }
        });
    }

    #[test]
    fn http01_request_corpus_never_panics_or_changes_binding() {
        let identifier = DnsIdentifier::parse("git.example", false).unwrap();
        let token = ChallengeToken::parse("fuzz-token").unwrap();
        let requests: &[&[u8]] = &[
            b"",
            b"GET / HTTP/1.1\r\n\r\n",
            b"GET /.well-known/acme-challenge/fuzz-token HTTP/1.1\r\nHost: git.example\r\n\r\n",
            b"GET //.well-known/acme-challenge/fuzz-token HTTP/1.1\r\nHost: git.example\r\n\r\n",
        ];
        visit_corpus(requests, |bytes| {
            let _ = validate_http01_request(bytes, &identifier, &token);
        });
    }

    #[test]
    fn dns_packet_and_compression_corpus_never_panics() {
        let zone = DnsIdentifier::parse("acme.example", false).unwrap();
        let nameserver = DnsIdentifier::parse("ns.acme.example", false).unwrap();
        let authority = AuthoritativeChallengeZone::new(zone, nameserver, [192, 0, 2, 1], 1, 1);
        let packets: &[&[u8]] = &[
            b"",
            &[0; 12],
            &[0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 16, 0, 1],
            &[
                0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0e, 0xc0, 0x0c, 0, 16, 0, 1,
            ],
        ];
        visit_corpus(packets, |bytes| {
            let mut output = [0u8; 512];
            let _ = authority.answer_udp(bytes, 0, &mut output);
            let _ = authority.answer_tcp(bytes, 0, &mut output);
        });
    }

    #[test]
    fn pem_chain_and_durable_record_corpora_never_panic() {
        struct RejectingAuthenticator;
        impl DurableAuthenticator for RejectingAuthenticator {
            fn authenticate(&mut self, _: &[u8]) -> Result<[u8; 32], DurableError> {
                Err(DurableError::AuthenticationFailed)
            }
            fn verify(&mut self, _: &[u8], _: &[u8; 32]) -> Result<bool, DurableError> {
                Ok(false)
            }
        }

        let seeds: &[&[u8]] = &[
            b"",
            b"MRMLCERT",
            b"-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n",
            b"-----BEGIN CERTIFICATE-----\nA===\n-----END CERTIFICATE-----\n",
        ];
        visit_corpus(seeds, |bytes| {
            let _ = PemCertificateChain::parse(bytes);
            let _ = DurableRecord::decode(bytes, &mut RejectingAuthenticator);
            let _ = verify_backup(bytes, &mut RejectingAuthenticator);
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
