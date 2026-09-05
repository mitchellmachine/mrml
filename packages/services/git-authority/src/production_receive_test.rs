// Local pack/ref integration only: the RPC adapter deliberately bypasses transport.
struct CatalogTestRpc<'a>(&'a ProductionAuthorityCatalog);
impl mrml_git::ProtectedAuthorityRpc for CatalogTestRpc<'_> {
    fn call(&mut self, operation: u8, request: &[u8], response: &mut [u8]) -> Result<usize, ()> {
        let result = self
            .0
            .dispatch(
                AuthorityOperation::from_code(operation).ok_or(())?,
                request,
                1_700_000_010,
            )
            .map_err(|_| ())?;
        if result.len() > response.len() {
            return Err(());
        }
        response[..result.len()].copy_from_slice(&result);
        Ok(result.len())
    }
    fn signer_identity(&self) -> [u8; 64] {
        let mut hash = mrml_crypto::Sha3_512::new();
        hash.update(b"MRML git receipt signer identity v1");
        hash.update(&mrml_crypto::ed25519_public(&[40; 32]));
        hash.finalize()
    }
}
struct CatalogTestReader {
    bytes: Vector<u8>,
    offset: usize,
}
impl mrml_git::BoundedRead for CatalogTestReader {
    fn remaining(&self) -> u64 {
        (self.bytes.len() - self.offset) as u64
    }
    fn read(&mut self, output: &mut [u8]) -> Result<usize, mrml_git::GitdCoreError> {
        let count = output.len().min(137).min(self.bytes.len() - self.offset);
        output[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}
struct CatalogTestWriter(Vector<u8>);
impl mrml_git::BoundedWrite for CatalogTestWriter {
    fn remaining(&self) -> u64 {
        (1024 * 1024 - self.0.len()) as u64
    }
    fn write(&mut self, input: &[u8]) -> Result<(), mrml_git::GitdCoreError> {
        self.0
            .try_extend_from_slice(input)
            .map_err(|_| mrml_git::GitdCoreError::Resource)
    }
}
fn catalog_receive_initial_tip() -> mrml_git::ObjectId {
    use mrml_git::{ObjectKind, encode_loose_object_with_format};
    let tree = encode_loose_object_with_format(ObjectFormat::Sha256, ObjectKind::Tree, &[]).0;
    let contents = format!(
        "tree {}\nauthor MRML Deployment <deployment@mrml.invalid> 1 +0000\ncommitter MRML Deployment <deployment@mrml.invalid> 1 +0000\n\nMRML repository initialization\n",
        tree.to_hex()
    );
    encode_loose_object_with_format(
        ObjectFormat::Sha256,
        ObjectKind::Commit,
        contents.as_bytes(),
    )
    .0
}
fn catalog_receive_pack_integration(root: &Path, catalog: &ProductionAuthorityCatalog) {
    use mrml_git::*;
    let mut public = [0; ML_DSA_65_PUBLIC_KEY_BYTES];
    let mut secret = [0; ML_DSA_65_SECRET_KEY_BYTES];
    ml_dsa_65_keygen(&[38; 32], &mut public, &mut secret).unwrap();
    let signing = SigningKeyV6::from_seed([37; 32], 1_700_000_000).unwrap();
    let pair = AuthorizedHybridPair::bind(&signing.public_key(), &public);
    let budget = WorkBudget {
        max_input_bytes: 2 * 1024 * 1024,
        max_output_bytes: 1024 * 1024,
        max_memory_bytes: 1024 * 1024,
        max_work_units: 16 * 1024 * 1024,
    };
    let limits = QueryLimits {
        max_entries: 16,
        max_bytes: 8192,
    };
    let mut fixtures = Vec::new();
    for (name, generation) in [("owner/first", 4), ("owner/second", 10)] {
        let directory = root.join("receive").join(name);
        std::fs::create_dir_all(&directory).unwrap();
        let identity = RepositoryIdentity::parse(name).unwrap();
        let view = FilesystemRepositoryView::initialize_sha256(
            identity.clone(),
            path(&directory.join("objects")),
            path(&directory.join("refs")),
            RepositoryGeneration(generation),
            TrustGeneration(1),
            RevocationGeneration(1),
        )
        .unwrap();
        let old = view.resolve_ref(&identity, "refs/heads/main").unwrap();
        assert_eq!(old, catalog_receive_initial_tip());
        let tree = view
            .read_commit_details(&identity, old, limits)
            .unwrap()
            .tree;
        let contents = format!(
            "tree {}\nparent {}\nauthor Owner <owner@example.invalid> 2 +0000\ncommitter Owner <owner@example.invalid> 2 +0000\n\nprotected {name}\n",
            tree.to_hex(),
            old.to_hex()
        );
        let new = encode_loose_object_with_format(
            ObjectFormat::Sha256,
            ObjectKind::Commit,
            contents.as_bytes(),
        )
        .0;
        let transcript = canonical_hybrid_transcript(
            &identity,
            ObjectFormat::Sha256,
            GitObjectType::Commit,
            SignaturePurpose::GitCommit,
            TrustGeneration(1),
            pair,
            contents.as_bytes(),
        )
        .unwrap();
        let mut pgp = [0; MAX_OPENPGP_SIGNATURE_BYTES];
        let length = sign_detached_v6_ascii_with_salt(
            &signing,
            &transcript,
            DigestAlgorithm::Sha512,
            1_700_000_001,
            &[50; 32],
            &mut pgp,
        )
        .unwrap();
        let mut ml = [0; ML_DSA_65_SIGNATURE_BYTES];
        ml_dsa_65_sign(
            &secret,
            b"mrml.git.hybrid.v1",
            &transcript,
            &[51; 32],
            &mut ml,
        )
        .unwrap();
        let proof = DetachedCommitProofRecord::new(new, &pgp[..length], &ml).unwrap();
        let mut input = protected_push_command_with_proofs(
            old,
            new,
            "refs/heads/main",
            QuarantineTransactionId([49; 16]),
            &[proof],
        )
        .unwrap();
        let pack = encode_pack_with_format(
            &[PackObject {
                id: new,
                kind: ObjectKind::Commit,
                contents: contents.as_bytes().iter().copied().collect(),
            }],
            ObjectFormat::Sha256,
        )
        .unwrap();
        input.extend(pack.iter().copied());
        fixtures.push((directory, identity, generation, old, new, contents, input));
    }
    erase_secret_bytes(&mut secret);
    for (index, (directory, identity, generation, _, new, _, bytes)) in fixtures.iter().enumerate()
    {
        let mut store = LinuxDurableReceiveStore::open(
            path(&directory.join("journals")),
            path(&directory.join("packs")),
            path(&directory.join("refs")),
            path(&directory.join("plain-receipts")),
            ObjectFormat::Sha256,
            1024 * 1024,
        )
        .unwrap();
        let receipts =
            AuthenticatedAuditReceiptDirectory::open(path(&directory.join("signed-receipts")))
                .unwrap();
        let mut view = FilesystemRepositoryView::open_with_arrivals(
            identity.clone(),
            path(&directory.join("objects")),
            path(&directory.join("refs")),
            path(&directory.join("packs")),
            1024 * 1024,
        )
        .unwrap();
        let policy = LinuxDurableTrustPolicyStore::open(path(
            &root.join("policies").join(identity.as_str()),
        ))
        .unwrap()
        .load()
        .unwrap();
        let mut authority = RemoteProtectedReceiveAuthority::new(CatalogTestRpc(catalog));
        let mut input = CatalogTestReader {
            bytes: bytes.clone(),
            offset: 0,
        };
        let mut output = CatalogTestWriter(Vector::new());
        view.execute_protected_receive_with_receipts(
            SmartGitRequest {
                repository: identity.clone(),
                repository_generation: RepositoryGeneration(*generation),
                operation: SmartGitOperation::ReceivePack,
                object_format: ObjectFormat::Sha256,
            },
            &mut store,
            &policy,
            receipts,
            &mut authority,
            QuarantineTransactionId([52; 16]),
            QuarantineLimits {
                max_incoming_pack_bytes: 1024 * 1024,
                max_expanded_object_bytes: 1024 * 1024,
                max_individual_object_bytes: 1024 * 1024,
                max_objects: 16,
                max_refs: 4,
                minimum_free_space_bytes: 0,
            },
            HistoryVerificationLimits::default(),
            16 * 1024 * 1024,
            &mut input,
            &mut output,
            budget,
        )
        .unwrap();
        assert_eq!(input.offset, bytes.len());
        assert!(!output.0.is_empty());
        assert_eq!(view.resolve_ref(identity, "refs/heads/main").unwrap(), *new);
        for (other_index, (other_dir, other_id, other_generation, old, new, _, _)) in
            fixtures.iter().enumerate()
        {
            let expected_generation =
                RepositoryGeneration(other_generation + u64::from(other_index <= index));
            let state = ActiveRefFile::open(path(&other_dir.join("refs")))
                .unwrap()
                .load()
                .unwrap();
            assert_eq!(state.repository_generation, expected_generation);
            assert_eq!(
                state.refs[0].1,
                if other_index <= index { *new } else { *old }
            );
            assert_eq!(
                parse_authority_generation_result(
                    &catalog
                        .dispatch(
                            AuthorityOperation::QueryGenerations,
                            &encode_authority_generation_query(other_id).unwrap(),
                            1_700_000_010
                        )
                        .unwrap()
                )
                .unwrap()
                .0,
                expected_generation
            );
        }
    }
    // Reopen selected arrival packs and fetch them through upload-pack. Rehash the
    // returned objects, including the new commit, without invoking host Git.
    for (directory, identity, generation, _, new, contents, _) in &fixtures {
        let mut view = FilesystemRepositoryView::open_with_arrivals(
            identity.clone(),
            path(&directory.join("objects")),
            path(&directory.join("refs")),
            path(&directory.join("packs")),
            1024 * 1024,
        )
        .unwrap();
        assert_eq!(view.resolve_ref(identity, "refs/heads/main").unwrap(), *new);
        let mut wire = CatalogTestWriter(Vector::new());
        let mut protocol = ProtocolBudget::new(budget);
        for line in [
            Some(b"command=fetch\n".as_slice()),
            Some(b"object-format=sha256\n"),
            None,
            Some(format!("want {}\n", new.to_hex()).as_bytes()),
            Some(b"done\n"),
            Some(b"ofs-delta\n"),
        ] {
            write_pkt_line(
                &mut wire,
                &match line {
                    Some(bytes) => PktLine::Data(bytes.iter().copied().collect()),
                    None => PktLine::Delimiter,
                },
                &mut protocol,
            )
            .unwrap();
        }
        write_pkt_line(&mut wire, &PktLine::Flush, &mut protocol).unwrap();
        let mut input = CatalogTestReader {
            bytes: wire.0,
            offset: 0,
        };
        let mut output = CatalogTestWriter(Vector::new());
        view.smart_git(
            SmartGitRequest {
                repository: identity.clone(),
                repository_generation: RepositoryGeneration(generation + 1),
                operation: SmartGitOperation::UploadPack,
                object_format: ObjectFormat::Sha256,
            },
            &mut input,
            &mut output,
            budget,
        )
        .unwrap();
        let mut input = CatalogTestReader {
            bytes: output.0,
            offset: 0,
        };
        let mut protocol = ProtocolBudget::new(budget);
        assert_eq!(
            read_pkt_line(&mut input, &mut protocol).unwrap(),
            PktLine::Data(Vector::from(*b"packfile\n"))
        );
        let mut pack = Vector::new();
        loop {
            match read_pkt_line(&mut input, &mut protocol).unwrap() {
                PktLine::Data(bytes) => {
                    assert_eq!(bytes[0], 1);
                    pack.extend(bytes[1..].iter().copied());
                }
                PktLine::Flush => break,
                _ => panic!("unexpected fetch packet"),
            }
        }
        let objects = parse_pack_with_format(&pack, ObjectFormat::Sha256).unwrap();
        assert!(
            objects
                .iter()
                .any(|object| object.id == *new && &*object.contents == contents.as_bytes())
        );
        for object in objects {
            assert_eq!(
                encode_loose_object_with_format(
                    ObjectFormat::Sha256,
                    object.kind,
                    &object.contents
                )
                .0,
                object.id
            );
        }
        let candidate = parse_authority_candidate_record(
            &catalog
                .dispatch(
                    AuthorityOperation::QueryCandidateById,
                    &encode_authority_candidate_lookup(identity, QuarantineTransactionId([49; 16]))
                        .unwrap(),
                    1_700_000_010,
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(candidate.status, AuthorityCandidateStatus::Completed);
    }
}
