use crate::{
    ActivationReceipt, DurableAuthenticator, DurableError, DurableNamespace, DurableObjectId,
    DurableRecord, DurableRecordKind, DurableStateStore, DurableTransaction,
    PreparedIdentityReceipt, TestedIdentityReceipt, TlsIdentityId, TransactionState,
};

const DEPLOYMENT_PAYLOAD_MAGIC: &[u8; 8] = b"MRMLDEPL";
pub const DEPLOYMENT_PAYLOAD_VERSION: u16 = 1;
const DEPLOYMENT_PAYLOAD_BYTES: usize = 131;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DurableDeploymentStage {
    CandidatePrepared = 1,
    Published = 2,
    Tested = 3,
    ActivationUncertain = 4,
    Active = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeploymentJournalError {
    Durable(DurableError),
    InvalidStage,
    ReceiptMismatch,
    Malformed,
}

impl From<DurableError> for DeploymentJournalError {
    fn from(value: DurableError) -> Self {
        Self::Durable(value)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DurableDeploymentReceipt {
    pub stage: DurableDeploymentStage,
    pub identity: TlsIdentityId,
    pub identity_generation: u64,
    pub descriptor_digest: [u8; 32],
    pub chain_digest: [u8; 32],
    pub target_generation: u64,
    pub previous_identity_generation: Option<u64>,
    pub record_generation: u64,
}

impl DurableDeploymentReceipt {
    pub fn prepared(receipt: PreparedIdentityReceipt, record_generation: u64) -> Self {
        Self {
            stage: DurableDeploymentStage::CandidatePrepared,
            identity: receipt.identity,
            identity_generation: receipt.generation,
            descriptor_digest: receipt.descriptor_digest,
            chain_digest: receipt.chain_digest,
            target_generation: 0,
            previous_identity_generation: None,
            record_generation,
        }
    }

    pub fn published(mut self, target_generation: u64) -> Result<Self, DeploymentJournalError> {
        if self.stage != DurableDeploymentStage::CandidatePrepared || target_generation == 0 {
            return Err(DeploymentJournalError::InvalidStage);
        }
        self.stage = DurableDeploymentStage::Published;
        self.target_generation = target_generation;
        Ok(self)
    }

    pub fn tested(
        mut self,
        receipt: TestedIdentityReceipt,
    ) -> Result<Self, DeploymentJournalError> {
        if self.stage != DurableDeploymentStage::Published
            || receipt.prepared.identity != self.identity
            || receipt.prepared.generation != self.identity_generation
            || receipt.prepared.descriptor_digest != self.descriptor_digest
            || receipt.prepared.chain_digest != self.chain_digest
            || receipt.target_generation != self.target_generation
            || !receipt.tls13_ok
            || !receipt.http3_quic_v2_ok
        {
            return Err(DeploymentJournalError::ReceiptMismatch);
        }
        self.stage = DurableDeploymentStage::Tested;
        Ok(self)
    }

    pub fn activation_uncertain(mut self) -> Result<Self, DeploymentJournalError> {
        if self.stage != DurableDeploymentStage::Tested {
            return Err(DeploymentJournalError::InvalidStage);
        }
        self.stage = DurableDeploymentStage::ActivationUncertain;
        Ok(self)
    }

    pub fn active(mut self, receipt: ActivationReceipt) -> Result<Self, DeploymentJournalError> {
        if !matches!(
            self.stage,
            DurableDeploymentStage::Tested | DurableDeploymentStage::ActivationUncertain
        ) || receipt.identity != self.identity
            || receipt.generation != self.identity_generation
            || receipt.descriptor_digest != self.descriptor_digest
            || receipt.target_generation != self.target_generation
        {
            return Err(DeploymentJournalError::ReceiptMismatch);
        }
        self.stage = DurableDeploymentStage::Active;
        self.previous_identity_generation = receipt.previous_generation;
        Ok(self)
    }

    pub fn prepare_persist(
        &self,
        object: DurableObjectId,
        authenticator: &mut impl DurableAuthenticator,
        store: &mut impl DurableStateStore,
    ) -> Result<DurableTransaction, DeploymentJournalError> {
        let mut payload = [0; DEPLOYMENT_PAYLOAD_BYTES];
        self.encode_payload(&mut payload);
        let record = DurableRecord::prepare(
            DurableNamespace::PublicState,
            DurableRecordKind::Deployment,
            object,
            self.record_generation,
            &payload,
            authenticator,
        )?;
        Ok(DurableTransaction::prepare(&record, store)?)
    }

    pub fn recover(
        encoded_record: &[u8],
        expected_object: DurableObjectId,
        authenticator: &mut impl DurableAuthenticator,
    ) -> Result<Self, DeploymentJournalError> {
        let record = DurableRecord::decode(encoded_record, authenticator)?;
        if record.namespace != DurableNamespace::PublicState
            || record.kind != DurableRecordKind::Deployment
            || record.object != expected_object
        {
            return Err(DeploymentJournalError::Malformed);
        }
        let mut receipt = Self::decode_payload(record.payload())?;
        receipt.record_generation = record.generation;
        Ok(receipt)
    }

    fn encode_payload(&self, output: &mut [u8; DEPLOYMENT_PAYLOAD_BYTES]) {
        output[..8].copy_from_slice(DEPLOYMENT_PAYLOAD_MAGIC);
        output[8..10].copy_from_slice(&DEPLOYMENT_PAYLOAD_VERSION.to_be_bytes());
        output[10] = self.stage as u8;
        output[11..27].copy_from_slice(&self.identity.0);
        output[27..35].copy_from_slice(&self.identity_generation.to_be_bytes());
        output[35..67].copy_from_slice(&self.descriptor_digest);
        output[67..99].copy_from_slice(&self.chain_digest);
        output[99..107].copy_from_slice(&self.target_generation.to_be_bytes());
        match self.previous_identity_generation {
            Some(generation) => {
                output[107] = 1;
                output[108..116].copy_from_slice(&generation.to_be_bytes());
            }
            None => output[107..116].fill(0),
        }
        output[116..124].copy_from_slice(&self.record_generation.to_be_bytes());
        output[124..131].fill(0);
    }

    fn decode_payload(input: &[u8]) -> Result<Self, DeploymentJournalError> {
        if input.len() != DEPLOYMENT_PAYLOAD_BYTES
            || input[..8] != *DEPLOYMENT_PAYLOAD_MAGIC
            || u16::from_be_bytes([input[8], input[9]]) != DEPLOYMENT_PAYLOAD_VERSION
            || input[124..].iter().any(|byte| *byte != 0)
        {
            return Err(DeploymentJournalError::Malformed);
        }
        let stage = match input[10] {
            1 => DurableDeploymentStage::CandidatePrepared,
            2 => DurableDeploymentStage::Published,
            3 => DurableDeploymentStage::Tested,
            4 => DurableDeploymentStage::ActivationUncertain,
            5 => DurableDeploymentStage::Active,
            _ => return Err(DeploymentJournalError::Malformed),
        };
        let mut identity = [0; 16];
        identity.copy_from_slice(&input[11..27]);
        let identity_generation = read_u64(&input[27..35])?;
        let mut descriptor_digest = [0; 32];
        descriptor_digest.copy_from_slice(&input[35..67]);
        let mut chain_digest = [0; 32];
        chain_digest.copy_from_slice(&input[67..99]);
        let target_generation = read_u64(&input[99..107])?;
        let previous_identity_generation = match input[107] {
            0 if input[108..116].iter().all(|byte| *byte == 0) => None,
            1 => Some(read_u64(&input[108..116])?),
            _ => return Err(DeploymentJournalError::Malformed),
        };
        let record_generation = read_u64(&input[116..124])?;
        if identity_generation == 0
            || descriptor_digest == [0; 32]
            || chain_digest == [0; 32]
            || (stage == DurableDeploymentStage::CandidatePrepared && target_generation != 0)
            || (stage != DurableDeploymentStage::CandidatePrepared && target_generation == 0)
            || (stage != DurableDeploymentStage::Active && previous_identity_generation.is_some())
        {
            return Err(DeploymentJournalError::Malformed);
        }
        Ok(Self {
            stage,
            identity: TlsIdentityId(identity),
            identity_generation,
            descriptor_digest,
            chain_digest,
            target_generation,
            previous_identity_generation,
            record_generation,
        })
    }
}

fn read_u64(input: &[u8]) -> Result<u64, DeploymentJournalError> {
    Ok(u64::from_be_bytes(
        input
            .try_into()
            .map_err(|_| DeploymentJournalError::Malformed)?,
    ))
}

pub fn commit_or_resolve_deployment(
    receipt: &mut DurableDeploymentReceipt,
    transaction: &mut DurableTransaction,
    store: &mut impl DurableStateStore,
) -> Result<TransactionState, DeploymentJournalError> {
    let state = match transaction.commit(store) {
        Ok(_) => TransactionState::Committed,
        Err(DurableError::CommitUncertain) => transaction.resolve(store)?,
        Err(error) => return Err(error.into()),
    };
    if state == TransactionState::Committed {
        receipt.record_generation =
            receipt
                .record_generation
                .checked_add(1)
                .ok_or(DeploymentJournalError::Durable(
                    DurableError::ArithmeticOverflow,
                ))?;
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommittedStoreReceipt, PreparedStoreReceipt};
    use mrml_crypto::hmac_sha256;

    struct Auth([u8; 32]);
    impl DurableAuthenticator for Auth {
        fn authenticate(&mut self, record: &[u8]) -> Result<[u8; 32], DurableError> {
            Ok(hmac_sha256(&self.0, &[record]))
        }
        fn verify(&mut self, record: &[u8], tag: &[u8; 32]) -> Result<bool, DurableError> {
            Ok(hmac_sha256(&self.0, &[record]) == *tag)
        }
    }

    struct Store {
        prepared: Option<PreparedStoreReceipt>,
        committed: Option<CommittedStoreReceipt>,
        uncertain: bool,
        apply: bool,
    }
    impl DurableStateStore for Store {
        fn prepare(
            &mut self,
            record: &DurableRecord,
        ) -> Result<PreparedStoreReceipt, DurableError> {
            let receipt = PreparedStoreReceipt {
                namespace: record.namespace,
                object: record.object,
                previous_generation: record.previous_generation,
                generation: record.generation,
                payload_digest: record.payload_digest,
                store_generation: record.generation,
            };
            self.prepared = Some(receipt);
            Ok(receipt)
        }
        fn commit(
            &mut self,
            prepared: PreparedStoreReceipt,
        ) -> Result<CommittedStoreReceipt, DurableError> {
            let receipt = CommittedStoreReceipt {
                namespace: prepared.namespace,
                object: prepared.object,
                generation: prepared.generation,
                payload_digest: prepared.payload_digest,
                store_generation: prepared.store_generation + 1,
            };
            if self.apply {
                self.committed = Some(receipt);
            }
            if self.uncertain {
                Err(DurableError::CommitUncertain)
            } else if self.apply {
                Ok(receipt)
            } else {
                Err(DurableError::StoreUnavailable)
            }
        }
        fn authoritative(
            &mut self,
            _: DurableNamespace,
            _: DurableObjectId,
        ) -> Result<Option<CommittedStoreReceipt>, DurableError> {
            Ok(self.committed)
        }
    }

    fn prepared() -> PreparedIdentityReceipt {
        PreparedIdentityReceipt {
            identity: TlsIdentityId([1; 16]),
            generation: 2,
            descriptor_digest: [3; 32],
            chain_digest: [4; 32],
        }
    }

    #[test]
    fn exact_stage_machine_rejects_substitution() {
        let receipt = DurableDeploymentReceipt::prepared(prepared(), 0);
        assert_eq!(
            receipt
                .tested(TestedIdentityReceipt {
                    prepared: prepared(),
                    target_generation: 1,
                    tls13_ok: true,
                    http3_quic_v2_ok: true,
                })
                .err(),
            Some(DeploymentJournalError::ReceiptMismatch)
        );
        let receipt = receipt.published(8).unwrap();
        let mut wrong = prepared();
        wrong.chain_digest[0] ^= 1;
        assert_eq!(
            receipt
                .tested(TestedIdentityReceipt {
                    prepared: wrong,
                    target_generation: 8,
                    tls13_ok: true,
                    http3_quic_v2_ok: true,
                })
                .err(),
            Some(DeploymentJournalError::ReceiptMismatch)
        );
    }

    #[test]
    fn uncertain_durable_commit_is_reread_and_authenticated() {
        let mut receipt = DurableDeploymentReceipt::prepared(prepared(), 0)
            .published(8)
            .unwrap()
            .tested(TestedIdentityReceipt {
                prepared: prepared(),
                target_generation: 8,
                tls13_ok: true,
                http3_quic_v2_ok: true,
            })
            .unwrap()
            .activation_uncertain()
            .unwrap();
        let object = DurableObjectId([9; 16]);
        let mut auth = Auth([7; 32]);
        let mut store = Store {
            prepared: None,
            committed: None,
            uncertain: true,
            apply: true,
        };
        let mut transaction = receipt
            .prepare_persist(object, &mut auth, &mut store)
            .unwrap();
        assert_eq!(
            commit_or_resolve_deployment(&mut receipt, &mut transaction, &mut store),
            Ok(TransactionState::Committed)
        );
        assert_eq!(receipt.record_generation, 1);

        let mut payload = [0; DEPLOYMENT_PAYLOAD_BYTES];
        receipt.encode_payload(&mut payload);
        let record = DurableRecord::prepare(
            DurableNamespace::PublicState,
            DurableRecordKind::Deployment,
            object,
            0,
            &payload,
            &mut auth,
        )
        .unwrap();
        let mut encoded = [0; crate::MAX_DURABLE_RECORD_BYTES];
        let used = record.encode(&mut encoded).unwrap();
        let recovered =
            DurableDeploymentReceipt::recover(&encoded[..used], object, &mut auth).unwrap();
        assert_eq!(recovered.stage, DurableDeploymentStage::ActivationUncertain);
        assert_eq!(recovered.identity_generation, 2);
        encoded[used - 1] ^= 1;
        assert!(matches!(
            DurableDeploymentReceipt::recover(&encoded[..used], object, &mut auth),
            Err(DeploymentJournalError::Durable(
                DurableError::AuthenticationFailed
            ))
        ));
    }

    #[test]
    fn authoritative_non_commit_does_not_advance_generation() {
        let mut receipt = DurableDeploymentReceipt::prepared(prepared(), 0);
        let mut auth = Auth([6; 32]);
        let mut store = Store {
            prepared: None,
            committed: None,
            uncertain: true,
            apply: false,
        };
        let mut transaction = receipt
            .prepare_persist(DurableObjectId([8; 16]), &mut auth, &mut store)
            .unwrap();
        assert_eq!(
            commit_or_resolve_deployment(&mut receipt, &mut transaction, &mut store),
            Ok(TransactionState::NotCommitted)
        );
        assert_eq!(receipt.record_generation, 0);
    }
}
