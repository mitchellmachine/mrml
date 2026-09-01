use mrml_crypto::Sha256;

pub const MAX_DURABLE_PAYLOAD: usize = 4096;
pub const MAX_DURABLE_RECORD_BYTES: usize = MAX_DURABLE_PAYLOAD + 110;
pub const DURABLE_RECORD_VERSION: u16 = 1;
const DURABLE_MAGIC: &[u8; 8] = b"MRMLCERT";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableError {
    PayloadTooLarge,
    InvalidGeneration,
    InvalidNamespace,
    AuthenticationFailed,
    Malformed,
    StoreUnavailable,
    ReceiptMismatch,
    CommitUncertain,
    ResolutionMismatch,
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DurableNamespace {
    PublicState = 1,
    AccountSecretHandles = 2,
    CertificateSecretHandles = 3,
    Audit = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DurableRecordKind {
    Directory = 1,
    TermsApproval = 2,
    Account = 3,
    Order = 4,
    Challenge = 5,
    Certificate = 6,
    AriSchedule = 7,
    Revocation = 8,
    Deployment = 9,
    AccountKeyHandle = 10,
    CertificateKeyHandle = 11,
    AuditEvent = 12,
    AccountSealedKey = 13,
    CertificateSealedKey = 14,
    RenewalTransaction = 15,
    AcmeOperation = 16,
    AcmeResource = 17,
    DnsPublication = 18,
}

impl DurableRecordKind {
    const fn required_namespace(self) -> DurableNamespace {
        match self {
            Self::AccountKeyHandle | Self::AccountSealedKey => {
                DurableNamespace::AccountSecretHandles
            }
            Self::CertificateKeyHandle | Self::CertificateSealedKey => {
                DurableNamespace::CertificateSecretHandles
            }
            Self::AuditEvent => DurableNamespace::Audit,
            _ => DurableNamespace::PublicState,
        }
    }
    fn parse(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Directory,
            2 => Self::TermsApproval,
            3 => Self::Account,
            4 => Self::Order,
            5 => Self::Challenge,
            6 => Self::Certificate,
            7 => Self::AriSchedule,
            8 => Self::Revocation,
            9 => Self::Deployment,
            10 => Self::AccountKeyHandle,
            11 => Self::CertificateKeyHandle,
            12 => Self::AuditEvent,
            13 => Self::AccountSealedKey,
            14 => Self::CertificateSealedKey,
            15 => Self::RenewalTransaction,
            16 => Self::AcmeOperation,
            17 => Self::AcmeResource,
            18 => Self::DnsPublication,
            _ => return None,
        })
    }
}

impl DurableNamespace {
    fn parse(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::PublicState,
            2 => Self::AccountSecretHandles,
            3 => Self::CertificateSecretHandles,
            4 => Self::Audit,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DurableObjectId(pub [u8; 16]);

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SecretHandle {
    pub identity: [u8; 32],
    pub provider_generation: u64,
}

pub struct DurableRecord {
    pub namespace: DurableNamespace,
    pub kind: DurableRecordKind,
    pub object: DurableObjectId,
    pub previous_generation: u64,
    pub generation: u64,
    payload: [u8; MAX_DURABLE_PAYLOAD],
    payload_len: u16,
    pub payload_digest: [u8; 32],
    pub authentication_tag: [u8; 32],
}

impl DurableRecord {
    pub fn prepare(
        namespace: DurableNamespace,
        kind: DurableRecordKind,
        object: DurableObjectId,
        previous_generation: u64,
        payload: &[u8],
        authenticator: &mut impl DurableAuthenticator,
    ) -> Result<Self, DurableError> {
        if namespace != kind.required_namespace() {
            return Err(DurableError::InvalidNamespace);
        }
        if payload.len() > MAX_DURABLE_PAYLOAD {
            return Err(DurableError::PayloadTooLarge);
        }
        let generation = previous_generation
            .checked_add(1)
            .ok_or(DurableError::ArithmeticOverflow)?;
        let mut stored = [0; MAX_DURABLE_PAYLOAD];
        stored[..payload.len()].copy_from_slice(payload);
        let mut record = Self {
            namespace,
            kind,
            object,
            previous_generation,
            generation,
            payload: stored,
            payload_len: payload.len() as u16,
            payload_digest: Sha256::digest(payload),
            authentication_tag: [0; 32],
        };
        let mut encoded = [0u8; MAX_DURABLE_PAYLOAD + 128];
        let len = record.encode_authenticated_portion(&mut encoded)?;
        record.authentication_tag = authenticator.authenticate(&encoded[..len])?;
        Ok(record)
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload[..usize::from(self.payload_len)]
    }

    pub fn verify(
        &self,
        authenticator: &mut impl DurableAuthenticator,
    ) -> Result<(), DurableError> {
        if self.namespace != self.kind.required_namespace()
            || self.generation != self.previous_generation.checked_add(1).unwrap_or(0)
            || self.payload_digest != Sha256::digest(self.payload())
        {
            return Err(DurableError::Malformed);
        }
        let mut encoded = [0u8; MAX_DURABLE_PAYLOAD + 128];
        let len = self.encode_authenticated_portion(&mut encoded)?;
        if authenticator.verify(&encoded[..len], &self.authentication_tag)? {
            Ok(())
        } else {
            Err(DurableError::AuthenticationFailed)
        }
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, DurableError> {
        let authenticated_len = self.encode_authenticated_portion(output)?;
        let end = authenticated_len
            .checked_add(32)
            .ok_or(DurableError::PayloadTooLarge)?;
        output
            .get_mut(authenticated_len..end)
            .ok_or(DurableError::PayloadTooLarge)?
            .copy_from_slice(&self.authentication_tag);
        Ok(end)
    }

    pub fn decode(
        input: &[u8],
        authenticator: &mut impl DurableAuthenticator,
    ) -> Result<Self, DurableError> {
        const HEADER: usize = 78;
        if input.len() < HEADER + 32 || input.get(..8) != Some(DURABLE_MAGIC) {
            return Err(DurableError::Malformed);
        }
        if u16::from_be_bytes([input[8], input[9]]) != DURABLE_RECORD_VERSION {
            return Err(DurableError::Malformed);
        }
        let namespace = DurableNamespace::parse(input[10]).ok_or(DurableError::Malformed)?;
        let kind = DurableRecordKind::parse(input[11]).ok_or(DurableError::Malformed)?;
        let mut object = [0; 16];
        object.copy_from_slice(&input[12..28]);
        let previous_generation = u64::from_be_bytes(
            input[28..36]
                .try_into()
                .map_err(|_| DurableError::Malformed)?,
        );
        let generation = u64::from_be_bytes(
            input[36..44]
                .try_into()
                .map_err(|_| DurableError::Malformed)?,
        );
        let payload_len = usize::from(u16::from_be_bytes([input[44], input[45]]));
        if payload_len > MAX_DURABLE_PAYLOAD || input.len() != HEADER + payload_len + 32 {
            return Err(DurableError::Malformed);
        }
        let mut payload_digest = [0; 32];
        payload_digest.copy_from_slice(&input[46..78]);
        let mut payload = [0; MAX_DURABLE_PAYLOAD];
        payload[..payload_len].copy_from_slice(&input[HEADER..HEADER + payload_len]);
        let mut authentication_tag = [0; 32];
        authentication_tag.copy_from_slice(&input[HEADER + payload_len..]);
        let record = Self {
            namespace,
            kind,
            object: DurableObjectId(object),
            previous_generation,
            generation,
            payload,
            payload_len: payload_len as u16,
            payload_digest,
            authentication_tag,
        };
        record.verify(authenticator)?;
        Ok(record)
    }

    fn encode_authenticated_portion(&self, output: &mut [u8]) -> Result<usize, DurableError> {
        let required = 8 + 2 + 1 + 1 + 16 + 8 + 8 + 2 + 32 + self.payload().len();
        if output.len() < required {
            return Err(DurableError::PayloadTooLarge);
        }
        let mut cursor = 0usize;
        for value in [
            DURABLE_MAGIC.as_slice(),
            &DURABLE_RECORD_VERSION.to_be_bytes(),
            &[self.namespace as u8],
            &[self.kind as u8],
            &self.object.0,
            &self.previous_generation.to_be_bytes(),
            &self.generation.to_be_bytes(),
            &self.payload_len.to_be_bytes(),
            &self.payload_digest,
            self.payload(),
        ] {
            output[cursor..cursor + value.len()].copy_from_slice(value);
            cursor += value.len();
        }
        Ok(cursor)
    }
}

pub trait DurableAuthenticator {
    fn authenticate(&mut self, record: &[u8]) -> Result<[u8; 32], DurableError>;
    fn verify(&mut self, record: &[u8], tag: &[u8; 32]) -> Result<bool, DurableError>;
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PreparedStoreReceipt {
    pub namespace: DurableNamespace,
    pub object: DurableObjectId,
    pub previous_generation: u64,
    pub generation: u64,
    pub payload_digest: [u8; 32],
    pub store_generation: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommittedStoreReceipt {
    pub namespace: DurableNamespace,
    pub object: DurableObjectId,
    pub generation: u64,
    pub payload_digest: [u8; 32],
    pub store_generation: u64,
}

pub trait DurableStateStore {
    fn prepare(&mut self, record: &DurableRecord) -> Result<PreparedStoreReceipt, DurableError>;
    fn commit(
        &mut self,
        prepared: PreparedStoreReceipt,
    ) -> Result<CommittedStoreReceipt, DurableError>;
    fn authoritative(
        &mut self,
        namespace: DurableNamespace,
        object: DurableObjectId,
    ) -> Result<Option<CommittedStoreReceipt>, DurableError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionState {
    Prepared,
    CommitUncertain,
    Committed,
    NotCommitted,
}

pub struct DurableTransaction {
    prepared: PreparedStoreReceipt,
    state: TransactionState,
}

impl DurableTransaction {
    pub fn prepare(
        record: &DurableRecord,
        store: &mut impl DurableStateStore,
    ) -> Result<Self, DurableError> {
        let prepared = store.prepare(record)?;
        if prepared.namespace != record.namespace
            || prepared.object != record.object
            || prepared.previous_generation != record.previous_generation
            || prepared.generation != record.generation
            || prepared.payload_digest != record.payload_digest
        {
            return Err(DurableError::ReceiptMismatch);
        }
        Ok(Self {
            prepared,
            state: TransactionState::Prepared,
        })
    }

    pub fn commit(
        &mut self,
        store: &mut impl DurableStateStore,
    ) -> Result<CommittedStoreReceipt, DurableError> {
        if self.state != TransactionState::Prepared {
            return Err(DurableError::InvalidGeneration);
        }
        match store.commit(self.prepared) {
            Ok(receipt) => {
                self.validate_committed(receipt)?;
                self.state = TransactionState::Committed;
                Ok(receipt)
            }
            Err(DurableError::CommitUncertain) => {
                self.state = TransactionState::CommitUncertain;
                Err(DurableError::CommitUncertain)
            }
            Err(error) => Err(error),
        }
    }

    pub fn resolve(
        &mut self,
        store: &mut impl DurableStateStore,
    ) -> Result<TransactionState, DurableError> {
        if self.state != TransactionState::CommitUncertain {
            return Err(DurableError::InvalidGeneration);
        }
        match store.authoritative(self.prepared.namespace, self.prepared.object)? {
            Some(receipt) if self.validate_committed(receipt).is_ok() => {
                self.state = TransactionState::Committed;
            }
            Some(receipt) if receipt.generation == self.prepared.previous_generation => {
                self.state = TransactionState::NotCommitted;
            }
            None if self.prepared.previous_generation == 0 => {
                self.state = TransactionState::NotCommitted;
            }
            _ => return Err(DurableError::ResolutionMismatch),
        }
        Ok(self.state)
    }

    fn validate_committed(&self, receipt: CommittedStoreReceipt) -> Result<(), DurableError> {
        if receipt.namespace == self.prepared.namespace
            && receipt.object == self.prepared.object
            && receipt.generation == self.prepared.generation
            && receipt.payload_digest == self.prepared.payload_digest
            && receipt.store_generation >= self.prepared.store_generation
        {
            Ok(())
        } else {
            Err(DurableError::ReceiptMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_crypto::hmac_sha256;
    struct Auth([u8; 32]);
    impl DurableAuthenticator for Auth {
        fn authenticate(&mut self, r: &[u8]) -> Result<[u8; 32], DurableError> {
            Ok(hmac_sha256(&self.0, &[r]))
        }
        fn verify(&mut self, r: &[u8], t: &[u8; 32]) -> Result<bool, DurableError> {
            Ok(hmac_sha256(&self.0, &[r]) == *t)
        }
    }
    struct Store {
        prepared: Option<PreparedStoreReceipt>,
        committed: Option<CommittedStoreReceipt>,
        uncertain: bool,
        apply: bool,
    }
    impl DurableStateStore for Store {
        fn prepare(&mut self, r: &DurableRecord) -> Result<PreparedStoreReceipt, DurableError> {
            let p = PreparedStoreReceipt {
                namespace: r.namespace,
                object: r.object,
                previous_generation: r.previous_generation,
                generation: r.generation,
                payload_digest: r.payload_digest,
                store_generation: 7,
            };
            self.prepared = Some(p);
            Ok(p)
        }
        fn commit(
            &mut self,
            p: PreparedStoreReceipt,
        ) -> Result<CommittedStoreReceipt, DurableError> {
            let c = CommittedStoreReceipt {
                namespace: p.namespace,
                object: p.object,
                generation: p.generation,
                payload_digest: p.payload_digest,
                store_generation: 8,
            };
            if self.apply {
                self.committed = Some(c);
            }
            if self.uncertain {
                Err(DurableError::CommitUncertain)
            } else if self.apply {
                Ok(c)
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
    #[test]
    fn authenticates_namespace_and_resolves_uncertain_commit() {
        let mut auth = Auth([3; 32]);
        let record = DurableRecord::prepare(
            DurableNamespace::PublicState,
            DurableRecordKind::Deployment,
            DurableObjectId([4; 16]),
            0,
            b"candidate",
            &mut auth,
        )
        .unwrap();
        record.verify(&mut auth).unwrap();
        let mut store = Store {
            prepared: None,
            committed: None,
            uncertain: true,
            apply: true,
        };
        let mut tx = DurableTransaction::prepare(&record, &mut store).unwrap();
        assert!(matches!(
            tx.commit(&mut store),
            Err(DurableError::CommitUncertain)
        ));
        assert_eq!(tx.resolve(&mut store), Ok(TransactionState::Committed));
    }
    #[test]
    fn secret_handle_kinds_cannot_enter_public_namespace() {
        let mut auth = Auth([1; 32]);
        assert!(matches!(
            DurableRecord::prepare(
                DurableNamespace::PublicState,
                DurableRecordKind::CertificateKeyHandle,
                DurableObjectId([0; 16]),
                0,
                b"handle",
                &mut auth
            ),
            Err(DurableError::InvalidNamespace)
        ));
    }
    #[test]
    fn canonical_record_round_trips_and_rejects_mutation_or_trailing_data() {
        let mut auth = Auth([8; 32]);
        let record = DurableRecord::prepare(
            DurableNamespace::PublicState,
            DurableRecordKind::Order,
            DurableObjectId([2; 16]),
            9,
            b"state",
            &mut auth,
        )
        .unwrap();
        let mut encoded = [0u8; MAX_DURABLE_RECORD_BYTES];
        let len = record.encode(&mut encoded).unwrap();
        let decoded = DurableRecord::decode(&encoded[..len], &mut auth).unwrap();
        assert_eq!(decoded.payload(), b"state");
        encoded[len - 1] ^= 1;
        assert_eq!(
            DurableRecord::decode(&encoded[..len], &mut auth).err(),
            Some(DurableError::AuthenticationFailed)
        );
        encoded[len - 1] ^= 1;
        assert_eq!(
            DurableRecord::decode(&encoded[..len + 1], &mut auth).err(),
            Some(DurableError::Malformed)
        );
    }
}
