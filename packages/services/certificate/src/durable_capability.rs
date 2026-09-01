use crate::{
    CommittedStoreReceipt, DurableError, DurableNamespace, DurableObjectId, DurableRecord,
    DurableStateStore, MAX_DURABLE_RECORD_BYTES, PreparedStoreReceipt,
};

pub trait CertificateDurableStorageCapability {
    type Error;

    fn prepare_record(
        &mut self,
        record: &[u8],
        expected: PreparedStoreReceipt,
    ) -> Result<PreparedStoreReceipt, Self::Error>;

    fn commit_record(
        &mut self,
        prepared: PreparedStoreReceipt,
    ) -> Result<CommittedStoreReceipt, Self::Error>;

    fn authoritative_receipt(
        &mut self,
        namespace: DurableNamespace,
        object: DurableObjectId,
    ) -> Result<Option<CommittedStoreReceipt>, Self::Error>;

    fn read_authoritative_record(
        &mut self,
        namespace: DurableNamespace,
        object: DurableObjectId,
        output: &mut [u8],
    ) -> Result<Option<(CommittedStoreReceipt, usize)>, Self::Error>;
}

pub struct CapabilityDurableStateStore<B> {
    backend: B,
    buffer: [u8; MAX_DURABLE_RECORD_BYTES],
}

impl<B> CapabilityDurableStateStore<B> {
    pub const fn new(backend: B) -> Self {
        Self {
            backend,
            buffer: [0; MAX_DURABLE_RECORD_BYTES],
        }
    }

    pub fn into_backend(self) -> B {
        self.backend
    }
}

impl<B: CertificateDurableStorageCapability> CapabilityDurableStateStore<B> {
    pub fn load_authoritative(
        &mut self,
        namespace: DurableNamespace,
        object: DurableObjectId,
        output: &mut [u8],
    ) -> Result<Option<(CommittedStoreReceipt, usize)>, DurableError> {
        if output.len() > MAX_DURABLE_RECORD_BYTES {
            return Err(DurableError::PayloadTooLarge);
        }
        let result = self
            .backend
            .read_authoritative_record(namespace, object, output)
            .map_err(|_| DurableError::StoreUnavailable)?;
        match result {
            Some((receipt, length))
                if receipt.namespace == namespace
                    && receipt.object == object
                    && length >= 110
                    && length <= output.len() =>
            {
                Ok(Some((receipt, length)))
            }
            Some(_) => Err(DurableError::ReceiptMismatch),
            None => Ok(None),
        }
    }
}

impl<B: CertificateDurableStorageCapability> DurableStateStore for CapabilityDurableStateStore<B> {
    fn prepare(&mut self, record: &DurableRecord) -> Result<PreparedStoreReceipt, DurableError> {
        self.buffer.fill(0);
        let length = record.encode(&mut self.buffer)?;
        let expected = PreparedStoreReceipt {
            namespace: record.namespace,
            object: record.object,
            previous_generation: record.previous_generation,
            generation: record.generation,
            payload_digest: record.payload_digest,
            store_generation: record.generation,
        };
        let result = self
            .backend
            .prepare_record(&self.buffer[..length], expected)
            .map_err(|_| DurableError::StoreUnavailable);
        self.buffer.fill(0);
        let receipt = result?;
        if receipt.namespace != expected.namespace
            || receipt.object != expected.object
            || receipt.previous_generation != expected.previous_generation
            || receipt.generation != expected.generation
            || receipt.payload_digest != expected.payload_digest
            || receipt.store_generation < expected.store_generation
        {
            return Err(DurableError::ReceiptMismatch);
        }
        Ok(receipt)
    }

    fn commit(
        &mut self,
        prepared: PreparedStoreReceipt,
    ) -> Result<CommittedStoreReceipt, DurableError> {
        self.backend
            .commit_record(prepared)
            .map_err(|_| DurableError::CommitUncertain)
    }

    fn authoritative(
        &mut self,
        namespace: DurableNamespace,
        object: DurableObjectId,
    ) -> Result<Option<CommittedStoreReceipt>, DurableError> {
        self.backend
            .authoritative_receipt(namespace, object)
            .map_err(|_| DurableError::StoreUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DurableAuthenticator, DurableRecordKind, DurableTransaction};
    use mrml_crypto::hmac_sha256;

    struct Auth([u8; 32]);
    impl DurableAuthenticator for Auth {
        fn authenticate(&mut self, bytes: &[u8]) -> Result<[u8; 32], DurableError> {
            Ok(hmac_sha256(&self.0, &[bytes]))
        }
        fn verify(&mut self, bytes: &[u8], tag: &[u8; 32]) -> Result<bool, DurableError> {
            Ok(hmac_sha256(&self.0, &[bytes]) == *tag)
        }
    }

    struct Backend {
        bytes: [u8; MAX_DURABLE_RECORD_BYTES],
        length: usize,
        prepared: Option<PreparedStoreReceipt>,
        committed: Option<CommittedStoreReceipt>,
        substitute: bool,
    }
    impl CertificateDurableStorageCapability for Backend {
        type Error = ();
        fn prepare_record(
            &mut self,
            record: &[u8],
            mut expected: PreparedStoreReceipt,
        ) -> Result<PreparedStoreReceipt, Self::Error> {
            self.bytes[..record.len()].copy_from_slice(record);
            self.length = record.len();
            if self.substitute {
                expected.object.0[0] ^= 1;
            }
            self.prepared = Some(expected);
            Ok(expected)
        }
        fn commit_record(
            &mut self,
            prepared: PreparedStoreReceipt,
        ) -> Result<CommittedStoreReceipt, Self::Error> {
            if self.prepared != Some(prepared) {
                return Err(());
            }
            let receipt = CommittedStoreReceipt {
                namespace: prepared.namespace,
                object: prepared.object,
                generation: prepared.generation,
                payload_digest: prepared.payload_digest,
                store_generation: prepared.store_generation,
            };
            self.committed = Some(receipt);
            Ok(receipt)
        }
        fn authoritative_receipt(
            &mut self,
            namespace: DurableNamespace,
            object: DurableObjectId,
        ) -> Result<Option<CommittedStoreReceipt>, Self::Error> {
            Ok(self
                .committed
                .filter(|receipt| receipt.namespace == namespace && receipt.object == object))
        }
        fn read_authoritative_record(
            &mut self,
            namespace: DurableNamespace,
            object: DurableObjectId,
            output: &mut [u8],
        ) -> Result<Option<(CommittedStoreReceipt, usize)>, Self::Error> {
            let Some(receipt) = self
                .committed
                .filter(|receipt| receipt.namespace == namespace && receipt.object == object)
            else {
                return Ok(None);
            };
            if output.len() < self.length {
                return Err(());
            }
            output[..self.length].copy_from_slice(&self.bytes[..self.length]);
            Ok(Some((receipt, self.length)))
        }
    }

    fn backend(substitute: bool) -> Backend {
        Backend {
            bytes: [0; MAX_DURABLE_RECORD_BYTES],
            length: 0,
            prepared: None,
            committed: None,
            substitute,
        }
    }

    #[test]
    fn capability_store_round_trips_authenticated_generation_without_allocation() {
        let object = DurableObjectId([7; 16]);
        let mut auth = Auth([9; 32]);
        let record = DurableRecord::prepare(
            DurableNamespace::PublicState,
            DurableRecordKind::Deployment,
            object,
            0,
            b"active",
            &mut auth,
        )
        .unwrap();
        let mut store = CapabilityDurableStateStore::new(backend(false));
        let mut transaction = DurableTransaction::prepare(&record, &mut store).unwrap();
        transaction.commit(&mut store).unwrap();
        let mut encoded = [0u8; MAX_DURABLE_RECORD_BYTES];
        let (_, length) = store
            .load_authoritative(DurableNamespace::PublicState, object, &mut encoded)
            .unwrap()
            .unwrap();
        let recovered = DurableRecord::decode(&encoded[..length], &mut auth).unwrap();
        assert_eq!(recovered.payload(), b"active");
    }

    #[test]
    fn substituted_capability_receipt_fails_before_commit() {
        let mut auth = Auth([9; 32]);
        let record = DurableRecord::prepare(
            DurableNamespace::PublicState,
            DurableRecordKind::Deployment,
            DurableObjectId([7; 16]),
            0,
            b"active",
            &mut auth,
        )
        .unwrap();
        let mut store = CapabilityDurableStateStore::new(backend(true));
        assert!(matches!(
            DurableTransaction::prepare(&record, &mut store),
            Err(DurableError::ReceiptMismatch)
        ));
        assert!(
            store
                .authoritative(DurableNamespace::PublicState, DurableObjectId([7; 16]))
                .unwrap()
                .is_none()
        );
    }
}
