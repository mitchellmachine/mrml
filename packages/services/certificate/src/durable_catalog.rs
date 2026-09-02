use crate::{
    CapabilityDurableStateStore, CertificateDurableStorageCapability, DurableAuthenticator,
    DurableError, DurableNamespace, DurableObjectId, DurableRecord, MAX_DURABLE_RECORD_BYTES,
};

pub const MAX_DURABLE_CATALOG_RECORDS: usize = 64;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DurableCatalogEntry {
    pub namespace: DurableNamespace,
    pub object: DurableObjectId,
    pub generation: u64,
    pub payload_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableCatalogError {
    Empty,
    TooManyRecords,
    NonCanonicalOrder,
    InvalidBinding,
    MissingRecord,
    Durable(DurableError),
    VisitorRejected,
}

impl From<DurableError> for DurableCatalogError {
    fn from(value: DurableError) -> Self {
        Self::Durable(value)
    }
}

/// Reloads only the exact objects selected by an already-authorized catalog
/// capability. Entries identify expected state; neither an object id nor this
/// manifest grants storage or lifecycle authority.
pub fn reconstruct_durable_catalog<B, A, F>(
    entries: &[DurableCatalogEntry],
    store: &mut CapabilityDurableStateStore<B>,
    authenticator: &mut A,
    mut visit: F,
) -> Result<usize, DurableCatalogError>
where
    B: CertificateDurableStorageCapability,
    A: DurableAuthenticator,
    F: FnMut(&DurableRecord) -> Result<(), ()>,
{
    if entries.is_empty() {
        return Err(DurableCatalogError::Empty);
    }
    if entries.len() > MAX_DURABLE_CATALOG_RECORDS {
        return Err(DurableCatalogError::TooManyRecords);
    }
    for (index, entry) in entries.iter().enumerate() {
        if entry.generation == 0 || entry.payload_digest == [0; 32] {
            return Err(DurableCatalogError::InvalidBinding);
        }
        if let Some(previous) = index.checked_sub(1).and_then(|i| entries.get(i)) {
            let previous_key = catalog_key(previous);
            let current_key = catalog_key(entry);
            if previous_key >= current_key {
                return Err(DurableCatalogError::NonCanonicalOrder);
            }
        }
    }

    let mut encoded = [0u8; MAX_DURABLE_RECORD_BYTES];
    for entry in entries {
        encoded.fill(0);
        let Some((receipt, written)) =
            store.load_authoritative(entry.namespace, entry.object, &mut encoded)?
        else {
            return Err(DurableCatalogError::MissingRecord);
        };
        if receipt.generation != entry.generation
            || receipt.payload_digest != entry.payload_digest
            || receipt.store_generation < entry.generation
        {
            encoded.fill(0);
            return Err(DurableCatalogError::InvalidBinding);
        }
        let record = DurableRecord::decode(&encoded[..written], authenticator)?;
        encoded.fill(0);
        if record.namespace != entry.namespace
            || record.object != entry.object
            || record.generation != entry.generation
            || record.payload_digest != entry.payload_digest
        {
            return Err(DurableCatalogError::InvalidBinding);
        }
        visit(&record).map_err(|()| DurableCatalogError::VisitorRejected)?;
    }
    Ok(entries.len())
}

fn catalog_key(entry: &DurableCatalogEntry) -> ([u8; 1], [u8; 16]) {
    ([entry.namespace as u8], entry.object.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::{CommittedStoreReceipt, DurableRecordKind, PreparedStoreReceipt};
    use mrml_crypto::{hmac_sha256, Sha256};
    use std::vec::Vec;

    struct Auth([u8; 32]);
    impl DurableAuthenticator for Auth {
        fn authenticate(&mut self, value: &[u8]) -> Result<[u8; 32], DurableError> {
            Ok(hmac_sha256(&self.0, &[value]))
        }
        fn verify(&mut self, value: &[u8], tag: &[u8; 32]) -> Result<bool, DurableError> {
            Ok(self.authenticate(value)? == *tag)
        }
    }

    struct Backend {
        records: Vec<(
            DurableNamespace,
            DurableObjectId,
            Vec<u8>,
            CommittedStoreReceipt,
        )>,
    }
    impl CertificateDurableStorageCapability for Backend {
        type Error = ();
        fn prepare_record(
            &mut self,
            _: &[u8],
            _: PreparedStoreReceipt,
        ) -> Result<PreparedStoreReceipt, Self::Error> {
            Err(())
        }
        fn commit_record(
            &mut self,
            _: PreparedStoreReceipt,
        ) -> Result<CommittedStoreReceipt, Self::Error> {
            Err(())
        }
        fn authoritative_receipt(
            &mut self,
            _: DurableNamespace,
            _: DurableObjectId,
        ) -> Result<Option<CommittedStoreReceipt>, Self::Error> {
            Err(())
        }
        fn read_authoritative_record(
            &mut self,
            namespace: DurableNamespace,
            object: DurableObjectId,
            output: &mut [u8],
        ) -> Result<Option<(CommittedStoreReceipt, usize)>, Self::Error> {
            let Some((_, _, encoded, receipt)) = self
                .records
                .iter()
                .find(|(n, o, _, _)| *n == namespace && *o == object)
            else {
                return Ok(None);
            };
            output[..encoded.len()].copy_from_slice(encoded);
            Ok(Some((*receipt, encoded.len())))
        }
    }

    fn fixture() -> (
        CapabilityDurableStateStore<Backend>,
        Auth,
        [DurableCatalogEntry; 2],
    ) {
        let mut auth = Auth([0x51; 32]);
        let records = [
            DurableRecord::prepare(
                DurableNamespace::PublicState,
                DurableRecordKind::Account,
                DurableObjectId([1; 16]),
                0,
                b"account",
                &mut auth,
            )
            .unwrap(),
            DurableRecord::prepare(
                DurableNamespace::Audit,
                DurableRecordKind::AuditEvent,
                DurableObjectId([2; 16]),
                0,
                b"audit",
                &mut auth,
            )
            .unwrap(),
        ];
        let entries = records.each_ref().map(|record| DurableCatalogEntry {
            namespace: record.namespace,
            object: record.object,
            generation: record.generation,
            payload_digest: record.payload_digest,
        });
        let mut stored = Vec::new();
        for record in &records {
            let mut encoded = [0u8; MAX_DURABLE_RECORD_BYTES];
            let written = record.encode(&mut encoded).unwrap();
            stored.push((
                record.namespace,
                record.object,
                encoded[..written].to_vec(),
                CommittedStoreReceipt {
                    namespace: record.namespace,
                    object: record.object,
                    generation: record.generation,
                    payload_digest: record.payload_digest,
                    store_generation: record.generation,
                },
            ));
        }
        (
            CapabilityDurableStateStore::new(Backend { records: stored }),
            auth,
            entries,
        )
    }

    #[test]
    fn exact_owner_catalog_reconstructs_authenticated_records_in_order() {
        let (mut store, mut auth, entries) = fixture();
        let mut observed = Vec::new();
        assert_eq!(
            reconstruct_durable_catalog(&entries, &mut store, &mut auth, |record| {
                observed.push((
                    record.namespace as u8,
                    record.object.0,
                    Sha256::digest(record.payload()),
                ));
                Ok(())
            }),
            Ok(2)
        );
        assert_eq!(observed.len(), 2);
    }

    #[test]
    fn missing_stale_reordered_and_substituted_catalogs_fail_closed() {
        let (mut store, mut auth, mut entries) = fixture();
        entries[0].generation += 1;
        assert_eq!(
            reconstruct_durable_catalog(&entries, &mut store, &mut auth, |_| Ok(())),
            Err(DurableCatalogError::InvalidBinding)
        );
        let (mut store, mut auth, mut entries) = fixture();
        entries.swap(0, 1);
        assert_eq!(
            reconstruct_durable_catalog(&entries, &mut store, &mut auth, |_| Ok(())),
            Err(DurableCatalogError::NonCanonicalOrder)
        );
        let (mut store, mut auth, mut entries) = fixture();
        entries[0].object = DurableObjectId([9; 16]);
        assert_eq!(
            reconstruct_durable_catalog(&entries, &mut store, &mut auth, |_| Ok(())),
            Err(DurableCatalogError::MissingRecord)
        );
    }
}
