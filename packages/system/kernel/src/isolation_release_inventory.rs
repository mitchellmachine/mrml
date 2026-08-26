use mrml_package_format::{
    ActivatedSystemGeneration, ActivatedSystemRelease, RuntimeInventoryView, RuntimeIsolationClass,
    SystemReleaseError, parse_system_release,
};

use crate::{
    HostSubstrateReason, ObjectId, TotalMicrovmClass, TotalMicrovmInventoryEntry,
    TotalMicrovmRuntimeError, isolation_total_runtime::TotalMicrovmInventory,
};

/// Policy-selected package-to-domain assignment for a complete authenticated
/// release. The assignment carries no capability and deliberately does not
/// restate package-controlled class or reason metadata. Host-substrate packages
/// additionally require one typed architectural reason because the release's
/// descriptive string cannot select a kernel enum value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeDomainAssignment<'a> {
    package_id: &'a str,
    domain: ObjectId,
    host_substrate_reason: Option<HostSubstrateReason>,
}

impl<'a> RuntimeDomainAssignment<'a> {
    pub const fn new(package_id: &'a str, domain: ObjectId) -> Result<Self, ReleaseInventoryError> {
        if package_id.is_empty() || domain.0 == 0 {
            return Err(ReleaseInventoryError::InvalidBinding);
        }
        Ok(Self {
            package_id,
            domain,
            host_substrate_reason: None,
        })
    }

    pub const fn host_substrate(
        package_id: &'a str,
        domain: ObjectId,
        reason: HostSubstrateReason,
    ) -> Result<Self, ReleaseInventoryError> {
        if package_id.is_empty() || domain.0 == 0 {
            return Err(ReleaseInventoryError::InvalidBinding);
        }
        Ok(Self {
            package_id,
            domain,
            host_substrate_reason: Some(reason),
        })
    }

    pub const fn package_id(self) -> &'a str {
        self.package_id
    }

    pub const fn domain(self) -> ObjectId {
        self.domain
    }

    pub const fn host_substrate_reason(self) -> Option<HostSubstrateReason> {
        self.host_substrate_reason
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeDomainBinding<'a> {
    package_id: &'a str,
    domain: ObjectId,
    class: TotalMicrovmClass,
    reason: &'a str,
}

impl<'a> RuntimeDomainBinding<'a> {
    pub const fn new(
        package_id: &'a str,
        domain: ObjectId,
        class: TotalMicrovmClass,
        reason: &'a str,
    ) -> Result<Self, ReleaseInventoryError> {
        if package_id.is_empty() || domain.0 == 0 {
            return Err(ReleaseInventoryError::InvalidBinding);
        }
        Ok(Self {
            package_id,
            domain,
            class,
            reason,
        })
    }

    pub const fn package_id(self) -> &'a str {
        self.package_id
    }

    pub const fn domain(self) -> ObjectId {
        self.domain
    }

    pub const fn class(self) -> TotalMicrovmClass {
        self.class
    }

    pub const fn reason(self) -> &'a str {
        self.reason
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseInventoryError {
    Release(SystemReleaseError),
    SignerMismatch,
    MissingRuntimeInventory,
    InvalidBinding,
    BindingCount,
    DuplicateBinding,
    MissingBinding,
    ClassificationMismatch,
    ReasonMismatch,
    HostSubstrateReasonMismatch,
    ActivatedGenerationMismatch,
    Inventory(TotalMicrovmRuntimeError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeDomainPolicyAssignmentError<E> {
    Inventory(ReleaseInventoryError),
    Decision(E),
}

/// Fixed-capacity control-plane transaction for assigning every authenticated
/// installed release member to one policy-selected runtime domain. The plan
/// retains the exact activated release identity and cannot be sealed with an
/// unknown, duplicate, omitted, or excess package. Domain identity still
/// carries no authority; normal launch admission must authorize each route.
pub struct RuntimeDomainAssignmentPlan<'a, const N: usize> {
    release_bytes: &'a [u8],
    expected_key_id: [u8; 64],
    active: ActivatedSystemRelease,
    runtime: RuntimeInventoryView<'a>,
    policy_generation: u64,
    assignments: [RuntimeDomainAssignment<'a>; N],
    count: usize,
}

impl<'a, const N: usize> RuntimeDomainAssignmentPlan<'a, N> {
    pub fn new(
        release_bytes: &'a [u8],
        expected_key_id: &[u8; 64],
        active: ActivatedSystemRelease,
        policy_generation: u64,
    ) -> Result<Self, ReleaseInventoryError> {
        let release =
            parse_system_release(release_bytes).map_err(ReleaseInventoryError::Release)?;
        let runtime = release
            .runtime_inventory()
            .ok_or(ReleaseInventoryError::MissingRuntimeInventory)?;
        if *expected_key_id == [0; 64] || release.key_id() != *expected_key_id {
            return Err(ReleaseInventoryError::SignerMismatch);
        }
        if runtime.package_count() as usize > N || runtime.package_count() == 0 {
            return Err(ReleaseInventoryError::BindingCount);
        }
        let generation = active.generation();
        if generation.generation() != release.generation().generation()
            || generation.generation_digest() != &release.generation().digest()
            || generation.interface_catalog_digest() != &release.interface_catalog().digest()
            || active.release() != release.identity()
        {
            return Err(ReleaseInventoryError::ActivatedGenerationMismatch);
        }
        let placeholder = RuntimeDomainAssignment {
            package_id: "",
            domain: ObjectId(0),
            host_substrate_reason: None,
        };
        Ok(Self {
            release_bytes,
            expected_key_id: *expected_key_id,
            active,
            runtime,
            policy_generation,
            assignments: [placeholder; N],
            count: 0,
        })
    }

    pub const fn expected_len(&self) -> usize {
        self.runtime.package_count() as usize
    }

    pub const fn assigned_len(&self) -> usize {
        self.count
    }

    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    pub fn packages(&self) -> impl Iterator<Item = &'a str> + '_ {
        self.runtime.records().map(|record| record.package_id)
    }

    /// Enumerates the exact authenticated runtime records through one
    /// caller-supplied policy decision. The callback may select only the
    /// domain and typed host-substrate reason for the record currently being
    /// visited; substituting an identity, omitting a record, or returning an
    /// error leaves the plan unsealed. This transaction carries no capability
    /// and does not itself authorize any returned domain.
    pub fn assign_from_policy<F>(&mut self, mut decide: F) -> Result<(), ReleaseInventoryError>
    where
        F: FnMut(
            mrml_package_format::RuntimeInventoryRecord<'a>,
        ) -> Result<RuntimeDomainAssignment<'a>, ReleaseInventoryError>,
    {
        if self.count != 0 {
            return Err(ReleaseInventoryError::BindingCount);
        }
        let placeholder = RuntimeDomainAssignment {
            package_id: "",
            domain: ObjectId(0),
            host_substrate_reason: None,
        };
        let mut assignments = [placeholder; N];
        let mut count = 0;
        let runtime = self.runtime;
        for record in runtime.records() {
            let assignment = decide(record)?;
            if assignment.package_id != record.package_id {
                return Err(ReleaseInventoryError::MissingBinding);
            }
            if count >= self.expected_len() || count >= N {
                return Err(ReleaseInventoryError::BindingCount);
            }
            if assignments[..count]
                .iter()
                .any(|present| present.package_id == assignment.package_id)
            {
                return Err(ReleaseInventoryError::DuplicateBinding);
            }
            assignments[count] = assignment;
            count += 1;
        }
        if count != self.expected_len() {
            return Err(ReleaseInventoryError::BindingCount);
        }
        self.assignments = assignments;
        self.count = count;
        Ok(())
    }

    /// Generic atomic policy adapter. Decision failure publishes no partial
    /// assignment, allowing configuration-backed policy reads to fail closed
    /// without translating their error into release metadata.
    pub fn assign_from_policy_transaction<F, E>(
        &mut self,
        mut decide: F,
    ) -> Result<(), RuntimeDomainPolicyAssignmentError<E>>
    where
        F: FnMut(
            mrml_package_format::RuntimeInventoryRecord<'a>,
        ) -> Result<RuntimeDomainAssignment<'a>, E>,
    {
        if self.count != 0 {
            return Err(RuntimeDomainPolicyAssignmentError::Inventory(
                ReleaseInventoryError::BindingCount,
            ));
        }
        let placeholder = RuntimeDomainAssignment {
            package_id: "",
            domain: ObjectId(0),
            host_substrate_reason: None,
        };
        let mut assignments = [placeholder; N];
        let mut count = 0;
        let runtime = self.runtime;
        for record in runtime.records() {
            let assignment =
                decide(record).map_err(RuntimeDomainPolicyAssignmentError::Decision)?;
            if assignment.package_id != record.package_id {
                return Err(RuntimeDomainPolicyAssignmentError::Inventory(
                    ReleaseInventoryError::MissingBinding,
                ));
            }
            if count >= self.expected_len() || count >= N {
                return Err(RuntimeDomainPolicyAssignmentError::Inventory(
                    ReleaseInventoryError::BindingCount,
                ));
            }
            if assignments[..count]
                .iter()
                .any(|present| present.package_id == assignment.package_id)
            {
                return Err(RuntimeDomainPolicyAssignmentError::Inventory(
                    ReleaseInventoryError::DuplicateBinding,
                ));
            }
            assignments[count] = assignment;
            count += 1;
        }
        if count != self.expected_len() {
            return Err(RuntimeDomainPolicyAssignmentError::Inventory(
                ReleaseInventoryError::BindingCount,
            ));
        }
        self.assignments = assignments;
        self.count = count;
        Ok(())
    }

    pub fn assign(
        &mut self,
        package_id: &'a str,
        domain: ObjectId,
    ) -> Result<(), ReleaseInventoryError> {
        self.assign_record(RuntimeDomainAssignment::new(package_id, domain)?)
    }

    pub fn assign_host_substrate(
        &mut self,
        package_id: &'a str,
        domain: ObjectId,
        reason: HostSubstrateReason,
    ) -> Result<(), ReleaseInventoryError> {
        self.assign_record(RuntimeDomainAssignment::host_substrate(
            package_id, domain, reason,
        )?)
    }

    fn assign_record(
        &mut self,
        assignment: RuntimeDomainAssignment<'a>,
    ) -> Result<(), ReleaseInventoryError> {
        if self.count >= self.expected_len() || self.count >= N {
            return Err(ReleaseInventoryError::BindingCount);
        }
        if !self
            .runtime
            .records()
            .any(|record| record.package_id == assignment.package_id)
        {
            return Err(ReleaseInventoryError::MissingBinding);
        }
        if self.assignments[..self.count]
            .iter()
            .any(|present| present.package_id == assignment.package_id)
        {
            return Err(ReleaseInventoryError::DuplicateBinding);
        }
        self.assignments[self.count] = assignment;
        self.count += 1;
        Ok(())
    }

    pub fn seal(self) -> Result<ActivatedReleaseTotalMicrovmInventory<N>, ReleaseInventoryError> {
        if self.count != self.expected_len() {
            return Err(ReleaseInventoryError::BindingCount);
        }
        total_inventory_from_system_release_assignments::<N>(
            self.release_bytes,
            &self.expected_key_id,
            self.policy_generation,
            &self.assignments[..self.count],
        )?
        .bind_activated(self.active)
    }
}

/// Complete Total inventory whose package classifications and system
/// generation were authenticated from one exact SystemRelease. Safe code cannot
/// construct this wrapper from ad hoc domain records.
pub struct ReleaseTotalMicrovmInventory<const N: usize> {
    inventory: TotalMicrovmInventory<N>,
    signer: [u8; 64],
    system_generation: u64,
    generation_digest: [u8; 64],
    interface_catalog_digest: [u8; 64],
    release_content_digest: [u8; 64],
    runtime_inventory_digest: [u8; 64],
    policy_generation: u64,
}

impl<const N: usize> ReleaseTotalMicrovmInventory<N> {
    pub const fn signer(&self) -> &[u8; 64] {
        &self.signer
    }

    pub const fn system_generation(&self) -> u64 {
        self.system_generation
    }

    pub const fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    pub const fn generation_digest(&self) -> &[u8; 64] {
        &self.generation_digest
    }

    pub const fn interface_catalog_digest(&self) -> &[u8; 64] {
        &self.interface_catalog_digest
    }

    pub const fn release_content_digest(&self) -> &[u8; 64] {
        &self.release_content_digest
    }

    pub const fn runtime_inventory_digest(&self) -> &[u8; 64] {
        &self.runtime_inventory_digest
    }

    pub const fn len(&self) -> usize {
        self.inventory.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.inventory.is_empty()
    }

    pub fn entries(&self) -> impl Iterator<Item = TotalMicrovmInventoryEntry> + '_ {
        self.inventory.entries()
    }

    pub fn finalize<const DOMAINS: usize>(
        &self,
        admission: &crate::IsolationAdmissionTable<DOMAINS>,
    ) -> Result<crate::TotalMicrovmRuntimeProof, TotalMicrovmRuntimeError> {
        self.inventory.finalize(admission)
    }

    /// Consumes the authenticated release inventory only when its exact
    /// canonical generation and interface catalog are the records retained by
    /// the activated deployment generation. Numeric generation equality alone
    /// is insufficient.
    pub fn bind_activated(
        self,
        active: ActivatedSystemRelease,
    ) -> Result<ActivatedReleaseTotalMicrovmInventory<N>, ReleaseInventoryError> {
        let generation = active.generation();
        let release = active.release();
        if generation.generation() != self.system_generation
            || generation.generation_digest() != &self.generation_digest
            || generation.interface_catalog_digest() != &self.interface_catalog_digest
            || release.key_id() != &self.signer
            || release.content_digest() != &self.release_content_digest
            || release.runtime_inventory_digest() != Some(&self.runtime_inventory_digest)
        {
            return Err(ReleaseInventoryError::ActivatedGenerationMismatch);
        }
        Ok(ActivatedReleaseTotalMicrovmInventory {
            release: self,
            active,
        })
    }
}

/// Authenticated complete runtime inventory joined to the exact activated
/// generation/catalog pair. Safe code cannot construct this from matching
/// numeric generations or detached digests.
pub struct ActivatedReleaseTotalMicrovmInventory<const N: usize> {
    release: ReleaseTotalMicrovmInventory<N>,
    active: ActivatedSystemRelease,
}

impl<const N: usize> ActivatedReleaseTotalMicrovmInventory<N> {
    pub const fn active(&self) -> ActivatedSystemGeneration {
        self.active.generation()
    }

    pub const fn active_release(&self) -> ActivatedSystemRelease {
        self.active
    }

    pub const fn release(&self) -> &ReleaseTotalMicrovmInventory<N> {
        &self.release
    }

    pub const fn system_generation(&self) -> u64 {
        self.release.system_generation()
    }

    pub const fn policy_generation(&self) -> u64 {
        self.release.policy_generation()
    }

    pub fn finalize<const DOMAINS: usize>(
        &self,
        admission: &crate::IsolationAdmissionTable<DOMAINS>,
    ) -> Result<crate::TotalMicrovmRuntimeProof, TotalMicrovmRuntimeError> {
        self.release.finalize(admission)
    }
}

/// Constructs the kernel's complete strict-Total inventory only from one
/// authenticated SystemRelease v2 and the exact package-to-live-domain bindings
/// created by the normal launch control plane. Multiple compatible packages
/// may share one domain; their must-run state is conservatively combined.
/// Package names identify records; neither package metadata nor this
/// translation grants domain authority.
pub fn total_inventory_from_system_release<const N: usize>(
    release_bytes: &[u8],
    expected_key_id: &[u8; 64],
    policy_generation: u64,
    bindings: &[RuntimeDomainBinding<'_>],
) -> Result<ReleaseTotalMicrovmInventory<N>, ReleaseInventoryError> {
    let release = parse_system_release(release_bytes).map_err(ReleaseInventoryError::Release)?;
    if *expected_key_id == [0; 64] || release.key_id() != *expected_key_id {
        return Err(ReleaseInventoryError::SignerMismatch);
    }
    let runtime = release
        .runtime_inventory()
        .ok_or(ReleaseInventoryError::MissingRuntimeInventory)?;
    if bindings.len() != runtime.package_count() as usize || bindings.len() > N {
        return Err(ReleaseInventoryError::BindingCount);
    }
    for (index, binding) in bindings.iter().enumerate() {
        if binding.package_id.is_empty() || binding.domain.0 == 0 {
            return Err(ReleaseInventoryError::InvalidBinding);
        }
        if bindings[..index]
            .iter()
            .any(|present| present.package_id == binding.package_id)
        {
            return Err(ReleaseInventoryError::DuplicateBinding);
        }
    }

    let mut inventory =
        TotalMicrovmInventory::new(release.generation().generation(), policy_generation)
            .map_err(ReleaseInventoryError::Inventory)?;
    for record in runtime.records() {
        let binding = bindings
            .iter()
            .find(|binding| binding.package_id == record.package_id)
            .ok_or(ReleaseInventoryError::MissingBinding)?;
        let class_matches = matches!(
            (record.class, binding.class),
            (
                RuntimeIsolationClass::MicrovmEligible,
                TotalMicrovmClass::MicrovmEligible
            ) | (
                RuntimeIsolationClass::HostSubstrateRequired,
                TotalMicrovmClass::HostSubstrateRequired(_)
            ) | (RuntimeIsolationClass::BootOnly, TotalMicrovmClass::BootOnly)
                | (
                    RuntimeIsolationClass::RecoveryOnly,
                    TotalMicrovmClass::RecoveryOnly
                )
                | (
                    RuntimeIsolationClass::UnsupportedBlocker,
                    TotalMicrovmClass::UnsupportedBlocker
                )
        );
        if !class_matches {
            return Err(ReleaseInventoryError::ClassificationMismatch);
        }
        if binding.reason != record.reason {
            return Err(ReleaseInventoryError::ReasonMismatch);
        }
    }
    for (index, binding) in bindings.iter().enumerate() {
        if bindings[..index]
            .iter()
            .any(|present| present.domain == binding.domain)
        {
            continue;
        }
        let mut must_be_running = false;
        for colocated in bindings
            .iter()
            .filter(|candidate| candidate.domain == binding.domain)
        {
            if colocated.class != binding.class || colocated.reason != binding.reason {
                return Err(ReleaseInventoryError::ClassificationMismatch);
            }
            let record = runtime
                .records()
                .find(|record| record.package_id == colocated.package_id)
                .ok_or(ReleaseInventoryError::MissingBinding)?;
            must_be_running |= record.must_run;
        }
        inventory
            .insert(
                TotalMicrovmInventoryEntry::new(binding.domain, binding.class, must_be_running)
                    .map_err(ReleaseInventoryError::Inventory)?,
            )
            .map_err(ReleaseInventoryError::Inventory)?;
    }
    Ok(ReleaseTotalMicrovmInventory {
        inventory,
        signer: *expected_key_id,
        system_generation: release.generation().generation(),
        generation_digest: release.generation().digest(),
        interface_catalog_digest: release.interface_catalog().digest(),
        release_content_digest: release.content_digest(),
        runtime_inventory_digest: *release
            .identity()
            .runtime_inventory_digest()
            .ok_or(ReleaseInventoryError::MissingRuntimeInventory)?,
        policy_generation,
    })
}

/// Constructs a complete strict-Total inventory from policy-selected domain
/// assignments while deriving every package class and descriptive reason from
/// the authenticated SystemRelease. This prevents launchers from restating or
/// substituting eligible/boot/recovery/blocker classifications. A typed host-
/// substrate reason remains explicit architectural policy and is accepted only
/// for a release record classified as host substrate. Names identify; neither
/// assignments nor authenticated metadata grant domain authority.
pub fn total_inventory_from_system_release_assignments<const N: usize>(
    release_bytes: &[u8],
    expected_key_id: &[u8; 64],
    policy_generation: u64,
    assignments: &[RuntimeDomainAssignment<'_>],
) -> Result<ReleaseTotalMicrovmInventory<N>, ReleaseInventoryError> {
    let release = parse_system_release(release_bytes).map_err(ReleaseInventoryError::Release)?;
    if *expected_key_id == [0; 64] || release.key_id() != *expected_key_id {
        return Err(ReleaseInventoryError::SignerMismatch);
    }
    let runtime = release
        .runtime_inventory()
        .ok_or(ReleaseInventoryError::MissingRuntimeInventory)?;
    if assignments.len() != runtime.package_count() as usize || assignments.len() > N {
        return Err(ReleaseInventoryError::BindingCount);
    }
    for (index, assignment) in assignments.iter().enumerate() {
        if assignment.package_id.is_empty() || assignment.domain.0 == 0 {
            return Err(ReleaseInventoryError::InvalidBinding);
        }
        if assignments[..index]
            .iter()
            .any(|present| present.package_id == assignment.package_id)
        {
            return Err(ReleaseInventoryError::DuplicateBinding);
        }
    }

    let placeholder = RuntimeDomainBinding {
        package_id: "",
        domain: ObjectId(0),
        class: TotalMicrovmClass::BootOnly,
        reason: "",
    };
    let mut bindings = [placeholder; N];
    let mut count = 0;
    for record in runtime.records() {
        let assignment = assignments
            .iter()
            .find(|assignment| assignment.package_id == record.package_id)
            .ok_or(ReleaseInventoryError::MissingBinding)?;
        let class = match (record.class, assignment.host_substrate_reason) {
            (RuntimeIsolationClass::MicrovmEligible, None) => TotalMicrovmClass::MicrovmEligible,
            (RuntimeIsolationClass::HostSubstrateRequired, Some(reason)) => {
                TotalMicrovmClass::HostSubstrateRequired(reason)
            }
            (RuntimeIsolationClass::BootOnly, None) => TotalMicrovmClass::BootOnly,
            (RuntimeIsolationClass::RecoveryOnly, None) => TotalMicrovmClass::RecoveryOnly,
            (RuntimeIsolationClass::UnsupportedBlocker, None) => {
                TotalMicrovmClass::UnsupportedBlocker
            }
            _ => return Err(ReleaseInventoryError::HostSubstrateReasonMismatch),
        };
        bindings[count] = RuntimeDomainBinding {
            package_id: record.package_id,
            domain: assignment.domain,
            class,
            reason: record.reason,
        };
        count += 1;
    }
    total_inventory_from_system_release(
        release_bytes,
        expected_key_id,
        policy_generation,
        &bindings[..count],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_crypto::{LAMPORT_PRIVATE_KEY_BYTES, LAMPORT_PUBLIC_KEY_BYTES, lamport_public_key};
    use mrml_package_format::{
        ComponentInterfaceProvider, ComponentInterfaceRequirement, ComponentProviderForms,
        MAX_SYSTEM_RELEASE_BYTES, RuntimeInventoryRecord, RuntimeIsolationPlacement,
        SystemGenerationDigestRecord, encode_interface_catalog, encode_runtime_inventory,
        encode_system_generation, encode_system_release,
        encode_system_release_with_runtime_inventory,
    };

    const POLICY: u64 = 19;

    fn build_release(
        include_runtime: bool,
        runtime_generation: u64,
    ) -> ([u8; MAX_SYSTEM_RELEASE_BYTES], usize, [u8; 64]) {
        build_release_with_class(
            include_runtime,
            runtime_generation,
            RuntimeIsolationClass::MicrovmEligible,
            "",
        )
    }

    fn build_release_with_class(
        include_runtime: bool,
        runtime_generation: u64,
        class: RuntimeIsolationClass,
        reason: &str,
    ) -> ([u8; MAX_SYSTEM_RELEASE_BYTES], usize, [u8; 64]) {
        let digest = [0x41; 64];
        let generation_record = SystemGenerationDigestRecord {
            package_id: "org.mrml.service.config",
            version: 5,
            artifact_digest: &digest,
        };
        let mut generation = [0; 160];
        let generation_length =
            encode_system_generation(13, &[generation_record], &mut generation).unwrap();
        let provider = ComponentInterfaceProvider::exact(
            "org.mrml.service.config",
            "org.mrml.interface.config",
            1,
            [0x52; 32],
            ComponentProviderForms::MICROVM,
        )
        .unwrap();
        let requirement = ComponentInterfaceRequirement::exact(
            "org.mrml.service.config",
            "org.mrml.interface.config",
            1,
            [0x52; 32],
        )
        .unwrap();
        let mut catalog = [0; 256];
        let catalog_length =
            encode_interface_catalog(13, &[requirement], &[provider], &mut catalog).unwrap();
        let (preferred, minimum, maximum, supported) =
            if class == RuntimeIsolationClass::HostSubstrateRequired {
                let platform = RuntimeIsolationPlacement::Platform;
                (platform, platform, platform, platform.bit())
            } else {
                (
                    RuntimeIsolationPlacement::NativeService,
                    RuntimeIsolationPlacement::NativeService,
                    RuntimeIsolationPlacement::Microvm,
                    RuntimeIsolationPlacement::NativeService.bit()
                        | RuntimeIsolationPlacement::Microvm.bit(),
                )
            };
        let runtime_record = RuntimeInventoryRecord {
            package_id: "org.mrml.service.config",
            version: 5,
            artifact_digest: &digest,
            class,
            must_run: true,
            preferred,
            minimum,
            maximum,
            supported,
            reason,
        };
        let mut runtime = [0; 256];
        let runtime_length =
            encode_runtime_inventory(runtime_generation, &[runtime_record], &mut runtime).unwrap();
        let private = [0x67; LAMPORT_PRIVATE_KEY_BYTES];
        let mut public = [0; LAMPORT_PUBLIC_KEY_BYTES];
        lamport_public_key(&private, &mut public).unwrap();
        let key_id = mrml_crypto::Sha3_512::digest(&public);
        let mut output = [0; MAX_SYSTEM_RELEASE_BYTES];
        let length = if include_runtime {
            encode_system_release_with_runtime_inventory(
                &generation[..generation_length],
                &catalog[..catalog_length],
                &runtime[..runtime_length],
                &private,
                &mut output,
            )
        } else {
            encode_system_release(
                &generation[..generation_length],
                &catalog[..catalog_length],
                &private,
                &mut output,
            )
        }
        .unwrap();
        (output, length, key_id)
    }

    fn build_colocated_release() -> ([u8; MAX_SYSTEM_RELEASE_BYTES], usize, [u8; 64]) {
        let first_digest = [0x31; 64];
        let second_digest = [0x32; 64];
        let generation_records = [
            SystemGenerationDigestRecord {
                package_id: "org.mrml.zim",
                version: 7,
                artifact_digest: &first_digest,
            },
            SystemGenerationDigestRecord {
                package_id: "org.mrml.zstd",
                version: 8,
                artifact_digest: &second_digest,
            },
        ];
        let mut generation = [0; 320];
        let generation_length =
            encode_system_generation(13, &generation_records, &mut generation).unwrap();
        let provider = ComponentInterfaceProvider::exact(
            "org.mrml.zstd",
            "org.mrml.interface.compression.zstd",
            3,
            [0x52; 32],
            ComponentProviderForms::MICROVM,
        )
        .unwrap();
        let requirement = ComponentInterfaceRequirement::exact(
            "org.mrml.zim",
            "org.mrml.interface.compression.zstd",
            3,
            [0x52; 32],
        )
        .unwrap();
        let mut catalog = [0; 256];
        let catalog_length =
            encode_interface_catalog(13, &[requirement], &[provider], &mut catalog).unwrap();
        let runtime_records = [
            RuntimeInventoryRecord {
                package_id: "org.mrml.zim",
                version: 7,
                artifact_digest: &first_digest,
                class: RuntimeIsolationClass::MicrovmEligible,
                must_run: false,
                preferred: RuntimeIsolationPlacement::InProcess,
                minimum: RuntimeIsolationPlacement::InProcess,
                maximum: RuntimeIsolationPlacement::Microvm,
                supported: RuntimeIsolationPlacement::InProcess.bit()
                    | RuntimeIsolationPlacement::Microvm.bit(),
                reason: "",
            },
            RuntimeInventoryRecord {
                package_id: "org.mrml.zstd",
                version: 8,
                artifact_digest: &second_digest,
                class: RuntimeIsolationClass::MicrovmEligible,
                must_run: true,
                preferred: RuntimeIsolationPlacement::NativeService,
                minimum: RuntimeIsolationPlacement::NativeService,
                maximum: RuntimeIsolationPlacement::Microvm,
                supported: RuntimeIsolationPlacement::NativeService.bit()
                    | RuntimeIsolationPlacement::Microvm.bit(),
                reason: "",
            },
        ];
        let mut runtime = [0; 512];
        let runtime_length = encode_runtime_inventory(13, &runtime_records, &mut runtime).unwrap();
        let private = [0x71; LAMPORT_PRIVATE_KEY_BYTES];
        let mut public = [0; LAMPORT_PUBLIC_KEY_BYTES];
        lamport_public_key(&private, &mut public).unwrap();
        let key_id = mrml_crypto::Sha3_512::digest(&public);
        let mut output = [0; MAX_SYSTEM_RELEASE_BYTES];
        let length = encode_system_release_with_runtime_inventory(
            &generation[..generation_length],
            &catalog[..catalog_length],
            &runtime[..runtime_length],
            &private,
            &mut output,
        )
        .unwrap();
        (output, length, key_id)
    }

    #[test]
    fn authenticated_release_constructs_complete_kernel_inventory() {
        let (release, release_length, key_id) = build_release(true, 13);
        let bindings = [RuntimeDomainBinding::new(
            "org.mrml.service.config",
            ObjectId(0x700),
            TotalMicrovmClass::MicrovmEligible,
            "",
        )
        .unwrap()];
        let inventory = total_inventory_from_system_release::<1>(
            &release[..release_length],
            &key_id,
            POLICY,
            &bindings,
        )
        .unwrap();
        let entry = inventory.entries().next().unwrap();
        assert_eq!(inventory.signer(), &key_id);
        assert_eq!(inventory.system_generation(), 13);
        assert_eq!(inventory.policy_generation(), POLICY);
        assert_eq!(inventory.len(), 1);
        assert_eq!(entry.domain(), ObjectId(0x700));
        assert_eq!(entry.class(), TotalMicrovmClass::MicrovmEligible);
        assert!(entry.must_be_running());
    }

    #[test]
    fn release_inventory_binds_only_the_exact_activated_generation() {
        let (release, release_length, key_id) = build_release(true, 13);
        let assignment =
            RuntimeDomainAssignment::new("org.mrml.service.config", ObjectId(0x700)).unwrap();
        let inventory = total_inventory_from_system_release_assignments::<1>(
            &release[..release_length],
            &key_id,
            POLICY,
            &[assignment],
        )
        .unwrap();
        let active_generation = ActivatedSystemGeneration::new(
            inventory.system_generation(),
            *inventory.generation_digest(),
            *inventory.interface_catalog_digest(),
            7,
            0x5155,
            3,
        )
        .unwrap();
        let release_identity = parse_system_release(&release[..release_length])
            .unwrap()
            .identity();
        let active = ActivatedSystemRelease::new(active_generation, release_identity);
        let bound = inventory.bind_activated(active).unwrap();
        assert_eq!(bound.active(), active_generation);
        assert_eq!(bound.active_release(), active);
        assert_eq!(bound.system_generation(), 13);
        assert_eq!(bound.policy_generation(), POLICY);
        assert_eq!(bound.release().signer(), &key_id);
    }

    #[test]
    fn activated_total_inventory_rejects_every_release_identity_substitution() {
        for mismatch in 0..6 {
            let (release, release_length, key_id) = build_release(true, 13);
            let assignment =
                RuntimeDomainAssignment::new("org.mrml.service.config", ObjectId(0x700)).unwrap();
            let inventory = total_inventory_from_system_release_assignments::<1>(
                &release[..release_length],
                &key_id,
                POLICY,
                &[assignment],
            )
            .unwrap();
            let generation = if mismatch == 0 { 14 } else { 13 };
            let generation_digest = if mismatch == 1 {
                [0x91; 64]
            } else {
                *inventory.generation_digest()
            };
            let catalog_digest = if mismatch == 2 {
                [0x92; 64]
            } else {
                *inventory.interface_catalog_digest()
            };
            let active_generation = ActivatedSystemGeneration::new(
                generation,
                generation_digest,
                catalog_digest,
                7,
                0x5155,
                3,
            )
            .unwrap();
            let parsed_identity = parse_system_release(&release[..release_length])
                .unwrap()
                .identity();
            let content_digest = if mismatch == 3 {
                [0x93; 64]
            } else {
                *parsed_identity.content_digest()
            };
            let key_id = if mismatch == 4 {
                [0x94; 64]
            } else {
                *parsed_identity.key_id()
            };
            let runtime_digest = if mismatch == 5 {
                [0x95; 64]
            } else {
                *parsed_identity.runtime_inventory_digest().unwrap()
            };
            let identity = mrml_package_format::SystemReleaseIdentity::from_digests(
                content_digest,
                key_id,
                Some(runtime_digest),
            )
            .unwrap();
            let active = ActivatedSystemRelease::new(active_generation, identity);
            assert!(matches!(
                inventory.bind_activated(active),
                Err(ReleaseInventoryError::ActivatedGenerationMismatch)
            ));
        }
    }

    #[test]
    fn v1_wrong_signer_and_binding_substitution_fail_closed() {
        let (release, release_length, key_id) = build_release(false, 13);
        let binding = RuntimeDomainBinding::new(
            "org.mrml.service.config",
            ObjectId(0x700),
            TotalMicrovmClass::MicrovmEligible,
            "",
        )
        .unwrap();
        assert!(matches!(
            total_inventory_from_system_release::<1>(
                &release[..release_length],
                &key_id,
                POLICY,
                &[binding]
            ),
            Err(ReleaseInventoryError::MissingRuntimeInventory)
        ));

        let (release, release_length, _) = build_release(true, 13);
        assert!(matches!(
            total_inventory_from_system_release::<1>(
                &release[..release_length],
                &[0x99; 64],
                POLICY,
                &[binding]
            ),
            Err(ReleaseInventoryError::SignerMismatch)
        ));
        let wrong_package = RuntimeDomainBinding::new(
            "org.mrml.service.other",
            ObjectId(0x700),
            TotalMicrovmClass::MicrovmEligible,
            "",
        )
        .unwrap();
        assert!(matches!(
            total_inventory_from_system_release::<1>(
                &release[..release_length],
                &key_id,
                POLICY,
                &[wrong_package]
            ),
            Err(ReleaseInventoryError::MissingBinding)
        ));
        let wrong_class = RuntimeDomainBinding::new(
            "org.mrml.service.config",
            ObjectId(0x700),
            TotalMicrovmClass::BootOnly,
            "",
        )
        .unwrap();
        assert!(matches!(
            total_inventory_from_system_release::<1>(
                &release[..release_length],
                &key_id,
                POLICY,
                &[wrong_class]
            ),
            Err(ReleaseInventoryError::ClassificationMismatch)
        ));
        let wrong_reason = RuntimeDomainBinding::new(
            "org.mrml.service.config",
            ObjectId(0x700),
            TotalMicrovmClass::MicrovmEligible,
            "substituted reason",
        )
        .unwrap();
        assert!(matches!(
            total_inventory_from_system_release::<1>(
                &release[..release_length],
                &key_id,
                POLICY,
                &[wrong_reason]
            ),
            Err(ReleaseInventoryError::ReasonMismatch)
        ));
    }

    #[test]
    fn release_inventory_requires_exact_binding_count() {
        let (release, release_length, key_id) = build_release(true, 13);
        assert!(matches!(
            total_inventory_from_system_release::<1>(
                &release[..release_length],
                &key_id,
                POLICY,
                &[]
            ),
            Err(ReleaseInventoryError::BindingCount)
        ));
        let first = RuntimeDomainBinding::new(
            "org.mrml.service.config",
            ObjectId(0x700),
            TotalMicrovmClass::MicrovmEligible,
            "",
        )
        .unwrap();
        let duplicate = RuntimeDomainBinding::new(
            "org.mrml.service.config",
            ObjectId(0x701),
            TotalMicrovmClass::MicrovmEligible,
            "",
        )
        .unwrap();
        assert!(matches!(
            total_inventory_from_system_release::<2>(
                &release[..release_length],
                &key_id,
                POLICY,
                &[first, duplicate]
            ),
            Err(ReleaseInventoryError::BindingCount)
        ));
    }

    #[test]
    fn compatible_colocated_packages_form_one_conservative_domain() {
        let (release, release_length, key_id) = build_colocated_release();
        let domain = ObjectId(0x5a49_4d5f_5a53_5444);
        let bindings = [
            RuntimeDomainBinding::new(
                "org.mrml.zim",
                domain,
                TotalMicrovmClass::MicrovmEligible,
                "",
            )
            .unwrap(),
            RuntimeDomainBinding::new(
                "org.mrml.zstd",
                domain,
                TotalMicrovmClass::MicrovmEligible,
                "",
            )
            .unwrap(),
        ];
        let inventory = total_inventory_from_system_release::<2>(
            &release[..release_length],
            &key_id,
            POLICY,
            &bindings,
        )
        .unwrap();
        let entry = inventory.entries().next().unwrap();
        assert_eq!(inventory.len(), 1);
        assert_eq!(entry.domain(), domain);
        assert_eq!(entry.class(), TotalMicrovmClass::MicrovmEligible);
        assert!(entry.must_be_running());
    }

    #[test]
    fn authenticated_classes_complete_policy_domain_assignments() {
        let (release, release_length, key_id) = build_colocated_release();
        let domain = ObjectId(0x5a49_4d5f_5a53_5444);
        let assignments = [
            RuntimeDomainAssignment::new("org.mrml.zim", domain).unwrap(),
            RuntimeDomainAssignment::new("org.mrml.zstd", domain).unwrap(),
        ];
        let inventory = total_inventory_from_system_release_assignments::<2>(
            &release[..release_length],
            &key_id,
            POLICY,
            &assignments,
        )
        .unwrap();
        let entry = inventory.entries().next().unwrap();
        assert_eq!(inventory.len(), 1);
        assert_eq!(entry.domain(), domain);
        assert_eq!(entry.class(), TotalMicrovmClass::MicrovmEligible);
        assert!(entry.must_be_running());

        let missing = [RuntimeDomainAssignment::new("org.mrml.zim", domain).unwrap()];
        assert!(matches!(
            total_inventory_from_system_release_assignments::<2>(
                &release[..release_length],
                &key_id,
                POLICY,
                &missing,
            ),
            Err(ReleaseInventoryError::BindingCount)
        ));
        let substituted = [
            RuntimeDomainAssignment::new("org.mrml.other", domain).unwrap(),
            RuntimeDomainAssignment::new("org.mrml.zstd", domain).unwrap(),
        ];
        assert!(matches!(
            total_inventory_from_system_release_assignments::<2>(
                &release[..release_length],
                &key_id,
                POLICY,
                &substituted,
            ),
            Err(ReleaseInventoryError::MissingBinding)
        ));
    }

    #[test]
    fn installed_assignment_plan_enumerates_and_seals_exact_release_membership() {
        let (release, release_length, key_id) = build_colocated_release();
        let parsed = parse_system_release(&release[..release_length]).unwrap();
        let generation = ActivatedSystemGeneration::new(
            parsed.generation().generation(),
            parsed.generation().digest(),
            parsed.interface_catalog().digest(),
            7,
            0x5155,
            3,
        )
        .unwrap();
        let active = ActivatedSystemRelease::new(generation, parsed.identity());
        let domain = ObjectId(0x5a49_4d5f_5a53_5444);
        let mut plan = RuntimeDomainAssignmentPlan::<2>::new(
            &release[..release_length],
            &key_id,
            active,
            POLICY,
        )
        .unwrap();
        assert_eq!(plan.expected_len(), 2);
        assert_eq!(plan.assigned_len(), 0);
        let mut packages = plan.packages();
        assert_eq!(packages.next(), Some("org.mrml.zim"));
        assert_eq!(packages.next(), Some("org.mrml.zstd"));
        assert_eq!(packages.next(), None);
        drop(packages);
        plan.assign("org.mrml.zim", domain).unwrap();
        plan.assign("org.mrml.zstd", domain).unwrap();
        let inventory = plan.seal().unwrap();
        assert_eq!(inventory.active_release(), active);
        assert_eq!(inventory.release().len(), 1);
        assert!(
            inventory
                .release()
                .entries()
                .next()
                .unwrap()
                .must_be_running()
        );

        let mut incomplete = RuntimeDomainAssignmentPlan::<2>::new(
            &release[..release_length],
            &key_id,
            active,
            POLICY,
        )
        .unwrap();
        incomplete.assign("org.mrml.zim", domain).unwrap();
        assert!(matches!(
            incomplete.seal(),
            Err(ReleaseInventoryError::BindingCount)
        ));

        let mut hostile = RuntimeDomainAssignmentPlan::<2>::new(
            &release[..release_length],
            &key_id,
            active,
            POLICY,
        )
        .unwrap();
        assert_eq!(
            hostile.assign("org.mrml.other", domain),
            Err(ReleaseInventoryError::MissingBinding)
        );
        hostile.assign("org.mrml.zim", domain).unwrap();
        assert_eq!(
            hostile.assign("org.mrml.zim", ObjectId(domain.0 + 1)),
            Err(ReleaseInventoryError::DuplicateBinding)
        );
        assert!(matches!(
            RuntimeDomainAssignmentPlan::<1>::new(
                &release[..release_length],
                &key_id,
                active,
                POLICY,
            ),
            Err(ReleaseInventoryError::BindingCount)
        ));
    }

    #[test]
    fn installed_assignment_policy_visits_every_authenticated_record_exactly_once() {
        let (release, release_length, key_id) = build_colocated_release();
        let parsed = parse_system_release(&release[..release_length]).unwrap();
        let generation = ActivatedSystemGeneration::new(
            parsed.generation().generation(),
            parsed.generation().digest(),
            parsed.interface_catalog().digest(),
            7,
            0x5155,
            3,
        )
        .unwrap();
        let active = ActivatedSystemRelease::new(generation, parsed.identity());
        let domain = ObjectId(0x504f_4c49_4359_0001);
        let mut visited = 0;
        let mut plan = RuntimeDomainAssignmentPlan::<2>::new(
            &release[..release_length],
            &key_id,
            active,
            POLICY,
        )
        .unwrap();
        plan.assign_from_policy(|record| {
            assert_eq!(record.class, RuntimeIsolationClass::MicrovmEligible);
            assert!(record.supported & RuntimeIsolationPlacement::Microvm.bit() != 0);
            visited += 1;
            RuntimeDomainAssignment::new(record.package_id, domain)
        })
        .unwrap();
        assert_eq!(visited, 2);
        assert_eq!(plan.policy_generation(), POLICY);
        assert_eq!(plan.assigned_len(), plan.expected_len());
        assert_eq!(plan.seal().unwrap().release().len(), 1);

        let mut substituted = RuntimeDomainAssignmentPlan::<2>::new(
            &release[..release_length],
            &key_id,
            active,
            POLICY,
        )
        .unwrap();
        assert_eq!(
            substituted
                .assign_from_policy(|_| RuntimeDomainAssignment::new("org.mrml.other", domain)),
            Err(ReleaseInventoryError::MissingBinding)
        );

        let mut rejected = RuntimeDomainAssignmentPlan::<2>::new(
            &release[..release_length],
            &key_id,
            active,
            POLICY,
        )
        .unwrap();
        let mut decisions = 0;
        assert_eq!(
            rejected.assign_from_policy(|record| {
                decisions += 1;
                if decisions == 2 {
                    return Err(ReleaseInventoryError::InvalidBinding);
                }
                RuntimeDomainAssignment::new(record.package_id, domain)
            }),
            Err(ReleaseInventoryError::InvalidBinding)
        );
        assert_eq!(rejected.assigned_len(), 0);
        assert!(matches!(
            rejected.seal(),
            Err(ReleaseInventoryError::BindingCount)
        ));

        let mut configuration_rejected = RuntimeDomainAssignmentPlan::<2>::new(
            &release[..release_length],
            &key_id,
            active,
            POLICY,
        )
        .unwrap();
        let mut configuration_decisions = 0;
        assert_eq!(
            configuration_rejected.assign_from_policy_transaction(|record| {
                configuration_decisions += 1;
                if configuration_decisions == 2 {
                    return Err(7u8);
                }
                RuntimeDomainAssignment::new(record.package_id, domain).map_err(|_| 8u8)
            }),
            Err(RuntimeDomainPolicyAssignmentError::Decision(7u8))
        );
        assert_eq!(configuration_rejected.assigned_len(), 0);

        let mut mixed = RuntimeDomainAssignmentPlan::<2>::new(
            &release[..release_length],
            &key_id,
            active,
            POLICY,
        )
        .unwrap();
        mixed.assign("org.mrml.zim", domain).unwrap();
        assert_eq!(
            mixed.assign_from_policy(|record| RuntimeDomainAssignment::new(
                record.package_id,
                domain
            )),
            Err(ReleaseInventoryError::BindingCount)
        );
    }

    #[test]
    fn host_substrate_reason_cannot_be_attached_to_eligible_release_record() {
        let (release, release_length, key_id) = build_release(true, 13);
        let assignments = [RuntimeDomainAssignment::host_substrate(
            "org.mrml.service.config",
            ObjectId(0x700),
            HostSubstrateReason::InstantiateMicrovms,
        )
        .unwrap()];
        assert!(matches!(
            total_inventory_from_system_release_assignments::<1>(
                &release[..release_length],
                &key_id,
                POLICY,
                &assignments,
            ),
            Err(ReleaseInventoryError::HostSubstrateReasonMismatch)
        ));

        let (release, release_length, key_id) = build_release_with_class(
            true,
            13,
            RuntimeIsolationClass::HostSubstrateRequired,
            "required to instantiate microVMs",
        );
        let inventory = total_inventory_from_system_release_assignments::<1>(
            &release[..release_length],
            &key_id,
            POLICY,
            &assignments,
        )
        .unwrap();
        assert_eq!(
            inventory.entries().next().unwrap().class(),
            TotalMicrovmClass::HostSubstrateRequired(HostSubstrateReason::InstantiateMicrovms)
        );
    }
}
