#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use mrml_crypto::{
        LAMPORT_PRIVATE_KEY_BYTES, LAMPORT_PUBLIC_KEY_BYTES, Sha3_512, lamport_public_key,
    };
    use mrml_kernel::{
        HostSubstrateCounts, InstalledRecoverySource, IsolationUnavailableCounts,
        RuntimeDomainAssignment, RuntimeDomainAssignmentPlan, TotalMicrovmClass, TotalMicrovmState,
        route_isolation_service,
    };
    use mrml_package_format::{
        ActivatedSystemGeneration, ActivatedSystemRelease, ComponentInterfaceProvider,
        ComponentInterfaceRequirement, ComponentProviderForms, MAX_SYSTEM_RELEASE_BYTES,
        RuntimeInventoryRecord, RuntimeIsolationClass, RuntimeIsolationPlacement,
        SystemGenerationDigestRecord, encode_interface_catalog, encode_runtime_inventory,
        encode_system_generation, encode_system_release_with_runtime_inventory,
        parse_system_release,
    };
    use mrml_storage::{
        AUTHORITY_RECOVERY_STATE_BYTES, AuthenticatedAuthorityRecoveryState,
        AuthorityCheckpointProofIssuer, AuthorityRecoveryGuard, AuthorityRecoveryStateStore,
        BlockDeviceDescriptor, BlockDeviceId, BlockRights, BlockService, BlockServiceBackend,
        BlockServiceError, BlockSessionGrant, BlockVolume, BootRecoveryAdmission, CowMetadataImage,
        CowMetadataWrite, CowPublicationBackend, CowPublicationPlan, ExtentRecord, FileReadBackend,
        FileWriteBackend, OwnerApprovedAuthorityCheckpoint, PlatformBlockDeviceDescriptor,
        PlatformBlockDeviceIdentity, PlatformBlockTransport, ServicedBlockDevice, StorageObjectId,
        StorageObjectKind, StorageRecoveryGrant, StorageRights, StorageTransactionId, Superblock,
        VolumeHeader, VolumeId, authority_checkpoint_digest, encode_authority_checkpoint,
        recover_validate_and_commit_stable_authorities,
    };
    use std::vec;

    const MEMORY_POOL_RIGHTS: Rights = Rights::ALLOCATE.union(Rights::INSPECT);

    fn configuration_release_records()
    -> (std::vec::Vec<u8>, usize, [u8; 64], ActivatedSystemRelease) {
        let digest = [0x44; 64];
        let generation_record = SystemGenerationDigestRecord {
            package_id: "org.mrml.service.config",
            version: 5,
            artifact_digest: &digest,
        };
        let mut generation = [0; 192];
        let generation_length =
            encode_system_generation(33, &[generation_record], &mut generation).unwrap();
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
            encode_interface_catalog(33, &[requirement], &[provider], &mut catalog).unwrap();
        let runtime_record = RuntimeInventoryRecord {
            package_id: "org.mrml.service.config",
            version: 5,
            artifact_digest: &digest,
            class: RuntimeIsolationClass::MicrovmEligible,
            must_run: true,
            preferred: RuntimeIsolationPlacement::NativeService,
            minimum: RuntimeIsolationPlacement::NativeService,
            maximum: RuntimeIsolationPlacement::Microvm,
            supported: RuntimeIsolationPlacement::NativeService.bit()
                | RuntimeIsolationPlacement::Microvm.bit(),
            reason: "",
        };
        let mut runtime = [0; 256];
        let runtime_length = encode_runtime_inventory(33, &[runtime_record], &mut runtime).unwrap();
        let private = [0x67; LAMPORT_PRIVATE_KEY_BYTES];
        let mut public = [0; LAMPORT_PUBLIC_KEY_BYTES];
        lamport_public_key(&private, &mut public).unwrap();
        let key_id = Sha3_512::digest(&public);
        let mut release = vec![0; MAX_SYSTEM_RELEASE_BYTES];
        let release_length = encode_system_release_with_runtime_inventory(
            &generation[..generation_length],
            &catalog[..catalog_length],
            &runtime[..runtime_length],
            &private,
            &mut release,
        )
        .unwrap();
        let parsed = parse_system_release(&release[..release_length]).unwrap();
        let active_generation = ActivatedSystemGeneration::new(
            33,
            parsed.generation().digest(),
            parsed.interface_catalog().digest(),
            7,
            0x5155,
            3,
        )
        .unwrap();
        let active = ActivatedSystemRelease::new(active_generation, parsed.identity());
        (release, release_length, key_id, active)
    }

    fn activated_configuration_release(
        domain: ObjectId,
        policy_generation: u64,
    ) -> ActivatedReleaseTotalMicrovmInventory<1> {
        let (release, release_length, key_id, active) = configuration_release_records();
        let mut plan = RuntimeDomainAssignmentPlan::<1>::new(
            &release[..release_length],
            &key_id,
            active,
            policy_generation,
        )
        .unwrap();
        plan.assign_from_policy(|record| RuntimeDomainAssignment::new(record.package_id, domain))
            .unwrap();
        plan.seal().unwrap()
    }

    fn two_domain_release_records() -> (std::vec::Vec<u8>, usize, [u8; 64], ActivatedSystemRelease)
    {
        let first_digest = [0x44; 64];
        let second_digest = [0x45; 64];
        let generation_records = [
            SystemGenerationDigestRecord {
                package_id: "org.mrml.service.config",
                version: 5,
                artifact_digest: &first_digest,
            },
            SystemGenerationDigestRecord {
                package_id: "org.mrml.service.deployment",
                version: 6,
                artifact_digest: &second_digest,
            },
        ];
        let mut generation = [0; 320];
        let generation_length =
            encode_system_generation(33, &generation_records, &mut generation).unwrap();
        let providers = [
            ComponentInterfaceProvider::exact(
                "org.mrml.service.config",
                "org.mrml.interface.config",
                1,
                [0x52; 32],
                ComponentProviderForms::MICROVM,
            )
            .unwrap(),
            ComponentInterfaceProvider::exact(
                "org.mrml.service.deployment",
                "org.mrml.interface.deployment",
                1,
                [0x53; 32],
                ComponentProviderForms::MICROVM,
            )
            .unwrap(),
        ];
        let requirements = [
            ComponentInterfaceRequirement::exact(
                "org.mrml.service.config",
                "org.mrml.interface.config",
                1,
                [0x52; 32],
            )
            .unwrap(),
            ComponentInterfaceRequirement::exact(
                "org.mrml.service.deployment",
                "org.mrml.interface.deployment",
                1,
                [0x53; 32],
            )
            .unwrap(),
        ];
        let mut catalog = [0; 512];
        let catalog_length =
            encode_interface_catalog(33, &requirements, &providers, &mut catalog).unwrap();
        let runtime_records = [
            RuntimeInventoryRecord {
                package_id: "org.mrml.service.config",
                version: 5,
                artifact_digest: &first_digest,
                class: RuntimeIsolationClass::MicrovmEligible,
                must_run: true,
                preferred: RuntimeIsolationPlacement::NativeService,
                minimum: RuntimeIsolationPlacement::NativeService,
                maximum: RuntimeIsolationPlacement::Microvm,
                supported: RuntimeIsolationPlacement::NativeService.bit()
                    | RuntimeIsolationPlacement::Microvm.bit(),
                reason: "",
            },
            RuntimeInventoryRecord {
                package_id: "org.mrml.service.deployment",
                version: 6,
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
        let runtime_length = encode_runtime_inventory(33, &runtime_records, &mut runtime).unwrap();
        let private = [0x68; LAMPORT_PRIVATE_KEY_BYTES];
        let mut public = [0; LAMPORT_PUBLIC_KEY_BYTES];
        lamport_public_key(&private, &mut public).unwrap();
        let key_id = Sha3_512::digest(&public);
        let mut release = vec![0; MAX_SYSTEM_RELEASE_BYTES];
        let release_length = encode_system_release_with_runtime_inventory(
            &generation[..generation_length],
            &catalog[..catalog_length],
            &runtime[..runtime_length],
            &private,
            &mut release,
        )
        .unwrap();
        let parsed = parse_system_release(&release[..release_length]).unwrap();
        let active_generation = ActivatedSystemGeneration::new(
            33,
            parsed.generation().digest(),
            parsed.interface_catalog().digest(),
            8,
            0x5156,
            3,
        )
        .unwrap();
        let active = ActivatedSystemRelease::new(active_generation, parsed.identity());
        (release, release_length, key_id, active)
    }

    fn activated_two_domain_release(
        first_domain: ObjectId,
        second_domain: ObjectId,
        policy_generation: u64,
    ) -> ActivatedReleaseTotalMicrovmInventory<2> {
        let (release, release_length, key_id, active) = two_domain_release_records();
        let mut plan = RuntimeDomainAssignmentPlan::<2>::new(
            &release[..release_length],
            &key_id,
            active,
            policy_generation,
        )
        .unwrap();
        plan.assign_from_policy(|record| {
            RuntimeDomainAssignment::new(
                record.package_id,
                if record.package_id == "org.mrml.service.config" {
                    first_domain
                } else {
                    second_domain
                },
            )
        })
        .unwrap();
        plan.seal().unwrap()
    }

    fn hosted_total_handoff(
        accepted_epoch: u64,
        accepted_volume: Option<[u8; 16]>,
        accepted_root_generation: u64,
    ) -> ([u8; 512], usize) {
        let framebuffer = mrml_kernel::FramebufferInfo::new(
            0xa0000,
            0x1000,
            16,
            16,
            16,
            mrml_kernel::PixelFormat::BlueGreenRedReserved,
        )
        .unwrap();
        let regions = [
            mrml_kernel::MemoryRegion::new(
                mrml_kernel::PhysAddr::new(0xa0000).unwrap(),
                1,
                mrml_kernel::MemoryKind::Mmio,
            )
            .unwrap(),
            mrml_kernel::MemoryRegion::new(
                mrml_kernel::PhysAddr::new(0x10_0000).unwrap(),
                64,
                mrml_kernel::MemoryKind::Reserved,
            )
            .unwrap(),
        ];
        let recovery = mrml_kernel::RecoveryStateMetadata::new(
            accepted_epoch,
            1,
            accepted_volume,
            accepted_root_generation,
        )
        .unwrap();
        let mut bytes = [0; 512];
        let length = if let Some(volume) = accepted_volume {
            let installed = InstalledRecoveryBootIdentity::new(
                InstalledRecoverySource::Hosted,
                [0x42; 32],
                1,
                1,
                4096,
                100,
                volume,
                1,
                accepted_root_generation,
            )
            .unwrap();
            mrml_kernel::encode_handoff_with_recovery_isolation_and_installed(
                7,
                [1; 32],
                [2; 64],
                true,
                true,
                false,
                true,
                0x9000,
                framebuffer,
                &regions,
                recovery,
                installed,
                Some(BootIsolationOverride::TotalMicrovmOnce),
                &mut bytes,
            )
        } else {
            mrml_kernel::encode_handoff_with_recovery_and_isolation(
                7,
                [1; 32],
                [2; 64],
                true,
                true,
                false,
                true,
                0x9000,
                framebuffer,
                &regions,
                recovery,
                Some(BootIsolationOverride::TotalMicrovmOnce),
                &mut bytes,
            )
        }
        .unwrap();
        (bytes, length)
    }

    #[test]
    fn hosted_recovery_source_is_independent_of_the_decoded_handoff_epoch() {
        let (release, release_length, key_id, _) = configuration_release_records();
        let mut release_output = [0; mrml_package_format::MAX_SYSTEM_RELEASE_BYTES];
        let (current_bytes, current_length) = hosted_total_handoff(8, Some([0x51; 16]), 14);
        let current = BootHandoff::decode(&current_bytes[..current_length], |_| {}).unwrap();
        // SAFETY: this is the controlled hosted fixture named by the helper's
        // contract; it does not represent owner presence or durable hardware.
        let total = unsafe {
            hosted_recovery_probe::recover_total_control_plane::<1>(
                &current,
                &release[..release_length],
                &key_id,
                &mut release_output,
            )
        }
        .unwrap();
        assert_eq!(
            total
                .installed_admission()
                .installed()
                .descriptor()
                .block_size(),
            4096
        );
        assert_eq!(
            total.installed_admission().installed().header().volume(),
            total.installed_admission().recovery_volume()
        );
        assert_eq!(
            total.installed_admission().installed().active_superblock(),
            total
                .installed_admission()
                .installed()
                .header()
                .primary_superblock()
        );
        assert_eq!(total.installed_admission().recovery_root_generation(), 14);
        assert_eq!(total.policy().authority_epoch(), 9);
        assert_eq!(total.policy().boot_accepted_epoch(), 8);
        let deployment_recovery = total.deployment().recovery();
        assert_eq!(deployment_recovery.epoch(), 1);
        assert_eq!(
            deployment_recovery.volume(),
            Some(VolumeId::new([0x51; 16]).unwrap())
        );
        assert_eq!(deployment_recovery.file_object(), 11);
        assert_eq!(deployment_recovery.file_generation(), 2);
        let activated = deployment_recovery.active().unwrap();
        assert_eq!(activated.source_object(), 12);
        assert_eq!(activated.source_generation(), 2);

        // A substituted release fails before a joined owner is returned.
        let mut substituted_release = release.clone();
        substituted_release[release_length - 1] ^= 1;
        assert!(matches!(
            unsafe {
                hosted_recovery_probe::recover_total_control_plane::<1>(
                    &current,
                    &substituted_release[..release_length],
                    &key_id,
                    &mut release_output,
                )
            },
            Err(hosted_recovery_probe::HostedRecoveryProbeBuildError::Probe(
                hosted_recovery_probe::HostedRecoveryProbeError::Deployment
            ))
        ));

        let (stale_bytes, stale_length) = hosted_total_handoff(7, Some([0x51; 16]), 14);
        let stale = BootHandoff::decode(&stale_bytes[..stale_length], |_| {}).unwrap();
        // SAFETY: same controlled hosted fixture; the stale handoff must not
        // redefine its independently fixed authenticated recovery state.
        assert!(
            unsafe {
                hosted_recovery_probe::recover_total_control_plane::<1>(
                    &stale,
                    &release[..release_length],
                    &key_id,
                    &mut release_output,
                )
            }
            .is_err()
        );

        let (wrong_root_bytes, wrong_root_length) = hosted_total_handoff(8, Some([0x51; 16]), 13);
        let wrong_root =
            BootHandoff::decode(&wrong_root_bytes[..wrong_root_length], |_| {}).unwrap();
        assert!(matches!(
            unsafe {
                hosted_recovery_probe::recover_total_control_plane::<1>(
                    &wrong_root,
                    &release[..release_length],
                    &key_id,
                    &mut release_output,
                )
            },
            Err(hosted_recovery_probe::HostedRecoveryProbeBuildError::Probe(
                hosted_recovery_probe::HostedRecoveryProbeError::RecoveryRootMismatch
            ))
        ));
    }

    #[test]
    fn hosted_recovery_distinct_policy_binds_every_release_member_to_its_own_domain() {
        let (release, release_length, key_id, _) = two_domain_release_records();
        let mut release_output = [0; mrml_package_format::MAX_SYSTEM_RELEASE_BYTES];
        let (handoff_bytes, handoff_length) = hosted_total_handoff(8, Some([0x51; 16]), 14);
        let handoff = BootHandoff::decode(&handoff_bytes[..handoff_length], |_| {}).unwrap();
        // SAFETY: this is the helper's private controlled hosted fixture. It
        // establishes no owner presence, durable recovery, or backend guest.
        let total = unsafe {
            hosted_recovery_probe::recover_distinct_total_control_plane(
                &handoff,
                &release[..release_length],
                &key_id,
                &mut release_output,
            )
        }
        .unwrap();
        let entries: std::vec::Vec<_> = total
            .installed_admission()
            .release()
            .release()
            .entries()
            .collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].domain(),
            hosted_recovery_probe::HOSTED_TOTAL_COMPONENT_DOMAIN
        );
        assert_eq!(
            entries[1].domain(),
            hosted_recovery_probe::HOSTED_TOTAL_SECONDARY_DOMAIN
        );
        assert_ne!(entries[0].domain(), entries[1].domain());
        assert_eq!(total.admission().running().count(), 0);
        assert!(matches!(
            total.authorize_runtime(),
            Err(mrml_kernel::TotalMicrovmRuntimeError::RequiredDomainMissing)
        ));
    }

    const SYSTEM_GENERATION: u64 = 108;

    type TestPolicySubstrate = AccountedPolicyServiceSubstrate<2, 4, 2, 3, 2>;

    #[derive(Default)]
    struct NativePlacementProbe {
        launches: usize,
    }

    impl NativeConfigurationServiceLauncher for NativePlacementProbe {
        type Endpoint = u64;
        type Error = ();

        fn launch_native(
            &mut self,
            spec: IsolationServiceSpec,
        ) -> Result<Self::Endpoint, (IsolationUnavailableReason, Self::Error)> {
            self.launches += 1;
            Ok(0x1000 | spec.provider_generation())
        }

        fn revoke_native(&mut self, _endpoint: &Self::Endpoint) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MicrovmPlacementProbe {
        launches: usize,
        unavailable: bool,
    }

    #[derive(Default)]
    struct NativeAddressSpaceEraser {
        attempts: usize,
        fail_first: bool,
        erased: Option<(TaskId, UserContext)>,
    }

    impl ServiceAddressSpaceEraser for NativeAddressSpaceEraser {
        type Error = ();

        fn erase(&mut self, task: TaskId, context: UserContext) -> Result<(), Self::Error> {
            self.attempts += 1;
            if self.fail_first && self.attempts == 1 {
                return Err(());
            }
            self.erased = Some((task, context));
            Ok(())
        }
    }

    impl MicrovmConfigurationServiceLauncher for MicrovmPlacementProbe {
        type Endpoint = u64;
        type Error = ();

        fn launch_microvm(
            &mut self,
            spec: IsolationServiceSpec,
        ) -> Result<Self::Endpoint, (IsolationUnavailableReason, Self::Error)> {
            self.launches += 1;
            if self.unavailable {
                Err((IsolationUnavailableReason::VmmResource, ()))
            } else {
                Ok(0x2000 | spec.provider_generation())
            }
        }

        fn revoke_microvm(&mut self, _endpoint: &Self::Endpoint) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct PreparedGuestFactoryProbe {
        preparations: usize,
        destructions: usize,
        fail_first_destruction: bool,
    }

    impl ConfigurationMicrovmFactory for PreparedGuestFactoryProbe {
        type Guest = IsolationServiceSpec;
        type Error = ();

        fn prepare(
            &mut self,
            spec: IsolationServiceSpec,
        ) -> Result<Self::Guest, (IsolationUnavailableReason, Self::Error)> {
            self.preparations += 1;
            Ok(spec)
        }

        fn destroy(&mut self, _guest: &mut Self::Guest) -> Result<(), Self::Error> {
            self.destructions += 1;
            if self.fail_first_destruction && self.destructions == 1 {
                return Err(());
            }
            Ok(())
        }
    }

    fn configuration_service_spec(placement: IsolationPlacement) -> IsolationServiceSpec {
        IsolationServiceSpec::new(
            ObjectId(0x434f_4e46_4947),
            ObjectId(0x434f_4e46_4947_0001),
            1,
            11,
            SYSTEM_GENERATION,
            5,
            TotalMicrovmClass::MicrovmEligible,
            placement,
        )
        .unwrap()
    }

    #[test]
    fn configuration_backend_preserves_binding_across_both_placements() {
        let mut native_admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, SYSTEM_GENERATION, 5)
                .unwrap();
        let mut native_backend = ConfigurationPlacementBackend::new(
            NativePlacementProbe::default(),
            MicrovmPlacementProbe::default(),
        );
        let native = route_isolation_service(
            &mut native_admission,
            &mut native_backend,
            configuration_service_spec(IsolationPlacement::NativeService),
        )
        .unwrap();
        assert_eq!(
            native.endpoint().placement(),
            IsolationPlacement::NativeService
        );
        assert_eq!(native.interface_generation(), 1);
        assert_eq!(native.provider_generation(), 11);
        assert_eq!(native.system_generation(), SYSTEM_GENERATION);
        let (native_probe, microvm_probe) = native_backend.into_parts();
        assert_eq!((native_probe.launches, microvm_probe.launches), (1, 0));

        let mut microvm_admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 5)
                .unwrap();
        let mut microvm_backend = ConfigurationPlacementBackend::new(
            NativePlacementProbe::default(),
            MicrovmPlacementProbe::default(),
        );
        let microvm = route_isolation_service(
            &mut microvm_admission,
            &mut microvm_backend,
            configuration_service_spec(IsolationPlacement::Microvm),
        )
        .unwrap();
        assert_eq!(microvm.endpoint().placement(), IsolationPlacement::Microvm);
        assert_eq!(microvm.interface(), native.interface());
        assert_eq!(
            microvm.interface_generation(),
            native.interface_generation()
        );
        assert_eq!(microvm.provider_generation(), native.provider_generation());
        let (native_probe, microvm_probe) = microvm_backend.into_parts();
        assert_eq!((native_probe.launches, microvm_probe.launches), (0, 1));
    }

    #[test]
    fn unavailable_configuration_microvm_never_invokes_native_launcher() {
        let mut admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 5)
                .unwrap();
        let mut backend = ConfigurationPlacementBackend::new(
            NativePlacementProbe::default(),
            MicrovmPlacementProbe {
                launches: 0,
                unavailable: true,
            },
        );
        assert!(matches!(
            route_isolation_service(
                &mut admission,
                &mut backend,
                configuration_service_spec(IsolationPlacement::Microvm),
            ),
            Err(mrml_kernel::IsolationServiceRouteError::Backend {
                reason: IsolationUnavailableReason::VmmResource,
                error: ConfigurationPlacementError::Microvm(()),
            })
        ));
        let (native_probe, microvm_probe) = backend.into_parts();
        assert_eq!((native_probe.launches, microvm_probe.launches), (0, 1));
        assert_eq!(admission.unavailable_domains().count(), 1);
        assert_eq!(admission.total_microvm_report().native_fallback, 0);
    }

    #[test]
    fn prepared_microvm_retains_exact_guest_until_confirmed_teardown() {
        let microvm = PreparedMicrovmConfigurationLauncher::new(PreparedGuestFactoryProbe {
            fail_first_destruction: true,
            ..PreparedGuestFactoryProbe::default()
        });
        let mut backend =
            ConfigurationPlacementBackend::new(NativePlacementProbe::default(), microvm);
        let mut admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 5)
                .unwrap();
        let routed = route_isolation_service(
            &mut admission,
            &mut backend,
            configuration_service_spec(IsolationPlacement::Microvm),
        )
        .unwrap();
        let endpoint = match routed.endpoint() {
            ConfigurationServiceEndpoint::Microvm(endpoint) => *endpoint,
            ConfigurationServiceEndpoint::Native(_) => panic!("wrong placement"),
        };
        assert_eq!(endpoint.launch_generation(), 1);
        assert_eq!(endpoint.domain(), ObjectId(0x434f_4e46_4947));
        assert_eq!(endpoint.interface(), routed.interface());
        assert_eq!(endpoint.interface_generation(), 1);
        assert_eq!(endpoint.provider_generation(), 11);
        assert_eq!(endpoint.policy_generation(), 5);
        assert_eq!(
            backend.microvm.active_guest(endpoint),
            Ok(&configuration_service_spec(IsolationPlacement::Microvm))
        );

        let mut wrong = endpoint;
        wrong.launch_generation += 1;
        assert_eq!(
            backend.microvm.active_guest_mut(wrong),
            Err(PreparedMicrovmConfigurationAccessError::WrongEndpoint)
        );
        assert_eq!(
            backend.revoke(&ConfigurationServiceEndpoint::Microvm(wrong)),
            Err(ConfigurationPlacementError::Microvm(
                PreparedMicrovmConfigurationError::WrongEndpoint
            ))
        );
        assert_eq!(backend.microvm.factory().destructions, 0);
        assert_eq!(
            backend.revoke(routed.endpoint()),
            Err(ConfigurationPlacementError::Microvm(
                PreparedMicrovmConfigurationError::Backend(())
            ))
        );
        assert_eq!(backend.microvm.active(), Some(endpoint));
        backend.revoke(routed.endpoint()).unwrap();
        assert_eq!(backend.microvm.active(), None);
        assert_eq!(backend.microvm.factory().destructions, 2);
        assert_eq!(backend.native.launches, 0);

        let replacement = backend
            .microvm
            .launch_microvm(configuration_service_spec(IsolationPlacement::Microvm))
            .unwrap();
        assert_eq!(replacement.launch_generation(), 2);
        assert_ne!(replacement, endpoint);
        assert_eq!(backend.microvm.factory().preparations, 2);
    }

    #[test]
    fn admitted_guest_transfer_rechecks_exact_binding_and_is_one_use() {
        let expected = configuration_service_spec(IsolationPlacement::Microvm);
        let mut factory = AdmittedConfigurationGuestFactory::new(expected, 0x55aa_u64);
        let different = IsolationServiceSpec::new(
            expected.domain(),
            expected.interface(),
            expected.interface_generation(),
            expected.provider_generation() + 1,
            expected.system_generation(),
            expected.policy_generation(),
            TotalMicrovmClass::MicrovmEligible,
            IsolationPlacement::Microvm,
        )
        .unwrap();
        assert_eq!(
            factory.prepare(different),
            Err((
                IsolationUnavailableReason::InterfaceTransport,
                AdmittedConfigurationGuestError::BindingMismatch
            ))
        );
        assert_eq!(factory.prepare(expected), Ok(0x55aa));
        assert_eq!(
            factory.prepare(expected),
            Err((
                IsolationUnavailableReason::VmmResource,
                AdmittedConfigurationGuestError::AlreadyConsumed
            ))
        );
    }

    #[test]
    fn supervised_native_configuration_launch_retries_exact_cleanup_before_revocation() {
        type NativeSubstrate = AccountedPolicyServiceSubstrate<1, 1, 1, 1, 1>;

        let pages = NativeSubstrate::required_pages().unwrap();
        let mut memory = MemoryPoolTable::<1, 1>::new(42).unwrap();
        let mut authorities = CapabilitySpace::<3>::new();
        let (pool, pool_capability) = memory
            .create_root(pages, 1, 0, MEMORY_POOL_RIGHTS, &mut authorities)
            .unwrap();
        let schema = SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(11)).unwrap();
        let substrate = NativeSubstrate::new(
            1_000,
            1,
            ObjectId(10),
            &[schema],
            pool,
            pool_capability,
            &mut memory,
            &mut authorities,
        )
        .unwrap();
        let context = UserContext::new(
            mrml_kernel::PhysAddr::new(0x20_0000).unwrap(),
            0x40_0000,
            0x7000_0000,
        )
        .unwrap();
        let native = SupervisedNativeConfigurationLauncher::new(
            substrate,
            NativeAddressSpaceEraser {
                fail_first: true,
                ..NativeAddressSpaceEraser::default()
            },
            Priority::NORMAL,
            context,
        );
        let mut backend =
            ConfigurationPlacementBackend::new(native, MicrovmPlacementProbe::default());
        let mut admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, SYSTEM_GENERATION, 5)
                .unwrap();
        let routed = route_isolation_service(
            &mut admission,
            &mut backend,
            configuration_service_spec(IsolationPlacement::NativeService),
        )
        .unwrap();
        let endpoint = match routed.endpoint() {
            ConfigurationServiceEndpoint::Native(endpoint) => *endpoint,
            ConfigurationServiceEndpoint::Microvm(_) => panic!("wrong placement"),
        };
        assert_eq!(endpoint.domain(), ObjectId(0x434f_4e46_4947));
        assert_eq!(endpoint.interface(), routed.interface());
        assert!(matches!(
            backend.revoke(routed.endpoint()),
            Err(ConfigurationPlacementError::Native(
                NativeConfigurationLaunchError::Cleanup(ServiceCleanupError::Eraser(()))
            ))
        ));
        assert_eq!(
            backend.native.active(),
            Some(endpoint),
            "uncertain cleanup must retain the endpoint for exact retry"
        );
        backend.revoke(routed.endpoint()).unwrap();
        let (native, _) = backend.into_parts();
        assert_eq!(native.active(), None);
        assert_eq!(native.eraser().attempts, 2);
        assert_eq!(native.eraser().erased, Some((endpoint.task(), context)));
        assert_eq!(
            native.substrate().supervisor().state(endpoint.service()),
            Ok(ServiceState::Exited)
        );
        assert_eq!(
            native
                .substrate()
                .supervisor()
                .pending_cleanup(endpoint.service()),
            Ok(None)
        );
        assert_eq!(
            native.substrate().runtime().context(endpoint.task()),
            Err(TaskRuntimeError::MissingTask)
        );
    }

    #[test]
    fn policy_substrate_uses_one_exact_aggregate_commitment_for_all_components() {
        let pages = TestPolicySubstrate::required_pages().unwrap();
        let mut memory = MemoryPoolTable::<1, 1>::new(32).unwrap();
        let mut authorities = CapabilitySpace::<3>::new();
        let (pool, pool_capability) = memory
            .create_root(pages, 1, 0, MEMORY_POOL_RIGHTS, &mut authorities)
            .unwrap();
        let schema = SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(11)).unwrap();
        let mut substrate = TestPolicySubstrate::new(
            1_000,
            1,
            ObjectId(10),
            &[schema],
            pool,
            pool_capability,
            &mut memory,
            &mut authorities,
        )
        .unwrap();
        assert_eq!(substrate.committed_pages(), pages);
        assert_eq!(memory.object_pool(substrate.charge()), Ok(pool));
        let usage = memory.usage(pool, pool_capability, &authorities).unwrap();
        assert_eq!((usage.committed_pages(), usage.live_objects()), (pages, 1));
        assert_eq!(substrate.configuration().setting_count(), 1);
        let task = substrate
            .runtime_mut()
            .create(
                Priority::NORMAL,
                UserContext::new(
                    mrml_kernel::PhysAddr::new(0x20_0000).unwrap(),
                    0x40_0000,
                    0x7000_0000,
                )
                .unwrap(),
            )
            .unwrap();
        let service = substrate
            .supervisor_mut()
            .register(ObjectId(0x90), task)
            .unwrap();
        assert_eq!(
            substrate.supervisor().state(service),
            Ok(ServiceState::Running)
        );
        assert_eq!(
            memory
                .usage(pool, pool_capability, &authorities)
                .unwrap()
                .committed_pages(),
            pages
        );
    }

    #[test]
    fn policy_substrate_failure_is_atomic_and_empty_release_returns_one_charge() {
        let pages = TestPolicySubstrate::required_pages().unwrap();
        assert!(pages > 1);
        let mut memory = MemoryPoolTable::<1, 1>::new(33).unwrap();
        let mut authorities = CapabilitySpace::<3>::new();
        let (pool, pool_capability) = memory
            .create_root(pages - 1, 1, 0, MEMORY_POOL_RIGHTS, &mut authorities)
            .unwrap();
        let schema = SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(11)).unwrap();
        assert!(matches!(
            TestPolicySubstrate::new(
                1_000,
                1,
                ObjectId(10),
                &[schema],
                pool,
                pool_capability,
                &mut memory,
                &mut authorities,
            ),
            Err(AccountedPolicyServiceError::Memory(
                MemoryResourceError::PoolExhausted
            ))
        ));
        assert!(matches!(
            TestPolicySubstrate::new(
                0,
                1,
                ObjectId(10),
                &[schema],
                pool,
                pool_capability,
                &mut memory,
                &mut authorities,
            ),
            Err(AccountedPolicyServiceError::Runtime(_))
        ));
        assert!(matches!(
            TestPolicySubstrate::new(
                1_000,
                1,
                ObjectId(10),
                &[],
                pool,
                pool_capability,
                &mut memory,
                &mut authorities,
            ),
            Err(AccountedPolicyServiceError::Configuration(
                ConfigError::Capacity
            ))
        ));
        assert_eq!(
            memory
                .usage(pool, pool_capability, &authorities)
                .unwrap()
                .committed_pages(),
            0
        );

        let mut exact_memory = MemoryPoolTable::<1, 1>::new(34).unwrap();
        let mut exact_authorities = CapabilitySpace::<3>::new();
        let (exact_pool, exact_pool_capability) = exact_memory
            .create_root(pages, 1, 0, MEMORY_POOL_RIGHTS, &mut exact_authorities)
            .unwrap();
        let substrate = TestPolicySubstrate::empty(
            1_000,
            1,
            ObjectId(10),
            exact_pool,
            exact_pool_capability,
            &mut exact_memory,
            &mut exact_authorities,
        )
        .unwrap();
        assert!(matches!(
            unsafe { substrate.release(&mut exact_memory, &mut exact_authorities) },
            Ok(released) if released == pages
        ));
        assert_eq!(
            exact_memory
                .usage(exact_pool, exact_pool_capability, &exact_authorities)
                .unwrap()
                .committed_pages(),
            0
        );
    }

    #[test]
    fn accounted_configuration_charges_complete_state_until_consuming_release() {
        let pages = AccountedConfigurationService::<3, 2>::required_pages().unwrap();
        let mut memory = MemoryPoolTable::<1, 1>::new(26).unwrap();
        let mut authorities = CapabilitySpace::<3>::new();
        let (pool, pool_capability) = memory
            .create_root(pages, 1, 0, MEMORY_POOL_RIGHTS, &mut authorities)
            .unwrap();
        let schema = SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(11)).unwrap();
        let service = AccountedConfigurationService::<3, 2>::new(
            ObjectId(10),
            &[schema],
            pool,
            pool_capability,
            &mut memory,
            &mut authorities,
        )
        .unwrap();
        assert_eq!(service.setting_count(), 1);
        assert_eq!(service.committed_pages(), pages);
        assert_eq!(memory.object_pool(service.charge()), Ok(pool));
        assert_eq!(
            memory
                .usage(pool, pool_capability, &authorities)
                .unwrap()
                .committed_pages(),
            pages
        );
        assert!(matches!(
            service.release(&mut memory, &mut authorities),
            Ok(released) if released == pages
        ));
        assert_eq!(
            memory
                .usage(pool, pool_capability, &authorities)
                .unwrap()
                .committed_pages(),
            0
        );
    }

    #[test]
    fn configuration_validation_and_pool_exhaustion_never_publish_unaccounted_state() {
        let pages = AccountedConfigurationService::<64, 64>::required_pages().unwrap();
        assert!(pages > 1);
        let mut memory = MemoryPoolTable::<1, 1>::new(27).unwrap();
        let mut authorities = CapabilitySpace::<3>::new();
        let (pool, pool_capability) = memory
            .create_root(pages - 1, 1, 0, MEMORY_POOL_RIGHTS, &mut authorities)
            .unwrap();
        let schema = SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(11)).unwrap();
        assert!(matches!(
            AccountedConfigurationService::<64, 64>::new(
                ObjectId(10),
                &[schema],
                pool,
                pool_capability,
                &mut memory,
                &mut authorities,
            ),
            Err(AccountedConfigurationError::Memory(
                MemoryResourceError::PoolExhausted
            ))
        ));
        assert!(matches!(
            AccountedConfigurationService::<64, 64>::new(
                ObjectId(10),
                &[],
                pool,
                pool_capability,
                &mut memory,
                &mut authorities,
            ),
            Err(AccountedConfigurationError::Configuration(
                ConfigError::Capacity
            ))
        ));
        assert_eq!(
            memory
                .usage(pool, pool_capability, &authorities)
                .unwrap()
                .committed_pages(),
            0
        );
    }

    fn fixture() -> (
        ConfigurationService<3, 2>,
        CapabilitySpace<7>,
        Capability,
        Capability,
        Capability,
        Capability,
        Capability,
        Capability,
    ) {
        let enabled = SettingId::new(1).unwrap();
        let limit = SettingId::new(2).unwrap();
        let schemas = [
            SettingSchema::boolean(enabled, ObjectId(11)).unwrap(),
            SettingSchema::unsigned(limit, ObjectId(12), 1, 100).unwrap(),
        ];
        let service = ConfigurationService::new(ObjectId(10), &schemas).unwrap();
        let mut capabilities = CapabilitySpace::new();
        let root_control = capabilities.insert(ObjectId(10), Rights::CONTROL).unwrap();
        let root_read = capabilities.insert(ObjectId(10), Rights::READ).unwrap();
        let enabled_write = capabilities.insert(ObjectId(11), Rights::WRITE).unwrap();
        let enabled_read = capabilities.insert(ObjectId(11), Rights::READ).unwrap();
        let limit_write = capabilities.insert(ObjectId(12), Rights::WRITE).unwrap();
        let limit_read = capabilities.insert(ObjectId(12), Rights::READ).unwrap();
        (
            service,
            capabilities,
            root_control,
            root_read,
            enabled_write,
            enabled_read,
            limit_write,
            limit_read,
        )
    }

    #[test]
    fn atomic_commit_requires_root_and_each_exact_setting_capability() {
        let (mut service, mut capabilities, root, _, enabled, enabled_read, limit, limit_read) =
            fixture();
        let overbroad = capabilities
            .insert(ObjectId(11), Rights::READ.union(Rights::WRITE))
            .unwrap();
        assert_eq!(
            service.read(&capabilities, overbroad, SettingId::new(1).unwrap()),
            Err(ConfigError::Unauthorized(CapabilityError::PermissionDenied))
        );
        let mut transaction = ConfigTransaction::<2>::new(0);
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                enabled,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(2).unwrap(),
                limit,
                ConfigValue::unsigned(42),
            ))
            .unwrap();
        assert_eq!(service.commit(&capabilities, root, &transaction), Ok(1));
        assert_eq!(
            service
                .read(&capabilities, enabled_read, SettingId::new(1).unwrap())
                .unwrap()
                .value
                .and_then(ConfigValue::as_bool),
            Some(true)
        );
        assert_eq!(
            service
                .read(&capabilities, limit_read, SettingId::new(2).unwrap())
                .unwrap()
                .value
                .and_then(ConfigValue::as_u64),
            Some(42)
        );
    }

    #[test]
    fn late_schema_or_authority_failure_rolls_back_every_update() {
        let (mut service, capabilities, root, _, enabled, enabled_read, _, _) = fixture();
        let mut transaction = ConfigTransaction::<2>::new(0);
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                enabled,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(2).unwrap(),
                enabled,
                ConfigValue::unsigned(101),
            ))
            .unwrap();
        assert_eq!(
            service.commit(&capabilities, root, &transaction),
            Err(ConfigError::WrongObject)
        );
        assert_eq!(service.revision(), 0);
        assert_eq!(
            service
                .read(&capabilities, enabled_read, SettingId::new(1).unwrap())
                .unwrap()
                .value,
            None
        );
    }

    #[test]
    fn stale_revision_duplicate_setting_and_stale_capability_fail_closed() {
        let (mut service, mut capabilities, root, _, enabled, _, _, _) = fixture();
        let stale = enabled;
        capabilities.revoke(enabled).unwrap();
        let replacement = capabilities.insert(ObjectId(11), Rights::WRITE).unwrap();
        let mut stale_transaction = ConfigTransaction::<1>::new(0);
        stale_transaction
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                stale,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        assert!(matches!(
            service.commit(&capabilities, root, &stale_transaction),
            Err(ConfigError::Unauthorized(CapabilityError::Invalid))
        ));
        let mut duplicate = ConfigTransaction::<2>::new(0);
        for value in [true, false] {
            duplicate
                .push(ConfigUpdate::new(
                    SettingId::new(1).unwrap(),
                    replacement,
                    ConfigValue::boolean(value),
                ))
                .unwrap();
        }
        assert_eq!(
            service.commit(&capabilities, root, &duplicate),
            Err(ConfigError::DuplicateSetting)
        );
        assert_eq!(service.revision(), 0);
    }

    #[test]
    fn bounded_audit_reports_overwrite_gap_with_monotonic_sequence() {
        let (mut service, capabilities, root, root_read, enabled, _, _, _) = fixture();
        for revision in 0..3 {
            let mut transaction = ConfigTransaction::<1>::new(revision);
            transaction
                .push(ConfigUpdate::new(
                    SettingId::new(1).unwrap(),
                    enabled,
                    ConfigValue::boolean(revision % 2 == 0),
                ))
                .unwrap();
            service.commit(&capabilities, root, &transaction).unwrap();
        }
        assert_eq!(
            service.audit_event(&capabilities, root_read, 1),
            Err(ConfigError::AuditUnavailable { oldest: 2 })
        );
        assert_eq!(
            service.audit_event(&capabilities, root_read, 3).unwrap(),
            Some(AuditEvent {
                sequence: 3,
                revision: 3,
                setting: SettingId::new(1).unwrap(),
            })
        );
    }

    #[test]
    fn configuration_wire_is_canonical_bounded_and_pointer_free() {
        let (_, _, root, _, enabled, enabled_read, limit, _) = fixture();
        let mut read_wire = [0; CONFIG_REQUEST_HEADER_BYTES];
        encode_read_request(8, SettingId::new(1).unwrap(), enabled_read, &mut read_wire).unwrap();
        assert_eq!(
            ConfigurationRequest::decode(&read_wire),
            Ok(ConfigurationRequest::Read {
                request_id: 8,
                setting: SettingId::new(1).unwrap(),
                capability: enabled_read,
            })
        );
        let mut transaction = ConfigTransaction::<2>::new(7);
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                enabled,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(2).unwrap(),
                limit,
                ConfigValue::unsigned(9),
            ))
            .unwrap();
        let mut wire = [0xa5; MAX_CONFIG_REQUEST_BYTES];
        let length = encode_commit_request(9, root, &transaction, &mut wire).unwrap();
        let decoded = ConfigurationRequest::decode(&wire[..length]).unwrap();
        let ConfigurationRequest::Commit {
            request_id,
            root: decoded_root,
            transaction: decoded_transaction,
        } = decoded
        else {
            panic!("expected commit");
        };
        assert_eq!(request_id, 9);
        assert_eq!(decoded_root, root);
        assert_eq!(decoded_transaction.len(), 2);
        let mut malformed = wire;
        malformed[11] = 1;
        assert_eq!(
            ConfigurationRequest::decode(&malformed[..length]),
            Err(ConfigError::NonCanonical)
        );
        assert_eq!(
            ConfigurationRequest::decode(&wire[..length - 1]),
            Err(ConfigError::NonCanonical)
        );
    }

    #[test]
    fn kernel_message_authorities_replace_payload_tokens_and_dispatch_atomically() {
        let schemas = [
            SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(11)).unwrap(),
            SettingSchema::unsigned(SettingId::new(2).unwrap(), ObjectId(12), 1, 100).unwrap(),
        ];
        let mut service = ConfigurationService::<2, 2>::new(ObjectId(10), &schemas).unwrap();
        let context = |root, entry| {
            UserContext::new(
                mrml_kernel::PhysAddr::new(root).unwrap(),
                entry,
                0x7000_0000,
            )
            .unwrap()
        };
        let mut runtime = TaskRuntime::<2, 8>::new(1_000, 1).unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let endpoint_object = ObjectId(99);
        let sender_space = runtime.capabilities_mut(sender).unwrap();
        let endpoint_capability = sender_space
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let root = sender_space
            .insert(ObjectId(10), Rights::CONTROL.union(Rights::DELEGATE))
            .unwrap();
        let enabled = sender_space
            .insert(ObjectId(11), Rights::WRITE.union(Rights::DELEGATE))
            .unwrap();
        let limit = sender_space
            .insert(ObjectId(12), Rights::WRITE.union(Rights::DELEGATE))
            .unwrap();
        let mut transaction = ConfigTransaction::<2>::new(0);
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                enabled,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        transaction
            .push(ConfigUpdate::new(
                SettingId::new(2).unwrap(),
                limit,
                ConfigValue::unsigned(17),
            ))
            .unwrap();
        let mut wire = [0; MAX_CONFIG_REQUEST_BYTES];
        let length = encode_commit_message_request(21, &transaction, &mut wire).unwrap();
        assert!(wire[32..40].iter().all(|byte| *byte == 0));
        assert!(wire[56..64].iter().all(|byte| *byte == 0));
        assert!(wire[136..144].iter().all(|byte| *byte == 0));
        let mut endpoint = mrml_kernel::Endpoint::new(endpoint_object);
        let (_, message) = runtime
            .send_ipc(
                sender,
                receiver,
                &mut endpoint,
                endpoint_capability,
                &wire[..length],
                &[
                    (root, Rights::CONTROL),
                    (enabled, Rights::WRITE),
                    (limit, Rights::WRITE),
                ],
            )
            .unwrap();
        let mut delivered_authorities = message.capabilities();
        let delivered = [
            delivered_authorities.next().unwrap(),
            delivered_authorities.next().unwrap(),
            delivered_authorities.next().unwrap(),
        ];
        assert!(delivered_authorities.next().is_none());
        assert_ne!(delivered[0], root);
        let mut response_wire = [0; CONFIG_RESPONSE_BYTES];
        dispatch_configuration_message(
            &mut service,
            runtime.capabilities_mut(receiver).unwrap(),
            &message,
            &mut response_wire,
        )
        .unwrap();
        assert_eq!(
            ConfigurationResponse::decode(&response_wire)
                .unwrap()
                .status,
            ResponseStatus::Ok
        );
        assert_eq!(service.revision(), 1);

        let extra = Message::new(
            &wire[..length],
            &[delivered[0], delivered[1], delivered[2], delivered[0]],
        )
        .unwrap();
        assert_eq!(
            ConfigurationRequest::decode_message(&extra),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        let mut forged = wire;
        forged[32] = 1;
        let forged = Message::new(&forged[..length], &delivered).unwrap();
        assert_eq!(
            ConfigurationRequest::decode_message(&forged),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
    }

    #[test]
    fn message_dispatch_represents_an_authorized_unset_value() {
        let (mut service, capabilities, _, _, _, enabled, _, _) = fixture();
        let mut wire = [0; CONFIG_REQUEST_HEADER_BYTES];
        encode_read_message_request(22, SettingId::new(1).unwrap(), &mut wire).unwrap();
        let message = Message::new(&wire, &[enabled]).unwrap();
        let mut response_wire = [0; CONFIG_RESPONSE_BYTES];
        dispatch_configuration_message(&mut service, &capabilities, &message, &mut response_wire)
            .unwrap();
        assert_eq!(
            ConfigurationResponse::decode(&response_wire),
            Ok(ConfigurationResponse {
                request_id: 22,
                status: ResponseStatus::Ok,
                revision: 0,
                setting: Some(SettingId::new(1).unwrap()),
                value: None,
            })
        );
    }

    #[test]
    fn supervision_wire_binds_generation_authority_time_and_version() {
        let (_, _, root, _, _, _, _, _) = fixture();
        let request = SupervisionRequest {
            operation: SupervisionOperation::Restart,
            request_id: 4,
            service: ServiceId::from_token((3u64 << 32) | 2),
            capability: root,
            setting: None,
            setting_capability: Capability::from_token(0),
        };
        let mut wire = [0; SUPERVISION_REQUEST_BYTES];
        request.encode(&mut wire).unwrap();
        assert_eq!(SupervisionRequest::decode(&wire), Ok(request));
        wire[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            SupervisionRequest::decode(&wire),
            Err(ConfigError::UnsupportedVersion)
        );
        wire[4..6].copy_from_slice(&SYSTEM_PROTOCOL_VERSION.to_le_bytes());
        wire[12] = 1;
        assert_eq!(
            SupervisionRequest::decode(&wire),
            Err(ConfigError::NonCanonical)
        );
        wire[12] = 0;
        wire[40..48].copy_from_slice(&99u64.to_le_bytes());
        assert_eq!(
            SupervisionRequest::decode(&wire),
            Err(ConfigError::NonCanonical)
        );

        let response = SupervisionResponse {
            request_id: 4,
            status: ResponseStatus::Ok,
            service: request.service,
            state: SupervisionState::Faulted,
            detail: 123,
        };
        let mut response_wire = [0; SUPERVISION_RESPONSE_BYTES];
        response.encode(&mut response_wire).unwrap();
        assert_eq!(SupervisionResponse::decode(&response_wire), Ok(response));
        response_wire[47] = 1;
        assert_eq!(
            SupervisionResponse::decode(&response_wire),
            Err(ConfigError::NonCanonical)
        );
    }

    #[test]
    fn supervision_message_uses_derived_control_and_trusted_restart_context() {
        struct Eraser;
        impl mrml_kernel::ServiceAddressSpaceEraser for Eraser {
            type Error = ();

            fn erase(&mut self, _: mrml_kernel::TaskId, _: UserContext) -> Result<(), Self::Error> {
                Ok(())
            }
        }

        fn context(root: u64, entry: u64) -> UserContext {
            UserContext::new(
                mrml_kernel::PhysAddr::new(root).unwrap(),
                entry,
                0x7000_0000,
            )
            .unwrap()
        }

        let object = ObjectId(70);
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 1).unwrap();
        let task = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        runtime.start();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let retired_service = supervisor.register(object, task).unwrap();
        let retirement = supervisor.exit_current(&mut runtime).unwrap();
        supervisor
            .complete_cleanup(retirement.cleanup, &mut Eraser)
            .unwrap();
        let mut management = CapabilitySpace::<1>::new();
        let control = management.insert(object, Rights::CONTROL).unwrap();
        let request = SupervisionRequest {
            operation: SupervisionOperation::Restart,
            request_id: 31,
            service: retired_service,
            capability: control,
            setting: None,
            setting_capability: Capability::from_token(0),
        };
        let mut request_wire = [0; SUPERVISION_REQUEST_BYTES];
        request.encode_message(&mut request_wire).unwrap();
        assert!(request_wire[32..40].iter().all(|byte| *byte == 0));
        let message = Message::new(&request_wire, &[control]).unwrap();
        let fresh = context(0x30_0000, 0x50_0000);
        let mut response_wire = [0; SUPERVISION_RESPONSE_BYTES];
        dispatch_supervision_message(
            &mut supervisor,
            &management,
            &mut runtime,
            &message,
            Priority::RESPONSIVE,
            fresh,
            0,
            &mut response_wire,
        )
        .unwrap();
        let response = SupervisionResponse::decode(&response_wire).unwrap();
        assert_eq!(response.status, ResponseStatus::Ok);
        assert_eq!(response.state, SupervisionState::Running);
        assert_ne!(response.service, retired_service);
        assert_eq!(
            supervisor.state(response.service),
            Ok(ServiceState::Running)
        );
        assert_eq!(
            runtime.context(supervisor.task(response.service).unwrap().unwrap()),
            Ok(&fresh)
        );

        let forged = Message::new(&request_wire, &[]).unwrap();
        assert_eq!(
            SupervisionRequest::decode_message(&forged),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
    }

    #[test]
    fn supervision_query_envelope_uses_only_delivered_read_authority() {
        struct QueryAuthorizer {
            capability: Capability,
            service: ServiceId,
        }

        impl ServiceStateAuthorizer for QueryAuthorizer {
            fn query_state(
                &self,
                capability: Capability,
                service: ServiceId,
            ) -> Result<ServiceState, ConfigError> {
                if capability == self.capability && service == self.service {
                    Ok(ServiceState::Running)
                } else {
                    Err(ConfigError::Unauthorized(CapabilityError::PermissionDenied))
                }
            }
        }

        let capability = Capability::from_token((8u64 << 32) | 3);
        let service = ServiceId::from_token((4u64 << 32) | 2);
        let authorizer = QueryAuthorizer {
            capability,
            service,
        };
        let request = SupervisionRequest {
            operation: SupervisionOperation::Query,
            request_id: 52,
            service,
            capability: Capability::from_token(0),
            setting: None,
            setting_capability: Capability::from_token(0),
        };
        let mut wire = [0; SUPERVISION_REQUEST_BYTES];
        request.encode(&mut wire).unwrap();
        let mut response = [0; SUPERVISION_RESPONSE_BYTES];
        dispatch_supervision_query_envelope(&authorizer, &wire, &[capability], &mut response)
            .unwrap();
        assert_eq!(
            SupervisionResponse::decode(&response),
            Ok(SupervisionResponse {
                request_id: 52,
                status: ResponseStatus::Ok,
                service,
                state: SupervisionState::Running,
                detail: 0,
            })
        );

        assert_eq!(
            dispatch_supervision_query_envelope(&authorizer, &wire, &[], &mut response),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        assert_eq!(
            dispatch_supervision_query_envelope(
                &authorizer,
                &wire,
                &[capability, capability],
                &mut response,
            ),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        let mut forged = wire;
        forged[32..40].copy_from_slice(&capability.token().to_le_bytes());
        assert_eq!(
            dispatch_supervision_query_envelope(&authorizer, &forged, &[capability], &mut response,),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        let wrong = Capability::from_token((9u64 << 32) | 3);
        dispatch_supervision_query_envelope(&authorizer, &wire, &[wrong], &mut response).unwrap();
        let rejected = SupervisionResponse::decode(&response).unwrap();
        assert_eq!(rejected.status, ResponseStatus::Rejected);
        assert_eq!(rejected.state, SupervisionState::Exited);
        assert_eq!(rejected.detail, 0);
    }

    #[test]
    fn userspace_supervision_dispatch_refuses_restart_requests() {
        struct RejectAll;
        impl ServiceStateAuthorizer for RejectAll {
            fn query_state(
                &self,
                _: Capability,
                _: ServiceId,
            ) -> Result<ServiceState, ConfigError> {
                panic!("restart must be rejected before querying the kernel")
            }
        }

        let capability = Capability::from_token((2u64 << 32) | 1);
        let mut wire = [0; SUPERVISION_REQUEST_BYTES];
        SupervisionRequest {
            operation: SupervisionOperation::Restart,
            request_id: 53,
            service: ServiceId::from_token((3u64 << 32) | 1),
            capability: Capability::from_token(0),
            setting: None,
            setting_capability: Capability::from_token(0),
        }
        .encode(&mut wire)
        .unwrap();
        let mut response = [0; SUPERVISION_RESPONSE_BYTES];
        assert_eq!(
            dispatch_supervision_query_envelope(&RejectAll, &wire, &[capability], &mut response),
            Err(ConfigError::InvalidProtocol)
        );
    }

    #[test]
    fn supervision_restart_envelope_uses_only_delivered_control_authority() {
        struct RestartAuthorizer {
            capability: Capability,
            retired: ServiceId,
            replacement: ServiceId,
        }

        impl ServiceRestartAuthorizer for RestartAuthorizer {
            fn restart_service(
                &self,
                capability: Capability,
                service: ServiceId,
            ) -> Result<ServiceId, ConfigError> {
                if capability == self.capability && service == self.retired {
                    Ok(self.replacement)
                } else {
                    Err(ConfigError::Unauthorized(CapabilityError::PermissionDenied))
                }
            }
        }

        let capability = Capability::from_token((11u64 << 32) | 2);
        let retired = ServiceId::from_token((7u64 << 32) | 1);
        let replacement = ServiceId::from_token((7u64 << 32) | 2);
        let authorizer = RestartAuthorizer {
            capability,
            retired,
            replacement,
        };
        let request = SupervisionRequest {
            operation: SupervisionOperation::Restart,
            request_id: 54,
            service: retired,
            capability: Capability::from_token(0),
            setting: None,
            setting_capability: Capability::from_token(0),
        };
        let mut wire = [0; SUPERVISION_REQUEST_BYTES];
        request.encode(&mut wire).unwrap();
        let mut response = [0; SUPERVISION_RESPONSE_BYTES];
        dispatch_supervision_restart_envelope(&authorizer, &wire, &[capability], &mut response)
            .unwrap();
        assert_eq!(
            SupervisionResponse::decode(&response),
            Ok(SupervisionResponse {
                request_id: 54,
                status: ResponseStatus::Ok,
                service: replacement,
                state: SupervisionState::Running,
                detail: 0,
            })
        );

        assert_eq!(
            dispatch_supervision_restart_envelope(&authorizer, &wire, &[], &mut response),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        assert_eq!(
            dispatch_supervision_restart_envelope(
                &authorizer,
                &wire,
                &[capability, capability],
                &mut response,
            ),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        let mut forged = wire;
        forged[32..40].copy_from_slice(&capability.token().to_le_bytes());
        assert_eq!(
            dispatch_supervision_restart_envelope(
                &authorizer,
                &forged,
                &[capability],
                &mut response,
            ),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );

        let wrong = Capability::from_token((12u64 << 32) | 2);
        dispatch_supervision_restart_envelope(&authorizer, &wire, &[wrong], &mut response).unwrap();
        assert_eq!(
            SupervisionResponse::decode(&response),
            Ok(SupervisionResponse {
                request_id: 54,
                status: ResponseStatus::Rejected,
                service: retired,
                state: SupervisionState::Exited,
                detail: 0,
            })
        );
    }

    #[test]
    fn restart_dispatch_refuses_query_before_calling_the_authorizer() {
        struct RejectAll;
        impl ServiceRestartAuthorizer for RejectAll {
            fn restart_service(
                &self,
                _: Capability,
                _: ServiceId,
            ) -> Result<ServiceId, ConfigError> {
                panic!("query must be rejected before requesting a restart")
            }
        }

        let capability = Capability::from_token((13u64 << 32) | 1);
        let mut wire = [0; SUPERVISION_REQUEST_BYTES];
        SupervisionRequest {
            operation: SupervisionOperation::Query,
            request_id: 55,
            service: ServiceId::from_token((8u64 << 32) | 1),
            capability: Capability::from_token(0),
            setting: None,
            setting_capability: Capability::from_token(0),
        }
        .encode(&mut wire)
        .unwrap();
        let mut response = [0; SUPERVISION_RESPONSE_BYTES];
        assert_eq!(
            dispatch_supervision_restart_envelope(&RejectAll, &wire, &[capability], &mut response),
            Err(ConfigError::InvalidProtocol)
        );
    }

    #[test]
    fn configuration_responses_round_trip_and_reject_hidden_tail_data() {
        let response = ConfigurationResponse {
            request_id: 7,
            status: ResponseStatus::Ok,
            revision: 3,
            setting: Some(SettingId::new(2).unwrap()),
            value: Some(ConfigValue::unsigned(44)),
        };
        let mut wire = [0; CONFIG_RESPONSE_BYTES];
        response.encode(&mut wire).unwrap();
        assert_eq!(ConfigurationResponse::decode(&wire), Ok(response));
        wire[111] = 1;
        assert_eq!(
            ConfigurationResponse::decode(&wire),
            Err(ConfigError::NonCanonical)
        );

        let rejected = ConfigurationResponse {
            request_id: 8,
            status: ResponseStatus::Rejected,
            revision: 3,
            setting: None,
            value: None,
        };
        rejected.encode(&mut wire).unwrap();
        assert_eq!(ConfigurationResponse::decode(&wire), Ok(rejected));
    }

    #[test]
    fn schema_and_identifiers_reject_ambiguous_inputs() {
        assert_eq!(SettingId::new(0), Err(ConfigError::InvalidSetting));
        assert!(SettingSchema::unsigned(SettingId::new(1).unwrap(), ObjectId(1), 2, 1).is_err());
        let duplicate = [
            SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(1)).unwrap(),
            SettingSchema::bytes(SettingId::new(1).unwrap(), ObjectId(2), 8).unwrap(),
        ];
        assert!(matches!(
            ConfigurationService::<2, 1>::new(ObjectId(9), &duplicate),
            Err(ConfigError::DuplicateSetting)
        ));
        let aliases_root =
            [SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(9)).unwrap()];
        assert!(matches!(
            ConfigurationService::<1, 1>::new(ObjectId(9), &aliases_root),
            Err(ConfigError::DuplicateObject)
        ));
    }

    #[test]
    fn schema_admission_uses_only_root_authority_from_the_message_envelope() {
        let root_object = ObjectId(10);
        let schema = SettingSchema::boolean(SettingId::new(1).unwrap(), ObjectId(11)).unwrap();
        let mut service = ConfigurationService::<2, 2>::empty(root_object).unwrap();
        let mut capabilities = CapabilitySpace::<2>::new();
        let root = capabilities.insert(root_object, Rights::CONTROL).unwrap();
        let mut wire = [0; MAX_CONFIG_REQUEST_BYTES];
        let length = encode_schema_message_request(41, schema, &mut wire).unwrap();
        assert_eq!(length, CONFIG_REQUEST_HEADER_BYTES + CONFIG_SCHEMA_BYTES);
        assert!(wire[32..40].iter().all(|byte| *byte == 0));
        let message = Message::new(&wire[..length], &[root]).unwrap();
        assert_eq!(
            ConfigurationRequest::decode_message(&message),
            Ok(ConfigurationRequest::AdmitSchema {
                request_id: 41,
                root,
                schema,
            })
        );
        let mut response = [0; CONFIG_RESPONSE_BYTES];
        dispatch_configuration_message(&mut service, &capabilities, &message, &mut response)
            .unwrap();
        assert_eq!(service.setting_count(), 1);
        assert_eq!(
            ConfigurationResponse::decode(&response).unwrap(),
            ConfigurationResponse {
                request_id: 41,
                status: ResponseStatus::Ok,
                revision: 0,
                setting: Some(schema.setting()),
                value: None,
            }
        );

        let missing = Message::new(&wire[..length], &[]).unwrap();
        assert_eq!(
            ConfigurationRequest::decode_message(&missing),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        wire[CONFIG_REQUEST_HEADER_BYTES + 10] = 1;
        assert_eq!(
            ConfigurationRequest::decode(&wire[..length]),
            Err(ConfigError::NonCanonical)
        );
    }

    #[test]
    fn schema_admission_rejects_aliases_capacity_and_post_commit_mutation() {
        let root_object = ObjectId(20);
        let setting = SettingId::new(1).unwrap();
        let schema = SettingSchema::boolean(setting, ObjectId(21)).unwrap();
        let mut service = ConfigurationService::<1, 1>::empty(root_object).unwrap();
        let mut capabilities = CapabilitySpace::<2>::new();
        let root = capabilities.insert(root_object, Rights::CONTROL).unwrap();
        let write = capabilities.insert(ObjectId(21), Rights::WRITE).unwrap();
        service.admit_schema(&capabilities, root, schema).unwrap();
        assert_eq!(
            service.admit_schema(&capabilities, root, schema),
            Err(ConfigError::DuplicateObject)
        );
        let mut transaction = ConfigTransaction::<1>::new(0);
        transaction
            .push(ConfigUpdate::new(
                setting,
                write,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        service.commit(&capabilities, root, &transaction).unwrap();
        assert_eq!(
            service.admit_schema(
                &capabilities,
                root,
                SettingSchema::boolean(SettingId::new(2).unwrap(), ObjectId(22)).unwrap(),
            ),
            Err(ConfigError::SchemaFrozen)
        );
    }

    #[test]
    fn checkpoint_round_trip_preserves_schema_values_revisions_and_audit_window() {
        let (mut service, capabilities, root, root_read, enabled, enabled_read, limit, limit_read) =
            fixture();
        let mut first = ConfigTransaction::<2>::new(0);
        first
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                enabled,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        first
            .push(ConfigUpdate::new(
                SettingId::new(2).unwrap(),
                limit,
                ConfigValue::unsigned(42),
            ))
            .unwrap();
        service.commit(&capabilities, root, &first).unwrap();
        let mut second = ConfigTransaction::<1>::new(1);
        second
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                enabled,
                ConfigValue::boolean(false),
            ))
            .unwrap();
        service.commit(&capabilities, root, &second).unwrap();

        let mut bytes = [0; 512];
        let checkpoint = service
            .export_checkpoint(&capabilities, root_read, &mut bytes)
            .unwrap();
        assert_eq!(checkpoint.length, 368);
        let recovered = ConfigurationService::<3, 2>::recover_checkpoint(
            &capabilities,
            root,
            &bytes[..checkpoint.length],
            checkpoint.digest,
        )
        .unwrap();
        assert_eq!(recovered.revision(), 2);
        assert_eq!(recovered.setting_count(), 2);
        assert_eq!(
            recovered
                .read(&capabilities, enabled_read, SettingId::new(1).unwrap())
                .unwrap()
                .value
                .and_then(ConfigValue::as_bool),
            Some(false)
        );
        assert_eq!(
            recovered
                .read(&capabilities, limit_read, SettingId::new(2).unwrap())
                .unwrap()
                .value
                .and_then(ConfigValue::as_u64),
            Some(42)
        );
        assert_eq!(
            recovered.audit_event(&capabilities, root_read, 1),
            Err(ConfigError::AuditUnavailable { oldest: 2 })
        );
        assert_eq!(
            recovered.audit_event(&capabilities, root_read, 2).unwrap(),
            Some(AuditEvent {
                sequence: 2,
                revision: 1,
                setting: SettingId::new(2).unwrap(),
            })
        );
        assert_eq!(
            recovered.audit_event(&capabilities, root_read, 3).unwrap(),
            Some(AuditEvent {
                sequence: 3,
                revision: 2,
                setting: SettingId::new(1).unwrap(),
            })
        );

        let pages = AccountedConfigurationService::<3, 2>::required_pages().unwrap();
        let mut memory = MemoryPoolTable::<1, 1>::new(28).unwrap();
        let mut authorities = CapabilitySpace::<3>::new();
        let (pool, pool_capability) = memory
            .create_root(pages, 1, 0, MEMORY_POOL_RIGHTS, &mut authorities)
            .unwrap();
        let recovered = AccountedConfigurationService::<3, 2>::recover_checkpoint(
            &capabilities,
            root,
            &bytes[..checkpoint.length],
            checkpoint.digest,
            pool,
            pool_capability,
            &mut memory,
            &mut authorities,
        )
        .unwrap();
        assert_eq!((recovered.revision(), recovered.setting_count()), (2, 2));
        assert_eq!(recovered.committed_pages(), pages);
        assert!(matches!(
            recovered.release(&mut memory, &mut authorities),
            Ok(released) if released == pages
        ));
    }

    #[test]
    fn checkpoint_recovery_rejects_corruption_stale_digest_capacity_and_hidden_data() {
        let (service, capabilities, root, root_read, _, enabled, _, _) = fixture();
        let mut bytes = [0; 512];
        let checkpoint = service
            .export_checkpoint(&capabilities, root_read, &mut bytes)
            .unwrap();
        let input = &mut bytes[..checkpoint.length];
        input[CONFIG_CHECKPOINT_HEADER_BYTES + 48] ^= 1;
        assert!(matches!(
            ConfigurationService::<3, 2>::recover_checkpoint(
                &capabilities,
                root,
                input,
                checkpoint.digest,
            ),
            Err(ConfigError::InvalidCheckpoint)
        ));

        input[CONFIG_CHECKPOINT_HEADER_BYTES + 48] ^= 1;
        input[CONFIG_CHECKPOINT_HEADER_BYTES + 41] = 1;
        let digest = checkpoint_digest(input);
        input[CONFIG_CHECKPOINT_DIGEST_OFFSET
            ..CONFIG_CHECKPOINT_DIGEST_OFFSET + CONFIG_CHECKPOINT_DIGEST_BYTES]
            .copy_from_slice(&digest);
        assert!(matches!(
            ConfigurationService::<3, 2>::recover_checkpoint(&capabilities, root, input, digest,),
            Err(ConfigError::InvalidCheckpoint)
        ));
        input[CONFIG_CHECKPOINT_HEADER_BYTES + 41] = 0;
        let digest = checkpoint_digest(input);
        input[CONFIG_CHECKPOINT_DIGEST_OFFSET
            ..CONFIG_CHECKPOINT_DIGEST_OFFSET + CONFIG_CHECKPOINT_DIGEST_BYTES]
            .copy_from_slice(&digest);
        assert!(matches!(
            ConfigurationService::<1, 2>::recover_checkpoint(&capabilities, root, input, digest,),
            Err(ConfigError::Capacity)
        ));
        assert!(matches!(
            ConfigurationService::<3, 2>::recover_checkpoint(&capabilities, enabled, input, digest,),
            Err(ConfigError::Unauthorized(_))
        ));
    }

    const STABLE_BLOCK_BYTES: usize = 4096;
    const STABLE_BLOCK_COUNT: usize = 16;

    fn stable_volume() -> VolumeId {
        VolumeId::new([0x51; 16]).unwrap()
    }

    #[test]
    fn selected_configuration_root_requires_exact_authenticated_provenance() {
        let selected = stable_volume();
        let other = VolumeId::new([0x52; 16]).unwrap();
        assert!(recovery_root_matches(Some(selected), 9, selected, 9));
        assert!(!recovery_root_matches(Some(selected), 9, other, 9));
        assert!(!recovery_root_matches(Some(selected), 9, selected, 8));
        assert!(recovery_root_matches(None, 0, other, 8));
    }

    fn stable_header() -> VolumeHeader {
        VolumeHeader::new(stable_volume(), STABLE_BLOCK_BYTES as u32, 100, 1, 2).unwrap()
    }

    fn stable_object(local: u64) -> StorageObjectId {
        StorageObjectId::new(stable_volume(), local).unwrap()
    }

    fn stable_principal() -> StoragePrincipal {
        StoragePrincipal::new(7).unwrap()
    }

    fn stable_digest(bytes: &[u8]) -> [u8; 32] {
        let mut digest = Sha3_256::new();
        digest.update(bytes);
        digest.finalize()
    }

    struct StableBackend {
        bytes: [u8; STABLE_BLOCK_BYTES],
        staged: usize,
        flushed: usize,
        reads: usize,
        fail_read: bool,
        corrupt_read: bool,
    }

    unsafe impl FileWriteBackend for StableBackend {
        type Error = u8;

        fn stage_new_extent(
            &mut self,
            file: StorageObjectId,
            old_generation: u64,
            old_length: u64,
            next: ExtentRecord,
            new_length: u64,
            patch_offset: u64,
            patch: &[u8],
        ) -> Result<(), Self::Error> {
            if file != stable_object(9)
                || old_generation != 1
                || old_length != 0
                || next.file() != file
                || next.metadata_generation() != 2
                || next.physical_block() != Some(10)
                || next.block_count() != 1
                || patch_offset != 0
                || usize::try_from(new_length).ok() != Some(patch.len())
            {
                return Err(1);
            }
            self.bytes.fill(0);
            self.bytes[..patch.len()].copy_from_slice(patch);
            if next.content_digest() != stable_digest(&self.bytes) {
                return Err(2);
            }
            self.staged += 1;
            Ok(())
        }

        fn flush_new_file_data(
            &mut self,
            file: StorageObjectId,
            generation: u64,
            length: u64,
            content_digest: [u8; 32],
        ) -> Result<(), Self::Error> {
            let length = usize::try_from(length).map_err(|_| 3)?;
            if file != stable_object(9)
                || generation != 2
                || length > self.bytes.len()
                || content_digest != stable_digest(&self.bytes[..length])
            {
                return Err(3);
            }
            self.flushed += 1;
            Ok(())
        }
    }

    unsafe impl FileReadBackend for StableBackend {
        type Error = u8;

        fn read_verified_extent(
            &mut self,
            record: ExtentRecord,
            byte_offset: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            self.reads += 1;
            if self.fail_read {
                return Err(4);
            }
            if record.file() != stable_object(9)
                || record.metadata_generation() != 2
                || record.content_digest() != stable_digest(&self.bytes)
            {
                return Err(5);
            }
            let start = usize::try_from(byte_offset).map_err(|_| 5)?;
            let end = start.checked_add(output.len()).ok_or(5)?;
            output.copy_from_slice(self.bytes.get(start..end).ok_or(5)?);
            if self.corrupt_read && !output.is_empty() {
                output[0] ^= 1;
            }
            Ok(())
        }
    }

    struct CheckpointReadBackend {
        object: StorageObjectId,
        bytes: [u8; STABLE_BLOCK_BYTES],
    }

    unsafe impl FileReadBackend for CheckpointReadBackend {
        type Error = u8;

        fn read_verified_extent(
            &mut self,
            record: ExtentRecord,
            byte_offset: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            if record.file() != self.object
                || record.metadata_generation() != 2
                || record.content_digest() != stable_digest(&self.bytes)
            {
                return Err(1);
            }
            let start = usize::try_from(byte_offset).map_err(|_| 2)?;
            let end = start.checked_add(output.len()).ok_or(2)?;
            output.copy_from_slice(self.bytes.get(start..end).ok_or(2)?);
            Ok(())
        }
    }

    struct RecoveryStateStore {
        bytes: [u8; AUTHORITY_RECOVERY_STATE_BYTES],
    }

    impl RecoveryStateStore {
        fn new(epoch: u64, generation: u32, volume: VolumeId, root_generation: u64) -> Self {
            let mut bytes = [0; AUTHORITY_RECOVERY_STATE_BYTES];
            bytes[..16].copy_from_slice(b"MRML-AUTHSTATE1\0");
            bytes[16..24].copy_from_slice(&epoch.to_le_bytes());
            bytes[24..28].copy_from_slice(&generation.to_le_bytes());
            bytes[32..48].copy_from_slice(&volume.bytes());
            bytes[48..56].copy_from_slice(&root_generation.to_le_bytes());
            Self { bytes }
        }
    }

    impl AuthorityRecoveryStateStore for RecoveryStateStore {
        type Error = u8;

        fn load_authenticated(
            &self,
            output: &mut [u8; AUTHORITY_RECOVERY_STATE_BYTES],
        ) -> Result<(), Self::Error> {
            output.copy_from_slice(&self.bytes);
            Ok(())
        }

        fn compare_and_store(
            &mut self,
            expected: &[u8; AUTHORITY_RECOVERY_STATE_BYTES],
            replacement: &[u8; AUTHORITY_RECOVERY_STATE_BYTES],
        ) -> Result<(), Self::Error> {
            if self.bytes != *expected {
                return Err(2);
            }
            self.bytes.copy_from_slice(replacement);
            Ok(())
        }
    }

    fn checkpoint_file(
        object: StorageObjectId,
        length: usize,
        bytes: &[u8; STABLE_BLOCK_BYTES],
    ) -> FileState<1> {
        let extent = ExtentRecord::data(object, 2, 0, 1, 11, stable_digest(bytes)).unwrap();
        let extents = ExtentMap::build(
            stable_header(),
            object,
            2,
            u64::try_from(length).unwrap(),
            &[extent],
        )
        .unwrap();
        FileState::new(object, 2, u64::try_from(length).unwrap(), extents).unwrap()
    }

    struct PublicationBackend;

    unsafe impl CowPublicationBackend for PublicationBackend {
        type Error = ();

        fn verify_new_metadata(&mut self, _: CowMetadataWrite) -> Result<(), Self::Error> {
            Ok(())
        }

        fn flush_new_metadata(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        fn replace_superblock(
            &mut self,
            block: u64,
            _: &[u8; mrml_storage::SUPERBLOCK_BYTES],
        ) -> Result<(), Self::Error> {
            (block == 2).then_some(()).ok_or(())
        }

        fn flush_superblock(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum StableBlockError {
        WrongDevice,
        Range,
    }

    struct StableBlockBackend {
        bytes: [u8; STABLE_BLOCK_BYTES * STABLE_BLOCK_COUNT],
        device: BlockDeviceId,
        reads: usize,
        writes: usize,
        flushes: usize,
        replacements: usize,
    }

    impl StableBlockBackend {
        fn new(device: BlockDeviceId) -> Self {
            Self {
                bytes: [0; STABLE_BLOCK_BYTES * STABLE_BLOCK_COUNT],
                device,
                reads: 0,
                writes: 0,
                flushes: 0,
                replacements: 0,
            }
        }

        fn range(
            &self,
            device: BlockDeviceId,
            block: u64,
            length: usize,
        ) -> Result<core::ops::Range<usize>, StableBlockError> {
            if device != self.device {
                return Err(StableBlockError::WrongDevice);
            }
            let start = usize::try_from(block)
                .ok()
                .and_then(|value| value.checked_mul(STABLE_BLOCK_BYTES))
                .ok_or(StableBlockError::Range)?;
            let end = start.checked_add(length).ok_or(StableBlockError::Range)?;
            (end <= self.bytes.len())
                .then_some(start..end)
                .ok_or(StableBlockError::Range)
        }

        fn install_block(&mut self, block: u64, bytes: &[u8; STABLE_BLOCK_BYTES]) {
            let range = self.range(self.device, block, bytes.len()).unwrap();
            self.bytes[range].copy_from_slice(bytes);
        }
    }

    unsafe impl BlockServiceBackend for StableBlockBackend {
        type Error = StableBlockError;

        fn read_blocks(
            &mut self,
            device: BlockDeviceId,
            block: u64,
            output: &mut [u8],
        ) -> Result<(), Self::Error> {
            let range = self.range(device, block, output.len())?;
            output.copy_from_slice(&self.bytes[range]);
            self.reads += 1;
            Ok(())
        }

        fn write_blocks(
            &mut self,
            device: BlockDeviceId,
            block: u64,
            input: &[u8],
        ) -> Result<(), Self::Error> {
            let range = self.range(device, block, input.len())?;
            self.bytes[range].copy_from_slice(input);
            self.writes += 1;
            Ok(())
        }

        fn flush(&mut self, device: BlockDeviceId) -> Result<(), Self::Error> {
            if device != self.device {
                return Err(StableBlockError::WrongDevice);
            }
            self.flushes += 1;
            Ok(())
        }

        fn replace_superblock(
            &mut self,
            device: BlockDeviceId,
            block: u64,
            encoded: &[u8; mrml_storage::SUPERBLOCK_BYTES],
        ) -> Result<(), Self::Error> {
            let range = self.range(device, block, STABLE_BLOCK_BYTES)?;
            self.bytes[range.clone()].fill(0);
            self.bytes[range.start..range.start + encoded.len()].copy_from_slice(encoded);
            self.replacements += 1;
            Ok(())
        }
    }

    struct StableRecoveryDiscovery {
        candidates: [Option<DiscoveredRecoveryDevice>; 3],
        next: usize,
    }

    impl StableRecoveryDiscovery {
        fn new(candidates: &[DiscoveredRecoveryDevice]) -> Self {
            let mut stored = [None; 3];
            for (slot, candidate) in stored.iter_mut().zip(candidates.iter().copied()) {
                *slot = Some(candidate);
            }
            Self {
                candidates: stored,
                next: 0,
            }
        }
    }

    impl InstalledRecoveryDeviceDiscovery for StableRecoveryDiscovery {
        type Error = u8;

        fn next_candidate(&mut self) -> Result<Option<DiscoveredRecoveryDevice>, Self::Error> {
            let candidate = self.candidates.get(self.next).copied().flatten();
            self.next = self.next.saturating_add(1);
            Ok(candidate)
        }
    }

    fn discovered_recovery_device(
        device: BlockDeviceId,
        volume: VolumeId,
    ) -> DiscoveredRecoveryDevice {
        let header = VolumeHeader::new(
            volume,
            STABLE_BLOCK_BYTES as u32,
            stable_header().block_count(),
            stable_header().primary_superblock(),
            stable_header().secondary_superblock(),
        )
        .unwrap();
        DiscoveredRecoveryDevice::new(
            BlockDeviceDescriptor::new(device, STABLE_BLOCK_BYTES as u32, header.block_count())
                .unwrap(),
            header,
            header.primary_superblock(),
        )
        .unwrap()
    }

    fn platform_descriptor(
        descriptor: BlockDeviceDescriptor,
        media_generation: u64,
    ) -> PlatformBlockDeviceDescriptor {
        PlatformBlockDeviceDescriptor::new(
            descriptor,
            PlatformBlockDeviceIdentity::new(
                mrml_storage::PlatformBlockTransport::Hosted,
                [0x61; 32],
                1,
                media_generation,
            )
            .unwrap(),
        )
    }

    #[test]
    fn installed_recovery_discovery_is_bounded_unique_and_non_authorizing() {
        let device = BlockDeviceId::new(7).unwrap();
        let descriptor = BlockDeviceDescriptor::new(
            device,
            STABLE_BLOCK_BYTES as u32,
            stable_header().block_count(),
        )
        .unwrap();
        let platform = platform_descriptor(descriptor, 1);
        let mut service = BlockService::<1, 1>::new();
        service
            .register_platform_devices_atomic(&[platform])
            .unwrap();
        let [session] = service
            .grant_sessions_atomic([BlockSessionGrant::new(
                device,
                stable_principal(),
                BlockRights::READ,
            )])
            .unwrap();
        let candidate = discovered_recovery_device(device, stable_volume());
        let other = discovered_recovery_device(
            BlockDeviceId::new(8).unwrap(),
            VolumeId::new([0x72; 16]).unwrap(),
        );

        let mut exact = StableRecoveryDiscovery::new(&[other, candidate]);
        let selected = discover_installed_recovery_device::<_, 1, 1, 2>(
            &service,
            session,
            stable_principal(),
            stable_volume(),
            &mut exact,
        )
        .unwrap();
        assert_eq!(selected.descriptor(), descriptor);

        let mut missing = StableRecoveryDiscovery::new(&[other]);
        assert_eq!(
            discover_installed_recovery_device::<_, 1, 1, 2>(
                &service,
                session,
                stable_principal(),
                stable_volume(),
                &mut missing,
            ),
            Err(InstalledRecoveryDeviceDiscoveryError::Missing)
        );
        let duplicate = discovered_recovery_device(BlockDeviceId::new(9).unwrap(), stable_volume());
        let mut ambiguous = StableRecoveryDiscovery::new(&[candidate, duplicate]);
        assert_eq!(
            discover_installed_recovery_device::<_, 1, 1, 2>(
                &service,
                session,
                stable_principal(),
                stable_volume(),
                &mut ambiguous,
            ),
            Err(InstalledRecoveryDeviceDiscoveryError::Ambiguous)
        );
        let mut over_capacity = StableRecoveryDiscovery::new(&[other, candidate]);
        assert_eq!(
            discover_installed_recovery_device::<_, 1, 1, 1>(
                &service,
                session,
                stable_principal(),
                stable_volume(),
                &mut over_capacity,
            ),
            Err(InstalledRecoveryDeviceDiscoveryError::Capacity)
        );
        let mut no_capacity = StableRecoveryDiscovery::new(&[candidate]);
        assert_eq!(
            discover_installed_recovery_device::<_, 1, 1, 0>(
                &service,
                session,
                stable_principal(),
                stable_volume(),
                &mut no_capacity,
            ),
            Err(InstalledRecoveryDeviceDiscoveryError::Capacity)
        );
    }

    #[test]
    fn serviced_recovery_enumeration_reads_only_authorized_bounded_sessions() {
        let device = BlockDeviceId::new(7).unwrap();
        let header = stable_header();
        let descriptor =
            BlockDeviceDescriptor::new(device, STABLE_BLOCK_BYTES as u32, header.block_count())
                .unwrap();
        let platform = platform_descriptor(descriptor, 1);
        let mut service = BlockService::<1, 1>::new();
        service
            .register_platform_devices_atomic(&[platform])
            .unwrap();
        let [session] = service
            .grant_sessions_atomic([BlockSessionGrant::new(
                device,
                stable_principal(),
                BlockRights::READ,
            )])
            .unwrap();
        let mut backend = StableBlockBackend::new(device);
        let mut encoded_header = [0; mrml_storage::VOLUME_HEADER_BYTES];
        header.encode(&mut encoded_header);
        let mut header_block = [0; STABLE_BLOCK_BYTES];
        header_block[..encoded_header.len()].copy_from_slice(&encoded_header);
        backend.install_block(0, &header_block);
        let mut scratch = [0; STABLE_BLOCK_BYTES];
        let mut inventory = enumerate_serviced_recovery_devices::<_, 1, 1, 1>(
            &service,
            &mut backend,
            &[session],
            stable_principal(),
            &mut scratch,
        )
        .unwrap();
        assert_eq!(inventory.count(), 1);
        assert_eq!(backend.reads, 1);
        let selected = discover_installed_recovery_device::<_, 1, 1, 1>(
            &service,
            session,
            stable_principal(),
            stable_volume(),
            &mut inventory,
        )
        .unwrap();
        assert_eq!(selected.descriptor(), descriptor);
        assert_eq!(selected.header(), header);
        assert_eq!(selected.platform_identity(), Some(platform.identity()));

        let mut legacy_service = BlockService::<1, 1>::new();
        legacy_service.register_device(descriptor).unwrap();
        let legacy_session = legacy_service
            .grant(device, stable_principal(), BlockRights::READ)
            .unwrap();
        let mut legacy_backend = StableBlockBackend::new(device);
        assert!(matches!(
            enumerate_serviced_recovery_devices::<_, 1, 1, 1>(
                &legacy_service,
                &mut legacy_backend,
                &[legacy_session],
                stable_principal(),
                &mut scratch,
            ),
            Err(ServicedRecoveryDeviceInventoryError::MissingPlatformIdentity)
        ));
        assert_eq!(legacy_backend.reads, 0);

        let mut replaced_service = BlockService::<1, 1>::new();
        replaced_service
            .register_platform_devices_atomic(&[platform_descriptor(descriptor, 2)])
            .unwrap();
        let [replaced_session] = replaced_service
            .grant_sessions_atomic([BlockSessionGrant::new(
                device,
                stable_principal(),
                BlockRights::READ,
            )])
            .unwrap();
        let mut substituted = ServicedRecoveryDeviceInventory {
            candidates: [Some(
                DiscoveredRecoveryDevice::new_platform(
                    platform,
                    header,
                    header.primary_superblock(),
                )
                .unwrap(),
            )],
            count: 1,
            next: 0,
        };
        assert_eq!(
            discover_installed_recovery_device::<_, 1, 1, 1>(
                &replaced_service,
                replaced_session,
                stable_principal(),
                stable_volume(),
                &mut substituted,
            ),
            Err(InstalledRecoveryDeviceDiscoveryError::Selection(
                InstalledRecoveryDeviceSelectionError::DeviceMismatch
            ))
        );

        let mut denied_backend = StableBlockBackend::new(device);
        denied_backend.install_block(0, &header_block);
        let denied = enumerate_serviced_recovery_devices::<_, 1, 1, 1>(
            &service,
            &mut denied_backend,
            &[session],
            StoragePrincipal::new(8).unwrap(),
            &mut scratch,
        );
        assert!(matches!(
            denied,
            Err(ServicedRecoveryDeviceInventoryError::Session(
                BlockServiceError::Denied
            ))
        ));
        assert_eq!(denied_backend.reads, 0);

        let mut short_backend = StableBlockBackend::new(device);
        let mut short = [0; STABLE_BLOCK_BYTES - 1];
        assert!(matches!(
            enumerate_serviced_recovery_devices::<_, 1, 1, 1>(
                &service,
                &mut short_backend,
                &[session],
                stable_principal(),
                &mut short,
            ),
            Err(ServicedRecoveryDeviceInventoryError::Scratch)
        ));
        assert_eq!(short_backend.reads, 0);

        let mut corrupt_backend = StableBlockBackend::new(device);
        let mut corrupt = enumerate_serviced_recovery_devices::<_, 1, 1, 1>(
            &service,
            &mut corrupt_backend,
            &[session],
            stable_principal(),
            &mut scratch,
        )
        .unwrap();
        assert_eq!(corrupt.count(), 0);
        assert_eq!(corrupt_backend.reads, 1);
        assert_eq!(
            discover_installed_recovery_device::<_, 1, 1, 1>(
                &service,
                session,
                stable_principal(),
                stable_volume(),
                &mut corrupt,
            ),
            Err(InstalledRecoveryDeviceDiscoveryError::Missing)
        );
    }

    #[test]
    fn installed_recovery_device_selection_rejects_substitution_before_device_io() {
        let device = BlockDeviceId::new(7).unwrap();
        let descriptor = BlockDeviceDescriptor::new(
            device,
            STABLE_BLOCK_BYTES as u32,
            stable_header().block_count(),
        )
        .unwrap();
        let mut service = BlockService::<1, 1>::new();
        service.register_device(descriptor).unwrap();
        let session = service
            .grant(device, stable_principal(), BlockRights::READ)
            .unwrap();
        let backend = StableBlockBackend::new(device);
        let wrong_principal = StoragePrincipal::new(8).unwrap();
        assert!(matches!(
            InstalledRecoveryDeviceSelection::new(
                &service,
                session,
                wrong_principal,
                device,
                stable_header().volume(),
                stable_header(),
                stable_header().primary_superblock(),
            ),
            Err(InstalledRecoveryDeviceSelectionError::Session(
                BlockServiceError::Denied
            ))
        ));
        assert_eq!(backend.reads, 0);

        assert_eq!(
            InstalledRecoveryDeviceSelection::new(
                &service,
                session,
                stable_principal(),
                BlockDeviceId::new(8).unwrap(),
                stable_header().volume(),
                stable_header(),
                stable_header().primary_superblock(),
            ),
            Err(InstalledRecoveryDeviceSelectionError::DeviceMismatch)
        );
        let wrong_volume = VolumeId::new([0x82; 16]).unwrap();
        assert_eq!(
            InstalledRecoveryDeviceSelection::new(
                &service,
                session,
                stable_principal(),
                device,
                wrong_volume,
                stable_header(),
                stable_header().primary_superblock(),
            ),
            Err(InstalledRecoveryDeviceSelectionError::VolumeMismatch)
        );
        let wrong_geometry = VolumeHeader::new(
            stable_header().volume(),
            (STABLE_BLOCK_BYTES * 2) as u32,
            stable_header().block_count(),
            stable_header().primary_superblock(),
            stable_header().secondary_superblock(),
        )
        .unwrap();
        assert_eq!(
            InstalledRecoveryDeviceSelection::new(
                &service,
                session,
                stable_principal(),
                device,
                stable_header().volume(),
                wrong_geometry,
                wrong_geometry.primary_superblock(),
            ),
            Err(InstalledRecoveryDeviceSelectionError::GeometryMismatch)
        );
        assert_eq!(
            InstalledRecoveryDeviceSelection::new(
                &service,
                session,
                stable_principal(),
                device,
                stable_header().volume(),
                stable_header(),
                3,
            ),
            Err(InstalledRecoveryDeviceSelectionError::InvalidActiveRoot)
        );
        assert_eq!(backend.reads, 0);

        let selected = InstalledRecoveryDeviceSelection::new(
            &service,
            session,
            stable_principal(),
            device,
            stable_header().volume(),
            stable_header(),
            stable_header().primary_superblock(),
        )
        .unwrap();
        assert_eq!(selected.descriptor(), descriptor);
        assert_eq!(selected.header(), stable_header());
        assert_eq!(
            selected.active_superblock(),
            stable_header().primary_superblock()
        );

        service.revoke(session, stable_principal()).unwrap();
        assert!(matches!(
            InstalledRecoveryDeviceSelection::new(
                &service,
                session,
                stable_principal(),
                device,
                stable_header().volume(),
                stable_header(),
                stable_header().primary_superblock(),
            ),
            Err(InstalledRecoveryDeviceSelectionError::Session(
                BlockServiceError::StaleHandle
            ))
        ));
        assert_eq!(backend.reads, 0);
    }

    #[test]
    fn handoff_reacquisition_uses_selected_root_and_cleans_failed_session() {
        let device = BlockDeviceId::new(7).unwrap();
        let descriptor = BlockDeviceDescriptor::new(
            device,
            STABLE_BLOCK_BYTES as u32,
            stable_header().block_count(),
        )
        .unwrap();
        let identity =
            PlatformBlockDeviceIdentity::new(PlatformBlockTransport::Hosted, [0x41; 32], 3, 5)
                .unwrap();
        let platform = PlatformBlockDeviceDescriptor::new(descriptor, identity);
        let mut service = BlockService::<1, 1>::new();
        service
            .register_platform_devices_atomic(&[platform])
            .unwrap();
        let mut backend = StableBlockBackend::new(device);
        let mut encoded_header = [0; VOLUME_HEADER_BYTES];
        stable_header().encode(&mut encoded_header);
        backend.bytes[..VOLUME_HEADER_BYTES].copy_from_slice(&encoded_header);
        let boot = |root_block| {
            InstalledRecoveryBootIdentity::new(
                InstalledRecoverySource::Hosted,
                [0x41; 32],
                3,
                5,
                STABLE_BLOCK_BYTES as u32,
                stable_header().block_count(),
                stable_volume().bytes(),
                root_block,
                14,
            )
            .unwrap()
        };
        let mut scratch = [0xa5; STABLE_BLOCK_BYTES];
        assert_eq!(
            reacquire_handoff_installed_recovery_device(
                &mut service,
                &mut backend,
                boot(3),
                stable_principal(),
                &mut scratch,
            ),
            Err(HandoffInstalledRecoveryError::Selection(
                InstalledRecoveryDeviceSelectionError::InvalidActiveRoot
            ))
        );
        let selected = reacquire_handoff_installed_recovery_device(
            &mut service,
            &mut backend,
            boot(stable_header().primary_superblock()),
            stable_principal(),
            &mut scratch,
        )
        .unwrap();
        assert_eq!(selected.platform_identity(), Some(identity));
        assert_eq!(selected.header(), stable_header());
        assert_eq!(
            selected.active_superblock(),
            stable_header().primary_superblock()
        );
        assert_eq!(backend.reads, 2);
    }

    #[test]
    fn typed_sata_handoff_correlation_is_atomic_through_reacquisition() {
        let device = BlockDeviceId::new(7).unwrap();
        let descriptor = BlockDeviceDescriptor::new(
            device,
            STABLE_BLOCK_BYTES as u32,
            stable_header().block_count(),
        )
        .unwrap();
        let stable_id = [0x51; 32];
        let identity =
            PlatformBlockDeviceIdentity::new(PlatformBlockTransport::Ahci, stable_id, 3, 5)
                .unwrap();
        let candidate = PlatformBlockDeviceDescriptor::new(descriptor, identity);
        let boot = |root_block| {
            InstalledRecoveryBootIdentity::new(
                InstalledRecoverySource::Uefi,
                stable_id,
                3,
                5,
                STABLE_BLOCK_BYTES as u32,
                stable_header().block_count(),
                stable_volume().bytes(),
                root_block,
                14,
            )
            .unwrap()
        };
        let boot_hops = [mrml_kernel::InstalledRecoveryPciHop::new(5, 0).unwrap()];
        let boot_media =
            mrml_kernel::InstalledRecoveryHardDriveMedia::new(2, 2048, 4096, [0x6a; 16], 2, 2)
                .unwrap();
        let handoff_route = |hba_port| {
            InstalledRecoverySataRoute::new(
                0x0a03_41d0,
                0,
                &boot_hops,
                hba_port,
                u16::MAX,
                0,
                Some(boot_media),
                stable_id,
            )
            .unwrap()
        };
        let native_hops = [mrml_storage::CanonicalUefiPciHop::new(5, 0).unwrap()];
        let native_media =
            mrml_storage::CanonicalUefiHardDriveMedia::new(2, 2048, 4096, [0x6a; 16], 2, 2)
                .unwrap();
        let native_route = NativeSataBlockRoute::new(
            0x0a03_41d0,
            0,
            &native_hops,
            3,
            u16::MAX,
            0,
            Some(native_media),
        )
        .unwrap();

        let mut backend = StableBlockBackend::new(device);
        let mut encoded_header = [0; VOLUME_HEADER_BYTES];
        stable_header().encode(&mut encoded_header);
        backend.bytes[..VOLUME_HEADER_BYTES].copy_from_slice(&encoded_header);
        let mut scratch = [0xa5; STABLE_BLOCK_BYTES];
        let mut rejected = BlockService::<1, 1>::new();
        assert_eq!(
            correlate_and_reacquire_handoff_installed_sata_device(
                &mut rejected,
                &mut backend,
                boot(stable_header().primary_superblock()),
                handoff_route(4),
                native_route,
                candidate,
                stable_principal(),
                &mut scratch,
            ),
            Err(NativeSataHandoffRecoveryError::Correlation(
                NativeBlockCorrelationError::Correlation(
                    SataNativeBlockCorrelationError::NativeRouteMismatch
                )
            ))
        );
        assert_eq!(backend.reads, 0);
        assert_eq!(
            rejected.grant(device, stable_principal(), mrml_storage::BlockRights::READ),
            Err(BlockServiceError::UnknownDevice)
        );

        let mut invalid_root = BlockService::<1, 1>::new();
        assert_eq!(
            correlate_and_reacquire_handoff_installed_sata_device(
                &mut invalid_root,
                &mut backend,
                boot(3),
                handoff_route(3),
                native_route,
                candidate,
                stable_principal(),
                &mut scratch,
            ),
            Err(NativeSataHandoffRecoveryError::Reacquire(
                HandoffInstalledRecoveryError::Selection(
                    InstalledRecoveryDeviceSelectionError::InvalidActiveRoot
                )
            ))
        );
        assert_eq!(
            invalid_root.grant(device, stable_principal(), mrml_storage::BlockRights::READ),
            Err(BlockServiceError::UnknownDevice)
        );

        let mut service = BlockService::<1, 1>::new();
        let selected = correlate_and_reacquire_handoff_installed_sata_device(
            &mut service,
            &mut backend,
            boot(stable_header().primary_superblock()),
            handoff_route(3),
            native_route,
            candidate,
            stable_principal(),
            &mut scratch,
        )
        .unwrap();
        assert_eq!(selected.platform_identity(), Some(identity));
        assert_eq!(selected.header(), stable_header());
        assert_eq!(backend.reads, 2);
    }

    #[test]
    fn decoded_handoff_is_the_only_source_of_installed_sata_identity() {
        let framebuffer = mrml_kernel::FramebufferInfo::new(
            0xa0000,
            0x1000,
            16,
            16,
            16,
            mrml_kernel::PixelFormat::BlueGreenRedReserved,
        )
        .unwrap();
        let regions = [
            mrml_kernel::MemoryRegion::new(
                mrml_kernel::PhysAddr::new(0xa0000).unwrap(),
                1,
                mrml_kernel::MemoryKind::Mmio,
            )
            .unwrap(),
            mrml_kernel::MemoryRegion::new(
                mrml_kernel::PhysAddr::new(0x10_0000).unwrap(),
                64,
                mrml_kernel::MemoryKind::Reserved,
            )
            .unwrap(),
        ];
        let recovery =
            mrml_kernel::RecoveryStateMetadata::new(8, 1, Some(stable_volume().bytes()), 14)
                .unwrap();
        let stable_id = [0x51; 32];
        let boot = InstalledRecoveryBootIdentity::new(
            InstalledRecoverySource::Uefi,
            stable_id,
            3,
            5,
            STABLE_BLOCK_BYTES as u32,
            stable_header().block_count(),
            stable_volume().bytes(),
            stable_header().primary_superblock(),
            14,
        )
        .unwrap();
        let boot_hops = [mrml_kernel::InstalledRecoveryPciHop::new(5, 0).unwrap()];
        let boot_media =
            mrml_kernel::InstalledRecoveryHardDriveMedia::new(2, 2048, 4096, [0x6a; 16], 2, 2)
                .unwrap();
        let route = InstalledRecoverySataRoute::new(
            0x0a03_41d0,
            0,
            &boot_hops,
            3,
            u16::MAX,
            0,
            Some(boot_media),
            stable_id,
        )
        .unwrap();
        let mut handoff_bytes = [0; 512];
        let length = mrml_kernel::encode_handoff_with_recovery_isolation_installed_and_sata_route(
            7,
            [1; 32],
            [2; 64],
            true,
            true,
            false,
            true,
            0x9000,
            framebuffer,
            &regions,
            recovery,
            boot,
            route,
            Some(BootIsolationOverride::TotalMicrovmOnce),
            &mut handoff_bytes,
        )
        .unwrap();
        let handoff = BootHandoff::decode(&handoff_bytes[..length], |_| {}).unwrap();

        let device = BlockDeviceId::new(7).unwrap();
        let descriptor = BlockDeviceDescriptor::new(
            device,
            STABLE_BLOCK_BYTES as u32,
            stable_header().block_count(),
        )
        .unwrap();
        let identity =
            PlatformBlockDeviceIdentity::new(PlatformBlockTransport::Ahci, stable_id, 3, 5)
                .unwrap();
        let candidate = PlatformBlockDeviceDescriptor::new(descriptor, identity);
        let native_hops = [mrml_storage::CanonicalUefiPciHop::new(5, 0).unwrap()];
        let native_media =
            mrml_storage::CanonicalUefiHardDriveMedia::new(2, 2048, 4096, [0x6a; 16], 2, 2)
                .unwrap();
        let native = NativeSataBlockRoute::new(
            0x0a03_41d0,
            0,
            &native_hops,
            3,
            u16::MAX,
            0,
            Some(native_media),
        )
        .unwrap();
        let mut backend = StableBlockBackend::new(device);
        let mut encoded_header = [0; VOLUME_HEADER_BYTES];
        stable_header().encode(&mut encoded_header);
        backend.bytes[..VOLUME_HEADER_BYTES].copy_from_slice(&encoded_header);
        let mut scratch = [0xa5; STABLE_BLOCK_BYTES];
        let mut service = BlockService::<1, 1>::new();
        let selected = recover_decoded_handoff_installed_sata_device(
            &mut service,
            &mut backend,
            &handoff,
            native,
            candidate,
            stable_principal(),
            &mut scratch,
        )
        .unwrap();
        assert_eq!(selected.platform_identity(), Some(identity));
        assert_eq!(
            validate_installed_selection_for_handoff(selected, &handoff),
            Ok((stable_volume(), 14))
        );

        let mut identity_only_bytes = [0; 512];
        let identity_only_length =
            mrml_kernel::encode_handoff_with_recovery_isolation_and_installed(
                7,
                [1; 32],
                [2; 64],
                true,
                true,
                false,
                true,
                0x9000,
                framebuffer,
                &regions,
                recovery,
                boot,
                None,
                &mut identity_only_bytes,
            )
            .unwrap();
        let identity_only =
            BootHandoff::decode(&identity_only_bytes[..identity_only_length], |_| {}).unwrap();
        assert_eq!(
            validate_installed_selection_for_handoff(selected, &identity_only),
            Err(ConfigError::RecoveryHandoffMismatch)
        );
        let reads = backend.reads;
        let mut missing_route_service = BlockService::<1, 1>::new();
        assert_eq!(
            recover_decoded_handoff_installed_sata_device(
                &mut missing_route_service,
                &mut backend,
                &identity_only,
                native,
                candidate,
                stable_principal(),
                &mut scratch,
            ),
            Err(DecodedHandoffSataRecoveryError::MissingSataRoute)
        );
        assert_eq!(backend.reads, reads);

        let mut recovery_only_bytes = [0; 512];
        let recovery_only_length = mrml_kernel::encode_handoff_with_recovery_and_isolation(
            7,
            [1; 32],
            [2; 64],
            true,
            true,
            false,
            true,
            0x9000,
            framebuffer,
            &regions,
            recovery,
            None,
            &mut recovery_only_bytes,
        )
        .unwrap();
        let recovery_only =
            BootHandoff::decode(&recovery_only_bytes[..recovery_only_length], |_| {}).unwrap();
        assert_eq!(
            validate_installed_selection_for_handoff(selected, &recovery_only),
            Err(ConfigError::RecoveryHandoffMismatch)
        );
        assert_eq!(
            recover_decoded_handoff_installed_sata_device(
                &mut missing_route_service,
                &mut backend,
                &recovery_only,
                native,
                candidate,
                stable_principal(),
                &mut scratch,
            ),
            Err(DecodedHandoffSataRecoveryError::MissingInstalledIdentity)
        );
        assert_eq!(backend.reads, reads);
    }

    fn stable_layout(
        checkpoint: &[u8],
    ) -> (
        FileState<0>,
        ExtentMap<1>,
        FileMetadata,
        [CowMetadataImage; 2],
    ) {
        let header = stable_header();
        let object = stable_object(9);
        let current_extents = ExtentMap::<0>::build(header, object, 1, 0, &[]).unwrap();
        let current = FileState::new(object, 1, 0, current_extents).unwrap();
        let mut block = [0; STABLE_BLOCK_BYTES];
        block[..checkpoint.len()].copy_from_slice(checkpoint);
        let record = ExtentRecord::data(object, 2, 0, 1, 10, stable_digest(&block)).unwrap();
        let next = ExtentMap::build(header, object, 2, checkpoint.len() as u64, &[record]).unwrap();
        let metadata = FileMetadata::new(
            header,
            object,
            2,
            checkpoint.len() as u64,
            1,
            MetadataPointer::new(20, 1).unwrap(),
            stable_digest(checkpoint),
        )
        .unwrap();
        let mut encoded_metadata = [0; STABLE_BLOCK_BYTES];
        metadata.encode(
            (&mut encoded_metadata[..mrml_storage::FILE_METADATA_BYTES])
                .try_into()
                .unwrap(),
        );
        let mut encoded_extents = [0; STABLE_BLOCK_BYTES];
        record.encode(
            (&mut encoded_extents[..mrml_storage::EXTENT_RECORD_BYTES])
                .try_into()
                .unwrap(),
        );
        (
            current,
            next,
            metadata,
            [
                CowMetadataImage::new(
                    MetadataPointer::new(21, 1).unwrap(),
                    stable_digest(&encoded_metadata),
                ),
                CowMetadataImage::new(
                    MetadataPointer::new(20, 1).unwrap(),
                    stable_digest(&encoded_extents),
                ),
            ],
        )
    }

    fn publication_plan(images: [CowMetadataImage; 2]) -> CowPublicationPlan<4> {
        let header = stable_header();
        let root = stable_object(1);
        let active = Superblock::new(
            header,
            1,
            0,
            root,
            MetadataPointer::new(30, 1).unwrap(),
            MetadataPointer::new(31, 1).unwrap(),
        )
        .unwrap();
        let root_write =
            CowMetadataWrite::new(MetadataPointer::new(40, 1).unwrap(), 2, [0x40; 32]).unwrap();
        let allocation_write =
            CowMetadataWrite::new(MetadataPointer::new(41, 1).unwrap(), 2, [0x41; 32]).unwrap();
        CowPublicationPlan::build(
            header,
            1,
            active,
            root,
            root_write.pointer(),
            allocation_write.pointer(),
            &[
                images[0].bind(2).unwrap(),
                images[1].bind(2).unwrap(),
                root_write,
                allocation_write,
            ],
            &[
                MetadataPointer::new(30, 1).unwrap(),
                MetadataPointer::new(31, 1).unwrap(),
            ],
        )
        .unwrap()
    }

    fn block_stable_layout(
        checkpoint: &[u8],
        backend: &mut StableBlockBackend,
    ) -> (
        FileState<0>,
        ExtentMap<1>,
        FileMetadata,
        CowPublicationPlan<4>,
    ) {
        let header = stable_header();
        let object = stable_object(9);
        let current = FileState::new(
            object,
            1,
            0,
            ExtentMap::<0>::build(header, object, 1, 0, &[]).unwrap(),
        )
        .unwrap();
        let mut data = [0; STABLE_BLOCK_BYTES];
        data[..checkpoint.len()].copy_from_slice(checkpoint);
        let record = ExtentRecord::data(object, 2, 0, 1, 3, stable_digest(&data)).unwrap();
        let next = ExtentMap::build(header, object, 2, checkpoint.len() as u64, &[record]).unwrap();
        let metadata = FileMetadata::new(
            header,
            object,
            2,
            checkpoint.len() as u64,
            1,
            MetadataPointer::new(4, 1).unwrap(),
            stable_digest(checkpoint),
        )
        .unwrap();

        let mut extents = [0; STABLE_BLOCK_BYTES];
        record.encode(
            (&mut extents[..mrml_storage::EXTENT_RECORD_BYTES])
                .try_into()
                .unwrap(),
        );
        let mut file_metadata = [0; STABLE_BLOCK_BYTES];
        metadata.encode(
            (&mut file_metadata[..mrml_storage::FILE_METADATA_BYTES])
                .try_into()
                .unwrap(),
        );
        let root = [0x61; STABLE_BLOCK_BYTES];
        let allocation = [0x71; STABLE_BLOCK_BYTES];
        backend.install_block(4, &extents);
        backend.install_block(5, &file_metadata);
        backend.install_block(6, &root);
        backend.install_block(7, &allocation);

        let active = Superblock::new(
            header,
            1,
            0,
            stable_object(1),
            MetadataPointer::new(8, 1).unwrap(),
            MetadataPointer::new(9, 1).unwrap(),
        )
        .unwrap();
        let plan = CowPublicationPlan::build(
            header,
            1,
            active,
            stable_object(1),
            MetadataPointer::new(6, 1).unwrap(),
            MetadataPointer::new(7, 1).unwrap(),
            &[
                CowMetadataWrite::new(
                    MetadataPointer::new(5, 1).unwrap(),
                    2,
                    stable_digest(&file_metadata),
                )
                .unwrap(),
                CowMetadataWrite::new(
                    MetadataPointer::new(4, 1).unwrap(),
                    2,
                    stable_digest(&extents),
                )
                .unwrap(),
                CowMetadataWrite::new(MetadataPointer::new(6, 1).unwrap(), 2, stable_digest(&root))
                    .unwrap(),
                CowMetadataWrite::new(
                    MetadataPointer::new(7, 1).unwrap(),
                    2,
                    stable_digest(&allocation),
                )
                .unwrap(),
            ],
            &[
                MetadataPointer::new(8, 1).unwrap(),
                MetadataPointer::new(9, 1).unwrap(),
            ],
        )
        .unwrap();
        (current, next, metadata, plan)
    }

    #[test]
    fn stable_checkpoint_requires_both_capabilities_and_one_use_publication_receipt() {
        struct CountingAuthorizer<'a, const CAPS: usize> {
            inner: &'a CapabilitySpace<CAPS>,
            calls: core::cell::Cell<usize>,
        }

        impl<const CAPS: usize> CapabilityAuthorizer for CountingAuthorizer<'_, CAPS> {
            fn authorize_exact(
                &self,
                capability: Capability,
                rights: Rights,
                expected: ObjectId,
            ) -> Result<(), ConfigError> {
                self.calls.set(self.calls.get() + 1);
                <CapabilitySpace<CAPS> as CapabilityAuthorizer>::authorize_exact(
                    self.inner,
                    capability,
                    rights,
                    expected,
                )
            }
        }

        let (mut service, capabilities, root, root_read, enabled, enabled_read, _, _) = fixture();
        let mut update = ConfigTransaction::<1>::new(0);
        update
            .push(ConfigUpdate::new(
                SettingId::new(1).unwrap(),
                enabled,
                ConfigValue::boolean(true),
            ))
            .unwrap();
        service.commit(&capabilities, root, &update).unwrap();
        let mut expected = [0; 512];
        let checkpoint = service
            .export_checkpoint(&capabilities, root_read, &mut expected)
            .unwrap();
        let (current, next, metadata, images) = stable_layout(&expected[..checkpoint.length]);
        let mut authority = StorageAuthorityTable::<1>::new();
        let file = authority
            .insert(
                stable_object(9),
                StorageObjectKind::File,
                StorageRights::READ
                    .union(StorageRights::WRITE)
                    .union(StorageRights::RESIZE),
                stable_principal(),
            )
            .unwrap();
        let mut backend = StableBackend {
            bytes: [0; STABLE_BLOCK_BYTES],
            staged: 0,
            flushed: 0,
            reads: 0,
            fail_read: false,
            corrupt_read: false,
        };
        let mut output = [0; 512];
        let authorizer = CountingAuthorizer {
            inner: &capabilities,
            calls: core::cell::Cell::new(0),
        };
        let prepared = prepare_stable_configuration(
            &service,
            &authorizer,
            root_read,
            &current,
            &authority,
            file,
            stable_principal(),
            next,
            metadata,
            MetadataPointer::new(21, 1).unwrap(),
            &[],
            &mut output,
            &mut backend,
        )
        .unwrap();
        assert_eq!(prepared.checkpoint(), checkpoint);
        assert_eq!(prepared.revision(), 1);
        assert_eq!((backend.staged, backend.flushed), (1, 1));

        let mut transaction =
            StorageTransaction::<1, 2>::new(StorageTransactionId::new(70).unwrap(), 2).unwrap();
        prepared.admit(&mut transaction).unwrap();
        let mut receipt = transaction
            .publish(&publication_plan(images), &mut PublicationBackend)
            .unwrap();
        let stable = prepared.commit(&authorizer, &mut receipt).unwrap();
        assert_eq!(authorizer.calls.get(), 2);
        assert_eq!(receipt.remaining(), 0);
        assert_eq!(stable.file().generation(), 2);
        assert_eq!(stable.checkpoint(), checkpoint);

        let mut recovered_bytes = [0xa5; 512];
        let recovered = recover_stable_configuration::<3, 2, _, _, _, _>(
            stable.file(),
            &authority,
            file,
            stable_principal(),
            stable.file().generation(),
            &capabilities,
            root,
            &mut recovered_bytes,
            &mut backend,
        )
        .unwrap();
        assert_eq!(recovered.revision(), 1);
        assert_eq!(
            recovered
                .read(&capabilities, enabled_read, SettingId::new(1).unwrap())
                .unwrap()
                .value
                .and_then(ConfigValue::as_bool),
            Some(true)
        );

        let grants = [StorageRecoveryGrant::root(
            stable_principal(),
            stable_object(9),
            StorageObjectKind::File,
            StorageRights::READ,
        )];
        let mut authority_bytes = [0; 128];
        let authority_length =
            encode_authority_checkpoint(9, stable_volume(), 14, 2, &grants, &mut authority_bytes)
                .unwrap();
        let authority_digest =
            authority_checkpoint_digest(&authority_bytes[..authority_length]).unwrap();
        let admission = unsafe {
            OwnerApprovedAuthorityCheckpoint::new(9, stable_volume(), 14, 2, authority_digest)
        };
        let mut issuer = AuthorityCheckpointProofIssuer::new(admission);
        let proof = issuer
            .issue::<1>(&authority_bytes[..authority_length])
            .unwrap();
        let authenticated = unsafe { AuthenticatedAuthorityRecoveryState::new(8, 1) };
        let mut guard = AuthorityRecoveryGuard::from_authenticated_state(authenticated);
        let recovered_authority = guard
            .recover::<1>(&authority_bytes[..authority_length], proof)
            .unwrap();
        let mut dependent_bytes = [0xa5; 512];
        let mut validator = StableConfigurationRecoveryValidator::<3, 2, _, _, _>::new(
            stable.file(),
            0,
            stable_principal(),
            2,
            &capabilities,
            root,
            enabled_read,
            SettingId::new(1).unwrap(),
            ObjectId(99),
            &mut dependent_bytes,
            &mut backend,
        );
        assert_eq!(
            validator.validate(&recovered_authority).map(|_| ()),
            Err(StableConfigurationRecoveryError::Policy(
                PersistedRestartPolicyError::InvalidRecord
            ))
        );
        assert!(dependent_bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn stable_policy_and_boot_isolation_round_trip_use_committed_recovery() {
        let root_object = ObjectId(79);
        let setting_object = ObjectId(80);
        let service_object = ObjectId(81);
        let setting = SettingId::new(1).unwrap();
        let restart_schema = SettingSchema::bytes(
            setting,
            setting_object,
            PERSISTED_RESTART_POLICY_BYTES as u8,
        )
        .unwrap();
        let system =
            IsolationPolicySetting::system(SettingId::new(2).unwrap(), ObjectId(83)).unwrap();
        let component = IsolationPolicySetting::component(
            SettingId::new(3).unwrap(),
            ObjectId(84),
            IsolationPlacement::NativeService,
        )
        .unwrap();
        let mut configuration = ConfigurationService::<3, 2>::new(
            root_object,
            &[
                restart_schema,
                system.schema().unwrap(),
                component.schema().unwrap(),
            ],
        )
        .unwrap();
        let mut capabilities = CapabilitySpace::<8>::new();
        let root_control = capabilities.insert(root_object, Rights::CONTROL).unwrap();
        let root_read = capabilities.insert(root_object, Rights::READ).unwrap();
        let setting_write = capabilities.insert(setting_object, Rights::WRITE).unwrap();
        let setting_read = capabilities.insert(setting_object, Rights::READ).unwrap();
        let system_write = capabilities.insert(system.object(), Rights::WRITE).unwrap();
        let system_read = capabilities.insert(system.object(), Rights::READ).unwrap();
        let component_write = capabilities
            .insert(component.object(), Rights::WRITE)
            .unwrap();
        let component_read = capabilities
            .insert(component.object(), Rights::READ)
            .unwrap();
        let policy = PersistedRestartPolicy::new(service_object, 3, 5, 20).unwrap();
        let mut encoded_policy = [0; PERSISTED_RESTART_POLICY_BYTES];
        policy.encode(&mut encoded_policy);
        let mut update = ConfigTransaction::<3>::new(0);
        update
            .push(ConfigUpdate::new(
                setting,
                setting_write,
                ConfigValue::bytes(&encoded_policy).unwrap(),
            ))
            .unwrap();
        system
            .stage(&mut update, system_write, OwnerIsolationSelection::Balanced)
            .unwrap();
        component
            .stage(
                &mut update,
                component_write,
                OwnerIsolationSelection::Native,
            )
            .unwrap();
        configuration
            .commit(&capabilities, root_control, &update)
            .unwrap();
        let mut checkpoint_bytes = [0; 512];
        let checkpoint = configuration
            .export_checkpoint(&capabilities, root_read, &mut checkpoint_bytes)
            .unwrap();

        let device = BlockDeviceId::new(7).unwrap();
        let descriptor = BlockDeviceDescriptor::new(
            device,
            STABLE_BLOCK_BYTES as u32,
            stable_header().block_count(),
        )
        .unwrap();
        let mut block_service = BlockService::<1, 2>::new();
        let installed_platform_identity =
            PlatformBlockDeviceIdentity::new(PlatformBlockTransport::Hosted, [0x42; 32], 1, 1)
                .unwrap();
        let installed_platform =
            PlatformBlockDeviceDescriptor::new(descriptor, installed_platform_identity);
        block_service
            .register_platform_devices_atomic(&[installed_platform])
            .unwrap();
        let block_session = block_service
            .grant(device, stable_principal(), BlockRights::ALL)
            .unwrap();
        let installed_selection = InstalledRecoveryDeviceSelection::new_platform(
            &block_service,
            block_session,
            stable_principal(),
            installed_platform,
            stable_volume(),
            stable_header(),
            stable_header().primary_superblock(),
        )
        .unwrap();
        let read_only_session = block_service
            .derive(
                block_session,
                stable_principal(),
                StoragePrincipal::new(8).unwrap(),
                BlockRights::READ,
            )
            .unwrap();
        let mut backend = StableBlockBackend::new(device);
        let (current, next, metadata, plan) =
            block_stable_layout(&checkpoint_bytes[..checkpoint.length], &mut backend);
        let (_, denied_next, denied_metadata, _) =
            block_stable_layout(&checkpoint_bytes[..checkpoint.length], &mut backend);
        let mut storage_authority = StorageAuthorityTable::<1>::new();
        let file = storage_authority
            .insert(
                stable_object(9),
                StorageObjectKind::File,
                StorageRights::READ
                    .union(StorageRights::WRITE)
                    .union(StorageRights::RESIZE),
                stable_principal(),
            )
            .unwrap();

        {
            let mut denied_volume_scratch = [0; STABLE_BLOCK_BYTES];
            let denied_serviced = ServicedBlockDevice::new(
                &block_service,
                &mut backend,
                read_only_session,
                StoragePrincipal::new(8).unwrap(),
            )
            .unwrap();
            let mut denied_volume = BlockVolume::new(
                stable_header(),
                1,
                denied_serviced,
                &mut denied_volume_scratch,
            )
            .unwrap();
            let mut denied_file_scratch = [0; STABLE_BLOCK_BYTES];
            let mut denied_export = [0; 512];
            assert!(
                prepare_block_stable_configuration(
                    &configuration,
                    &capabilities,
                    root_read,
                    &current,
                    &storage_authority,
                    file,
                    stable_principal(),
                    denied_next,
                    denied_metadata,
                    MetadataPointer::new(5, 1).unwrap(),
                    &[],
                    &mut denied_export,
                    &mut denied_volume,
                    &mut denied_file_scratch,
                )
                .is_err()
            );
        }
        assert_eq!(backend.writes, 0);

        {
            let mut volume_scratch = [0; STABLE_BLOCK_BYTES];
            let serviced = ServicedBlockDevice::new(
                &block_service,
                &mut backend,
                block_session,
                stable_principal(),
            )
            .unwrap();
            let mut volume =
                BlockVolume::new(stable_header(), 1, serviced, &mut volume_scratch).unwrap();
            let mut export = [0; 512];
            let mut file_scratch = [0; STABLE_BLOCK_BYTES];
            let prepared = prepare_block_stable_configuration(
                &configuration,
                &capabilities,
                root_read,
                &current,
                &storage_authority,
                file,
                stable_principal(),
                next,
                metadata,
                MetadataPointer::new(5, 1).unwrap(),
                &[],
                &mut export,
                &mut volume,
                &mut file_scratch,
            )
            .unwrap();
            let mut transaction =
                StorageTransaction::<1, 2>::new(StorageTransactionId::new(72).unwrap(), 2).unwrap();
            prepared.admit(&mut transaction).unwrap();
            let mut receipt = transaction.publish(&plan, &mut volume).unwrap();
            let stable = prepared.commit(&capabilities, &mut receipt).unwrap();
            assert_eq!(receipt.remaining(), 0);

            let grants = [StorageRecoveryGrant::root(
                stable_principal(),
                stable_object(9),
                StorageObjectKind::File,
                StorageRights::READ,
            )];
            let mut authority_bytes = [0; 128];
            let authority_length = encode_authority_checkpoint(
                9,
                stable_volume(),
                14,
                2,
                &grants,
                &mut authority_bytes,
            )
            .unwrap();
            let authority_digest =
                authority_checkpoint_digest(&authority_bytes[..authority_length]).unwrap();
            let admission = unsafe {
                OwnerApprovedAuthorityCheckpoint::new(9, stable_volume(), 14, 2, authority_digest)
            };
            let mut issuer = AuthorityCheckpointProofIssuer::new(admission);
            let authority_object = stable_object(10);
            let mut authority_backend = CheckpointReadBackend {
                object: authority_object,
                bytes: [0; STABLE_BLOCK_BYTES],
            };
            authority_backend.bytes[..authority_length]
                .copy_from_slice(&authority_bytes[..authority_length]);
            let authority_file =
                checkpoint_file(authority_object, authority_length, &authority_backend.bytes);
            let mut bootstrap = StorageAuthorityTable::<1>::new();
            let bootstrap_file = bootstrap
                .insert(
                    authority_object,
                    StorageObjectKind::File,
                    StorageRights::READ,
                    stable_principal(),
                )
                .unwrap();
            let mut state_store = RecoveryStateStore::new(8, 1, stable_volume(), 14);
            let mut runtime = TaskRuntime::<1, 1>::new(1_000, 1).unwrap();
            let task = runtime
                .create(
                    Priority::NORMAL,
                    UserContext::new(
                        mrml_kernel::PhysAddr::new(0x20_0000).unwrap(),
                        0x40_0000,
                        0x7000_0000,
                    )
                    .unwrap(),
                )
                .unwrap();
            let recovery_object = ObjectId(0xb0);
            let recovery_capability = runtime
                .capabilities_mut(task)
                .unwrap()
                .insert(recovery_object, Rights::READ)
                .unwrap();
            let recovery_metadata =
                mrml_kernel::RecoveryStateMetadata::new(8, 1, Some(stable_volume().bytes()), 14)
                    .unwrap();
            let installed_boot = InstalledRecoveryBootIdentity::new(
                InstalledRecoverySource::Hosted,
                installed_platform_identity.stable_id(),
                installed_platform_identity.controller_generation(),
                installed_platform_identity.media_generation(),
                descriptor.block_size(),
                descriptor.block_count(),
                stable_volume().bytes(),
                stable_header().primary_superblock(),
                14,
            )
            .unwrap();
            let outbound_envelope = mrml_kernel::BootRecoveryEnvelope::new(
                recovery_metadata,
                Some(installed_boot),
                None,
                Some(BootIsolationOverride::TotalMicrovmOnce),
            )
            .unwrap();
            let mut delivery = mrml_kernel::BootRecoveryDelivery::from_envelope(
                task,
                recovery_object,
                outbound_envelope,
            )
            .unwrap();
            let mut delivered = [0xa5; mrml_kernel::BOOT_RECOVERY_ENVELOPE_BYTES];
            delivery
                .deliver(&mut runtime, task, recovery_capability, &mut delivered)
                .unwrap();
            let delivered_envelope = mrml_kernel::BootRecoveryEnvelope::decode(&delivered).unwrap();
            let mut boot_store = BootRecoveryAdmission::new(delivered_envelope.recovery())
                .unwrap()
                .bind(&mut state_store);
            let mut supervisor = ServiceSupervisor::<1>::new();
            let mut recovered_bytes = [0xa5; 512];
            struct CountingAuthorizer<'a, const CAPS: usize> {
                inner: &'a CapabilitySpace<CAPS>,
                calls: core::cell::Cell<usize>,
            }
            impl<const CAPS: usize> CapabilityAuthorizer for CountingAuthorizer<'_, CAPS> {
                fn authorize_exact(
                    &self,
                    capability: Capability,
                    rights: Rights,
                    expected: ObjectId,
                ) -> Result<(), ConfigError> {
                    self.calls.set(self.calls.get() + 1);
                    <CapabilitySpace<CAPS> as CapabilityAuthorizer>::authorize_exact(
                        self.inner,
                        capability,
                        rights,
                        expected,
                    )
                }
            }
            let authorizer = CountingAuthorizer {
                inner: &capabilities,
                calls: core::cell::Cell::new(0),
            };
            let configuration_validator =
                StableConfigurationRecoveryValidator::<3, 2, _, _, _>::new(
                    stable.file(),
                    0,
                    stable_principal(),
                    2,
                    &authorizer,
                    root_control,
                    setting_read,
                    setting,
                    service_object,
                    &mut recovered_bytes,
                    &mut volume,
                );
            let mut validator =
                StableServiceRecoveryValidator::new(configuration_validator, &supervisor, task);
            let mut authority_scratch = [0xa5; 128];
            let (authorities, prepared_service) =
                recover_validate_and_commit_stable_authorities::<1, 1, 1, _, _, _>(
                    &authority_file,
                    &bootstrap,
                    bootstrap_file,
                    stable_principal(),
                    2,
                    &mut issuer,
                    &mut authority_scratch,
                    &mut authority_backend,
                    &mut boot_store,
                    &mut validator,
                )
                .unwrap();
            drop(boot_store);
            assert!(
                supervisor
                    .plan_registration(ObjectId(82), task, RestartPolicy::ONCE_IMMEDIATE)
                    .is_ok()
            );
            let authorizations_before_commit = authorizer.calls.get();
            let recovered = prepared_service
                .commit(authorities, &authorizer, &mut supervisor)
                .unwrap();
            assert_eq!(authorizer.calls.get(), authorizations_before_commit + 1);
            assert_eq!(recovered.service().token(), 1u64 << 32);
            assert_eq!(recovered.configuration().revision(), 1);
            assert_eq!(recovered.authorities().epoch(), 9);

            let (release, release_length, key_id, active) = configuration_release_records();
            let mut runtime_plan = RuntimeDomainAssignmentPlan::<1>::new(
                &release[..release_length],
                &key_id,
                active,
                recovered.configuration().revision(),
            )
            .unwrap();
            let runtime_binding = RuntimeDomainPolicyBinding::new(
                "org.mrml.service.config",
                component,
                component_read,
            )
            .unwrap();
            recovered
                .assign_runtime_domains(&capabilities, &mut runtime_plan, &[runtime_binding])
                .unwrap();
            assert_eq!(runtime_plan.assigned_len(), 1);
            let assigned_release = runtime_plan.seal().unwrap();
            assert_eq!(assigned_release.release().len(), 1);
            assert_eq!(
                assigned_release
                    .release()
                    .entries()
                    .next()
                    .unwrap()
                    .domain(),
                component.object()
            );

            let mut missing_policy = RuntimeDomainAssignmentPlan::<1>::new(
                &release[..release_length],
                &key_id,
                active,
                recovered.configuration().revision(),
            )
            .unwrap();
            assert_eq!(
                recovered.assign_runtime_domains(&capabilities, &mut missing_policy, &[]),
                Err(RecoveredRuntimeDomainPolicyError::BindingCount)
            );
            assert_eq!(missing_policy.assigned_len(), 0);

            let mut wrong_authority = RuntimeDomainAssignmentPlan::<1>::new(
                &release[..release_length],
                &key_id,
                active,
                recovered.configuration().revision(),
            )
            .unwrap();
            let wrong_binding =
                RuntimeDomainPolicyBinding::new("org.mrml.service.config", component, system_read)
                    .unwrap();
            assert!(matches!(
                recovered.assign_runtime_domains(
                    &capabilities,
                    &mut wrong_authority,
                    &[wrong_binding],
                ),
                Err(RecoveredRuntimeDomainPolicyError::Configuration(_))
            ));
            assert_eq!(wrong_authority.assigned_len(), 0);

            let mut stale_policy = RuntimeDomainAssignmentPlan::<1>::new(
                &release[..release_length],
                &key_id,
                active,
                recovered.configuration().revision() + 1,
            )
            .unwrap();
            assert_eq!(
                recovered.assign_runtime_domains(
                    &capabilities,
                    &mut stale_policy,
                    &[runtime_binding],
                ),
                Err(RecoveredRuntimeDomainPolicyError::PolicyGenerationMismatch)
            );
            assert_eq!(stale_policy.assigned_len(), 0);

            const HANDOFF_LENGTH: usize = mrml_kernel::HANDOFF_HEADER_BYTES
                + 2 * mrml_kernel::HANDOFF_REGION_BYTES
                + mrml_kernel::HANDOFF_SERVICE_BYTES
                + mrml_kernel::HANDOFF_RECOVERY_STATE_BYTES
                + mrml_kernel::INSTALLED_RECOVERY_BOOT_IDENTITY_BYTES
                + 16
                + 52;
            let regions = [
                mrml_kernel::MemoryRegion::new(
                    mrml_kernel::PhysAddr::new(0xa0000).unwrap(),
                    1,
                    mrml_kernel::MemoryKind::Mmio,
                )
                .unwrap(),
                mrml_kernel::MemoryRegion::new(
                    mrml_kernel::PhysAddr::new(0x10_0000).unwrap(),
                    64,
                    mrml_kernel::MemoryKind::Reserved,
                )
                .unwrap(),
            ];
            let framebuffer = mrml_kernel::FramebufferInfo::new(
                0xa0000,
                0x1000,
                16,
                16,
                16,
                mrml_kernel::PixelFormat::BlueGreenRedReserved,
            )
            .unwrap();
            let launch = mrml_kernel::ServiceLaunch::new(
                mrml_kernel::PhysAddr::new(0x11_0000).unwrap(),
                1024,
                mrml_kernel::PhysAddr::new(0x10_0000).unwrap(),
                2,
                0x1_4000_0000,
                0x1_4000_0080,
                mrml_kernel::PhysAddr::new(0x10_4000).unwrap(),
                2,
                0x2_0000_2000,
                mrml_kernel::PhysAddr::new(0x10_8000).unwrap(),
                4,
                11,
                [9; 64],
            )
            .unwrap();
            let mut madt = [0u8; 52];
            madt[..4].copy_from_slice(b"APIC");
            madt[4..8].copy_from_slice(&52u32.to_le_bytes());
            madt[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
            madt[44..].copy_from_slice(&[0, 8, 0, 1, 1, 0, 0, 0]);
            madt[9] = 0u8.wrapping_sub(madt.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)));
            let mut handoff_bytes = [0u8; HANDOFF_LENGTH];
            mrml_kernel::encode_handoff_with_smp_service_recovery_isolation_and_installed(
                7,
                [1; 32],
                [2; 64],
                true,
                true,
                false,
                true,
                0x9000,
                framebuffer,
                &regions,
                0x8000,
                0x40_0000,
                launch,
                Some(delivered_envelope.recovery()),
                Some(installed_boot),
                Some(BootIsolationOverride::TotalMicrovmOnce),
                &madt,
                &mut handoff_bytes,
            )
            .unwrap();
            let handoff = BootHandoff::decode(&handoff_bytes, |_| {}).unwrap();
            let early = EarlyKernelContext::from_handoff(&handoff, &regions).unwrap();
            let boot_policy = recovered
                .compose_early_boot_isolation_policy(
                    &capabilities,
                    system,
                    system_read,
                    component,
                    component_read,
                    &early,
                )
                .unwrap();
            assert_eq!(boot_policy.authority_epoch(), 9);
            assert_eq!(boot_policy.boot_accepted_epoch(), 8);
            assert_eq!(boot_policy.recovery_volume(), stable_volume());
            assert_eq!(boot_policy.recovery_root_generation(), 14);
            assert_eq!(boot_policy.configuration_revision(), 1);
            assert_eq!(boot_policy.configuration_service(), recovered.service());
            assert_eq!(
                boot_policy.effective().configured().mode(),
                IsolationMode::Balanced
            );
            assert_eq!(boot_policy.effective().mode(), IsolationMode::TotalMicrovm);
            assert_eq!(
                boot_policy.effective().boot_override(),
                Some(BootIsolationOverride::TotalMicrovmOnce)
            );
            let admission = boot_policy.admission_table::<1>(33).unwrap();
            assert_eq!(admission.mode(), IsolationMode::TotalMicrovm);
            assert_eq!(admission.policy_generation(), 1);

            let domain = ObjectId(0x434f_4e46_4947_0001);
            let incomplete = recovered
                .build_installed_total_boot_admission(
                    installed_selection,
                    &capabilities,
                    system,
                    system_read,
                    component,
                    component_read,
                    &handoff,
                    |policy_generation| {
                        Ok::<_, ()>(activated_configuration_release(domain, policy_generation))
                    },
                )
                .unwrap();
            assert!(matches!(
                incomplete.authorize_runtime(),
                Err(mrml_kernel::TotalMicrovmRuntimeError::RequiredDomainMissing)
            ));
            let stale_delivered_recovery = mrml_kernel::RecoveryStateMetadata::new(
                7,
                1,
                delivered_envelope.recovery().accepted_volume(),
                delivered_envelope.recovery().accepted_root_generation(),
            )
            .unwrap();
            let stale_delivered = mrml_kernel::BootRecoveryEnvelope::new(
                stale_delivered_recovery,
                delivered_envelope.installed(),
                delivered_envelope.sata_route(),
                delivered_envelope.isolation_override(),
            )
            .unwrap();
            assert_eq!(
                recovered.validate_delivered_boot(stale_delivered),
                Err(ConfigError::RecoveryHandoffMismatch)
            );
            let delivered_recovered = recovered.bind_delivered_boot(delivered_envelope).unwrap();
            assert_eq!(delivered_recovered.delivered(), delivered_envelope);
            let (release, release_length, key_id, active) = configuration_release_records();
            let stale_runtime_plan = RuntimeDomainAssignmentPlan::<1>::new(
                &release[..release_length],
                &key_id,
                active,
                delivered_recovered.recovered().configuration().revision() + 1,
            )
            .unwrap();
            assert_eq!(
                delivered_recovered
                    .build_assigned_installed_total_boot_admission(
                        installed_selection,
                        &capabilities,
                        system,
                        system_read,
                        component,
                        component_read,
                        stale_runtime_plan,
                        &[runtime_binding],
                    )
                    .err(),
                Some(RecoveredAssignedTotalAdmissionError::Assignment(
                    RecoveredRuntimeDomainPolicyError::PolicyGenerationMismatch
                ))
            );
            let runtime_plan = RuntimeDomainAssignmentPlan::<1>::new(
                &release[..release_length],
                &key_id,
                active,
                delivered_recovered.recovered().configuration().revision(),
            )
            .unwrap();
            let mut total = delivered_recovered
                .build_assigned_installed_total_boot_admission(
                    installed_selection,
                    &capabilities,
                    system,
                    system_read,
                    component,
                    component_read,
                    runtime_plan,
                    &[runtime_binding],
                )
                .unwrap();
            assert_eq!(total.installed(), installed_selection);
            assert_eq!(total.policy().authority_epoch(), 9);
            assert_eq!(total.policy().boot_accepted_epoch(), 8);
            let bounds = IsolationServiceBounds::new(
                IsolationPlacement::NativeService,
                IsolationPlacement::NativeService,
                IsolationPlacement::Microvm,
                true,
                true,
            )
            .unwrap();
            let identity = IsolationServiceIdentity::new(
                component.object(),
                ObjectId(0x434f_4e46_0000_0001),
                1,
                5,
                TotalMicrovmClass::MicrovmEligible,
            )
            .unwrap();
            assert_eq!(
                total.prepare_complete_service_set(&[]).err(),
                Some(CompleteTotalServicePreparationError::BindingCount)
            );
            assert_eq!(total.admission().running().count(), 0);
            let mut prepared_set = total
                .prepare_complete_service_set(&[TotalServicePreparationBinding::new(
                    bounds, identity,
                )])
                .unwrap();
            assert_eq!(prepared_set.len(), 1);
            let prepared = prepared_set.take(component.object()).unwrap();
            assert!(prepared_set.take(component.object()).is_none());
            assert_eq!(prepared.spec().placement(), IsolationPlacement::Microvm);
            let routed = prepared.commit(total.admission_mut(), 0x51u64).unwrap();
            assert_eq!(routed.domain(), component.object());
            assert_eq!(routed.into_endpoint(), 0x51);
            let runtime = total.authorize_runtime().unwrap();
            assert_eq!(runtime.installed(), installed_selection);
            assert_eq!(runtime.admission().running().count(), 1);
            let proof = runtime.proof();
            assert_eq!(proof.classified_domains(), 1);
            assert_eq!(proof.running_microvm_eligible(), 1);
            assert_eq!(proof.running_in_microvm(), 1);

            let stale_recovery = mrml_kernel::RecoveryStateMetadata::new(7, 1, None, 0).unwrap();
            let stale_length = mrml_kernel::encode_handoff_with_smp_service_recovery_and_isolation(
                7,
                [1; 32],
                [2; 64],
                true,
                true,
                false,
                true,
                0x9000,
                framebuffer,
                &regions,
                0x8000,
                0x40_0000,
                launch,
                Some(stale_recovery),
                Some(BootIsolationOverride::TotalMicrovmOnce),
                &madt,
                &mut handoff_bytes,
            )
            .unwrap();
            let stale_handoff =
                BootHandoff::decode(&handoff_bytes[..stale_length], |_| {}).unwrap();
            let recovered = delivered_recovered.recovered();
            let missing_installed: Result<
                RecoveredInstalledTotalAdmission<1>,
                RecoveredInstalledTotalAdmissionBuildError<()>,
            > = recovered.build_installed_total_boot_admission(
                installed_selection,
                &capabilities,
                system,
                system_read,
                component,
                component_read,
                &stale_handoff,
                |_| panic!("release builder must not run without installed handoff identity"),
            );
            assert_eq!(
                missing_installed.err(),
                Some(RecoveredInstalledTotalAdmissionBuildError::Installed(
                    ConfigError::RecoveryHandoffMismatch
                ))
            );
            assert_eq!(
                recovered.compose_boot_isolation_policy(
                    &capabilities,
                    system,
                    system_read,
                    component,
                    component_read,
                    &stale_handoff,
                ),
                Err(ConfigError::RecoveryHandoffMismatch)
            );
            assert_eq!(
                recovered.authorities().authority_table().authorize(
                    recovered.authorities().handle(0).unwrap(),
                    stable_principal(),
                    StorageObjectKind::File,
                    StorageRights::READ,
                ),
                Ok(stable_object(9))
            );
            assert_eq!(
                u64::from_le_bytes(state_store.bytes[16..24].try_into().unwrap()),
                9
            );
            assert!(authority_scratch.iter().all(|byte| *byte == 0));
            assert!(recovered_bytes.iter().all(|byte| *byte == 0));
            assert_eq!(supervisor.task(recovered.service()), Ok(Some(task)));
        }
        assert!(backend.writes > 0);
        assert!(backend.reads > 0);
        assert!(backend.flushes >= 3);
        assert_eq!(backend.replacements, 1);

        assert_eq!(
            block_service
                .revoke(block_session, stable_principal())
                .unwrap(),
            2
        );
        assert_eq!(
            ServicedBlockDevice::new(
                &block_service,
                &mut backend,
                block_session,
                stable_principal(),
            )
            .err(),
            Some(BlockServiceError::StaleHandle)
        );
    }

    #[test]
    fn stable_checkpoint_rejects_wrong_authority_binding_corruption_and_io_uncertainty() {
        let (service, capabilities, _, root, _, enabled, _, _) = fixture();
        let mut expected = [0; 512];
        let checkpoint = service
            .export_checkpoint(&capabilities, root, &mut expected)
            .unwrap();
        let (current, next, mut metadata, _) = stable_layout(&expected[..checkpoint.length]);
        let mut denied_authority = StorageAuthorityTable::<1>::new();
        let denied = denied_authority
            .insert(
                stable_object(9),
                StorageObjectKind::File,
                StorageRights::WRITE,
                stable_principal(),
            )
            .unwrap();
        let mut backend = StableBackend {
            bytes: [0; STABLE_BLOCK_BYTES],
            staged: 0,
            flushed: 0,
            reads: 0,
            fail_read: false,
            corrupt_read: false,
        };
        let mut output = [0; 512];
        assert!(matches!(
            prepare_stable_configuration(
                &service,
                &capabilities,
                root,
                &current,
                &denied_authority,
                denied,
                stable_principal(),
                next,
                metadata,
                MetadataPointer::new(21, 1).unwrap(),
                &[],
                &mut output,
                &mut backend,
            ),
            Err(ConfigurationStorageError::Write(FileWriteError::Authority(
                _
            )))
        ));
        assert_eq!(backend.staged, 0);

        let (_, next, _, _) = stable_layout(&expected[..checkpoint.length]);
        metadata = FileMetadata::new(
            stable_header(),
            stable_object(9),
            2,
            checkpoint.length as u64,
            1,
            MetadataPointer::new(20, 1).unwrap(),
            [0xff; 32],
        )
        .unwrap();
        let mut authority = StorageAuthorityTable::<1>::new();
        let file = authority
            .insert(
                stable_object(9),
                StorageObjectKind::File,
                StorageRights::READ
                    .union(StorageRights::WRITE)
                    .union(StorageRights::RESIZE),
                stable_principal(),
            )
            .unwrap();
        let (_, unauthorized_next, unauthorized_metadata, _) =
            stable_layout(&expected[..checkpoint.length]);
        assert!(matches!(
            prepare_stable_configuration(
                &service,
                &capabilities,
                enabled,
                &current,
                &authority,
                file,
                stable_principal(),
                unauthorized_next,
                unauthorized_metadata,
                MetadataPointer::new(21, 1).unwrap(),
                &[],
                &mut output,
                &mut backend,
            ),
            Err(ConfigurationStorageError::Configuration(
                ConfigError::WrongObject
            ))
        ));
        assert_eq!(backend.staged, 0);
        assert!(matches!(
            prepare_stable_configuration(
                &service,
                &capabilities,
                root,
                &current,
                &authority,
                file,
                stable_principal(),
                next,
                metadata,
                MetadataPointer::new(21, 1).unwrap(),
                &[],
                &mut output,
                &mut backend,
            ),
            Err(ConfigurationStorageError::InvalidBinding)
        ));
        assert_eq!(backend.staged, 0);

        let (_, next, metadata, _) = stable_layout(&expected[..checkpoint.length]);
        let prepared = prepare_stable_configuration(
            &service,
            &capabilities,
            root,
            &current,
            &authority,
            file,
            stable_principal(),
            next,
            metadata,
            MetadataPointer::new(21, 1).unwrap(),
            &[],
            &mut output,
            &mut backend,
        )
        .unwrap();
        let mut transaction =
            StorageTransaction::<1, 2>::new(StorageTransactionId::new(71).unwrap(), 2).unwrap();
        prepared.admit(&mut transaction).unwrap();
        let (_, _, _, images) = stable_layout(&expected[..checkpoint.length]);
        let mut receipt = transaction
            .publish(&publication_plan(images), &mut PublicationBackend)
            .unwrap();
        let stable = prepared.commit(&capabilities, &mut receipt).unwrap();

        let mut recovered_bytes = [0xa5; 512];
        assert!(matches!(
            recover_stable_configuration::<3, 2, _, _, _, _>(
                stable.file(),
                &authority,
                file,
                stable_principal(),
                stable.file().generation() - 1,
                &capabilities,
                root,
                &mut recovered_bytes,
                &mut backend,
            ),
            Err(ConfigurationStorageError::InvalidBinding)
        ));
        assert_eq!(backend.reads, 0);

        backend.corrupt_read = true;
        assert!(matches!(
            recover_stable_configuration::<3, 2, _, _, _, _>(
                stable.file(),
                &authority,
                file,
                stable_principal(),
                stable.file().generation(),
                &capabilities,
                root,
                &mut recovered_bytes,
                &mut backend,
            ),
            Err(ConfigurationStorageError::Configuration(
                ConfigError::InvalidCheckpoint
            ))
        ));
        backend.corrupt_read = false;
        backend.fail_read = true;
        assert!(matches!(
            recover_stable_configuration::<3, 2, _, _, _, _>(
                stable.file(),
                &authority,
                file,
                stable_principal(),
                stable.file().generation(),
                &capabilities,
                root,
                &mut recovered_bytes,
                &mut backend,
            ),
            Err(ConfigurationStorageError::Read(FileReadError::Backend(4)))
        ));
        assert!(recovered_bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn persisted_restart_policy_is_canonical_and_service_bound() {
        assert_eq!(
            PersistedRestartPolicy::new(ObjectId(0), 1, 0, 0),
            Err(PersistedRestartPolicyError::InvalidRecord)
        );
        assert_eq!(
            PersistedRestartPolicy::new(ObjectId(70), 0, 0, 0),
            Err(PersistedRestartPolicyError::Service(
                ServiceError::InvalidRestartPolicy
            ))
        );
        let policy = PersistedRestartPolicy::new(ObjectId(70), 3, 10, 40).unwrap();
        let mut encoded = [0xa5; PERSISTED_RESTART_POLICY_BYTES];
        policy.encode(&mut encoded);
        assert_eq!(PersistedRestartPolicy::decode(&encoded), Ok(policy));

        for offset in [4usize, 6, 20, 40, 47] {
            let mut malformed = encoded;
            malformed[offset] ^= 1;
            assert_eq!(
                PersistedRestartPolicy::decode(&malformed),
                Err(PersistedRestartPolicyError::InvalidRecord)
            );
        }
        assert_eq!(
            PersistedRestartPolicy::decode(&encoded[..encoded.len() - 1]),
            Err(PersistedRestartPolicyError::InvalidRecord)
        );
        let mut substituted = encoded;
        substituted[8..16].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(
            PersistedRestartPolicy::decode(&substituted),
            Err(PersistedRestartPolicyError::InvalidRecord)
        );
    }

    #[test]
    fn recovered_restart_policy_requires_live_setting_read_and_trusted_registration() {
        let setting = SettingId::new(9).unwrap();
        let policy_object = ObjectId(80);
        let service_object = ObjectId(70);
        let schema =
            SettingSchema::bytes(setting, policy_object, PERSISTED_RESTART_POLICY_BYTES as u8)
                .unwrap();
        let mut configuration = ConfigurationService::<1, 2>::new(ObjectId(79), &[schema]).unwrap();
        let mut capabilities = CapabilitySpace::<5>::new();
        let root_control = capabilities.insert(ObjectId(79), Rights::CONTROL).unwrap();
        let root_read = capabilities.insert(ObjectId(79), Rights::READ).unwrap();
        let policy_write = capabilities.insert(policy_object, Rights::WRITE).unwrap();
        let policy_read = capabilities.insert(policy_object, Rights::READ).unwrap();
        let unrelated = capabilities.insert(ObjectId(81), Rights::READ).unwrap();
        let policy = PersistedRestartPolicy::new(service_object, 1, 10, 10).unwrap();
        let mut encoded = [0; PERSISTED_RESTART_POLICY_BYTES];
        policy.encode(&mut encoded);
        let mut transaction = ConfigTransaction::<1>::new(0);
        transaction
            .push(ConfigUpdate::new(
                setting,
                policy_write,
                ConfigValue::bytes(&encoded).unwrap(),
            ))
            .unwrap();
        configuration
            .commit(&capabilities, root_control, &transaction)
            .unwrap();

        assert!(matches!(
            load_persisted_restart_policy(
                &configuration,
                &capabilities,
                unrelated,
                setting,
                service_object,
            ),
            Err(PersistedRestartPolicyError::Configuration(
                ConfigError::WrongObject
            ))
        ));
        assert_eq!(
            load_persisted_restart_policy(
                &configuration,
                &capabilities,
                policy_read,
                setting,
                ObjectId(71),
            ),
            Err(PersistedRestartPolicyError::WrongService)
        );

        let mut checkpoint_bytes = [0; 256];
        let checkpoint = configuration
            .export_checkpoint(&capabilities, root_read, &mut checkpoint_bytes)
            .unwrap();
        let recovered = ConfigurationService::<1, 2>::recover_checkpoint(
            &capabilities,
            root_control,
            &checkpoint_bytes[..checkpoint.length],
            checkpoint.digest,
        )
        .unwrap();
        let bound = load_persisted_restart_policy(
            &recovered,
            &capabilities,
            policy_read,
            setting,
            service_object,
        )
        .unwrap();
        assert_eq!(bound.service(), service_object);
        assert_eq!(bound.configuration_revision(), 1);
        assert_eq!(bound.setting_revision(), 1);

        let context = UserContext::new(
            mrml_kernel::PhysAddr::new(0x20_0000).unwrap(),
            0x40_0000,
            0x7000_0000,
        )
        .unwrap();
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let task = runtime.create(Priority::NORMAL, context).unwrap();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let service = bound
            .register(
                &recovered,
                &capabilities,
                policy_read,
                &mut supervisor,
                task,
            )
            .unwrap();
        assert_eq!(supervisor.state(service), Ok(ServiceState::Running));
        assert!(matches!(
            runtime.start(),
            mrml_kernel::ScheduleOutcome::Switch { .. }
        ));
        let retirement = supervisor.exit_current_at(&mut runtime, 0).unwrap();
        struct Eraser;
        impl mrml_kernel::ServiceAddressSpaceEraser for Eraser {
            type Error = ();

            fn erase(&mut self, _: TaskId, _: UserContext) -> Result<(), Self::Error> {
                Ok(())
            }
        }
        supervisor
            .complete_cleanup(retirement.cleanup, &mut Eraser)
            .unwrap();
        let mut management = CapabilitySpace::<1>::new();
        let control = management.insert(service_object, Rights::CONTROL).unwrap();
        let replacement_context = UserContext::new(
            mrml_kernel::PhysAddr::new(0x30_0000).unwrap(),
            0x50_0000,
            0x7000_0000,
        )
        .unwrap();
        assert_eq!(
            supervisor.restart_at(
                service,
                &management,
                control,
                &mut runtime,
                Priority::NORMAL,
                replacement_context,
                9,
            ),
            Err(ServiceError::RestartBackoff { eligible_at: 10 })
        );
        let replacement = supervisor
            .restart_at(
                service,
                &management,
                control,
                &mut runtime,
                Priority::NORMAL,
                replacement_context,
                10,
            )
            .unwrap();
        assert!(matches!(
            runtime.start(),
            mrml_kernel::ScheduleOutcome::Switch { .. }
        ));
        let retirement = supervisor.exit_current_at(&mut runtime, 20).unwrap();
        supervisor
            .complete_cleanup(retirement.cleanup, &mut Eraser)
            .unwrap();
        assert_eq!(
            supervisor.restart_at(
                replacement,
                &management,
                control,
                &mut runtime,
                Priority::NORMAL,
                replacement_context,
                30,
            ),
            Err(ServiceError::RestartLimit)
        );

        capabilities.revoke(policy_read).unwrap();
        assert!(matches!(
            bound.register(
                &recovered,
                &capabilities,
                policy_read,
                &mut supervisor,
                task,
            ),
            Err(PersistedRestartPolicyError::Configuration(
                ConfigError::Unauthorized(CapabilityError::Invalid)
            ))
        ));
        assert!(matches!(
            load_persisted_restart_policy(
                &recovered,
                &capabilities,
                policy_read,
                setting,
                service_object,
            ),
            Err(PersistedRestartPolicyError::Configuration(
                ConfigError::Unauthorized(CapabilityError::Invalid)
            ))
        ));
    }

    #[test]
    fn dynamic_restart_policy_revalidates_revisions_read_and_service_control() {
        let setting = SettingId::new(10).unwrap();
        let root_object = ObjectId(90);
        let policy_object = ObjectId(91);
        let service_object = ObjectId(92);
        let schema =
            SettingSchema::bytes(setting, policy_object, PERSISTED_RESTART_POLICY_BYTES as u8)
                .unwrap();
        let mut configuration = ConfigurationService::<1, 3>::new(root_object, &[schema]).unwrap();
        let mut capabilities = CapabilitySpace::<3>::new();
        let root = capabilities.insert(root_object, Rights::CONTROL).unwrap();
        let policy_write = capabilities.insert(policy_object, Rights::WRITE).unwrap();
        let policy_read = capabilities.insert(policy_object, Rights::READ).unwrap();

        let initial = PersistedRestartPolicy::new(service_object, 1, 10, 10).unwrap();
        let mut encoded = [0; PERSISTED_RESTART_POLICY_BYTES];
        initial.encode(&mut encoded);
        let mut transaction = ConfigTransaction::<1>::new(0);
        transaction
            .push(ConfigUpdate::new(
                setting,
                policy_write,
                ConfigValue::bytes(&encoded).unwrap(),
            ))
            .unwrap();
        configuration
            .commit(&capabilities, root, &transaction)
            .unwrap();
        let stale = load_persisted_restart_policy(
            &configuration,
            &capabilities,
            policy_read,
            setting,
            service_object,
        )
        .unwrap();

        let replacement = PersistedRestartPolicy::new(service_object, 3, 20, 40).unwrap();
        replacement.encode(&mut encoded);
        let mut transaction = ConfigTransaction::<1>::new(1);
        transaction
            .push(ConfigUpdate::new(
                setting,
                policy_write,
                ConfigValue::bytes(&encoded).unwrap(),
            ))
            .unwrap();
        configuration
            .commit(&capabilities, root, &transaction)
            .unwrap();

        let context = UserContext::new(
            mrml_kernel::PhysAddr::new(0x20_0000).unwrap(),
            0x40_0000,
            0x7000_0000,
        )
        .unwrap();
        let mut runtime = TaskRuntime::<1, 0>::new(1_000, 1).unwrap();
        let task = runtime.create(Priority::NORMAL, context).unwrap();
        let mut supervisor = ServiceSupervisor::<1>::new();
        let service = supervisor.register(service_object, task).unwrap();
        let mut management = CapabilitySpace::<2>::new();
        let wrong = management.insert(ObjectId(93), Rights::CONTROL).unwrap();
        let control = management.insert(service_object, Rights::CONTROL).unwrap();

        assert_eq!(
            stale.replace(
                &configuration,
                &capabilities,
                &mut supervisor,
                service,
                &management,
                RestartPolicyApplicationAuthority::new(policy_read, control),
            ),
            Err(PersistedRestartPolicyError::PolicyChanged)
        );
        let current = load_persisted_restart_policy(
            &configuration,
            &capabilities,
            policy_read,
            setting,
            service_object,
        )
        .unwrap();
        assert_eq!(current.configuration_revision(), 2);
        assert_eq!(current.setting_revision(), 2);
        assert_eq!(
            current.replace(
                &configuration,
                &capabilities,
                &mut supervisor,
                service,
                &management,
                RestartPolicyApplicationAuthority::new(policy_read, wrong),
            ),
            Err(PersistedRestartPolicyError::Service(
                ServiceError::Unauthorized(CapabilityError::PermissionDenied)
            ))
        );
        current
            .replace(
                &configuration,
                &capabilities,
                &mut supervisor,
                service,
                &management,
                RestartPolicyApplicationAuthority::new(policy_read, control),
            )
            .unwrap();
        capabilities.revoke(policy_read).unwrap();
        assert_eq!(
            current.replace(
                &configuration,
                &capabilities,
                &mut supervisor,
                service,
                &management,
                RestartPolicyApplicationAuthority::new(policy_read, control),
            ),
            Err(PersistedRestartPolicyError::Configuration(
                ConfigError::Unauthorized(CapabilityError::Invalid)
            ))
        );
    }

    #[test]
    fn policy_envelope_requires_ordered_read_and_control_authorities() {
        struct Kernel {
            control: Capability,
            service: ServiceId,
            policy: RestartPolicy,
        }
        impl ServicePolicyAuthorizer for Kernel {
            fn replace_policy(
                &self,
                capability: Capability,
                service: ServiceId,
                policy: RestartPolicy,
            ) -> Result<(), ConfigError> {
                if capability == self.control && service == self.service && policy == self.policy {
                    Ok(())
                } else {
                    Err(ConfigError::Unauthorized(CapabilityError::PermissionDenied))
                }
            }
        }

        let setting = SettingId::new(11).unwrap();
        let root_object = ObjectId(100);
        let policy_object = ObjectId(101);
        let service_object = ObjectId(102);
        let schema =
            SettingSchema::bytes(setting, policy_object, PERSISTED_RESTART_POLICY_BYTES as u8)
                .unwrap();
        let mut configuration = ConfigurationService::<1, 2>::new(root_object, &[schema]).unwrap();
        let mut configuration_capabilities = CapabilitySpace::<3>::new();
        let root = configuration_capabilities
            .insert(root_object, Rights::CONTROL)
            .unwrap();
        let setting_write = configuration_capabilities
            .insert(policy_object, Rights::WRITE)
            .unwrap();
        let setting_read = configuration_capabilities
            .insert(policy_object, Rights::READ)
            .unwrap();
        let persisted = PersistedRestartPolicy::new(service_object, 2, 5, 20).unwrap();
        let mut encoded = [0; PERSISTED_RESTART_POLICY_BYTES];
        persisted.encode(&mut encoded);
        let mut transaction = ConfigTransaction::<1>::new(0);
        transaction
            .push(ConfigUpdate::new(
                setting,
                setting_write,
                ConfigValue::bytes(&encoded).unwrap(),
            ))
            .unwrap();
        configuration
            .commit(&configuration_capabilities, root, &transaction)
            .unwrap();

        let service = ServiceId::from_token((17u64 << 32) | 2);
        let control = Capability::from_token((18u64 << 32) | 3);
        let kernel = Kernel {
            control,
            service,
            policy: persisted.restart_policy().unwrap(),
        };
        let request = SupervisionRequest {
            operation: SupervisionOperation::ReplacePolicy,
            request_id: 56,
            service,
            capability: control,
            setting: Some(setting),
            setting_capability: setting_read,
        };
        let mut wire = [0; SUPERVISION_REQUEST_BYTES];
        request.encode_message(&mut wire).unwrap();
        assert!(wire[32..40].iter().all(|byte| *byte == 0));
        assert_eq!(read_u32(&wire, 40), Ok(setting.get()));
        let decoded_request = SupervisionRequest::decode_message(
            &Message::new(&wire, &[setting_read, control]).unwrap(),
        )
        .unwrap();
        assert_eq!(decoded_request, request);

        let mut malformed = wire;
        malformed[32] = 1;
        assert_eq!(
            SupervisionRequest::decode_message(
                &Message::new(&malformed, &[setting_read, control]).unwrap()
            ),
            Err(ConfigError::InvalidAuthorityEnvelope)
        );
        malformed = wire;
        malformed[44] = 1;
        assert_eq!(
            SupervisionRequest::decode(&malformed),
            Err(ConfigError::NonCanonical)
        );
        malformed = wire;
        write_u16(&mut malformed, 6, SupervisionOperation::Query as u16).unwrap();
        assert_eq!(
            SupervisionRequest::decode(&malformed),
            Err(ConfigError::NonCanonical)
        );
        let mut response = [0; SUPERVISION_RESPONSE_BYTES];
        dispatch_supervision_policy_envelope(
            &configuration,
            &configuration_capabilities,
            &kernel,
            service_object,
            &wire,
            &[setting_read, control],
            &mut response,
        )
        .unwrap();
        let decoded = SupervisionResponse::decode(&response).unwrap();
        assert_eq!(decoded.status, ResponseStatus::Ok);
        assert_eq!(decoded.service, service);
        assert_eq!(decoded.state, SupervisionState::Running);
        assert_eq!(decoded.detail, 0);

        for authorities in [
            &[][..],
            &[setting_read][..],
            &[setting_read, control, control][..],
        ] {
            assert_eq!(
                dispatch_supervision_policy_envelope(
                    &configuration,
                    &configuration_capabilities,
                    &kernel,
                    service_object,
                    &wire,
                    authorities,
                    &mut response,
                ),
                Err(ConfigError::InvalidAuthorityEnvelope)
            );
        }
        dispatch_supervision_policy_envelope(
            &configuration,
            &configuration_capabilities,
            &kernel,
            service_object,
            &wire,
            &[control, setting_read],
            &mut response,
        )
        .unwrap();
        assert_eq!(
            SupervisionResponse::decode(&response).unwrap().status,
            ResponseStatus::Rejected
        );
        dispatch_supervision_policy_envelope(
            &configuration,
            &configuration_capabilities,
            &kernel,
            ObjectId(103),
            &wire,
            &[setting_read, control],
            &mut response,
        )
        .unwrap();
        assert_eq!(
            SupervisionResponse::decode(&response).unwrap().status,
            ResponseStatus::Rejected
        );
    }

    #[test]
    fn isolation_policy_is_typed_capability_authorized_and_recoverable() {
        let root_object = ObjectId(0x4953_4f4c_4154_494f);
        let component_object = ObjectId(0x434f_4d50_4f4e_454e);
        let system_object = ObjectId(0x5359_5354_454d_504f);
        let component = IsolationPolicySetting::component(
            SettingId::new(40).unwrap(),
            component_object,
            IsolationPlacement::NativeService,
        )
        .unwrap();
        let system =
            IsolationPolicySetting::system(SettingId::new(41).unwrap(), system_object).unwrap();
        let system_edit = IsolationSettingsAction::new(OwnerIsolationSelection::TotalMicrovm, 0)
            .edit(system)
            .unwrap();
        assert_eq!(
            IsolationShellCommand::parse("isolation set total-microvm 0", system),
            Ok(IsolationShellCommand::Set(system_edit))
        );
        assert_eq!(
            IsolationShellCommand::parse("isolation set native 0", system),
            Err(ConfigError::SchemaViolation)
        );
        let schemas = [component.schema().unwrap(), system.schema().unwrap()];
        let mut configuration = ConfigurationService::<2, 4>::new(root_object, &schemas).unwrap();
        let mut capabilities = CapabilitySpace::<7>::new();
        let root_control = capabilities.insert(root_object, Rights::CONTROL).unwrap();
        let root_read = capabilities.insert(root_object, Rights::READ).unwrap();
        let component_write = capabilities
            .insert(component_object, Rights::WRITE)
            .unwrap();
        let component_read = capabilities.insert(component_object, Rights::READ).unwrap();
        let system_write = capabilities.insert(system_object, Rights::WRITE).unwrap();
        let system_read = capabilities.insert(system_object, Rights::READ).unwrap();

        let mut transaction = ConfigTransaction::<2>::new(0);
        component
            .stage(
                &mut transaction,
                component_write,
                OwnerIsolationSelection::Microvm,
            )
            .unwrap();
        system
            .stage(
                &mut transaction,
                system_write,
                OwnerIsolationSelection::TotalMicrovm,
            )
            .unwrap();
        assert_eq!(
            configuration.commit(&capabilities, root_control, &transaction),
            Ok(1)
        );

        let component_policy = component
            .read(&configuration, &capabilities, component_read)
            .unwrap();
        assert_eq!(
            component_policy.selection(),
            OwnerIsolationSelection::Microvm
        );
        assert_eq!(component_policy.setting(), component);
        assert_eq!(component_policy.revision(), 1);
        let substituted_native_class = IsolationPolicySetting::component(
            component.setting(),
            component.object(),
            IsolationPlacement::NativeProcess,
        )
        .unwrap();
        assert_eq!(
            substituted_native_class.read(&configuration, &capabilities, component_read),
            Err(ConfigError::SchemaViolation)
        );
        assert_eq!(
            system
                .read(&configuration, &capabilities, system_read)
                .unwrap()
                .selection(),
            OwnerIsolationSelection::TotalMicrovm
        );
        let plan = IsolationPolicyApplicationPlan::load(
            &configuration,
            &capabilities,
            system,
            system_read,
            component,
            component_read,
        )
        .unwrap();
        let applied = plan.apply(&configuration, &capabilities).unwrap();
        assert_eq!(applied.mode(), IsolationMode::TotalMicrovm);
        assert_eq!(
            applied.component_request(),
            Some(IsolationPlacement::Microvm)
        );
        assert_eq!(applied.policy_generation(), 1);
        let admission = applied.admission_table::<2>(SYSTEM_GENERATION).unwrap();
        assert_eq!(admission.mode(), IsolationMode::TotalMicrovm);
        assert_eq!(admission.policy_generation(), 1);
        let status = IsolationStatusSnapshot {
            system_generation: SYSTEM_GENERATION,
            policy_generation: 1,
            requested_mode: IsolationMode::TotalMicrovm,
            total_state: TotalMicrovmState::Satisfied,
            running_microvm_eligible: 1,
            running_in_microvm: 1,
            running_eligible_outside_microvm: 0,
            running_boot_only: 0,
            running_recovery_only: 0,
            running_unsupported_blockers: 0,
            unavailable_microvm_eligible: 0,
            native_fallback: 0,
            host_substrate: HostSubstrateCounts::default(),
            unavailable: IsolationUnavailableCounts::default(),
        };
        let bounds = IsolationServiceBounds::new(
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            IsolationPlacement::Microvm,
            true,
            true,
        )
        .unwrap();
        let view = applied.semantic_view(bounds, status).unwrap();
        assert_eq!(
            view.configured_system(),
            OwnerIsolationSelection::TotalMicrovm
        );
        assert_eq!(
            view.configured_component(),
            OwnerIsolationSelection::Microvm
        );
        assert_eq!(
            view.effective_placement(),
            Some(IsolationPlacement::Microvm)
        );
        assert_eq!(
            view.policy_source(),
            Some(IsolationPolicySource::TotalMicrovm)
        );
        assert!(!view.component_blocked());
        assert_eq!(view.status(), status);
        let mut stale_status = status;
        stale_status.policy_generation = 2;
        assert_eq!(
            applied.semantic_view(bounds, stale_status),
            Err(ConfigError::IsolationPolicyMismatch)
        );
        stale_status = status;
        stale_status.requested_mode = IsolationMode::Balanced;
        assert_eq!(
            applied.semantic_view(bounds, stale_status),
            Err(ConfigError::IsolationPolicyMismatch)
        );
        let native_only = IsolationServiceBounds::new(
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            true,
            false,
        )
        .unwrap();
        let blocked = applied.semantic_view(native_only, status).unwrap();
        assert!(blocked.component_blocked());
        assert_eq!(blocked.effective_placement(), None);
        assert_eq!(blocked.policy_source(), None);
        assert!(!blocked.microvm_supported());
        assert!(matches!(
            component.read(&configuration, &capabilities, system_read),
            Err(ConfigError::WrongObject)
        ));

        let mut checkpoint_bytes = [0; 512];
        let checkpoint = configuration
            .export_checkpoint(&capabilities, root_read, &mut checkpoint_bytes)
            .unwrap();
        let recovered = ConfigurationService::<2, 4>::recover_checkpoint(
            &capabilities,
            root_control,
            &checkpoint_bytes[..checkpoint.length],
            checkpoint.digest,
        )
        .unwrap();
        assert_eq!(
            component
                .read(&recovered, &capabilities, component_read)
                .unwrap()
                .selection(),
            OwnerIsolationSelection::Microvm
        );
        assert_eq!(
            system
                .read(&recovered, &capabilities, system_read)
                .unwrap()
                .selection(),
            OwnerIsolationSelection::TotalMicrovm
        );

        let revocable_read = capabilities.insert(component_object, Rights::READ).unwrap();
        let revoked_plan = IsolationPolicyApplicationPlan::load(
            &configuration,
            &capabilities,
            system,
            system_read,
            component,
            revocable_read,
        )
        .unwrap();
        capabilities.revoke(revocable_read).unwrap();
        assert_eq!(
            revoked_plan.apply(&configuration, &capabilities),
            Err(ConfigError::Unauthorized(CapabilityError::Invalid))
        );

        let stale_plan = IsolationPolicyApplicationPlan::load(
            &configuration,
            &capabilities,
            system,
            system_read,
            component,
            component_read,
        )
        .unwrap();
        let mut replacement = ConfigTransaction::<1>::new(1);
        component
            .stage(
                &mut replacement,
                component_write,
                OwnerIsolationSelection::Default,
            )
            .unwrap();
        configuration
            .commit(&capabilities, root_control, &replacement)
            .unwrap();
        assert_eq!(
            stale_plan.apply(&configuration, &capabilities),
            Err(ConfigError::RevisionConflict { current: 2 })
        );
    }

    #[test]
    fn settings_and_shell_share_one_capability_checked_isolation_edit() {
        let root_object = ObjectId(0x4953_4f45_4449_5452);
        let component_object = ObjectId(0x4953_4f45_4449_5443);
        let setting = IsolationPolicySetting::component(
            SettingId::new(73).unwrap(),
            component_object,
            IsolationPlacement::NativeProcess,
        )
        .unwrap();
        let mut configuration =
            ConfigurationService::<1, 4>::new(root_object, &[setting.schema().unwrap()]).unwrap();
        let mut capabilities = CapabilitySpace::<5>::new();
        let root_control = capabilities.insert(root_object, Rights::CONTROL).unwrap();
        let setting_write = capabilities
            .insert(component_object, Rights::WRITE)
            .unwrap();
        let setting_read = capabilities.insert(component_object, Rights::READ).unwrap();
        let wrong_write = capabilities.insert(ObjectId(99), Rights::WRITE).unwrap();

        let settings_edit =
            IsolationPolicyEdit::new(setting, OwnerIsolationSelection::Microvm, 0).unwrap();
        assert_eq!(
            IsolationSettingsAction::new(OwnerIsolationSelection::Microvm, 0)
                .edit(setting)
                .unwrap(),
            settings_edit
        );
        assert_eq!(
            IsolationShellCommand::parse("isolation set microvm 0", setting),
            Ok(IsolationShellCommand::Set(settings_edit))
        );
        assert_eq!(
            IsolationShellCommand::parse("isolation show", setting),
            Ok(IsolationShellCommand::Show)
        );
        assert_eq!(
            IsolationShellCommand::parse("isolation set total-microvm 0", setting),
            Err(ConfigError::SchemaViolation)
        );
        assert_eq!(
            IsolationShellCommand::parse("isolation set microvm 0 extra", setting),
            Err(ConfigError::NonCanonical)
        );
        assert_eq!(
            IsolationShellCommand::parse("isolation set microvm 18446744073709551616", setting),
            Err(ConfigError::InvalidValue)
        );
        let wire = settings_edit.encode();
        let shell_edit = IsolationPolicyEdit::decode(&wire).unwrap();
        assert_eq!(shell_edit, settings_edit);
        assert_eq!(
            shell_edit.commit(&mut configuration, &capabilities, root_control, wrong_write,),
            Err(ConfigError::WrongObject)
        );
        let committed = shell_edit
            .commit(
                &mut configuration,
                &capabilities,
                root_control,
                setting_write,
            )
            .unwrap();
        assert_eq!(committed.setting(), setting);
        assert_eq!(committed.selection(), OwnerIsolationSelection::Microvm);
        assert_eq!(committed.policy_generation(), 1);
        assert_eq!(
            setting
                .read(&configuration, &capabilities, setting_read)
                .unwrap()
                .selection(),
            OwnerIsolationSelection::Microvm
        );

        assert_eq!(
            settings_edit.commit(
                &mut configuration,
                &capabilities,
                root_control,
                setting_write,
            ),
            Err(ConfigError::RevisionConflict { current: 1 })
        );
        let mut tampered = wire;
        tampered[15] = 1;
        assert_eq!(
            IsolationPolicyEdit::decode(&tampered),
            Err(ConfigError::InvalidProtocol)
        );
        tampered = wire;
        tampered[12] = 2;
        assert_eq!(
            IsolationPolicyEdit::decode(&tampered),
            Err(ConfigError::InvalidProtocol)
        );
    }

    #[test]
    fn isolation_policy_rejects_scope_confusion_and_noncanonical_data() {
        let component = IsolationPolicySetting::component(
            SettingId::new(42).unwrap(),
            ObjectId(420),
            IsolationPlacement::NativeProcess,
        )
        .unwrap();
        let mut transaction = ConfigTransaction::<1>::new(0);
        assert_eq!(
            component.stage(
                &mut transaction,
                Capability::from_token(1),
                OwnerIsolationSelection::TotalMicrovm,
            ),
            Err(ConfigError::SchemaViolation)
        );
        assert!(transaction.is_empty());

        let mut configuration =
            ConfigurationService::<1, 2>::new(ObjectId(419), &[component.schema().unwrap()])
                .unwrap();
        let mut capabilities = CapabilitySpace::<3>::new();
        let root = capabilities.insert(ObjectId(419), Rights::CONTROL).unwrap();
        let write = capabilities.insert(ObjectId(420), Rights::WRITE).unwrap();
        let read = capabilities.insert(ObjectId(420), Rights::READ).unwrap();
        let mut malformed = [0; ISOLATION_POLICY_VALUE_BYTES];
        malformed[..8].copy_from_slice(&ISOLATION_POLICY_VALUE_MAGIC);
        malformed[8] = 1;
        malformed[9] = OwnerIsolationSelection::Microvm.token();
        malformed[15] = 1;
        let mut generic = ConfigTransaction::<1>::new(0);
        generic
            .push(ConfigUpdate::new(
                component.setting(),
                write,
                ConfigValue::bytes(&malformed).unwrap(),
            ))
            .unwrap();
        configuration.commit(&capabilities, root, &generic).unwrap();
        assert_eq!(
            component.read(&configuration, &capabilities, read),
            Err(ConfigError::NonCanonical)
        );
    }

    #[test]
    fn service_bounds_admit_exact_policy_without_fallback() {
        let dual = IsolationServiceBounds::new(
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            IsolationPlacement::Microvm,
            true,
            true,
        )
        .unwrap();
        let default = AppliedIsolationPolicy {
            mode: IsolationMode::Balanced,
            component_request: None,
            system_selection: OwnerIsolationSelection::Balanced,
            component_selection: OwnerIsolationSelection::Default,
            policy_generation: 9,
        }
        .admit_service(dual)
        .unwrap();
        assert_eq!(default.placement(), IsolationPlacement::NativeService);
        assert_eq!(default.source(), IsolationPolicySource::PackageDefault);
        assert_eq!(default.policy_generation(), 9);

        let total = AppliedIsolationPolicy {
            mode: IsolationMode::TotalMicrovm,
            component_request: Some(IsolationPlacement::NativeService),
            system_selection: OwnerIsolationSelection::TotalMicrovm,
            component_selection: OwnerIsolationSelection::Native,
            policy_generation: 10,
        }
        .admit_service(dual)
        .unwrap();
        assert_eq!(total.placement(), IsolationPlacement::Microvm);
        assert_eq!(total.source(), IsolationPolicySource::TotalMicrovm);
        let spec = total
            .service_spec(
                SYSTEM_GENERATION,
                ObjectId(501),
                ObjectId(502),
                3,
                17,
                TotalMicrovmClass::MicrovmEligible,
            )
            .unwrap();
        assert_eq!(spec.placement(), IsolationPlacement::Microvm);
        assert_eq!(spec.system_generation(), SYSTEM_GENERATION);
        assert_eq!(spec.policy_generation(), 10);
        assert_eq!(spec.interface_generation(), 3);
        assert_eq!(spec.provider_generation(), 17);

        let native_only = IsolationServiceBounds::new(
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            true,
            false,
        )
        .unwrap();
        assert_eq!(
            AppliedIsolationPolicy {
                mode: IsolationMode::TotalMicrovm,
                component_request: None,
                system_selection: OwnerIsolationSelection::TotalMicrovm,
                component_selection: OwnerIsolationSelection::Default,
                policy_generation: 11,
            }
            .admit_service(native_only),
            Err(ConfigError::SchemaViolation)
        );

        let microvm_required = IsolationServiceBounds::new(
            IsolationPlacement::Microvm,
            IsolationPlacement::Microvm,
            IsolationPlacement::Microvm,
            false,
            true,
        )
        .unwrap();
        assert_eq!(
            AppliedIsolationPolicy {
                mode: IsolationMode::Custom,
                component_request: Some(IsolationPlacement::NativeService),
                system_selection: OwnerIsolationSelection::Custom,
                component_selection: OwnerIsolationSelection::Native,
                policy_generation: 12,
            }
            .admit_service(microvm_required),
            Err(ConfigError::SchemaViolation)
        );
        assert!(
            IsolationServiceBounds::new(
                IsolationPlacement::NativeService,
                IsolationPlacement::Microvm,
                IsolationPlacement::Microvm,
                true,
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn recovered_total_admission_prepares_only_release_classified_service_routes() {
        let persistent = AppliedIsolationPolicy {
            mode: IsolationMode::Balanced,
            component_request: Some(IsolationPlacement::NativeService),
            system_selection: OwnerIsolationSelection::Balanced,
            component_selection: OwnerIsolationSelection::Native,
            policy_generation: 9,
        };
        let policy = RecoveredBootIsolationPolicy {
            effective: persistent
                .compose_boot_override(Some(BootIsolationOverride::TotalMicrovmOnce)),
            authority_epoch: 12,
            configuration_revision: 9,
            configuration_service: ServiceId::from_token((3u64 << 32) | 1),
            boot_accepted_epoch: 11,
            recovery_volume: stable_volume(),
            recovery_root_generation: 14,
        };
        let domain = ObjectId(0x434f_4e46_4947_0001);
        let release = activated_configuration_release(domain, 9);
        let mut total = policy.bind_release_inventory(release).unwrap();
        let active_generation = total.release().active_release().generation();
        assert_eq!(
            total.admission().system_generation_digest(),
            Some(active_generation.generation_digest())
        );
        assert_eq!(
            total.admission().interface_catalog_digest(),
            Some(active_generation.interface_catalog_digest())
        );
        let bounds = IsolationServiceBounds::new(
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            IsolationPlacement::Microvm,
            true,
            true,
        )
        .unwrap();
        let identity = IsolationServiceIdentity::new(
            domain,
            ObjectId(0x434f_4e46_0000_0001),
            1,
            5,
            TotalMicrovmClass::MicrovmEligible,
        )
        .unwrap();
        let prepared = total.prepare_service(bounds, identity).unwrap();
        assert_eq!(prepared.spec().placement(), IsolationPlacement::Microvm);
        assert_eq!(prepared.spec().system_generation(), 33);
        assert_eq!(prepared.spec().policy_generation(), 9);
        let routed = prepared.commit(total.admission_mut(), 0x51u64).unwrap();
        assert_eq!(routed.domain(), domain);
        assert_eq!(routed.into_endpoint(), 0x51);
        let proof = total.finalize().unwrap();
        assert_eq!(proof.classified_domains(), 1);
        assert_eq!(proof.running_microvm_eligible(), 1);
        assert_eq!(proof.running_in_microvm(), 1);

        let release = activated_configuration_release(domain, 9);
        let mut rejected = policy.bind_release_inventory(release).unwrap();
        let unclassified = IsolationServiceIdentity::new(
            ObjectId(domain.0 + 1),
            ObjectId(0x434f_4e46_0000_0001),
            1,
            5,
            TotalMicrovmClass::MicrovmEligible,
        )
        .unwrap();
        assert_eq!(
            rejected.prepare_service(bounds, unclassified),
            Err(ConfiguredIsolationPreparationError::Configuration(
                ConfigError::SchemaViolation
            ))
        );
        assert_eq!(rejected.admission().running().count(), 0);
        assert_eq!(rejected.admission().unavailable_domains().count(), 0);

        let release = activated_configuration_release(domain, 10);
        assert!(matches!(
            policy.bind_release_inventory(release),
            Err(ConfigError::IsolationPolicyMismatch)
        ));
    }

    #[test]
    fn complete_service_set_rolls_back_an_earlier_distinct_domain() {
        let policy = AppliedIsolationPolicy {
            mode: IsolationMode::Balanced,
            component_request: Some(IsolationPlacement::NativeService),
            system_selection: OwnerIsolationSelection::Balanced,
            component_selection: OwnerIsolationSelection::Native,
            policy_generation: 19,
        }
        .compose_boot_override(Some(BootIsolationOverride::TotalMicrovmOnce));
        let first_domain = ObjectId(0x434f_4e46_4947_0011);
        let second_domain = ObjectId(0x4445_504c_4f59_0012);
        let valid_bounds = IsolationServiceBounds::new(
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            IsolationPlacement::Microvm,
            true,
            true,
        )
        .unwrap();
        let native_only_bounds = IsolationServiceBounds::new(
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            true,
            false,
        )
        .unwrap();
        let first = IsolationServiceIdentity::new(
            first_domain,
            ObjectId(0x434f_4e46_0000_0011),
            1,
            5,
            TotalMicrovmClass::MicrovmEligible,
        )
        .unwrap();
        let second = IsolationServiceIdentity::new(
            second_domain,
            ObjectId(0x4445_504c_0000_0012),
            1,
            6,
            TotalMicrovmClass::MicrovmEligible,
        )
        .unwrap();

        let release = activated_two_domain_release(first_domain, second_domain, 19);
        let mut rejected = policy.bind_release_inventory(release).unwrap();
        assert_eq!(
            rejected
                .prepare_complete_service_set(&[
                    TotalServicePreparationBinding::new(valid_bounds, first),
                    TotalServicePreparationBinding::new(native_only_bounds, second),
                ])
                .err(),
            Some(CompleteTotalServicePreparationError::Preparation(
                ConfiguredIsolationPreparationError::Configuration(ConfigError::SchemaViolation)
            ))
        );
        assert_eq!(rejected.admission().running().count(), 0);
        assert_eq!(rejected.admission().unavailable_domains().count(), 0);

        // Reusing the same admission owner proves the failed transaction left
        // neither distinct domain occupying a prepared slot.
        let mut prepared = rejected
            .prepare_complete_service_set(&[
                TotalServicePreparationBinding::new(valid_bounds, first),
                TotalServicePreparationBinding::new(valid_bounds, second),
            ])
            .unwrap();
        assert_eq!(prepared.len(), 2);
        prepared
            .take(second_domain)
            .unwrap()
            .cancel(rejected.admission_mut())
            .unwrap();
        prepared
            .take(first_domain)
            .unwrap()
            .cancel(rejected.admission_mut())
            .unwrap();
        assert!(prepared.is_empty());
        assert_eq!(prepared.len(), 0);
        assert!(prepared.into_routes().iter().all(Option::is_none));
        assert_eq!(rejected.admission().running().count(), 0);

        let mut prepared = rejected
            .prepare_complete_service_set(&[
                TotalServicePreparationBinding::new(valid_bounds, first),
                TotalServicePreparationBinding::new(valid_bounds, second),
            ])
            .unwrap();
        let transformed = prepared.take(first_domain).unwrap();
        assert_eq!(prepared.len(), 1);
        prepared.restore(transformed).unwrap();
        assert_eq!(prepared.len(), 2);
        let mut routed = prepared
            .commit_complete(
                rejected.admission_mut(),
                [
                    Some(TotalServiceEndpointBinding::new(second_domain, 0x62u64)),
                    Some(TotalServiceEndpointBinding::new(first_domain, 0x51u64)),
                ],
            )
            .unwrap();
        assert_eq!(routed.len(), 2);
        assert_eq!(routed.take(first_domain).unwrap().into_endpoint(), 0x51);
        assert_eq!(routed.take(second_domain).unwrap().into_endpoint(), 0x62);
        assert!(routed.is_empty());
        assert_eq!(rejected.admission().running().count(), 2);
        let proof = rejected.finalize().unwrap();
        assert_eq!(proof.classified_domains(), 2);
        assert_eq!(proof.running_in_microvm(), 2);
        rejected.admission_mut().retire(second_domain).unwrap();
        rejected.admission_mut().retire(first_domain).unwrap();

        let release = activated_two_domain_release(first_domain, second_domain, 19);
        let mut invalid = policy.bind_release_inventory(release).unwrap();
        let prepared = invalid
            .prepare_complete_service_set(&[
                TotalServicePreparationBinding::new(valid_bounds, first),
                TotalServicePreparationBinding::new(valid_bounds, second),
            ])
            .unwrap();
        let failure = prepared
            .commit_complete(
                invalid.admission_mut(),
                [
                    Some(TotalServiceEndpointBinding::new(first_domain, 0x71u64)),
                    Some(TotalServiceEndpointBinding::new(first_domain, 0x72u64)),
                ],
            )
            .err()
            .unwrap();
        assert_eq!(
            failure.error(),
            CompleteTotalServiceCommitError::DuplicateDomain
        );
        assert_eq!(failure.into_endpoints().iter().flatten().count(), 2);
        assert_eq!(invalid.admission().running().count(), 0);
        let prepared = invalid
            .prepare_complete_service_set(&[
                TotalServicePreparationBinding::new(valid_bounds, first),
                TotalServicePreparationBinding::new(valid_bounds, second),
            ])
            .unwrap();
        for route in prepared.into_routes().into_iter().rev().flatten() {
            route.cancel(invalid.admission_mut()).unwrap();
        }

        let release = activated_two_domain_release(first_domain, second_domain, 19);
        let mut construction = policy.bind_release_inventory(release).unwrap();
        let prepared = construction
            .prepare_complete_service_set(&[
                TotalServicePreparationBinding::new(valid_bounds, first),
                TotalServicePreparationBinding::new(valid_bounds, second),
            ])
            .unwrap();
        let failure = prepared
            .construct_complete_endpoints(construction.admission_mut(), |spec| {
                if spec.domain() == second_domain {
                    Err(0xdead_u32)
                } else {
                    Ok(spec.provider_generation())
                }
            })
            .err()
            .unwrap();
        assert_eq!(
            failure.error(),
            &CompleteTotalServiceConstructionError::Construction(0xdead)
        );
        let returned = failure.into_endpoints();
        assert_eq!(returned.iter().flatten().count(), 1);
        assert_eq!(
            returned.iter().flatten().next().unwrap().domain(),
            first_domain
        );
        assert_eq!(construction.admission().running().count(), 0);

        // The same exact owner can immediately prepare, construct and publish
        // both domains after tearing down the returned provisional endpoint.
        let prepared = construction
            .prepare_complete_service_set(&[
                TotalServicePreparationBinding::new(valid_bounds, first),
                TotalServicePreparationBinding::new(valid_bounds, second),
            ])
            .unwrap();
        let (prepared, endpoints) = prepared
            .construct_complete_endpoints(construction.admission_mut(), |spec| {
                Ok::<_, u32>(spec.provider_generation())
            })
            .unwrap();
        let routed = prepared
            .commit_complete(construction.admission_mut(), endpoints)
            .unwrap();
        assert_eq!(routed.len(), 2);
        assert_eq!(construction.finalize().unwrap().running_in_microvm(), 2);
        assert_eq!(routed.into_endpoints().iter().flatten().count(), 2);
        construction.admission_mut().retire(second_domain).unwrap();
        construction.admission_mut().retire(first_domain).unwrap();
    }

    #[test]
    fn one_boot_total_overlay_strengthens_without_mutating_persistent_policy() {
        let configured = AppliedIsolationPolicy {
            mode: IsolationMode::Balanced,
            component_request: Some(IsolationPlacement::NativeService),
            system_selection: OwnerIsolationSelection::Balanced,
            component_selection: OwnerIsolationSelection::Native,
            policy_generation: 27,
        };
        let ordinary = configured.compose_boot_override(None);
        assert_eq!(ordinary.configured(), configured);
        assert_eq!(ordinary.mode(), IsolationMode::Balanced);
        assert_eq!(ordinary.boot_override(), None);
        assert_eq!(ordinary.policy_generation(), 27);

        let total = configured.compose_boot_override(Some(BootIsolationOverride::TotalMicrovmOnce));
        assert_eq!(total.configured(), configured);
        assert_eq!(total.configured().mode(), IsolationMode::Balanced);
        assert_eq!(total.mode(), IsolationMode::TotalMicrovm);
        assert_eq!(
            total.boot_override(),
            Some(BootIsolationOverride::TotalMicrovmOnce)
        );
        assert_eq!(total.policy_generation(), 27);
        let admission = total.admission_table::<1>(SYSTEM_GENERATION).unwrap();
        assert_eq!(admission.mode(), IsolationMode::TotalMicrovm);
        assert_eq!(admission.policy_generation(), 27);

        let dual = IsolationServiceBounds::new(
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            IsolationPlacement::Microvm,
            true,
            true,
        )
        .unwrap();
        let admitted = total.admit_service(dual).unwrap();
        assert_eq!(admitted.placement(), IsolationPlacement::Microvm);
        assert_eq!(admitted.source(), IsolationPolicySource::TotalMicrovm);
        assert_eq!(admitted.policy_generation(), 27);

        let native_only = IsolationServiceBounds::new(
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            true,
            false,
        )
        .unwrap();
        assert_eq!(
            total.admit_service(native_only),
            Err(ConfigError::SchemaViolation)
        );
        assert_eq!(configured.mode(), IsolationMode::Balanced);
        assert_eq!(
            configured.component_request(),
            Some(IsolationPlacement::NativeService)
        );
    }

    #[test]
    fn configured_route_revalidates_policy_binding_before_backend_launch() {
        let root_object = ObjectId(601);
        let component_object = ObjectId(602);
        let system_object = ObjectId(603);
        let component = IsolationPolicySetting::component(
            SettingId::new(60).unwrap(),
            component_object,
            IsolationPlacement::NativeService,
        )
        .unwrap();
        let system =
            IsolationPolicySetting::system(SettingId::new(61).unwrap(), system_object).unwrap();
        let mut configuration = ConfigurationService::<2, 4>::new(
            root_object,
            &[component.schema().unwrap(), system.schema().unwrap()],
        )
        .unwrap();
        let mut capabilities = CapabilitySpace::<5>::new();
        let root = capabilities.insert(root_object, Rights::CONTROL).unwrap();
        let component_write = capabilities
            .insert(component_object, Rights::WRITE)
            .unwrap();
        let component_read = capabilities.insert(component_object, Rights::READ).unwrap();
        let system_write = capabilities.insert(system_object, Rights::WRITE).unwrap();
        let system_read = capabilities.insert(system_object, Rights::READ).unwrap();
        let mut initial = ConfigTransaction::<2>::new(0);
        component
            .stage(
                &mut initial,
                component_write,
                OwnerIsolationSelection::Microvm,
            )
            .unwrap();
        system
            .stage(
                &mut initial,
                system_write,
                OwnerIsolationSelection::TotalMicrovm,
            )
            .unwrap();
        configuration.commit(&capabilities, root, &initial).unwrap();
        let plan = IsolationPolicyApplicationPlan::load(
            &configuration,
            &capabilities,
            system,
            system_read,
            component,
            component_read,
        )
        .unwrap();
        let bounds = IsolationServiceBounds::new(
            IsolationPlacement::NativeService,
            IsolationPlacement::NativeService,
            IsolationPlacement::Microvm,
            true,
            true,
        )
        .unwrap();
        let identity = IsolationServiceIdentity::new(
            ObjectId(604),
            ObjectId(605),
            3,
            19,
            TotalMicrovmClass::MicrovmEligible,
        )
        .unwrap();
        let mut prepared_admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 1)
                .unwrap();
        let prepared = prepare_configured_isolation_service_route(
            &configuration,
            &capabilities,
            plan,
            bounds,
            identity,
            &mut prepared_admission,
        )
        .unwrap();
        assert_eq!(prepared.spec().placement(), IsolationPlacement::Microvm);
        assert_eq!(prepared.spec().provider_generation(), 19);
        prepared.cancel(&mut prepared_admission).unwrap();
        let mut admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 1)
                .unwrap();
        let mut backend = ConfigurationPlacementBackend::new(
            NativePlacementProbe::default(),
            MicrovmPlacementProbe::default(),
        );
        let routed = route_configured_isolation_service(
            &configuration,
            &capabilities,
            plan,
            bounds,
            identity,
            &mut admission,
            &mut backend,
        )
        .unwrap();
        assert_eq!(routed.placement(), IsolationPlacement::Microvm);
        assert_eq!(routed.interface(), ObjectId(605));
        assert_eq!(routed.interface_generation(), 3);
        assert_eq!(routed.provider_generation(), 19);
        let (native, microvm) = backend.into_parts();
        assert_eq!((native.launches, microvm.launches), (0, 1));

        let stale_plan = IsolationPolicyApplicationPlan::load(
            &configuration,
            &capabilities,
            system,
            system_read,
            component,
            component_read,
        )
        .unwrap();
        let mut replacement = ConfigTransaction::<1>::new(1);
        component
            .stage(
                &mut replacement,
                component_write,
                OwnerIsolationSelection::Default,
            )
            .unwrap();
        configuration
            .commit(&capabilities, root, &replacement)
            .unwrap();
        let mut stale_admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::TotalMicrovm, SYSTEM_GENERATION, 1)
                .unwrap();
        let mut stale_backend = ConfigurationPlacementBackend::new(
            NativePlacementProbe::default(),
            MicrovmPlacementProbe::default(),
        );
        assert!(matches!(
            route_configured_isolation_service(
                &configuration,
                &capabilities,
                stale_plan,
                bounds,
                identity,
                &mut stale_admission,
                &mut stale_backend,
            ),
            Err(ConfiguredIsolationRouteError::Configuration(
                ConfigError::RevisionConflict { current: 2 }
            ))
        ));
        let (native, microvm) = stale_backend.into_parts();
        assert_eq!((native.launches, microvm.launches), (0, 0));

        let current_plan = IsolationPolicyApplicationPlan::load(
            &configuration,
            &capabilities,
            system,
            system_read,
            component,
            component_read,
        )
        .unwrap();
        let mut wrong_admission =
            IsolationAdmissionTable::<1>::new(IsolationMode::Balanced, SYSTEM_GENERATION, 2)
                .unwrap();
        let mut wrong_backend = ConfigurationPlacementBackend::new(
            NativePlacementProbe::default(),
            MicrovmPlacementProbe::default(),
        );
        assert!(matches!(
            route_configured_isolation_service(
                &configuration,
                &capabilities,
                current_plan,
                bounds,
                identity,
                &mut wrong_admission,
                &mut wrong_backend,
            ),
            Err(ConfiguredIsolationRouteError::Configuration(
                ConfigError::IsolationPolicyMismatch
            ))
        ));
        let (native, microvm) = wrong_backend.into_parts();
        assert_eq!((native.launches, microvm.launches), (0, 0));
    }
}
