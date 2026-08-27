#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TrustRoot, VmBackend, artifact_statement};
    use mrml_crypto::{
        LAMPORT_PRIVATE_KEY_BYTES, LAMPORT_PUBLIC_KEY_BYTES, LAMPORT_SIGNATURE_BYTES,
        lamport_public_key, lamport_sign,
    };

    struct MockExecutor(Result<bool, u8>);

    impl<const N: usize> GpuBatchExecutor<N> for MockExecutor {
        type Error = u8;

        fn submit(&mut self, _: &ValidatedGpuBatch<N>) -> Result<bool, Self::Error> {
            self.0
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockVmmError {
        Bounds,
        Injected,
    }

    struct MockVmm {
        memory: [u8; 0x6000],
        fail_io: bool,
    }

    impl MockVmm {
        const fn new() -> Self {
            Self {
                memory: [0; 0x6000],
                fail_io: false,
            }
        }
    }

    impl crate::VmBackend for MockVmm {
        type Error = MockVmmError;

        fn run(&mut self, _: u32) -> Result<crate::VmExit, Self::Error> {
            Ok(crate::VmExit::Halted)
        }

        fn read_guest(&self, address: u64, output: &mut [u8]) -> Result<(), Self::Error> {
            if self.fail_io {
                return Err(MockVmmError::Injected);
            }
            let start = usize::try_from(address).map_err(|_| MockVmmError::Bounds)?;
            let end = start
                .checked_add(output.len())
                .ok_or(MockVmmError::Bounds)?;
            output.copy_from_slice(self.memory.get(start..end).ok_or(MockVmmError::Bounds)?);
            Ok(())
        }

        fn write_guest(&mut self, address: u64, input: &[u8]) -> Result<(), Self::Error> {
            if self.fail_io {
                return Err(MockVmmError::Injected);
            }
            let start = usize::try_from(address).map_err(|_| MockVmmError::Bounds)?;
            let end = start.checked_add(input.len()).ok_or(MockVmmError::Bounds)?;
            self.memory
                .get_mut(start..end)
                .ok_or(MockVmmError::Bounds)?
                .copy_from_slice(input);
            Ok(())
        }

        fn inject_interrupt(&mut self, _: u32, _: u8) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl GpuVmmMemory for MockVmm {
        fn write_gpu_service(&mut self, address: u64, input: &[u8]) -> Result<(), Self::Error> {
            self.write_guest(address, input)
        }
    }

    #[test]
    fn vmm_bridge_copies_disjoint_rings_and_poison_fails_closed() {
        const SLOTS: usize = 4;
        let layout = GpuSharedQueueLayout::new(0x1000, 0x3000, SLOTS).unwrap();
        let mut backend = MockVmm::new();
        let mut bridge = GpuVmmQueueBridge::<SLOTS>::new(layout).unwrap();
        let mut owned = GpuCommandRing::<SLOTS>::new().unwrap();
        let command = [0x5a; GPU_QUEUE_MESSAGE_BYTES];
        let command_slot = 0x1000 + core::mem::size_of::<GpuSharedRingIndices>() as u64;
        backend.write_guest(command_slot, &command).unwrap();
        backend.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();

        bridge.consume_command(&mut backend, &mut owned).unwrap();
        let mut copied = [0; GPU_QUEUE_MESSAGE_BYTES];
        owned.dequeue(&mut copied).unwrap();
        assert_eq!(copied, command);
        let mut consumed = [0; 8];
        backend.read_guest(0x1040, &mut consumed).unwrap();
        assert_eq!(u64::from_le_bytes(consumed), 1);

        let completion = [0xa5; GPU_QUEUE_MESSAGE_BYTES];
        bridge
            .publish_completion(&mut backend, &completion)
            .unwrap();
        let completion_slot = 0x3000 + core::mem::size_of::<GpuSharedRingIndices>() as u64;
        let mut copied_completion = [0; GPU_QUEUE_MESSAGE_BYTES];
        backend
            .read_guest(completion_slot, &mut copied_completion)
            .unwrap();
        assert_eq!(copied_completion, completion);
        let mut published = [0; 8];
        backend.read_guest(0x3000, &mut published).unwrap();
        assert_eq!(u64::from_le_bytes(published), 1);

        backend.fail_io = true;
        assert_eq!(
            bridge.consume_command(&mut backend, &mut owned),
            Err(GpuVmmQueueError::Backend(MockVmmError::Injected))
        );
        assert!(bridge.is_poisoned());
        backend.fail_io = false;
        assert_eq!(
            bridge.publish_completion(&mut backend, &completion),
            Err(GpuVmmQueueError::Poisoned)
        );
    }

    #[test]
    fn queue_identity_is_launch_unique_and_rejects_absent_entropy() {
        assert_eq!(
            GpuQueueIdentity::from_boot_entropy(&[0; 32]),
            Err(GpuError::InvalidQueueIdentity)
        );
        let first = GpuQueueIdentity::from_boot_entropy(&[0x35; 32]).unwrap();
        let repeated = GpuQueueIdentity::from_boot_entropy(&[0x35; 32]).unwrap();
        let second = GpuQueueIdentity::from_boot_entropy(&[0x36; 32]).unwrap();
        assert_eq!(first, repeated);
        assert_ne!(first, second);
        assert_ne!(first.session(), 0);
        assert!(first.key().iter().any(|byte| *byte != 0));
        GpuQueueSender::new(first.session(), first.key()).unwrap();
        GpuQueueReceiver::new(first.session(), first.key()).unwrap();
    }

    #[test]
    fn quotas_ranges_and_stale_buffer_ids_are_enforced() {
        let mut session = VirtualGpuSession::<2>::new(1024);
        let buffer = session.allocate(768).unwrap();
        assert_eq!(session.allocate(257), Err(GpuError::QuotaExceeded));
        assert_eq!(
            session.validate_access(BufferAccess::new(buffer, 700, 69, BufferMode::Read)),
            Err(GpuError::OutOfBounds)
        );
        assert!(
            session
                .validate_access(BufferAccess::new(buffer, 700, 68, BufferMode::Read))
                .is_ok()
        );
        session.free(buffer).unwrap();
        let replacement = session.allocate(32).unwrap();
        assert_ne!(buffer, replacement);
        assert_eq!(
            session.validate_access(BufferAccess::new(buffer, 0, 1, BufferMode::Read)),
            Err(GpuError::InvalidBuffer)
        );
    }

    #[test]
    fn mediated_executor_preflights_all_proofs_before_ordered_launches() {
        #[derive(Clone, Copy)]
        struct Backend {
            proof_valid: bool,
            verified: bool,
            launches: u32,
            launched_before_verify: bool,
            finished: bool,
        }
        impl GpuHostBackend for Backend {
            type Error = ();
            fn reverify_expert_selection(
                &mut self,
                _: &ValidatedExpertSelection,
            ) -> Result<bool, Self::Error> {
                self.verified = true;
                Ok(self.proof_valid)
            }
            fn launch(
                &mut self,
                _: PreparedGpuDispatch,
                _: ValidatedKernelLaunch,
            ) -> Result<(), Self::Error> {
                self.launched_before_verify |= !self.verified;
                self.launches += 1;
                Ok(())
            }
            fn finish_batch(&mut self) -> Result<(), Self::Error> {
                self.finished = true;
                Ok(())
            }
        }
        let id = |slot| BufferId {
            slot,
            generation: 1,
        };
        let access = BufferAccess::new(id(0), 0, 4, BufferMode::Read);
        let mut ids = [0u8; 4];
        ids.copy_from_slice(&0_i32.to_le_bytes());
        let mut weights = [0u8; 4];
        weights.copy_from_slice(&1.0_f32.to_bits().to_le_bytes());
        let selection = ValidatedExpertSelection::admit(
            access,
            &ids,
            BufferAccess::new(id(1), 0, 4, BufferMode::Read),
            &weights,
            1,
            1,
            1,
        )
        .unwrap();
        let dispatch = Dispatch::new(
            KernelId::new(7).unwrap(),
            [1, 1, 1],
            [256, 1, 1],
            0,
            &[
                access,
                access,
                BufferAccess::new(id(2), 0, 4, BufferMode::Write),
            ],
        )
        .unwrap();
        let launch = dispatch.validate_executor_schema().unwrap();
        let prepared_entry = |request_id, slot| PreparedGpuDispatch {
            request_id,
            dispatch_id: DispatchId {
                slot,
                generation: 1,
            },
            dispatch,
        };
        let batch = ValidatedGpuBatch {
            prepared: PreparedGpuBatch {
                entries: [Some(prepared_entry(1, 0)), Some(prepared_entry(2, 1))],
                count: 2,
            },
            launches: [Some(launch), Some(launch)],
            moe_selections: [None, Some(selection)],
        };
        let mut rejected = MediatedGpuExecutor::new(Backend {
            proof_valid: false,
            verified: false,
            launches: 0,
            launched_before_verify: false,
            finished: false,
        });
        assert_eq!(
            GpuBatchExecutor::<2>::submit(&mut rejected, &batch),
            Ok(false)
        );
        assert_eq!(rejected.backend().launches, 0);
        assert!(!rejected.backend().finished);

        let mut accepted = MediatedGpuExecutor::new(Backend {
            proof_valid: true,
            verified: false,
            launches: 0,
            launched_before_verify: false,
            finished: false,
        });
        assert_eq!(
            GpuBatchExecutor::<2>::submit(&mut accepted, &batch),
            Ok(true)
        );
        assert_eq!(accepted.backend().launches, 2);
        assert!(!accepted.backend().launched_before_verify);
        assert!(accepted.backend().finished);
    }

    #[test]
    fn only_embedded_kernels_and_bounded_launch_shapes_are_accepted() {
        assert!(KernelId::new(27).is_ok());
        assert_eq!(KernelId::new(28), Err(GpuError::InvalidKernel));
        let kernel = KernelId::new(0).unwrap();
        assert!(Dispatch::new(kernel, [1, 1, 1], [32, 1, 1], 0, &[]).is_ok());
        assert!(matches!(
            Dispatch::new(kernel, [1, 1, 1], [1024, 2, 1], 0, &[]),
            Err(GpuError::InvalidGrid)
        ));
        assert!(matches!(
            Dispatch::new(kernel, [1, 1, 1], [32, 1, 1], MAX_SHARED_MEMORY + 1, &[]),
            Err(GpuError::ExcessiveSharedMemory)
        ));
        assert_eq!(
            Dispatch::new_with_scalars(
                kernel,
                [1, 1, 1],
                [32, 1, 1],
                0,
                &[],
                &[ScalarArg::u32(0); MAX_DISPATCH_SCALARS + 1],
            ),
            Err(GpuError::TooManyScalars)
        );
    }

    #[test]
    fn executor_accepts_only_the_exact_add_f32_abi() {
        let id = |slot| BufferId {
            slot,
            generation: 1,
        };
        let accesses = [
            BufferAccess::new(id(0), 0, 4096, BufferMode::Read),
            BufferAccess::new(id(1), 0, 4096, BufferMode::Read),
            BufferAccess::new(id(2), 0, 4096, BufferMode::Write),
        ];
        let dispatch = Dispatch::new(
            KernelId::new(7).unwrap(),
            [4, 1, 1],
            [256, 1, 1],
            0,
            &accesses,
        )
        .unwrap();
        let launch = dispatch.validate_executor_schema().unwrap();
        assert_eq!(launch.element_count(), 1024);
        assert_eq!(launch.dispatch(), &dispatch);
        for kernel in [9, 10] {
            let activation = Dispatch::new(
                KernelId::new(kernel).unwrap(),
                [4, 1, 1],
                [256, 1, 1],
                0,
                &accesses,
            )
            .unwrap();
            assert_eq!(
                activation
                    .validate_executor_schema()
                    .unwrap()
                    .element_count(),
                1024
            );
        }

        let wrong_mode = [
            accesses[0],
            accesses[1],
            BufferAccess::new(id(2), 0, 4096, BufferMode::ReadWrite),
        ];
        let wrong_mode = Dispatch::new(
            KernelId::new(7).unwrap(),
            [4, 1, 1],
            [256, 1, 1],
            0,
            &wrong_mode,
        )
        .unwrap();
        assert_eq!(
            wrong_mode.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );

        let wrong_grid = Dispatch::new(
            KernelId::new(7).unwrap(),
            [5, 1, 1],
            [256, 1, 1],
            0,
            &accesses,
        )
        .unwrap();
        assert_eq!(
            wrong_grid.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );
        let unsupported = Dispatch::new(
            KernelId::new(22).unwrap(),
            [1, 1, 1],
            [128, 1, 1],
            0,
            &accesses,
        )
        .unwrap();
        assert_eq!(
            unsupported.validate_executor_schema(),
            Err(GpuError::UnsupportedKernelSchema)
        );
        let prepared = PreparedGpuBatch {
            entries: [Some(PreparedGpuDispatch {
                request_id: 9,
                dispatch_id: DispatchId {
                    slot: 0,
                    generation: 1,
                },
                dispatch: unsupported,
            })],
            count: 1,
        };
        let bundle = VerifiedGpuKernelBundle {
            version: 1,
            digest: [3; 64],
        };
        assert_eq!(
            bundle.validate_batch(&prepared).map(|_| ()),
            Err(GpuError::UnsupportedKernelSchema)
        );
    }

    #[test]
    fn executor_binds_q4_gemm_dimensions_to_ranges_and_geometry() {
        let id = |slot| BufferId {
            slot,
            generation: 1,
        };
        let accesses = [
            BufferAccess::new(id(0), 0, 288, BufferMode::Read),
            BufferAccess::new(id(1), 0, 1024, BufferMode::Read),
            BufferAccess::new(id(2), 0, 512, BufferMode::Write),
        ];
        let scalars = [ScalarArg::i32(16), ScalarArg::i32(32), ScalarArg::i32(8)];
        let dispatch = Dispatch::new_with_scalars(
            KernelId::new(0).unwrap(),
            [2, 1, 1],
            [128, 1, 1],
            0,
            &accesses,
            &scalars,
        )
        .unwrap();
        assert_eq!(
            dispatch.validate_executor_schema().unwrap().element_count(),
            128
        );

        let wrong_columns = [ScalarArg::i32(16), ScalarArg::i32(31), ScalarArg::i32(8)];
        let wrong_columns = Dispatch::new_with_scalars(
            KernelId::new(0).unwrap(),
            [2, 1, 1],
            [128, 1, 1],
            0,
            &accesses,
            &wrong_columns,
        )
        .unwrap();
        assert_eq!(
            wrong_columns.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );

        let short_output = [
            accesses[0],
            accesses[1],
            BufferAccess::new(id(2), 0, 508, BufferMode::Write),
        ];
        let short_output = Dispatch::new_with_scalars(
            KernelId::new(0).unwrap(),
            [2, 1, 1],
            [128, 1, 1],
            0,
            &short_output,
            &scalars,
        )
        .unwrap();
        assert_eq!(
            short_output.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );

        let wrong_type = [ScalarArg::u32(16), ScalarArg::i32(32), ScalarArg::i32(8)];
        let wrong_type = Dispatch::new_with_scalars(
            KernelId::new(0).unwrap(),
            [2, 1, 1],
            [128, 1, 1],
            0,
            &accesses,
            &wrong_type,
        )
        .unwrap();
        assert_eq!(
            wrong_type.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );
    }

    #[test]
    fn executor_binds_fused_qkv_matrices_and_packed_output() {
        let id = |slot| BufferId {
            slot,
            generation: 1,
        };
        let batched_accesses = [
            BufferAccess::new(id(0), 0, 288, BufferMode::Read),
            BufferAccess::new(id(1), 0, 144, BufferMode::Read),
            BufferAccess::new(id(2), 0, 144, BufferMode::Read),
            BufferAccess::new(id(3), 0, 1024, BufferMode::Read),
            BufferAccess::new(id(4), 0, 1024, BufferMode::Write),
        ];
        let batched_scalars = [
            ScalarArg::i32(16),
            ScalarArg::i32(8),
            ScalarArg::i32(32),
            ScalarArg::i32(8),
        ];
        let batched = Dispatch::new_with_scalars(
            KernelId::new(1).unwrap(),
            [2, 1, 1],
            [256, 1, 1],
            0,
            &batched_accesses,
            &batched_scalars,
        )
        .unwrap();
        assert_eq!(
            batched.validate_executor_schema().unwrap().element_count(),
            256
        );

        let gemv_accesses = [
            batched_accesses[0],
            batched_accesses[1],
            batched_accesses[2],
            BufferAccess::new(id(3), 0, 128, BufferMode::Read),
            BufferAccess::new(id(4), 0, 128, BufferMode::Write),
        ];
        let gemv_scalars = [batched_scalars[0], batched_scalars[1], batched_scalars[2]];
        let gemv = Dispatch::new_with_scalars(
            KernelId::new(2).unwrap(),
            [4, 1, 1],
            [128, 1, 1],
            0,
            &gemv_accesses,
            &gemv_scalars,
        )
        .unwrap();
        assert_eq!(gemv.validate_executor_schema().unwrap().element_count(), 32);

        let short_v = [
            batched_accesses[0],
            batched_accesses[1],
            BufferAccess::new(id(2), 0, 143, BufferMode::Read),
            batched_accesses[3],
            batched_accesses[4],
        ];
        let short_v = Dispatch::new_with_scalars(
            KernelId::new(1).unwrap(),
            [2, 1, 1],
            [256, 1, 1],
            0,
            &short_v,
            &batched_scalars,
        )
        .unwrap();
        assert_eq!(
            short_v.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );
    }

    #[test]
    fn executor_binds_fused_q4_geglu_matrices() {
        let id = |slot| BufferId {
            slot,
            generation: 1,
        };
        let batched_accesses = [
            BufferAccess::new(id(0), 0, 288, BufferMode::Read),
            BufferAccess::new(id(1), 0, 288, BufferMode::Read),
            BufferAccess::new(id(2), 0, 1024, BufferMode::Read),
            BufferAccess::new(id(3), 0, 512, BufferMode::Write),
        ];
        let batched_scalars = [ScalarArg::i32(16), ScalarArg::i32(32), ScalarArg::i32(8)];
        let batched = Dispatch::new_with_scalars(
            KernelId::new(5).unwrap(),
            [1, 1, 1],
            [256, 1, 1],
            0,
            &batched_accesses,
            &batched_scalars,
        )
        .unwrap();
        assert_eq!(
            batched.validate_executor_schema().unwrap().element_count(),
            128
        );

        let gemv_accesses = [
            batched_accesses[0],
            batched_accesses[1],
            BufferAccess::new(id(2), 0, 128, BufferMode::Read),
            BufferAccess::new(id(3), 0, 64, BufferMode::Write),
        ];
        let gemv_scalars = [batched_scalars[0], batched_scalars[1]];
        let gemv = Dispatch::new_with_scalars(
            KernelId::new(6).unwrap(),
            [2, 1, 1],
            [128, 1, 1],
            0,
            &gemv_accesses,
            &gemv_scalars,
        )
        .unwrap();
        assert_eq!(gemv.validate_executor_schema().unwrap().element_count(), 16);

        let short_up = [
            batched_accesses[0],
            BufferAccess::new(id(1), 0, 287, BufferMode::Read),
            batched_accesses[2],
            batched_accesses[3],
        ];
        let short_up = Dispatch::new_with_scalars(
            KernelId::new(5).unwrap(),
            [1, 1, 1],
            [256, 1, 1],
            0,
            &short_up,
            &batched_scalars,
        )
        .unwrap();
        assert_eq!(
            short_up.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );
    }

    #[test]
    fn executor_distinguishes_q4_and_q8_gemv_storage_and_tiling() {
        let id = |slot| BufferId {
            slot,
            generation: 1,
        };
        let scalars = [ScalarArg::i32(32), ScalarArg::i32(64)];
        let q4_accesses = [
            BufferAccess::new(id(0), 0, 1152, BufferMode::Read),
            BufferAccess::new(id(1), 0, 256, BufferMode::Read),
            BufferAccess::new(id(2), 0, 128, BufferMode::Write),
        ];
        let q4 = Dispatch::new_with_scalars(
            KernelId::new(3).unwrap(),
            [2, 1, 1],
            [256, 1, 1],
            0,
            &q4_accesses,
            &scalars,
        )
        .unwrap();
        assert_eq!(q4.validate_executor_schema().unwrap().element_count(), 32);

        let q8_accesses = [
            BufferAccess::new(id(0), 0, 2176, BufferMode::Read),
            q4_accesses[1],
            q4_accesses[2],
        ];
        let q8 = Dispatch::new_with_scalars(
            KernelId::new(4).unwrap(),
            [4, 1, 1],
            [128, 1, 1],
            0,
            &q8_accesses,
            &scalars,
        )
        .unwrap();
        assert_eq!(q8.validate_executor_schema().unwrap().element_count(), 32);

        let q8_with_q4_storage = Dispatch::new_with_scalars(
            KernelId::new(4).unwrap(),
            [4, 1, 1],
            [128, 1, 1],
            0,
            &q4_accesses,
            &scalars,
        )
        .unwrap();
        assert_eq!(
            q8_with_q4_storage.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );
    }

    #[test]
    fn executor_bounds_f32_embedding_token_and_row() {
        let id = |slot| BufferId {
            slot,
            generation: 1,
        };
        let accesses = [
            BufferAccess::new(id(0), 0, 5120, BufferMode::Read),
            BufferAccess::new(id(1), 0, 512, BufferMode::Write),
        ];
        let scalars = [ScalarArg::i32(9), ScalarArg::i32(128)];
        let dispatch = Dispatch::new_with_scalars(
            KernelId::new(8).unwrap(),
            [1, 1, 1],
            [256, 1, 1],
            0,
            &accesses,
            &scalars,
        )
        .unwrap();
        assert_eq!(
            dispatch.validate_executor_schema().unwrap().element_count(),
            128
        );

        let past_end = [ScalarArg::i32(10), ScalarArg::i32(128)];
        let past_end = Dispatch::new_with_scalars(
            KernelId::new(8).unwrap(),
            [1, 1, 1],
            [256, 1, 1],
            0,
            &accesses,
            &past_end,
        )
        .unwrap();
        assert_eq!(
            past_end.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );

        let wrong_output = [
            accesses[0],
            BufferAccess::new(id(1), 0, 508, BufferMode::Write),
        ];
        let wrong_output = Dispatch::new_with_scalars(
            KernelId::new(8).unwrap(),
            [1, 1, 1],
            [256, 1, 1],
            0,
            &wrong_output,
            &scalars,
        )
        .unwrap();
        assert_eq!(
            wrong_output.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );
    }

    #[test]
    fn executor_validates_weighted_and_unweighted_rms_norm() {
        let id = |slot| BufferId {
            slot,
            generation: 1,
        };
        let scalars = [
            ScalarArg::i32(128),
            ScalarArg::i32(2),
            ScalarArg::f32_bits(1.0e-6f32.to_bits()),
        ];
        let unweighted_accesses = [
            BufferAccess::new(id(0), 0, 1024, BufferMode::Read),
            BufferAccess::new(id(2), 0, 1024, BufferMode::Write),
        ];
        let unweighted = Dispatch::new_with_scalars(
            KernelId::new(12).unwrap(),
            [2, 1, 1],
            [256, 1, 1],
            0,
            &unweighted_accesses,
            &scalars,
        )
        .unwrap();
        assert_eq!(
            unweighted
                .validate_executor_schema()
                .unwrap()
                .element_count(),
            256
        );

        let weighted_accesses = [
            unweighted_accesses[0],
            BufferAccess::new(id(1), 0, 512, BufferMode::Read),
            unweighted_accesses[1],
        ];
        let weighted = Dispatch::new_with_scalars(
            KernelId::new(12).unwrap(),
            [2, 1, 1],
            [256, 1, 1],
            0,
            &weighted_accesses,
            &scalars,
        )
        .unwrap();
        assert!(weighted.validate_executor_schema().is_ok());

        let invalid_epsilon = [
            scalars[0],
            scalars[1],
            ScalarArg::f32_bits(f32::NAN.to_bits()),
        ];
        let invalid_epsilon = Dispatch::new_with_scalars(
            KernelId::new(12).unwrap(),
            [2, 1, 1],
            [256, 1, 1],
            0,
            &weighted_accesses,
            &invalid_epsilon,
        )
        .unwrap();
        assert_eq!(
            invalid_epsilon.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );

        let short_weight = [
            unweighted_accesses[0],
            BufferAccess::new(id(1), 0, 508, BufferMode::Read),
            unweighted_accesses[1],
        ];
        let short_weight = Dispatch::new_with_scalars(
            KernelId::new(12).unwrap(),
            [2, 1, 1],
            [256, 1, 1],
            0,
            &short_weight,
            &scalars,
        )
        .unwrap();
        assert_eq!(
            short_weight.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );
    }

    #[test]
    fn executor_binds_rope_shape_position_and_frequencies() {
        let vector = BufferAccess::new(
            BufferId {
                slot: 0,
                generation: 1,
            },
            0,
            8192,
            BufferMode::ReadWrite,
        );
        let scalars = [
            ScalarArg::i32(0),
            ScalarArg::i32(128),
            ScalarArg::i32(16),
            ScalarArg::f32_bits(10_000.0f32.to_bits()),
            ScalarArg::f32_bits(1.0f32.to_bits()),
        ];
        let dispatch = Dispatch::new_with_scalars(
            KernelId::new(11).unwrap(),
            [16, 1, 1],
            [64, 1, 1],
            0,
            &[vector],
            &scalars,
        )
        .unwrap();
        assert_eq!(
            dispatch.validate_executor_schema().unwrap().element_count(),
            2048
        );

        let odd_dimension = [
            scalars[0],
            ScalarArg::i32(127),
            scalars[2],
            scalars[3],
            scalars[4],
        ];
        let odd_dimension = Dispatch::new_with_scalars(
            KernelId::new(11).unwrap(),
            [16, 1, 1],
            [63, 1, 1],
            0,
            &[vector],
            &odd_dimension,
        )
        .unwrap();
        assert_eq!(
            odd_dimension.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );

        let invalid_frequency = [
            scalars[0],
            scalars[1],
            scalars[2],
            ScalarArg::f32_bits(f32::INFINITY.to_bits()),
            scalars[4],
        ];
        let invalid_frequency = Dispatch::new_with_scalars(
            KernelId::new(11).unwrap(),
            [16, 1, 1],
            [64, 1, 1],
            0,
            &[vector],
            &invalid_frequency,
        )
        .unwrap();
        assert_eq!(
            invalid_frequency.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );
    }

    #[test]
    fn executor_bounds_q8_embedding_rows_and_scale() {
        let accesses = [
            BufferAccess::new(
                BufferId {
                    slot: 0,
                    generation: 1,
                },
                0,
                680,
                BufferMode::Read,
            ),
            BufferAccess::new(
                BufferId {
                    slot: 1,
                    generation: 1,
                },
                0,
                256,
                BufferMode::Write,
            ),
        ];
        let scalars = [
            ScalarArg::i32(9),
            ScalarArg::i32(64),
            ScalarArg::f32_bits(8.0f32.to_bits()),
        ];
        let dispatch = Dispatch::new_with_scalars(
            KernelId::new(27).unwrap(),
            [1, 1, 1],
            [256, 1, 1],
            0,
            &accesses,
            &scalars,
        )
        .unwrap();
        assert_eq!(
            dispatch.validate_executor_schema().unwrap().element_count(),
            64
        );

        for invalid in [
            [ScalarArg::i32(10), scalars[1], scalars[2]],
            [scalars[0], ScalarArg::i32(63), scalars[2]],
            [
                scalars[0],
                scalars[1],
                ScalarArg::f32_bits(0.0f32.to_bits()),
            ],
        ] {
            let invalid = Dispatch::new_with_scalars(
                KernelId::new(27).unwrap(),
                [1, 1, 1],
                [256, 1, 1],
                0,
                &accesses,
                &invalid,
            )
            .unwrap();
            assert_eq!(
                invalid.validate_executor_schema(),
                Err(GpuError::InvalidKernelSchema)
            );
        }
    }

    #[test]
    fn executor_binds_router_logits_and_top8_buffers() {
        let id = |slot| BufferId {
            slot,
            generation: 1,
        };
        let logits_accesses = [
            BufferAccess::new(id(0), 0, 4096, BufferMode::Read),
            BufferAccess::new(id(1), 0, 512, BufferMode::Read),
            BufferAccess::new(id(2), 0, 128, BufferMode::Write),
        ];
        let logits_scalars = [ScalarArg::i32(64), ScalarArg::i32(16), ScalarArg::i32(2)];
        let logits = Dispatch::new_with_scalars(
            KernelId::new(13).unwrap(),
            [16, 2, 1],
            [256, 1, 1],
            0,
            &logits_accesses,
            &logits_scalars,
        )
        .unwrap();
        assert_eq!(
            logits.validate_executor_schema().unwrap().element_count(),
            32
        );

        let top_accesses = [
            BufferAccess::new(id(2), 0, 128, BufferMode::Read),
            BufferAccess::new(id(3), 0, 64, BufferMode::Write),
            BufferAccess::new(id(4), 0, 64, BufferMode::Write),
        ];
        let top_scalars = [ScalarArg::i32(16), ScalarArg::i32(2)];
        let top = Dispatch::new_with_scalars(
            KernelId::new(14).unwrap(),
            [2, 1, 1],
            [1, 1, 1],
            0,
            &top_accesses,
            &top_scalars,
        )
        .unwrap();
        assert_eq!(top.validate_executor_schema().unwrap().element_count(), 16);

        let too_few_experts = [ScalarArg::i32(7), ScalarArg::i32(2)];
        let too_few_experts = Dispatch::new_with_scalars(
            KernelId::new(14).unwrap(),
            [2, 1, 1],
            [1, 1, 1],
            0,
            &top_accesses,
            &too_few_experts,
        )
        .unwrap();
        assert_eq!(
            too_few_experts.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );

        let bad_ids = [
            top_accesses[0],
            BufferAccess::new(id(3), 0, 64, BufferMode::Read),
            top_accesses[2],
        ];
        let bad_ids = Dispatch::new_with_scalars(
            KernelId::new(14).unwrap(),
            [2, 1, 1],
            [1, 1, 1],
            0,
            &bad_ids,
            &top_scalars,
        )
        .unwrap();
        assert_eq!(
            bad_ids.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );
    }

    #[test]
    fn executor_selects_only_the_bounded_vocab_topk_variant() {
        let id = |slot| BufferId {
            slot,
            generation: 1,
        };
        let make_accesses = |vocabulary: u64| {
            [
                BufferAccess::new(id(0), 0, vocabulary * 4, BufferMode::Read),
                BufferAccess::new(id(1), 0, vocabulary, BufferMode::Read),
                BufferAccess::new(id(2), 0, 16, BufferMode::Read),
                BufferAccess::new(id(3), 0, 64, BufferMode::Write),
                BufferAccess::new(id(4), 0, 64, BufferMode::Write),
            ]
        };
        let specialized_scalars = [
            ScalarArg::i32(4096),
            ScalarArg::i32(4),
            ScalarArg::i32(7),
            ScalarArg::i32(8),
            ScalarArg::i32(2),
        ];
        let specialized = Dispatch::new_with_scalars(
            KernelId::new(17).unwrap(),
            [2, 1, 1],
            [256, 1, 1],
            0,
            &make_accesses(4096),
            &specialized_scalars,
        )
        .unwrap();
        assert_eq!(
            specialized
                .validate_executor_schema()
                .unwrap()
                .element_count(),
            16
        );

        let generic_scalars = [
            ScalarArg::i32(4097),
            specialized_scalars[1],
            specialized_scalars[2],
            specialized_scalars[3],
            specialized_scalars[4],
        ];
        let generic = Dispatch::new_with_scalars(
            KernelId::new(18).unwrap(),
            [2, 1, 1],
            [1, 1, 1],
            0,
            &make_accesses(4097),
            &generic_scalars,
        )
        .unwrap();
        assert!(generic.validate_executor_schema().is_ok());

        let wrong_variant = Dispatch::new_with_scalars(
            KernelId::new(17).unwrap(),
            [2, 1, 1],
            [256, 1, 1],
            0,
            &make_accesses(4097),
            &generic_scalars,
        )
        .unwrap();
        assert_eq!(
            wrong_variant.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );
    }

    #[test]
    fn executor_binds_ffn_preparation_and_completion_tensors() {
        let id = |slot| BufferId {
            slot,
            generation: 1,
        };
        let prepare_accesses = [
            BufferAccess::new(id(0), 0, 512, BufferMode::Read),
            BufferAccess::new(id(1), 0, 512, BufferMode::Read),
            BufferAccess::new(id(2), 0, 256, BufferMode::Read),
            BufferAccess::new(id(3), 0, 256, BufferMode::Read),
            BufferAccess::new(id(4), 0, 256, BufferMode::Read),
            BufferAccess::new(id(5), 0, 256, BufferMode::Read),
            BufferAccess::new(id(6), 0, 512, BufferMode::Write),
            BufferAccess::new(id(7), 0, 512, BufferMode::Write),
            BufferAccess::new(id(8), 0, 512, BufferMode::Write),
            BufferAccess::new(id(9), 0, 512, BufferMode::Write),
        ];
        let dimensions = [ScalarArg::i32(64), ScalarArg::i32(2)];
        let prepare = Dispatch::new_with_scalars(
            KernelId::new(15).unwrap(),
            [2, 1, 1],
            [512, 1, 1],
            0,
            &prepare_accesses,
            &dimensions,
        )
        .unwrap();
        assert_eq!(
            prepare.validate_executor_schema().unwrap().element_count(),
            128
        );

        let finish_accesses = [
            BufferAccess::new(id(0), 0, 512, BufferMode::Read),
            BufferAccess::new(id(1), 0, 512, BufferMode::Read),
            BufferAccess::new(id(2), 0, 512, BufferMode::ReadWrite),
            BufferAccess::new(id(3), 0, 256, BufferMode::Read),
            BufferAccess::new(id(4), 0, 256, BufferMode::Read),
            BufferAccess::new(id(5), 0, 256, BufferMode::Read),
            BufferAccess::new(id(6), 0, 512, BufferMode::Write),
        ];
        let finish_scalars = [
            ScalarArg::f32_bits(1.0_f32.to_bits()),
            dimensions[0],
            dimensions[1],
        ];
        let finish = Dispatch::new_with_scalars(
            KernelId::new(16).unwrap(),
            [2, 1, 1],
            [512, 1, 1],
            0,
            &finish_accesses,
            &finish_scalars,
        )
        .unwrap();
        assert_eq!(
            finish.validate_executor_schema().unwrap().element_count(),
            128
        );

        let mut wrong_mode = finish_accesses;
        wrong_mode[2] = BufferAccess::new(id(2), 0, 512, BufferMode::Write);
        let invalid = Dispatch::new_with_scalars(
            KernelId::new(16).unwrap(),
            [2, 1, 1],
            [512, 1, 1],
            0,
            &wrong_mode,
            &finish_scalars,
        )
        .unwrap();
        assert_eq!(
            invalid.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );

        let mut nonfinite = finish_scalars;
        nonfinite[0] = ScalarArg::f32_bits(f32::NAN.to_bits());
        let invalid = Dispatch::new_with_scalars(
            KernelId::new(16).unwrap(),
            [2, 1, 1],
            [512, 1, 1],
            0,
            &finish_accesses,
            &nonfinite,
        )
        .unwrap();
        assert_eq!(
            invalid.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );
    }

    #[test]
    fn executor_binds_qkv_postprocess_cache_formats_and_positions() {
        let id = |slot| BufferId {
            slot,
            generation: 1,
        };
        let accesses = [
            BufferAccess::new(id(0), 0, 4096, BufferMode::ReadWrite),
            BufferAccess::new(id(1), 0, 256, BufferMode::Read),
            BufferAccess::new(id(2), 0, 256, BufferMode::Read),
            BufferAccess::new(id(3), 0, 2048, BufferMode::Write),
            BufferAccess::new(id(4), 0, 1088, BufferMode::Write),
        ];
        let scalars = [
            ScalarArg::i32(0),
            ScalarArg::i32(0),
            ScalarArg::i32(4),
            ScalarArg::i32(2),
            ScalarArg::i32(64),
            ScalarArg::f32_bits(10_000.0_f32.to_bits()),
            ScalarArg::i32(2),
            ScalarArg::i32(8),
            ScalarArg::i32(0),
            ScalarArg::i32(1),
        ];
        let dispatch = Dispatch::new_with_scalars(
            KernelId::new(19).unwrap(),
            [8, 2, 1],
            [128, 1, 1],
            0,
            &accesses,
            &scalars,
        )
        .unwrap();
        assert_eq!(
            dispatch.validate_executor_schema().unwrap().element_count(),
            1024
        );

        let mut short_cache = accesses;
        short_cache[4] = BufferAccess::new(id(4), 0, 1087, BufferMode::Write);
        let invalid = Dispatch::new_with_scalars(
            KernelId::new(19).unwrap(),
            [8, 2, 1],
            [128, 1, 1],
            0,
            &short_cache,
            &scalars,
        )
        .unwrap();
        assert_eq!(
            invalid.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );

        let mut invalid_format = scalars;
        invalid_format[9] = ScalarArg::i32(3);
        let invalid = Dispatch::new_with_scalars(
            KernelId::new(19).unwrap(),
            [8, 2, 1],
            [128, 1, 1],
            0,
            &accesses,
            &invalid_format,
        )
        .unwrap();
        assert_eq!(
            invalid.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );

        let mut overflowing_position = scalars;
        overflowing_position[0] = ScalarArg::i32(i32::MAX);
        let invalid = Dispatch::new_with_scalars(
            KernelId::new(19).unwrap(),
            [8, 2, 1],
            [128, 1, 1],
            0,
            &accesses,
            &overflowing_position,
        )
        .unwrap();
        assert_eq!(
            invalid.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );
    }

    #[test]
    fn executor_selects_only_bounded_shared_f16_attention() {
        let id = |slot| BufferId {
            slot,
            generation: 1,
        };
        let accesses = [
            BufferAccess::new(id(0), 0, 3072, BufferMode::Read),
            BufferAccess::new(id(1), 0, 2048, BufferMode::Read),
            BufferAccess::new(id(2), 0, 2048, BufferMode::Read),
            BufferAccess::new(id(3), 0, 2048, BufferMode::Write),
        ];
        let scalars = [
            ScalarArg::i32(4),
            ScalarArg::i32(2),
            ScalarArg::i32(4),
            ScalarArg::i32(2),
            ScalarArg::i32(64),
            ScalarArg::i32(512),
            ScalarArg::f32_bits(0.125_f32.to_bits()),
            ScalarArg::i32(0),
            ScalarArg::i32(8),
            ScalarArg::i32(0),
            ScalarArg::i32(0),
        ];
        let dispatch = Dispatch::new_with_scalars(
            KernelId::new(20).unwrap(),
            [4, 2, 1],
            [128, 1, 1],
            24,
            &accesses,
            &scalars,
        )
        .unwrap();
        assert_eq!(
            dispatch.validate_executor_schema().unwrap().element_count(),
            512
        );

        let wrong_shared = Dispatch::new_with_scalars(
            KernelId::new(20).unwrap(),
            [4, 2, 1],
            [128, 1, 1],
            20,
            &accesses,
            &scalars,
        )
        .unwrap();
        assert_eq!(
            wrong_shared.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );

        let mut quantized = scalars;
        quantized[9] = ScalarArg::i32(1);
        let wrong_variant = Dispatch::new_with_scalars(
            KernelId::new(20).unwrap(),
            [4, 2, 1],
            [128, 1, 1],
            24,
            &accesses,
            &quantized,
        )
        .unwrap();
        assert_eq!(
            wrong_variant.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );

        let mut overflowing = scalars;
        overflowing[0] = ScalarArg::i32(i32::MAX);
        let invalid = Dispatch::new_with_scalars(
            KernelId::new(20).unwrap(),
            [4, 2, 1],
            [128, 1, 1],
            24,
            &accesses,
            &overflowing,
        )
        .unwrap();
        assert_eq!(
            invalid.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );

        let quantized_accesses = [
            accesses[0],
            BufferAccess::new(id(1), 0, 1088, BufferMode::Read),
            BufferAccess::new(id(2), 0, 576, BufferMode::Read),
            accesses[3],
        ];
        let mut quantized_formats = scalars;
        quantized_formats[9] = ScalarArg::i32(1);
        quantized_formats[10] = ScalarArg::i32(2);
        let streaming = Dispatch::new_with_scalars(
            KernelId::new(21).unwrap(),
            [4, 2, 1],
            [128, 1, 1],
            0,
            &quantized_accesses,
            &quantized_formats,
        )
        .unwrap();
        assert_eq!(
            streaming
                .validate_executor_schema()
                .unwrap()
                .element_count(),
            512
        );

        let wrong_streaming_variant = Dispatch::new_with_scalars(
            KernelId::new(21).unwrap(),
            [4, 2, 1],
            [128, 1, 1],
            0,
            &accesses,
            &scalars,
        )
        .unwrap();
        assert_eq!(
            wrong_streaming_variant.validate_executor_schema(),
            Err(GpuError::InvalidKernelSchema)
        );
    }

    #[test]
    fn kernel_bundle_token_requires_signed_bytes_matching_embedded_ptx() {
        const BUNDLE: &[u8] = b"original embedded MRML PTX bundle";
        const ENCODED_BYTES: usize = crate::SIGNED_ARTIFACT_OVERHEAD_BYTES + BUNDLE.len();
        let bundle = BUNDLE;
        let mut private = [0u8; LAMPORT_PRIVATE_KEY_BYTES];
        for (index, byte) in private.iter_mut().enumerate() {
            *byte = (index as u64).wrapping_mul(29).wrapping_add(3) as u8;
        }
        let mut public = [0u8; LAMPORT_PUBLIC_KEY_BYTES];
        lamport_public_key(&private, &mut public).unwrap();
        let root = TrustRoot::new(ArtifactKind::CudaKernelBundle, Sha3_512::digest(&public), 5);
        let statement = artifact_statement(
            ArtifactKind::CudaKernelBundle,
            5,
            bundle.len() as u64,
            Sha3_512::digest(bundle),
        );
        let mut signature = [0u8; LAMPORT_SIGNATURE_BYTES];
        lamport_sign(&private, &statement, &mut signature).unwrap();
        let artifact = root.verify(5, bundle, &public, &signature).unwrap();
        let admitted = VerifiedGpuKernelBundle::admit(&artifact, bundle).unwrap();
        assert_eq!(admitted.version(), 5);
        assert!(admitted.permits(KernelId::new(27).unwrap()));

        let mut encoded = [0u8; ENCODED_BYTES];
        encoded[..16].copy_from_slice(b"MRML-SIGNED-v1\0\0");
        encoded[16] = ArtifactKind::CudaKernelBundle as u8;
        encoded[24..32].copy_from_slice(&5u64.to_le_bytes());
        encoded[32..40].copy_from_slice(&(bundle.len() as u64).to_le_bytes());
        encoded[40..104].copy_from_slice(&Sha3_512::digest(bundle));
        let public_end = crate::SIGNED_ARTIFACT_HEADER_BYTES + LAMPORT_PUBLIC_KEY_BYTES;
        let signature_end = public_end + LAMPORT_SIGNATURE_BYTES;
        encoded[crate::SIGNED_ARTIFACT_HEADER_BYTES..public_end].copy_from_slice(&public);
        encoded[public_end..signature_end].copy_from_slice(&signature);
        encoded[signature_end..].copy_from_slice(bundle);
        assert_eq!(
            verify_gpu_kernel_bundle(&encoded, &public, 5, bundle)
                .unwrap()
                .digest(),
            &Sha3_512::digest(bundle)
        );
        assert!(matches!(
            verify_gpu_kernel_bundle(&encoded, &public, 6, bundle),
            Err(GpuError::UntrustedKernelBundle)
        ));
        assert!(matches!(
            verify_gpu_kernel_bundle(&encoded, &public[..public.len() - 1], 5, bundle),
            Err(GpuError::UntrustedKernelBundle)
        ));
        assert!(matches!(
            verify_gpu_kernel_bundle(&encoded, &public, 5, b"changed PTX"),
            Err(GpuError::UntrustedKernelBundle)
        ));
        assert!(matches!(
            VerifiedGpuKernelBundle::admit(&artifact, b"changed PTX"),
            Err(GpuError::UntrustedKernelBundle)
        ));

        let wrong_root = TrustRoot::new(ArtifactKind::VmImage, Sha3_512::digest(&public), 5);
        let wrong_statement = artifact_statement(
            ArtifactKind::VmImage,
            5,
            bundle.len() as u64,
            Sha3_512::digest(bundle),
        );
        lamport_sign(&private, &wrong_statement, &mut signature).unwrap();
        let wrong_artifact = wrong_root.verify(5, bundle, &public, &signature).unwrap();
        assert!(matches!(
            VerifiedGpuKernelBundle::admit(&wrong_artifact, bundle),
            Err(GpuError::UntrustedKernelBundle)
        ));
    }

    #[test]
    fn resource_commands_have_one_exact_bounded_encoding() {
        let command = ResourceCommand::Free {
            buffer: BufferId {
                slot: 4,
                generation: 2,
            },
        };
        let mut wire = [0u8; ResourceCommand::WIRE_LENGTH];
        command.encode(7, &mut wire).unwrap();
        assert_eq!(ResourceCommand::decode(&wire), Ok((7, command)));
        assert_eq!(
            ResourceCommand::decode(&wire[..wire.len() - 1]),
            Err(GpuError::MalformedCommand)
        );
        wire[6] = 1;
        assert_eq!(
            ResourceCommand::decode(&wire),
            Err(GpuError::MalformedCommand)
        );

        let mut controls = ControlBufferTable::<1>::new();
        let control = controls.seal(b"canonical batch descriptor").unwrap();
        let submit = ResourceCommand::SubmitBatch { control };
        submit.encode(8, &mut wire).unwrap();
        assert_eq!(ResourceCommand::decode(&wire), Ok((8, submit)));

        let benchmark = ResourceCommand::BenchmarkAdd {
            elements: 4 * 1024 * 1024,
            iterations: 1000,
        };
        benchmark.encode(9, &mut wire).unwrap();
        assert_eq!(ResourceCommand::decode(&wire), Ok((9, benchmark)));
        assert_eq!(
            ResourceCommand::BenchmarkAdd {
                elements: 0,
                iterations: 1,
            }
            .encode(9, &mut wire),
            Err(GpuError::InvalidKernelSchema)
        );
        wire.fill(0);
        wire[..4].copy_from_slice(b"MRVG");
        wire[4] = 1;
        wire[5] = 4;
        wire[8..16].copy_from_slice(&9u64.to_le_bytes());
        wire[16..20].copy_from_slice(&(MAX_GPU_BENCHMARK_ELEMENTS + 1).to_le_bytes());
        wire[20..24].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            ResourceCommand::decode(&wire),
            Err(GpuError::InvalidKernelSchema)
        );
    }

    #[test]
    fn benchmark_response_is_authenticated_bounded_and_replay_safe() {
        let key = [0x6d; 32];
        let response = GpuResourceResponse::BenchmarkComplete {
            request_id: 17,
            elapsed_ns: 98_765,
        };
        let mut sender = GpuResourceResponseSender::new(29, key).unwrap();
        let mut receiver = GpuResourceResponseReceiver::new(29, key).unwrap();
        let mut wire = [0u8; GPU_QUEUE_MESSAGE_BYTES];
        sender.encode(response, &mut wire).unwrap();
        assert_eq!(receiver.decode(&wire), Ok(response));
        assert_eq!(receiver.decode(&wire), Err(GpuError::Replay));

        let mut tampered = wire;
        tampered[32] ^= 1;
        let mut fresh = GpuResourceResponseReceiver::new(29, key).unwrap();
        assert_eq!(fresh.decode(&tampered), Err(GpuError::AuthenticationFailed));

        let invalid = GpuResourceResponse::BenchmarkComplete {
            request_id: 17,
            elapsed_ns: 0,
        };
        let mut invalid_wire = [0u8; GPU_QUEUE_MESSAGE_BYTES];
        GpuResourceResponseSender::new(29, key)
            .unwrap()
            .encode(invalid, &mut invalid_wire)
            .unwrap();
        assert_eq!(
            GpuResourceResponseReceiver::new(29, key)
                .unwrap()
                .decode(&invalid_wire),
            Err(GpuError::MalformedCommand)
        );
    }

    #[test]
    fn control_buffers_are_typed_sealed_bounded_and_generational() {
        let mut controls = ControlBufferTable::<1>::new();
        assert_eq!(controls.seal(&[]), Err(GpuError::ControlBufferTooLarge));
        let bytes = b"bounded canonical dispatch batch";
        let id = controls.seal(bytes).unwrap();
        assert!(controls.verify(id, bytes).is_ok());
        assert_eq!(
            controls.verify(id, b"bounded canonical dispatch batcH"),
            Err(GpuError::ControlBufferChanged)
        );
        assert_eq!(
            controls.seal(b"second"),
            Err(GpuError::ControlBufferTableFull)
        );
        controls.release(id).unwrap();
        assert_eq!(
            controls.verify(id, bytes),
            Err(GpuError::InvalidControlBuffer)
        );
        let replacement = controls.seal(bytes).unwrap();
        assert_ne!(replacement, id);
        assert_eq!(controls.release(id), Err(GpuError::InvalidControlBuffer));
    }

    #[test]
    fn expert_selection_is_range_checked_unique_and_mutation_bound() {
        let id = |slot| BufferId {
            slot,
            generation: 1,
        };
        let ids_access = BufferAccess::new(id(0), 0, 16, BufferMode::Read);
        let weights_access = BufferAccess::new(id(1), 0, 16, BufferMode::Read);
        let mut ids = [0u8; 16];
        for (index, value) in [0_i32, 2, 1, 3].into_iter().enumerate() {
            ids[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        let mut weights = [0u8; 16];
        for (index, value) in [0.6_f32, 0.4, 0.75, 0.25].into_iter().enumerate() {
            weights[index * 4..index * 4 + 4].copy_from_slice(&value.to_bits().to_le_bytes());
        }
        let proof =
            ValidatedExpertSelection::admit(ids_access, &ids, weights_access, &weights, 4, 2, 2)
                .unwrap();
        assert_eq!(proof.experts(), 4);
        assert_eq!(proof.active(), 2);
        assert_eq!(proof.batch(), 2);
        assert_eq!(proof.ids(), ids_access);
        assert_eq!(proof.weights(), weights_access);
        assert!(proof.verify(&ids, &weights).is_ok());

        let mut changed = ids;
        changed[0] = 1;
        assert_eq!(
            proof.verify(&changed, &weights),
            Err(GpuError::ExpertSelectionChanged)
        );

        let mut out_of_range = ids;
        out_of_range[..4].copy_from_slice(&4_i32.to_le_bytes());
        assert_eq!(
            ValidatedExpertSelection::admit(
                ids_access,
                &out_of_range,
                weights_access,
                &weights,
                4,
                2,
                2,
            ),
            Err(GpuError::InvalidExpertSelection)
        );

        let mut duplicate = ids;
        duplicate[4..8].copy_from_slice(&0_i32.to_le_bytes());
        assert_eq!(
            ValidatedExpertSelection::admit(
                ids_access,
                &duplicate,
                weights_access,
                &weights,
                4,
                2,
                2,
            ),
            Err(GpuError::InvalidExpertSelection)
        );
    }

    #[test]
    fn moe_schemas_require_and_retain_validated_expert_selection() {
        let id = |slot| BufferId {
            slot,
            generation: 1,
        };
        let ids_access = BufferAccess::new(id(1), 0, 16, BufferMode::Read);
        let weights_access = BufferAccess::new(id(2), 0, 16, BufferMode::Read);
        let mut ids = [0u8; 16];
        let mut weights = [0u8; 16];
        for (index, value) in [0_i32, 2, 1, 3].into_iter().enumerate() {
            ids[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (index, value) in [0.6_f32, 0.4, 0.75, 0.25].into_iter().enumerate() {
            weights[index * 4..index * 4 + 4].copy_from_slice(&value.to_bits().to_le_bytes());
        }
        let selection =
            ValidatedExpertSelection::admit(ids_access, &ids, weights_access, &weights, 4, 2, 2)
                .unwrap();
        let gate_accesses = [
            BufferAccess::new(id(0), 0, 4608, BufferMode::Read),
            ids_access,
            BufferAccess::new(id(3), 0, 256, BufferMode::Read),
            BufferAccess::new(id(4), 0, 512, BufferMode::Write),
        ];
        let dimensions = [
            ScalarArg::i32(32),
            ScalarArg::i32(32),
            ScalarArg::i32(2),
            ScalarArg::i32(2),
        ];
        let gate = Dispatch::new_with_scalars(
            KernelId::new(22).unwrap(),
            [4, 2, 2],
            [128, 1, 1],
            0,
            &gate_accesses,
            &dimensions,
        )
        .unwrap();
        assert_eq!(
            gate.validate_executor_schema(),
            Err(GpuError::UnsupportedKernelSchema)
        );
        let proven = gate.validate_moe_executor_schema(&selection).unwrap();
        assert_eq!(proven.launch().element_count(), 128);
        assert_eq!(proven.selection(), &selection);
        let prepared = PreparedGpuBatch {
            entries: [Some(PreparedGpuDispatch {
                request_id: 1,
                dispatch_id: DispatchId {
                    slot: 0,
                    generation: 1,
                },
                dispatch: gate,
            })],
            count: 1,
        };
        let bundle = VerifiedGpuKernelBundle {
            version: 1,
            digest: [7; 64],
        };
        assert_eq!(
            bundle.validate_batch(&prepared).map(|_| ()),
            Err(GpuError::UnsupportedKernelSchema)
        );
        let validated = bundle
            .validate_batch_with_expert_selections(&prepared, &[selection])
            .unwrap();
        assert_eq!(validated.moe_selection(0), Some(&selection));
        assert_eq!(validated.entries().next().unwrap().1.element_count(), 128);
        assert_eq!(
            bundle
                .validate_batch_with_expert_selections(&prepared, &[])
                .map(|_| ()),
            Err(GpuError::InvalidExpertSelection)
        );

        let down_accesses = [
            BufferAccess::new(id(5), 0, 2304, BufferMode::Read),
            ids_access,
            weights_access,
            BufferAccess::new(id(6), 0, 16, BufferMode::Read),
            BufferAccess::new(id(4), 0, 512, BufferMode::Read),
            BufferAccess::new(id(7), 0, 256, BufferMode::ReadWrite),
        ];
        let down = Dispatch::new_with_scalars(
            KernelId::new(24).unwrap(),
            [4, 2, 2],
            [128, 1, 1],
            0,
            &down_accesses,
            &dimensions,
        )
        .unwrap();
        assert_eq!(
            down.validate_moe_executor_schema(&selection)
                .unwrap()
                .launch()
                .element_count(),
            64
        );

        let mut forged = gate_accesses;
        forged[1] = BufferAccess::new(id(8), 0, 16, BufferMode::Read);
        let invalid = Dispatch::new_with_scalars(
            KernelId::new(22).unwrap(),
            [4, 2, 2],
            [128, 1, 1],
            0,
            &forged,
            &dimensions,
        )
        .unwrap();
        assert_eq!(
            invalid.validate_moe_executor_schema(&selection),
            Err(GpuError::InvalidKernelSchema)
        );
    }

    #[test]
    fn command_ring_is_bounded_fifo_and_wraps_without_overwrite() {
        assert!(matches!(
            GpuCommandRing::<0>::new(),
            Err(GpuError::InvalidQueueCapacity)
        ));
        assert!(matches!(
            GpuCommandRing::<257>::new(),
            Err(GpuError::InvalidQueueCapacity)
        ));
        let mut ring = GpuCommandRing::<2>::new().unwrap();
        let first = [1u8; GPU_QUEUE_MESSAGE_BYTES];
        let second = [2u8; GPU_QUEUE_MESSAGE_BYTES];
        let third = [3u8; GPU_QUEUE_MESSAGE_BYTES];
        let mut output = [0u8; GPU_QUEUE_MESSAGE_BYTES];

        assert_eq!(ring.dequeue(&mut output), Err(GpuError::QueueEmpty));
        assert!(ring.enqueue(&first).is_ok());
        assert!(ring.enqueue(&second).is_ok());
        assert_eq!(ring.len(), 2);
        assert_eq!(ring.enqueue(&third), Err(GpuError::QueueFull));
        ring.dequeue(&mut output).unwrap();
        assert_eq!(output, first);
        assert!(ring.enqueue(&third).is_ok());
        ring.dequeue(&mut output).unwrap();
        assert_eq!(output, second);
        ring.dequeue(&mut output).unwrap();
        assert_eq!(output, third);
        assert!(ring.is_empty());
        assert_eq!(ring.enqueue(&first[..79]), Err(GpuError::MalformedCommand));
    }

    #[test]
    fn shared_ring_ownership_rejects_lapping_forgery_and_reuse() {
        let mut producer = GpuRingProducer::<2>::new().unwrap();
        let mut consumer = GpuRingConsumer::<2>::new().unwrap();
        assert_eq!(consumer.acquire(0), Err(GpuError::QueueEmpty));

        let first = producer.reserve(consumer.consumed()).unwrap();
        assert_eq!(
            first,
            GpuRingTicket {
                position: 1,
                slot: 0
            }
        );
        assert_eq!(
            producer.reserve(consumer.consumed()),
            Err(GpuError::ReservationPending)
        );
        assert_eq!(producer.commit(first), Ok(1));
        let second = producer.reserve(consumer.consumed()).unwrap();
        assert_eq!(
            second,
            GpuRingTicket {
                position: 2,
                slot: 1
            }
        );
        producer.commit(second).unwrap();
        assert_eq!(
            producer.reserve(consumer.consumed()),
            Err(GpuError::QueueFull)
        );

        assert_eq!(consumer.acquire(producer.published()), Ok(first));
        assert_eq!(consumer.release(second), Err(GpuError::InvalidReservation));
        consumer.release(first).unwrap();
        let third = producer.reserve(consumer.consumed()).unwrap();
        assert_eq!(
            third,
            GpuRingTicket {
                position: 3,
                slot: 0
            }
        );
        producer.commit(third).unwrap();
        assert_eq!(consumer.acquire(producer.published()), Ok(second));
        consumer.release(second).unwrap();
        assert_eq!(consumer.acquire(producer.published()), Ok(third));
        consumer.release(third).unwrap();
        assert_eq!(consumer.acquire(2), Err(GpuError::InvalidQueueState));
        assert_eq!(consumer.acquire(6), Err(GpuError::InvalidQueueState));
        assert_eq!(producer.reserve(4), Err(GpuError::InvalidQueueState));
    }

    #[test]
    fn shared_indices_publish_and_consume_only_in_exact_order() {
        assert_eq!(core::mem::align_of::<GpuSharedRingIndices>(), 64);
        assert_eq!(core::mem::size_of::<GpuSharedRingIndices>(), 128);
        let indices = GpuSharedRingIndices::new();
        let first = GpuRingTicket {
            position: 1,
            slot: 0,
        };
        let second = GpuRingTicket {
            position: 2,
            slot: 1,
        };
        assert_eq!(
            indices.publish(0, second),
            Err(GpuError::InvalidReservation)
        );
        assert!(indices.publish(0, first).is_ok());
        assert_eq!(indices.published(), 1);
        assert_eq!(indices.publish(0, first), Err(GpuError::InvalidQueueState));
        assert_eq!(
            indices.consume(0, second),
            Err(GpuError::InvalidReservation)
        );
        assert!(indices.consume(0, first).is_ok());
        assert_eq!(indices.consumed(), 1);
        assert_eq!(indices.consume(0, first), Err(GpuError::InvalidQueueState));
    }

    #[test]
    fn guest_command_publisher_copies_before_release_and_detects_forgery() {
        let indices = GpuSharedRingIndices::new();
        let mut slots = [[0u8; GPU_QUEUE_MESSAGE_BYTES]; 2];
        let mut publisher = GpuGuestCommandPublisher::<2>::new().unwrap();
        let first = [0x35; GPU_QUEUE_MESSAGE_BYTES];
        assert_eq!(publisher.publish(&indices, &mut slots, &first), Ok(1));
        assert_eq!(indices.published(), 1);
        assert_eq!(slots[0], first);

        let forged = GpuRingTicket {
            position: 1,
            slot: 0,
        };
        indices.consume(0, forged).unwrap();
        let second = [0x57; GPU_QUEUE_MESSAGE_BYTES];
        assert_eq!(publisher.publish(&indices, &mut slots, &second), Ok(2));
        assert_eq!(slots[1], second);

        indices.published.store(9, Ordering::Release);
        assert_eq!(
            publisher.publish(&indices, &mut slots, &first),
            Err(GpuError::InvalidQueueState)
        );
        assert!(publisher.is_poisoned());
    }

    #[test]
    fn shared_queue_layout_is_page_bounded_disjoint_and_overflow_safe() {
        let layout = GpuSharedQueueLayout::new(0x1000, 0x3000, 64).unwrap();
        assert_eq!(layout.command_base(), 0x1000);
        assert_eq!(layout.completion_base(), 0x3000);
        assert_eq!(layout.pages_per_ring(), 2);
        assert_eq!(layout.slots(), 64);
        assert_eq!(
            GpuSharedQueueLayout::new(0x1000, 0x2000, 64),
            Err(GpuError::InvalidQueueMapping)
        );
        assert_eq!(
            GpuSharedQueueLayout::new(0x1001, 0x4000, 1),
            Err(GpuError::InvalidQueueMapping)
        );
        assert_eq!(
            GpuSharedQueueLayout::new(0x1000, 0x4000, 0),
            Err(GpuError::InvalidQueueMapping)
        );
        assert_eq!(
            GpuSharedQueueLayout::new(u64::MAX - (PAGE_SIZE - 1), 0x1000, 1),
            Err(GpuError::RangeOverflow)
        );
    }

    #[test]
    fn control_plane_establishes_one_bounded_data_plane() {
        assert_eq!(
            GpuControlPlaneAuthority::new(0, 2, 3, 4096, 8),
            Err(GpuError::InvalidControlPlaneAuthority)
        );
        let authority = GpuControlPlaneAuthority::new(1, 2, 3, 4096, 8).unwrap();
        let identity = GpuQueueIdentity::from_boot_entropy(&[0x5a; 32]).unwrap();
        let layout = GpuSharedQueueLayout::new(0x1000, 0x3000, 2).unwrap();
        assert!(matches!(
            GpuDataPlaneBinding::<1>::establish(authority, identity, layout),
            Err(GpuError::InvalidQueueCapacity)
        ));
        let binding = GpuDataPlaneBinding::<2>::establish(authority, identity, layout).unwrap();
        assert_eq!(binding.authority(), authority);
        let (publisher, bridge, mut sender, mut receiver) = binding.into_endpoints().unwrap();
        assert!(!publisher.is_poisoned());
        assert!(!bridge.is_poisoned());
        let mut message = [0; GPU_QUEUE_MESSAGE_BYTES];
        sender
            .encode(1, ResourceCommand::Allocate { bytes: 4096 }, &mut message)
            .unwrap();
        assert_eq!(
            receiver.decode(&message),
            Ok((1, ResourceCommand::Allocate { bytes: 4096 }))
        );
    }

    #[test]
    fn authenticated_queue_rejects_tampering_replay_and_cross_session_use() {
        let key = [7; 32];
        let command = ResourceCommand::Allocate { bytes: 4096 };
        let mut sender = GpuQueueSender::new(11, key).unwrap();
        let mut receiver = GpuQueueReceiver::new(11, key).unwrap();
        let mut wire = [0u8; GPU_QUEUE_MESSAGE_BYTES];
        sender.encode(9, command, &mut wire).unwrap();

        let mut tampered = wire;
        tampered[47] ^= 1;
        assert_eq!(
            receiver.decode(&tampered),
            Err(GpuError::AuthenticationFailed)
        );
        assert_eq!(receiver.decode(&wire), Ok((9, command)));
        assert_eq!(receiver.decode(&wire), Err(GpuError::Replay));

        let mut other = GpuQueueReceiver::new(12, key).unwrap();
        assert_eq!(other.decode(&wire), Err(GpuError::WrongSession));
        let mut wrong_key = GpuQueueReceiver::new(11, [8; 32]).unwrap();
        assert_eq!(wrong_key.decode(&wire), Err(GpuError::AuthenticationFailed));
        assert!(matches!(
            GpuQueueSender::new(11, [0; 32]),
            Err(GpuError::InvalidQueueKey)
        ));
    }

    #[test]
    fn resource_service_consumes_authenticated_allocate_free_and_submit_commands() {
        let key = [0x2d; 32];
        let mut sender = GpuQueueSender::new(31, key).unwrap();
        let mut receiver = GpuQueueReceiver::new(31, key).unwrap();
        let mut response_sender = GpuResourceResponseSender::new(31, key).unwrap();
        let mut response_receiver = GpuResourceResponseReceiver::new(31, key).unwrap();
        let mut ring = GpuCommandRing::<2>::new().unwrap();
        let mut response_ring = GpuCompletionRing::<1>::new().unwrap();
        let mut session = VirtualGpuSession::<1>::new(4096);
        let mut wire = [0; GPU_QUEUE_MESSAGE_BYTES];

        sender
            .encode(81, ResourceCommand::Allocate { bytes: 4096 }, &mut wire)
            .unwrap();
        let mut tampered = wire;
        tampered[48] ^= 1;
        ring.enqueue(&tampered).unwrap();
        assert_eq!(
            process_gpu_resource_command_with_response(
                &mut ring,
                &mut receiver,
                &mut session,
                &mut response_sender,
                &mut response_ring,
            ),
            Err(GpuCommandServiceError::Protocol(
                GpuError::AuthenticationFailed
            ))
        );
        assert!(ring.is_empty());
        assert_eq!(session.allocated_bytes(), 0);

        response_ring
            .enqueue_batch(&[[0; GPU_QUEUE_MESSAGE_BYTES]; 1], 1)
            .unwrap();
        ring.enqueue(&wire).unwrap();
        assert_eq!(
            process_gpu_resource_command_with_response(
                &mut ring,
                &mut receiver,
                &mut session,
                &mut response_sender,
                &mut response_ring,
            ),
            Err(GpuCommandServiceError::Protocol(GpuError::QueueFull))
        );
        assert_eq!(ring.len(), 1);
        assert_eq!(session.allocated_bytes(), 0);
        let mut response_wire = [0; GPU_QUEUE_MESSAGE_BYTES];
        response_ring.dequeue(&mut response_wire).unwrap();
        let allocated = process_gpu_resource_command_with_response(
            &mut ring,
            &mut receiver,
            &mut session,
            &mut response_sender,
            &mut response_ring,
        )
        .unwrap();
        let buffer = match allocated {
            GpuResourceOutcome::Allocated { request_id, buffer } => {
                assert_eq!(request_id, 81);
                buffer
            }
            _ => panic!("unexpected resource outcome"),
        };
        response_ring.dequeue(&mut response_wire).unwrap();
        let mut tampered_response = response_wire;
        tampered_response[32] ^= 1;
        assert_eq!(
            response_receiver.decode(&tampered_response),
            Err(GpuError::AuthenticationFailed)
        );
        assert_eq!(
            response_receiver.decode(&response_wire),
            Ok(GpuResourceResponse::Allocated {
                request_id: 81,
                buffer,
            })
        );

        sender
            .encode(82, ResourceCommand::Allocate { bytes: 1 }, &mut wire)
            .unwrap();
        ring.enqueue(&wire).unwrap();
        assert_eq!(
            process_gpu_resource_command_with_response(
                &mut ring,
                &mut receiver,
                &mut session,
                &mut response_sender,
                &mut response_ring,
            ),
            Err(GpuCommandServiceError::Backend {
                request_id: 82,
                error: GpuError::QuotaExceeded,
            })
        );
        response_ring.dequeue(&mut response_wire).unwrap();
        assert_eq!(
            response_receiver.decode(&response_wire),
            Ok(GpuResourceResponse::Rejected { request_id: 82 })
        );
        assert_eq!(session.allocated_bytes(), 4096);

        sender
            .encode(83, ResourceCommand::Free { buffer }, &mut wire)
            .unwrap();
        ring.enqueue(&wire).unwrap();
        assert_eq!(
            process_gpu_resource_command_with_response(
                &mut ring,
                &mut receiver,
                &mut session,
                &mut response_sender,
                &mut response_ring,
            ),
            Ok(GpuResourceOutcome::Freed {
                request_id: 83,
                bytes: 4096,
            })
        );
        response_ring.dequeue(&mut response_wire).unwrap();
        assert_eq!(
            response_receiver.decode(&response_wire),
            Ok(GpuResourceResponse::Freed {
                request_id: 83,
                bytes: 4096,
            })
        );

        let control = ControlBufferId {
            slot: 0,
            generation: 1,
        };
        sender
            .encode(84, ResourceCommand::SubmitBatch { control }, &mut wire)
            .unwrap();
        ring.enqueue(&wire).unwrap();
        assert_eq!(
            process_gpu_resource_command_with_response(
                &mut ring,
                &mut receiver,
                &mut session,
                &mut response_sender,
                &mut response_ring,
            ),
            Ok(GpuResourceOutcome::SubmitBatch {
                request_id: 84,
                control,
            })
        );
        assert!(response_ring.is_empty());
    }

    #[test]
    fn completion_queue_binds_dispatch_and_rejects_replay_and_cross_direction() {
        let key = [9; 32];
        let mut dispatches = DispatchTable::<2>::new();
        let dispatch = dispatches.begin(44, 100, 200).unwrap();
        let completion = GpuCompletion::new(44, dispatch, GpuCompletionStatus::Success).unwrap();
        let mut sender = GpuCompletionSender::new(17, key).unwrap();
        let mut receiver = GpuCompletionReceiver::new(17, key).unwrap();
        let mut wire = [0u8; GPU_QUEUE_MESSAGE_BYTES];
        sender.encode(completion, &mut wire).unwrap();

        let mut tampered = wire;
        tampered[24] ^= 1;
        assert_eq!(
            receiver.decode(&tampered),
            Err(GpuError::AuthenticationFailed)
        );
        let decoded = receiver.decode(&wire).unwrap();
        assert_eq!(decoded, completion);
        assert_eq!(dispatches.complete(decoded.dispatch()), Ok(44));
        assert_eq!(receiver.decode(&wire), Err(GpuError::Replay));

        let mut command_receiver = GpuQueueReceiver::new(17, key).unwrap();
        assert_eq!(
            command_receiver.decode(&wire),
            Err(GpuError::MalformedCommand)
        );
        let mut command_sender = GpuQueueSender::new(17, key).unwrap();
        command_sender
            .encode(1, ResourceCommand::Allocate { bytes: 1 }, &mut wire)
            .unwrap();
        let mut completion_receiver = GpuCompletionReceiver::new(17, key).unwrap();
        assert_eq!(
            completion_receiver.decode(&wire),
            Err(GpuError::MalformedCommand)
        );

        let invalid = GpuCompletion::new(
            44,
            DispatchId {
                slot: 0,
                generation: 0,
            },
            GpuCompletionStatus::Success,
        );
        assert_eq!(invalid, Err(GpuError::InvalidDispatch));
    }

    #[test]
    fn dispatch_batches_are_bounded_ordered_and_session_validated() {
        assert!(matches!(
            GpuDispatchBatch::<0>::new(),
            Err(GpuError::InvalidBatchCapacity)
        ));
        assert!(matches!(
            GpuDispatchBatch::<33>::new(),
            Err(GpuError::InvalidBatchCapacity)
        ));
        let mut session = VirtualGpuSession::<2>::new(4096);
        let buffer = session.allocate(4096).unwrap();
        let dispatch = Dispatch::new(
            KernelId::new(7).unwrap(),
            [4, 1, 1],
            [256, 1, 1],
            0,
            &[
                BufferAccess::new(buffer, 0, 4096, BufferMode::Read),
                BufferAccess::new(buffer, 0, 4096, BufferMode::Read),
                BufferAccess::new(buffer, 0, 4096, BufferMode::Write),
            ],
        )
        .unwrap();
        let mut batch = GpuDispatchBatch::<2>::new().unwrap();
        assert_eq!(batch.validate_ready(), Err(GpuError::EmptyBatch));
        assert!(batch.push(10, dispatch, &session).is_ok());
        assert_eq!(
            batch.push(10, dispatch, &session),
            Err(GpuError::DuplicateRequest)
        );
        assert!(batch.push(11, dispatch, &session).is_ok());
        assert_eq!(batch.push(12, dispatch, &session), Err(GpuError::BatchFull));
        assert!(batch.validate_ready().is_ok());
        let mut entries = batch.entries();
        assert_eq!(entries.next().map(BatchedDispatch::request_id), Some(10));
        assert_eq!(entries.next().map(BatchedDispatch::request_id), Some(11));
        assert_eq!(entries.next(), None);

        let mut wire = [0u8; GpuDispatchBatch::<2>::WIRE_HEADER_BYTES + 2 * Dispatch::WIRE_LENGTH];
        let length = batch.encode(77, &mut wire).unwrap();
        assert_eq!(length, wire.len());
        let (batch_id, decoded) = GpuDispatchBatch::<2>::decode(&wire, &session).unwrap();
        assert_eq!(batch_id, 77);
        assert_eq!(decoded.len(), 2);
        let mut decoded_entries = decoded.entries();
        assert_eq!(decoded_entries.next().unwrap().request_id(), 10);
        assert_eq!(decoded_entries.next().unwrap().request_id(), 11);
        assert_eq!(decoded_entries.next(), None);
        assert_eq!(
            GpuDispatchBatch::<2>::decode(&wire[..wire.len() - 1], &session).map(|_| ()),
            Err(GpuError::MalformedCommand)
        );
        let mut noncanonical = wire;
        noncanonical[5] = 1;
        assert_eq!(
            GpuDispatchBatch::<2>::decode(&noncanonical, &session).map(|_| ()),
            Err(GpuError::MalformedCommand)
        );

        let mut controls = ControlBufferTable::<1>::new();
        let control = controls.seal(&wire).unwrap();
        assert!(controls.verify(control, &wire).is_ok());

        let mut too_small = DispatchTable::<1>::new();
        assert!(matches!(
            too_small.begin_batch(&batch, 100, 200),
            Err(GpuError::DispatchTableFull)
        ));
        let recovered = too_small.begin(99, 100, 200).unwrap();
        assert!(too_small.contains(recovered));

        let mut watchdog = DispatchTable::<2>::new();
        let prepared = watchdog.begin_batch(&batch, 100, 200).unwrap();
        assert_eq!(prepared.len(), 2);
        for entry in prepared.entries() {
            assert!(watchdog.contains(entry.dispatch_id()));
        }
        watchdog.cancel_batch(&prepared);
        for entry in prepared.entries() {
            assert!(!watchdog.contains(entry.dispatch_id()));
        }

        let mut rejected_watchdog = DispatchTable::<2>::new();
        let rejected_batch = rejected_watchdog.begin_batch(&batch, 100, 200).unwrap();
        let bundle = VerifiedGpuKernelBundle {
            version: 1,
            digest: [7; 64],
        };
        let validated_rejected = bundle.validate_batch(&rejected_batch).unwrap();
        assert_eq!(validated_rejected.len(), 2);
        assert_eq!(validated_rejected.entries().count(), 2);
        assert_eq!(
            submit_gpu_batch(
                &mut MockExecutor(Ok(false)),
                &mut rejected_watchdog,
                &validated_rejected
            ),
            Err(GpuSubmitError::Rejected)
        );
        for entry in rejected_batch.entries() {
            assert!(!rejected_watchdog.contains(entry.dispatch_id()));
        }

        let mut uncertain_watchdog = DispatchTable::<2>::new();
        let uncertain_batch = uncertain_watchdog.begin_batch(&batch, 100, 200).unwrap();
        let validated_uncertain = bundle.validate_batch(&uncertain_batch).unwrap();
        assert_eq!(
            submit_gpu_batch(
                &mut MockExecutor(Err(7)),
                &mut uncertain_watchdog,
                &validated_uncertain
            ),
            Err(GpuSubmitError::Uncertain(7))
        );
        for entry in uncertain_batch.entries() {
            assert!(uncertain_watchdog.contains(entry.dispatch_id()));
        }

        let mut accepted_watchdog = DispatchTable::<2>::new();
        let completion_key = [0x5a; 32];
        let mut completion_sender = GpuCompletionSender::new(71, completion_key).unwrap();
        let mut completion_receiver = GpuCompletionReceiver::new(71, completion_key).unwrap();
        let mut too_small_ring = GpuCompletionRing::<1>::new().unwrap();
        assert_eq!(
            submit_gpu_control_batch::<MockExecutor, 1, 2, 2, 2, 1>(
                &controls,
                control,
                &wire,
                &session,
                &mut accepted_watchdog,
                &bundle,
                &[],
                &mut MockExecutor(Ok(true)),
                &mut completion_sender,
                &mut too_small_ring,
                100,
                200,
            ),
            Err(GpuLifecycleError::InvalidState(GpuError::QueueFull))
        );
        let mut completion_ring = GpuCompletionRing::<2>::new().unwrap();
        assert_eq!(
            submit_gpu_control_batch::<MockExecutor, 1, 2, 2, 2, 2>(
                &controls,
                control,
                &wire,
                &session,
                &mut accepted_watchdog,
                &bundle,
                &[],
                &mut MockExecutor(Ok(true)),
                &mut completion_sender,
                &mut completion_ring,
                100,
                200,
            ),
            Ok(77)
        );
        assert_eq!(completion_ring.len(), 2);
        for expected in batch.entries() {
            let mut frame = [0; GPU_QUEUE_MESSAGE_BYTES];
            completion_ring.dequeue(&mut frame).unwrap();
            let completion = completion_receiver.decode(&frame).unwrap();
            assert_eq!(completion.request_id(), expected.request_id());
            assert_eq!(completion.status(), GpuCompletionStatus::Success);
            assert!(!accepted_watchdog.contains(completion.dispatch()));
        }
        assert!(completion_ring.is_empty());

        session.free(buffer).unwrap();
        let mut stale_batch = GpuDispatchBatch::<1>::new().unwrap();
        assert_eq!(
            stale_batch.push(12, dispatch, &session),
            Err(GpuError::InvalidBuffer)
        );
    }

    #[test]
    fn dispatch_wire_is_canonical_bounded_and_pointer_free() {
        let accesses = [
            BufferAccess::new(
                BufferId {
                    slot: 2,
                    generation: 4,
                },
                64,
                128,
                BufferMode::Read,
            ),
            BufferAccess::new(
                BufferId {
                    slot: 3,
                    generation: 5,
                },
                0,
                256,
                BufferMode::Write,
            ),
        ];
        let scalars = [
            ScalarArg::u32(17),
            ScalarArg::i32(-9),
            ScalarArg::f32_bits(1.5f32.to_bits()),
        ];
        let dispatch = Dispatch::new_with_scalars(
            KernelId::new(7).unwrap(),
            [2, 3, 4],
            [32, 2, 1],
            1024,
            &accesses,
            &scalars,
        )
        .unwrap();
        let mut wire = [0u8; Dispatch::WIRE_LENGTH];
        dispatch.encode(19, &mut wire).unwrap();
        let (request, decoded) = Dispatch::decode(&wire).unwrap();
        assert_eq!(request, 19);
        assert_eq!(decoded.kernel(), KernelId::new(7).unwrap());
        assert_eq!(decoded.grid(), [2, 3, 4]);
        assert_eq!(decoded.block(), [32, 2, 1]);
        let mut decoded_accesses = decoded.accesses();
        assert_eq!(decoded_accesses.next(), Some(accesses[0]));
        assert_eq!(decoded_accesses.next(), Some(accesses[1]));
        assert_eq!(decoded_accesses.next(), None);
        assert!(decoded.scalars().eq(scalars));

        let mut old_version = wire;
        old_version[4] = 1;
        assert_eq!(
            Dispatch::decode(&old_version),
            Err(GpuError::MalformedCommand)
        );

        wire[48 + 25] = 1;
        assert_eq!(
            Dispatch::decode(&wire).err(),
            Some(GpuError::MalformedCommand)
        );
        let mut wire = [0u8; Dispatch::WIRE_LENGTH];
        dispatch.encode(19, &mut wire).unwrap();
        wire[48 + 24] = 0;
        assert_eq!(
            Dispatch::decode(&wire).err(),
            Some(GpuError::MalformedCommand)
        );
        let mut wire = [0u8; Dispatch::WIRE_LENGTH];
        dispatch.encode(19, &mut wire).unwrap();
        wire[48 + 2 * 32] = 1;
        assert_eq!(
            Dispatch::decode(&wire).err(),
            Some(GpuError::MalformedCommand)
        );
        let mut wire = [0u8; Dispatch::WIRE_LENGTH];
        dispatch.encode(19, &mut wire).unwrap();
        wire[Dispatch::SCALAR_WIRE_OFFSET + 1] = 1;
        assert_eq!(Dispatch::decode(&wire), Err(GpuError::MalformedCommand));
        let mut wire = [0u8; Dispatch::WIRE_LENGTH];
        dispatch.encode(19, &mut wire).unwrap();
        wire[Dispatch::SCALAR_WIRE_OFFSET + scalars.len() * 8] = 1;
        assert_eq!(Dispatch::decode(&wire), Err(GpuError::MalformedCommand));
    }

    #[test]
    fn dispatch_watchdog_rejects_duplicates_and_stale_completions() {
        let mut table = DispatchTable::<2>::new();
        let first = table.begin(41, 100, 120).unwrap();
        assert_eq!(table.begin(41, 100, 130), Err(GpuError::DuplicateRequest));
        assert_eq!(table.begin(42, 100, 100), Err(GpuError::InvalidDeadline));
        let second = table.begin(42, 100, 140).unwrap();
        assert_eq!(table.begin(43, 100, 150), Err(GpuError::DispatchTableFull));

        let mut expired_id = None;
        assert_eq!(
            table.expire(120, |id, request| {
                expired_id = Some((id, request));
            }),
            1
        );
        assert_eq!(expired_id, Some((first, 41)));
        assert!(!table.contains(first));
        assert_eq!(table.complete(first), Err(GpuError::InvalidDispatch));

        let replacement = table.begin(43, 120, 150).unwrap();
        assert_ne!(replacement, first);
        assert_eq!(table.cancel(second), Ok(42));
        assert_eq!(table.complete(second), Err(GpuError::InvalidDispatch));
        assert_eq!(table.complete(replacement), Ok(43));
    }

    #[test]
    fn watchdog_recovery_emits_authenticated_timeout_and_reset_completions() {
        let key = [0x35; 32];
        let mut sender = GpuCompletionSender::new(91, key).unwrap();
        let mut receiver = GpuCompletionReceiver::new(91, key).unwrap();
        let mut table = DispatchTable::<2>::new();
        let expired = table.begin(51, 100, 120).unwrap();
        let reset = table.begin(52, 100, 140).unwrap();

        let mut frames = [[0; GPU_QUEUE_MESSAGE_BYTES]; 2];
        assert_eq!(
            table.expire_with_completions(120, &mut sender, &mut frames),
            Ok(1)
        );
        assert_eq!(
            receiver.decode(&frames[0]).unwrap(),
            GpuCompletion::new(51, expired, GpuCompletionStatus::TimedOut).unwrap()
        );
        assert!(!table.contains(expired));
        assert!(table.contains(reset));

        frames.fill([0; GPU_QUEUE_MESSAGE_BYTES]);
        assert_eq!(
            table.reset_with_completions(&mut sender, &mut frames),
            Ok(1)
        );
        assert_eq!(
            receiver.decode(&frames[0]).unwrap(),
            GpuCompletion::new(52, reset, GpuCompletionStatus::DeviceReset).unwrap()
        );
        assert!(!table.contains(reset));

        let live = table.begin(53, 200, 210).unwrap();
        sender.next_sequence = u64::MAX;
        assert_eq!(
            table.expire_with_completions(210, &mut sender, &mut frames),
            Err(GpuError::SequenceExhausted)
        );
        assert!(table.contains(live));
    }
}
