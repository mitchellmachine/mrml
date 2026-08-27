#[cfg(test)]
mod tests {
    use super::*;
    use crate::VmExit;

    fn layout<const N: usize>() -> VirtualBlockQueueLayout {
        VirtualBlockQueueLayout::new(0x1000, 0x3000, N).unwrap()
    }

    fn active<const N: usize>() -> VirtualBlockDevice<N> {
        let mut device = VirtualBlockDevice::new(4096, 64, VIRTUAL_BLOCK_FEATURE_FLUSH).unwrap();
        device.negotiate(VIRTUAL_BLOCK_FEATURE_FLUSH).unwrap();
        device.activate(layout::<N>(), 48).unwrap();
        device
    }

    fn active_mmio<const N: usize>() -> VirtualBlockDevice<N> {
        let mut device = VirtualBlockDevice::new_with_transport(
            4096,
            64,
            VIRTUAL_BLOCK_FEATURE_FLUSH,
            VirtualBlockTransport::MrmlSpecificPciMmio,
        )
        .unwrap();
        device.negotiate(VIRTUAL_BLOCK_FEATURE_FLUSH).unwrap();
        device.activate(layout::<N>(), 48).unwrap();
        device
    }

    fn encoded(request: VirtualBlockRequest) -> [u8; VIRTUAL_BLOCK_REQUEST_BYTES] {
        let mut output = [0; VIRTUAL_BLOCK_REQUEST_BYTES];
        request.encode(&mut output);
        output
    }

    #[test]
    fn canonical_requests_reject_hidden_unknown_and_invalid_ranges() {
        let request = VirtualBlockRequest::write(1, 1, 63, 1, 0x8000, 4096);
        let mut bytes = encoded(request);
        assert_eq!(VirtualBlockRequest::decode(&bytes), Ok(request));
        bytes[63] = 1;
        assert_eq!(
            VirtualBlockRequest::decode(&bytes),
            Err(VirtualBlockError::MalformedRequest)
        );
        bytes = encoded(request);
        bytes[5] = 0xff;
        assert_eq!(
            VirtualBlockRequest::decode(&bytes),
            Err(VirtualBlockError::UnsupportedOperation)
        );
        bytes = encoded(request);
        bytes[8..12].fill(0);
        assert_eq!(
            VirtualBlockRequest::decode(&bytes),
            Err(VirtualBlockError::MalformedRequest)
        );

        let mut device = active::<2>();
        assert_eq!(
            device.admit(&encoded(VirtualBlockRequest::read(
                1, 1, 64, 1, 0x8000, 4096
            ))),
            Err(VirtualBlockError::InvalidRange)
        );
        assert_eq!(
            device.admit(&encoded(VirtualBlockRequest::read(1, 1, 0, 1, 3, 4096))),
            Err(VirtualBlockError::InvalidBuffer)
        );
        assert_eq!(
            device.admit(&encoded(VirtualBlockRequest::flush(2, 1))),
            Err(VirtualBlockError::StaleGeneration)
        );
    }

    #[test]
    fn active_configuration_round_trips_exact_mechanics_without_authority() {
        let device = active::<2>();
        let configuration = device.configuration().unwrap();
        assert_eq!(configuration.generation(), 1);
        assert_eq!(configuration.block_size(), 4096);
        assert_eq!(configuration.block_count(), 64);
        assert_eq!(
            configuration.supported_features(),
            VIRTUAL_BLOCK_FEATURE_FLUSH
        );
        assert_eq!(
            configuration.negotiated_features(),
            VIRTUAL_BLOCK_FEATURE_FLUSH
        );
        assert_eq!(configuration.queue(), layout::<2>());
        assert_eq!(configuration.interrupt_vector(), 48);
        assert_eq!(
            configuration.transport(),
            VirtualBlockTransport::MrmlSpecificScalarIo
        );
        assert_eq!(
            configuration.transport().doorbell_port(),
            Some(VIRTUAL_BLOCK_DOORBELL_PORT)
        );
        assert_eq!(
            configuration.transport().completion_acknowledgement_port(),
            Some(VIRTUAL_BLOCK_COMPLETION_ACK_PORT)
        );
        let transport_policy = configuration.transport().io_policy().unwrap();
        assert!(transport_policy.permits(VIRTUAL_BLOCK_DOORBELL_PORT, 4, true));
        assert!(transport_policy.permits(VIRTUAL_BLOCK_COMPLETION_ACK_PORT, 4, true));
        assert!(!transport_policy.permits(VIRTUAL_BLOCK_DOORBELL_PORT, 4, false));
        assert!(!transport_policy.permits(VIRTUAL_BLOCK_DOORBELL_PORT, 2, true));
        assert!(!transport_policy.permits(VIRTUAL_BLOCK_DOORBELL_PORT + 2, 4, true));

        let mut encoded = [0xa5; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
        configuration.encode(&mut encoded);
        assert_eq!(
            VirtualBlockConfiguration::decode(&encoded),
            Ok(configuration)
        );
        assert!(encoded[80..].iter().all(|byte| *byte == 0));
        assert_eq!(device.validate_configuration(configuration), Ok(()));
    }

    #[test]
    fn pci_mmio_configuration_is_canonical_and_grants_no_scalar_ports() {
        let configuration = active_mmio::<2>().configuration().unwrap();
        assert_eq!(
            configuration.transport(),
            VirtualBlockTransport::MrmlSpecificPciMmio
        );
        assert_eq!(configuration.transport().doorbell_port(), None);
        assert_eq!(
            configuration.transport().completion_acknowledgement_port(),
            None
        );
        assert_eq!(
            configuration.transport().doorbell_mmio_offset(),
            Some(VIRTUAL_BLOCK_MMIO_DOORBELL_OFFSET)
        );
        assert_eq!(
            configuration
                .transport()
                .completion_acknowledgement_mmio_offset(),
            Some(VIRTUAL_BLOCK_MMIO_COMPLETION_ACK_OFFSET)
        );
        let policy = configuration.transport().io_policy().unwrap();
        assert!(!policy.permits(VIRTUAL_BLOCK_DOORBELL_PORT, 4, true));
        assert!(!policy.permits(VIRTUAL_BLOCK_COMPLETION_ACK_PORT, 4, true));

        let mut encoded = [0xa5; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
        configuration.encode(&mut encoded);
        assert_eq!(encoded[67], 1);
        assert_eq!(
            u16::from_le_bytes(encoded[68..70].try_into().unwrap()),
            VIRTUAL_BLOCK_MMIO_DOORBELL_OFFSET as u16
        );
        assert_eq!(
            u16::from_le_bytes(encoded[70..72].try_into().unwrap()),
            VIRTUAL_BLOCK_MMIO_COMPLETION_ACK_OFFSET as u16
        );
        assert_eq!(
            VirtualBlockConfiguration::decode(&encoded),
            Ok(configuration)
        );

        encoded[67] = 2;
        assert_eq!(
            VirtualBlockConfiguration::decode(&encoded),
            Err(VirtualBlockError::InvalidConfiguration)
        );
    }

    #[test]
    fn configuration_decode_rejects_every_noncanonical_boundary_class() {
        let configuration = active::<2>().configuration().unwrap();
        let mut canonical = [0; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
        configuration.encode(&mut canonical);
        assert_eq!(
            VirtualBlockConfiguration::decode(&canonical[..127]),
            Err(VirtualBlockError::InvalidConfiguration)
        );

        let mutations: [fn(&mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]); 21] = [
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[0] ^= 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[4] += 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[5] += 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[6] = 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[8..12].fill(0),
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[12..16].fill(0),
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[16..24].fill(0),
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[24..32].fill(2),
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[24..32].fill(0),
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[40] |= 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| {
                let request_base: [u8; 8] = bytes[40..48].try_into().unwrap();
                bytes[48..56].copy_from_slice(&request_base);
            },
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[56..64].fill(0),
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[64..66].fill(0),
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[66] = 31,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[67] = 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[68] ^= 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[70] ^= 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[72] ^= 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[76] ^= 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[78] ^= 1,
            |bytes: &mut [u8; VIRTUAL_BLOCK_CONFIGURATION_BYTES]| bytes[127] = 1,
        ];
        for mutate in mutations {
            let mut corrupted = canonical;
            mutate(&mut corrupted);
            assert_eq!(
                VirtualBlockConfiguration::decode(&corrupted),
                Err(VirtualBlockError::InvalidConfiguration)
            );
        }
    }

    #[test]
    fn configuration_requires_exact_live_binding_and_reset_stales_snapshot() {
        let mut device = active::<1>();
        let configuration = device.configuration().unwrap();
        let mut encoded = [0; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
        configuration.encode(&mut encoded);
        encoded[32..40].fill(0);
        let altered = VirtualBlockConfiguration::decode(&encoded).unwrap();
        assert_eq!(
            device.validate_configuration(altered),
            Err(VirtualBlockError::InvalidConfiguration)
        );
        assert_eq!(device.suspend(), Ok(()));
        assert_eq!(
            device.validate_configuration(configuration),
            Err(VirtualBlockError::InvalidState)
        );
        device.resume().unwrap();
        device.reset().unwrap();
        assert_eq!(
            device.validate_configuration(configuration),
            Err(VirtualBlockError::StaleGeneration)
        );
    }

    #[test]
    fn configuration_page_is_exact_zero_padded_and_queue_disjoint() {
        let configuration = active::<1>().configuration().unwrap();
        let page = VirtualBlockConfigurationPage::new(0x30_0000, configuration).unwrap();
        assert_eq!(page.base(), 0x30_0000);
        assert_eq!(page.configuration(), configuration);
        let mut encoded = [0xa5; PAGE_SIZE as usize];
        page.encode_page(&mut encoded);
        assert_eq!(
            VirtualBlockConfiguration::decode(&encoded[..VIRTUAL_BLOCK_CONFIGURATION_BYTES]),
            Ok(configuration)
        );
        assert!(
            encoded[VIRTUAL_BLOCK_CONFIGURATION_BYTES..]
                .iter()
                .all(|byte| *byte == 0)
        );
        for invalid in [
            0,
            0x30_0001,
            configuration.queue().request_base(),
            configuration.queue().completion_base(),
            !(PAGE_SIZE - 1),
        ] {
            assert_eq!(
                VirtualBlockConfigurationPage::new(invalid, configuration),
                Err(VirtualBlockError::InvalidConfiguration)
            );
        }
    }

    #[test]
    fn resume_page_is_exact_zero_padded_and_disjoint_from_configuration_and_queues() {
        let configuration = active::<1>().configuration().unwrap();
        let configuration_page =
            VirtualBlockConfigurationPage::new(0x30_0000, configuration).unwrap();
        let page = VirtualBlockResumePage::fresh(0x31_0000, configuration_page).unwrap();
        assert_eq!(page.base(), 0x31_0000);
        assert_eq!(page.configuration_base(), configuration_page.base());
        assert_eq!(page.state().configuration(), configuration);
        let mut encoded = [0xa5; PAGE_SIZE as usize];
        page.encode_page(&mut encoded);
        assert_eq!(
            VirtualBlockResumeState::decode(&encoded[..VIRTUAL_BLOCK_RESUME_STATE_BYTES]),
            Ok(page.state())
        );
        assert!(
            encoded[VIRTUAL_BLOCK_RESUME_STATE_BYTES..]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(
            VirtualBlockResumePage::decode_page(&encoded),
            Ok(page.state())
        );
        encoded[VIRTUAL_BLOCK_RESUME_STATE_BYTES] = 1;
        assert_eq!(
            VirtualBlockResumePage::decode_page(&encoded),
            Err(VirtualBlockError::InvalidConfiguration)
        );
        assert_eq!(
            VirtualBlockResumePage::decode_page(&encoded[..PAGE_SIZE as usize - 1]),
            Err(VirtualBlockError::InvalidConfiguration)
        );

        for invalid in [
            0,
            0x31_0001,
            configuration_page.base(),
            configuration.queue().request_base(),
            configuration.queue().completion_base(),
            !(PAGE_SIZE - 1),
        ] {
            assert_eq!(
                VirtualBlockResumePage::fresh(invalid, configuration_page),
                Err(VirtualBlockError::InvalidConfiguration)
            );
        }
    }

    fn discovered_driver<const N: usize>(
        device: &VirtualBlockDevice<N>,
    ) -> VirtualBlockGuestDriver {
        let mut encoded = [0; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
        device.configuration().unwrap().encode(&mut encoded);
        VirtualBlockGuestDriver::discover(&encoded, 0, 0, 0, 0).unwrap()
    }

    fn completion_bytes(
        generation: u32,
        request_id: u64,
        status: VirtualBlockCompletionStatus,
        transferred: u32,
    ) -> [u8; VIRTUAL_BLOCK_COMPLETION_BYTES] {
        let mut encoded = [0; VIRTUAL_BLOCK_COMPLETION_BYTES];
        VirtualBlockCompletion {
            generation,
            request_id,
            status,
            transferred,
        }
        .encode(&mut encoded);
        encoded
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum GuestQueueTransportError {
        Injected,
    }

    struct MockGuestQueueTransport {
        published_request: Option<(
            u64,
            [u8; VIRTUAL_BLOCK_REQUEST_BYTES],
            u64,
            u64,
            VirtualBlockGuestNotification,
        )>,
        completion_published: u64,
        completion: [u8; VIRTUAL_BLOCK_COMPLETION_BYTES],
        completion_read: Option<(u64, u64)>,
        acknowledgement: Option<(u64, u64, VirtualBlockGuestNotification)>,
        fail_publish: bool,
        fail_read: bool,
        fail_acknowledge: bool,
    }

    impl MockGuestQueueTransport {
        fn new() -> Self {
            Self {
                published_request: None,
                completion_published: 0,
                completion: [0; VIRTUAL_BLOCK_COMPLETION_BYTES],
                completion_read: None,
                acknowledgement: None,
                fail_publish: false,
                fail_read: false,
                fail_acknowledge: false,
            }
        }
    }

    unsafe impl VirtualBlockGuestQueueTransport for MockGuestQueueTransport {
        type Error = GuestQueueTransportError;

        fn publish_request_and_notify(
            &mut self,
            request_address: u64,
            request: &[u8; VIRTUAL_BLOCK_REQUEST_BYTES],
            producer_address: u64,
            producer: u64,
            notification: VirtualBlockGuestNotification,
        ) -> Result<(), Self::Error> {
            if self.fail_publish {
                return Err(GuestQueueTransportError::Injected);
            }
            self.published_request = Some((
                request_address,
                *request,
                producer_address,
                producer,
                notification,
            ));
            Ok(())
        }

        fn read_completion(
            &mut self,
            published_address: u64,
            completion_address: u64,
            published: &mut u64,
            completion: &mut [u8; VIRTUAL_BLOCK_COMPLETION_BYTES],
        ) -> Result<(), Self::Error> {
            if self.fail_read {
                return Err(GuestQueueTransportError::Injected);
            }
            self.completion_read = Some((published_address, completion_address));
            *published = self.completion_published;
            completion.copy_from_slice(&self.completion);
            Ok(())
        }

        fn acknowledge_completion(
            &mut self,
            consumer_address: u64,
            consumer: u64,
            notification: VirtualBlockGuestNotification,
        ) -> Result<(), Self::Error> {
            if self.fail_acknowledge {
                return Err(GuestQueueTransportError::Injected);
            }
            self.acknowledgement = Some((consumer_address, consumer, notification));
            Ok(())
        }
    }

    #[test]
    fn guest_driver_discovery_requires_one_exact_idle_queue_snapshot() {
        let configuration = active::<2>().configuration().unwrap();
        let mut encoded = [0; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
        configuration.encode(&mut encoded);
        let driver = VirtualBlockGuestDriver::discover(&encoded, 0, 0, 0, 0).unwrap();
        assert_eq!(driver.configuration(), configuration);
        assert_eq!(driver.request_producer(), 0);
        assert_eq!(driver.completion_consumer(), 0);
        assert!(!driver.has_pending());
        assert!(!driver.is_terminal());

        for counters in [(1, 0, 0, 0), (1, 1, 0, 0), (1, 1, 1, 0), (1, 1, 1, 1)] {
            assert_eq!(
                VirtualBlockGuestDriver::discover(
                    &encoded, counters.0, counters.1, counters.2, counters.3,
                ),
                Err(VirtualBlockError::InvalidQueue)
            );
        }
        encoded[0] ^= 1;
        assert_eq!(
            VirtualBlockGuestDriver::discover(&encoded, 0, 0, 0, 0),
            Err(VirtualBlockError::InvalidConfiguration)
        );
    }

    #[test]
    fn guest_driver_reconstructs_exact_nonzero_pending_history() {
        let configuration = active::<2>().configuration().unwrap();
        let state = VirtualBlockResumeState {
            configuration,
            request_producer: 5,
            request_consumed: 4,
            completion_published: 4,
            completion_consumer: 3,
            last_admitted_request_id: 40,
            last_published_request_id: 50,
        };
        let mut encoded_state = [0; VIRTUAL_BLOCK_RESUME_STATE_BYTES];
        state.encode(&mut encoded_state);
        assert_eq!(VirtualBlockResumeState::decode(&encoded_state), Ok(state));

        let mut requests = [[0; VIRTUAL_BLOCK_REQUEST_BYTES]; 2];
        VirtualBlockRequest::read(1, 40, 0, 1, 0x80_0000, 4096).encode(&mut requests[1]);
        VirtualBlockRequest::write(1, 50, 1, 1, 0x81_0000, 4096).encode(&mut requests[0]);
        let mut driver = VirtualBlockGuestDriver::reconstruct(&encoded_state, &requests).unwrap();
        let configuration_page =
            VirtualBlockConfigurationPage::new(0x30_0000, configuration).unwrap();
        let page = VirtualBlockResumePage::new(0x31_0000, configuration_page, state).unwrap();
        let mut encoded_page = [0; PAGE_SIZE as usize];
        page.encode_page(&mut encoded_page);
        assert_eq!(
            VirtualBlockGuestDriver::reconstruct_from_page(&encoded_page, &requests),
            Ok(driver.clone())
        );
        let mut encoded_configuration = [0; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
        configuration.encode(&mut encoded_configuration);
        assert_eq!(
            VirtualBlockGuestDriver::resume_from_page(
                &encoded_configuration,
                &encoded_page,
                &requests,
                5,
                4,
                4,
                3,
            ),
            Ok(driver.clone())
        );
        for counters in [(6, 4, 4, 3), (5, 5, 4, 3), (5, 4, 5, 3), (5, 4, 4, 4)] {
            assert_eq!(
                VirtualBlockGuestDriver::resume_from_page(
                    &encoded_configuration,
                    &encoded_page,
                    &requests,
                    counters.0,
                    counters.1,
                    counters.2,
                    counters.3,
                ),
                Err(VirtualBlockError::InvalidQueue)
            );
        }
        encoded_configuration[16] ^= 1;
        assert!(
            VirtualBlockGuestDriver::resume_from_page(
                &encoded_configuration,
                &encoded_page,
                &requests,
                5,
                4,
                4,
                3,
            )
            .is_err()
        );
        assert_eq!(driver.configuration(), configuration);
        assert_eq!(driver.request_producer(), 5);
        assert_eq!(driver.completion_consumer(), 3);
        assert_eq!(driver.pending_count(), 2);
        assert_eq!(
            driver.prepare_read(0, 1, 0x90_0000, 4096),
            Err(VirtualBlockError::QueueFull)
        );

        let completion = completion_bytes(1, 40, VirtualBlockCompletionStatus::Ok, 4096);
        driver.accept_completion(4, &completion).unwrap();
        let next = driver.prepare_read(0, 1, 0x90_0000, 4096).unwrap();
        assert_eq!(next.producer(), 6);
        assert_eq!(next.slot(), 1);
        assert_eq!(next.request().request_id(), 51);
    }

    #[test]
    fn guest_driver_reconstructs_nonzero_idle_history_without_reusing_ids() {
        let configuration = active::<2>().configuration().unwrap();
        let state = VirtualBlockResumeState {
            configuration,
            request_producer: 5,
            request_consumed: 5,
            completion_published: 5,
            completion_consumer: 5,
            last_admitted_request_id: 50,
            last_published_request_id: 50,
        };
        let mut encoded_state = [0; VIRTUAL_BLOCK_RESUME_STATE_BYTES];
        state.encode(&mut encoded_state);
        let mut requests = [[0; VIRTUAL_BLOCK_REQUEST_BYTES]; 2];
        VirtualBlockRequest::write(1, 50, 1, 1, 0x81_0000, 4096).encode(&mut requests[0]);
        let driver = VirtualBlockGuestDriver::reconstruct(&encoded_state, &requests).unwrap();
        assert!(!driver.has_pending());
        let next = driver.prepare_read(0, 1, 0x90_0000, 4096).unwrap();
        assert_eq!(next.request().request_id(), 51);
        assert_eq!(next.producer(), 6);

        let configuration_page =
            VirtualBlockConfigurationPage::new(0x30_0000, configuration).unwrap();
        let page = VirtualBlockResumePage::new(0x31_0000, configuration_page, state).unwrap();
        let mut encoded_page = [0; PAGE_SIZE as usize];
        page.encode_page(&mut encoded_page);
        let reconstructed =
            VirtualBlockGuestDriver::reconstruct_from_page(&encoded_page, &requests).unwrap();
        assert_eq!(reconstructed, driver);

        let exhausted = VirtualBlockResumeState {
            request_producer: u64::MAX,
            request_consumed: u64::MAX,
            completion_published: u64::MAX,
            completion_consumer: u64::MAX,
            last_admitted_request_id: u64::MAX,
            last_published_request_id: u64::MAX,
            ..state
        };
        exhausted.encode(&mut encoded_state);
        VirtualBlockRequest::read(1, u64::MAX, 0, 1, 0x80_0000, 4096).encode(&mut requests[0]);
        let exhausted_driver =
            VirtualBlockGuestDriver::reconstruct(&encoded_state, &requests).unwrap();
        assert_eq!(
            exhausted_driver.terminal_reason(),
            Some(VirtualBlockGuestTerminalReason::SequenceExhausted)
        );
    }

    #[test]
    fn guest_driver_reconstruction_rejects_counter_slot_and_history_substitution() {
        let configuration = active::<2>().configuration().unwrap();
        let canonical = VirtualBlockResumeState {
            configuration,
            request_producer: 5,
            request_consumed: 4,
            completion_published: 4,
            completion_consumer: 3,
            last_admitted_request_id: 40,
            last_published_request_id: 50,
        };
        let mut requests = [[0; VIRTUAL_BLOCK_REQUEST_BYTES]; 2];
        VirtualBlockRequest::read(1, 40, 0, 1, 0x80_0000, 4096).encode(&mut requests[1]);
        VirtualBlockRequest::write(1, 50, 1, 1, 0x81_0000, 4096).encode(&mut requests[0]);

        for invalid in [
            VirtualBlockResumeState {
                completion_published: 3,
                ..canonical
            },
            VirtualBlockResumeState {
                completion_consumer: 2,
                ..canonical
            },
            VirtualBlockResumeState {
                last_admitted_request_id: 41,
                ..canonical
            },
            VirtualBlockResumeState {
                last_published_request_id: 49,
                ..canonical
            },
        ] {
            let mut encoded = [0; VIRTUAL_BLOCK_RESUME_STATE_BYTES];
            invalid.encode(&mut encoded);
            assert!(VirtualBlockGuestDriver::reconstruct(&encoded, &requests).is_err());
        }

        let mut encoded = [0; VIRTUAL_BLOCK_RESUME_STATE_BYTES];
        canonical.encode(&mut encoded);
        assert_eq!(
            VirtualBlockGuestDriver::reconstruct(&encoded, &requests[..1]),
            Err(VirtualBlockError::InvalidQueue)
        );
        let mut replay = requests;
        VirtualBlockRequest::write(1, 40, 1, 1, 0x81_0000, 4096).encode(&mut replay[0]);
        assert_eq!(
            VirtualBlockGuestDriver::reconstruct(&encoded, &replay),
            Err(VirtualBlockError::Replay)
        );
        let mut stale = requests;
        VirtualBlockRequest::write(2, 50, 1, 1, 0x81_0000, 4096).encode(&mut stale[0]);
        assert_eq!(
            VirtualBlockGuestDriver::reconstruct(&encoded, &stale),
            Err(VirtualBlockError::StaleGeneration)
        );
        let mut hidden = encoded;
        hidden[191] = 1;
        assert_eq!(
            VirtualBlockGuestDriver::reconstruct(&hidden, &requests),
            Err(VirtualBlockError::InvalidConfiguration)
        );
    }

    #[test]
    fn guest_driver_submission_and_completion_are_exact_two_phase_state() {
        let device = active::<2>();
        let mut driver = discovered_driver(&device);
        let first = driver.prepare_write(0, 1, 0x80_0000, 4096).unwrap();
        assert_eq!(first.producer(), 1);
        assert_eq!(first.slot(), 0);
        assert_eq!(first.request().generation(), 1);
        assert_eq!(first.request().request_id(), 1);
        assert_eq!(driver.request_producer(), 0);
        assert!(!driver.has_pending());
        let mut request = [0; VIRTUAL_BLOCK_REQUEST_BYTES];
        first.request().encode(&mut request);
        assert_eq!(VirtualBlockRequest::decode(&request), Ok(first.request()));

        driver.commit_submission(first).unwrap();
        assert_eq!(driver.request_producer(), 1);
        assert!(driver.has_pending());
        assert_eq!(driver.pending_count(), 1);
        let second = driver.prepare_read(0, 1, 0x80_0000, 4096).unwrap();
        assert_eq!(second.producer(), 2);
        assert_eq!(second.slot(), 1);
        assert_eq!(second.request().request_id(), 2);
        driver.commit_submission(second).unwrap();
        assert_eq!(driver.pending_count(), 2);
        assert_eq!(
            driver.prepare_read(0, 1, 0x80_0000, 4096),
            Err(VirtualBlockError::QueueFull)
        );
        assert_eq!(
            driver.commit_submission(first),
            Err(VirtualBlockError::QueueFull)
        );

        let second_completion = completion_bytes(1, 2, VirtualBlockCompletionStatus::Ok, 4096);
        assert_eq!(
            driver.accept_completion(1, &second_completion),
            Err(VirtualBlockError::InvalidCompletion)
        );
        assert!(driver.has_pending());
        assert_eq!(driver.pending_count(), 2);
        assert_eq!(driver.completion_consumer(), 0);
        let completed = completion_bytes(1, 1, VirtualBlockCompletionStatus::Ok, 4096);
        assert_eq!(
            driver.accept_completion(0, &completed),
            Err(VirtualBlockError::InvalidCompletion)
        );
        let completion_ticket = driver.prepare_completion(1, &completed).unwrap();
        assert_eq!(completion_ticket.status(), VirtualBlockCompletionStatus::Ok);
        assert_eq!(completion_ticket.transferred(), 4096);
        assert_eq!(completion_ticket.acknowledgement(), 1);
        assert_eq!(driver.completion_consumer(), 0);
        assert_eq!(driver.pending_count(), 2);
        let outcome = driver.commit_completion(completion_ticket).unwrap();
        assert_eq!(outcome.status(), VirtualBlockCompletionStatus::Ok);
        assert_eq!(outcome.transferred(), 4096);
        assert_eq!(outcome.acknowledgement(), 1);
        assert!(driver.has_pending());
        assert_eq!(driver.pending_count(), 1);
        assert_eq!(
            driver.commit_completion(completion_ticket),
            Err(VirtualBlockError::StaleTicket)
        );
        assert_eq!(driver.pending_count(), 1);

        let third = driver.prepare_read(0, 1, 0x80_0000, 4096).unwrap();
        assert_eq!(third.producer(), 3);
        assert_eq!(third.slot(), 0);
        assert_eq!(third.request().request_id(), 3);
        assert_eq!(
            driver.commit_submission(first),
            Err(VirtualBlockError::StaleTicket)
        );
        driver.commit_submission(third).unwrap();
        assert_eq!(driver.pending_count(), 2);
        driver.accept_completion(2, &second_completion).unwrap();
        let third_completion = completion_bytes(1, 3, VirtualBlockCompletionStatus::Ok, 4096);
        driver.accept_completion(3, &third_completion).unwrap();
        assert!(!driver.has_pending());

        let fourth = driver.prepare_write(0, 1, 0x80_0000, 4096).unwrap();
        driver.commit_submission(fourth).unwrap();
        let fifth = driver.prepare_read(0, 1, 0x80_0000, 4096).unwrap();
        driver.commit_submission(fifth).unwrap();
        assert_eq!(driver.pending_count(), 2);
        let reset = completion_bytes(1, 4, VirtualBlockCompletionStatus::Reset, 0);
        let reset_ticket = driver.prepare_completion(4, &reset).unwrap();
        assert_eq!(driver.pending_count(), 2);
        assert_eq!(driver.terminal_reason(), None);
        driver.commit_completion(reset_ticket).unwrap();
        assert_eq!(
            driver.terminal_reason(),
            Some(VirtualBlockGuestTerminalReason::Reset)
        );
        assert_eq!(driver.pending_count(), 0);
        let invalidated = completion_bytes(1, 5, VirtualBlockCompletionStatus::Ok, 4096);
        assert_eq!(
            driver.accept_completion(5, &invalidated),
            Err(VirtualBlockError::InvalidState)
        );
    }

    #[test]
    fn guest_driver_queue_transport_is_exact_and_transactional() {
        let device = active::<2>();
        let mut driver = discovered_driver(&device);
        let submission = driver.prepare_write(0, 1, 0x80_0000, 4096).unwrap();
        let mut transport = MockGuestQueueTransport::new();

        transport.fail_publish = true;
        assert_eq!(
            driver.publish_submission(&mut transport, submission),
            Err(VirtualBlockGuestQueueTransportError::Transport(
                GuestQueueTransportError::Injected
            ))
        );
        assert_eq!(driver.request_producer(), 0);
        assert_eq!(driver.pending_count(), 0);
        assert_eq!(transport.published_request, None);
        transport.fail_publish = false;
        driver
            .publish_submission(&mut transport, submission)
            .unwrap();
        let (request_address, encoded_request, producer_address, producer, notification) =
            transport.published_request.unwrap();
        assert_eq!(
            request_address,
            layout::<2>().request_base() + QUEUE_HEADER_BYTES
        );
        assert_eq!(producer_address, layout::<2>().request_base());
        assert_eq!(producer, 1);
        assert_eq!(
            notification,
            VirtualBlockGuestNotification::ScalarIo {
                port: VIRTUAL_BLOCK_DOORBELL_PORT,
                value: VIRTUAL_BLOCK_DOORBELL_VALUE,
            }
        );
        assert_eq!(
            VirtualBlockRequest::decode(&encoded_request),
            Ok(submission.request())
        );
        assert_eq!(driver.request_producer(), 1);
        assert_eq!(driver.pending_count(), 1);

        let second = driver.prepare_read(1, 1, 0x81_0000, 4096).unwrap();
        driver.publish_submission(&mut transport, second).unwrap();
        assert_eq!(driver.request_producer(), 2);
        assert_eq!(driver.pending_count(), 2);

        transport.completion_published = 2;
        transport.completion = completion_bytes(1, 1, VirtualBlockCompletionStatus::Ok, 4096);
        transport.fail_read = true;
        assert_eq!(
            driver.prepare_completion_from_transport(&mut transport),
            Err(VirtualBlockGuestQueueTransportError::Transport(
                GuestQueueTransportError::Injected
            ))
        );
        assert_eq!(driver.completion_consumer(), 0);
        assert_eq!(driver.pending_count(), 2);
        transport.fail_read = false;
        let ticket = driver
            .prepare_completion_from_transport(&mut transport)
            .unwrap();
        assert_eq!(
            transport.completion_read,
            Some((
                layout::<2>().completion_base(),
                layout::<2>().completion_base() + QUEUE_HEADER_BYTES,
            ))
        );
        assert_eq!(ticket.acknowledgement(), 1);
        assert_eq!(driver.completion_consumer(), 0);

        transport.fail_acknowledge = true;
        assert_eq!(
            driver.acknowledge_completion_with_transport(&mut transport, ticket),
            Err(VirtualBlockGuestQueueTransportError::Transport(
                GuestQueueTransportError::Injected
            ))
        );
        assert_eq!(driver.completion_consumer(), 0);
        assert_eq!(driver.pending_count(), 2);
        transport.fail_acknowledge = false;
        let outcome = driver
            .acknowledge_completion_with_transport(&mut transport, ticket)
            .unwrap();
        assert_eq!(outcome.status(), VirtualBlockCompletionStatus::Ok);
        assert_eq!(
            transport.acknowledgement,
            Some((
                layout::<2>().completion_base() + 64,
                1,
                VirtualBlockGuestNotification::ScalarIo {
                    port: VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
                    value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
                },
            ))
        );
        assert_eq!(driver.completion_consumer(), 1);
        assert_eq!(driver.pending_count(), 1);

        transport.acknowledgement = None;
        assert_eq!(
            driver.acknowledge_completion_with_transport(&mut transport, ticket),
            Err(VirtualBlockGuestQueueTransportError::Protocol(
                VirtualBlockError::StaleTicket
            ))
        );
        assert_eq!(transport.acknowledgement, None);
    }

    #[test]
    fn guest_driver_maximum_window_is_bounded_and_drains_in_order() {
        let device = active::<MAX_VIRTUAL_BLOCK_QUEUE_SLOTS>();
        let mut driver = discovered_driver(&device);
        for index in 0..MAX_VIRTUAL_BLOCK_QUEUE_SLOTS {
            let submission = driver
                .prepare_read(index as u64, 1, 0x80_0000 + (index as u64 * 4096), 4096)
                .unwrap();
            assert_eq!(submission.slot(), index as u16);
            assert_eq!(submission.request().request_id(), index as u64 + 1);
            driver.commit_submission(submission).unwrap();
        }
        assert_eq!(driver.pending_count(), MAX_VIRTUAL_BLOCK_QUEUE_SLOTS as u16);
        assert_eq!(
            driver.prepare_read(0, 1, 0x90_0000, 4096),
            Err(VirtualBlockError::QueueFull)
        );

        for position in 1..=MAX_VIRTUAL_BLOCK_QUEUE_SLOTS as u64 {
            let completion = completion_bytes(1, position, VirtualBlockCompletionStatus::Ok, 4096);
            driver.accept_completion(position, &completion).unwrap();
            assert_eq!(
                driver.pending_count(),
                (MAX_VIRTUAL_BLOCK_QUEUE_SLOTS as u64 - position) as u16
            );
        }
        assert!(!driver.has_pending());
    }

    #[test]
    fn guest_driver_bounds_features_errors_and_terminal_completions() {
        let mut no_flush =
            VirtualBlockDevice::<1>::new(4096, 2, VIRTUAL_BLOCK_FEATURE_FLUSH).unwrap();
        no_flush.negotiate(0).unwrap();
        no_flush.activate(layout::<1>(), 48).unwrap();
        let mut driver = discovered_driver(&no_flush);
        assert_eq!(
            driver.prepare_flush(),
            Err(VirtualBlockError::InvalidFeatures)
        );
        for result in [
            driver.prepare_read(0, 0, 0x80_0000, 0),
            driver.prepare_read(2, 1, 0x80_0000, 4096),
            driver.prepare_read(0, 1, 0, 4096),
            driver.prepare_read(0, 1, u64::MAX - 1024, 4096),
            driver.prepare_read(0, 1, 0x80_0000, 2048),
        ] {
            assert!(matches!(
                result,
                Err(VirtualBlockError::InvalidRange | VirtualBlockError::InvalidBuffer)
            ));
        }
        let submission = driver.prepare_write(0, 1, 0x80_0000, 4096).unwrap();
        driver.commit_submission(submission).unwrap();
        let reset = completion_bytes(1, 1, VirtualBlockCompletionStatus::Reset, 0);
        let outcome = driver.accept_completion(1, &reset).unwrap();
        assert_eq!(outcome.status(), VirtualBlockCompletionStatus::Reset);
        assert!(driver.is_terminal());
        assert_eq!(
            driver.terminal_reason(),
            Some(VirtualBlockGuestTerminalReason::Reset)
        );
        assert_eq!(
            driver.prepare_write(0, 1, 0x80_0000, 4096),
            Err(VirtualBlockError::InvalidState)
        );

        let reset_state = driver.clone();
        let mut stale_configuration = [0; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
        no_flush
            .configuration()
            .unwrap()
            .encode(&mut stale_configuration);
        assert_eq!(
            driver.rediscover_after_reset(&stale_configuration, 0, 0, 0, 0),
            Err(VirtualBlockError::StaleGeneration)
        );
        assert_eq!(driver, reset_state);

        no_flush.reset().unwrap();
        no_flush.negotiate(0).unwrap();
        no_flush.activate(layout::<1>(), 49).unwrap();
        let replacement = no_flush.configuration().unwrap();
        let mut encoded_replacement = [0; VIRTUAL_BLOCK_CONFIGURATION_BYTES];
        replacement.encode(&mut encoded_replacement);
        let mut skipped_generation = encoded_replacement;
        skipped_generation[8..12].copy_from_slice(&3_u32.to_le_bytes());
        assert_eq!(
            driver.rediscover_after_reset(&skipped_generation, 0, 0, 0, 0),
            Err(VirtualBlockError::StaleGeneration)
        );
        assert_eq!(driver, reset_state);
        for counters in [(1, 0, 0, 0), (0, 1, 0, 0), (0, 0, 1, 0), (0, 0, 0, 1)] {
            assert_eq!(
                driver.rediscover_after_reset(
                    &encoded_replacement,
                    counters.0,
                    counters.1,
                    counters.2,
                    counters.3,
                ),
                Err(VirtualBlockError::InvalidQueue)
            );
            assert_eq!(driver, reset_state);
        }
        let mut corrupt = encoded_replacement;
        corrupt[127] = 1;
        assert_eq!(
            driver.rediscover_after_reset(&corrupt, 0, 0, 0, 0),
            Err(VirtualBlockError::InvalidConfiguration)
        );
        assert_eq!(driver, reset_state);
        driver
            .rediscover_after_reset(&encoded_replacement, 0, 0, 0, 0)
            .unwrap();
        assert_eq!(driver.configuration(), replacement);
        assert_eq!(driver.terminal_reason(), None);
        let rediscovered = driver.prepare_write(0, 1, 0x80_0000, 4096).unwrap();
        assert_eq!(rediscovered.request().generation(), 2);
        assert_eq!(rediscovered.request().request_id(), 1);
        assert_eq!(rediscovered.producer(), 1);

        let configuration = no_flush.configuration().unwrap();
        let mut exhausted = VirtualBlockGuestDriver {
            configuration,
            next_request_id: u64::MAX,
            request_ids_exhausted: false,
            request_producer: u64::MAX - 1,
            completion_consumer: u64::MAX - 1,
            pending: [None; MAX_VIRTUAL_BLOCK_QUEUE_SLOTS],
            pending_count: 0,
            terminal: None,
        };
        let last = exhausted.prepare_write(0, 1, 0x80_0000, 4096).unwrap();
        assert_eq!(last.request().request_id(), u64::MAX);
        assert_eq!(last.producer(), u64::MAX);
        exhausted.commit_submission(last).unwrap();
        assert_eq!(
            exhausted.prepare_write(0, 1, 0x80_0000, 4096),
            Err(VirtualBlockError::SequenceExhausted)
        );
        let completed = completion_bytes(
            configuration.generation(),
            u64::MAX,
            VirtualBlockCompletionStatus::Ok,
            4096,
        );
        exhausted.accept_completion(u64::MAX, &completed).unwrap();
        assert!(exhausted.is_terminal());
        assert_eq!(
            exhausted.terminal_reason(),
            Some(VirtualBlockGuestTerminalReason::SequenceExhausted)
        );
        assert_eq!(
            exhausted.rediscover_after_reset(&encoded_replacement, 0, 0, 0, 0),
            Err(VirtualBlockError::InvalidState)
        );

        let mut removed = discovered_driver(&no_flush);
        let request = removed.prepare_read(0, 1, 0x80_0000, 4096).unwrap();
        removed.commit_submission(request).unwrap();
        let completion = completion_bytes(2, 1, VirtualBlockCompletionStatus::Removed, 0);
        removed.accept_completion(1, &completion).unwrap();
        assert_eq!(
            removed.terminal_reason(),
            Some(VirtualBlockGuestTerminalReason::Removed)
        );
        assert_eq!(
            removed.rediscover_after_reset(&encoded_replacement, 0, 0, 0, 0),
            Err(VirtualBlockError::InvalidState)
        );
    }

    #[test]
    fn lifecycle_negotiation_reset_and_removal_invalidate_stale_work() {
        let mut device =
            VirtualBlockDevice::<2>::new(4096, 64, VIRTUAL_BLOCK_FEATURE_FLUSH).unwrap();
        assert_eq!(device.state(), VirtualBlockDeviceState::Created);
        assert_eq!(device.negotiate(2), Err(VirtualBlockError::InvalidFeatures));
        device.negotiate(VIRTUAL_BLOCK_FEATURE_FLUSH).unwrap();
        assert_eq!(
            device.activate(layout::<2>(), 31),
            Err(VirtualBlockError::InvalidInterrupt)
        );
        device.activate(layout::<2>(), 48).unwrap();
        let admitted = device
            .admit(&encoded(VirtualBlockRequest::read(
                1, 1, 0, 1, 0x8000, 4096,
            )))
            .unwrap();
        assert_eq!(device.suspend(), Err(VirtualBlockError::InvalidState));
        assert_eq!(device.reset(), Ok(1));
        assert_eq!(
            (device.state(), device.generation()),
            (VirtualBlockDeviceState::Created, 2)
        );
        assert_eq!(
            device.complete(admitted.ticket(), VirtualBlockCompletionStatus::Ok, 4096),
            Err(VirtualBlockError::InvalidState)
        );
        device.negotiate(0).unwrap();
        device.activate(layout::<2>(), 49).unwrap();
        assert_eq!(
            device.admit(&encoded(VirtualBlockRequest::read(
                1, 2, 0, 1, 0x8000, 4096
            ))),
            Err(VirtualBlockError::StaleGeneration)
        );
        assert_eq!(device.remove(), Ok(0));
        assert_eq!(device.state(), VirtualBlockDeviceState::Removed);
        device.destroy().unwrap();
        assert_eq!(device.state(), VirtualBlockDeviceState::Destroyed);
    }

    #[test]
    fn reset_exhaustion_preserves_live_state_and_inflight_ticket() {
        let mut device = active::<1>();
        let admitted = device
            .admit(&encoded(VirtualBlockRequest::read(
                1, 1, 0, 1, 0x8000, 4096,
            )))
            .unwrap();
        device.slot_generations[0] = u32::MAX;
        assert_eq!(device.reset(), Err(VirtualBlockError::SequenceExhausted));
        assert_eq!(device.state(), VirtualBlockDeviceState::Active);
        assert_eq!(
            device
                .complete(admitted.ticket(), VirtualBlockCompletionStatus::Ok, 4096,)
                .map(|completion| completion.request_id()),
            Ok(1)
        );
    }

    #[test]
    fn fail_exhaustion_is_terminal_instead_of_returning_to_active_use() {
        let mut device = active::<1>();
        let admitted = device
            .admit(&encoded(VirtualBlockRequest::read(
                1, 1, 0, 1, 0x8000, 4096,
            )))
            .unwrap();
        device.slot_generations[0] = u32::MAX;
        assert_eq!(device.fail(), Err(VirtualBlockError::SequenceExhausted));
        assert_eq!(device.state(), VirtualBlockDeviceState::Failed);
        assert_eq!(
            device.complete(admitted.ticket(), VirtualBlockCompletionStatus::Ok, 4096),
            Err(VirtualBlockError::InvalidState)
        );
        assert_eq!(
            device.admit(&encoded(VirtualBlockRequest::read(
                1, 2, 1, 1, 0x9000, 4096,
            ))),
            Err(VirtualBlockError::InvalidState)
        );
    }

    #[test]
    fn completion_notification_coalesces_and_terminal_lifecycle_clears_it() {
        let mut device = active::<1>();
        device.latch_completion_interrupt().unwrap();
        device.latch_completion_interrupt().unwrap();
        assert_eq!(device.pending_interrupt_vector(), Some(48));
        assert_eq!(device.suspend(), Err(VirtualBlockError::InvalidState));
        assert_eq!(device.reset(), Ok(0));
        assert_eq!(device.pending_interrupt_vector(), None);

        device.negotiate(0).unwrap();
        device.activate(layout::<1>(), 49).unwrap();
        device.latch_completion_interrupt().unwrap();
        assert_eq!(device.fail(), Ok(0));
        assert_eq!(device.pending_interrupt_vector(), None);
        assert_eq!(
            device.acknowledge_interrupt(49),
            Err(VirtualBlockError::InvalidInterrupt)
        );
    }

    #[test]
    fn admission_is_monotonic_bounded_and_completion_is_ticket_bound() {
        let mut device = active::<1>();
        let first = device
            .admit(&encoded(VirtualBlockRequest::read(
                1, 7, 0, 1, 0x8000, 4096,
            )))
            .unwrap();
        assert_eq!(
            device.admit(&encoded(VirtualBlockRequest::write(
                1, 8, 1, 1, 0x9000, 4096
            ))),
            Err(VirtualBlockError::QueueFull)
        );
        let mut forged = first.ticket();
        forged.request_id = 8;
        assert_eq!(
            device.complete(forged, VirtualBlockCompletionStatus::Ok, 4096),
            Err(VirtualBlockError::StaleTicket)
        );
        let completion = device
            .complete(first.ticket(), VirtualBlockCompletionStatus::Ok, 4096)
            .unwrap();
        assert_eq!(
            (completion.request_id(), completion.transferred()),
            (7, 4096)
        );
        assert_eq!(
            device.admit(&encoded(VirtualBlockRequest::read(
                1, 7, 0, 1, 0x8000, 4096
            ))),
            Err(VirtualBlockError::Replay)
        );
    }

    #[test]
    fn admission_skips_exhausted_empty_slots_and_reports_terminal_exhaustion() {
        let mut device = active::<2>();
        device.slot_generations[0] = u32::MAX;
        let admitted = device
            .admit(&encoded(VirtualBlockRequest::read(
                1, 1, 0, 1, 0x8000, 4096,
            )))
            .unwrap();
        assert_eq!(admitted.ticket().slot, 1);
        device
            .complete(admitted.ticket(), VirtualBlockCompletionStatus::Ok, 4096)
            .unwrap();
        device.slot_generations[1] = u32::MAX;
        assert_eq!(
            device.admission_ready(),
            Err(VirtualBlockError::SequenceExhausted)
        );
        assert_eq!(
            device.admit(&encoded(VirtualBlockRequest::read(
                1, 2, 1, 1, 0x9000, 4096,
            ))),
            Err(VirtualBlockError::SequenceExhausted)
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockError {
        Bounds,
        Injected,
    }

    struct MockVmm {
        bytes: [u8; 0x5000],
        fail_read: bool,
        fail_write: bool,
        fail_write_address: Option<u64>,
        next_exit: Option<VmExit>,
        injected: Option<(u32, u8)>,
        fail_inject: bool,
        completed_mmio: Option<(u32, u64, u8, u64)>,
        fail_mmio_completion: bool,
    }

    impl MockVmm {
        fn new() -> Self {
            Self {
                bytes: [0; 0x5000],
                fail_read: false,
                fail_write: false,
                fail_write_address: None,
                next_exit: None,
                injected: None,
                fail_inject: false,
                completed_mmio: None,
                fail_mmio_completion: false,
            }
        }
    }

    impl VmBackend for MockVmm {
        type Error = MockError;

        fn run(&mut self, _: u32) -> Result<VmExit, Self::Error> {
            self.next_exit.take().ok_or(MockError::Injected)
        }

        fn read_guest(&self, address: u64, output: &mut [u8]) -> Result<(), Self::Error> {
            if self.fail_read {
                return Err(MockError::Injected);
            }
            let start = usize::try_from(address).map_err(|_| MockError::Bounds)?;
            let end = start.checked_add(output.len()).ok_or(MockError::Bounds)?;
            output.copy_from_slice(self.bytes.get(start..end).ok_or(MockError::Bounds)?);
            Ok(())
        }

        fn write_guest(&mut self, address: u64, input: &[u8]) -> Result<(), Self::Error> {
            self.write_virtual_block(address, input)
        }

        fn inject_interrupt(&mut self, vcpu: u32, vector: u8) -> Result<(), Self::Error> {
            if self.fail_inject {
                return Err(MockError::Injected);
            }
            self.injected = Some((vcpu, vector));
            Ok(())
        }
    }

    impl MmioWriteCompleter for MockVmm {
        fn complete_mmio_write(
            &mut self,
            vcpu: u32,
            guest_address: u64,
            size: u8,
            value: u64,
        ) -> Result<(), Self::Error> {
            if self.fail_mmio_completion || self.completed_mmio.is_some() {
                return Err(MockError::Injected);
            }
            self.completed_mmio = Some((vcpu, guest_address, size, value));
            Ok(())
        }
    }

    impl VirtualBlockVmmMemory for MockVmm {
        fn write_virtual_block(&mut self, address: u64, input: &[u8]) -> Result<(), Self::Error> {
            if self.fail_write || self.fail_write_address == Some(address) {
                return Err(MockError::Injected);
            }
            let start = usize::try_from(address).map_err(|_| MockError::Bounds)?;
            let end = start.checked_add(input.len()).ok_or(MockError::Bounds)?;
            self.bytes
                .get_mut(start..end)
                .ok_or(MockError::Bounds)?
                .copy_from_slice(input);
            Ok(())
        }
    }

    #[test]
    fn live_bridge_resume_state_binds_device_history_and_poison_on_uncertainty() {
        let mut device = active::<2>();
        let queue = layout::<2>();
        let mut bridge = VirtualBlockQueueBridge::<2>::new(queue).unwrap();
        let first = VirtualBlockRequest::read(1, 10, 0, 1, 0x4000, 4096);
        let second = VirtualBlockRequest::write(1, 20, 1, 1, 0x4000, 4096);
        let first_admitted = device.admit(&encoded(first)).unwrap();
        let second_admitted = device.admit(&encoded(second)).unwrap();
        device
            .complete(
                first_admitted.ticket(),
                VirtualBlockCompletionStatus::Ok,
                4096,
            )
            .unwrap();
        device
            .complete(
                second_admitted.ticket(),
                VirtualBlockCompletionStatus::Ok,
                4096,
            )
            .unwrap();
        bridge.request_consumed = 2;
        bridge.completion_published = 2;
        bridge.completion_consumed = 1;

        let mut vmm = MockVmm::new();
        vmm.bytes[queue.request_base() as usize..queue.request_base() as usize + 8]
            .copy_from_slice(&2_u64.to_le_bytes());
        let first_address = queue.request_base() as usize + QUEUE_HEADER_BYTES as usize;
        vmm.bytes[first_address..first_address + VIRTUAL_BLOCK_REQUEST_BYTES]
            .copy_from_slice(&encoded(first));
        let second_address = first_address + VIRTUAL_BLOCK_REQUEST_BYTES;
        vmm.bytes[second_address..second_address + VIRTUAL_BLOCK_REQUEST_BYTES]
            .copy_from_slice(&encoded(second));

        assert_eq!(
            bridge.resume_state(&vmm, &device),
            Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::InvalidState
            ))
        );
        let active_configuration = device.configuration().unwrap();
        device.suspend().unwrap();
        let state = bridge.resume_state(&vmm, &device).unwrap();
        assert_eq!(state.configuration(), active_configuration);
        assert_eq!(state.request_producer(), 2);
        assert_eq!(state.request_consumed(), 2);
        assert_eq!(state.completion_published(), 2);
        assert_eq!(state.completion_consumer(), 1);
        assert_eq!(state.last_admitted_request_id(), 20);
        assert_eq!(state.last_published_request_id(), 20);

        let mut encoded_state = [0; VIRTUAL_BLOCK_RESUME_STATE_BYTES];
        state.encode(&mut encoded_state);
        let requests = [encoded(first), encoded(second)];
        let driver = VirtualBlockGuestDriver::reconstruct(&encoded_state, &requests).unwrap();
        assert_eq!(driver.pending_count(), 1);
        assert_eq!(driver.completion_consumer(), 1);

        let configuration_page =
            VirtualBlockConfigurationPage::new(0x5000, active_configuration).unwrap();
        let resume_page = VirtualBlockResumePage::fresh(0x4000, configuration_page).unwrap();
        let published = bridge
            .publish_resume_page(&mut vmm, &device, resume_page)
            .unwrap();
        assert_eq!(published.state(), state);
        assert_eq!(
            VirtualBlockResumeState::decode(
                &vmm.bytes[0x4000..0x4000 + VIRTUAL_BLOCK_RESUME_STATE_BYTES]
            ),
            Ok(state)
        );
        assert!(
            vmm.bytes[0x4000 + VIRTUAL_BLOCK_RESUME_STATE_BYTES..0x5000]
                .iter()
                .all(|byte| *byte == 0)
        );
        vmm.fail_write_address = Some(resume_page.base());
        assert_eq!(
            bridge.publish_resume_page(&mut vmm, &device, resume_page),
            Err(VirtualBlockQueueError::Backend(MockError::Injected))
        );
        assert!(bridge.is_poisoned());

        let mut uncertain_bridge = VirtualBlockQueueBridge::<2>::new(queue).unwrap();
        let mut uncertain_vmm = MockVmm::new();
        uncertain_vmm.fail_read = true;
        assert_eq!(
            uncertain_bridge.resume_state(&uncertain_vmm, &device),
            Err(VirtualBlockQueueError::Backend(MockError::Injected))
        );
        assert!(uncertain_bridge.is_poisoned());
    }

    #[test]
    fn restart_image_is_bounded_one_use_and_restores_only_fresh_memory() {
        assert!(core::mem::needs_drop::<VirtualBlockRestartImage>());
        assert!(core::mem::size_of::<VirtualBlockRestartImage>() <= 16 * 1024);
        assert!(core::mem::needs_drop::<VirtualBlockLostExecution>());
        assert!(core::mem::size_of::<VirtualBlockLostExecution>() <= 16 * 1024);
        let mut device = active::<4>();
        let queue = layout::<4>();
        let mut bridge = VirtualBlockQueueBridge::<4>::new(queue).unwrap();
        let first = VirtualBlockRequest::write(1, 10, 0, 1, 0x4000, 4096);
        let second = VirtualBlockRequest::write(1, 20, 1, 1, 0x5000, 4096);
        let first_admitted = device.admit(&encoded(first)).unwrap();
        let second_admitted = device.admit(&encoded(second)).unwrap();
        let first_completion = device
            .complete(
                first_admitted.ticket(),
                VirtualBlockCompletionStatus::Ok,
                4096,
            )
            .unwrap();
        let second_completion = device
            .complete(
                second_admitted.ticket(),
                VirtualBlockCompletionStatus::Ok,
                4096,
            )
            .unwrap();
        bridge.request_consumed = 2;
        bridge.completion_published = 2;

        let mut source = MockVmm::new();
        source.bytes[queue.request_base() as usize..queue.request_base() as usize + 8]
            .copy_from_slice(&2_u64.to_le_bytes());
        source.bytes[queue.request_base() as usize + 64..queue.request_base() as usize + 72]
            .copy_from_slice(&2_u64.to_le_bytes());
        for (position, request) in [(1, first), (2, second)] {
            let address = slot_address(
                queue.request_base(),
                position,
                4,
                VIRTUAL_BLOCK_REQUEST_BYTES,
            )
            .unwrap() as usize;
            source.bytes[address..address + VIRTUAL_BLOCK_REQUEST_BYTES]
                .copy_from_slice(&encoded(request));
        }
        source.bytes[queue.request_base() as usize + 0x800] = 0xa5;
        source.bytes[queue.completion_base() as usize..queue.completion_base() as usize + 8]
            .copy_from_slice(&2_u64.to_le_bytes());
        for (position, completion) in [(1, first_completion), (2, second_completion)] {
            let address = slot_address(
                queue.completion_base(),
                position,
                4,
                VIRTUAL_BLOCK_COMPLETION_BYTES,
            )
            .unwrap() as usize;
            completion.encode(
                (&mut source.bytes[address..address + VIRTUAL_BLOCK_COMPLETION_BYTES])
                    .try_into()
                    .unwrap(),
            );
        }
        source.bytes[queue.completion_base() as usize + 0x800] = 0x5a;

        let configuration = device.configuration().unwrap();
        let configuration_page = VirtualBlockConfigurationPage::new(0x5000, configuration).unwrap();
        let resume_page = VirtualBlockResumePage::fresh(0x4000, configuration_page).unwrap();
        device.suspend().unwrap();
        let published = bridge
            .publish_resume_page(&mut source, &device, resume_page)
            .unwrap();
        let nonfresh_image = bridge
            .capture_restart_image(&source, &device, published)
            .unwrap();
        assert_eq!(nonfresh_image.state(), published.state());
        assert!(
            nonfresh_image.request_slots[2..]
                .iter()
                .flatten()
                .all(|byte| *byte == 0)
        );
        assert!(
            nonfresh_image.completion_slots[2..]
                .iter()
                .flatten()
                .all(|byte| *byte == 0)
        );
        let mut encoded_fresh_resume = [0; PAGE_SIZE as usize];
        resume_page.encode_page(&mut encoded_fresh_resume);

        let mut nonfresh = MockVmm::new();
        nonfresh.bytes[queue.request_base() as usize + 1] = 1;
        // SAFETY: this mock has no runnable native execution context.
        let nonfresh_loss = unsafe { nonfresh_image.confirm_execution_loss() };
        assert_eq!(
            bridge.restore_restart_image(&mut nonfresh, &device, nonfresh_loss),
            Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::InvalidQueue
            ))
        );
        assert_eq!(
            &nonfresh.bytes[queue.completion_base() as usize..queue.completion_base() as usize + 8],
            &[0; 8]
        );

        let image = bridge
            .capture_restart_image(&source, &device, published)
            .unwrap();
        let mut replacement = MockVmm::new();
        replacement.bytes[0x4000..0x5000].copy_from_slice(&encoded_fresh_resume);
        // SAFETY: this mock has no runnable native execution context.
        let lost = unsafe { image.confirm_execution_loss() };
        bridge
            .restore_restart_image(&mut replacement, &device, lost)
            .unwrap();
        assert_eq!(
            &replacement.bytes[queue.request_base() as usize..queue.request_base() as usize + 8],
            &2_u64.to_le_bytes()
        );
        assert_eq!(
            &replacement.bytes
                [queue.completion_base() as usize..queue.completion_base() as usize + 8],
            &2_u64.to_le_bytes()
        );
        assert_eq!(
            &replacement.bytes[0x4000..0x5000],
            &source.bytes[0x4000..0x5000]
        );
        assert_eq!(replacement.bytes[queue.request_base() as usize + 0x800], 0);
        assert_eq!(
            replacement.bytes[queue.completion_base() as usize + 0x800],
            0
        );

        let second_completion_address = slot_address(
            queue.completion_base(),
            2,
            4,
            VIRTUAL_BLOCK_COMPLETION_BYTES,
        )
        .unwrap() as usize;
        source.bytes[second_completion_address + 16] ^= 1;
        assert!(matches!(
            bridge.capture_restart_image(&source, &device, published),
            Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::InvalidCompletion
            ))
        ));

        source.bytes[second_completion_address + 16] ^= 1;
        let uncertain_image = bridge
            .capture_restart_image(&source, &device, published)
            .unwrap();
        let mut uncertain = MockVmm::new();
        uncertain.bytes[0x4000..0x5000].copy_from_slice(&encoded_fresh_resume);
        uncertain.fail_write_address =
            Some(slot_address(queue.request_base(), 1, 4, VIRTUAL_BLOCK_REQUEST_BYTES).unwrap());
        // SAFETY: this mock has no runnable native execution context.
        let uncertain_loss = unsafe { uncertain_image.confirm_execution_loss() };
        assert_eq!(
            bridge.restore_restart_image(&mut uncertain, &device, uncertain_loss),
            Err(VirtualBlockQueueError::Backend(MockError::Injected))
        );
        assert!(bridge.is_poisoned());
    }

    #[test]
    fn restart_image_rejects_transport_substitution_before_restoration() {
        let queue = layout::<2>();
        let mut pci = VirtualBlockDevice::<2>::new_with_transport(
            4096,
            64,
            VIRTUAL_BLOCK_FEATURE_FLUSH,
            VirtualBlockTransport::MrmlSpecificPciMmio,
        )
        .unwrap();
        pci.negotiate(VIRTUAL_BLOCK_FEATURE_FLUSH).unwrap();
        pci.activate(queue, 48).unwrap();
        let mut bridge = VirtualBlockQueueBridge::<2>::new(queue).unwrap();
        let mut source = MockVmm::new();
        let pci_configuration = pci.configuration().unwrap();
        let pci_page = VirtualBlockConfigurationPage::new(0x5000, pci_configuration).unwrap();
        let resume_page = VirtualBlockResumePage::fresh(0x4000, pci_page).unwrap();
        pci.suspend().unwrap();
        let published = bridge
            .publish_resume_page(&mut source, &pci, resume_page)
            .unwrap();
        let image = bridge
            .capture_restart_image(&source, &pci, published)
            .unwrap();

        let mut scalar = VirtualBlockDevice::<2>::new_with_transport(
            4096,
            64,
            VIRTUAL_BLOCK_FEATURE_FLUSH,
            VirtualBlockTransport::MrmlSpecificScalarIo,
        )
        .unwrap();
        scalar.negotiate(VIRTUAL_BLOCK_FEATURE_FLUSH).unwrap();
        scalar.activate(queue, 48).unwrap();
        let scalar_configuration = scalar.configuration().unwrap();
        scalar.suspend().unwrap();
        let scalar_page = VirtualBlockConfigurationPage::new(0x5000, scalar_configuration).unwrap();
        let scalar_resume = VirtualBlockResumePage::fresh(0x4000, scalar_page).unwrap();
        let mut encoded_scalar_resume = [0; PAGE_SIZE as usize];
        scalar_resume.encode_page(&mut encoded_scalar_resume);
        let mut replacement = MockVmm::new();
        replacement.bytes[0x4000..0x5000].copy_from_slice(&encoded_scalar_resume);
        // SAFETY: this mock has no runnable native execution context.
        let lost = unsafe { image.confirm_execution_loss() };
        assert_eq!(
            bridge.restore_restart_image(&mut replacement, &scalar, lost),
            Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::InvalidConfiguration
            ))
        );
        assert_eq!(
            &replacement.bytes
                [queue.request_base() as usize..queue.request_base() as usize + PAGE_SIZE as usize],
            &[0; PAGE_SIZE as usize]
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockMutation {
        Complete,
        Reject,
        Uncertain,
    }

    struct MockBlock {
        bytes: [u8; 0x4000],
        mutation: MockMutation,
        reads: usize,
        writes: usize,
        flushes: usize,
    }

    impl MockBlock {
        fn new() -> Self {
            Self {
                bytes: [0; 0x4000],
                mutation: MockMutation::Complete,
                reads: 0,
                writes: 0,
                flushes: 0,
            }
        }

        fn range(&self, block: u64, bytes: usize) -> Result<core::ops::Range<usize>, MockError> {
            let start = usize::try_from(block)
                .ok()
                .and_then(|block| block.checked_mul(4096))
                .ok_or(MockError::Bounds)?;
            let end = start.checked_add(bytes).ok_or(MockError::Bounds)?;
            self.bytes.get(start..end).ok_or(MockError::Bounds)?;
            Ok(start..end)
        }
    }

    unsafe impl VirtualBlockBackend for MockBlock {
        type Error = MockError;

        fn read_blocks(&mut self, block: u64, output: &mut [u8]) -> Result<(), Self::Error> {
            let range = self.range(block, output.len())?;
            self.reads += 1;
            output.copy_from_slice(&self.bytes[range]);
            Ok(())
        }

        fn write_blocks(
            &mut self,
            block: u64,
            input: &[u8],
        ) -> Result<(), VirtualBlockMutationError<Self::Error>> {
            let range = self
                .range(block, input.len())
                .map_err(VirtualBlockMutationError::Rejected)?;
            self.writes += 1;
            match self.mutation {
                MockMutation::Complete => {
                    self.bytes[range].copy_from_slice(input);
                    Ok(())
                }
                MockMutation::Reject => {
                    Err(VirtualBlockMutationError::Rejected(MockError::Injected))
                }
                MockMutation::Uncertain => {
                    self.bytes[range.start] = input[0];
                    Err(VirtualBlockMutationError::Uncertain(MockError::Injected))
                }
            }
        }

        fn flush(&mut self) -> Result<(), VirtualBlockMutationError<Self::Error>> {
            self.flushes += 1;
            match self.mutation {
                MockMutation::Complete => Ok(()),
                MockMutation::Reject => {
                    Err(VirtualBlockMutationError::Rejected(MockError::Injected))
                }
                MockMutation::Uncertain => {
                    Err(VirtualBlockMutationError::Uncertain(MockError::Injected))
                }
            }
        }
    }

    #[test]
    fn capability_selected_backend_enforces_independent_operation_rights() {
        let object = ObjectId(0x300);

        let mut read_space = CapabilitySpace::<1>::new();
        let read_capability = read_space.insert(object, crate::Rights::READ).unwrap();
        let mut read_backend = MockBlock::new();
        read_backend.bytes[..4096].fill(0x5a);
        let mut output = [0; 4096];
        let mut selected = CapabilitySelectedVirtualBlockBackend::new(
            &mut read_backend,
            &read_space,
            VirtualBlockBackendAuthority::new(read_capability, object, 0, 4).unwrap(),
            4096,
        );
        assert_eq!(selected.read_blocks(0, &mut output), Ok(()));
        assert!(output.iter().all(|byte| *byte == 0x5a));
        assert!(matches!(
            selected.write_blocks(0, &[0x65; 4096]),
            Err(VirtualBlockMutationError::Rejected(
                VirtualBlockCapabilityError::Capability(CapabilityError::PermissionDenied)
            ))
        ));
        assert!(matches!(
            selected.flush(),
            Err(VirtualBlockMutationError::Rejected(
                VirtualBlockCapabilityError::Capability(CapabilityError::PermissionDenied)
            ))
        ));
        assert_eq!(
            (
                read_backend.reads,
                read_backend.writes,
                read_backend.flushes
            ),
            (1, 0, 0)
        );

        let mut write_space = CapabilitySpace::<1>::new();
        let write_capability = write_space.insert(object, crate::Rights::WRITE).unwrap();
        let mut write_backend = MockBlock::new();
        let mut selected = CapabilitySelectedVirtualBlockBackend::new(
            &mut write_backend,
            &write_space,
            VirtualBlockBackendAuthority::new(write_capability, object, 0, 4).unwrap(),
            4096,
        );
        assert!(matches!(
            selected.read_blocks(0, &mut output),
            Err(VirtualBlockCapabilityError::Capability(
                CapabilityError::PermissionDenied
            ))
        ));
        assert_eq!(selected.write_blocks(0, &[0x65; 4096]), Ok(()));
        assert!(matches!(
            selected.flush(),
            Err(VirtualBlockMutationError::Rejected(
                VirtualBlockCapabilityError::Capability(CapabilityError::PermissionDenied)
            ))
        ));
        assert_eq!(
            (
                write_backend.reads,
                write_backend.writes,
                write_backend.flushes
            ),
            (0, 1, 0)
        );

        let mut flush_space = CapabilitySpace::<1>::new();
        let flush_capability = flush_space.insert(object, crate::Rights::FLUSH).unwrap();
        let mut flush_backend = MockBlock::new();
        let mut selected = CapabilitySelectedVirtualBlockBackend::new(
            &mut flush_backend,
            &flush_space,
            VirtualBlockBackendAuthority::new(flush_capability, object, 0, 4).unwrap(),
            4096,
        );
        assert!(matches!(
            selected.read_blocks(0, &mut output),
            Err(VirtualBlockCapabilityError::Capability(
                CapabilityError::PermissionDenied
            ))
        ));
        assert!(matches!(
            selected.write_blocks(0, &[0x65; 4096]),
            Err(VirtualBlockMutationError::Rejected(
                VirtualBlockCapabilityError::Capability(CapabilityError::PermissionDenied)
            ))
        ));
        assert_eq!(selected.flush(), Ok(()));
        assert_eq!(
            (
                flush_backend.reads,
                flush_backend.writes,
                flush_backend.flushes
            ),
            (0, 0, 1)
        );
    }

    #[test]
    fn capability_selected_backend_rejects_wrong_object_and_revoked_handle_before_io() {
        let object = ObjectId(0x300);
        let other = ObjectId(0x301);
        let mut output = [0xa5; 4096];

        let mut wrong_space = CapabilitySpace::<1>::new();
        let wrong_capability = wrong_space.insert(other, crate::Rights::READ).unwrap();
        let mut wrong_backend = MockBlock::new();
        let mut selected = CapabilitySelectedVirtualBlockBackend::new(
            &mut wrong_backend,
            &wrong_space,
            VirtualBlockBackendAuthority::new(wrong_capability, object, 0, 4).unwrap(),
            4096,
        );
        assert_eq!(
            selected.read_blocks(0, &mut output),
            Err(VirtualBlockCapabilityError::ObjectMismatch)
        );
        assert_eq!(wrong_backend.reads, 0);
        assert!(output.iter().all(|byte| *byte == 0xa5));

        let mut revoked_space = CapabilitySpace::<1>::new();
        let revoked_capability = revoked_space.insert(object, crate::Rights::READ).unwrap();
        revoked_space.revoke(revoked_capability).unwrap();
        let mut revoked_backend = MockBlock::new();
        let mut selected = CapabilitySelectedVirtualBlockBackend::new(
            &mut revoked_backend,
            &revoked_space,
            VirtualBlockBackendAuthority::new(revoked_capability, object, 0, 4).unwrap(),
            4096,
        );
        assert_eq!(
            selected.read_blocks(0, &mut output),
            Err(VirtualBlockCapabilityError::Capability(
                CapabilityError::Invalid
            ))
        );
        assert_eq!(revoked_backend.reads, 0);
        assert!(output.iter().all(|byte| *byte == 0xa5));
    }

    #[test]
    fn block_authority_rejects_empty_and_overflowing_backend_regions() {
        let mut capabilities = CapabilitySpace::<1>::new();
        let capability = capabilities
            .insert(ObjectId(0x300), crate::Rights::READ)
            .unwrap();
        assert_eq!(
            VirtualBlockBackendAuthority::new(capability, ObjectId(0x300), 0, 0),
            Err(VirtualBlockAuthorityError::InvalidRange)
        );
        assert_eq!(
            VirtualBlockBackendAuthority::new(capability, ObjectId(0x300), u64::MAX, 1),
            Err(VirtualBlockAuthorityError::InvalidRange)
        );
    }

    #[test]
    fn capability_selected_backend_translates_and_bounds_the_exposed_region() {
        let object = ObjectId(0x300);
        let mut capabilities = CapabilitySpace::<1>::new();
        let capability = capabilities
            .insert(object, crate::Rights::READ.union(crate::Rights::WRITE))
            .unwrap();
        let authority = VirtualBlockBackendAuthority::new(capability, object, 1, 2).unwrap();
        assert_eq!(authority.capability(), capability);
        assert_eq!(authority.object(), object);
        assert_eq!(authority.backend_first_block(), 1);
        assert_eq!(authority.exposed_block_count(), 2);

        let mut backend = MockBlock::new();
        backend.bytes[2 * 4096..3 * 4096].fill(0x5a);
        let mut selected = CapabilitySelectedVirtualBlockBackend::new(
            &mut backend,
            &capabilities,
            authority,
            4096,
        );
        assert_eq!(selected.write_blocks(0, &[0x65; 4096]), Ok(()));
        let mut output = [0; 4096];
        assert_eq!(selected.read_blocks(1, &mut output), Ok(()));
        assert!(output.iter().all(|byte| *byte == 0x5a));
        assert!(matches!(
            selected.read_blocks(2, &mut output),
            Err(VirtualBlockCapabilityError::InvalidRange)
        ));
        let mut oversized = [0xa5; 8192];
        assert!(matches!(
            selected.read_blocks(1, &mut oversized),
            Err(VirtualBlockCapabilityError::InvalidRange)
        ));
        assert!(matches!(
            selected.write_blocks(0, &[0x11; 4095]),
            Err(VirtualBlockMutationError::Rejected(
                VirtualBlockCapabilityError::InvalidRange
            ))
        ));
        assert_eq!((backend.reads, backend.writes), (1, 1));
        assert!(backend.bytes[..4096].iter().all(|byte| *byte == 0));
        assert!(backend.bytes[4096..8192].iter().all(|byte| *byte == 0x65));
        assert!(backend.bytes[8192..12288].iter().all(|byte| *byte == 0x5a));
        assert!(backend.bytes[12288..].iter().all(|byte| *byte == 0));
    }

    struct RecordingBlockPciRevoker {
        fail: bool,
        last: Option<VirtualBlockPciCleanupRecord>,
    }

    unsafe impl VirtualBlockPciResourceRevoker for RecordingBlockPciRevoker {
        type Error = MockError;

        fn revoke_block_resources(
            &mut self,
            record: VirtualBlockPciCleanupRecord,
        ) -> Result<(), Self::Error> {
            self.last = Some(record);
            if self.fail {
                Err(MockError::Injected)
            } else {
                Ok(())
            }
        }
    }

    struct RecordingBlockPciWindowBackend {
        map_result: Result<(), VirtualPciNativeResourceError>,
        unmap_result: Result<(), VirtualPciNativeResourceError>,
        maps: usize,
        unmaps: usize,
        last: Option<VirtualBlockPciCleanupRecord>,
    }

    unsafe impl VirtualBlockPciWindowBackend for RecordingBlockPciWindowBackend {
        fn map_block_window(
            &mut self,
            record: VirtualBlockPciCleanupRecord,
        ) -> Result<(), VirtualPciNativeResourceError> {
            self.maps += 1;
            self.last = Some(record);
            self.map_result
        }

        fn unmap_block_window(
            &mut self,
            record: VirtualBlockPciCleanupRecord,
        ) -> Result<(), VirtualPciNativeResourceError> {
            self.unmaps += 1;
            self.last = Some(record);
            self.unmap_result
        }
    }

    fn block_pci_function(class: u8) -> crate::VirtualPciType0Function {
        let identity =
            crate::VirtualPciIdentity::new(0x1234, 0x5678, 1, 0, 0x80, class, 0x1234, 0x5678)
                .unwrap();
        crate::VirtualPciType0Function::new(
            identity,
            crate::VirtualPciMemoryBar::new(4096).unwrap(),
        )
    }

    fn block_pci_function_with_subclass(subclass: u8) -> crate::VirtualPciType0Function {
        let identity =
            crate::VirtualPciIdentity::new(0x1234, 0x5678, 1, 0, subclass, 1, 0x1234, 0x5678)
                .unwrap();
        crate::VirtualPciType0Function::new(
            identity,
            crate::VirtualPciMemoryBar::new(4096).unwrap(),
        )
    }

    #[test]
    fn pci_block_attachment_binds_exact_generations_and_resets_after_cleanup() {
        let location = crate::VirtualPciLocation::new(0, 0, 4, 0).unwrap();
        let mut router = crate::VirtualPciConfigurationRouter::new();
        let pci_id = router.attach(location, block_pci_function(1)).unwrap();
        let description = router.describe_attachment(pci_id).unwrap();
        let mut device = active::<1>();
        let bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut capabilities = CapabilitySpace::<1>::new();
        let block_capability = capabilities
            .insert(
                ObjectId(0x300),
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let authority =
            VirtualBlockBackendAuthority::new(block_capability, ObjectId(0x300), 8, 64).unwrap();
        let mut attachment =
            VirtualBlockPciAttachment::new(description, &device, &bridge, authority).unwrap();
        assert_eq!(attachment.state(), VirtualBlockPciAttachmentState::Attached);
        assert_eq!(attachment.pci(), description.resources());
        assert_eq!(attachment.block_generation(), 1);
        assert_eq!(attachment.backend(), authority);

        device
            .admit(&encoded(VirtualBlockRequest::read(
                1, 1, 0, 1, 0x4000, 4096,
            )))
            .unwrap();
        router.write(location, 16, 4, 0x20_0000).unwrap();
        let mut resource_revoker = RecordingBlockPciRevoker {
            fail: false,
            last: None,
        };
        {
            let mut revoker = VirtualBlockPciFunctionRevoker::new(
                &mut attachment,
                &mut device,
                &mut resource_revoker,
                VirtualBlockPciCleanupMode::Reset,
            );
            assert_eq!(router.reset_with_revoker(pci_id, &mut revoker), Ok(2));
        }

        assert_eq!(attachment.state(), VirtualBlockPciAttachmentState::Reset);
        assert_eq!(attachment.invalidated_requests(), 1);
        assert_eq!(device.state(), VirtualBlockDeviceState::Created);
        assert_eq!(device.generation(), 2);
        let cleaned = resource_revoker.last.unwrap();
        assert_eq!(cleaned.pci().attachment(), pci_id);
        assert_eq!(cleaned.pci().location(), location);
        assert_eq!(cleaned.pci().function_generation(), 1);
        assert_eq!(cleaned.pci().mmio_window().unwrap().address(), 0x20_0000);
        assert_eq!(cleaned.block_generation(), 1);
        assert_eq!(cleaned.queue(), layout::<1>());
        assert_eq!(cleaned.interrupt_vector(), 48);
        assert_eq!(cleaned.backend(), authority);
        assert_eq!(
            router
                .describe_attachment(pci_id)
                .unwrap()
                .resources()
                .function_generation(),
            2
        );
    }

    #[test]
    fn pci_block_reset_with_pending_state_rejects_every_stale_successor_action() {
        let location = crate::VirtualPciLocation::new(0, 0, 4, 0).unwrap();
        let mut router = crate::VirtualPciConfigurationRouter::new();
        let pci_id = router.attach(location, block_pci_function(1)).unwrap();
        let mut device = active_mmio::<2>();
        let mut old_bridge = VirtualBlockQueueBridge::<2>::new(layout::<2>()).unwrap();
        let mut capabilities = CapabilitySpace::<1>::new();
        let capability = capabilities
            .insert(
                ObjectId(0x30a),
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let authority =
            VirtualBlockBackendAuthority::new(capability, ObjectId(0x30a), 0, 64).unwrap();
        let mut old_attachment = VirtualBlockPciAttachment::new(
            router.describe_attachment(pci_id).unwrap(),
            &device,
            &old_bridge,
            authority,
        )
        .unwrap();
        router.write(location, 16, 4, 0x20_0000).unwrap();
        let old_window = router
            .describe_attachment(pci_id)
            .unwrap()
            .resources()
            .mmio_window()
            .unwrap();
        let mut window_backend = RecordingBlockPciWindowBackend {
            map_result: Ok(()),
            unmap_result: Ok(()),
            maps: 0,
            unmaps: 0,
            last: None,
        };
        {
            let mut mapper =
                VirtualBlockPciMemoryMapper::new(&mut old_attachment, &device, &mut window_backend);
            router
                .write_with_mapper(
                    location,
                    4,
                    2,
                    crate::PCI_COMMAND_MEMORY_SPACE as u32,
                    &mut mapper,
                )
                .unwrap();
        }

        let completed_request = VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096);
        let pending_request = VirtualBlockRequest::read(1, 2, 1, 1, 0x5000, 4096);
        let completed = device.admit(&encoded(completed_request)).unwrap();
        let pending = device.admit(&encoded(pending_request)).unwrap();
        let stale_completion = device
            .complete(completed.ticket(), VirtualBlockCompletionStatus::Ok, 4096)
            .unwrap();
        let mut old_memory = MockVmm::new();
        old_bridge
            .publish_completion(&mut old_memory, stale_completion)
            .unwrap();
        device.latch_completion_interrupt().unwrap();

        let mut resource_revoker = RecordingBlockPciRevoker {
            fail: false,
            last: None,
        };
        {
            let mut revoker = VirtualBlockPciFunctionRevoker::new(
                &mut old_attachment,
                &mut device,
                &mut resource_revoker,
                VirtualBlockPciCleanupMode::Reset,
            );
            assert_eq!(router.reset_with_revoker(pci_id, &mut revoker), Ok(2));
        }
        assert_eq!(old_attachment.invalidated_requests(), 1);
        assert_eq!(
            old_attachment.state(),
            VirtualBlockPciAttachmentState::Reset
        );
        assert_eq!(device.pending_interrupt_vector(), None);

        device.negotiate(VIRTUAL_BLOCK_FEATURE_FLUSH).unwrap();
        device.activate(layout::<2>(), 48).unwrap();
        let successor_bridge = VirtualBlockQueueBridge::<2>::new(layout::<2>()).unwrap();
        let successor_attachment = VirtualBlockPciAttachment::new(
            router.describe_attachment(pci_id).unwrap(),
            &device,
            &successor_bridge,
            authority,
        )
        .unwrap();
        assert_eq!(successor_attachment.block_generation(), 2);
        assert_eq!(successor_attachment.pci().function_generation(), 2);

        let stale_ack = ExitDisposition::Mmio {
            guest_address: u64::from(old_window.address())
                + u64::from(VIRTUAL_BLOCK_MMIO_COMPLETION_ACK_OFFSET),
            size: 4,
            write: true,
            value: u64::from(VIRTUAL_BLOCK_COMPLETION_ACK_VALUE),
        };
        assert_eq!(
            process_virtual_block_mmio_completion_ack(
                stale_ack,
                &old_attachment,
                &mut device,
                &mut old_bridge,
                &mut old_memory,
            ),
            Err(VirtualBlockCompletionAckError::InvalidExit)
        );
        assert_eq!(device.state(), VirtualBlockDeviceState::Active);
        assert!(!successor_bridge.is_poisoned());
        assert_eq!(
            device.complete(pending.ticket(), VirtualBlockCompletionStatus::Ok, 4096),
            Err(VirtualBlockError::StaleTicket)
        );
        assert_eq!(
            device.admit(&encoded(pending_request)),
            Err(VirtualBlockError::StaleGeneration)
        );
        assert!(
            device
                .admit(&encoded(VirtualBlockRequest::read(
                    2, 3, 0, 1, 0x6000, 4096,
                )))
                .is_ok()
        );
    }

    #[test]
    fn pci_block_detach_removes_device_only_after_exact_resource_cleanup() {
        let location = crate::VirtualPciLocation::new(0, 0, 5, 0).unwrap();
        let mut router = crate::VirtualPciConfigurationRouter::new();
        let pci_id = router.attach(location, block_pci_function(1)).unwrap();
        let mut device = active::<1>();
        let bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut capabilities = CapabilitySpace::<1>::new();
        let capability = capabilities
            .insert(ObjectId(0x301), crate::Rights::READ)
            .unwrap();
        let authority =
            VirtualBlockBackendAuthority::new(capability, ObjectId(0x301), 0, 64).unwrap();
        let mut attachment = VirtualBlockPciAttachment::new(
            router.describe_attachment(pci_id).unwrap(),
            &device,
            &bridge,
            authority,
        )
        .unwrap();
        let mut resource_revoker = RecordingBlockPciRevoker {
            fail: false,
            last: None,
        };
        {
            let mut revoker = VirtualBlockPciFunctionRevoker::new(
                &mut attachment,
                &mut device,
                &mut resource_revoker,
                VirtualBlockPciCleanupMode::Remove,
            );
            let detached = router.detach_with_revoker(pci_id, &mut revoker).unwrap();
            assert_eq!(detached.identity().class(), 1);
        }
        assert_eq!(attachment.state(), VirtualBlockPciAttachmentState::Removed);
        assert_eq!(device.state(), VirtualBlockDeviceState::Removed);
        assert_eq!(device.generation(), 2);
        assert_eq!(
            router.describe_attachment(pci_id),
            Err(crate::VirtualPciError::StaleAttachment)
        );
        assert_eq!(resource_revoker.last.unwrap().backend(), authority);
    }

    #[test]
    fn pci_block_cleanup_failure_and_stale_state_preserve_pci_configuration() {
        let location = crate::VirtualPciLocation::new(0, 0, 6, 0).unwrap();
        let mut router = crate::VirtualPciConfigurationRouter::new();
        let pci_id = router.attach(location, block_pci_function(1)).unwrap();
        let mut device = active::<1>();
        let bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut capabilities = CapabilitySpace::<1>::new();
        let capability = capabilities
            .insert(ObjectId(0x302), crate::Rights::READ)
            .unwrap();
        let authority =
            VirtualBlockBackendAuthority::new(capability, ObjectId(0x302), 0, 64).unwrap();
        let description = router.describe_attachment(pci_id).unwrap();
        let mut attachment =
            VirtualBlockPciAttachment::new(description, &device, &bridge, authority).unwrap();
        let mut resource_revoker = RecordingBlockPciRevoker {
            fail: true,
            last: None,
        };
        {
            let mut revoker = VirtualBlockPciFunctionRevoker::new(
                &mut attachment,
                &mut device,
                &mut resource_revoker,
                VirtualBlockPciCleanupMode::Reset,
            );
            assert_eq!(
                router.reset_with_revoker(pci_id, &mut revoker),
                Err(crate::VirtualPciResetError::Revocation(
                    VirtualBlockPciCleanupError::Resource(MockError::Injected)
                ))
            );
        }
        assert_eq!(attachment.state(), VirtualBlockPciAttachmentState::Attached);
        assert_eq!(device.state(), VirtualBlockDeviceState::Active);
        assert_eq!(device.generation(), 1);
        assert_eq!(router.describe_attachment(pci_id), Ok(description));

        device.reset().unwrap();
        resource_revoker.fail = false;
        let mut revoker = VirtualBlockPciFunctionRevoker::new(
            &mut attachment,
            &mut device,
            &mut resource_revoker,
            VirtualBlockPciCleanupMode::Reset,
        );
        assert_eq!(
            router.reset_with_revoker(pci_id, &mut revoker),
            Err(crate::VirtualPciResetError::Revocation(
                VirtualBlockPciCleanupError::Attachment(VirtualBlockPciError::StaleBlockGeneration)
            ))
        );
        assert_eq!(router.describe_attachment(pci_id), Ok(description));
    }

    #[test]
    fn pci_block_attachment_rejects_identity_state_and_geometry_substitution() {
        let location = crate::VirtualPciLocation::new(0, 0, 7, 0).unwrap();
        let mut router = crate::VirtualPciConfigurationRouter::new();
        let non_block_id = router.attach(location, block_pci_function(2)).unwrap();
        let device = active::<1>();
        let mut poisoned_bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        poisoned_bridge.fail_stop();
        let clean_bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut capabilities = CapabilitySpace::<1>::new();
        let capability = capabilities
            .insert(ObjectId(0x303), crate::Rights::READ)
            .unwrap();
        let exact = VirtualBlockBackendAuthority::new(capability, ObjectId(0x303), 0, 64).unwrap();
        assert_eq!(
            VirtualBlockPciAttachment::new(
                router.describe_attachment(non_block_id).unwrap(),
                &device,
                &clean_bridge,
                exact,
            )
            .map(|_| ()),
            Err(VirtualBlockPciError::InvalidPciClass)
        );
        let mut subclass_router = crate::VirtualPciConfigurationRouter::new();
        let subclass_id = subclass_router
            .attach(location, block_pci_function_with_subclass(0x01))
            .unwrap();
        assert_eq!(
            VirtualBlockPciAttachment::new(
                subclass_router.describe_attachment(subclass_id).unwrap(),
                &device,
                &clean_bridge,
                exact,
            )
            .map(|_| ()),
            Err(VirtualBlockPciError::InvalidPciClass)
        );

        let mut block_router = crate::VirtualPciConfigurationRouter::new();
        let block_id = block_router
            .attach(location, block_pci_function(1))
            .unwrap();
        let description = block_router.describe_attachment(block_id).unwrap();
        assert_eq!(
            VirtualBlockPciAttachment::new(description, &device, &poisoned_bridge, exact)
                .map(|_| ()),
            Err(VirtualBlockPciError::InvalidState)
        );
        let narrow = VirtualBlockBackendAuthority::new(capability, ObjectId(0x303), 0, 63).unwrap();
        assert_eq!(
            VirtualBlockPciAttachment::new(description, &device, &clean_bridge, narrow).map(|_| ()),
            Err(VirtualBlockPciError::GeometryMismatch)
        );
    }

    #[test]
    fn pci_block_bar_mapping_tracks_only_the_exact_attachment_window() {
        let location = crate::VirtualPciLocation::new(0, 0, 4, 0).unwrap();
        let mut router = crate::VirtualPciConfigurationRouter::new();
        let pci_id = router.attach(location, block_pci_function(1)).unwrap();
        let mut device = active::<1>();
        let bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut capabilities = CapabilitySpace::<1>::new();
        let capability = capabilities
            .insert(ObjectId(0x304), crate::Rights::READ)
            .unwrap();
        let authority =
            VirtualBlockBackendAuthority::new(capability, ObjectId(0x304), 8, 64).unwrap();
        let mut attachment = VirtualBlockPciAttachment::new(
            router.describe_attachment(pci_id).unwrap(),
            &device,
            &bridge,
            authority,
        )
        .unwrap();
        router.write(location, 16, 4, 0x20_0000).unwrap();
        let expected_window = router
            .describe_attachment(pci_id)
            .unwrap()
            .resources()
            .mmio_window()
            .unwrap();
        let mut backend = RecordingBlockPciWindowBackend {
            map_result: Ok(()),
            unmap_result: Ok(()),
            maps: 0,
            unmaps: 0,
            last: None,
        };

        {
            let mut mapper =
                VirtualBlockPciMemoryMapper::new(&mut attachment, &device, &mut backend);
            router
                .write_with_mapper(
                    location,
                    4,
                    2,
                    crate::PCI_COMMAND_MEMORY_SPACE as u32,
                    &mut mapper,
                )
                .unwrap();
        }
        assert_eq!(attachment.mapped_window(), Some(expected_window));
        assert_eq!(backend.maps, 1);
        let mapped = backend.last.unwrap();
        assert_eq!(mapped.pci().attachment(), pci_id);
        assert_eq!(mapped.pci().mmio_window(), Some(expected_window));
        assert_eq!(mapped.mapped_window(), None);
        assert_eq!(mapped.backend(), authority);

        {
            let mut mapper =
                VirtualBlockPciMemoryMapper::new(&mut attachment, &device, &mut backend);
            router
                .write_with_mapper(location, 4, 2, 0, &mut mapper)
                .unwrap();
        }
        assert_eq!(attachment.mapped_window(), None);
        assert_eq!(backend.unmaps, 1);
        let unmapped = backend.last.unwrap();
        assert_eq!(unmapped.pci().mmio_window(), Some(expected_window));
        assert_eq!(unmapped.mapped_window(), Some(expected_window));

        {
            let mut mapper =
                VirtualBlockPciMemoryMapper::new(&mut attachment, &device, &mut backend);
            router
                .write_with_mapper(
                    location,
                    4,
                    2,
                    crate::PCI_COMMAND_MEMORY_SPACE as u32,
                    &mut mapper,
                )
                .unwrap();
        }
        let mut resources = RecordingBlockPciRevoker {
            fail: false,
            last: None,
        };
        {
            let mut revoker = VirtualBlockPciFunctionRevoker::new(
                &mut attachment,
                &mut device,
                &mut resources,
                VirtualBlockPciCleanupMode::Reset,
            );
            assert_eq!(router.reset_with_revoker(pci_id, &mut revoker), Ok(2));
        }
        assert_eq!(
            resources.last.unwrap().mapped_window(),
            Some(expected_window)
        );
    }

    #[test]
    fn pci_mmio_doorbell_requires_exact_live_mapping_and_tuple() {
        let location = crate::VirtualPciLocation::new(0, 0, 4, 0).unwrap();
        let mut router = crate::VirtualPciConfigurationRouter::new();
        let pci_id = router.attach(location, block_pci_function(1)).unwrap();
        let mut device = active_mmio::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut capabilities = CapabilitySpace::<1>::new();
        let capability = capabilities
            .insert(
                ObjectId(0x30a),
                crate::Rights::READ.union(crate::Rights::WRITE),
            )
            .unwrap();
        let authority =
            VirtualBlockBackendAuthority::new(capability, ObjectId(0x30a), 0, 64).unwrap();
        let mut attachment = VirtualBlockPciAttachment::new(
            router.describe_attachment(pci_id).unwrap(),
            &device,
            &bridge,
            authority,
        )
        .unwrap();
        router.write(location, 16, 4, 0x20_0000).unwrap();
        let mut window_backend = RecordingBlockPciWindowBackend {
            map_result: Ok(()),
            unmap_result: Ok(()),
            maps: 0,
            unmaps: 0,
            last: None,
        };
        {
            let mut mapper =
                VirtualBlockPciMemoryMapper::new(&mut attachment, &device, &mut window_backend);
            router
                .write_with_mapper(
                    location,
                    4,
                    2,
                    crate::PCI_COMMAND_MEMORY_SPACE as u32,
                    &mut mapper,
                )
                .unwrap();
        }
        router
            .write(
                location,
                4,
                2,
                u32::from(PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_INTERRUPT_DISABLE),
            )
            .unwrap();
        let masked = router.describe_attachment(pci_id).unwrap().resources();
        assert_eq!(
            attachment.validate_interrupt_state(masked, &device, &bridge),
            Ok(VirtualBlockPciInterruptState::Masked)
        );
        router
            .write(location, 4, 2, u32::from(PCI_COMMAND_MEMORY_SPACE))
            .unwrap();
        let unmasked = router.describe_attachment(pci_id).unwrap().resources();
        assert_eq!(
            attachment.validate_interrupt_state(unmasked, &device, &bridge),
            Ok(VirtualBlockPciInterruptState::Enabled)
        );

        let exact = ExitDisposition::Mmio {
            guest_address: 0x20_0000,
            size: 4,
            write: true,
            value: u64::from(VIRTUAL_BLOCK_DOORBELL_VALUE),
        };
        let mut memory = MockVmm::new();
        let mut block = MockBlock::new();
        let mut scratch = [0; 4096];
        assert_eq!(
            process_virtual_block_mmio_doorbell(
                exact,
                &attachment,
                &mut device,
                &mut bridge,
                &mut memory,
                &mut block,
                &mut scratch,
            ),
            Ok(VirtualBlockProcessOutcome::Idle)
        );

        for hostile in [
            ExitDisposition::Mmio {
                guest_address: 0x20_0004,
                size: 4,
                write: true,
                value: 1,
            },
            ExitDisposition::Mmio {
                guest_address: 0x20_0000,
                size: 2,
                write: true,
                value: 1,
            },
            ExitDisposition::Mmio {
                guest_address: 0x20_0000,
                size: 4,
                write: true,
                value: 2,
            },
            ExitDisposition::Mmio {
                guest_address: 0x20_0000,
                size: 4,
                write: false,
                value: 1,
            },
        ] {
            assert_eq!(
                process_virtual_block_mmio_doorbell(
                    hostile,
                    &attachment,
                    &mut device,
                    &mut bridge,
                    &mut memory,
                    &mut block,
                    &mut scratch,
                ),
                Err(VirtualBlockDoorbellError::InvalidExit)
            );
        }

        {
            let mut mapper =
                VirtualBlockPciMemoryMapper::new(&mut attachment, &device, &mut window_backend);
            router
                .write_with_mapper(location, 4, 2, 0, &mut mapper)
                .unwrap();
        }
        assert_eq!(
            process_virtual_block_mmio_doorbell(
                exact,
                &attachment,
                &mut device,
                &mut bridge,
                &mut memory,
                &mut block,
                &mut scratch,
            ),
            Err(VirtualBlockDoorbellError::InvalidExit)
        );
        assert_eq!((block.reads, block.writes, block.flushes), (0, 0, 0));
    }

    #[test]
    fn pci_block_bar_mapping_failures_preserve_configuration_and_attachment_state() {
        for error in [
            VirtualPciNativeResourceError::Rejected,
            VirtualPciNativeResourceError::Uncertain,
        ] {
            let location = crate::VirtualPciLocation::new(0, 0, 4, 0).unwrap();
            let mut router = crate::VirtualPciConfigurationRouter::new();
            let pci_id = router.attach(location, block_pci_function(1)).unwrap();
            let device = active::<1>();
            let bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
            let mut capabilities = CapabilitySpace::<1>::new();
            let capability = capabilities
                .insert(ObjectId(0x305), crate::Rights::READ)
                .unwrap();
            let authority =
                VirtualBlockBackendAuthority::new(capability, ObjectId(0x305), 0, 64).unwrap();
            let mut attachment = VirtualBlockPciAttachment::new(
                router.describe_attachment(pci_id).unwrap(),
                &device,
                &bridge,
                authority,
            )
            .unwrap();
            router.write(location, 16, 4, 0x20_0000).unwrap();
            let before = router.read(location, 4, 2).unwrap();
            let mut backend = RecordingBlockPciWindowBackend {
                map_result: Err(error),
                unmap_result: Ok(()),
                maps: 0,
                unmaps: 0,
                last: None,
            };
            let result = {
                let mut mapper =
                    VirtualBlockPciMemoryMapper::new(&mut attachment, &device, &mut backend);
                router.write_with_mapper(
                    location,
                    4,
                    2,
                    crate::PCI_COMMAND_MEMORY_SPACE as u32,
                    &mut mapper,
                )
            };
            let expected = match error {
                VirtualPciNativeResourceError::Rejected => {
                    crate::VirtualPciError::NativeResourceRejected
                }
                VirtualPciNativeResourceError::Uncertain => {
                    crate::VirtualPciError::NativeResourceUncertain
                }
            };
            assert_eq!(result, Err(expected));
            assert_eq!(router.read(location, 4, 2), Ok(before));
            assert_eq!(attachment.mapped_window(), None);
            assert_eq!(backend.maps, 1);
        }
    }

    #[test]
    fn pci_block_bar_unmap_failure_preserves_decode_and_mapping_state() {
        let location = crate::VirtualPciLocation::new(0, 0, 4, 0).unwrap();
        let mut router = crate::VirtualPciConfigurationRouter::new();
        let pci_id = router.attach(location, block_pci_function(1)).unwrap();
        let device = active::<1>();
        let bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut capabilities = CapabilitySpace::<1>::new();
        let capability = capabilities
            .insert(ObjectId(0x306), crate::Rights::READ)
            .unwrap();
        let authority =
            VirtualBlockBackendAuthority::new(capability, ObjectId(0x306), 0, 64).unwrap();
        let mut attachment = VirtualBlockPciAttachment::new(
            router.describe_attachment(pci_id).unwrap(),
            &device,
            &bridge,
            authority,
        )
        .unwrap();
        router.write(location, 16, 4, 0x20_0000).unwrap();
        let mut backend = RecordingBlockPciWindowBackend {
            map_result: Ok(()),
            unmap_result: Err(VirtualPciNativeResourceError::Uncertain),
            maps: 0,
            unmaps: 0,
            last: None,
        };
        {
            let mut mapper =
                VirtualBlockPciMemoryMapper::new(&mut attachment, &device, &mut backend);
            router
                .write_with_mapper(
                    location,
                    4,
                    2,
                    crate::PCI_COMMAND_MEMORY_SPACE as u32,
                    &mut mapper,
                )
                .unwrap();
        }
        let mapped = attachment.mapped_window();
        let command = router.read(location, 4, 2).unwrap();
        let result = {
            let mut mapper =
                VirtualBlockPciMemoryMapper::new(&mut attachment, &device, &mut backend);
            router.write_with_mapper(location, 4, 2, 0, &mut mapper)
        };
        assert_eq!(result, Err(crate::VirtualPciError::NativeResourceUncertain));
        assert_eq!(router.read(location, 4, 2), Ok(command));
        assert_eq!(attachment.mapped_window(), mapped);
        assert_eq!(backend.unmaps, 1);
    }

    #[test]
    fn executor_copies_reads_and_writes_privately_and_flushes() {
        let mut device = active::<2>();
        let mut bridge = VirtualBlockQueueBridge::<2>::new(layout::<2>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        backend.bytes[4096..8192].fill(0x5a);

        let read = device
            .admit(&encoded(VirtualBlockRequest::read(
                1, 1, 1, 1, 0x4000, 4096,
            )))
            .unwrap();
        let outcome = execute_virtual_block_request(
            &mut device,
            &mut bridge,
            &mut vmm,
            &mut backend,
            read,
            &mut scratch,
        )
        .unwrap();
        assert!(matches!(
            outcome,
            VirtualBlockExecutionOutcome::Completed(_)
        ));
        assert!(vmm.bytes[0x4000..0x5000].iter().all(|byte| *byte == 0x5a));
        assert!(scratch.iter().all(|byte| *byte == 0));

        vmm.bytes[0x4000..0x5000].fill(0x3c);
        let write = device
            .admit(&encoded(VirtualBlockRequest::write(
                1, 2, 2, 1, 0x4000, 4096,
            )))
            .unwrap();
        execute_virtual_block_request(
            &mut device,
            &mut bridge,
            &mut vmm,
            &mut backend,
            write,
            &mut scratch,
        )
        .unwrap();
        assert!(backend.bytes[8192..12_288].iter().all(|byte| *byte == 0x3c));
        assert!(scratch.iter().all(|byte| *byte == 0));
        assert_eq!(
            execute_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                write,
                &mut scratch,
            ),
            Err(VirtualBlockExecutionError::Protocol(
                VirtualBlockError::StaleTicket
            ))
        );
        assert_eq!(backend.writes, 1);

        let flush = device
            .admit(&encoded(VirtualBlockRequest::flush(1, 3)))
            .unwrap();
        execute_virtual_block_request(
            &mut device,
            &mut bridge,
            &mut vmm,
            &mut backend,
            flush,
            &mut scratch,
        )
        .unwrap();
        assert_eq!((backend.reads, backend.writes, backend.flushes), (1, 1, 1));
        assert_eq!(device.state(), VirtualBlockDeviceState::Active);
    }

    #[test]
    fn executor_distinguishes_clean_rejection_from_uncertain_mutation() {
        let mut device = active::<2>();
        let mut bridge = VirtualBlockQueueBridge::<2>::new(layout::<2>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        vmm.bytes[0x4000..0x5000].fill(0x7b);

        backend.mutation = MockMutation::Reject;
        let rejected = device
            .admit(&encoded(VirtualBlockRequest::write(
                1, 1, 0, 1, 0x4000, 4096,
            )))
            .unwrap();
        assert_eq!(
            execute_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                rejected,
                &mut scratch,
            ),
            Ok(VirtualBlockExecutionOutcome::BackendRejected {
                completion: VirtualBlockCompletion {
                    generation: 1,
                    request_id: 1,
                    status: VirtualBlockCompletionStatus::DeviceError,
                    transferred: 0,
                },
                error: MockError::Injected,
            })
        );
        assert_eq!(device.state(), VirtualBlockDeviceState::Active);
        assert!(!bridge.is_poisoned());

        backend.mutation = MockMutation::Uncertain;
        let uncertain = device
            .admit(&encoded(VirtualBlockRequest::write(
                1, 2, 1, 1, 0x4000, 4096,
            )))
            .unwrap();
        assert_eq!(
            execute_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                uncertain,
                &mut scratch,
            ),
            Err(VirtualBlockExecutionError::BackendUncertain {
                error: MockError::Injected,
                invalidated: Ok(1),
            })
        );
        assert_eq!(device.state(), VirtualBlockDeviceState::Failed);
        assert!(bridge.is_poisoned());
        assert!(scratch.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn executor_guest_memory_uncertainty_precedes_backend_mutation() {
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        let admitted = device
            .admit(&encoded(VirtualBlockRequest::write(
                1, 1, 0, 1, 0x4000, 4096,
            )))
            .unwrap();
        vmm.fail_read = true;
        assert_eq!(
            execute_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                admitted,
                &mut scratch,
            ),
            Err(VirtualBlockExecutionError::GuestMemory {
                error: VirtualBlockQueueError::Backend(MockError::Injected),
                invalidated: Ok(1),
            })
        );
        assert_eq!(backend.writes, 0);
        assert_eq!(device.state(), VirtualBlockDeviceState::Failed);
        assert!(bridge.is_poisoned());
        assert!(scratch.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn executor_rejects_wrong_queue_and_scratch_before_backend_access() {
        let mut device = active::<1>();
        let wrong_layout = VirtualBlockQueueLayout::new(0x5000, 0x7000, 1).unwrap();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(wrong_layout).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let admitted = device
            .admit(&encoded(VirtualBlockRequest::read(
                1, 1, 0, 1, 0x4000, 4096,
            )))
            .unwrap();
        let mut scratch = [0xa5; 4096];
        assert_eq!(
            execute_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                admitted,
                &mut scratch,
            ),
            Err(VirtualBlockExecutionError::Protocol(
                VirtualBlockError::InvalidQueue
            ))
        );
        assert!(scratch.iter().all(|byte| *byte == 0));
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));

        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut short_scratch = [0xa5; 4095];
        assert_eq!(
            execute_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                admitted,
                &mut short_scratch,
            ),
            Err(VirtualBlockExecutionError::Protocol(
                VirtualBlockError::InvalidBuffer
            ))
        );
        assert!(short_scratch.iter().all(|byte| *byte == 0));
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));
    }

    #[test]
    fn processor_completes_one_exact_queue_transaction_then_idles() {
        let mut device = active::<2>();
        let mut bridge = VirtualBlockQueueBridge::<2>::new(layout::<2>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        let request = encoded(VirtualBlockRequest::write(1, 1, 2, 1, 0x4000, 4096));
        vmm.bytes[0x4000..0x5000].fill(0x6d);
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();

        let outcome = process_virtual_block_request(
            &mut device,
            &mut bridge,
            &mut vmm,
            &mut backend,
            &mut scratch,
        )
        .unwrap();
        assert!(matches!(
            outcome,
            VirtualBlockProcessOutcome::Completed(VirtualBlockExecutionOutcome::Completed(_))
        ));
        assert!(backend.bytes[8192..12_288].iter().all(|byte| *byte == 0x6d));
        assert!(scratch.iter().all(|byte| *byte == 0));
        let mut counter = [0; 8];
        vmm.read_guest(0x1040, &mut counter).unwrap();
        assert_eq!(u64::from_le_bytes(counter), 1);
        vmm.read_guest(0x3000, &mut counter).unwrap();
        assert_eq!(u64::from_le_bytes(counter), 1);
        let mut completion = [0; VIRTUAL_BLOCK_COMPLETION_BYTES];
        vmm.read_guest(0x3000 + QUEUE_HEADER_BYTES, &mut completion)
            .unwrap();
        assert_eq!(
            VirtualBlockCompletion::decode(&completion)
                .map(|completion| (completion.request_id(), completion.transferred())),
            Ok((1, 4096))
        );
        assert_eq!(
            process_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                &mut scratch,
            ),
            Ok(VirtualBlockProcessOutcome::Idle)
        );
        assert_eq!(backend.writes, 1);
        assert_eq!(device.pending_interrupt_vector(), Some(48));
        assert_eq!(device.suspend(), Err(VirtualBlockError::InvalidState));
        assert_eq!(
            device.acknowledge_interrupt(49),
            Err(VirtualBlockError::InvalidInterrupt)
        );
        assert_eq!(device.pending_interrupt_vector(), Some(48));
        device.acknowledge_interrupt(48).unwrap();
        assert_eq!(device.pending_interrupt_vector(), None);
    }

    #[test]
    fn processor_backpressure_precedes_request_consumption() {
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        bridge.completion_published = 1;
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        let request = encoded(VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096));
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();

        assert_eq!(
            process_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                &mut scratch,
            ),
            Ok(VirtualBlockProcessOutcome::Backpressured)
        );
        let mut consumed = [0; 8];
        vmm.read_guest(0x1040, &mut consumed).unwrap();
        assert_eq!(u64::from_le_bytes(consumed), 0);
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));
        assert_eq!(device.state(), VirtualBlockDeviceState::Active);
        assert!(!bridge.is_poisoned());
    }

    #[test]
    fn processor_consumes_malformed_request_without_backend_access() {
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        let mut request = encoded(VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096));
        request[63] = 1;
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();

        assert_eq!(
            process_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                &mut scratch,
            ),
            Ok(VirtualBlockProcessOutcome::Rejected(
                VirtualBlockError::MalformedRequest
            ))
        );
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));
        assert_eq!(device.state(), VirtualBlockDeviceState::Active);
        assert!(!bridge.is_poisoned());
        let mut consumed = [0; 8];
        vmm.read_guest(0x1040, &mut consumed).unwrap();
        assert_eq!(u64::from_le_bytes(consumed), 1);
    }

    #[test]
    fn processor_completion_uncertainty_fails_after_one_mutation() {
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        let request = encoded(VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096));
        vmm.bytes[0x4000..0x5000].fill(0x4e);
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();
        vmm.fail_write_address = Some(0x3000 + QUEUE_HEADER_BYTES);

        assert_eq!(
            process_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                &mut scratch,
            ),
            Err(VirtualBlockProcessError::Queue {
                error: VirtualBlockQueueError::Backend(MockError::Injected),
                invalidated: Ok(0),
            })
        );
        assert_eq!(backend.writes, 1);
        assert!(backend.bytes[..4096].iter().all(|byte| *byte == 0x4e));
        assert_eq!(device.state(), VirtualBlockDeviceState::Failed);
        assert!(bridge.is_poisoned());
        assert!(scratch.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn processor_insufficient_scratch_fails_after_admission_before_backend() {
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4095];
        let request = encoded(VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096));
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();

        assert_eq!(
            process_virtual_block_request(
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                &mut scratch,
            ),
            Err(VirtualBlockProcessError::Execution(
                VirtualBlockExecutionError::Protocol(VirtualBlockError::InvalidBuffer)
            ))
        );
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));
        assert_eq!(device.state(), VirtualBlockDeviceState::Failed);
        assert!(bridge.is_poisoned());
        assert!(scratch.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn doorbell_rejects_every_scalar_mismatch_before_queue_or_backend_access() {
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        let request = encoded(VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096));
        vmm.bytes[0x4000..0x5000].fill(0x73);
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();

        let invalid = [
            ExitDisposition::Io {
                port: VIRTUAL_BLOCK_DOORBELL_PORT + 1,
                size: 4,
                write: true,
                value: VIRTUAL_BLOCK_DOORBELL_VALUE,
            },
            ExitDisposition::Io {
                port: VIRTUAL_BLOCK_DOORBELL_PORT,
                size: 2,
                write: true,
                value: VIRTUAL_BLOCK_DOORBELL_VALUE,
            },
            ExitDisposition::Io {
                port: VIRTUAL_BLOCK_DOORBELL_PORT,
                size: 4,
                write: false,
                value: VIRTUAL_BLOCK_DOORBELL_VALUE,
            },
            ExitDisposition::Io {
                port: VIRTUAL_BLOCK_DOORBELL_PORT,
                size: 4,
                write: true,
                value: VIRTUAL_BLOCK_DOORBELL_VALUE + 1,
            },
            ExitDisposition::Resume,
        ];
        for disposition in invalid {
            assert_eq!(
                process_virtual_block_doorbell(
                    disposition,
                    &mut device,
                    &mut bridge,
                    &mut vmm,
                    &mut backend,
                    &mut scratch,
                ),
                Err(VirtualBlockDoorbellError::InvalidExit)
            );
        }
        let mut consumed = [0; 8];
        vmm.read_guest(0x1040, &mut consumed).unwrap();
        assert_eq!(u64::from_le_bytes(consumed), 0);
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));
        assert!(scratch.iter().all(|byte| *byte == 0xa5));
        assert_eq!(device.pending_interrupt_vector(), None);
    }

    #[test]
    fn exact_doorbell_processes_at_most_one_request_and_latches_notification() {
        let mut device = active::<2>();
        let mut bridge = VirtualBlockQueueBridge::<2>::new(layout::<2>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        for (slot, request_id) in [1u64, 2].into_iter().enumerate() {
            let request = encoded(VirtualBlockRequest::write(
                1,
                request_id,
                request_id - 1,
                1,
                0x4000,
                4096,
            ));
            vmm.write_guest(
                0x1000 + QUEUE_HEADER_BYTES + (slot * VIRTUAL_BLOCK_REQUEST_BYTES) as u64,
                &request,
            )
            .unwrap();
        }
        vmm.bytes[0x4000..0x5000].fill(0x41);
        vmm.write_guest(0x1000, &2u64.to_le_bytes()).unwrap();
        let doorbell = ExitDisposition::Io {
            port: VIRTUAL_BLOCK_DOORBELL_PORT,
            size: 4,
            write: true,
            value: VIRTUAL_BLOCK_DOORBELL_VALUE,
        };

        assert!(matches!(
            process_virtual_block_doorbell(
                doorbell,
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                &mut scratch,
            ),
            Ok(VirtualBlockProcessOutcome::Completed(_))
        ));
        assert_eq!(backend.writes, 1);
        assert_eq!(device.pending_interrupt_vector(), Some(48));
        let mut consumed = [0; 8];
        vmm.read_guest(0x1040, &mut consumed).unwrap();
        assert_eq!(u64::from_le_bytes(consumed), 1);

        assert!(matches!(
            process_virtual_block_doorbell(
                doorbell,
                &mut device,
                &mut bridge,
                &mut vmm,
                &mut backend,
                &mut scratch,
            ),
            Ok(VirtualBlockProcessOutcome::Completed(_))
        ));
        assert_eq!(backend.writes, 2);
        vmm.read_guest(0x1040, &mut consumed).unwrap();
        assert_eq!(u64::from_le_bytes(consumed), 2);
    }

    fn runner_vm() -> (VmTable<1>, VmId) {
        let mut vms = VmTable::new();
        let vm = vms.create(8).unwrap();
        vms.mark_loaded(vm).unwrap();
        vms.start(vm).unwrap();
        (vms, vm)
    }

    fn block_io_policy() -> IoPortPolicy<1> {
        let mut policy = IoPortPolicy::deny_all();
        policy
            .allow(
                crate::IoPortRule::new(VIRTUAL_BLOCK_DOORBELL_PORT, 4, crate::IoDirection::Write)
                    .unwrap(),
            )
            .unwrap();
        policy
    }

    fn block_ack_io_policy() -> IoPortPolicy<1> {
        let mut policy = IoPortPolicy::deny_all();
        policy
            .allow(
                crate::IoPortRule::new(
                    VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
                    4,
                    crate::IoDirection::Write,
                )
                .unwrap(),
            )
            .unwrap();
        policy
    }

    fn block_transaction_io_policy() -> IoPortPolicy<2> {
        let mut policy = IoPortPolicy::deny_all();
        for port in [
            VIRTUAL_BLOCK_DOORBELL_PORT,
            VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
        ] {
            policy
                .allow(crate::IoPortRule::new(port, 4, crate::IoDirection::Write).unwrap())
                .unwrap();
        }
        policy
    }

    fn mapped_mmio_attachment(
        device: &VirtualBlockDevice<1>,
        bridge: &VirtualBlockQueueBridge<1>,
        authority: VirtualBlockBackendAuthority,
    ) -> (VirtualBlockPciAttachment, VirtualPciConfigurationRouter) {
        let location = crate::VirtualPciLocation::new(0, 0, 4, 0).unwrap();
        let mut router = crate::VirtualPciConfigurationRouter::new();
        let pci_id = router.attach(location, block_pci_function(1)).unwrap();
        let mut attachment = VirtualBlockPciAttachment::new(
            router.describe_attachment(pci_id).unwrap(),
            device,
            bridge,
            authority,
        )
        .unwrap();
        router.write(location, 16, 4, 0x20_0000).unwrap();
        let mut backend = RecordingBlockPciWindowBackend {
            map_result: Ok(()),
            unmap_result: Ok(()),
            maps: 0,
            unmaps: 0,
            last: None,
        };
        {
            let mut mapper =
                VirtualBlockPciMemoryMapper::new(&mut attachment, device, &mut backend);
            router
                .write_with_mapper(
                    location,
                    4,
                    2,
                    crate::PCI_COMMAND_MEMORY_SPACE as u32,
                    &mut mapper,
                )
                .unwrap();
        }
        assert_eq!(backend.maps, 1);
        (attachment, router)
    }

    #[test]
    fn mmio_transaction_runner_retires_only_the_consumed_exact_write() {
        let interrupt_object = ObjectId(0x320);
        let block_object = ObjectId(0x321);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(
                block_object,
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let authority =
            VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64).unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(0x322), ObjectId(0x323), ObjectId(0x324));
        let guest_memory = GuestMemory::<0>::new();
        let io = IoPortPolicy::<0>::deny_all();
        let mut device = active_mmio::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let (attachment, pci_router) = mapped_mmio_attachment(&device, &bridge, authority);
        let mut vmm = MockVmm::new();
        vmm.next_exit = Some(VmExit::Mmio {
            guest_address: 0x20_0000,
            size: 4,
            write: true,
            value: 1,
        });
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];

        assert_eq!(
            run_virtual_block_mmio_transaction_once(
                &mut vmm,
                &mut backend,
                authority,
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &pci_router,
                &attachment,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Ok(VirtualBlockTransactionOutcome::Doorbell(
                VirtualBlockProcessOutcome::Idle
            ))
        );
        assert_eq!(vmm.completed_mmio, Some((0, 0x20_0000, 4, 1)));
        assert_eq!(vms.state(vm), Ok(crate::VmState::Running));
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));
    }

    #[test]
    fn mmio_transaction_runner_completes_request_and_protected_acknowledgement() {
        let interrupt_object = ObjectId(0x325);
        let block_object = ObjectId(0x326);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(block_object, crate::Rights::WRITE)
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let authority =
            VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64).unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(0x327), ObjectId(0x328), ObjectId(0x329));
        let guest_memory = GuestMemory::<0>::new();
        let io = IoPortPolicy::<0>::deny_all();
        let mut device = active_mmio::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let (attachment, pci_router) = mapped_mmio_attachment(&device, &bridge, authority);
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0; 4096];
        let request = encoded(VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096));
        vmm.bytes[0x4000..0x5000].fill(0x6b);
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();
        vmm.next_exit = Some(VmExit::Mmio {
            guest_address: 0x20_0000,
            size: 4,
            write: true,
            value: 1,
        });

        assert!(matches!(
            run_virtual_block_mmio_transaction_once(
                &mut vmm,
                &mut backend,
                authority,
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &pci_router,
                &attachment,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Ok(VirtualBlockTransactionOutcome::Doorbell(
                VirtualBlockProcessOutcome::Completed(_)
            ))
        ));
        assert_eq!(vmm.injected, Some((0, 48)));
        assert_eq!(backend.writes, 1);

        // Model the native backend having consumed its exact pending tuple.
        vmm.completed_mmio = None;
        vmm.next_exit = Some(VmExit::Mmio {
            guest_address: 0x20_0004,
            size: 4,
            write: true,
            value: 1,
        });
        assert_eq!(
            run_virtual_block_mmio_transaction_once(
                &mut vmm,
                &mut backend,
                authority,
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &pci_router,
                &attachment,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Ok(VirtualBlockTransactionOutcome::CompletionAcknowledged(1))
        );
        assert_eq!(bridge.completion_consumed, 1);
        assert_eq!(vms.state(vm), Ok(crate::VmState::Running));
    }

    #[test]
    fn mmio_completion_uncertainty_fail_stops_the_vm() {
        let interrupt_object = ObjectId(0x330);
        let block_object = ObjectId(0x331);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(block_object, crate::Rights::READ)
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let authority =
            VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64).unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(0x332), ObjectId(0x333), ObjectId(0x334));
        let guest_memory = GuestMemory::<0>::new();
        let io = IoPortPolicy::<0>::deny_all();
        let mut device = active_mmio::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let (attachment, pci_router) = mapped_mmio_attachment(&device, &bridge, authority);
        let mut vmm = MockVmm::new();
        vmm.fail_mmio_completion = true;
        vmm.next_exit = Some(VmExit::Mmio {
            guest_address: 0x20_0000,
            size: 4,
            write: true,
            value: 1,
        });
        let mut backend = MockBlock::new();
        let mut scratch = [0; 4096];

        assert_eq!(
            run_virtual_block_mmio_transaction_once(
                &mut vmm,
                &mut backend,
                authority,
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &pci_router,
                &attachment,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Err(VirtualBlockTransactionRunError::Completion(
                MockError::Injected
            ))
        );
        assert_eq!(vms.state(vm), Ok(crate::VmState::Failed));
        assert_eq!(vmm.completed_mmio, None);
        assert!(bridge.is_poisoned());
        assert_eq!(device.state(), VirtualBlockDeviceState::Failed);
    }

    #[test]
    fn shared_ack_runner_accounts_exact_exit_and_updates_protected_counter() {
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(76), ObjectId(77), ObjectId(78));
        let capabilities = CapabilitySpace::<0>::new();
        let guest_memory = GuestMemory::<0>::new();
        let io = block_ack_io_policy();
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        published_completion(&mut device, &mut bridge, &mut vmm);
        vmm.next_exit = Some(VmExit::Io {
            port: VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
            size: 4,
            write: true,
            value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
        });

        assert_eq!(
            run_virtual_block_completion_ack_once(
                &mut vmm,
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &mut device,
                &mut bridge,
            ),
            Ok(1)
        );
        assert_eq!(vms.state(vm), Ok(crate::VmState::Running));
        let mut consumed = [0; 8];
        vmm.read_guest(0x3000 + 64, &mut consumed).unwrap();
        assert_eq!(u64::from_le_bytes(consumed), 1);
    }

    #[test]
    fn shared_ack_runner_fails_vm_on_dispatched_scalar_mismatch() {
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(72), ObjectId(73), ObjectId(74));
        let capabilities = CapabilitySpace::<0>::new();
        let guest_memory = GuestMemory::<0>::new();
        let io = block_ack_io_policy();
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        published_completion(&mut device, &mut bridge, &mut vmm);
        vmm.next_exit = Some(VmExit::Io {
            port: VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
            size: 4,
            write: true,
            value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE + 1,
        });

        assert_eq!(
            run_virtual_block_completion_ack_once(
                &mut vmm,
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &mut device,
                &mut bridge,
            ),
            Err(VirtualBlockCompletionAckRunError::Acknowledgement(
                VirtualBlockCompletionAckError::InvalidExit
            ))
        );
        assert_eq!(vms.state(vm), Ok(crate::VmState::Failed));
        assert_eq!(device.state(), VirtualBlockDeviceState::Active);
        assert!(!bridge.is_poisoned());
        assert_eq!(bridge.completion_consumed, 0);
    }

    #[test]
    fn shared_runners_reuse_one_slot_for_bounded_write_then_read() {
        let interrupt_object = ObjectId(68);
        let block_object = ObjectId(0x300);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(
                block_object,
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(69), ObjectId(70), ObjectId(71));
        let guest_memory = GuestMemory::<0>::new();
        let io = block_transaction_io_policy();
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];

        for (sequence, request) in [
            VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096),
            VirtualBlockRequest::read(1, 2, 0, 1, 0x4000, 4096),
        ]
        .into_iter()
        .enumerate()
        {
            let sequence = sequence as u64 + 1;
            if sequence == 1 {
                vmm.bytes[0x4000..0x5000].fill(0x65);
            } else {
                vmm.bytes[0x4000..0x5000].fill(0);
            }
            vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &encoded(request))
                .unwrap();
            vmm.write_guest(0x1000, &sequence.to_le_bytes()).unwrap();
            vmm.next_exit = Some(VmExit::Io {
                port: VIRTUAL_BLOCK_DOORBELL_PORT,
                size: 4,
                write: true,
                value: VIRTUAL_BLOCK_DOORBELL_VALUE,
            });
            assert!(matches!(
                run_virtual_block_doorbell_once(
                    &mut vmm,
                    &mut backend,
                    VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64)
                        .unwrap(),
                    0,
                    &mut vms,
                    vm,
                    &mut router,
                    &capabilities,
                    &guest_memory,
                    &io,
                    &interrupts,
                    interrupt_capability,
                    interrupt_object,
                    &mut device,
                    &mut bridge,
                    &mut scratch,
                ),
                Ok(VirtualBlockProcessOutcome::Completed(_))
            ));
            vmm.next_exit = Some(VmExit::Io {
                port: VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
                size: 4,
                write: true,
                value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
            });
            assert_eq!(
                run_virtual_block_completion_ack_once(
                    &mut vmm,
                    0,
                    &mut vms,
                    vm,
                    &mut router,
                    &capabilities,
                    &guest_memory,
                    &io,
                    &mut device,
                    &mut bridge,
                ),
                Ok(sequence)
            );
        }

        assert_eq!((backend.writes, backend.reads), (1, 1));
        assert!(vmm.bytes[0x4000..0x5000].iter().all(|byte| *byte == 0x65));
        assert_eq!(bridge.request_consumed, 2);
        assert_eq!(bridge.completion_published, 2);
        assert_eq!(bridge.completion_consumed, 2);
        assert_eq!(vms.state(vm), Ok(crate::VmState::Running));
    }

    #[test]
    fn transaction_runner_dispatches_doorbell_then_protected_acknowledgement() {
        let interrupt_object = ObjectId(96);
        let block_object = ObjectId(0x300);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(
                block_object,
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(97), ObjectId(98), ObjectId(99));
        let guest_memory = GuestMemory::<0>::new();
        let io = block_transaction_io_policy();
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        let request = encoded(VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096));
        vmm.bytes[0x4000..0x5000].fill(0x65);
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();
        vmm.next_exit = Some(VmExit::Io {
            port: VIRTUAL_BLOCK_DOORBELL_PORT,
            size: 4,
            write: true,
            value: VIRTUAL_BLOCK_DOORBELL_VALUE,
        });

        assert!(matches!(
            run_virtual_block_transaction_once(
                &mut vmm,
                &mut backend,
                VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64).unwrap(),
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Ok(VirtualBlockTransactionOutcome::Doorbell(
                VirtualBlockProcessOutcome::Completed(_)
            ))
        ));
        assert_eq!(vmm.injected, Some((0, 48)));

        vmm.next_exit = Some(VmExit::Io {
            port: VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
            size: 4,
            write: true,
            value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
        });
        assert_eq!(
            run_virtual_block_transaction_once(
                &mut vmm,
                &mut backend,
                VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64).unwrap(),
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Ok(VirtualBlockTransactionOutcome::CompletionAcknowledged(1))
        );
        assert_eq!(vms.state(vm), Ok(crate::VmState::Running));
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 1, 0));
        assert_eq!(bridge.completion_consumed, 1);
    }

    #[test]
    fn transaction_runner_fails_vm_on_non_transport_exit() {
        let interrupt_object = ObjectId(100);
        let block_object = ObjectId(0x300);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(
                block_object,
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(101), ObjectId(102), ObjectId(103));
        let guest_memory = GuestMemory::<0>::new();
        let io = block_transaction_io_policy();
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        vmm.next_exit = Some(VmExit::Halted);

        assert_eq!(
            run_virtual_block_transaction_once(
                &mut vmm,
                &mut backend,
                VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64).unwrap(),
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Err(VirtualBlockTransactionRunError::InvalidExit)
        );
        assert_eq!(vms.state(vm), Ok(crate::VmState::Failed));
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));
        assert!(scratch.iter().all(|byte| *byte == 0xa5));
        assert_eq!(bridge.request_consumed, 0);
        assert_eq!(bridge.completion_consumed, 0);
    }

    #[test]
    fn transaction_runner_rejects_backend_region_geometry_before_vcpu_entry() {
        let block_object = ObjectId(0x300);
        let interrupt_object = ObjectId(0x310);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(
                block_object,
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(0x311), ObjectId(0x312), ObjectId(0x313));
        let guest_memory = GuestMemory::<0>::new();
        let io = block_transaction_io_policy();
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let expected_exit = VmExit::Halted;
        vmm.next_exit = Some(expected_exit);
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];

        assert_eq!(
            run_virtual_block_transaction_once(
                &mut vmm,
                &mut backend,
                VirtualBlockBackendAuthority::new(block_capability, block_object, 1, 63).unwrap(),
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Err(VirtualBlockTransactionRunError::Authority(
                VirtualBlockAuthorityError::GeometryMismatch
            ))
        );
        assert_eq!(vmm.next_exit, Some(expected_exit));
        assert_eq!(vms.state(vm), Ok(crate::VmState::Failed));
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));
        assert_eq!(bridge.request_consumed, 0);
        assert!(scratch.iter().all(|byte| *byte == 0xa5));
    }

    #[test]
    fn shared_runner_completes_exact_doorbell_and_authorized_interrupt() {
        let interrupt_object = ObjectId(80);
        let block_object = ObjectId(0x300);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(
                block_object,
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(81), ObjectId(82), ObjectId(83));
        let guest_memory = GuestMemory::<0>::new();
        let io = block_io_policy();
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        let request = encoded(VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096));
        vmm.bytes[0x4000..0x5000].fill(0x65);
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();
        vmm.next_exit = Some(VmExit::Io {
            port: VIRTUAL_BLOCK_DOORBELL_PORT,
            size: 4,
            write: true,
            value: VIRTUAL_BLOCK_DOORBELL_VALUE,
        });

        assert!(matches!(
            run_virtual_block_doorbell_once(
                &mut vmm,
                &mut backend,
                VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64).unwrap(),
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Ok(VirtualBlockProcessOutcome::Completed(_))
        ));
        assert_eq!(vms.state(vm), Ok(crate::VmState::Running));
        assert_eq!(backend.writes, 1);
        assert_eq!(vmm.injected, Some((0, 48)));
        assert_eq!(device.pending_interrupt_vector(), None);
    }

    #[test]
    fn shared_runner_rejects_bad_doorbell_and_fails_vm_before_queue_access() {
        let interrupt_object = ObjectId(84);
        let block_object = ObjectId(0x300);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(
                block_object,
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(85), ObjectId(86), ObjectId(87));
        let guest_memory = GuestMemory::<0>::new();
        let io = block_io_policy();
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        vmm.next_exit = Some(VmExit::Io {
            port: VIRTUAL_BLOCK_DOORBELL_PORT,
            size: 4,
            write: true,
            value: VIRTUAL_BLOCK_DOORBELL_VALUE + 1,
        });

        assert_eq!(
            run_virtual_block_doorbell_once(
                &mut vmm,
                &mut backend,
                VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64).unwrap(),
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Err(VirtualBlockRunError::Doorbell(
                VirtualBlockDoorbellError::InvalidExit
            ))
        );
        assert_eq!(vms.state(vm), Ok(crate::VmState::Failed));
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));
        assert!(scratch.iter().all(|byte| *byte == 0xa5));
    }

    #[test]
    fn shared_runner_injection_failure_retains_completion_and_fails_vm() {
        let interrupt_object = ObjectId(88);
        let block_object = ObjectId(0x300);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(
                block_object,
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(89), ObjectId(90), ObjectId(91));
        let guest_memory = GuestMemory::<0>::new();
        let io = block_io_policy();
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];
        let request = encoded(VirtualBlockRequest::write(1, 1, 0, 1, 0x4000, 4096));
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();
        vmm.next_exit = Some(VmExit::Io {
            port: VIRTUAL_BLOCK_DOORBELL_PORT,
            size: 4,
            write: true,
            value: VIRTUAL_BLOCK_DOORBELL_VALUE,
        });
        vmm.fail_inject = true;

        assert_eq!(
            run_virtual_block_doorbell_once(
                &mut vmm,
                &mut backend,
                VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64).unwrap(),
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Err(VirtualBlockRunError::Interrupt(
                VirtualBlockInterruptError::Injection(VmRunError::Backend(MockError::Injected))
            ))
        );
        assert_eq!(vms.state(vm), Ok(crate::VmState::Failed));
        assert_eq!(backend.writes, 1);
        assert_eq!(device.pending_interrupt_vector(), Some(48));
    }

    #[test]
    fn shared_runner_delivers_pending_notification_before_vcpu_entry() {
        let interrupt_object = ObjectId(92);
        let block_object = ObjectId(0x300);
        let mut capabilities = CapabilitySpace::<2>::new();
        let block_capability = capabilities
            .insert(
                block_object,
                crate::Rights::READ
                    .union(crate::Rights::WRITE)
                    .union(crate::Rights::FLUSH),
            )
            .unwrap();
        let interrupt_capability = capabilities
            .insert(interrupt_object, crate::Rights::SIGNAL)
            .unwrap();
        let mut interrupts = InterruptPolicy::deny_all();
        interrupts.allow(48).unwrap();
        let (mut vms, vm) = runner_vm();
        let mut router = HypercallRouter::new(ObjectId(93), ObjectId(94), ObjectId(95));
        let guest_memory = GuestMemory::<0>::new();
        let io = block_io_policy();
        let mut device = active::<1>();
        device.latch_completion_interrupt().unwrap();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        let expected_exit = VmExit::Io {
            port: VIRTUAL_BLOCK_DOORBELL_PORT,
            size: 4,
            write: true,
            value: VIRTUAL_BLOCK_DOORBELL_VALUE,
        };
        vmm.next_exit = Some(expected_exit);
        vmm.fail_inject = true;
        let mut backend = MockBlock::new();
        let mut scratch = [0xa5; 4096];

        assert!(matches!(
            run_virtual_block_doorbell_once(
                &mut vmm,
                &mut backend,
                VirtualBlockBackendAuthority::new(block_capability, block_object, 0, 64).unwrap(),
                0,
                &mut vms,
                vm,
                &mut router,
                &capabilities,
                &guest_memory,
                &io,
                &interrupts,
                interrupt_capability,
                interrupt_object,
                &mut device,
                &mut bridge,
                &mut scratch,
            ),
            Err(VirtualBlockRunError::Interrupt(_))
        ));
        assert_eq!(vmm.next_exit, Some(expected_exit));
        assert_eq!(vms.state(vm), Ok(crate::VmState::Failed));
        assert_eq!(device.pending_interrupt_vector(), Some(48));
        assert_eq!((backend.reads, backend.writes, backend.flushes), (0, 0, 0));
    }

    #[test]
    fn queue_bridge_copies_disjoint_slots_and_poison_is_permanent() {
        const N: usize = 2;
        let layout = layout::<N>();
        let mut bridge = VirtualBlockQueueBridge::<N>::new(layout).unwrap();
        let mut vmm = MockVmm::new();
        let request = encoded(VirtualBlockRequest::read(1, 1, 0, 1, 0x4000, 4096));
        let request_slot = 0x1000 + QUEUE_HEADER_BYTES;
        vmm.write_guest(request_slot, &request).unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();
        let mut copied = [0; VIRTUAL_BLOCK_REQUEST_BYTES];
        bridge.consume_request(&mut vmm, &mut copied).unwrap();
        assert_eq!(copied, request);
        let mut consumed = [0; 8];
        vmm.read_guest(0x1040, &mut consumed).unwrap();
        assert_eq!(u64::from_le_bytes(consumed), 1);

        let mut device = active::<N>();
        let admitted = device.admit(&copied).unwrap();
        let completion = device
            .complete(admitted.ticket(), VirtualBlockCompletionStatus::Ok, 4096)
            .unwrap();
        bridge.publish_completion(&mut vmm, completion).unwrap();
        let mut encoded_completion = [0; VIRTUAL_BLOCK_COMPLETION_BYTES];
        vmm.read_guest(0x3000 + QUEUE_HEADER_BYTES, &mut encoded_completion)
            .unwrap();
        assert_eq!(
            VirtualBlockCompletion::decode(&encoded_completion),
            Ok(completion)
        );

        vmm.fail_read = true;
        assert_eq!(
            bridge.consume_request(&mut vmm, &mut copied),
            Err(VirtualBlockQueueError::Backend(MockError::Injected))
        );
        assert!(bridge.is_poisoned());
        vmm.fail_read = false;
        assert_eq!(
            bridge.publish_completion(&mut vmm, completion),
            Err(VirtualBlockQueueError::Poisoned)
        );
    }

    #[test]
    fn failed_consumed_publication_returns_no_request_and_poisons_bridge() {
        let layout = layout::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout).unwrap();
        let mut vmm = MockVmm::new();
        let request = encoded(VirtualBlockRequest::flush(1, 1));
        vmm.write_guest(0x1000 + QUEUE_HEADER_BYTES, &request)
            .unwrap();
        vmm.write_guest(0x1000, &1u64.to_le_bytes()).unwrap();
        vmm.fail_write = true;
        let mut output = [0xa5; VIRTUAL_BLOCK_REQUEST_BYTES];
        assert_eq!(
            bridge.consume_request(&mut vmm, &mut output),
            Err(VirtualBlockQueueError::Backend(MockError::Injected))
        );
        assert!(output.iter().all(|byte| *byte == 0));
        assert!(bridge.is_poisoned());
    }

    #[test]
    fn hostile_ring_indices_fail_before_slot_or_completion_access() {
        let layout = layout::<2>();
        let mut bridge = VirtualBlockQueueBridge::<2>::new(layout).unwrap();
        let mut vmm = MockVmm::new();
        vmm.write_guest(0x1000, &3u64.to_le_bytes()).unwrap();
        let mut output = [0xa5; VIRTUAL_BLOCK_REQUEST_BYTES];
        assert_eq!(
            bridge.consume_request(&mut vmm, &mut output),
            Err(VirtualBlockQueueError::Protocol(
                VirtualBlockError::InvalidQueue
            ))
        );
        assert!(output.iter().all(|byte| *byte == 0));

        vmm.write_guest(0x3040, &1u64.to_le_bytes()).unwrap();
        let completion = VirtualBlockCompletion {
            generation: 1,
            request_id: 1,
            status: VirtualBlockCompletionStatus::Ok,
            transferred: 4096,
        };
        bridge.publish_completion(&mut vmm, completion).unwrap();
        assert_eq!(bridge.completion_consumed, 0);
        assert_eq!(bridge.completion_published, 1);
        let completion_slot = 0x3000 + QUEUE_HEADER_BYTES;
        assert_eq!(
            VirtualBlockCompletion::decode(
                &vmm.bytes[completion_slot as usize
                    ..completion_slot as usize + VIRTUAL_BLOCK_COMPLETION_BYTES]
            ),
            Ok(completion)
        );
    }

    fn exact_completion_ack() -> ExitDisposition {
        ExitDisposition::Io {
            port: VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
            size: 4,
            write: true,
            value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
        }
    }

    fn published_completion<const N: usize>(
        device: &mut VirtualBlockDevice<N>,
        bridge: &mut VirtualBlockQueueBridge<N>,
        vmm: &mut MockVmm,
    ) -> VirtualBlockCompletion {
        let request = VirtualBlockRequest::flush(device.generation(), 1);
        let mut encoded = [0; VIRTUAL_BLOCK_REQUEST_BYTES];
        request.encode(&mut encoded);
        let admitted = device.admit(&encoded).unwrap();
        let completion = device
            .complete(admitted.ticket(), VirtualBlockCompletionStatus::Ok, 0)
            .unwrap();
        bridge.publish_completion(vmm, completion).unwrap();
        completion
    }

    #[test]
    fn completion_ack_advances_one_protected_counter_and_restores_capacity() {
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        published_completion(&mut device, &mut bridge, &mut vmm);
        assert_eq!(bridge.completion_ready(&vmm), Ok(false));

        assert_eq!(
            process_virtual_block_completion_ack(
                exact_completion_ack(),
                &mut device,
                &mut bridge,
                &mut vmm,
            ),
            Ok(1)
        );
        assert_eq!(bridge.completion_consumed, 1);
        assert_eq!(bridge.completion_ready(&vmm), Ok(true));
        let mut consumed = [0; 8];
        vmm.read_guest(0x3000 + 64, &mut consumed).unwrap();
        assert_eq!(u64::from_le_bytes(consumed), 1);
    }

    #[test]
    fn completion_ack_rechecks_every_scalar_before_state_or_memory_access() {
        for disposition in [
            ExitDisposition::Io {
                port: VIRTUAL_BLOCK_COMPLETION_ACK_PORT + 1,
                size: 4,
                write: true,
                value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
            },
            ExitDisposition::Io {
                port: VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
                size: 2,
                write: true,
                value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
            },
            ExitDisposition::Io {
                port: VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
                size: 4,
                write: false,
                value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE,
            },
            ExitDisposition::Io {
                port: VIRTUAL_BLOCK_COMPLETION_ACK_PORT,
                size: 4,
                write: true,
                value: VIRTUAL_BLOCK_COMPLETION_ACK_VALUE + 1,
            },
            ExitDisposition::Stopped,
        ] {
            let mut device = active::<1>();
            let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
            let mut vmm = MockVmm::new();
            published_completion(&mut device, &mut bridge, &mut vmm);
            vmm.fail_write = true;
            assert_eq!(
                process_virtual_block_completion_ack(
                    disposition,
                    &mut device,
                    &mut bridge,
                    &mut vmm,
                ),
                Err(VirtualBlockCompletionAckError::InvalidExit)
            );
            assert_eq!(device.state(), VirtualBlockDeviceState::Active);
            assert!(!bridge.is_poisoned());
            assert_eq!(bridge.completion_consumed, 0);
        }
    }

    #[test]
    fn premature_or_uncertain_completion_ack_fails_closed() {
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        published_completion(&mut device, &mut bridge, &mut vmm);
        device.latch_completion_interrupt().unwrap();
        assert!(matches!(
            process_virtual_block_completion_ack(
                exact_completion_ack(),
                &mut device,
                &mut bridge,
                &mut vmm,
            ),
            Err(VirtualBlockCompletionAckError::Queue {
                error: VirtualBlockQueueError::Protocol(VirtualBlockError::InvalidState),
                ..
            })
        ));
        assert_eq!(device.state(), VirtualBlockDeviceState::Failed);
        assert!(bridge.is_poisoned());

        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        published_completion(&mut device, &mut bridge, &mut vmm);
        vmm.fail_write = true;
        assert!(matches!(
            process_virtual_block_completion_ack(
                exact_completion_ack(),
                &mut device,
                &mut bridge,
                &mut vmm,
            ),
            Err(VirtualBlockCompletionAckError::Queue {
                error: VirtualBlockQueueError::Backend(MockError::Injected),
                ..
            })
        ));
        assert_eq!(device.state(), VirtualBlockDeviceState::Failed);
        assert!(bridge.is_poisoned());
        assert_eq!(bridge.completion_consumed, 0);
    }

    #[test]
    fn empty_completion_ack_fails_device_and_bridge_closed() {
        let mut device = active::<1>();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout::<1>()).unwrap();
        let mut vmm = MockVmm::new();
        assert!(matches!(
            process_virtual_block_completion_ack(
                exact_completion_ack(),
                &mut device,
                &mut bridge,
                &mut vmm,
            ),
            Err(VirtualBlockCompletionAckError::Queue {
                error: VirtualBlockQueueError::Protocol(VirtualBlockError::QueueEmpty),
                ..
            })
        ));
        assert_eq!(device.state(), VirtualBlockDeviceState::Failed);
        assert!(bridge.is_poisoned());
        assert_eq!(bridge.completion_consumed, 0);
    }

    #[test]
    fn queue_layout_rejects_aliases_capacity_and_overflow() {
        assert_eq!(
            VirtualBlockQueueLayout::new(0x1000, 0x1000, 1),
            Err(VirtualBlockError::InvalidQueue)
        );
        assert_eq!(
            VirtualBlockQueueLayout::new(0x1001, 0x3000, 1),
            Err(VirtualBlockError::InvalidQueue)
        );
        assert_eq!(
            VirtualBlockQueueLayout::new(0x1000, 0x3000, 0),
            Err(VirtualBlockError::InvalidQueue)
        );
        assert_eq!(
            VirtualBlockQueueLayout::new(u64::MAX - PAGE_SIZE + 1, 0x3000, 1),
            Err(VirtualBlockError::RangeOverflow)
        );
    }
}
