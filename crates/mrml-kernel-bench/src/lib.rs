#![no_std]

//! Host-only performance gates for `mrml-kernel`. Keeping this crate separate
//! prevents operating-system timing and output services from entering the UEFI
//! kernel dependency graph.

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use core::hint::black_box;
    use mrml_kernel::arch::x86_64::UserContext;
    use mrml_kernel::{
        CapabilitySpace, Endpoint, ExitDisposition, GuestMemory, GuestRegion, HostResourceHandle,
        InterruptPolicy, KernelScheduler, ObjectId, PeriodicBalancer, PhysAddr, Priority, Rights,
        Scheduler, SchedulerLoad, SharedAccess, SharedEndpoint, SharedMemoryBindings, TaskRuntime,
        VIRTUAL_BLOCK_DOORBELL_PORT, VIRTUAL_BLOCK_DOORBELL_VALUE, VirtualBlockBackend,
        VirtualBlockDevice, VirtualBlockMutationError, VirtualBlockProcessOutcome,
        VirtualBlockQueueBridge, VirtualBlockQueueLayout, VirtualBlockRequest,
        VirtualBlockVmmMemory, VmBackend, VmExit, VmTable, inject_virtual_block_interrupt,
        process_virtual_block_doorbell,
    };
    use mrml_runtime::{Instant, mrml_println};

    const ITERATIONS: u64 = 1_000_000;
    const MAX_NANOSECONDS_PER_OPERATION: u128 = 10_000;
    const SERVICE_ITERATIONS: u64 = 100_000;
    const MAX_SERVICE_NANOSECONDS_PER_OPERATION: u128 = 100_000;
    const VIRTUAL_BLOCK_ITERATIONS: u64 = 10_000;

    struct VirtualBlockMemory {
        bytes: [u8; 0x5000],
        interrupts: u64,
    }

    impl VirtualBlockMemory {
        fn write(&mut self, address: u64, input: &[u8]) {
            let start = address as usize;
            self.bytes[start..start + input.len()].copy_from_slice(input);
        }
    }

    impl VmBackend for VirtualBlockMemory {
        type Error = ();

        fn run(&mut self, _: u32) -> Result<VmExit, Self::Error> {
            Err(())
        }

        fn read_guest(&self, address: u64, output: &mut [u8]) -> Result<(), Self::Error> {
            let start = usize::try_from(address).map_err(|_| ())?;
            let end = start.checked_add(output.len()).ok_or(())?;
            output.copy_from_slice(self.bytes.get(start..end).ok_or(())?);
            Ok(())
        }

        fn write_guest(&mut self, address: u64, input: &[u8]) -> Result<(), Self::Error> {
            self.write_virtual_block(address, input)
        }

        fn inject_interrupt(&mut self, _: u32, _: u8) -> Result<(), Self::Error> {
            self.interrupts = self.interrupts.checked_add(1).ok_or(())?;
            Ok(())
        }
    }

    impl VirtualBlockVmmMemory for VirtualBlockMemory {
        fn write_virtual_block(&mut self, address: u64, input: &[u8]) -> Result<(), Self::Error> {
            let start = usize::try_from(address).map_err(|_| ())?;
            let end = start.checked_add(input.len()).ok_or(())?;
            self.bytes
                .get_mut(start..end)
                .ok_or(())?
                .copy_from_slice(input);
            Ok(())
        }
    }

    struct VirtualBlockStorage([u8; 4096]);

    unsafe impl VirtualBlockBackend for VirtualBlockStorage {
        type Error = ();

        fn read_blocks(&mut self, block: u64, output: &mut [u8]) -> Result<(), Self::Error> {
            if block != 0 || output.len() != self.0.len() {
                return Err(());
            }
            output.copy_from_slice(&self.0);
            Ok(())
        }

        fn write_blocks(
            &mut self,
            block: u64,
            input: &[u8],
        ) -> Result<(), VirtualBlockMutationError<Self::Error>> {
            if block != 0 || input.len() != self.0.len() {
                return Err(VirtualBlockMutationError::Rejected(()));
            }
            self.0.copy_from_slice(input);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), VirtualBlockMutationError<Self::Error>> {
            Ok(())
        }
    }

    fn report(label: &str, elapsed: u128, iterations: u64) {
        mrml_println!(
            "MRML_KERNEL_BENCH {}_total_ns={} {}_ps={} iterations={}",
            label,
            elapsed,
            label,
            elapsed.saturating_mul(1000) / iterations as u128,
            iterations
        );
        assert!(elapsed / (iterations as u128) < MAX_SERVICE_NANOSECONDS_PER_OPERATION);
    }

    fn context(root: u64, entry: u64) -> UserContext {
        UserContext::new(PhysAddr::new(root).unwrap(), entry, 0x7000_0000).unwrap()
    }

    #[cfg(windows)]
    mod windows_affinity {
        use core::ffi::c_void;
        use core::mem::size_of;
        use std::vec;

        const RELATION_PROCESSOR_CORE: u32 = 0;
        const RELATION_ALL: u32 = 0xffff;

        #[repr(C)]
        #[derive(Clone, Copy)]
        struct GroupAffinity {
            mask: usize,
            group: u16,
            reserved: [u16; 3],
        }

        #[repr(C)]
        struct ProcessorNumber {
            group: u16,
            number: u8,
            reserved: u8,
        }

        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetCurrentThread() -> *mut c_void;
            fn GetCurrentProcessorNumberEx(number: *mut ProcessorNumber);
            fn GetLogicalProcessorInformationEx(
                relationship: u32,
                buffer: *mut u8,
                bytes: *mut u32,
            ) -> i32;
            fn SetThreadGroupAffinity(
                thread: *mut c_void,
                affinity: *const GroupAffinity,
                previous: *mut GroupAffinity,
            ) -> i32;
        }

        pub struct AffinityGuard(GroupAffinity);

        impl Drop for AffinityGuard {
            fn drop(&mut self) {
                let mut ignored = GroupAffinity {
                    mask: 0,
                    group: 0,
                    reserved: [0; 3],
                };
                unsafe {
                    SetThreadGroupAffinity(GetCurrentThread(), &self.0, &mut ignored);
                }
            }
        }

        pub fn pin(group: u16, number: u8) -> AffinityGuard {
            assert_eq!(size_of::<usize>(), 8);
            assert!(number < 64);
            let requested = GroupAffinity {
                mask: 1usize << number,
                group,
                reserved: [0; 3],
            };
            let mut previous = GroupAffinity {
                mask: 0,
                group: 0,
                reserved: [0; 3],
            };
            assert_ne!(
                unsafe { SetThreadGroupAffinity(GetCurrentThread(), &requested, &mut previous) },
                0
            );
            let actual = current();
            assert_eq!(actual, (group, number));
            AffinityGuard(previous)
        }

        pub fn current() -> (u16, u8) {
            let mut number = ProcessorNumber {
                group: 0,
                number: 0,
                reserved: 0,
            };
            unsafe { GetCurrentProcessorNumberEx(&mut number) };
            (number.group, number.number)
        }

        pub fn distinct_cores() -> [(u16, u8); 2] {
            let mut bytes = 0u32;
            unsafe {
                GetLogicalProcessorInformationEx(RELATION_ALL, core::ptr::null_mut(), &mut bytes);
            }
            assert!(bytes >= 32);
            let mut buffer = vec![0u8; bytes as usize];
            assert_ne!(
                unsafe {
                    GetLogicalProcessorInformationEx(RELATION_ALL, buffer.as_mut_ptr(), &mut bytes)
                },
                0
            );
            let mut selected = [(0u16, 0u8); 2];
            let mut count = 0usize;
            let mut offset = 0usize;
            while offset < bytes as usize {
                assert!(offset + 8 <= bytes as usize);
                let relationship =
                    u32::from_ne_bytes(buffer[offset..offset + 4].try_into().unwrap());
                let entry_bytes =
                    u32::from_ne_bytes(buffer[offset + 4..offset + 8].try_into().unwrap()) as usize;
                assert!(entry_bytes >= 8 && offset + entry_bytes <= bytes as usize);
                if relationship == RELATION_PROCESSOR_CORE {
                    assert!(entry_bytes >= 48);
                    let groups =
                        u16::from_ne_bytes(buffer[offset + 30..offset + 32].try_into().unwrap())
                            as usize;
                    assert!(groups != 0 && 32 + groups * 16 <= entry_bytes);
                    let mask_offset = offset + 32;
                    let mask = u64::from_ne_bytes(
                        buffer[mask_offset..mask_offset + 8].try_into().unwrap(),
                    );
                    let group = u16::from_ne_bytes(
                        buffer[mask_offset + 8..mask_offset + 10]
                            .try_into()
                            .unwrap(),
                    );
                    if mask != 0 {
                        selected[count] = (group, mask.trailing_zeros() as u8);
                        count += 1;
                        if count == 2 {
                            assert_ne!(selected[0], selected[1]);
                            return selected;
                        }
                    }
                }
                offset += entry_bytes;
            }
            panic!("two distinct Windows processor cores are required");
        }
    }

    #[test]
    #[ignore = "manual release-mode performance gate"]
    fn capability_authorization_budget() {
        let mut space = CapabilitySpace::<64>::new();
        let capability = space.insert(ObjectId(7), Rights::READ).unwrap();
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            black_box(
                space
                    .authorize(black_box(capability), Rights::READ)
                    .unwrap(),
            );
        }
        let elapsed = start.elapsed().as_nanos();
        let per_operation = elapsed / ITERATIONS as u128;
        let picoseconds = elapsed.saturating_mul(1000) / ITERATIONS as u128;
        mrml_println!(
            "MRML_KERNEL_BENCH capability_authorize_total_ns={} capability_authorize_ps={} iterations={}",
            elapsed,
            picoseconds,
            ITERATIONS
        );
        assert!(per_operation < MAX_NANOSECONDS_PER_OPERATION);
    }

    #[test]
    #[ignore = "manual release-mode performance gate"]
    fn scheduler_selection_budget() {
        let mut scheduler = Scheduler::<64>::new();
        for index in 0..64 {
            let priority = if index == 0 {
                Priority::RESPONSIVE
            } else {
                Priority::NORMAL
            };
            scheduler.create(priority).unwrap();
        }
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            black_box(scheduler.schedule().unwrap());
        }
        let elapsed = start.elapsed().as_nanos();
        let per_operation = elapsed / ITERATIONS as u128;
        let picoseconds = elapsed.saturating_mul(1000) / ITERATIONS as u128;
        mrml_println!(
            "MRML_KERNEL_BENCH scheduler_select_total_ns={} scheduler_select_ps={} iterations={}",
            elapsed,
            picoseconds,
            ITERATIONS
        );
        assert!(per_operation < MAX_NANOSECONDS_PER_OPERATION);
    }

    #[test]
    #[ignore = "manual release-mode performance gate"]
    fn vm_exit_accounting_budget() {
        let mut table = VmTable::<8>::new();
        let id = table.create(ITERATIONS).unwrap();
        table.mark_loaded(id).unwrap();
        table.start(id).unwrap();
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            black_box(table.account_exit(black_box(id)).unwrap());
        }
        let elapsed = start.elapsed().as_nanos();
        let per_operation = elapsed / ITERATIONS as u128;
        let picoseconds = elapsed.saturating_mul(1000) / ITERATIONS as u128;
        mrml_println!(
            "MRML_KERNEL_BENCH vm_exit_account_total_ns={} vm_exit_account_ps={} iterations={}",
            elapsed,
            picoseconds,
            ITERATIONS
        );
        assert!(per_operation < MAX_NANOSECONDS_PER_OPERATION);
    }

    #[test]
    #[ignore = "manual release-mode performance gate"]
    fn timer_tick_accounting_budget() {
        let mut scheduler = KernelScheduler::<1>::new(10_000, 10_000).unwrap();
        scheduler.create(Priority::NORMAL).unwrap();
        scheduler.start();
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            black_box(scheduler.timer_tick().unwrap());
        }
        let elapsed = start.elapsed().as_nanos();
        let per_operation = elapsed / ITERATIONS as u128;
        let picoseconds = elapsed.saturating_mul(1000) / ITERATIONS as u128;
        mrml_println!(
            "MRML_KERNEL_BENCH timer_tick_total_ns={} timer_tick_ps={} iterations={}",
            elapsed,
            picoseconds,
            ITERATIONS
        );
        assert!(per_operation < MAX_NANOSECONDS_PER_OPERATION);
    }

    #[test]
    #[ignore = "manual release-mode performance gate"]
    fn periodic_balance_full_topology_budget() {
        const BALANCE_ITERATIONS: u64 = 100_000;
        let mut policy = PeriodicBalancer::<256>::new(0, 1).unwrap();
        let mut loads = [SchedulerLoad::new(1, 1, 4).unwrap(); 256];
        loads[0] = SchedulerLoad::new(4, 4, 8).unwrap();
        let start = Instant::now();
        for tick in 1..=BALANCE_ITERATIONS {
            black_box(policy.poll(black_box(tick), 0, black_box(&loads)).unwrap());
        }
        let elapsed = start.elapsed().as_nanos();
        let per_operation = elapsed / BALANCE_ITERATIONS as u128;
        mrml_println!(
            "MRML_KERNEL_BENCH periodic_balance_256_total_ns={} periodic_balance_256_ns={} iterations={}",
            elapsed,
            per_operation,
            BALANCE_ITERATIONS
        );
        assert!(per_operation < MAX_NANOSECONDS_PER_OPERATION);
    }

    #[test]
    #[ignore = "manual release-mode performance gate"]
    fn ipc_one_way_policy_budget() {
        let object = ObjectId(0x101);
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 10).unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let endpoint_capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        let mut endpoint = Endpoint::new(object);
        let start = Instant::now();
        for _ in 0..SERVICE_ITERATIONS {
            black_box(
                black_box(&mut runtime)
                    .send_ipc(
                        black_box(sender),
                        black_box(receiver),
                        &mut endpoint,
                        endpoint_capability,
                        black_box(b"ping"),
                        &[],
                    )
                    .unwrap(),
            );
        }
        report(
            "ipc_one_way_policy",
            start.elapsed().as_nanos(),
            SERVICE_ITERATIONS,
        );
    }

    #[test]
    #[ignore = "manual release-mode performance gate"]
    fn ipc_round_trip_policy_budget() {
        let first_object = ObjectId(0x111);
        let second_object = ObjectId(0x112);
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 10).unwrap();
        let first = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let second = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let first_capability = runtime
            .capabilities_mut(first)
            .unwrap()
            .insert(first_object, Rights::SIGNAL)
            .unwrap();
        let second_capability = runtime
            .capabilities_mut(second)
            .unwrap()
            .insert(second_object, Rights::SIGNAL)
            .unwrap();
        let mut outbound = Endpoint::new(first_object);
        let mut reply = Endpoint::new(second_object);
        let start = Instant::now();
        for _ in 0..SERVICE_ITERATIONS {
            black_box(
                black_box(&mut runtime)
                    .send_ipc(first, second, &mut outbound, first_capability, b"ping", &[])
                    .unwrap(),
            );
            black_box(
                black_box(&mut runtime)
                    .send_ipc(second, first, &mut reply, second_capability, b"pong", &[])
                    .unwrap(),
            );
        }
        report(
            "ipc_round_trip_policy",
            start.elapsed().as_nanos(),
            SERVICE_ITERATIONS,
        );
    }

    #[test]
    #[ignore = "manual release-mode performance gate"]
    fn blocked_receiver_wakeup_policy_budget() {
        let object = ObjectId(0x121);
        let mut runtime = TaskRuntime::<2, 1>::new(1_000, 10).unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let endpoint_capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(object, Rights::SIGNAL)
            .unwrap();
        let mut endpoint = Endpoint::new(object);
        runtime.start();
        assert!(runtime.receive_or_block_current().unwrap().is_err());
        let start = Instant::now();
        for _ in 0..SERVICE_ITERATIONS {
            black_box(&mut runtime)
                .deliver_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    b"wake",
                    &[],
                )
                .unwrap();
            black_box(&mut runtime).yield_current().unwrap();
            black_box(black_box(&mut runtime).receive_ipc(receiver).unwrap());
            assert!(
                black_box(&mut runtime)
                    .receive_or_block_current()
                    .unwrap()
                    .is_err()
            );
        }
        report(
            "blocked_receiver_wakeup_policy",
            start.elapsed().as_nanos(),
            SERVICE_ITERATIONS,
        );
    }

    #[test]
    #[ignore = "manual release-mode performance gate"]
    fn capability_transfer_policy_budget() {
        let endpoint_object = ObjectId(0x131);
        let resource_object = ObjectId(0x132);
        let mut runtime = TaskRuntime::<2, 2>::new(1_000, 10).unwrap();
        let sender = runtime
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let receiver = runtime
            .create(Priority::NORMAL, context(0x30_0000, 0x50_0000))
            .unwrap();
        let endpoint_capability = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(endpoint_object, Rights::SIGNAL)
            .unwrap();
        let source = runtime
            .capabilities_mut(sender)
            .unwrap()
            .insert(
                resource_object,
                Rights::READ.union(Rights::WRITE).union(Rights::DELEGATE),
            )
            .unwrap();
        let mut endpoint = Endpoint::new(endpoint_object);
        let start = Instant::now();
        for _ in 0..SERVICE_ITERATIONS {
            let (_, message) = black_box(&mut runtime)
                .send_ipc(
                    sender,
                    receiver,
                    &mut endpoint,
                    endpoint_capability,
                    &[],
                    &[(source, Rights::READ)],
                )
                .unwrap();
            let derived = message.capabilities().next().unwrap();
            black_box(&mut runtime)
                .revoke_capability(receiver, derived)
                .unwrap();
        }
        report(
            "capability_transfer_policy",
            start.elapsed().as_nanos(),
            SERVICE_ITERATIONS,
        );
    }

    #[test]
    #[ignore = "manual release-mode performance gate"]
    fn capability_revocation_policy_budget() {
        let mut space = CapabilitySpace::<1>::new();
        let mut capability = space.insert(ObjectId(0x141), Rights::READ).unwrap();
        let start = Instant::now();
        for _ in 0..SERVICE_ITERATIONS {
            black_box(&mut space).revoke(black_box(capability)).unwrap();
            capability = black_box(
                black_box(&mut space)
                    .insert(black_box(ObjectId(0x141)), Rights::READ)
                    .unwrap(),
            );
        }
        report(
            "capability_revoke_reissue_policy",
            start.elapsed().as_nanos(),
            SERVICE_ITERATIONS,
        );
    }

    #[test]
    #[ignore = "manual release-mode performance gate"]
    fn shared_memory_setup_policy_budget() {
        let object = ObjectId(0x151);
        let mut vms = VmTable::<1>::new();
        let vm = vms.create(SERVICE_ITERATIONS * 2).unwrap();
        let mut memory = GuestMemory::<1>::new();
        let mapping = memory
            .map(GuestRegion::new(0x4000, PhysAddr::new(0x8000).unwrap(), 1, false, false).unwrap())
            .unwrap();
        let mut capabilities = CapabilitySpace::<1>::new();
        let authority = capabilities
            .insert(
                object,
                Rights::MAP.union(Rights::READ).union(Rights::CONTROL),
            )
            .unwrap();
        let endpoint = SharedEndpoint::new(vm, mapping, SharedAccess::ReadOnly);
        let handle = HostResourceHandle::new(1).unwrap();
        let mut bindings = SharedMemoryBindings::<1>::new();
        let start = Instant::now();
        for _ in 0..SERVICE_ITERATIONS {
            let binding = black_box(&mut bindings)
                .bind(&capabilities, authority, &memory, endpoint, handle)
                .unwrap();
            black_box(
                black_box(&mut bindings)
                    .revoke(black_box(binding), &capabilities, authority)
                    .unwrap(),
            );
        }
        report(
            "shared_memory_bind_revoke_policy",
            start.elapsed().as_nanos(),
            SERVICE_ITERATIONS,
        );
    }

    #[test]
    #[ignore = "manual release-mode performance gate"]
    fn cross_runtime_domain_handoff_policy_budget() {
        const HANDOFF_ITERATIONS: u64 = 10_000;
        let mut first = TaskRuntime::<1, 0>::new(1_000, 10).unwrap();
        let mut second = TaskRuntime::<1, 0>::new(1_000, 10).unwrap();
        let mut task = first
            .create(Priority::NORMAL, context(0x20_0000, 0x40_0000))
            .unwrap();
        let start = Instant::now();
        for _ in 0..HANDOFF_ITERATIONS {
            let mut outbound = Some(
                black_box(&mut first)
                    .detach_domain(black_box(task))
                    .unwrap(),
            );
            task = black_box(&mut second)
                .attach_domain(black_box(&mut outbound))
                .unwrap()
                .destination();
            let mut inbound = Some(
                black_box(&mut second)
                    .detach_domain(black_box(task))
                    .unwrap(),
            );
            task = black_box(&mut first)
                .attach_domain(black_box(&mut inbound))
                .unwrap()
                .destination();
        }
        report(
            "cross_runtime_round_trip_policy",
            start.elapsed().as_nanos(),
            HANDOFF_ITERATIONS,
        );
    }

    #[test]
    #[ignore = "manual release-mode performance gate"]
    fn virtual_block_doorbell_interrupt_policy_budget() {
        let layout = VirtualBlockQueueLayout::new(0x1000, 0x3000, 1).unwrap();
        let mut device = VirtualBlockDevice::<1>::new(4096, 1, 0).unwrap();
        device.negotiate(0).unwrap();
        device.activate(layout, 48).unwrap();
        let mut bridge = VirtualBlockQueueBridge::<1>::new(layout).unwrap();
        let mut memory = VirtualBlockMemory {
            bytes: [0; 0x5000],
            interrupts: 0,
        };
        memory.bytes[0x4000..0x5000].fill(0x5a);
        let mut storage = VirtualBlockStorage([0; 4096]);
        let mut scratch = [0; 4096];

        let interrupt_object = ObjectId(0x161);
        let mut capabilities = CapabilitySpace::<1>::new();
        let interrupt_capability = capabilities
            .insert(interrupt_object, Rights::SIGNAL)
            .unwrap();
        let mut policy = InterruptPolicy::deny_all();
        policy.allow(48).unwrap();
        let mut vms = VmTable::<1>::new();
        let vm = vms.create(VIRTUAL_BLOCK_ITERATIONS + 1).unwrap();
        vms.mark_loaded(vm).unwrap();
        vms.start(vm).unwrap();

        let start = Instant::now();
        for sequence in 1..=VIRTUAL_BLOCK_ITERATIONS {
            let mut request = [0; 64];
            VirtualBlockRequest::write(1, sequence, 0, 1, 0x4000, 4096).encode(&mut request);
            memory.write(0x1000 + 128, &request);
            memory.write(0x1000, &sequence.to_le_bytes());
            memory.write(0x3000 + 64, &(sequence - 1).to_le_bytes());
            assert!(matches!(
                black_box(process_virtual_block_doorbell(
                    ExitDisposition::Io {
                        port: VIRTUAL_BLOCK_DOORBELL_PORT,
                        size: 4,
                        write: true,
                        value: VIRTUAL_BLOCK_DOORBELL_VALUE,
                    },
                    &mut device,
                    &mut bridge,
                    &mut memory,
                    &mut storage,
                    &mut scratch,
                ))
                .unwrap(),
                VirtualBlockProcessOutcome::Completed(_)
            ));
            assert_eq!(
                black_box(inject_virtual_block_interrupt(
                    &mut device,
                    &mut memory,
                    &mut vms,
                    vm,
                    0,
                    &policy,
                    &capabilities,
                    interrupt_capability,
                    interrupt_object,
                )),
                Ok(true)
            );
        }
        report(
            "virtual_block_doorbell_interrupt_policy",
            start.elapsed().as_nanos(),
            VIRTUAL_BLOCK_ITERATIONS,
        );
        assert_eq!(memory.interrupts, VIRTUAL_BLOCK_ITERATIONS);
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "manual affinity-pinned physical-core performance gate"]
    fn physical_cross_core_mailbox_round_trip_budget() {
        use mrml_kernel::OwnershipMailbox;
        use std::sync::{Arc, mpsc};
        use std::thread;

        const CROSS_CORE_ITERATIONS: u64 = 100_000;
        let [first_processor, second_processor] = windows_affinity::distinct_cores();
        let _main_affinity = windows_affinity::pin(first_processor.0, first_processor.1);
        let outbound = Arc::new(OwnershipMailbox::<u64>::new());
        let inbound = Arc::new(OwnershipMailbox::<u64>::new());
        let worker_outbound = outbound.clone();
        let worker_inbound = inbound.clone();
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let _worker_affinity = windows_affinity::pin(second_processor.0, second_processor.1);
            ready_sender.send(windows_affinity::current()).unwrap();
            for _ in 0..CROSS_CORE_ITERATIONS {
                let token = loop {
                    if let Some(token) = worker_outbound.take() {
                        break token;
                    }
                    core::hint::spin_loop();
                };
                let mut pending = token;
                loop {
                    match worker_inbound.publish(pending) {
                        Ok(()) => break,
                        Err((_, returned)) => {
                            pending = returned;
                            core::hint::spin_loop();
                        }
                    }
                }
            }
        });
        assert_eq!(ready_receiver.recv().unwrap(), second_processor);
        assert_eq!(windows_affinity::current(), first_processor);

        let start = Instant::now();
        for sequence in 0..CROSS_CORE_ITERATIONS {
            outbound.publish(black_box(sequence)).unwrap();
            let returned = loop {
                if let Some(token) = inbound.take() {
                    break token;
                }
                core::hint::spin_loop();
            };
            assert_eq!(returned, sequence);
        }
        let elapsed = start.elapsed().as_nanos();
        worker.join().unwrap();
        mrml_println!(
            "MRML_KERNEL_BENCH physical_cross_core_mailbox_round_trip_total_ns={} physical_cross_core_mailbox_round_trip_ns={} iterations={} first_group={} first_cpu={} second_group={} second_cpu={}",
            elapsed,
            elapsed / CROSS_CORE_ITERATIONS as u128,
            CROSS_CORE_ITERATIONS,
            first_processor.0,
            first_processor.1,
            second_processor.0,
            second_processor.1,
        );
        assert!(elapsed / (CROSS_CORE_ITERATIONS as u128) < 1_000_000);
    }
}
