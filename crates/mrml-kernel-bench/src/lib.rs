#![no_std]

//! Host-only performance gates for `mrml-kernel`. Keeping this crate separate
//! prevents operating-system timing and output services from entering the UEFI
//! kernel dependency graph.

#[cfg(test)]
mod tests {
    use core::hint::black_box;
    use mrml_kernel::arch::x86_64::UserContext;
    use mrml_kernel::{
        CapabilitySpace, Endpoint, GuestMemory, GuestRegion, HostResourceHandle, KernelScheduler,
        ObjectId, PeriodicBalancer, PhysAddr, Priority, Rights, Scheduler, SchedulerLoad,
        SharedAccess, SharedEndpoint, SharedMemoryBindings, TaskRuntime, VmTable,
    };
    use mrml_runtime::{Instant, mrml_println};

    const ITERATIONS: u64 = 1_000_000;
    const MAX_NANOSECONDS_PER_OPERATION: u128 = 10_000;
    const SERVICE_ITERATIONS: u64 = 100_000;
    const MAX_SERVICE_NANOSECONDS_PER_OPERATION: u128 = 100_000;

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
                .capabilities_mut(receiver)
                .unwrap()
                .revoke(derived)
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
}
