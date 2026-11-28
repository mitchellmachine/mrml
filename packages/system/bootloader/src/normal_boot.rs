//! Release-policy entry. This path must never dispatch a bring-up fixture.

use mrml_kernel::{BootHandoff, BootPolicy, EarlyKernelContext};

pub(super) fn enter(handoff: &BootHandoff, _early: &EarlyKernelContext<'_>) -> ! {
    let Some(minimum_version) = embedded_minimum_version() else {
        observe(b"MRML:BOOT:FLOOR:INVALID\n");
        super::halt();
    };
    if let Err(error) = BootPolicy::production(minimum_version).validate(handoff.evidence()) {
        use mrml_kernel::BootValidationError;
        observe(match error {
            BootValidationError::SecureBootRequired => b"MRML:BOOT:POLICY:SECURE-BOOT\n",
            BootValidationError::MeasuredBootRequired => b"MRML:BOOT:POLICY:MEASUREMENT\n",
            BootValidationError::RollbackDetected => b"MRML:BOOT:POLICY:ROLLBACK\n",
            BootValidationError::CoherentReleaseRequired => b"MRML:BOOT:POLICY:RELEASE\n",
            _ => b"MRML:BOOT:POLICY:REJECTED\n",
        });
        super::halt();
    }
    observe(b"MRML:BOOT:POLICY:ACCEPTED\n");

    // No selection means no eligible supervisor. The observation profile can
    // still check the retained generic service as a separate diagnostic.
    if handoff.supervisor_selection().is_none() {
        observe(b"MRML:BOOT:SUPERVISOR:MISSING\n");
        #[cfg(feature = "normal-boot-observation")]
        check_retained_service(handoff);
        super::halt();
    }
    if check_retained_service(handoff) {
        observe(b"MRML:BOOT:SUPERVISOR:CHECKED\n");
    } else {
        observe(b"MRML:BOOT:SUPERVISOR:REJECTED\n");
    }

    // Checking the selection does not install guest mappings or start a VM.
    super::halt()
}

fn check_retained_service(handoff: &BootHandoff) -> bool {
    let Some(launch) = handoff.service() else {
        observe(b"MRML:BOOT:SERVICE:MISSING\n");
        return false;
    };
    let Ok(length) = usize::try_from(launch.artifact_length()) else {
        observe(b"MRML:BOOT:SERVICE:REJECTED\n");
        return false;
    };
    // SAFETY: normal entry follows complete handoff decoding and the boot
    // policy check. The loader retained the exact bounded service allocation
    // in a supervisor-only, read-only identity mapping. No guest has run.
    let bytes = unsafe {
        core::slice::from_raw_parts(launch.artifact_physical().get() as *const u8, length)
    };
    if mrml_kernel::BootServiceImage::check(launch, handoff.evidence().image_version(), bytes)
        .is_ok()
    {
        observe(b"MRML:BOOT:SERVICE:CHECKED\n");
        true
    } else {
        observe(b"MRML:BOOT:SERVICE:REJECTED\n");
        false
    }
}

fn embedded_minimum_version() -> Option<u64> {
    let bytes = option_env!("MRML_KERNEL_MIN_VERSION")?.as_bytes();
    if bytes.is_empty() || bytes.len() > 20 {
        return None;
    }
    let mut value = 0u64;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((byte - b'0') as u64)?;
    }
    (value != 0).then_some(value)
}

// Only the QEMU observation build contains debug-port writes. Neither the
// output nor the observer grants authority or changes the admission policy.
#[cfg(feature = "normal-boot-observation")]
fn observe(record: &[u8]) {
    for &byte in record {
        super::smp_trace(byte);
    }
}

#[cfg(not(feature = "normal-boot-observation"))]
const fn observe(_: &[u8]) {}
