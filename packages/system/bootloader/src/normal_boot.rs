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

    // No authenticated supervisor is wired to this entry yet. Keep the
    // machine parked rather than starting a diagnostic or native workload.
    super::halt()
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
