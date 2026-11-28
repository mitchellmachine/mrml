//! Release-policy entry. This path must never dispatch a bring-up fixture.

use mrml_kernel::{BootHandoff, BootPolicy, EarlyKernelContext};

pub(super) fn enter(handoff: &BootHandoff, _early: &EarlyKernelContext<'_>) -> ! {
    let minimum_version = embedded_minimum_version().unwrap_or_else(|| super::halt());
    BootPolicy::production(minimum_version)
        .validate(handoff.evidence())
        .unwrap_or_else(|_| super::halt());

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
