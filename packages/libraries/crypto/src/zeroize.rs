use core::{
    ptr,
    sync::atomic::{compiler_fence, Ordering},
};

/// Best-effort erasure for owned scalar byte and word buffers.
///
/// Volatile stores make ordinary dead-store elimination inapplicable to these
/// writes, and the compiler fence prevents them from being reordered across
/// the call. This does not erase compiler-created copies, registers, caches,
/// swap, or hardware traces, and is not a formal compiler or hardware erasure
/// guarantee.
#[inline(never)]
pub(crate) fn volatile_zero<T: Copy + Default>(values: &mut [T]) {
    for value in values {
        // SAFETY: `value` comes from an exclusive reference, is aligned and
        // valid for one `T`, and `T::default()` is a valid value of `T`.
        unsafe { ptr::write_volatile(value, T::default()) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Best-effort volatile erasure for secret byte buffers owned by callers.
///
/// This has the same compiler and hardware limitations documented above and
/// does not establish a formal erasure guarantee.
pub fn erase_secret_bytes(values: &mut [u8]) {
    volatile_zero(values);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_byte_and_word_buffers() {
        let mut bytes = [0xa5u8; 32];
        volatile_zero(&mut bytes);
        assert_eq!(bytes, [0u8; 32]);

        let mut words = [u64::MAX; 8];
        volatile_zero(&mut words);
        assert_eq!(words, [0u64; 8]);
    }
}
