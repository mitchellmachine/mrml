use core::alloc::{GlobalAlloc, Layout};
use core::marker::Unsize;
use core::ops::{CoerceUnsized, Deref, DerefMut};
use core::ptr::NonNull;

/// A uniquely owned value allocated by the MRML platform allocator.
///
/// `Owned` supports nightly unsizing so callers can own trait objects without
/// using Rust's global `alloc` crate.
pub struct Owned<T: ?Sized> {
    pointer: NonNull<T>,
}

unsafe impl<T: Send + ?Sized> Send for Owned<T> {}
unsafe impl<T: Sync + ?Sized> Sync for Owned<T> {}
// `Owned` never changes its pointee address, moves out through `DerefMut`, or
// deallocates before dropping the pointee in place.
unsafe impl<T: ?Sized> core::pin::PinSafePointer for Owned<T> {}

impl<T> Owned<T> {
    pub fn new(value: T) -> Self {
        let layout = Layout::new::<T>();
        let pointer = unsafe { allocator().alloc(layout) }.cast::<T>();
        let pointer = NonNull::new(pointer).unwrap_or_else(|| panic!("MRML allocation failed"));
        unsafe { pointer.as_ptr().write(value) };
        Self { pointer }
    }
}

impl<T: ?Sized, U: ?Sized> CoerceUnsized<Owned<U>> for Owned<T> where T: Unsize<U> {}

impl<T: ?Sized> Deref for Owned<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { self.pointer.as_ref() }
    }
}

impl<T: ?Sized> DerefMut for Owned<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { self.pointer.as_mut() }
    }
}

impl<T: ?Sized> Drop for Owned<T> {
    fn drop(&mut self) {
        unsafe {
            let layout = Layout::for_value(self.pointer.as_ref());
            self.pointer.as_ptr().drop_in_place();
            allocator().dealloc(self.pointer.as_ptr().cast(), layout);
        }
    }
}

#[cfg(windows)]
fn allocator() -> mrml_windows::SystemAllocator {
    mrml_windows::SystemAllocator
}

#[cfg(unix)]
fn allocator() -> mrml_linux::SystemAllocator {
    mrml_linux::SystemAllocator
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DROPS: AtomicUsize = AtomicUsize::new(0);

    trait DynamicValue {
        fn value(&self) -> usize;
    }

    struct Value(usize);

    #[repr(align(32))]
    struct Aligned32(u8);
    #[repr(align(64))]
    struct Aligned64(u8);
    #[repr(align(256))]
    struct Aligned256(u8);
    #[repr(align(4096))]
    struct Aligned4096(u8);

    impl DynamicValue for Value {
        fn value(&self) -> usize {
            self.0
        }
    }

    impl Drop for Value {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn owns_and_drops_dynamic_values() {
        DROPS.store(0, Ordering::Relaxed);
        let value: Owned<dyn DynamicValue> = Owned::new(Value(31));
        assert_eq!(value.value(), 31);
        drop(value);
        assert_eq!(DROPS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn owned_honors_overaligned_values() {
        let a32 = Owned::new(Aligned32(1));
        let a64 = Owned::new(Aligned64(2));
        let a256 = Owned::new(Aligned256(3));
        let a4096 = Owned::new(Aligned4096(4));
        assert_eq!((&*a32 as *const Aligned32 as usize) % 32, 0);
        assert_eq!((&*a64 as *const Aligned64 as usize) % 64, 0);
        assert_eq!((&*a256 as *const Aligned256 as usize) % 256, 0);
        assert_eq!((&*a4096 as *const Aligned4096 as usize) % 4096, 0);
        assert_eq!((a32.0, a64.0, a256.0, a4096.0), (1, 2, 3, 4));
    }
}
