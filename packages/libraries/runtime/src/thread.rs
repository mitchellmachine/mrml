use crate::Vector;
use core::ffi::c_void;

pub fn available_parallelism() -> usize {
    #[cfg(windows)]
    return mrml_windows::processor_count();
    #[cfg(unix)]
    return mrml_linux::processor_count();
}

pub fn yield_now() {
    #[cfg(windows)]
    mrml_windows::yield_now();
    #[cfg(unix)]
    mrml_linux::yield_now();
}

struct ThreadStart<F> {
    operation: F,
    _non_zero_sized: u8,
}

pub fn spawn_detached<F>(operation: F) -> Result<(), F>
where
    F: FnOnce() + Send + 'static,
{
    let mut storage = match Vector::with_capacity(1) {
        Ok(storage) => storage,
        Err(_) => return Err(operation),
    };
    storage.push(ThreadStart {
        operation,
        _non_zero_sized: 0,
    });
    let (pointer, _, _) = storage.into_raw_parts();

    #[cfg(windows)]
    let started = unsafe { mrml_windows::spawn_detached_thread(pointer.cast(), run::<F>) };
    #[cfg(unix)]
    let started = unsafe { mrml_linux::spawn_detached_thread(pointer.cast(), run::<F>) };

    if started {
        Ok(())
    } else {
        let mut storage = unsafe { Vector::from_raw_parts(pointer, 1, 1) };
        Err(storage
            .pop()
            .expect("thread start storage missing")
            .operation)
    }
}

pub struct JoinHandle {
    #[cfg(windows)]
    native: mrml_windows::NativeThread,
    #[cfg(unix)]
    native: mrml_linux::NativeThread,
}

impl JoinHandle {
    /// Waits for confirmed native worker retirement.
    pub fn join(self) -> bool {
        self.native.join()
    }
}

pub fn spawn_joinable<F>(operation: F) -> Result<JoinHandle, F>
where
    F: FnOnce() + Send + 'static,
{
    let mut storage = match Vector::with_capacity(1) {
        Ok(storage) => storage,
        Err(_) => return Err(operation),
    };
    storage.push(ThreadStart {
        operation,
        _non_zero_sized: 0,
    });
    let (pointer, _, _) = storage.into_raw_parts();

    #[cfg(windows)]
    let native = unsafe { mrml_windows::spawn_joinable_thread(pointer.cast(), run::<F>) };
    #[cfg(unix)]
    let native = unsafe { mrml_linux::spawn_joinable_thread(pointer.cast(), run::<F>) };

    match native {
        Some(native) => Ok(JoinHandle { native }),
        None => {
            let mut storage = unsafe { Vector::from_raw_parts(pointer, 1, 1) };
            Err(storage
                .pop()
                .expect("thread start storage missing")
                .operation)
        }
    }
}

#[cfg(windows)]
unsafe extern "system" fn run<F>(context: *mut c_void) -> u32
where
    F: FnOnce() + Send + 'static,
{
    run_owned::<F>(context);
    0
}

#[cfg(unix)]
unsafe extern "C" fn run<F>(context: *mut c_void) -> *mut c_void
where
    F: FnOnce() + Send + 'static,
{
    run_owned::<F>(context);
    core::ptr::null_mut()
}

fn run_owned<F>(context: *mut c_void)
where
    F: FnOnce() + Send + 'static,
{
    let mut storage = unsafe { Vector::from_raw_parts(context.cast::<ThreadStart<F>>(), 1, 1) };
    let start = storage.pop().expect("thread start storage missing");
    drop(storage);
    (start.operation)();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Shared;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::time::Duration;

    #[test]
    fn detached_thread_owns_and_runs_closure() {
        let value = Shared::new(AtomicUsize::new(0));
        let worker_value = value.clone();
        assert!(spawn_detached(move || worker_value.store(42, Ordering::Release)).is_ok());

        let deadline = crate::Instant::now();
        while value.load(Ordering::Acquire) != 42 && deadline.elapsed() < Duration::from_secs(2) {
            #[cfg(windows)]
            mrml_windows::sleep_millis(1);
            #[cfg(unix)]
            mrml_linux::sleep_millis(1);
        }
        assert_eq!(value.load(Ordering::Acquire), 42);
    }

    #[test]
    fn joinable_thread_confirms_retirement_before_return() {
        let value = Shared::new(AtomicUsize::new(0));
        let worker_value = value.clone();
        let worker = match spawn_joinable(move || worker_value.store(7, Ordering::Release)) {
            Ok(worker) => worker,
            Err(_) => panic!("joinable thread creation failed"),
        };
        assert!(worker.join());
        assert_eq!(value.load(Ordering::Acquire), 7);
    }
}
