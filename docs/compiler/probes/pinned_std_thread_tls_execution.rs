use std::cell::Cell;
use std::ffi::c_void;
use std::ptr;

type Handle = *mut c_void;
type ThreadStart = unsafe extern "system" fn(*mut c_void) -> u32;

unsafe extern "system" {
    fn CreateThread(
        attributes: *mut c_void,
        stack_size: usize,
        start: Option<ThreadStart>,
        parameter: *mut c_void,
        flags: u32,
        thread_id: *mut u32,
    ) -> Handle;
    fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    fn GetExitCodeThread(handle: Handle, exit_code: *mut u32) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
}

std::thread_local! {
    static VALUE: Cell<u32> = const { Cell::new(40) };
}

unsafe extern "system" fn thread_entry(_: *mut c_void) -> u32 {
    VALUE.with(|value| {
        let initial = value.get();
        value.set(initial + 2);
        if initial == 40 && value.get() == 42 {
            42
        } else {
            1
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn entry() -> u32 {
    VALUE.with(|value| value.set(value.get() + 1));
    // SAFETY: thread_entry has the Win32 callback ABI and needs no parameter.
    let thread = unsafe {
        CreateThread(
            ptr::null_mut(),
            0,
            Some(thread_entry),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        )
    };
    if thread.is_null() {
        return 1;
    }
    let mut child = 0u32;
    // SAFETY: the thread handle is valid and owned until CloseHandle below.
    let wait = unsafe { WaitForSingleObject(thread, u32::MAX) };
    // SAFETY: this handle is still open and child is a writable u32 out parameter.
    let read = unsafe { GetExitCodeThread(thread, &mut child) };
    // SAFETY: this is the only close of the owned handle and there is no later use.
    let closed = unsafe { CloseHandle(thread) };
    let main = VALUE.with(Cell::get);
    if wait == 0 && read != 0 && closed != 0 && child == 42 && main == 41 {
        42
    } else {
        1
    }
}
