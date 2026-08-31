use std::cell::Cell;
use std::sync::atomic::{AtomicU32, Ordering};

static INITIALIZATIONS: AtomicU32 = AtomicU32::new(0);

#[inline(never)]
fn initial_value() -> Cell<u32> {
    INITIALIZATIONS.fetch_add(1, Ordering::Relaxed);
    Cell::new(40)
}

std::thread_local! {
    static VALUE: Cell<u32> = initial_value();
}

#[unsafe(no_mangle)]
pub extern "C" fn entry() -> u32 {
    let first = VALUE.with(|value| {
        value.set(value.get() + 2);
        value.get()
    });
    let second = VALUE.with(Cell::get);
    if first == 42 && second == 42 && INITIALIZATIONS.load(Ordering::Relaxed) == 1 {
        42
    } else {
        1
    }
}
