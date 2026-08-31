use std::cell::Cell;

std::thread_local! {
    static VALUE: Cell<u32> = const { Cell::new(40) };
}

#[unsafe(no_mangle)]
pub extern "C" fn entry() -> u32 {
    VALUE.with(|value| {
        value.set(value.get() + 2);
        value.get()
    })
}
