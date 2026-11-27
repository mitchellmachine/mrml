#![forbid(unsafe_code)]

//! Linux host tests that exercise the public xHCI, USB disk and FAT32 APIs.

mod tests;

pub use tests::with_emulated_probe_disk;
