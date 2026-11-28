#![forbid(unsafe_code)]

//! Shared disposable QEMU fixture for service and MicroVM integration tests.

mod tests;

pub use tests::{
    CommandIo, FIXTURE_DATA_SECTOR, FIXTURE_PARTITION_START, FIXTURE_VOLUME_SERIAL, PreflightIo,
    ProbePartition, with_emulated_bulk_read_probe, with_emulated_bulk_setup_probe,
    with_emulated_bulk_write_probe, with_emulated_command_probe, with_emulated_enumeration_probe,
    with_emulated_probe_disk, with_emulated_probe_preflight, with_emulated_service_partition,
};
