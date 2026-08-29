#![no_std]

#[path = "../1.rs"]
mod generated;

pub use generated::*;

pub const MAX_BLOCK_TRANSFER_BYTES: u64 = 1024 * 1024;
pub const MAX_DEVICE_CATALOG_BYTES: u64 = 64 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views_and_handles_are_bounded_and_generational() {
        assert!(OpaqueHandle::new(4, 0).is_none());
        let session = OpaqueHandle::new(4, 7).unwrap();
        let output = BorrowedWriteView::within(0, MAX_BLOCK_TRANSFER_BYTES, MAX_BLOCK_TRANSFER_BYTES).unwrap();
        assert!(ReadRequest { session, lba: 9, sector_count: 2048, output }.validate());
        assert!(BorrowedWriteView::within(0, MAX_BLOCK_TRANSFER_BYTES + 1, MAX_BLOCK_TRANSFER_BYTES + 1)
            .is_some_and(|output| !ReadRequest { session, lba: 9, sector_count: 2048, output }.validate()));
    }
}
