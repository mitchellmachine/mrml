#![no_std]

#[path = "../1.rs"]
mod generated;

pub use generated::*;

pub const MAX_FILESYSTEM_TRANSFER_BYTES: u64 = 1024 * 1024;
pub const MAX_FILESYSTEM_REPORT_BYTES: u64 = 64 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_views_and_mount_generations_are_explicit() {
        let volume = OpaqueHandle::new(2, 5).unwrap();
        let file = OpaqueHandle::new(9, 3).unwrap();
        let output = BorrowedWriteView::within(0, MAX_FILESYSTEM_TRANSFER_BYTES, MAX_FILESYSTEM_TRANSFER_BYTES).unwrap();
        assert!(ReadRequest { volume, generation: 11, file, offset: 0, output }.validate());
        let oversized = BorrowedWriteView::within(0, MAX_FILESYSTEM_TRANSFER_BYTES + 1, MAX_FILESYSTEM_TRANSFER_BYTES + 1).unwrap();
        assert!(!ReadRequest { volume, generation: 11, file, offset: 0, output: oversized }.validate());
    }
}
