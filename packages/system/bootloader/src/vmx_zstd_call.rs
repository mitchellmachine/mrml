//! Fixed mailbox for the opt-in VMX Zstd caller/monitor regression.

#[cfg(feature = "vmx-kernel-payload")]
use mrml_interface_zstd_v3::{
    BorrowedReadView, BorrowedWriteView, decode_decompress_response, encode_decompress_request,
};
use mrml_interface_zstd_v3::{DECOMPRESS_REQUEST_BYTES, DECOMPRESS_RESPONSE_BYTES};

pub(super) const CALL_GPA: usize = 0x15_000;
#[cfg(feature = "vmx-kernel-payload")]
pub(super) const CALL_VA: u64 = 0xffff_8000_0000_0000 + CALL_GPA as u64;
#[cfg(feature = "vmx-kernel-payload")]
pub(super) const CONTENT: usize = 3;
const FRAME: usize = 12;
#[cfg(feature = "vmx-kernel-payload")]
const OUTPUT: usize = 32;
const MEMORY: usize = 64;
pub(super) const REQUEST: usize = DECOMPRESS_REQUEST_BYTES + FRAME;
pub(super) const REPLY: usize = DECOMPRESS_RESPONSE_BYTES + MEMORY;

#[cfg(feature = "vmx-kernel-payload")]
pub(super) fn encode(content: [u8; CONTENT]) -> Option<[u8; REQUEST]> {
    let input = BorrowedReadView::within(0, FRAME as u64, MEMORY as u64)?;
    let output = BorrowedWriteView::within(OUTPUT as u64, CONTENT as u64, MEMORY as u64)?;
    let mut request = [0; REQUEST];
    request[..DECOMPRESS_REQUEST_BYTES]
        .copy_from_slice(&encode_decompress_request(input, output).ok()?);
    let header = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 3, 0x19, 0, 0];
    request[DECOMPRESS_REQUEST_BYTES..REQUEST - CONTENT].copy_from_slice(&header);
    request[REQUEST - CONTENT..].copy_from_slice(&content);
    Some(request)
}

#[cfg(feature = "vmx-kernel-payload")]
pub(super) fn valid_reply(reply: &[u8; REPLY], expected: [u8; CONTENT]) -> bool {
    let (wire, memory) = reply.split_at(DECOMPRESS_RESPONSE_BYTES);
    decode_decompress_response(wire.try_into().expect("fixed response prefix"))
        == Ok(Ok(CONTENT as u64))
        && memory[OUTPUT..OUTPUT + CONTENT] == expected
}
