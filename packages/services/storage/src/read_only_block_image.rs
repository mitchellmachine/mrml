//! Immutable, in-memory backing for the canonical block-provider read ABI.

use mrml_interface_storage_block_provider_v1::{
    BlockProviderReadTransport, OpaqueHandle, ProtocolError, READ_REQUEST_BYTES,
    READ_RESPONSE_BYTES, ReadError, decode_read_request, encode_read_response,
};

/// An already admitted, immutable image and its exact block session.
///
/// The owner must supply the image and authenticated session. This object is
/// only a data-plane adapter: a wire token never authenticates an IPC sender
/// or authorizes a shared-memory copy. The service must enforce those
/// boundaries before passing the request and local scratch here.
pub struct ReadOnlyBlockImage<'a> {
    image: &'a [u8],
    sector_bytes: usize,
    session: OpaqueHandle,
}

impl<'a> ReadOnlyBlockImage<'a> {
    pub fn new(image: &'a [u8], sector_bytes: usize, session: OpaqueHandle) -> Option<Self> {
        if !matches!(sector_bytes, 512 | 1024 | 2048 | 4096)
            || image.is_empty()
            || !image.len().is_multiple_of(sector_bytes)
        {
            return None;
        }
        Some(Self {
            image,
            sector_bytes,
            session,
        })
    }

    pub fn sector_count(&self) -> usize {
        self.image.len() / self.sector_bytes
    }

    fn read_range(
        &self,
        request: &[u8; READ_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<Result<u64, ReadError>, ProtocolError> {
        let decoded = decode_read_request(request, memory.len() as u64)?;
        if decoded.session != self.session {
            return Ok(Err(ReadError::StaleObject));
        }
        let checked = || {
            let length = usize::try_from(decoded.sector_count)
                .ok()?
                .checked_mul(self.sector_bytes)?;
            if decoded.output.length() != length as u64 {
                return None;
            }
            let source = usize::try_from(decoded.lba)
                .ok()?
                .checked_mul(self.sector_bytes)?;
            let start = usize::try_from(decoded.output.offset()).ok()?;
            Some((source..source.checked_add(length)?, start..start.checked_add(length)?))
        };
        let Some((source, output)) = checked() else {
            return Ok(Err(ReadError::InvalidRequest));
        };
        let (Some(source), Some(output)) = (self.image.get(source), memory.get_mut(output)) else {
            return Ok(Err(ReadError::InvalidRequest));
        };
        output.copy_from_slice(source);
        Ok(Ok(decoded.output.length()))
    }
}

impl BlockProviderReadTransport for ReadOnlyBlockImage<'_> {
    fn read(
        &mut self,
        request: &[u8; READ_REQUEST_BYTES],
        memory: &mut [u8],
    ) -> Result<[u8; READ_RESPONSE_BYTES], ProtocolError> {
        self.read_range(request, memory).map(encode_read_response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_interface_storage_block_provider_v1::{
        BorrowedWriteView, decode_read_response, encode_read_request,
    };

    #[test]
    fn copies_only_the_exact_borrowed_range_from_the_admitted_session() {
        let mut image = [0x22; 1024];
        image[512..].fill(0x55);
        let session = OpaqueHandle::new(1, 2).unwrap();
        let mut provider = ReadOnlyBlockImage::new(&image, 512, session).unwrap();
        assert_eq!(provider.sector_count(), 2);
        let mut memory = [0xaa; 524];
        let output = BorrowedWriteView::within(5, 512, memory.len() as u64).unwrap();
        let request = encode_read_request(session, 1, 1, output).unwrap();
        let response = provider.read(&request, &mut memory).unwrap();
        assert_eq!(decode_read_response(&response, 512), Ok(Ok(512)));
        assert_eq!(memory[..5], [0xaa; 5]);
        assert_eq!(memory[5..517], [0x55; 512]);
        assert_eq!(memory[517..], [0xaa; 7]);
    }

    #[test]
    fn stale_sessions_and_bad_extents_do_not_publish_bytes() {
        let image = [0x33; 1024];
        let session = OpaqueHandle::new(1, 2).unwrap();
        assert!(ReadOnlyBlockImage::new(&image[..513], 512, session).is_none());
        let mut provider = ReadOnlyBlockImage::new(&image, 512, session).unwrap();
        let mut memory = [0xaa; 1024];
        let view = BorrowedWriteView::within(0, 512, 1024).unwrap();
        for (handle, lba, sectors, expected) in [
            (OpaqueHandle::new(1, 1).unwrap(), 0, 1, ReadError::StaleObject),
            (session, 2, 1, ReadError::InvalidRequest),
            (session, u64::MAX, 1, ReadError::InvalidRequest),
            (session, 0, 2, ReadError::InvalidRequest),
        ] {
            let request = encode_read_request(handle, lba, sectors, view).unwrap();
            let response = provider.read(&request, &mut memory).unwrap();
            assert_eq!(decode_read_response(&response, 512), Ok(Err(expected)));
            assert_eq!(memory, [0xaa; 1024]);
        }
        let mut wrong_operation = encode_read_request(session, 0, 1, view).unwrap();
        wrong_operation[52..56].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(
            provider.read(&wrong_operation, &mut memory),
            Err(ProtocolError::InvalidHeader)
        );
        assert_eq!(memory, [0xaa; 1024]);
    }
}
