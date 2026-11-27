//! Read-only storage adapter for the existing generation-bound microVM call slot.
//!
//! The queue carries a canonical one-sector READ with an output view at zero.
//! Its response is the canonical status followed by data only on success. This
//! adapter neither creates guest mappings nor authenticates backend selection.

use mrml_interface_storage_block_provider_v1::{
    BlockProviderReadTransport, BorrowedWriteView, INTERFACE_FINGERPRINT, INTERFACE_GENERATION,
    OP_READ, OpaqueHandle, ProtocolError, READ_REQUEST_BYTES, READ_RESPONSE_BYTES, ReadError,
    decode_read_request, decode_read_response, encode_read_request, encode_read_response,
};
use mrml_kernel::{
    Capability, CapabilitySpace, MicrovmInterfaceQueueConsumer, MicrovmInterfaceQueueError,
    MicrovmInterfaceQueueIdentity, MicrovmInterfaceQueuePair, MicrovmInterfaceQueueProvider,
    MicrovmInterfaceRequestNotification, MicrovmInterfaceResponseNotification,
    MicrovmPeerPageProjection,
};

pub const MICROVM_BLOCK_READ_BYTES: usize = 512;
const REPLY_BYTES: usize = READ_RESPONSE_BYTES + MICROVM_BLOCK_READ_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MicrovmBlockReadError {
    Queue(MicrovmInterfaceQueueError),
    Wire(ProtocolError),
    Provider(ReadError),
}

impl From<MicrovmInterfaceQueueError> for MicrovmBlockReadError {
    fn from(error: MicrovmInterfaceQueueError) -> Self {
        Self::Queue(error)
    }
}

impl From<ProtocolError> for MicrovmBlockReadError {
    fn from(error: ProtocolError) -> Self {
        Self::Wire(error)
    }
}

pub struct MicrovmBlockReadConsumer {
    queue: MicrovmInterfaceQueueConsumer,
    session: OpaqueHandle,
}

pub struct MicrovmBlockReadProvider {
    queue: MicrovmInterfaceQueueProvider,
    session: OpaqueHandle,
}

/// The caller must use the session and generations from the admitted binding,
/// not identities supplied by either peer's queue bytes.
#[allow(clippy::too_many_arguments)]
pub fn bind_microvm_block_read<const C: usize>(
    provider_generation: u64,
    system_generation: u64,
    policy_generation: u64,
    binding_generation: u64,
    session: OpaqueHandle,
    projection: &MicrovmPeerPageProjection,
    consumer: Capability,
    provider: Capability,
    capabilities: &CapabilitySpace<C>,
) -> Result<
    (
        MicrovmInterfaceQueueIdentity,
        MicrovmBlockReadConsumer,
        MicrovmBlockReadProvider,
    ),
    MicrovmBlockReadError,
> {
    let identity = MicrovmInterfaceQueueIdentity::new(
        INTERFACE_FINGERPRINT,
        INTERFACE_GENERATION,
        provider_generation,
        system_generation,
        policy_generation,
        binding_generation,
    )?;
    let (consumer, provider) =
        MicrovmInterfaceQueuePair::bind(identity, projection, consumer, provider, capabilities)?
            .split();
    Ok((
        identity,
        MicrovmBlockReadConsumer {
            queue: consumer,
            session,
        },
        MicrovmBlockReadProvider {
            queue: provider,
            session,
        },
    ))
}

impl MicrovmBlockReadConsumer {
    pub fn initialize<const C: usize>(
        &self,
        page: &mut [u8],
        projection: &MicrovmPeerPageProjection,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<(), MicrovmBlockReadError> {
        self.queue.initialize(page, projection, capabilities)?;
        Ok(())
    }

    pub fn submit<const C: usize>(
        &self,
        lba: u64,
        page: &mut [u8],
        projection: &MicrovmPeerPageProjection,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<MicrovmInterfaceRequestNotification, MicrovmBlockReadError> {
        let output = BorrowedWriteView::within(
            0,
            MICROVM_BLOCK_READ_BYTES as u64,
            MICROVM_BLOCK_READ_BYTES as u64,
        )
        .ok_or(ProtocolError::InvalidRequest)?;
        let request = encode_read_request(self.session, lba, 1, output)?;
        Ok(self
            .queue
            .submit(page, projection, capabilities, OP_READ, &request)?)
    }

    /// Does not publish any bytes to the caller before status and length agree.
    pub fn complete<const C: usize>(
        &mut self,
        page: &mut [u8],
        projection: &MicrovmPeerPageProjection,
        capabilities: &CapabilitySpace<C>,
        notification: MicrovmInterfaceResponseNotification,
        output: &mut [u8; MICROVM_BLOCK_READ_BYTES],
    ) -> Result<(), MicrovmBlockReadError> {
        if notification.operation() != OP_READ {
            return Err(ProtocolError::InvalidResponse.into());
        }
        let mut reply = [0; REPLY_BYTES];
        let (_, length) = self.queue.consume_response(
            page,
            projection,
            capabilities,
            notification,
            &mut reply,
        )?;
        if length < READ_RESPONSE_BYTES {
            return Err(ProtocolError::InvalidResponse.into());
        }
        let status = reply[..READ_RESPONSE_BYTES].try_into().unwrap();
        match decode_read_response(status, MICROVM_BLOCK_READ_BYTES as u64)? {
            Ok(bytes) if bytes == MICROVM_BLOCK_READ_BYTES as u64 && length == REPLY_BYTES => {
                output.copy_from_slice(&reply[READ_RESPONSE_BYTES..]);
                Ok(())
            }
            Err(error) if length == READ_RESPONSE_BYTES => {
                Err(MicrovmBlockReadError::Provider(error))
            }
            _ => Err(ProtocolError::InvalidResponse.into()),
        }
    }
}

impl MicrovmBlockReadProvider {
    pub fn serve<const C: usize>(
        &mut self,
        page: &mut [u8],
        projection: &MicrovmPeerPageProjection,
        capabilities: &CapabilitySpace<C>,
        notification: MicrovmInterfaceRequestNotification,
        backend: &mut impl BlockProviderReadTransport,
    ) -> Result<MicrovmInterfaceResponseNotification, MicrovmBlockReadError> {
        if notification.operation() != OP_READ {
            return Err(ProtocolError::InvalidRequest.into());
        }
        let mut frame = [0; READ_REQUEST_BYTES];
        let (sequence, operation, length) =
            self.queue
                .receive_request(page, projection, capabilities, notification, &mut frame)?;
        let mut reply = [0; REPLY_BYTES];
        let (status, data_bytes) = match (length == READ_REQUEST_BYTES)
            .then(|| decode_read_request(&frame, MICROVM_BLOCK_READ_BYTES as u64))
        {
            Some(Ok(request)) if request.session != self.session => {
                (Err(ReadError::StaleObject), 0)
            }
            Some(Ok(request))
                if request.sector_count == 1
                    && request.output.offset() == 0
                    && request.output.length() == MICROVM_BLOCK_READ_BYTES as u64 =>
            {
                let result = backend
                    .read(&frame, &mut reply[READ_RESPONSE_BYTES..])
                    .and_then(|wire| decode_read_response(&wire, MICROVM_BLOCK_READ_BYTES as u64));
                match result {
                    Ok(Ok(bytes)) if bytes == MICROVM_BLOCK_READ_BYTES as u64 => {
                        (Ok(bytes), MICROVM_BLOCK_READ_BYTES)
                    }
                    Ok(Err(error)) => (Err(error), 0),
                    _ => (Err(ReadError::IoFailure), 0),
                }
            }
            _ => (Err(ReadError::InvalidRequest), 0),
        };
        reply[..READ_RESPONSE_BYTES].copy_from_slice(&encode_read_response(status));
        Ok(self.queue.respond(
            page,
            projection,
            capabilities,
            sequence,
            operation,
            &reply[..READ_RESPONSE_BYTES + data_bytes],
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReadOnlyBlockImage;
    use mrml_kernel::{
        MemoryPoolTable, ObjectId, PAGE_SIZE, Rights, reserve_microvm_peer_page_projection,
    };

    struct Counted<'a> {
        image: ReadOnlyBlockImage<'a>,
        accesses: usize,
    }

    impl BlockProviderReadTransport for Counted<'_> {
        fn read(
            &mut self,
            frame: &[u8; READ_REQUEST_BYTES],
            output: &mut [u8],
        ) -> Result<[u8; READ_RESPONSE_BYTES], ProtocolError> {
            self.accesses += 1;
            self.image.read(frame, output)
        }
    }

    #[test]
    fn retired_request_and_completion_cannot_reach_replacement() {
        let mut caps = CapabilitySpace::<8>::new();
        let mut memory = MemoryPoolTable::<1, 2, 4>::new(0x91).unwrap();
        let (pool, quota) = memory
            .create_root(
                2,
                4,
                0,
                Rights::ALLOCATE
                    .union(Rights::CONTROL)
                    .union(Rights::INSPECT),
                &mut caps,
            )
            .unwrap();
        let target = Rights::MAP.union(Rights::INSPECT).union(Rights::CONTROL);
        let client = caps.insert(ObjectId(0x92), target).unwrap();
        let server = caps.insert(ObjectId(0x93), target).unwrap();

        let (old, _) = reserve_microvm_peer_page_projection(
            &mut memory,
            pool,
            quota,
            client,
            server,
            0x700,
            0x800,
            &mut caps,
        )
        .unwrap();
        let old_session = OpaqueHandle::new(1, 7).unwrap();
        let (_, old_client, mut old_server) =
            bind_microvm_block_read(7, 1, 1, 1, old_session, &old, client, server, &caps).unwrap();
        let mut old_page = [0; PAGE_SIZE as usize];
        let original_bytes = [0x71; 512];
        let mut original = Counted {
            image: ReadOnlyBlockImage::new(&original_bytes, 512, old_session).unwrap(),
            accesses: 0,
        };
        old_client.initialize(&mut old_page, &old, &caps).unwrap();
        let stale_request = old_client.submit(0, &mut old_page, &old, &caps).unwrap();
        let stale_completion = old_server
            .serve(&mut old_page, &old, &caps, stale_request, &mut original)
            .unwrap();
        assert_eq!(original.accesses, 1);
        // Retire the old queue's authority before binding any replacement.
        caps.revoke(server).unwrap();
        assert!(matches!(
            old_server.serve(&mut old_page, &old, &caps, stale_request, &mut original),
            Err(MicrovmBlockReadError::Queue(
                MicrovmInterfaceQueueError::Authority(_)
            ))
        ));
        assert_eq!(original.accesses, 1);
        let server = caps.insert(ObjectId(0x94), target).unwrap();
        let (new, _) = reserve_microvm_peer_page_projection(
            &mut memory,
            pool,
            quota,
            client,
            server,
            0x701,
            0x801,
            &mut caps,
        )
        .unwrap();
        let new_session = OpaqueHandle::new(1, 8).unwrap();
        let (identity, mut new_client, mut new_server) =
            bind_microvm_block_read(8, 1, 1, 2, new_session, &new, client, server, &caps).unwrap();
        let mut page = [0; PAGE_SIZE as usize];
        let new_bytes = [0x82; 512];
        let mut replacement = Counted {
            image: ReadOnlyBlockImage::new(&new_bytes, 512, new_session).unwrap(),
            accesses: 0,
        };
        new_client.initialize(&mut page, &new, &caps).unwrap();
        let request = new_client.submit(0, &mut page, &new, &caps).unwrap();
        assert_eq!(
            new_server.serve(&mut page, &new, &caps, stale_request, &mut replacement),
            Err(MicrovmInterfaceQueueError::InvalidNotification.into())
        );
        assert_eq!(replacement.accesses, 0);
        let completion = new_server
            .serve(&mut page, &new, &caps, request, &mut replacement)
            .unwrap();
        let mut output = [0xa5; 512];
        assert_eq!(
            new_client.complete(&mut page, &new, &caps, stale_completion, &mut output),
            Err(MicrovmInterfaceQueueError::InvalidNotification.into())
        );
        assert_eq!(output, [0xa5; 512]);
        new_client
            .complete(&mut page, &new, &caps, completion, &mut output)
            .unwrap();
        assert_eq!(output, new_bytes);
        assert_eq!(replacement.accesses, 1);

        // Even with a genuine notification from the replacement route, the
        // peer cannot name a stale block session in the canonical READ.
        let (raw_client, _) =
            MicrovmInterfaceQueuePair::bind(identity, &new, client, server, &caps)
                .unwrap()
                .split();
        page.fill(0);
        raw_client.initialize(&mut page, &new, &caps).unwrap();
        let (_, new_server) =
            MicrovmInterfaceQueuePair::bind(identity, &new, client, server, &caps)
                .unwrap()
                .split();
        let mut new_server = MicrovmBlockReadProvider {
            queue: new_server,
            session: new_session,
        };
        let frame = encode_read_request(
            old_session,
            0,
            1,
            BorrowedWriteView::within(0, 512, 512).unwrap(),
        )
        .unwrap();
        let request = raw_client
            .submit(&mut page, &new, &caps, OP_READ, &frame)
            .unwrap();
        let completion = new_server
            .serve(&mut page, &new, &caps, request, &mut replacement)
            .unwrap();
        let mut raw_client = MicrovmBlockReadConsumer {
            queue: raw_client,
            session: new_session,
        };
        assert_eq!(
            raw_client.complete(&mut page, &new, &caps, completion, &mut output),
            Err(MicrovmBlockReadError::Provider(ReadError::StaleObject))
        );
        assert_eq!(replacement.accesses, 1);
        assert_eq!(output, new_bytes);
    }
}
