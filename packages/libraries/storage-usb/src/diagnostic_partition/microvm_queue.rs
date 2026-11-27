//! One fixed-size diagnostic write over a generation-bound MicroVM call slot.
//! The supervisor still owns peer mappings and the device/partition leases.

use super::{DiagnosticPartition, DiagnosticPartitionError};
use crate::{BulkTransport, SECTOR_BYTES};
use mrml_interface_storage_block_provider_v1::{
    BorrowedReadView, INTERFACE_FINGERPRINT, INTERFACE_GENERATION, OP_WRITE, OpaqueHandle,
    ProtocolError, WRITE_REQUEST_BYTES, WRITE_RESPONSE_BYTES, WriteError, decode_write_response,
    encode_write_request, encode_write_response,
};
use mrml_kernel::{
    Capability, CapabilitySpace, MicrovmInterfaceQueueConsumer, MicrovmInterfaceQueueError,
    MicrovmInterfaceQueueIdentity, MicrovmInterfaceQueuePair, MicrovmInterfaceQueueProvider,
    MicrovmInterfaceRequestNotification, MicrovmInterfaceResponseNotification,
    MicrovmPeerPageProjection,
};

const FRAME_BYTES: usize = WRITE_REQUEST_BYTES + SECTOR_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeQueueError {
    Queue(MicrovmInterfaceQueueError),
    Protocol(ProtocolError),
    Provider(WriteError),
    /// The operation may already have changed the medium. Do not replay it.
    CompletionUncertain,
}

impl From<MicrovmInterfaceQueueError> for ProbeQueueError {
    fn from(error: MicrovmInterfaceQueueError) -> Self {
        Self::Queue(error)
    }
}

impl From<ProtocolError> for ProbeQueueError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeQueueGenerations {
    pub provider: u64,
    pub system: u64,
    pub policy: u64,
    pub binding: u64,
}

pub struct ProbeQueueConsumer {
    queue: MicrovmInterfaceQueueConsumer,
    session: OpaqueHandle,
    completion_uncertain: bool,
}

pub struct ProbeQueueProvider<'a, T: BulkTransport> {
    queue: MicrovmInterfaceQueueProvider,
    partition: DiagnosticPartition<'a, T>,
    completion_uncertain: bool,
}

/// Binds an already opened partition to the exact authorized peer projection.
/// The supervisor selects both peers and generations, and controls publication.
pub fn bind_probe_write<'a, T: BulkTransport, const C: usize>(
    partition: DiagnosticPartition<'a, T>,
    generations: ProbeQueueGenerations,
    projection: &MicrovmPeerPageProjection,
    consumer: Capability,
    provider: Capability,
    capabilities: &CapabilitySpace<C>,
) -> Result<(ProbeQueueConsumer, ProbeQueueProvider<'a, T>), ProbeQueueError> {
    let identity = MicrovmInterfaceQueueIdentity::new(
        INTERFACE_FINGERPRINT,
        INTERFACE_GENERATION,
        generations.provider,
        generations.system,
        generations.policy,
        generations.binding,
    )?;
    let (client, server) =
        MicrovmInterfaceQueuePair::bind(identity, projection, consumer, provider, capabilities)?
            .split();
    Ok((
        ProbeQueueConsumer {
            queue: client,
            session: partition.assignment.partition_session,
            completion_uncertain: false,
        },
        ProbeQueueProvider {
            queue: server,
            partition,
            completion_uncertain: false,
        },
    ))
}

impl ProbeQueueConsumer {
    pub fn initialize<const C: usize>(
        &self,
        page: &mut [u8],
        projection: &MicrovmPeerPageProjection,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<(), ProbeQueueError> {
        Ok(self.queue.initialize(page, projection, capabilities)?)
    }

    pub fn submit<const C: usize>(
        &self,
        page: &mut [u8],
        projection: &MicrovmPeerPageProjection,
        capabilities: &CapabilitySpace<C>,
        sector: u32,
        input: &[u8; SECTOR_BYTES],
    ) -> Result<MicrovmInterfaceRequestNotification, ProbeQueueError> {
        if self.completion_uncertain {
            return Err(ProbeQueueError::CompletionUncertain);
        }
        let view = BorrowedReadView::within(0, SECTOR_BYTES as u64, SECTOR_BYTES as u64)
            .ok_or(ProtocolError::InvalidRequest)?;
        let request = encode_write_request(self.session, u64::from(sector), 1, view)?;
        let mut frame = [0; FRAME_BYTES];
        frame[..WRITE_REQUEST_BYTES].copy_from_slice(&request);
        frame[WRITE_REQUEST_BYTES..].copy_from_slice(input);
        Ok(self
            .queue
            .submit(page, projection, capabilities, OP_WRITE, &frame)?)
    }

    /// Call with the exact response. Failure to obtain a valid completion
    /// never authorizes a retry of the write.
    pub fn complete<const C: usize>(
        &mut self,
        page: &mut [u8],
        projection: &MicrovmPeerPageProjection,
        capabilities: &CapabilitySpace<C>,
        notification: MicrovmInterfaceResponseNotification,
    ) -> Result<(), ProbeQueueError> {
        if self.completion_uncertain {
            return Err(ProbeQueueError::CompletionUncertain);
        }
        let mut wire = [0; WRITE_RESPONSE_BYTES];
        match self
            .queue
            .consume_response(page, projection, capabilities, notification, &mut wire)
        {
            Ok((OP_WRITE, WRITE_RESPONSE_BYTES)) => {}
            _ => {
                self.completion_uncertain = true;
                return Err(ProbeQueueError::CompletionUncertain);
            }
        }
        match decode_write_response(&wire, SECTOR_BYTES as u64) {
            Ok(Ok(bytes)) if bytes == SECTOR_BYTES as u64 => Ok(()),
            Ok(Err(error)) => Err(ProbeQueueError::Provider(error)),
            _ => {
                self.completion_uncertain = true;
                Err(ProbeQueueError::CompletionUncertain)
            }
        }
    }
}

impl<T: BulkTransport> ProbeQueueProvider<'_, T> {
    pub fn read_partition<const C: usize>(
        &mut self,
        capabilities: &CapabilitySpace<C>,
        sector: u32,
        output: &mut [u8; SECTOR_BYTES],
    ) -> Result<(), DiagnosticPartitionError> {
        if self.completion_uncertain {
            return Err(DiagnosticPartitionError::StaleSession);
        }
        self.partition.read(capabilities, sector, output)
    }

    pub fn serve<const C: usize>(
        &mut self,
        page: &mut [u8],
        projection: &MicrovmPeerPageProjection,
        capabilities: &CapabilitySpace<C>,
        notification: MicrovmInterfaceRequestNotification,
    ) -> Result<MicrovmInterfaceResponseNotification, ProbeQueueError> {
        if self.completion_uncertain {
            return Err(ProbeQueueError::CompletionUncertain);
        }
        if notification.operation() != OP_WRITE {
            return Err(ProtocolError::InvalidRequest.into());
        }
        let mut frame = [0; FRAME_BYTES];
        let (sequence, operation, len) =
            self.queue
                .receive_request(page, projection, capabilities, notification, &mut frame)?;
        let reply = if len == FRAME_BYTES {
            let (header, data) = frame.split_at(WRITE_REQUEST_BYTES);
            self.partition
                .write(capabilities, header.try_into().unwrap(), data)
                .unwrap_or_else(|_| encode_write_response(Err(WriteError::InvalidRequest)))
        } else {
            encode_write_response(Err(WriteError::InvalidRequest))
        };
        match self
            .queue
            .respond(page, projection, capabilities, sequence, operation, &reply)
        {
            Ok(notification) => Ok(notification),
            Err(_) => {
                // The queue accepted one request and the device may have
                // completed it. Keep this endpoint closed after lost reply.
                self.completion_uncertain = true;
                self.partition.provider.invalidate_session();
                Err(ProbeQueueError::CompletionUncertain)
            }
        }
    }
}
