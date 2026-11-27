use core::sync::atomic::{Ordering, fence};

use crate::{
    Capability, CapabilitySpace, MemoryResourceError, MicrovmPeerPageIdentity,
    MicrovmPeerPageProjection, ObjectId, PAGE_SIZE,
};

const QUEUE_MAGIC: [u8; 8] = *b"MRMLQ1\0\0";
const QUEUE_VERSION: u16 = 1;
const HEADER_BYTES: usize = 112;
pub const MICROVM_INTERFACE_QUEUE_MAX_PAYLOAD: usize = PAGE_SIZE as usize - HEADER_BYTES;

const STATE_IDLE: u16 = 0;
const STATE_REQUEST: u16 = 1;
const STATE_RESPONSE: u16 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MicrovmInterfaceQueueError {
    Authority(MemoryResourceError),
    InvalidIdentity,
    InvalidPage,
    InvalidState,
    InvalidSequence,
    InvalidNotification,
    InvalidOperation,
    PayloadTooLarge,
    OutputTooSmall,
    SequenceExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MicrovmInterfaceQueueIdentity {
    fingerprint: [u8; 32],
    interface_generation: u32,
    provider_generation: u64,
    system_generation: u64,
    policy_generation: u64,
    binding_generation: u64,
}

impl MicrovmInterfaceQueueIdentity {
    pub fn new(
        fingerprint: [u8; 32],
        interface_generation: u32,
        provider_generation: u64,
        system_generation: u64,
        policy_generation: u64,
        binding_generation: u64,
    ) -> Result<Self, MicrovmInterfaceQueueError> {
        if fingerprint == [0; 32]
            || interface_generation == 0
            || provider_generation == 0
            || system_generation == 0
            || policy_generation == 0
            || binding_generation == 0
        {
            return Err(MicrovmInterfaceQueueError::InvalidIdentity);
        }
        Ok(Self {
            fingerprint,
            interface_generation,
            provider_generation,
            system_generation,
            policy_generation,
            binding_generation,
        })
    }
}

#[derive(Clone, Copy)]
struct ProjectionIdentity {
    page: MicrovmPeerPageIdentity,
    first_target: ObjectId,
    second_target: ObjectId,
    first_virtual_page: u64,
    second_virtual_page: u64,
    first_capability: Capability,
    second_capability: Capability,
}

pub struct MicrovmInterfaceQueuePair {
    consumer: MicrovmInterfaceQueueConsumer,
    provider: MicrovmInterfaceQueueProvider,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MicrovmInterfaceRequestNotification {
    identity: MicrovmInterfaceQueueIdentity,
    projection: MicrovmPeerPageIdentity,
    sequence: u64,
    operation: u32,
}

impl MicrovmInterfaceRequestNotification {
    pub(crate) const fn identity(self) -> MicrovmInterfaceQueueIdentity {
        self.identity
    }

    pub(crate) const fn projection(self) -> MicrovmPeerPageIdentity {
        self.projection
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    pub const fn operation(self) -> u32 {
        self.operation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MicrovmInterfaceResponseNotification {
    identity: MicrovmInterfaceQueueIdentity,
    projection: MicrovmPeerPageIdentity,
    sequence: u64,
    operation: u32,
}

impl MicrovmInterfaceResponseNotification {
    pub(crate) const fn identity(self) -> MicrovmInterfaceQueueIdentity {
        self.identity
    }

    pub(crate) const fn projection(self) -> MicrovmPeerPageIdentity {
        self.projection
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    pub const fn operation(self) -> u32 {
        self.operation
    }
}

pub struct MicrovmInterfaceQueueConsumer {
    identity: MicrovmInterfaceQueueIdentity,
    projection: ProjectionIdentity,
    next_sequence: u64,
}

pub struct MicrovmInterfaceQueueProvider {
    identity: MicrovmInterfaceQueueIdentity,
    projection: ProjectionIdentity,
    next_sequence: u64,
    accepted_sequence: Option<u64>,
}

impl MicrovmInterfaceQueuePair {
    pub fn bind<const C: usize>(
        identity: MicrovmInterfaceQueueIdentity,
        projection: &MicrovmPeerPageProjection,
        first_capability: Capability,
        second_capability: Capability,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<Self, MicrovmInterfaceQueueError> {
        projection
            .validate_targets(first_capability, second_capability, capabilities)
            .map_err(MicrovmInterfaceQueueError::Authority)?;
        let bound = ProjectionIdentity {
            page: projection.identity(),
            first_target: projection.first_target(),
            second_target: projection.second_target(),
            first_virtual_page: projection.first_virtual_page(),
            second_virtual_page: projection.second_virtual_page(),
            first_capability,
            second_capability,
        };
        Ok(Self {
            consumer: MicrovmInterfaceQueueConsumer {
                identity,
                projection: bound,
                next_sequence: 1,
            },
            provider: MicrovmInterfaceQueueProvider {
                identity,
                projection: bound,
                next_sequence: 1,
                accepted_sequence: None,
            },
        })
    }

    pub fn split(self) -> (MicrovmInterfaceQueueConsumer, MicrovmInterfaceQueueProvider) {
        (self.consumer, self.provider)
    }
}

impl MicrovmInterfaceQueueConsumer {
    pub fn initialize<const C: usize>(
        &self,
        page: &mut [u8],
        projection: &MicrovmPeerPageProjection,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<(), MicrovmInterfaceQueueError> {
        self.authorize(projection, capabilities)?;
        exact_page(page)?;
        if page.iter().any(|byte| *byte != 0) {
            return Err(MicrovmInterfaceQueueError::InvalidState);
        }
        page.fill(0);
        write_identity(page, self.identity);
        Ok(())
    }

    pub fn submit<const C: usize>(
        &self,
        page: &mut [u8],
        projection: &MicrovmPeerPageProjection,
        capabilities: &CapabilitySpace<C>,
        operation: u32,
        payload: &[u8],
    ) -> Result<MicrovmInterfaceRequestNotification, MicrovmInterfaceQueueError> {
        self.authorize(projection, capabilities)?;
        validate_header(page, self.identity)?;
        if operation == 0 {
            return Err(MicrovmInterfaceQueueError::InvalidOperation);
        }
        if payload.len() > MICROVM_INTERFACE_QUEUE_MAX_PAYLOAD {
            return Err(MicrovmInterfaceQueueError::PayloadTooLarge);
        }
        self.next_sequence
            .checked_add(1)
            .ok_or(MicrovmInterfaceQueueError::SequenceExhausted)?;
        if read_u16(page, 10)? != STATE_IDLE {
            return Err(MicrovmInterfaceQueueError::InvalidState);
        }
        fence(Ordering::Acquire);
        if read_u64(page, 88)? != 0 || read_u32(page, 96)? != 0 || read_u32(page, 100)? != 0 {
            return Err(MicrovmInterfaceQueueError::InvalidState);
        }
        page[HEADER_BYTES..].fill(0);
        page[HEADER_BYTES..HEADER_BYTES + payload.len()].copy_from_slice(payload);
        write_u64(page, 88, self.next_sequence);
        write_u32(page, 96, operation);
        write_u32(page, 100, payload.len() as u32);
        // State is published last. The matching receiver observes it before
        // its acquire fence and then validates the exact notification token.
        fence(Ordering::Release);
        write_u16(page, 10, STATE_REQUEST);
        Ok(MicrovmInterfaceRequestNotification {
            identity: self.identity,
            projection: self.projection.page,
            sequence: self.next_sequence,
            operation,
        })
    }

    pub fn consume_response<const C: usize>(
        &mut self,
        page: &mut [u8],
        projection: &MicrovmPeerPageProjection,
        capabilities: &CapabilitySpace<C>,
        notification: MicrovmInterfaceResponseNotification,
        output: &mut [u8],
    ) -> Result<(u32, usize), MicrovmInterfaceQueueError> {
        self.authorize(projection, capabilities)?;
        validate_header(page, self.identity)?;
        if notification.identity != self.identity
            || notification.projection != self.projection.page
            || notification.sequence != self.next_sequence
            || notification.operation == 0
        {
            return Err(MicrovmInterfaceQueueError::InvalidNotification);
        }
        if read_u16(page, 10)? != STATE_RESPONSE {
            return Err(MicrovmInterfaceQueueError::InvalidState);
        }
        fence(Ordering::Acquire);
        if read_u64(page, 88)? != self.next_sequence {
            return Err(MicrovmInterfaceQueueError::InvalidSequence);
        }
        let operation = read_u32(page, 96)?;
        if operation == 0 || operation != notification.operation {
            return Err(MicrovmInterfaceQueueError::InvalidNotification);
        }
        let length = payload_length(page)?;
        if output.len() < length {
            return Err(MicrovmInterfaceQueueError::OutputTooSmall);
        }
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(MicrovmInterfaceQueueError::SequenceExhausted)?;
        output[..length].copy_from_slice(&page[HEADER_BYTES..HEADER_BYTES + length]);
        page[HEADER_BYTES..].fill(0);
        write_u64(page, 88, 0);
        write_u32(page, 96, 0);
        write_u32(page, 100, 0);
        fence(Ordering::Release);
        write_u16(page, 10, STATE_IDLE);
        self.next_sequence = next_sequence;
        Ok((operation, length))
    }

    fn authorize<const C: usize>(
        &self,
        projection: &MicrovmPeerPageProjection,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<(), MicrovmInterfaceQueueError> {
        authorize_projection(self.projection, projection, capabilities)
    }
}

impl MicrovmInterfaceQueueProvider {
    pub fn receive_request<const C: usize>(
        &mut self,
        page: &[u8],
        projection: &MicrovmPeerPageProjection,
        capabilities: &CapabilitySpace<C>,
        notification: MicrovmInterfaceRequestNotification,
        output: &mut [u8],
    ) -> Result<(u64, u32, usize), MicrovmInterfaceQueueError> {
        self.authorize(projection, capabilities)?;
        validate_header(page, self.identity)?;
        if notification.identity != self.identity
            || notification.projection != self.projection.page
            || notification.sequence != self.next_sequence
            || notification.operation == 0
        {
            return Err(MicrovmInterfaceQueueError::InvalidNotification);
        }
        if self.accepted_sequence.is_some() || read_u16(page, 10)? != STATE_REQUEST {
            return Err(MicrovmInterfaceQueueError::InvalidState);
        }
        fence(Ordering::Acquire);
        let sequence = read_u64(page, 88)?;
        if sequence != self.next_sequence {
            return Err(MicrovmInterfaceQueueError::InvalidSequence);
        }
        let operation = read_u32(page, 96)?;
        if operation == 0 || operation != notification.operation {
            return Err(MicrovmInterfaceQueueError::InvalidNotification);
        }
        let length = payload_length(page)?;
        if output.len() < length {
            return Err(MicrovmInterfaceQueueError::OutputTooSmall);
        }
        output[..length].copy_from_slice(&page[HEADER_BYTES..HEADER_BYTES + length]);
        self.accepted_sequence = Some(sequence);
        Ok((sequence, operation, length))
    }

    pub fn respond<const C: usize>(
        &mut self,
        page: &mut [u8],
        projection: &MicrovmPeerPageProjection,
        capabilities: &CapabilitySpace<C>,
        sequence: u64,
        operation: u32,
        payload: &[u8],
    ) -> Result<MicrovmInterfaceResponseNotification, MicrovmInterfaceQueueError> {
        self.authorize(projection, capabilities)?;
        validate_header(page, self.identity)?;
        if self.accepted_sequence != Some(sequence)
            || sequence != self.next_sequence
            || read_u16(page, 10)? != STATE_REQUEST
            || read_u64(page, 88)? != sequence
            || read_u32(page, 96)? != operation
        {
            return Err(MicrovmInterfaceQueueError::InvalidState);
        }
        if payload.len() > MICROVM_INTERFACE_QUEUE_MAX_PAYLOAD {
            return Err(MicrovmInterfaceQueueError::PayloadTooLarge);
        }
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(MicrovmInterfaceQueueError::SequenceExhausted)?;
        page[HEADER_BYTES..].fill(0);
        page[HEADER_BYTES..HEADER_BYTES + payload.len()].copy_from_slice(payload);
        write_u32(page, 100, payload.len() as u32);
        fence(Ordering::Release);
        write_u16(page, 10, STATE_RESPONSE);
        self.accepted_sequence = None;
        self.next_sequence = next_sequence;
        Ok(MicrovmInterfaceResponseNotification {
            identity: self.identity,
            projection: self.projection.page,
            sequence,
            operation,
        })
    }

    fn authorize<const C: usize>(
        &self,
        projection: &MicrovmPeerPageProjection,
        capabilities: &CapabilitySpace<C>,
    ) -> Result<(), MicrovmInterfaceQueueError> {
        authorize_projection(self.projection, projection, capabilities)
    }
}

fn authorize_projection<const C: usize>(
    expected: ProjectionIdentity,
    projection: &MicrovmPeerPageProjection,
    capabilities: &CapabilitySpace<C>,
) -> Result<(), MicrovmInterfaceQueueError> {
    projection
        .validate_targets(
            expected.first_capability,
            expected.second_capability,
            capabilities,
        )
        .map_err(MicrovmInterfaceQueueError::Authority)?;
    if projection.identity() != expected.page
        || projection.first_target() != expected.first_target
        || projection.second_target() != expected.second_target
        || projection.first_virtual_page() != expected.first_virtual_page
        || projection.second_virtual_page() != expected.second_virtual_page
    {
        return Err(MicrovmInterfaceQueueError::InvalidIdentity);
    }
    Ok(())
}

fn exact_page(page: &[u8]) -> Result<(), MicrovmInterfaceQueueError> {
    if page.len() != PAGE_SIZE as usize {
        Err(MicrovmInterfaceQueueError::InvalidPage)
    } else {
        Ok(())
    }
}

fn write_identity(page: &mut [u8], identity: MicrovmInterfaceQueueIdentity) {
    page[0..8].copy_from_slice(&QUEUE_MAGIC);
    page[8..10].copy_from_slice(&QUEUE_VERSION.to_le_bytes());
    page[16..48].copy_from_slice(&identity.fingerprint);
    write_u32(page, 48, identity.interface_generation);
    write_u64(page, 56, identity.provider_generation);
    write_u64(page, 64, identity.system_generation);
    write_u64(page, 72, identity.policy_generation);
    write_u64(page, 80, identity.binding_generation);
}

fn validate_header(
    page: &[u8],
    identity: MicrovmInterfaceQueueIdentity,
) -> Result<(), MicrovmInterfaceQueueError> {
    exact_page(page)?;
    if page[0..8] != QUEUE_MAGIC
        || read_u16(page, 8)? != QUEUE_VERSION
        || page[12..16] != [0; 4]
        || page[16..48] != identity.fingerprint
        || read_u32(page, 48)? != identity.interface_generation
        || page[52..56] != [0; 4]
        || read_u64(page, 56)? != identity.provider_generation
        || read_u64(page, 64)? != identity.system_generation
        || read_u64(page, 72)? != identity.policy_generation
        || read_u64(page, 80)? != identity.binding_generation
        || page[104..112] != [0; 8]
    {
        return Err(MicrovmInterfaceQueueError::InvalidIdentity);
    }
    Ok(())
}

fn payload_length(page: &[u8]) -> Result<usize, MicrovmInterfaceQueueError> {
    let length = usize::try_from(read_u32(page, 100)?)
        .map_err(|_| MicrovmInterfaceQueueError::PayloadTooLarge)?;
    if length > MICROVM_INTERFACE_QUEUE_MAX_PAYLOAD {
        return Err(MicrovmInterfaceQueueError::PayloadTooLarge);
    }
    Ok(length)
}

fn read_u16(page: &[u8], offset: usize) -> Result<u16, MicrovmInterfaceQueueError> {
    let bytes = page
        .get(offset..offset + 2)
        .ok_or(MicrovmInterfaceQueueError::InvalidPage)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(page: &[u8], offset: usize) -> Result<u32, MicrovmInterfaceQueueError> {
    let bytes = page
        .get(offset..offset + 4)
        .ok_or(MicrovmInterfaceQueueError::InvalidPage)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(page: &[u8], offset: usize) -> Result<u64, MicrovmInterfaceQueueError> {
    let bytes = page
        .get(offset..offset + 8)
        .ok_or(MicrovmInterfaceQueueError::InvalidPage)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn write_u16(page: &mut [u8], offset: usize, value: u16) {
    page[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(page: &mut [u8], offset: usize, value: u32) {
    page[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(page: &mut [u8], offset: usize, value: u64) {
    page[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryPoolTable, Rights, reserve_microvm_peer_page_projection};

    fn identity() -> MicrovmInterfaceQueueIdentity {
        MicrovmInterfaceQueueIdentity::new([0x5a; 32], 3, 14, 9, 7, 11).unwrap()
    }

    #[test]
    fn matching_queue_generations_do_not_cross_ledger_namespaces() {
        let mut caps = CapabilitySpace::<8>::new();
        let target = Rights::MAP.union(Rights::INSPECT).union(Rights::CONTROL);
        let first = caps.insert(ObjectId(0x902), target).unwrap();
        let second = caps.insert(ObjectId(0x903), target).unwrap();
        let mut reserve = |namespace| {
            let mut memory = MemoryPoolTable::<1, 1, 2>::new(namespace).unwrap();
            let (pool, quota) = memory.create_root(
                1, 2, 0, Rights::ALLOCATE.union(Rights::CONTROL).union(Rights::INSPECT),
                &mut caps,
            ).unwrap();
            let (projection, _) = reserve_microvm_peer_page_projection(
                &mut memory, pool, quota, first, second, 0x700, 0x800, &mut caps,
            ).unwrap();
            (memory, projection)
        };
        let (_local_ledger, local) = reserve(0x901);
        let (_foreign_ledger, foreign) = reserve(0x904);
        assert_eq!(local.object(), foreign.object());
        assert_eq!(local.first_mapping(), foreign.first_mapping());
        assert_eq!(local.second_mapping(), foreign.second_mapping());
        assert_ne!(local.identity(), foreign.identity());

        let (mut client, mut server) =
            MicrovmInterfaceQueuePair::bind(identity(), &local, first, second, &caps)
                .unwrap().split();
        let (foreign_client, mut foreign_server) =
            MicrovmInterfaceQueuePair::bind(identity(), &foreign, first, second, &caps)
                .unwrap().split();
        let mut page = [0; PAGE_SIZE as usize];
        let mut foreign_page = [0; PAGE_SIZE as usize];
        assert_eq!(
            client.initialize(&mut page, &foreign, &caps),
            Err(MicrovmInterfaceQueueError::InvalidIdentity)
        );
        assert_eq!(page, [0; PAGE_SIZE as usize]);
        client.initialize(&mut page, &local, &caps).unwrap();
        let request = client.submit(&mut page, &local, &caps, 1, b"local").unwrap();
        foreign_client.initialize(&mut foreign_page, &foreign, &caps).unwrap();
        let wrong = foreign_client.submit(&mut foreign_page, &foreign, &caps, 1, b"other").unwrap();

        let vm = crate::VmTable::<1>::new().create(1).unwrap();
        let mut route = crate::MicrovmInterfaceRequestInterrupt::new(
            identity(), local.identity(), vm, 0, 64, ObjectId(0x991),
        );
        assert_eq!(route.publish(wrong), Err(crate::MicrovmInterfaceInterruptError::InvalidNotification));
        assert!(route.pending().is_none());
        route.publish(request).unwrap();

        let mut output = [0x5a; 8];
        assert_eq!(
            server.receive_request(&page, &local, &caps, wrong, &mut output),
            Err(MicrovmInterfaceQueueError::InvalidNotification)
        );
        assert_eq!(output, [0x5a; 8]);
        server.receive_request(&page, &local, &caps, request, &mut output).unwrap();
        foreign_server.receive_request(&foreign_page, &foreign, &caps, wrong, &mut output).unwrap();
        let response = server.respond(&mut page, &local, &caps, 1, 1, b"local").unwrap();
        let wrong = foreign_server.respond(&mut foreign_page, &foreign, &caps, 1, 1, b"other").unwrap();
        let mut route = crate::MicrovmInterfaceResponseInterrupt::new(
            identity(), local.identity(), vm, 0, 65, ObjectId(0x992),
        );
        assert_eq!(route.publish(wrong), Err(crate::MicrovmInterfaceInterruptError::InvalidNotification));
        assert!(route.pending().is_none());
        route.publish(response).unwrap();

        let before = page;
        output.fill(0x5a);
        assert_eq!(
            client.consume_response(&mut page, &local, &caps, wrong, &mut output),
            Err(MicrovmInterfaceQueueError::InvalidNotification)
        );
        assert_eq!(page, before);
        assert_eq!(output, [0x5a; 8]);
        assert_eq!(
            client.consume_response(&mut page, &local, &caps, response, &mut output),
            Ok((1, 5))
        );
        assert_eq!(&output[..5], b"local");
    }

    #[test]
    fn exact_projection_queue_round_trips_and_rejects_forgery() {
        let target_rights = Rights::MAP.union(Rights::INSPECT).union(Rights::CONTROL);
        let pool_rights = Rights::ALLOCATE
            .union(Rights::CONTROL)
            .union(Rights::INSPECT);
        let mut capabilities = CapabilitySpace::<8>::new();
        let mut memory = MemoryPoolTable::<1, 1, 2>::new(0x901).unwrap();
        let (pool, pool_capability) = memory
            .create_root(1, 2, 0, pool_rights, &mut capabilities)
            .unwrap();
        let first = capabilities.insert(ObjectId(0x902), target_rights).unwrap();
        let second = capabilities.insert(ObjectId(0x903), target_rights).unwrap();
        let (projection, _) = reserve_microvm_peer_page_projection(
            &mut memory,
            pool,
            pool_capability,
            first,
            second,
            0x700,
            0x800,
            &mut capabilities,
        )
        .unwrap();
        let pair =
            MicrovmInterfaceQueuePair::bind(identity(), &projection, first, second, &capabilities)
                .unwrap();
        let (mut consumer, mut provider) = pair.split();
        let mut page = [0_u8; PAGE_SIZE as usize];
        consumer
            .initialize(&mut page, &projection, &capabilities)
            .unwrap();
        let request_notification = consumer
            .submit(&mut page, &projection, &capabilities, 1, b"request")
            .unwrap();
        assert_eq!(request_notification.sequence(), 1);
        assert_eq!(request_notification.operation(), 1);
        let mut request = [0_u8; 16];
        let wrong_binding_notification = MicrovmInterfaceRequestNotification {
            identity: MicrovmInterfaceQueueIdentity::new([0x6b; 32], 3, 14, 9, 7, 11).unwrap(),
            ..request_notification
        };
        assert_eq!(
            provider.receive_request(
                &page,
                &projection,
                &capabilities,
                wrong_binding_notification,
                &mut request,
            ),
            Err(MicrovmInterfaceQueueError::InvalidNotification)
        );
        let stale_notification = MicrovmInterfaceRequestNotification {
            sequence: 2,
            ..request_notification
        };
        assert_eq!(
            provider.receive_request(
                &page,
                &projection,
                &capabilities,
                stale_notification,
                &mut request,
            ),
            Err(MicrovmInterfaceQueueError::InvalidNotification)
        );
        assert_eq!(
            provider.receive_request(
                &page,
                &projection,
                &capabilities,
                request_notification,
                &mut request,
            ),
            Ok((1, 1, 7))
        );
        assert_eq!(&request[..7], b"request");
        assert_eq!(
            provider.respond(&mut page, &projection, &capabilities, 2, 1, b"response",),
            Err(MicrovmInterfaceQueueError::InvalidState)
        );
        let response_notification = provider
            .respond(&mut page, &projection, &capabilities, 1, 1, b"response")
            .unwrap();
        assert_eq!(response_notification.sequence(), 1);
        assert_eq!(response_notification.operation(), 1);
        let mut too_small = [0_u8; 1];
        let wrong_response_notification = MicrovmInterfaceResponseNotification {
            operation: 2,
            ..response_notification
        };
        assert_eq!(
            consumer.consume_response(
                &mut page,
                &projection,
                &capabilities,
                wrong_response_notification,
                &mut too_small,
            ),
            Err(MicrovmInterfaceQueueError::InvalidNotification)
        );
        assert_eq!(
            consumer.consume_response(
                &mut page,
                &projection,
                &capabilities,
                response_notification,
                &mut too_small,
            ),
            Err(MicrovmInterfaceQueueError::OutputTooSmall)
        );
        let mut response = [0_u8; 16];
        assert_eq!(
            consumer.consume_response(
                &mut page,
                &projection,
                &capabilities,
                response_notification,
                &mut response,
            ),
            Ok((1, 8))
        );
        assert_eq!(&response[..8], b"response");

        let mut forged = page;
        forged[16] ^= 1;
        assert_eq!(
            consumer.submit(&mut forged, &projection, &capabilities, 1, b"x"),
            Err(MicrovmInterfaceQueueError::InvalidIdentity)
        );
        write_u64(&mut page, 88, 1);
        write_u16(&mut page, 10, STATE_REQUEST);
        write_u32(&mut page, 96, 1);
        assert_eq!(
            provider.receive_request(
                &page,
                &projection,
                &capabilities,
                stale_notification,
                &mut request,
            ),
            Err(MicrovmInterfaceQueueError::InvalidSequence)
        );
    }

    #[test]
    fn stale_authority_and_sequence_exhaustion_never_publish() {
        let target_rights = Rights::MAP.union(Rights::INSPECT).union(Rights::CONTROL);
        let pool_rights = Rights::ALLOCATE
            .union(Rights::CONTROL)
            .union(Rights::INSPECT);
        let mut capabilities = CapabilitySpace::<8>::new();
        let mut memory = MemoryPoolTable::<1, 1, 2>::new(0x911).unwrap();
        let (pool, pool_capability) = memory
            .create_root(1, 2, 0, pool_rights, &mut capabilities)
            .unwrap();
        let first = capabilities.insert(ObjectId(0x912), target_rights).unwrap();
        let second = capabilities.insert(ObjectId(0x913), target_rights).unwrap();
        let (projection, _) = reserve_microvm_peer_page_projection(
            &mut memory,
            pool,
            pool_capability,
            first,
            second,
            0x700,
            0x800,
            &mut capabilities,
        )
        .unwrap();
        let pair =
            MicrovmInterfaceQueuePair::bind(identity(), &projection, first, second, &capabilities)
                .unwrap();
        let (mut consumer, _provider) = pair.split();
        let mut page = [0_u8; PAGE_SIZE as usize];
        consumer
            .initialize(&mut page, &projection, &capabilities)
            .unwrap();
        let before = page;
        consumer.next_sequence = u64::MAX;
        assert_eq!(
            consumer.submit(&mut page, &projection, &capabilities, 1, b"never",),
            Err(MicrovmInterfaceQueueError::SequenceExhausted)
        );
        assert_eq!(page, before);

        capabilities.revoke(first).unwrap();
        assert!(matches!(
            consumer.submit(&mut page, &projection, &capabilities, 1, b"x"),
            Err(MicrovmInterfaceQueueError::Authority(_))
        ));
    }
}
