use mrml_kernel::{AUTHORITY_RECEIPT_BYTES, LAUNCH_REQUEST_BYTES, LaunchRequest};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerTicket(u64);

impl BrokerTicket {
    const fn new(index: usize, generation: u32) -> Self {
        Self(((generation as u64) << 32) | index as u64)
    }

    const fn index(self) -> usize {
        self.0 as u32 as usize
    }

    const fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }

    pub const fn token(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerError {
    Full,
    StaleTicket,
    WrongState,
    WrongLength,
    SequenceExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlotState {
    RequestPending,
    ReceiptReady,
}

#[derive(Clone, Copy)]
struct Slot {
    generation: u32,
    state: SlotState,
    request: [u8; LAUNCH_REQUEST_BYTES],
    receipt: [u8; AUTHORITY_RECEIPT_BYTES],
}

/// Bounded transport for an untrusted WHP/VTL0 process. It deliberately has
/// no MAC key and cannot turn a receipt into trusted evidence; endpoints must
/// verify request binding and authentication after transport.
pub struct UntrustedLaunchBroker<const N: usize> {
    slots: [Option<Slot>; N],
    generations: [u32; N],
}

impl<const N: usize> UntrustedLaunchBroker<N> {
    pub const fn new() -> Self {
        Self {
            slots: [None; N],
            generations: [0; N],
        }
    }

    pub fn submit(&mut self, request: LaunchRequest) -> Result<BrokerTicket, BrokerError> {
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(BrokerError::Full)?;
        let generation = self.generations[index]
            .checked_add(1)
            .ok_or(BrokerError::SequenceExhausted)?;
        self.generations[index] = generation;
        self.slots[index] = Some(Slot {
            generation,
            state: SlotState::RequestPending,
            request: request.encode(),
            receipt: [0; AUTHORITY_RECEIPT_BYTES],
        });
        Ok(BrokerTicket::new(index, generation))
    }

    pub fn authority_request(
        &self,
        ticket: BrokerTicket,
    ) -> Result<&[u8; LAUNCH_REQUEST_BYTES], BrokerError> {
        let slot = self.slot(ticket)?;
        if slot.state != SlotState::RequestPending {
            return Err(BrokerError::WrongState);
        }
        Ok(&slot.request)
    }

    pub fn publish_receipt(
        &mut self,
        ticket: BrokerTicket,
        receipt: &[u8],
    ) -> Result<(), BrokerError> {
        if receipt.len() != AUTHORITY_RECEIPT_BYTES {
            return Err(BrokerError::WrongLength);
        }
        let slot = self.slot_mut(ticket)?;
        if slot.state != SlotState::RequestPending {
            return Err(BrokerError::WrongState);
        }
        slot.receipt.copy_from_slice(receipt);
        slot.state = SlotState::ReceiptReady;
        Ok(())
    }

    pub fn take_receipt(
        &mut self,
        ticket: BrokerTicket,
        output: &mut [u8; AUTHORITY_RECEIPT_BYTES],
    ) -> Result<(), BrokerError> {
        let slot = self.slot(ticket)?;
        if slot.state != SlotState::ReceiptReady {
            return Err(BrokerError::WrongState);
        }
        output.copy_from_slice(&slot.receipt);
        self.clear_slot(ticket.index());
        Ok(())
    }

    /// Atomically returns the exact stored request and corresponding opaque
    /// receipt. Authentication remains exclusively the trusted endpoint's job.
    pub fn take_exchange(
        &mut self,
        ticket: BrokerTicket,
        request: &mut [u8; LAUNCH_REQUEST_BYTES],
        receipt: &mut [u8; AUTHORITY_RECEIPT_BYTES],
    ) -> Result<(), BrokerError> {
        let slot = self.slot(ticket)?;
        if slot.state != SlotState::ReceiptReady {
            return Err(BrokerError::WrongState);
        }
        request.copy_from_slice(&slot.request);
        receipt.copy_from_slice(&slot.receipt);
        self.clear_slot(ticket.index());
        Ok(())
    }

    pub fn cancel(&mut self, ticket: BrokerTicket) -> Result<(), BrokerError> {
        self.slot(ticket)?;
        self.clear_slot(ticket.index());
        Ok(())
    }

    fn clear_slot(&mut self, index: usize) {
        if let Some(slot) = self.slots.get_mut(index).and_then(Option::as_mut) {
            for byte in slot.request.iter_mut().chain(slot.receipt.iter_mut()) {
                // SAFETY: each byte is exclusively borrowed and valid. The
                // volatile wipe prevents stale exchanges surviving slot reuse.
                unsafe { core::ptr::write_volatile(byte, 0) };
            }
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
        self.slots[index] = None;
    }

    fn slot(&self, ticket: BrokerTicket) -> Result<&Slot, BrokerError> {
        self.slots
            .get(ticket.index())
            .and_then(Option::as_ref)
            .filter(|slot| slot.generation == ticket.generation())
            .ok_or(BrokerError::StaleTicket)
    }

    fn slot_mut(&mut self, ticket: BrokerTicket) -> Result<&mut Slot, BrokerError> {
        self.slots
            .get_mut(ticket.index())
            .and_then(Option::as_mut)
            .filter(|slot| slot.generation == ticket.generation())
            .ok_or(BrokerError::StaleTicket)
    }
}

impl<const N: usize> Default for UntrustedLaunchBroker<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(sequence: u64) -> LaunchRequest {
        LaunchRequest::new(sequence, [1; 32], [2; 64], [3; 64]).unwrap()
    }

    #[test]
    fn exact_bounded_messages_round_trip() {
        let mut broker = UntrustedLaunchBroker::<1>::new();
        let ticket = broker.submit(request(7)).unwrap();
        assert_eq!(
            LaunchRequest::decode(broker.authority_request(ticket).unwrap()).unwrap(),
            request(7)
        );
        let receipt = [0x5a; AUTHORITY_RECEIPT_BYTES];
        broker.publish_receipt(ticket, &receipt).unwrap();
        assert_eq!(
            broker.publish_receipt(ticket, &receipt),
            Err(BrokerError::WrongState)
        );
        let mut output = [0; AUTHORITY_RECEIPT_BYTES];
        broker.take_receipt(ticket, &mut output).unwrap();
        assert_eq!(output, receipt);
        assert_eq!(broker.cancel(ticket), Err(BrokerError::StaleTicket));
    }

    #[test]
    fn paired_exchange_returns_the_original_request_once() {
        let mut broker = UntrustedLaunchBroker::<1>::new();
        let expected_request = request(11);
        let ticket = broker.submit(expected_request).unwrap();
        let expected_receipt = [0x6b; AUTHORITY_RECEIPT_BYTES];
        broker.publish_receipt(ticket, &expected_receipt).unwrap();
        let mut request_output = [0; LAUNCH_REQUEST_BYTES];
        let mut receipt_output = [0; AUTHORITY_RECEIPT_BYTES];
        broker
            .take_exchange(ticket, &mut request_output, &mut receipt_output)
            .unwrap();
        assert_eq!(LaunchRequest::decode(&request_output), Ok(expected_request));
        assert_eq!(receipt_output, expected_receipt);
        assert_eq!(
            broker.take_exchange(ticket, &mut request_output, &mut receipt_output),
            Err(BrokerError::StaleTicket)
        );
    }

    #[test]
    fn stale_ticket_cannot_target_reused_slot() {
        let mut broker = UntrustedLaunchBroker::<1>::new();
        let old = broker.submit(request(1)).unwrap();
        broker.cancel(old).unwrap();
        let current = broker.submit(request(2)).unwrap();
        assert_ne!(old, current);
        assert_eq!(broker.authority_request(old), Err(BrokerError::StaleTicket));
        assert_eq!(
            LaunchRequest::decode(broker.authority_request(current).unwrap()).unwrap(),
            request(2)
        );
    }

    #[test]
    fn capacity_and_lengths_fail_closed() {
        let mut broker = UntrustedLaunchBroker::<1>::new();
        let ticket = broker.submit(request(1)).unwrap();
        assert_eq!(broker.submit(request(2)), Err(BrokerError::Full));
        assert_eq!(
            broker.publish_receipt(ticket, &[0; AUTHORITY_RECEIPT_BYTES - 1]),
            Err(BrokerError::WrongLength)
        );
        let mut output = [0; AUTHORITY_RECEIPT_BYTES];
        assert_eq!(
            broker.take_receipt(ticket, &mut output),
            Err(BrokerError::WrongState)
        );
    }
}
