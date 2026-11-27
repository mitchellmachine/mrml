//! Diagnostic guest transport. Only the test broker can enable or revoke PCI.
use super::{PAYLOAD, read_byte, request_address, transfer, write_byte};
use mrml_usb_guest_probe::{
    BulkDma, Controller, DeviceDma, DmaAssignment, DmaLayout, PciActivation, PciController,
    PciLocation, PciSnapshot, Platform, RevocablePlatform,
};

const DMA: DmaLayout = DmaLayout {
    device_contexts: 0x10_0000,
    command_ring: 0x10_0100,
    event_segments: 0x10_0200,
    event_ring: 0x10_0300,
};

struct Channel;

fn send(op: u8, address: u64, bytes: &[u8]) -> Result<(), ()> {
    request_address(address);
    for (index, &byte) in bytes.iter().enumerate() {
        write_byte(PAYLOAD + index, byte);
    }
    transfer(op, bytes.len())
}

fn receive(op: u8, address: u64, bytes: &mut [u8]) -> Result<(), ()> {
    request_address(address);
    transfer(op, bytes.len())?;
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = read_byte(PAYLOAD + index);
    }
    Ok(())
}

impl Platform for Channel {
    type Error = ();

    fn read32(&mut self, offset: u32) -> Result<u32, ()> {
        let mut bytes = [0; 4];
        receive(5, u64::from(offset), &mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn write32(&mut self, offset: u32, value: u32) -> Result<(), ()> {
        send(8, u64::from(offset), &value.to_le_bytes())
    }

    fn dma_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), ()> {
        if bytes.is_empty() || bytes.len() > 33 * 64 {
            return Err(());
        }
        send(6, address, bytes)
    }

    fn dma_read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), ()> {
        if bytes.is_empty() || bytes.len() > 33 * 64 {
            return Err(());
        }
        receive(7, address, bytes)
    }

    fn publish_dma(&mut self) -> Result<(), ()> {
        send(13, 0, &[])
    }
    fn acquire_dma(&mut self) -> Result<(), ()> {
        send(14, 0, &[])
    }
    fn wait_tick(&mut self) -> Result<(), ()> {
        send(12, 0, &[])
    }
}

impl PciActivation for Channel {
    fn activation_state(&mut self) -> Result<(PciSnapshot, DmaAssignment), ()> {
        let mut data = [0; 40];
        receive(9, 0, &mut data)?;
        let snapshot = PciSnapshot {
            location: PciLocation {
                segment: u16::from_le_bytes(data[..2].try_into().unwrap()),
                bus: data[2],
                device: data[3],
                function: data[4],
            },
            header_type: data[5],
            command: u16::from_le_bytes(data[6..8].try_into().unwrap()),
            configuration_generation: u64::from_le_bytes(data[8..16].try_into().unwrap()),
            vendor_device: u32::from_le_bytes(data[16..20].try_into().unwrap()),
            class_revision: u32::from_le_bytes(data[20..24].try_into().unwrap()),
            bar0: u32::from_le_bytes(data[24..28].try_into().unwrap()),
            bar1: u32::from_le_bytes(data[28..32].try_into().unwrap()),
            bar0_bytes: u64::from_le_bytes(data[32..40].try_into().unwrap()),
        };
        let controller = PciController::discover(snapshot).map_err(|_| ())?;
        Ok((
            snapshot,
            DmaAssignment {
                controller,
                mapping_generation: 1,
                device_base: DMA.device_contexts,
                bytes: 0x8000,
            },
        ))
    }

    fn enable_bus_master(&mut self, _: DmaAssignment, before: u16) -> Result<(), ()> {
        // This operation selects no device or mapping. The monitor uses
        // its own retained assignment and independently checks the command.
        send(10, 0, &before.to_le_bytes())
    }
}

impl RevocablePlatform for Channel {
    fn revoke_after_halt(&mut self) -> Result<(), ()> {
        send(11, 0, &[])
    }
}

pub(super) fn exercise(level: u8) -> bool {
    let mut channel = Channel;
    let Ok((_, assignment)) = channel.activation_state() else {
        return false;
    };
    let Ok(mut controller) = Controller::start_pci(channel, assignment, DMA, 100) else {
        return false;
    };
    let passed = controller.no_op(100).is_ok()
        && (level == 0
            || (|| {
                let port = (1..=u8::MAX).find(|&port| {
                    controller
                        .port_status(port)
                        .is_ok_and(|status| status.connected)
                })?;
                controller
                    .address_device(
                        port,
                        DeviceDma {
                            input_context: 0x10_1000,
                            output_context: 0x10_2000,
                            control_ring: 0x10_3000,
                            control_buffer: 0x10_4000,
                        },
                        100,
                    )
                    .ok()?;
                let mut descriptor = [0; 18];
                controller
                    .read_descriptor(1, 0, &mut descriptor, 100)
                    .ok()?;
                if descriptor[..2] != [18, 1] {
                    return None;
                }
                if level >= 2 {
                    let mut configuration = [0; 256];
                    controller
                        .read_descriptor(2, 0, &mut configuration[..9], 100)
                        .ok()?;
                    let len = usize::from(u16::from_le_bytes([configuration[2], configuration[3]]));
                    if !(9..=256).contains(&len) {
                        return None;
                    }
                    controller
                        .read_descriptor(2, 0, &mut configuration[..len], 100)
                        .ok()?;
                    let pipe = controller
                        .configure_bulk(
                            &configuration[..len],
                            BulkDma {
                                input_ring: 0x10_5000,
                                output_ring: 0x10_6000,
                                buffer: 0x10_7000,
                            },
                            100,
                        )
                        .ok()?;
                    if level == 3 {
                        let mut disk = mrml_usb_guest_probe::UsbDisk::probe(pipe).ok()?;
                        let mut data = [0; 512];
                        disk.read_sector(u64::from(mrml_usb_guest_probe::FILE), &mut data)
                            .ok()?;
                        if disk.sectors() != mrml_usb_guest_probe::fixture_sectors()
                            || &data[..3] != b"old"
                            || !data[3..].iter().all(|&x| x == 0xa5)
                        {
                            return None;
                        }
                    }
                }
                Some(())
            })()
            .is_some());
    let retired = controller
        .stop(100)
        .ok()
        .is_some_and(|halted| halted.revoke().is_ok());
    passed && retired
}
