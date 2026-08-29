//! Exact capability-bound I/O-port ownership for one legacy IDE channel.

use crate::IdeControllerDescriptor;
use mrml_kernel::{Capability, CapabilityError, CapabilitySpace, ObjectId, Rights};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdeChannel {
    Primary,
    Secondary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdePortRange {
    pub base: u16,
    pub bytes: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdePortGrantRequest {
    pub port_capability: Capability,
    pub port_object: ObjectId,
    pub channel: IdeChannel,
    pub grant_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdeChannelPortGrant {
    pub controller_generation: u64,
    pub grant_generation: u64,
    pub port_object: ObjectId,
    pub channel: IdeChannel,
    pub command: IdePortRange,
    pub control: IdePortRange,
    pub bus_master: Option<IdePortRange>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdePortGrantError {
    Capability(CapabilityError),
    WrongPortObject,
    InvalidGeneration,
    InvalidRange,
    OverlappingRange,
    BackendRejected,
}

pub trait IdePortGrantBackend {
    /// Atomically grants only these port ranges to the isolated provider.
    fn install(&mut self, grant: IdeChannelPortGrant) -> Result<(), ()>;
    /// Removes the exact port projection before the provider can be replaced.
    fn remove(&mut self, grant: IdeChannelPortGrant) -> Result<(), ()>;
}

#[derive(Debug, Eq, PartialEq)]
pub struct IdePortRevocationError {
    pub grant: IdeChannelPortGrant,
}

pub fn revoke_ide_channel_ports<B: IdePortGrantBackend>(
    grant: IdeChannelPortGrant,
    backend: &mut B,
) -> Result<(), IdePortRevocationError> {
    backend
        .remove(grant)
        .map_err(|_| IdePortRevocationError { grant })
}

pub fn prepare_ide_channel_ports<const N: usize, B: IdePortGrantBackend>(
    capabilities: &CapabilitySpace<N>,
    controller: IdeControllerDescriptor,
    request: IdePortGrantRequest,
    backend: &mut B,
) -> Result<IdeChannelPortGrant, IdePortGrantError> {
    let object = capabilities
        .authorize_exact(request.port_capability, Rights::READ.union(Rights::WRITE))
        .map_err(IdePortGrantError::Capability)?;
    if object != request.port_object {
        return Err(IdePortGrantError::WrongPortObject);
    }
    if controller.configuration_generation == 0 || request.grant_generation == 0 {
        return Err(IdePortGrantError::InvalidGeneration);
    }
    let descriptor = match request.channel {
        IdeChannel::Primary => controller.primary,
        IdeChannel::Secondary => controller.secondary,
    };
    let command = range(descriptor.command_base, 8)?;
    let control = range(descriptor.control_base, 1)?;
    let bus_master = controller
        .bus_master_base
        .map(|base| {
            let offset = match request.channel {
                IdeChannel::Primary => 0,
                IdeChannel::Secondary => 8,
            };
            range(
                base.checked_add(offset)
                    .ok_or(IdePortGrantError::InvalidRange)?,
                8,
            )
        })
        .transpose()?;
    if overlaps(command, control)
        || bus_master.is_some_and(|dma| overlaps(command, dma) || overlaps(control, dma))
    {
        return Err(IdePortGrantError::OverlappingRange);
    }
    let grant = IdeChannelPortGrant {
        controller_generation: controller.configuration_generation,
        grant_generation: request.grant_generation,
        port_object: request.port_object,
        channel: request.channel,
        command,
        control,
        bus_master,
    };
    backend
        .install(grant)
        .map_err(|_| IdePortGrantError::BackendRejected)?;
    Ok(grant)
}

fn range(base: u16, bytes: u16) -> Result<IdePortRange, IdePortGrantError> {
    if base == 0 || bytes == 0 || base.checked_add(bytes - 1).is_none() {
        return Err(IdePortGrantError::InvalidRange);
    }
    Ok(IdePortRange { base, bytes })
}

const fn overlaps(left: IdePortRange, right: IdePortRange) -> bool {
    let left_end = left.base as u32 + left.bytes as u32;
    let right_end = right.base as u32 + right.bytes as u32;
    (left.base as u32) < right_end && (right.base as u32) < left_end
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IdeChannelDescriptor, IdeChannelMode, PciFunctionLocation};

    #[derive(Default)]
    struct Backend(Option<IdeChannelPortGrant>, bool);
    impl IdePortGrantBackend for Backend {
        fn install(&mut self, grant: IdeChannelPortGrant) -> Result<(), ()> {
            if self.1 {
                Err(())
            } else {
                self.0 = Some(grant);
                Ok(())
            }
        }
        fn remove(&mut self, grant: IdeChannelPortGrant) -> Result<(), ()> {
            if self.1 || self.0 != Some(grant) {
                return Err(());
            }
            self.0 = None;
            Ok(())
        }
    }

    fn controller() -> IdeControllerDescriptor {
        IdeControllerDescriptor {
            location: PciFunctionLocation::new(0, 0, 31, 1).unwrap(),
            configuration_generation: 4,
            vendor_id: 0x8086,
            device_id: 0x7010,
            primary: IdeChannelDescriptor {
                mode: IdeChannelMode::Compatibility,
                switchable: false,
                command_base: 0x1f0,
                control_base: 0x3f6,
            },
            secondary: IdeChannelDescriptor {
                mode: IdeChannelMode::Compatibility,
                switchable: false,
                command_base: 0x170,
                control_base: 0x376,
            },
            bus_master_base: Some(0x2400),
        }
    }

    #[test]
    fn grants_only_one_exact_channel_and_its_dma_registers() {
        let mut caps = CapabilitySpace::<1>::new();
        let cap = caps
            .insert(ObjectId(9), Rights::READ.union(Rights::WRITE))
            .unwrap();
        let request = IdePortGrantRequest {
            port_capability: cap,
            port_object: ObjectId(9),
            channel: IdeChannel::Secondary,
            grant_generation: 7,
        };
        let mut backend = Backend::default();
        let grant = prepare_ide_channel_ports(&caps, controller(), request, &mut backend).unwrap();
        assert_eq!(
            grant.command,
            IdePortRange {
                base: 0x170,
                bytes: 8
            }
        );
        assert_eq!(
            grant.control,
            IdePortRange {
                base: 0x376,
                bytes: 1
            }
        );
        assert_eq!(
            grant.bus_master,
            Some(IdePortRange {
                base: 0x2408,
                bytes: 8
            })
        );
        assert_eq!(backend.0, Some(grant));
    }

    #[test]
    fn wrong_rights_object_generations_overlap_and_backend_fail_closed() {
        for rights in [
            Rights::READ,
            Rights::WRITE,
            Rights::READ.union(Rights::WRITE).union(Rights::CONTROL),
        ] {
            let mut caps = CapabilitySpace::<1>::new();
            let cap = caps.insert(ObjectId(9), rights).unwrap();
            let request = IdePortGrantRequest {
                port_capability: cap,
                port_object: ObjectId(9),
                channel: IdeChannel::Primary,
                grant_generation: 7,
            };
            assert!(matches!(
                prepare_ide_channel_ports(&caps, controller(), request, &mut Backend::default()),
                Err(IdePortGrantError::Capability(_))
            ));
        }
        let mut caps = CapabilitySpace::<1>::new();
        let cap = caps
            .insert(ObjectId(9), Rights::READ.union(Rights::WRITE))
            .unwrap();
        let request = IdePortGrantRequest {
            port_capability: cap,
            port_object: ObjectId(8),
            channel: IdeChannel::Primary,
            grant_generation: 7,
        };
        assert_eq!(
            prepare_ide_channel_ports(&caps, controller(), request, &mut Backend::default()),
            Err(IdePortGrantError::WrongPortObject)
        );
        let mut bad = controller();
        bad.primary.control_base = 0x1f7;
        let request = IdePortGrantRequest {
            port_capability: cap,
            port_object: ObjectId(9),
            channel: IdeChannel::Primary,
            grant_generation: 7,
        };
        assert_eq!(
            prepare_ide_channel_ports(&caps, bad, request, &mut Backend::default()),
            Err(IdePortGrantError::OverlappingRange)
        );
        assert_eq!(
            prepare_ide_channel_ports(&caps, controller(), request, &mut Backend(None, true)),
            Err(IdePortGrantError::BackendRejected)
        );
    }

    #[test]
    fn revocation_retains_grant_until_exact_backend_removal() {
        let mut caps = CapabilitySpace::<1>::new();
        let cap = caps
            .insert(ObjectId(9), Rights::READ.union(Rights::WRITE))
            .unwrap();
        let request = IdePortGrantRequest {
            port_capability: cap,
            port_object: ObjectId(9),
            channel: IdeChannel::Primary,
            grant_generation: 7,
        };
        let mut backend = Backend::default();
        let grant = prepare_ide_channel_ports(&caps, controller(), request, &mut backend).unwrap();
        backend.1 = true;
        let retained = revoke_ide_channel_ports(grant, &mut backend)
            .unwrap_err()
            .grant;
        backend.1 = false;
        assert_eq!(revoke_ide_channel_ports(retained, &mut backend), Ok(()));
        assert_eq!(backend.0, None);
    }
}
