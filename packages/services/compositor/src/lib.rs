#![no_std]

mod boot_scanout;
mod scanout_probe;
mod transport;

pub use boot_scanout::{
    BootProjection, BootScanoutError, publish_total_guest_scanout, render_private_boot_frame,
};

pub use scanout_probe::{
    BOOT_SCANOUT_PROBE_BYTES, BOOT_SCANOUT_PROBE_HEIGHT, BOOT_SCANOUT_PROBE_READY,
    BOOT_SCANOUT_PROBE_WIDTH, BootScanoutProbeError, BootScanoutProbeTransport,
    run_boot_scanout_probe,
};

use core::array;
use mrml_interface_gui_surface_v1::OpaqueHandle;
use mrml_kernel::{
    Capability, DisplayOutputIdentity, GraphicsBufferDescriptor, GraphicsProtocolError,
    SurfaceIdentity, SurfaceObjectResolver,
};

pub use transport::{
    SURFACE_CALL_BYTES, SurfaceCallFrame, SurfaceMicrovmQueue, SurfaceMicrovmQueueError,
    SurfaceMicrovmServiceError, SurfaceMicrovmTicket, SurfaceNativeTransportError,
    decode_surface_call, encode_surface_call, serve_microvm_surface_once,
    serve_native_surface_once,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisteredGraphicsObject {
    Surface {
        capability: Capability,
        identity: SurfaceIdentity,
    },
    Output {
        capability: Capability,
        identity: DisplayOutputIdentity,
    },
    Buffer {
        capability: Capability,
        descriptor: GraphicsBufferDescriptor,
    },
}

impl RegisteredGraphicsObject {
    const fn capability(self) -> Capability {
        match self {
            Self::Surface { capability, .. }
            | Self::Output { capability, .. }
            | Self::Buffer { capability, .. } => capability,
        }
    }

    const fn object(self) -> u64 {
        match self {
            Self::Surface { identity, .. } => identity.object().0,
            Self::Output { identity, .. } => identity.object().0,
            Self::Buffer { descriptor, .. } => descriptor.object().0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphicsRegistryError {
    InvalidRegistryGeneration,
    Full,
    DuplicateObject,
    DuplicateAuthority,
    InvalidHandle,
    WrongObjectKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GraphicsRegistryGeneration(u16);

impl GraphicsRegistryGeneration {
    pub const fn new(value: u16) -> Result<Self, GraphicsRegistryError> {
        if value == 0 {
            return Err(GraphicsRegistryError::InvalidRegistryGeneration);
        }
        Ok(Self(value))
    }

    const fn first_handle_generation(self) -> u32 {
        ((self.0 as u32) << 16) | 1
    }
}

#[derive(Clone, Copy)]
struct Entry {
    generation: u32,
    object: Option<RegisteredGraphicsObject>,
    reusable: bool,
}

impl Entry {
    const fn empty(registry_generation: GraphicsRegistryGeneration) -> Self {
        Self {
            generation: registry_generation.first_handle_generation(),
            object: None,
            reusable: true,
        }
    }
}

/// Fixed-capacity compositor-side registry for interface-visible handles.
///
/// The registry owns no capability minting authority. It retains capabilities
/// created by the normal control plane and gives untrusted protocol bytes only
/// a generational name that must resolve here before kernel admission.
pub struct GraphicsObjectRegistry<const N: usize> {
    entries: [Entry; N],
}

impl<const N: usize> GraphicsObjectRegistry<N> {
    pub fn new(registry_generation: GraphicsRegistryGeneration) -> Self {
        Self {
            entries: array::from_fn(|_| Entry::empty(registry_generation)),
        }
    }

    pub fn register(
        &mut self,
        object: RegisteredGraphicsObject,
    ) -> Result<OpaqueHandle, GraphicsRegistryError> {
        if self
            .entries
            .iter()
            .filter_map(|entry| entry.object)
            .any(|existing| existing.object() == object.object())
        {
            return Err(GraphicsRegistryError::DuplicateObject);
        }
        if self
            .entries
            .iter()
            .filter_map(|entry| entry.object)
            .any(|existing| existing.capability() == object.capability())
        {
            return Err(GraphicsRegistryError::DuplicateAuthority);
        }
        let (index, entry) = self
            .entries
            .iter_mut()
            .enumerate()
            .find(|(_, entry)| entry.object.is_none() && entry.reusable)
            .ok_or(GraphicsRegistryError::Full)?;
        let index = u32::try_from(index).map_err(|_| GraphicsRegistryError::Full)?;
        let handle =
            OpaqueHandle::new(index, entry.generation).ok_or(GraphicsRegistryError::Full)?;
        entry.object = Some(object);
        Ok(handle)
    }

    pub fn retire(
        &mut self,
        handle: OpaqueHandle,
    ) -> Result<RegisteredGraphicsObject, GraphicsRegistryError> {
        let entry = self.entry_mut(handle)?;
        let object = entry
            .object
            .take()
            .ok_or(GraphicsRegistryError::InvalidHandle)?;
        if entry.generation & 0xffff == 0xffff {
            entry.reusable = false;
        } else {
            entry.generation += 1;
        }
        Ok(object)
    }

    pub fn get(
        &self,
        handle: OpaqueHandle,
    ) -> Result<RegisteredGraphicsObject, GraphicsRegistryError> {
        self.entry(handle)?
            .object
            .ok_or(GraphicsRegistryError::InvalidHandle)
    }

    fn entry(&self, handle: OpaqueHandle) -> Result<&Entry, GraphicsRegistryError> {
        self.entries
            .get(handle.index() as usize)
            .filter(|entry| entry.object.is_some() && entry.generation == handle.generation())
            .ok_or(GraphicsRegistryError::InvalidHandle)
    }

    fn entry_mut(&mut self, handle: OpaqueHandle) -> Result<&mut Entry, GraphicsRegistryError> {
        self.entries
            .get_mut(handle.index() as usize)
            .filter(|entry| entry.object.is_some() && entry.generation == handle.generation())
            .ok_or(GraphicsRegistryError::InvalidHandle)
    }
}

impl<const N: usize> SurfaceObjectResolver for GraphicsObjectRegistry<N> {
    fn resolve_surface(
        &mut self,
        handle: OpaqueHandle,
    ) -> Result<(Capability, SurfaceIdentity), GraphicsProtocolError> {
        match self
            .get(handle)
            .map_err(|_| GraphicsProtocolError::InvalidIdentity)?
        {
            RegisteredGraphicsObject::Surface {
                capability,
                identity,
            } => Ok((capability, identity)),
            _ => Err(GraphicsProtocolError::WrongObject),
        }
    }

    fn resolve_output(
        &mut self,
        handle: OpaqueHandle,
    ) -> Result<(Capability, DisplayOutputIdentity), GraphicsProtocolError> {
        match self
            .get(handle)
            .map_err(|_| GraphicsProtocolError::InvalidIdentity)?
        {
            RegisteredGraphicsObject::Output {
                capability,
                identity,
            } => Ok((capability, identity)),
            _ => Err(GraphicsProtocolError::WrongObject),
        }
    }

    fn resolve_buffer(
        &mut self,
        handle: OpaqueHandle,
    ) -> Result<(Capability, GraphicsBufferDescriptor), GraphicsProtocolError> {
        match self
            .get(handle)
            .map_err(|_| GraphicsProtocolError::InvalidIdentity)?
        {
            RegisteredGraphicsObject::Buffer {
                capability,
                descriptor,
            } => Ok((capability, descriptor)),
            _ => Err(GraphicsProtocolError::WrongObject),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_kernel::{
        CapabilitySpace, GraphicsFormat, ObjectId, PhysicalExtent, Rights,
        admit_surface_interface_commit,
    };

    fn epoch(value: u16) -> GraphicsRegistryGeneration {
        GraphicsRegistryGeneration::new(value).unwrap()
    }

    #[test]
    fn stale_handles_and_wrong_kinds_never_resolve_reused_slots() {
        let mut capabilities = CapabilitySpace::<4>::new();
        let surface_identity = SurfaceIdentity::new(ObjectId(10), 1).unwrap();
        let output_identity = DisplayOutputIdentity::new(ObjectId(20), 1).unwrap();
        let surface_capability = capabilities.insert(ObjectId(10), Rights::CONTROL).unwrap();
        let output_capability = capabilities.insert(ObjectId(20), Rights::INSPECT).unwrap();
        let mut registry = GraphicsObjectRegistry::<1>::new(epoch(1));
        let stale = registry
            .register(RegisteredGraphicsObject::Surface {
                capability: surface_capability,
                identity: surface_identity,
            })
            .unwrap();
        assert_eq!(
            registry.resolve_output(stale),
            Err(GraphicsProtocolError::WrongObject)
        );
        assert!(matches!(
            registry.retire(stale),
            Ok(RegisteredGraphicsObject::Surface { .. })
        ));
        let current = registry
            .register(RegisteredGraphicsObject::Output {
                capability: output_capability,
                identity: output_identity,
            })
            .unwrap();
        assert_ne!(stale, current);
        assert_eq!(
            registry.resolve_surface(stale),
            Err(GraphicsProtocolError::InvalidIdentity)
        );
        assert_eq!(
            registry.resolve_output(current),
            Ok((output_capability, output_identity))
        );

        let mut restarted = GraphicsObjectRegistry::<1>::new(epoch(2));
        let after_restart = restarted
            .register(RegisteredGraphicsObject::Output {
                capability: output_capability,
                identity: output_identity,
            })
            .unwrap();
        assert_ne!(stale, after_restart);
        assert_eq!(
            restarted.resolve_output(stale),
            Err(GraphicsProtocolError::InvalidIdentity)
        );
    }

    #[test]
    fn generation_validation_and_exhaustion_never_wrap() {
        assert_eq!(
            GraphicsRegistryGeneration::new(0),
            Err(GraphicsRegistryError::InvalidRegistryGeneration)
        );
        let mut capabilities = CapabilitySpace::<2>::new();
        let first = capabilities.insert(ObjectId(10), Rights::CONTROL).unwrap();
        let second = capabilities.insert(ObjectId(20), Rights::CONTROL).unwrap();
        let mut registry = GraphicsObjectRegistry::<1>::new(epoch(7));
        let handle = registry
            .register(RegisteredGraphicsObject::Surface {
                capability: first,
                identity: SurfaceIdentity::new(ObjectId(10), 1).unwrap(),
            })
            .unwrap();
        registry.entries[0].generation = (7_u32 << 16) | 0xffff;
        let exhausted = OpaqueHandle::new(handle.index(), (7_u32 << 16) | 0xffff).unwrap();
        registry.retire(exhausted).unwrap();
        assert_eq!(
            registry.register(RegisteredGraphicsObject::Surface {
                capability: second,
                identity: SurfaceIdentity::new(ObjectId(20), 1).unwrap(),
            }),
            Err(GraphicsRegistryError::Full)
        );
    }

    #[test]
    fn duplicate_objects_authority_and_capacity_fail_without_mutation() {
        let mut capabilities = CapabilitySpace::<3>::new();
        let first = capabilities.insert(ObjectId(10), Rights::CONTROL).unwrap();
        let second = capabilities.insert(ObjectId(20), Rights::CONTROL).unwrap();
        let mut registry = GraphicsObjectRegistry::<2>::new(epoch(1));
        let handle = registry
            .register(RegisteredGraphicsObject::Surface {
                capability: first,
                identity: SurfaceIdentity::new(ObjectId(10), 1).unwrap(),
            })
            .unwrap();
        assert_eq!(
            registry.register(RegisteredGraphicsObject::Surface {
                capability: second,
                identity: SurfaceIdentity::new(ObjectId(10), 2).unwrap(),
            }),
            Err(GraphicsRegistryError::DuplicateObject)
        );
        assert_eq!(
            registry.register(RegisteredGraphicsObject::Surface {
                capability: first,
                identity: SurfaceIdentity::new(ObjectId(30), 1).unwrap(),
            }),
            Err(GraphicsRegistryError::DuplicateAuthority)
        );
        assert!(matches!(
            registry.get(handle),
            Ok(RegisteredGraphicsObject::Surface { .. })
        ));
    }

    #[test]
    fn buffer_registry_retains_the_authoritative_complete_descriptor() {
        let mut capabilities = CapabilitySpace::<1>::new();
        let capability = capabilities.insert(ObjectId(30), Rights::READ).unwrap();
        let descriptor = GraphicsBufferDescriptor::new(
            ObjectId(30),
            7,
            PhysicalExtent::new(800, 600).unwrap(),
            3200,
            1_920_000,
            GraphicsFormat::Bgra8Srgb,
        )
        .unwrap();
        let mut registry = GraphicsObjectRegistry::<1>::new(epoch(1));
        let handle = registry
            .register(RegisteredGraphicsObject::Buffer {
                capability,
                descriptor,
            })
            .unwrap();
        assert_eq!(
            registry.resolve_buffer(handle),
            Ok((capability, descriptor))
        );
    }

    #[test]
    fn canonical_interface_commit_uses_registry_authority_end_to_end() {
        use mrml_interface_gui_surface_v1 as abi;

        let mut capabilities = CapabilitySpace::<3>::new();
        let surface = SurfaceIdentity::new(ObjectId(10), 5).unwrap();
        let output = DisplayOutputIdentity::new(ObjectId(20), 6).unwrap();
        let buffer = GraphicsBufferDescriptor::new(
            ObjectId(30),
            7,
            PhysicalExtent::new(800, 600).unwrap(),
            3200,
            1_920_000,
            GraphicsFormat::Bgra8Srgb,
        )
        .unwrap();
        let surface_capability = capabilities.insert(ObjectId(10), Rights::CONTROL).unwrap();
        let output_capability = capabilities.insert(ObjectId(20), Rights::INSPECT).unwrap();
        let buffer_capability = capabilities.insert(ObjectId(30), Rights::READ).unwrap();
        let mut registry = GraphicsObjectRegistry::<3>::new(epoch(1));
        let surface_handle = registry
            .register(RegisteredGraphicsObject::Surface {
                capability: surface_capability,
                identity: surface,
            })
            .unwrap();
        let output_handle = registry
            .register(RegisteredGraphicsObject::Output {
                capability: output_capability,
                identity: output,
            })
            .unwrap();
        let buffer_handle = registry
            .register(RegisteredGraphicsObject::Buffer {
                capability: buffer_capability,
                descriptor: buffer,
            })
            .unwrap();
        let mut damage = [abi::LogicalRect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        }; abi::MAX_DAMAGE_RECTS];
        damage[0] = abi::LogicalRect {
            x: 0,
            y: 0,
            width: 80,
            height: 60,
        };
        let state = abi::SurfaceState {
            logical_bounds: abi::LogicalRect {
                x: 0,
                y: 0,
                width: 800,
                height: 600,
            },
            scale_numerator: 1,
            scale_denominator: 1,
            buffer_width: 800,
            buffer_height: 600,
            buffer_stride: 3200,
            buffer_byte_length: 1_920_000,
            format: abi::SurfaceFormat::Bgra8Srgb,
            serial: 44,
            damage_count: 1,
            damage,
        };
        let state_bytes = abi::encode_surface_state(state).unwrap();
        let state = abi::decode_surface_state(&state_bytes).unwrap();
        let view = abi::BorrowedReadView::within(
            0,
            abi::SURFACE_STATE_BYTES as u64,
            abi::SURFACE_STATE_BYTES as u64,
        )
        .unwrap();
        let request =
            abi::encode_commit_request(surface_handle, output_handle, buffer_handle, view).unwrap();
        let envelope =
            abi::decode_commit_request(&request, abi::SURFACE_STATE_BYTES as u64).unwrap();
        let binding = admit_surface_interface_commit(&capabilities, &mut registry, envelope, state)
            .unwrap()
            .into_data_plane();
        assert_eq!(binding.serial(), 44);
        assert_eq!(binding.surface(), surface);
        assert_eq!(binding.output(), output);
        assert_eq!(binding.buffer(), buffer);
        assert_eq!(binding.revalidate(&capabilities), Ok(()));
    }
}
