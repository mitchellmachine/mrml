use crate::{Capability, CapabilitySpace, ObjectId, Rights};
use mrml_interface_gui_surface_v1 as surface_abi;

pub const MAX_GRAPHICS_DIMENSION: u32 = 16_384;
pub const MAX_GRAPHICS_BUFFER_BYTES: u64 = 1 << 30;
pub const MAX_LOGICAL_COORDINATE: i32 = 1 << 20;
pub const MAX_SURFACE_DAMAGE_RECTS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphicsProtocolError {
    InvalidIdentity,
    InvalidGeneration,
    InvalidGeometry,
    InvalidScale,
    InvalidBuffer,
    InvalidDamage,
    InvalidCapability,
    WrongObject,
    InterfaceRejected,
}

/// Trusted compositor-side lookup of generational interface handles.
///
/// Interface bytes identify candidate objects. Only this resolver supplies the
/// live kernel capabilities and authoritative object generations/descriptors.
pub trait SurfaceObjectResolver {
    fn resolve_surface(
        &mut self,
        handle: surface_abi::OpaqueHandle,
    ) -> Result<(Capability, SurfaceIdentity), GraphicsProtocolError>;

    fn resolve_output(
        &mut self,
        handle: surface_abi::OpaqueHandle,
    ) -> Result<(Capability, DisplayOutputIdentity), GraphicsProtocolError>;

    fn resolve_buffer(
        &mut self,
        handle: surface_abi::OpaqueHandle,
    ) -> Result<(Capability, GraphicsBufferDescriptor), GraphicsProtocolError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisplayOutputIdentity {
    object: ObjectId,
    generation: u64,
}

impl DisplayOutputIdentity {
    pub const fn new(object: ObjectId, generation: u64) -> Result<Self, GraphicsProtocolError> {
        if object.0 == 0 {
            return Err(GraphicsProtocolError::InvalidIdentity);
        }
        if generation == 0 {
            return Err(GraphicsProtocolError::InvalidGeneration);
        }
        Ok(Self { object, generation })
    }

    pub const fn object(self) -> ObjectId {
        self.object
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurfaceIdentity {
    object: ObjectId,
    generation: u64,
}

impl SurfaceIdentity {
    pub const fn new(object: ObjectId, generation: u64) -> Result<Self, GraphicsProtocolError> {
        if object.0 == 0 {
            return Err(GraphicsProtocolError::InvalidIdentity);
        }
        if generation == 0 {
            return Err(GraphicsProtocolError::InvalidGeneration);
        }
        Ok(Self { object, generation })
    }

    pub const fn object(self) -> ObjectId {
        self.object
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogicalScale {
    numerator: u16,
    denominator: u16,
}

impl LogicalScale {
    pub const fn new(numerator: u16, denominator: u16) -> Result<Self, GraphicsProtocolError> {
        if numerator == 0 || denominator == 0 || numerator > 4096 || denominator > 4096 {
            return Err(GraphicsProtocolError::InvalidScale);
        }
        Ok(Self {
            numerator,
            denominator,
        })
    }

    pub const fn numerator(self) -> u16 {
        self.numerator
    }

    pub const fn denominator(self) -> u16 {
        self.denominator
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogicalRect {
    x: i32,
    y: i32,
    width: u32,
    height: u32,
}

impl LogicalRect {
    pub const EMPTY: Self = Self {
        x: 0,
        y: 0,
        width: 0,
        height: 0,
    };

    pub const fn new(
        x: i32,
        y: i32,
        width: u32,
        height: u32,
    ) -> Result<Self, GraphicsProtocolError> {
        let Some(right) = x.checked_add_unsigned(width) else {
            return Err(GraphicsProtocolError::InvalidGeometry);
        };
        let Some(bottom) = y.checked_add_unsigned(height) else {
            return Err(GraphicsProtocolError::InvalidGeometry);
        };
        if width == 0
            || height == 0
            || width > MAX_LOGICAL_COORDINATE as u32
            || height > MAX_LOGICAL_COORDINATE as u32
            || x < -MAX_LOGICAL_COORDINATE
            || y < -MAX_LOGICAL_COORDINATE
            || right > MAX_LOGICAL_COORDINATE
            || bottom > MAX_LOGICAL_COORDINATE
        {
            return Err(GraphicsProtocolError::InvalidGeometry);
        }
        Ok(Self {
            x,
            y,
            width,
            height,
        })
    }

    pub const fn x(self) -> i32 {
        self.x
    }

    pub const fn y(self) -> i32 {
        self.y
    }

    pub const fn width(self) -> u32 {
        self.width
    }

    pub const fn height(self) -> u32 {
        self.height
    }

    const fn contains(self, other: Self) -> bool {
        let Some(self_right) = self.x.checked_add_unsigned(self.width) else {
            return false;
        };
        let Some(self_bottom) = self.y.checked_add_unsigned(self.height) else {
            return false;
        };
        let Some(other_right) = other.x.checked_add_unsigned(other.width) else {
            return false;
        };
        let Some(other_bottom) = other.y.checked_add_unsigned(other.height) else {
            return false;
        };
        other.x >= self.x
            && other.y >= self.y
            && other_right <= self_right
            && other_bottom <= self_bottom
    }

    pub const fn is_empty(self) -> bool {
        self.width == 0 || self.height == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurfaceDamage {
    count: u8,
    rects: [LogicalRect; MAX_SURFACE_DAMAGE_RECTS],
}

impl SurfaceDamage {
    pub const fn new(
        count: u8,
        rects: [LogicalRect; MAX_SURFACE_DAMAGE_RECTS],
    ) -> Result<Self, GraphicsProtocolError> {
        if count as usize > MAX_SURFACE_DAMAGE_RECTS {
            return Err(GraphicsProtocolError::InvalidDamage);
        }
        let mut index = 0;
        while index < MAX_SURFACE_DAMAGE_RECTS {
            if (index < count as usize && rects[index].is_empty())
                || (index >= count as usize && !rects[index].is_empty())
            {
                return Err(GraphicsProtocolError::InvalidDamage);
            }
            index += 1;
        }
        Ok(Self { count, rects })
    }

    pub const fn count(self) -> u8 {
        self.count
    }

    pub const fn rects(self) -> [LogicalRect; MAX_SURFACE_DAMAGE_RECTS] {
        self.rects
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalExtent {
    width: u32,
    height: u32,
}

impl PhysicalExtent {
    pub const fn new(width: u32, height: u32) -> Result<Self, GraphicsProtocolError> {
        if width == 0
            || height == 0
            || width > MAX_GRAPHICS_DIMENSION
            || height > MAX_GRAPHICS_DIMENSION
        {
            return Err(GraphicsProtocolError::InvalidGeometry);
        }
        Ok(Self { width, height })
    }

    pub const fn width(self) -> u32 {
        self.width
    }

    pub const fn height(self) -> u32 {
        self.height
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphicsFormat {
    Bgra8Srgb,
    Rgba8Srgb,
}

impl GraphicsFormat {
    const fn bytes_per_pixel(self) -> u64 {
        4
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GraphicsBufferDescriptor {
    object: ObjectId,
    generation: u64,
    extent: PhysicalExtent,
    stride: u32,
    byte_length: u64,
    format: GraphicsFormat,
}

impl GraphicsBufferDescriptor {
    pub const fn new(
        object: ObjectId,
        generation: u64,
        extent: PhysicalExtent,
        stride: u32,
        byte_length: u64,
        format: GraphicsFormat,
    ) -> Result<Self, GraphicsProtocolError> {
        if object.0 == 0 {
            return Err(GraphicsProtocolError::InvalidIdentity);
        }
        if generation == 0 {
            return Err(GraphicsProtocolError::InvalidGeneration);
        }
        let Some(minimum_stride) = (extent.width as u64).checked_mul(format.bytes_per_pixel())
        else {
            return Err(GraphicsProtocolError::InvalidBuffer);
        };
        let Some(required_bytes) = (stride as u64).checked_mul(extent.height as u64) else {
            return Err(GraphicsProtocolError::InvalidBuffer);
        };
        if (stride as u64) < minimum_stride
            || required_bytes > byte_length
            || byte_length == 0
            || byte_length > MAX_GRAPHICS_BUFFER_BYTES
        {
            return Err(GraphicsProtocolError::InvalidBuffer);
        }
        Ok(Self {
            object,
            generation,
            extent,
            stride,
            byte_length,
            format,
        })
    }

    pub const fn object(self) -> ObjectId {
        self.object
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn extent(self) -> PhysicalExtent {
        self.extent
    }

    pub const fn stride(self) -> u32 {
        self.stride
    }

    pub const fn byte_length(self) -> u64 {
        self.byte_length
    }

    pub const fn format(self) -> GraphicsFormat {
        self.format
    }
}

/// Immutable control-plane result for one atomic surface update.
///
/// Capability validation happens once. Consuming this value establishes the
/// shortest safe data-plane binding; buffer bytes still cannot confer surface,
/// output, presentation, or configuration authority.
pub struct AdmittedSurfaceCommit {
    surface_capability: Capability,
    output_capability: Capability,
    buffer_capability: Capability,
    surface: SurfaceIdentity,
    output: DisplayOutputIdentity,
    buffer: GraphicsBufferDescriptor,
    logical_bounds: LogicalRect,
    scale: LogicalScale,
    serial: u64,
    damage: SurfaceDamage,
}

impl AdmittedSurfaceCommit {
    pub fn into_data_plane(self) -> SurfaceDataPlaneBinding {
        SurfaceDataPlaneBinding {
            surface_capability: self.surface_capability,
            output_capability: self.output_capability,
            buffer_capability: self.buffer_capability,
            surface: self.surface,
            output: self.output,
            buffer: self.buffer,
            logical_bounds: self.logical_bounds,
            scale: self.scale,
            serial: self.serial,
            damage: self.damage,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct SurfaceDataPlaneBinding {
    surface_capability: Capability,
    output_capability: Capability,
    buffer_capability: Capability,
    surface: SurfaceIdentity,
    output: DisplayOutputIdentity,
    buffer: GraphicsBufferDescriptor,
    logical_bounds: LogicalRect,
    scale: LogicalScale,
    serial: u64,
    damage: SurfaceDamage,
}

impl SurfaceDataPlaneBinding {
    pub const fn surface(&self) -> SurfaceIdentity {
        self.surface
    }

    pub const fn output(&self) -> DisplayOutputIdentity {
        self.output
    }

    pub const fn buffer(&self) -> GraphicsBufferDescriptor {
        self.buffer
    }

    pub const fn logical_bounds(&self) -> LogicalRect {
        self.logical_bounds
    }

    pub const fn scale(&self) -> LogicalScale {
        self.scale
    }

    pub const fn serial(&self) -> u64 {
        self.serial
    }

    pub const fn damage(&self) -> SurfaceDamage {
        self.damage
    }

    /// Rechecks the exact handles before a data-plane mapping, copy, or
    /// presentation step. This is a bounded table lookup, not policy replay;
    /// revocation or slot reuse therefore still stops the shortest safe path.
    pub fn revalidate<const CAPABILITIES: usize>(
        &self,
        capabilities: &CapabilitySpace<CAPABILITIES>,
    ) -> Result<(), GraphicsProtocolError> {
        let surface = capabilities
            .authorize(self.surface_capability, Rights::CONTROL)
            .map_err(|_| GraphicsProtocolError::InvalidCapability)?;
        let output = capabilities
            .authorize(self.output_capability, Rights::INSPECT)
            .map_err(|_| GraphicsProtocolError::InvalidCapability)?;
        let buffer = capabilities
            .authorize(self.buffer_capability, Rights::READ)
            .map_err(|_| GraphicsProtocolError::InvalidCapability)?;
        if surface != self.surface.object
            || output != self.output.object
            || buffer != self.buffer.object
        {
            return Err(GraphicsProtocolError::WrongObject);
        }
        Ok(())
    }
}

pub fn admit_surface_interface_commit<const CAPABILITIES: usize, R: SurfaceObjectResolver>(
    capabilities: &CapabilitySpace<CAPABILITIES>,
    resolver: &mut R,
    envelope: surface_abi::CommitEnvelope,
    state: surface_abi::SurfaceState,
) -> Result<AdmittedSurfaceCommit, GraphicsProtocolError> {
    // `SurfaceState` is source-level convenience, not a proof that bytes were
    // decoded canonically. Re-encoding applies the complete generation-1
    // interface validation before any resolver or capability-table access.
    surface_abi::encode_surface_state(state)
        .map_err(|_| GraphicsProtocolError::InterfaceRejected)?;

    let (surface_capability, surface) = resolver.resolve_surface(envelope.surface)?;
    let (output_capability, output) = resolver.resolve_output(envelope.output)?;
    let (buffer_capability, buffer) = resolver.resolve_buffer(envelope.buffer)?;

    let expected_format = match state.format {
        surface_abi::SurfaceFormat::Bgra8Srgb => GraphicsFormat::Bgra8Srgb,
        surface_abi::SurfaceFormat::Rgba8Srgb => GraphicsFormat::Rgba8Srgb,
    };
    if buffer.extent().width() != state.buffer_width
        || buffer.extent().height() != state.buffer_height
        || buffer.stride() != state.buffer_stride
        || buffer.byte_length() != state.buffer_byte_length
        || buffer.format() != expected_format
    {
        return Err(GraphicsProtocolError::InvalidBuffer);
    }

    let logical_bounds = LogicalRect::new(
        state.logical_bounds.x,
        state.logical_bounds.y,
        state.logical_bounds.width,
        state.logical_bounds.height,
    )?;
    let scale = LogicalScale::new(state.scale_numerator, state.scale_denominator)?;
    let mut damage_rects = [LogicalRect::EMPTY; MAX_SURFACE_DAMAGE_RECTS];
    for (target, source) in damage_rects
        .iter_mut()
        .zip(state.damage.iter())
        .take(state.damage_count as usize)
    {
        *target = LogicalRect::new(source.x, source.y, source.width, source.height)?;
    }
    let damage = SurfaceDamage::new(state.damage_count as u8, damage_rects)?;
    authorize_surface_commit(
        capabilities,
        surface_capability,
        surface,
        output_capability,
        output,
        buffer_capability,
        buffer,
        logical_bounds,
        scale,
        state.serial,
        damage,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn authorize_surface_commit<const CAPABILITIES: usize>(
    capabilities: &CapabilitySpace<CAPABILITIES>,
    surface_capability: Capability,
    surface: SurfaceIdentity,
    output_capability: Capability,
    output: DisplayOutputIdentity,
    buffer_capability: Capability,
    buffer: GraphicsBufferDescriptor,
    logical_bounds: LogicalRect,
    scale: LogicalScale,
    serial: u64,
    damage: SurfaceDamage,
) -> Result<AdmittedSurfaceCommit, GraphicsProtocolError> {
    if serial == 0 {
        return Err(GraphicsProtocolError::InvalidGeneration);
    }
    let authorized_surface = capabilities
        .authorize(surface_capability, Rights::CONTROL)
        .map_err(|_| GraphicsProtocolError::InvalidCapability)?;
    let authorized_output = capabilities
        .authorize(output_capability, Rights::INSPECT)
        .map_err(|_| GraphicsProtocolError::InvalidCapability)?;
    let authorized_buffer = capabilities
        .authorize(buffer_capability, Rights::READ)
        .map_err(|_| GraphicsProtocolError::InvalidCapability)?;
    if authorized_surface != surface.object
        || authorized_output != output.object
        || authorized_buffer != buffer.object
    {
        return Err(GraphicsProtocolError::WrongObject);
    }
    let rects = damage.rects();
    for rect in &rects[..damage.count() as usize] {
        if !logical_bounds.contains(*rect) {
            return Err(GraphicsProtocolError::InvalidDamage);
        }
    }
    Ok(AdmittedSurfaceCommit {
        surface_capability,
        output_capability,
        buffer_capability,
        surface,
        output,
        buffer,
        logical_bounds,
        scale,
        serial,
        damage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Resolver {
        surface_handle: surface_abi::OpaqueHandle,
        surface: (Capability, SurfaceIdentity),
        output_handle: surface_abi::OpaqueHandle,
        output: (Capability, DisplayOutputIdentity),
        buffer_handle: surface_abi::OpaqueHandle,
        buffer: (Capability, GraphicsBufferDescriptor),
    }

    impl SurfaceObjectResolver for Resolver {
        fn resolve_surface(
            &mut self,
            handle: surface_abi::OpaqueHandle,
        ) -> Result<(Capability, SurfaceIdentity), GraphicsProtocolError> {
            (handle == self.surface_handle)
                .then_some(self.surface)
                .ok_or(GraphicsProtocolError::InvalidIdentity)
        }

        fn resolve_output(
            &mut self,
            handle: surface_abi::OpaqueHandle,
        ) -> Result<(Capability, DisplayOutputIdentity), GraphicsProtocolError> {
            (handle == self.output_handle)
                .then_some(self.output)
                .ok_or(GraphicsProtocolError::InvalidIdentity)
        }

        fn resolve_buffer(
            &mut self,
            handle: surface_abi::OpaqueHandle,
        ) -> Result<(Capability, GraphicsBufferDescriptor), GraphicsProtocolError> {
            (handle == self.buffer_handle)
                .then_some(self.buffer)
                .ok_or(GraphicsProtocolError::InvalidIdentity)
        }
    }

    fn one_damage(rect: LogicalRect) -> SurfaceDamage {
        let mut rects = [LogicalRect::EMPTY; MAX_SURFACE_DAMAGE_RECTS];
        rects[0] = rect;
        SurfaceDamage::new(1, rects).unwrap()
    }

    fn fixture() -> (
        CapabilitySpace<4>,
        Capability,
        SurfaceIdentity,
        Capability,
        DisplayOutputIdentity,
        Capability,
        GraphicsBufferDescriptor,
    ) {
        let surface = SurfaceIdentity::new(ObjectId(10), 4).unwrap();
        let output = DisplayOutputIdentity::new(ObjectId(20), 8).unwrap();
        let buffer = GraphicsBufferDescriptor::new(
            ObjectId(30),
            12,
            PhysicalExtent::new(800, 600).unwrap(),
            3200,
            1_920_000,
            GraphicsFormat::Bgra8Srgb,
        )
        .unwrap();
        let mut capabilities = CapabilitySpace::<4>::new();
        let surface_capability = capabilities
            .insert(surface.object(), Rights::CONTROL)
            .unwrap();
        let output_capability = capabilities
            .insert(output.object(), Rights::INSPECT)
            .unwrap();
        let buffer_capability = capabilities.insert(buffer.object(), Rights::READ).unwrap();
        (
            capabilities,
            surface_capability,
            surface,
            output_capability,
            output,
            buffer_capability,
            buffer,
        )
    }

    #[test]
    fn geometry_and_buffer_layout_are_bounded_before_authority() {
        assert_eq!(
            LogicalScale::new(0, 1),
            Err(GraphicsProtocolError::InvalidScale)
        );
        assert_eq!(
            LogicalRect::new(i32::MAX, 0, 2, 1),
            Err(GraphicsProtocolError::InvalidGeometry)
        );
        assert_eq!(
            GraphicsBufferDescriptor::new(
                ObjectId(1),
                1,
                PhysicalExtent::new(800, 600).unwrap(),
                3199,
                1_920_000,
                GraphicsFormat::Bgra8Srgb,
            ),
            Err(GraphicsProtocolError::InvalidBuffer)
        );
    }

    #[test]
    fn atomic_commit_requires_exact_distinct_capability_objects() {
        let (capabilities, surface_cap, surface, output_cap, output, buffer_cap, buffer) =
            fixture();
        let bounds = LogicalRect::new(10, 20, 800, 600).unwrap();
        let damage = one_damage(LogicalRect::new(10, 20, 100, 50).unwrap());
        let admitted = authorize_surface_commit(
            &capabilities,
            surface_cap,
            surface,
            output_cap,
            output,
            buffer_cap,
            buffer,
            bounds,
            LogicalScale::new(3, 2).unwrap(),
            99,
            damage,
        )
        .unwrap();
        let binding = admitted.into_data_plane();
        assert_eq!(binding.surface(), surface);
        assert_eq!(binding.output(), output);
        assert_eq!(binding.buffer(), buffer);
        assert_eq!(binding.serial(), 99);
        assert_eq!(binding.damage(), damage);
        assert_eq!(binding.revalidate(&capabilities), Ok(()));

        assert!(matches!(
            authorize_surface_commit(
                &capabilities,
                surface_cap,
                SurfaceIdentity::new(ObjectId(11), 4).unwrap(),
                output_cap,
                output,
                buffer_cap,
                buffer,
                bounds,
                LogicalScale::new(1, 1).unwrap(),
                100,
                damage,
            ),
            Err(GraphicsProtocolError::WrongObject)
        ));
    }

    #[test]
    fn damage_and_rights_fail_closed_without_a_data_plane_binding() {
        let (mut capabilities, surface_cap, surface, output_cap, output, buffer_cap, buffer) =
            fixture();
        let bounds = LogicalRect::new(0, 0, 800, 600).unwrap();
        let outside = one_damage(LogicalRect::new(799, 599, 2, 1).unwrap());
        assert!(matches!(
            authorize_surface_commit(
                &capabilities,
                surface_cap,
                surface,
                output_cap,
                output,
                buffer_cap,
                buffer,
                bounds,
                LogicalScale::new(1, 1).unwrap(),
                1,
                outside,
            ),
            Err(GraphicsProtocolError::InvalidDamage)
        ));
        let binding = authorize_surface_commit(
            &capabilities,
            surface_cap,
            surface,
            output_cap,
            output,
            buffer_cap,
            buffer,
            bounds,
            LogicalScale::new(1, 1).unwrap(),
            2,
            one_damage(bounds),
        )
        .unwrap()
        .into_data_plane();
        capabilities.revoke(buffer_cap).unwrap();
        assert_eq!(
            binding.revalidate(&capabilities),
            Err(GraphicsProtocolError::InvalidCapability)
        );
        assert!(matches!(
            authorize_surface_commit(
                &capabilities,
                surface_cap,
                surface,
                output_cap,
                output,
                buffer_cap,
                buffer,
                bounds,
                LogicalScale::new(1, 1).unwrap(),
                3,
                one_damage(bounds),
            ),
            Err(GraphicsProtocolError::InvalidCapability)
        ));
    }

    #[test]
    fn stable_interface_handles_resolve_into_the_same_revocable_binding() {
        let (capabilities, surface_cap, surface, output_cap, output, buffer_cap, buffer) =
            fixture();
        let surface_handle = surface_abi::OpaqueHandle::new(1, 4).unwrap();
        let output_handle = surface_abi::OpaqueHandle::new(2, 8).unwrap();
        let buffer_handle = surface_abi::OpaqueHandle::new(3, 12).unwrap();
        let mut resolver = Resolver {
            surface_handle,
            surface: (surface_cap, surface),
            output_handle,
            output: (output_cap, output),
            buffer_handle,
            buffer: (buffer_cap, buffer),
        };
        let view = surface_abi::BorrowedReadView::within(
            0,
            surface_abi::SURFACE_STATE_BYTES as u64,
            surface_abi::SURFACE_STATE_BYTES as u64,
        )
        .unwrap();
        let request =
            surface_abi::encode_commit_request(surface_handle, output_handle, buffer_handle, view)
                .unwrap();
        let envelope =
            surface_abi::decode_commit_request(&request, surface_abi::SURFACE_STATE_BYTES as u64)
                .unwrap();
        let mut damage = [surface_abi::LogicalRect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        }; surface_abi::MAX_DAMAGE_RECTS];
        damage[0] = surface_abi::LogicalRect {
            x: 10,
            y: 20,
            width: 100,
            height: 50,
        };
        let state = surface_abi::SurfaceState {
            logical_bounds: surface_abi::LogicalRect {
                x: 10,
                y: 20,
                width: 800,
                height: 600,
            },
            scale_numerator: 1,
            scale_denominator: 1,
            buffer_width: 800,
            buffer_height: 600,
            buffer_stride: 3200,
            buffer_byte_length: 1_920_000,
            format: surface_abi::SurfaceFormat::Bgra8Srgb,
            serial: 21,
            damage_count: 1,
            damage,
        };
        let canonical_state = surface_abi::encode_surface_state(state).unwrap();
        let decoded_state = surface_abi::decode_surface_state(&canonical_state).unwrap();
        let binding =
            admit_surface_interface_commit(&capabilities, &mut resolver, envelope, decoded_state)
                .unwrap()
                .into_data_plane();
        assert_eq!(binding.serial(), 21);
        assert_eq!(binding.damage().count(), 1);
        assert_eq!(binding.revalidate(&capabilities), Ok(()));

        let substituted = surface_abi::CommitEnvelope {
            buffer: surface_abi::OpaqueHandle::new(4, 12).unwrap(),
            ..envelope
        };
        assert!(matches!(
            admit_surface_interface_commit(&capabilities, &mut resolver, substituted, state),
            Err(GraphicsProtocolError::InvalidIdentity)
        ));
    }
}
