use crate::PhysAddr;

const WRITE_BACK_MEMORY_TYPE: u8 = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmxError {
    Unsupported,
    InvalidRegionSize,
    WrongMemoryType,
    MissingEpt,
    MissingUnrestrictedGuest,
    MissingInvept,
    InvalidControl,
    InvalidEptPointer,
    InvalidState,
    InvalidVmcsField,
    InvalidVmExit,
    InstructionFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmxInstructionError {
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmxLaunchOutcome {
    GuestRunning,
    VmExit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmcsField(u32);

impl VmcsField {
    pub const VM_INSTRUCTION_ERROR: Self = Self(0x4400);
    pub const EXIT_REASON: Self = Self(0x4402);
    pub const EXIT_QUALIFICATION: Self = Self(0x6400);
    pub const GUEST_PHYSICAL_ADDRESS: Self = Self(0x2400);
    pub const GUEST_LINEAR_ADDRESS: Self = Self(0x640a);

    pub const fn new(encoding: u32) -> Result<Self, VmxError> {
        // Bits 15:13 select the architectural VMCS field width and bit 12 is
        // reserved. Encodings above bit 15 are not architectural VMCS fields.
        if encoding & 0x9000 != 0 {
            return Err(VmxError::InvalidVmcsField);
        }
        Ok(Self(encoding))
    }

    pub const fn encoding(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EptViolation {
    qualification: u64,
    guest_physical_address: u64,
    guest_linear_address: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmExitSnapshot {
    reason: u32,
    qualification: u64,
    guest_physical_address: u64,
    guest_linear_address: u64,
}

impl VmExitSnapshot {
    pub const fn reason(self) -> u32 {
        self.reason
    }

    pub const fn qualification(self) -> u64 {
        self.qualification
    }

    pub const fn guest_physical_address(self) -> u64 {
        self.guest_physical_address
    }

    pub const fn guest_linear_address(self) -> u64 {
        self.guest_linear_address
    }

    pub fn private_page_violation(self, private_page: PhysAddr) -> Result<EptViolation, VmxError> {
        if private_page.get() & 0xfff != 0 {
            return Err(VmxError::InvalidVmExit);
        }
        let violation = EptViolation::decode(
            self.reason,
            self.qualification,
            self.guest_physical_address,
            self.guest_linear_address,
        )?;
        if self
            .guest_physical_address
            .checked_sub(private_page.get())
            .is_none_or(|offset| offset >= 4096)
        {
            return Err(VmxError::InvalidVmExit);
        }
        Ok(violation)
    }
}

impl EptViolation {
    pub const fn decode(
        raw_reason: u32,
        qualification: u64,
        guest_physical_address: u64,
        guest_linear_address: u64,
    ) -> Result<Self, VmxError> {
        const EPT_VIOLATION: u32 = 48;
        const ENTRY_FAILURE: u32 = 1 << 31;
        const ACCESS_MASK: u64 = 0b111;
        const GPA_VALID: u64 = 1 << 7;
        const GLA_VALID: u64 = 1 << 8;
        if raw_reason & ENTRY_FAILURE != 0
            || raw_reason & 0xffff != EPT_VIOLATION
            || qualification & ACCESS_MASK == 0
            || qualification & GPA_VALID == 0
            || qualification & GLA_VALID != 0 && qualification & GPA_VALID == 0
            || guest_physical_address > 0x000f_ffff_ffff_ffff
        {
            return Err(VmxError::InvalidVmExit);
        }
        Ok(Self {
            qualification,
            guest_physical_address,
            guest_linear_address: if qualification & GLA_VALID != 0 {
                Some(guest_linear_address)
            } else {
                None
            },
        })
    }

    pub const fn attempted_read(self) -> bool {
        self.qualification & 1 != 0
    }

    pub const fn attempted_write(self) -> bool {
        self.qualification & 2 != 0
    }

    pub const fn attempted_execute(self) -> bool {
        self.qualification & 4 != 0
    }

    pub const fn guest_physical_address(self) -> u64 {
        self.guest_physical_address
    }

    pub const fn guest_linear_address(self) -> Option<u64> {
        self.guest_linear_address
    }
}

/// Intel VMX control MSRs encode required-one bits in the low half and
/// allowed-one bits in the high half. A set low-half bit requires one,
/// while a clear high-half bit forbids one. Adjustment therefore forces
/// required ones and clears forbidden ones without trusting a caller-provided
/// control.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmxControlMask {
    required_one: u32,
    allowed_one: u32,
}

impl VmxControlMask {
    pub const fn new(msr: u64) -> Result<Self, VmxError> {
        let required_one = msr as u32;
        let allowed_one = (msr >> 32) as u32;
        if required_one & !allowed_one != 0 {
            return Err(VmxError::InvalidControl);
        }
        Ok(Self {
            required_one,
            allowed_one,
        })
    }

    pub const fn adjust(self, requested: u32) -> u32 {
        (requested | self.required_one) & self.allowed_one
    }

    pub const fn accepts(self, value: u32) -> bool {
        self.adjust(value) == value
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmxControl(u32);

impl VmxControl {
    pub const fn constrained(requested: u32, mask: VmxControlMask) -> Self {
        Self(mask.adjust(requested))
    }

    pub const fn bits(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmxControlPolicy {
    pin: VmxControlMask,
    primary: VmxControlMask,
    exit: VmxControlMask,
    entry: VmxControlMask,
    secondary: VmxControlMask,
}

impl VmxControlPolicy {
    pub fn from_msrs(
        pin: u64,
        primary: u64,
        exit: u64,
        entry: u64,
        secondary: u64,
    ) -> Result<Self, VmxError> {
        Ok(Self {
            pin: VmxControlMask::new(pin)?,
            primary: VmxControlMask::new(primary)?,
            exit: VmxControlMask::new(exit)?,
            entry: VmxControlMask::new(entry)?,
            secondary: VmxControlMask::new(secondary)?,
        })
    }

    const fn accepts(self, pin: u32, primary: u32, exit: u32, entry: u32, secondary: u32) -> bool {
        self.pin.accepts(pin)
            && self.primary.accepts(primary)
            && self.exit.accepts(exit)
            && self.entry.accepts(entry)
            && self.secondary.accepts(secondary)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmxCapabilities {
    revision_id: u32,
    region_bytes: u16,
    memory_type: u8,
    ept: bool,
    unrestricted_guest: bool,
    invept_single_context: bool,
}

impl VmxCapabilities {
    pub const fn from_msrs(
        vmx_basic: u64,
        secondary_controls: u64,
        ept_vpid_capabilities: u64,
    ) -> Result<Self, VmxError> {
        let revision_id = vmx_basic as u32;
        let region_bytes = ((vmx_basic >> 32) & 0x1fff) as u16;
        let memory_type = ((vmx_basic >> 50) & 0xf) as u8;
        let allowed_one = (secondary_controls >> 32) as u32;
        let ept = allowed_one & (1 << 1) != 0;
        let unrestricted_guest = allowed_one & (1 << 7) != 0;
        let invept = ept_vpid_capabilities & (1 << 20) != 0;
        let invept_single_context = ept_vpid_capabilities & (1 << 25) != 0;
        Self::new(
            revision_id,
            region_bytes,
            memory_type,
            ept,
            unrestricted_guest,
            invept && invept_single_context,
        )
    }

    pub const fn new(
        revision_id: u32,
        region_bytes: u16,
        memory_type: u8,
        ept: bool,
        unrestricted_guest: bool,
        invept_single_context: bool,
    ) -> Result<Self, VmxError> {
        if revision_id & (1 << 31) != 0 {
            return Err(VmxError::Unsupported);
        }
        if region_bytes == 0 || region_bytes > 4096 {
            return Err(VmxError::InvalidRegionSize);
        }
        if memory_type != WRITE_BACK_MEMORY_TYPE {
            return Err(VmxError::WrongMemoryType);
        }
        if !ept {
            return Err(VmxError::MissingEpt);
        }
        if !unrestricted_guest {
            return Err(VmxError::MissingUnrestrictedGuest);
        }
        if !invept_single_context {
            return Err(VmxError::MissingInvept);
        }
        Ok(Self {
            revision_id,
            region_bytes,
            memory_type,
            ept,
            unrestricted_guest,
            invept_single_context,
        })
    }

    pub const fn revision_id(self) -> u32 {
        self.revision_id
    }

    pub const fn region_bytes(self) -> u16 {
        self.region_bytes
    }

    pub const fn memory_type(self) -> u8 {
        self.memory_type
    }

    pub const fn has_required_isolation(self) -> bool {
        self.ept && self.unrestricted_guest && self.invept_single_context
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmxPrerequisites {
    feature_control: u64,
    cr0: u64,
    cr4: u64,
    cr0_fixed_zero: u64,
    cr0_fixed_one: u64,
    cr4_fixed_zero: u64,
    cr4_fixed_one: u64,
}

impl VmxPrerequisites {
    pub const fn new(
        feature_control: u64,
        cr0: u64,
        cr4: u64,
        cr0_fixed_zero: u64,
        cr0_fixed_one: u64,
        cr4_fixed_zero: u64,
        cr4_fixed_one: u64,
    ) -> Self {
        Self {
            feature_control,
            cr0,
            cr4,
            cr0_fixed_zero,
            cr0_fixed_one,
            cr4_fixed_zero,
            cr4_fixed_one,
        }
    }

    /// Bits that violate VMX host-control requirements, in this order:
    /// missing CR0, forbidden CR0, missing CR4 (including VMXE), forbidden CR4.
    pub const fn host_control_mismatch(self) -> [u64; 4] {
        const CR4_VMXE: u64 = 1 << 13;
        [
            self.cr0_fixed_zero & !self.cr0,
            self.cr0 & !self.cr0_fixed_one,
            (self.cr4_fixed_zero | CR4_VMXE) & !self.cr4,
            self.cr4 & !self.cr4_fixed_one,
        ]
    }

    pub const fn validate(self) -> Result<(), VmxError> {
        const FEATURE_LOCK: u64 = 1;
        const VMX_OUTSIDE_SMX: u64 = 1 << 2;
        if self.feature_control & (FEATURE_LOCK | VMX_OUTSIDE_SMX) != FEATURE_LOCK | VMX_OUTSIDE_SMX
        {
            return Err(VmxError::Unsupported);
        }
        if let [0, 0, 0, 0] = self.host_control_mismatch() {
            Ok(())
        } else {
            Err(VmxError::InvalidControl)
        }
    }

    pub fn unrestricted_guest_controls(self) -> Result<(u64, u64), VmxError> {
        self.validate()?;
        const CR0_PE: u64 = 1;
        const CR0_PG: u64 = 1 << 31;
        let cr0 = self.cr0_fixed_zero & !(CR0_PE | CR0_PG);
        let cr4 = self.cr4_fixed_zero;
        if cr0 & !self.cr0_fixed_one != 0 || cr4 & !self.cr4_fixed_one != 0 {
            return Err(VmxError::InvalidControl);
        }
        Ok((cr0, cr4))
    }
}

/// Canonical four-level EPT pointer using write-back page-table memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EptPointer(u64);

impl EptPointer {
    pub const fn new(root: PhysAddr, accessed_dirty: bool) -> Result<Self, VmxError> {
        if root.get() == 0 {
            return Err(VmxError::InvalidEptPointer);
        }
        Ok(Self(
            root.get() | WRITE_BACK_MEMORY_TYPE as u64 | (3 << 3) | ((accessed_dirty as u64) << 6),
        ))
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn root(self) -> Result<PhysAddr, VmxError> {
        match PhysAddr::new(self.0 & 0x000f_ffff_ffff_f000) {
            Ok(root) if root.get() != 0 => Ok(root),
            _ => Err(VmxError::InvalidEptPointer),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmxState {
    Disabled,
    Root,
    VmcsClear,
    VmcsLoaded,
    GuestRunning,
    VmExitPending,
    Poisoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmcsWrite {
    field: VmcsField,
    value: u64,
}

impl VmcsWrite {
    pub const fn new(field: VmcsField, value: u64) -> Result<Self, VmxError> {
        let width = (field.encoding() >> 13) & 3;
        if width == 0 && value > u16::MAX as u64 || width == 2 && value > u32::MAX as u64 {
            return Err(VmxError::InvalidControl);
        }
        Ok(Self { field, value })
    }

    pub const fn field(self) -> VmcsField {
        self.field
    }

    pub const fn value(self) -> u64 {
        self.value
    }
}

pub const VMCS_MINIMAL_LAUNCH_FIELDS: usize = 84;

/// Complete fixed field set for MRML's minimal unrestricted real-mode guest.
/// Optional bitmap, MSR-list, CR3-target, and posted-interrupt fields remain
/// disabled by the corresponding controls and therefore are deliberately not
/// part of this canonical launch format.
const MINIMAL_LAUNCH_FIELD_ENCODINGS: [u32; VMCS_MINIMAL_LAUNCH_FIELDS] = [
    0x0800, 0x0802, 0x0804, 0x0806, 0x0808, 0x080a, 0x080c, 0x080e, // guest selectors
    0x0c00, 0x0c02, 0x0c04, 0x0c06, 0x0c08, 0x0c0a, 0x0c0c, // host selectors
    0x201a, // EPT pointer
    0x2800, 0x2802, 0x2804, 0x2806, 0x2808, // guest link/debug/PAT/EFER/perf
    0x2c00, 0x2c02, 0x2c04, // host PAT/EFER/perf
    0x4000, 0x4002, 0x4004, 0x400c, 0x4012, 0x401e, // execution controls
    0x4800, 0x4802, 0x4804, 0x4806, 0x4808, 0x480a, 0x480c, 0x480e, // segment limits
    0x4810, 0x4812, // GDTR/IDTR limits
    0x4814, 0x4816, 0x4818, 0x481a, 0x481c, 0x481e, 0x4820, 0x4822, // guest access rights
    0x4824, 0x4826, 0x482a, // interrupt/activity/SYSENTER CS
    0x4c00, // host SYSENTER CS
    0x6800, 0x6802, 0x6804, // guest CR0/CR3/CR4
    0x6806, 0x6808, 0x680a, 0x680c, 0x680e, 0x6810, 0x6812, 0x6814, // segment bases
    0x6816, 0x6818, // GDTR/IDTR bases
    0x681a, 0x681c, 0x681e, 0x6820, // guest DR7/RSP/RIP/RFLAGS
    0x6822, 0x6824, 0x6826, // pending debug/SYSENTER ESP/EIP
    0x6c00, 0x6c02, 0x6c04, // host CR0/CR3/CR4
    0x6c06, 0x6c08, 0x6c0a, 0x6c0c, 0x6c0e, // host FS/GS/TR/GDTR/IDTR bases
    0x6c10, 0x6c12, // host SYSENTER ESP/EIP
    0x6c14, 0x6c16, // host RSP/RIP
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MinimalVmcsLaunch {
    writes: [VmcsWrite; VMCS_MINIMAL_LAUNCH_FIELDS],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmxHostState {
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
    pub pat: u64,
    pub perf_global_control: u64,
    pub selectors: [u16; 7],
    pub fs_base: u64,
    pub gs_base: u64,
    pub tr_base: u64,
    pub gdtr_base: u64,
    pub idtr_base: u64,
    pub sysenter_cs: u32,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    pub stack_pointer: u64,
    pub instruction_pointer: u64,
}

impl MinimalVmcsLaunch {
    pub fn unrestricted_real_mode(
        ept: EptPointer,
        controls: VmxControlPolicy,
        host: VmxHostState,
        guest_cr0: u64,
        guest_cr4: u64,
        guest_rip: u16,
        guest_rsp: u16,
    ) -> Result<Self, VmxError> {
        let mut values = [0u64; VMCS_MINIMAL_LAUNCH_FIELDS];
        values[..8].fill(0);
        for (destination, selector) in values[8..15].iter_mut().zip(host.selectors) {
            *destination = u64::from(selector);
        }
        values[15] = ept.bits();
        values[16] = u64::MAX;
        values[17..20].copy_from_slice(&[0, host.pat, 0]);
        values[20] = 0;
        values[21..24].copy_from_slice(&[host.pat, host.efer, host.perf_global_control]);
        values[24] = u64::from(VmxControl::constrained(0, controls.pin).bits());
        values[25] = u64::from(VmxControl::constrained(1 << 31, controls.primary).bits());
        values[26] = 0;
        values[27] = u64::from(VmxControl::constrained(1 << 9, controls.exit).bits());
        values[28] = u64::from(VmxControl::constrained(0, controls.entry).bits());
        values[29] =
            u64::from(VmxControl::constrained((1 << 1) | (1 << 7), controls.secondary).bits());
        values[30..40].copy_from_slice(&[
            0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0, 0x67, 0xffff, 0xffff,
        ]);
        values[40..48].copy_from_slice(&[
            0x0093,
            0x009b,
            0x0093,
            0x0093,
            0x0093,
            0x0093,
            1 << 16,
            0x008b,
        ]);
        values[48..52].fill(0);
        values[52..65].fill(0);
        values[52] = guest_cr0;
        values[54] = guest_cr4;
        values[65..72].copy_from_slice(&[
            0x400,
            u64::from(guest_rsp),
            u64::from(guest_rip),
            2,
            0,
            0,
            0,
        ]);
        values[72..75].copy_from_slice(&[host.cr0, host.cr3, host.cr4]);
        values[75..84].copy_from_slice(&[
            host.fs_base,
            host.gs_base,
            host.tr_base,
            host.gdtr_base,
            host.idtr_base,
            host.sysenter_esp,
            host.sysenter_eip,
            host.stack_pointer,
            host.instruction_pointer,
        ]);
        values[51] = u64::from(host.sysenter_cs);
        Self::new(values, controls)
    }

    pub fn new(
        values: [u64; VMCS_MINIMAL_LAUNCH_FIELDS],
        controls: VmxControlPolicy,
    ) -> Result<Self, VmxError> {
        let mut writes = [VmcsWrite {
            field: VmcsField(0),
            value: 0,
        }; VMCS_MINIMAL_LAUNCH_FIELDS];
        let mut index = 0;
        while index < writes.len() {
            let field = VmcsField::new(MINIMAL_LAUNCH_FIELD_ENCODINGS[index])?;
            writes[index] = VmcsWrite::new(field, values[index])?;
            index += 1;
        }
        let launch = Self { writes };
        launch.validate(controls)?;
        Ok(launch)
    }

    fn validate(&self, controls: VmxControlPolicy) -> Result<(), VmxError> {
        let value = |encoding| {
            self.writes
                .iter()
                .find(|write| write.field.encoding() == encoding)
                .map(|write| write.value)
                .ok_or(VmxError::InvalidControl)
        };
        let pin = value(0x4000)? as u32;
        let primary = value(0x4002)? as u32;
        let exit = value(0x400c)? as u32;
        let entry = value(0x4012)? as u32;
        let secondary = value(0x401e)? as u32;
        let ept = value(0x201a)?;
        let guest_rflags = value(0x6820)?;
        let guest_rip = value(0x681e)?;
        let host_rsp = value(0x6c14)?;
        let host_rip = value(0x6c16)?;
        const ACTIVATE_SECONDARY: u32 = 1 << 31;
        const ENABLE_EPT: u32 = 1 << 1;
        const UNRESTRICTED_GUEST: u32 = 1 << 7;
        const HOST_ADDRESS_SPACE_SIZE: u32 = 1 << 9;
        const IA32E_GUEST: u32 = 1 << 9;
        if !controls.accepts(pin, primary, exit, entry, secondary)
            || primary & ACTIVATE_SECONDARY == 0
            || secondary & (ENABLE_EPT | UNRESTRICTED_GUEST) != ENABLE_EPT | UNRESTRICTED_GUEST
            || exit & HOST_ADDRESS_SPACE_SIZE == 0
            || entry & IA32E_GUEST != 0
            || EptPointer(ept).root().is_err()
            || value(0x6800)? & ((1 << 31) | 1) != 0
            || value(0x6804)? & (1 << 5) != 0
            || value(0x2806)? & ((1 << 10) | (1 << 8)) != 0
            || value(0x2c02)? & ((1 << 10) | (1 << 8)) != (1 << 10) | (1 << 8)
            || !valid_pat(value(0x2804)?)
            || !valid_pat(value(0x2c00)?)
            || guest_rflags & 2 == 0
            || guest_rip > u16::MAX as u64
            || host_rsp == 0
            || !canonical(host_rsp)
            || host_rip == 0
            || !canonical(host_rip)
            || value(0x2800)? != u64::MAX
        {
            return Err(VmxError::InvalidControl);
        }
        for selector in [0x0c00, 0x0c02, 0x0c04, 0x0c06, 0x0c08, 0x0c0a] {
            if value(selector)? & 7 != 0 {
                return Err(VmxError::InvalidControl);
            }
        }
        if value(0x0c02)? == 0 || value(0x0c0c)? & 7 != 0 || value(0x0c0c)? == 0 {
            return Err(VmxError::InvalidControl);
        }
        for address in [
            0x6c06, 0x6c08, 0x6c0a, 0x6c0c, 0x6c0e, 0x6c10, 0x6c12, 0x6c14, 0x6c16,
        ] {
            if !canonical(value(address)?) {
                return Err(VmxError::InvalidControl);
            }
        }
        Ok(())
    }

    pub fn writes(&self) -> &[VmcsWrite; VMCS_MINIMAL_LAUNCH_FIELDS] {
        &self.writes
    }

    pub fn ept_pointer(&self) -> EptPointer {
        EptPointer(self.writes[15].value)
    }
}

const fn canonical(address: u64) -> bool {
    let upper = address >> 48;
    upper == 0 || upper == 0xffff
}

const fn valid_pat(pat: u64) -> bool {
    let mut index = 0;
    while index < 8 {
        let entry = ((pat >> (index * 8)) & 0xff) as u8;
        if !matches!(entry, 0 | 1 | 4 | 5 | 6 | 7) {
            return false;
        }
        index += 1;
    }
    true
}

/// Narrow unsafe-instruction boundary. A bare-metal adapter implements these
/// operations; tests and hosted probes use a deterministic emulator.
pub trait VmxInstructions {
    fn vmxon(&mut self, region: PhysAddr) -> Result<(), VmxInstructionError>;
    fn vmxoff(&mut self) -> Result<(), VmxInstructionError>;
    fn vmclear(&mut self, vmcs: PhysAddr) -> Result<(), VmxInstructionError>;
    fn vmptrld(&mut self, vmcs: PhysAddr) -> Result<(), VmxInstructionError>;
    fn vmlaunch(&mut self) -> Result<VmxLaunchOutcome, VmxInstructionError>;
    fn vmresume(&mut self) -> Result<VmxLaunchOutcome, VmxInstructionError>;
    fn vmwrite(&mut self, field: VmcsField, value: u64) -> Result<(), VmxInstructionError>;
    fn vmread(&mut self, field: VmcsField) -> Result<u64, VmxInstructionError>;
    fn invept_single_context(&mut self, ept: EptPointer) -> Result<(), VmxInstructionError>;
}

/// Direct Intel VMX instruction adapter for the bare-metal kernel.
/// Construction is unsafe so hosted code cannot accidentally execute
/// privileged instructions through an otherwise safe trait method.
pub struct NativeVmx {
    _private: (),
}

impl NativeVmx {
    /// # Safety
    ///
    /// The caller must be executing at CPL0 on an x86_64 CPU with VMX enabled
    /// in IA32_FEATURE_CONTROL and CR4.VMXE. VMX regions and VMCS host-state
    /// fields must remain valid according to the Intel architecture contract.
    pub const unsafe fn assume_cpl0_vmx_enabled() -> Self {
        Self { _private: () }
    }

    fn physical_operand(
        instruction: unsafe fn(*const u64) -> u8,
        address: PhysAddr,
    ) -> Result<(), VmxInstructionError> {
        let operand = address.get();
        // SAFETY: NativeVmx can only be constructed through the documented
        // unsafe CPL0 boundary; `operand` is live for the instruction.
        if unsafe { instruction(core::ptr::from_ref(&operand)) } == 0 {
            Ok(())
        } else {
            Err(VmxInstructionError::Failed)
        }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn native_vmxon(operand: *const u64) -> u8 {
    let failed: u8;
    unsafe {
        core::arch::asm!(
            "vmxon [{operand}]",
            "setna {failed}",
            operand = in(reg) operand,
            failed = lateout(reg_byte) failed,
            options(nostack),
        );
    }
    failed
}

#[cfg(target_arch = "x86_64")]
unsafe fn native_vmclear(operand: *const u64) -> u8 {
    let failed: u8;
    unsafe {
        core::arch::asm!(
            "vmclear [{operand}]",
            "setna {failed}",
            operand = in(reg) operand,
            failed = lateout(reg_byte) failed,
            options(nostack),
        );
    }
    failed
}

#[cfg(target_arch = "x86_64")]
unsafe fn native_vmptrld(operand: *const u64) -> u8 {
    let failed: u8;
    unsafe {
        core::arch::asm!(
            "vmptrld [{operand}]",
            "setna {failed}",
            operand = in(reg) operand,
            failed = lateout(reg_byte) failed,
            options(nostack),
        );
    }
    failed
}

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    r#"
    .text
    .p2align 4
    .globl mrml_native_vmlaunch
mrml_native_vmlaunch:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rax, 0x6c14
    vmwrite rax, rsp
    setna cl
    test cl, cl
    jnz 3f
    lea rdx, [rip + 2f]
    mov rax, 0x6c16
    vmwrite rax, rdx
    setna cl
    test cl, cl
    jnz 3f
    vmlaunch
    jmp 3f
2:
    xor eax, eax
    jmp 4f
3:
    mov eax, 1
4:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

    .p2align 4
    .globl mrml_native_vmresume
mrml_native_vmresume:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rax, 0x6c14
    vmwrite rax, rsp
    setna cl
    test cl, cl
    jnz 7f
    lea rdx, [rip + 6f]
    mov rax, 0x6c16
    vmwrite rax, rdx
    setna cl
    test cl, cl
    jnz 7f
    vmresume
    jmp 7f
6:
    xor eax, eax
    jmp 8f
7:
    mov eax, 1
8:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
"#
);

#[cfg(target_arch = "x86_64")]
unsafe extern "sysv64" {
    fn mrml_native_vmlaunch() -> u8;
    fn mrml_native_vmresume() -> u8;
}

impl VmxInstructions for NativeVmx {
    fn vmxon(&mut self, region: PhysAddr) -> Result<(), VmxInstructionError> {
        Self::physical_operand(native_vmxon, region)
    }

    fn vmxoff(&mut self) -> Result<(), VmxInstructionError> {
        let failed: u8;
        unsafe {
            core::arch::asm!(
                "vmxoff",
                "setna {failed}",
                failed = lateout(reg_byte) failed,
                options(nostack),
            )
        };
        if failed == 0 {
            Ok(())
        } else {
            Err(VmxInstructionError::Failed)
        }
    }

    fn vmclear(&mut self, vmcs: PhysAddr) -> Result<(), VmxInstructionError> {
        Self::physical_operand(native_vmclear, vmcs)
    }

    fn vmptrld(&mut self, vmcs: PhysAddr) -> Result<(), VmxInstructionError> {
        Self::physical_operand(native_vmptrld, vmcs)
    }

    fn vmlaunch(&mut self) -> Result<VmxLaunchOutcome, VmxInstructionError> {
        // SAFETY: construction of NativeVmx requires CPL0 and a completely
        // programmed active VMCS. The assembly routine preserves the SysV
        // callee-saved registers and returns zero only through the host RIP
        // installed immediately before VMLAUNCH.
        if unsafe { mrml_native_vmlaunch() } == 0 {
            Ok(VmxLaunchOutcome::VmExit)
        } else {
            Err(VmxInstructionError::Failed)
        }
    }

    fn vmresume(&mut self) -> Result<VmxLaunchOutcome, VmxInstructionError> {
        // SAFETY: identical host-stack and register contract to VMLAUNCH above.
        if unsafe { mrml_native_vmresume() } == 0 {
            Ok(VmxLaunchOutcome::VmExit)
        } else {
            Err(VmxInstructionError::Failed)
        }
    }

    fn vmwrite(&mut self, field: VmcsField, value: u64) -> Result<(), VmxInstructionError> {
        let failed: u8;
        unsafe {
            core::arch::asm!(
                "vmwrite {field}, {value}",
                "setna {failed}",
                value = in(reg) value,
                field = in(reg) u64::from(field.encoding()),
                failed = lateout(reg_byte) failed,
                options(nostack),
            )
        };
        if failed == 0 {
            Ok(())
        } else {
            Err(VmxInstructionError::Failed)
        }
    }

    fn vmread(&mut self, field: VmcsField) -> Result<u64, VmxInstructionError> {
        let value: u64;
        let failed: u8;
        unsafe {
            core::arch::asm!(
                "vmread {value}, {field}",
                "setna {failed}",
                field = in(reg) u64::from(field.encoding()),
                value = lateout(reg) value,
                failed = lateout(reg_byte) failed,
                options(nostack),
            )
        };
        if failed == 0 {
            Ok(value)
        } else {
            Err(VmxInstructionError::Failed)
        }
    }

    fn invept_single_context(&mut self, ept: EptPointer) -> Result<(), VmxInstructionError> {
        #[repr(C, align(16))]
        struct InveptDescriptor {
            ept_pointer: u64,
            reserved: u64,
        }
        let descriptor = InveptDescriptor {
            ept_pointer: ept.bits(),
            reserved: 0,
        };
        let failed: u8;
        unsafe {
            core::arch::asm!(
                "invept {kind}, [{descriptor}]",
                "setna {failed}",
                kind = in(reg) 1u64,
                descriptor = in(reg) core::ptr::from_ref(&descriptor),
                failed = lateout(reg_byte) failed,
                options(nostack, readonly),
            )
        };
        if failed == 0 {
            Ok(())
        } else {
            Err(VmxInstructionError::Failed)
        }
    }
}

pub struct VmxController<I: VmxInstructions> {
    instructions: I,
    capabilities: VmxCapabilities,
    state: VmxState,
    active_vmcs: Option<PhysAddr>,
    active_ept: Option<EptPointer>,
    failed_vmwrite_index: Option<u8>,
}

impl<I: VmxInstructions> VmxController<I> {
    pub const fn new(instructions: I, capabilities: VmxCapabilities) -> Self {
        Self {
            instructions,
            capabilities,
            state: VmxState::Disabled,
            active_vmcs: None,
            active_ept: None,
            failed_vmwrite_index: None,
        }
    }

    pub const fn state(&self) -> VmxState {
        self.state
    }

    pub const fn capabilities(&self) -> VmxCapabilities {
        self.capabilities
    }

    pub const fn failed_vmwrite_index(&self) -> Option<u8> {
        self.failed_vmwrite_index
    }

    pub fn enter_root(&mut self, region: PhysAddr) -> Result<(), VmxError> {
        if self.state != VmxState::Disabled {
            return Err(VmxError::InvalidState);
        }
        self.instructions
            .vmxon(region)
            .map_err(|_| VmxError::InstructionFailed)?;
        self.state = VmxState::Root;
        Ok(())
    }

    pub fn clear_vmcs(&mut self, vmcs: PhysAddr) -> Result<(), VmxError> {
        if !matches!(self.state, VmxState::Root | VmxState::VmcsLoaded) {
            return Err(VmxError::InvalidState);
        }
        self.instructions
            .vmclear(vmcs)
            .map_err(|_| VmxError::InstructionFailed)?;
        self.active_vmcs = Some(vmcs);
        self.active_ept = None;
        self.state = VmxState::VmcsClear;
        Ok(())
    }

    pub fn load_vmcs(&mut self, vmcs: PhysAddr, ept: EptPointer) -> Result<(), VmxError> {
        if self.state != VmxState::VmcsClear || self.active_vmcs != Some(vmcs) {
            return Err(VmxError::InvalidState);
        }
        ept.root()?;
        self.instructions
            .vmptrld(vmcs)
            .map_err(|_| VmxError::InstructionFailed)?;
        self.instructions
            .invept_single_context(ept)
            .map_err(|_| VmxError::InstructionFailed)?;
        self.active_ept = Some(ept);
        self.state = VmxState::VmcsLoaded;
        Ok(())
    }

    pub fn launch(&mut self) -> Result<(), VmxError> {
        if self.state != VmxState::VmcsLoaded || self.active_ept.is_none() {
            return Err(VmxError::InvalidState);
        }
        match self.instructions.vmlaunch() {
            Ok(VmxLaunchOutcome::GuestRunning) => self.state = VmxState::GuestRunning,
            Ok(VmxLaunchOutcome::VmExit) => self.state = VmxState::VmExitPending,
            Err(_) => {
                self.state = VmxState::Poisoned;
                return Err(VmxError::InstructionFailed);
            }
        }
        Ok(())
    }

    pub fn program_minimal_vmcs(&mut self, launch: &MinimalVmcsLaunch) -> Result<(), VmxError> {
        if self.state != VmxState::VmcsLoaded || self.active_ept != Some(launch.ept_pointer()) {
            return Err(VmxError::InvalidState);
        }
        self.failed_vmwrite_index = None;
        for (index, write) in launch.writes().iter().enumerate() {
            if self.instructions.vmwrite(write.field, write.value).is_err() {
                self.failed_vmwrite_index = u8::try_from(index).ok();
                self.state = VmxState::Poisoned;
                return Err(VmxError::InstructionFailed);
            }
        }
        Ok(())
    }

    /// Records a VM exit before exit handling reads guest-controlled state.
    pub fn record_vm_exit(&mut self) -> Result<(), VmxError> {
        if !matches!(self.state, VmxState::GuestRunning | VmxState::VmExitPending) {
            return Err(VmxError::InvalidState);
        }
        self.state = VmxState::VmcsLoaded;
        Ok(())
    }

    /// Consumes the first exit after launch and proves it was an access to the
    /// exact monitor-private 4 KiB guest-physical page. Any VMREAD or decoding
    /// failure leaves the controller out of GuestRunning so callers must fail
    /// closed rather than resume uncertain guest state.
    pub fn record_private_page_violation(
        &mut self,
        private_page: PhysAddr,
    ) -> Result<EptViolation, VmxError> {
        self.record_vm_exit_snapshot()?
            .private_page_violation(private_page)
    }

    /// Captures the fixed architectural fields for one exit after first
    /// transitioning the controller out of a resumable guest state. This raw
    /// snapshot is diagnostic input, not authenticated protection evidence.
    pub fn record_vm_exit_snapshot(&mut self) -> Result<VmExitSnapshot, VmxError> {
        self.record_vm_exit()?;
        let reason = self
            .instructions
            .vmread(VmcsField::EXIT_REASON)
            .map_err(|_| VmxError::InstructionFailed)?;
        let qualification = self
            .instructions
            .vmread(VmcsField::EXIT_QUALIFICATION)
            .map_err(|_| VmxError::InstructionFailed)?;
        let guest_physical = self
            .instructions
            .vmread(VmcsField::GUEST_PHYSICAL_ADDRESS)
            .map_err(|_| VmxError::InstructionFailed)?;
        let guest_linear = self
            .instructions
            .vmread(VmcsField::GUEST_LINEAR_ADDRESS)
            .map_err(|_| VmxError::InstructionFailed)?;
        Ok(VmExitSnapshot {
            reason: u32::try_from(reason).map_err(|_| VmxError::InvalidVmExit)?,
            qualification,
            guest_physical_address: guest_physical,
            guest_linear_address: guest_linear,
        })
    }

    pub fn resume(&mut self) -> Result<(), VmxError> {
        if self.state != VmxState::VmcsLoaded || self.active_ept.is_none() {
            return Err(VmxError::InvalidState);
        }
        match self.instructions.vmresume() {
            Ok(VmxLaunchOutcome::GuestRunning) => self.state = VmxState::GuestRunning,
            Ok(VmxLaunchOutcome::VmExit) => self.state = VmxState::VmExitPending,
            Err(_) => {
                self.state = VmxState::Poisoned;
                return Err(VmxError::InstructionFailed);
            }
        }
        Ok(())
    }

    pub fn leave_root(&mut self) -> Result<(), VmxError> {
        if self.state == VmxState::GuestRunning || self.state == VmxState::Disabled {
            return Err(VmxError::InvalidState);
        }
        if self.instructions.vmxoff().is_err() {
            self.state = VmxState::Poisoned;
            return Err(VmxError::InstructionFailed);
        }
        self.active_vmcs = None;
        self.active_ept = None;
        self.failed_vmwrite_index = None;
        self.state = VmxState::Disabled;
        Ok(())
    }

    pub fn into_instructions(self) -> I {
        self.instructions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct EmulatedVmx {
        trace: u64,
        fail_at: u8,
        exit_reason: u64,
        exit_qualification: u64,
        guest_physical: u64,
        guest_linear: u64,
        exit_on_launch: bool,
    }

    impl EmulatedVmx {
        fn step(&mut self, operation: u8) -> Result<(), VmxInstructionError> {
            if self.fail_at == operation {
                return Err(VmxInstructionError::Failed);
            }
            self.trace = (self.trace << 8) | operation as u64;
            Ok(())
        }
    }

    impl VmxInstructions for EmulatedVmx {
        fn vmxon(&mut self, _: PhysAddr) -> Result<(), VmxInstructionError> {
            self.step(1)
        }
        fn vmxoff(&mut self) -> Result<(), VmxInstructionError> {
            self.step(2)
        }
        fn vmclear(&mut self, _: PhysAddr) -> Result<(), VmxInstructionError> {
            self.step(3)
        }
        fn vmptrld(&mut self, _: PhysAddr) -> Result<(), VmxInstructionError> {
            self.step(4)
        }
        fn vmlaunch(&mut self) -> Result<VmxLaunchOutcome, VmxInstructionError> {
            self.step(6)?;
            Ok(if self.exit_on_launch {
                VmxLaunchOutcome::VmExit
            } else {
                VmxLaunchOutcome::GuestRunning
            })
        }
        fn vmresume(&mut self) -> Result<VmxLaunchOutcome, VmxInstructionError> {
            self.step(7)?;
            Ok(if self.exit_on_launch {
                VmxLaunchOutcome::VmExit
            } else {
                VmxLaunchOutcome::GuestRunning
            })
        }
        fn vmwrite(&mut self, _: VmcsField, _: u64) -> Result<(), VmxInstructionError> {
            self.step(8)
        }
        fn vmread(&mut self, field: VmcsField) -> Result<u64, VmxInstructionError> {
            self.step(9)?;
            Ok(match field {
                VmcsField::EXIT_REASON => self.exit_reason,
                VmcsField::EXIT_QUALIFICATION => self.exit_qualification,
                VmcsField::GUEST_PHYSICAL_ADDRESS => self.guest_physical,
                VmcsField::GUEST_LINEAR_ADDRESS => self.guest_linear,
                _ => return Err(VmxInstructionError::Failed),
            })
        }
        fn invept_single_context(&mut self, _: EptPointer) -> Result<(), VmxInstructionError> {
            self.step(5)
        }
    }

    fn capabilities() -> VmxCapabilities {
        VmxCapabilities::new(7, 4096, 6, true, true, true).unwrap()
    }

    fn permissive_control_policy() -> VmxControlPolicy {
        const PERMISSIVE: u64 = (u32::MAX as u64) << 32;
        VmxControlPolicy::from_msrs(PERMISSIVE, PERMISSIVE, PERMISSIVE, PERMISSIVE, PERMISSIVE)
            .unwrap()
    }

    fn minimal_launch(ept: EptPointer) -> MinimalVmcsLaunch {
        MinimalVmcsLaunch::unrestricted_real_mode(
            ept,
            permissive_control_policy(),
            VmxHostState {
                cr0: 0x8001_0033,
                cr3: 0x10_0000,
                cr4: 0x2020,
                efer: 0xd00,
                pat: 0x0007_0406_0007_0406,
                perf_global_control: 0,
                selectors: [16, 8, 16, 16, 0, 0, 24],
                fs_base: 0,
                gs_base: 0,
                tr_base: 0xffff_8000_0000_3000,
                gdtr_base: 0xffff_8000_0000_4000,
                idtr_base: 0xffff_8000_0000_5000,
                sysenter_cs: 0,
                sysenter_esp: 0,
                sysenter_eip: 0,
                stack_pointer: 0xffff_8000_0000_6000,
                instruction_pointer: 0xffff_8000_0000_7000,
            },
            0x20,
            0x2000,
            0x1000,
            0x3000,
        )
        .unwrap()
    }

    #[test]
    fn controls_force_required_bits_and_clear_forbidden_bits() {
        let mask = VmxControlMask::new(0xffff_fff5_ffff_fff0).unwrap();
        let control = VmxControl::constrained(u32::MAX, mask);
        assert_eq!(control.bits(), 0xffff_fff5);
        assert!(mask.accepts(control.bits()));
        assert_eq!(VmxControl::constrained(0, mask).bits(), 0xffff_fff0);
        assert_eq!(
            VmxControlMask::new(0x0000_0000_0000_0001),
            Err(VmxError::InvalidControl)
        );
        assert!(!mask.accepts(u32::MAX));
    }

    #[test]
    fn consumer_policy_rejects_missing_isolation_facilities() {
        assert_eq!(
            VmxCapabilities::new(1, 4096, 6, false, true, true),
            Err(VmxError::MissingEpt)
        );
        assert_eq!(
            VmxCapabilities::new(1, 4096, 6, true, false, true),
            Err(VmxError::MissingUnrestrictedGuest)
        );
        assert_eq!(
            VmxCapabilities::new(1, 4096, 6, true, true, false),
            Err(VmxError::MissingInvept)
        );
    }

    #[test]
    fn raw_msr_capabilities_are_parsed_without_caller_claims() {
        let basic = 7u64 | (4096u64 << 32) | (6u64 << 50);
        let secondary = ((1u64 << 1) | (1u64 << 7)) << 32;
        let ept_vpid = (1u64 << 20) | (1u64 << 25);
        let capabilities = VmxCapabilities::from_msrs(basic, secondary, ept_vpid).unwrap();
        assert_eq!(capabilities.revision_id(), 7);
        assert!(capabilities.has_required_isolation());
        assert_eq!(
            VmxCapabilities::from_msrs(basic, secondary, 1 << 20),
            Err(VmxError::MissingInvept)
        );
    }

    #[test]
    fn prerequisites_require_locked_policy_vmxe_and_fixed_bits() {
        let invalid = VmxPrerequisites::new(
            5,
            1 << 30,
            1 << 31,
            1 << 5,
            1 << 5,
            1 << 9,
            (1 << 9) | (1 << 13),
        );
        assert_eq!(
            invalid.host_control_mismatch(),
            [1 << 5, 1 << 30, (1 << 9) | (1 << 13), 1 << 31]
        );
        assert_eq!(invalid.validate(), Err(VmxError::InvalidControl));
        let valid = VmxPrerequisites::new(5, 0x21, 1 << 13, 0x21, u64::MAX, 0, u64::MAX);
        assert_eq!(valid.host_control_mismatch(), [0; 4]);
        assert_eq!(valid.validate(), Ok(()));
        let guest = VmxPrerequisites::new(
            5,
            0x8000_0021,
            1 << 13,
            0x8000_0021,
            u64::MAX,
            1 << 13,
            u64::MAX,
        );
        assert_eq!(guest.unrestricted_guest_controls(), Ok((0x20, 1 << 13)));
        assert_eq!(
            VmxPrerequisites::new(4, 0x21, 1 << 13, 0x21, u64::MAX, 0, u64::MAX)
                .unrestricted_guest_controls(),
            Err(VmxError::Unsupported)
        );
        assert_eq!(
            VmxPrerequisites::new(4, 0x21, 1 << 13, 0x21, u64::MAX, 0, u64::MAX).validate(),
            Err(VmxError::Unsupported)
        );
        assert_eq!(
            VmxPrerequisites::new(5, 0x20, 1 << 13, 0x21, u64::MAX, 0, u64::MAX).validate(),
            Err(VmxError::InvalidControl)
        );
    }

    #[test]
    fn launch_order_requires_ept_invalidation() {
        let vmxon = PhysAddr::new(0x10_0000).unwrap();
        let vmcs = PhysAddr::new(0x11_0000).unwrap();
        let ept = EptPointer::new(PhysAddr::new(0x12_0000).unwrap(), true).unwrap();
        let mut controller = VmxController::new(EmulatedVmx::default(), capabilities());
        assert_eq!(controller.launch(), Err(VmxError::InvalidState));
        controller.enter_root(vmxon).unwrap();
        controller.clear_vmcs(vmcs).unwrap();
        controller.load_vmcs(vmcs, ept).unwrap();
        controller.launch().unwrap();
        controller.record_vm_exit().unwrap();
        controller.resume().unwrap();
        controller.record_vm_exit().unwrap();
        controller.leave_root().unwrap();
        assert_eq!(controller.into_instructions().trace, 0x0001_0304_0506_0702);
    }

    #[test]
    fn failed_instruction_never_advances_state() {
        let mut controller = VmxController::new(
            EmulatedVmx {
                trace: 0,
                fail_at: 1,
                ..EmulatedVmx::default()
            },
            capabilities(),
        );
        assert_eq!(
            controller.enter_root(PhysAddr::new(0x10_0000).unwrap()),
            Err(VmxError::InstructionFailed)
        );
        assert_eq!(controller.state(), VmxState::Disabled);
    }

    #[test]
    fn vmcs_fields_and_ept_exit_are_adversarially_bounded() {
        assert_eq!(VmcsField::new(0x1000), Err(VmxError::InvalidVmcsField));
        assert_eq!(VmcsField::new(0x8000), Err(VmxError::InvalidVmcsField));
        assert_eq!(VmcsField::new(0x4402), Ok(VmcsField::EXIT_REASON));

        let violation = EptViolation::decode(48, 1 | (1 << 7) | (1 << 8), 0x4000, 0x5000).unwrap();
        assert!(violation.attempted_read());
        assert!(!violation.attempted_write());
        assert_eq!(violation.guest_physical_address(), 0x4000);
        assert_eq!(violation.guest_linear_address(), Some(0x5000));
        assert_eq!(
            EptViolation::decode(48, 1, 0x4000, 0),
            Err(VmxError::InvalidVmExit)
        );
        assert_eq!(
            EptViolation::decode((1 << 31) | 48, 1 | (1 << 7), 0x4000, 0),
            Err(VmxError::InvalidVmExit)
        );
        assert_eq!(
            EptViolation::decode(12, 1 | (1 << 7), 0x4000, 0),
            Err(VmxError::InvalidVmExit)
        );
    }

    #[test]
    fn first_guest_exit_must_prove_the_exact_private_page_violation() {
        let vmxon = PhysAddr::new(0x10_0000).unwrap();
        let vmcs = PhysAddr::new(0x11_0000).unwrap();
        let ept = EptPointer::new(PhysAddr::new(0x12_0000).unwrap(), true).unwrap();
        let private = PhysAddr::new(0x20_0000).unwrap();
        let instructions = EmulatedVmx {
            exit_reason: 48,
            exit_qualification: 1 | (1 << 7) | (1 << 8),
            guest_physical: private.get() + 37,
            guest_linear: 0x4000_0025,
            ..EmulatedVmx::default()
        };
        let mut controller = VmxController::new(instructions, capabilities());
        controller.enter_root(vmxon).unwrap();
        controller.clear_vmcs(vmcs).unwrap();
        controller.load_vmcs(vmcs, ept).unwrap();
        controller.launch().unwrap();
        let exit = controller.record_private_page_violation(private).unwrap();
        assert!(exit.attempted_read());
        assert_eq!(controller.state(), VmxState::VmcsLoaded);

        let instructions = EmulatedVmx {
            exit_reason: 48,
            exit_qualification: 1 | (1 << 7),
            guest_physical: private.get(),
            exit_on_launch: true,
            ..EmulatedVmx::default()
        };
        let mut controller = VmxController::new(instructions, capabilities());
        controller.enter_root(vmxon).unwrap();
        controller.clear_vmcs(vmcs).unwrap();
        controller.load_vmcs(vmcs, ept).unwrap();
        controller.launch().unwrap();
        assert_eq!(controller.state(), VmxState::VmExitPending);
        controller.record_private_page_violation(private).unwrap();
        assert_eq!(controller.state(), VmxState::VmcsLoaded);

        let instructions = EmulatedVmx {
            exit_reason: 48,
            exit_qualification: 2 | (1 << 7),
            guest_physical: private.get() + 4096,
            ..EmulatedVmx::default()
        };
        let mut controller = VmxController::new(instructions, capabilities());
        controller.enter_root(vmxon).unwrap();
        controller.clear_vmcs(vmcs).unwrap();
        controller.load_vmcs(vmcs, ept).unwrap();
        controller.launch().unwrap();
        assert_eq!(
            controller.record_private_page_violation(private),
            Err(VmxError::InvalidVmExit)
        );
        assert_eq!(controller.state(), VmxState::VmcsLoaded);
    }

    #[test]
    fn complete_vmcs_is_prevalidated_and_partial_programming_poisoned() {
        let vmxon = PhysAddr::new(0x10_0000).unwrap();
        let vmcs = PhysAddr::new(0x11_0000).unwrap();
        let ept = EptPointer::new(PhysAddr::new(0x12_0000).unwrap(), true).unwrap();
        let launch = minimal_launch(ept);
        assert_eq!(launch.writes().len(), VMCS_MINIMAL_LAUNCH_FIELDS);
        let mut values = [0u64; VMCS_MINIMAL_LAUNCH_FIELDS];
        for (destination, write) in values.iter_mut().zip(launch.writes()) {
            *destination = write.value();
        }
        let field = |encoding| {
            MINIMAL_LAUNCH_FIELD_ENCODINGS
                .iter()
                .position(|candidate| *candidate == encoding)
                .unwrap()
        };
        values[field(0x6c06)] = 0x0001_0000_0000_0000;
        assert_eq!(
            MinimalVmcsLaunch::new(values, permissive_control_policy()),
            Err(VmxError::InvalidControl)
        );
        values[field(0x6c06)] = 0;
        values[field(0x2c00)] = 2;
        assert_eq!(
            MinimalVmcsLaunch::new(values, permissive_control_policy()),
            Err(VmxError::InvalidControl)
        );

        let mut controller = VmxController::new(EmulatedVmx::default(), capabilities());
        controller.enter_root(vmxon).unwrap();
        controller.clear_vmcs(vmcs).unwrap();
        controller.load_vmcs(vmcs, ept).unwrap();
        controller.program_minimal_vmcs(&launch).unwrap();
        assert_eq!(controller.state(), VmxState::VmcsLoaded);

        let mut controller = VmxController::new(
            EmulatedVmx {
                fail_at: 8,
                ..EmulatedVmx::default()
            },
            capabilities(),
        );
        controller.enter_root(vmxon).unwrap();
        controller.clear_vmcs(vmcs).unwrap();
        controller.load_vmcs(vmcs, ept).unwrap();
        assert_eq!(
            controller.program_minimal_vmcs(&launch),
            Err(VmxError::InstructionFailed)
        );
        assert_eq!(controller.state(), VmxState::Poisoned);
        assert_eq!(controller.failed_vmwrite_index(), Some(0));
        assert_eq!(controller.resume(), Err(VmxError::InvalidState));
        controller.leave_root().unwrap();
        assert_eq!(controller.state(), VmxState::Disabled);
        assert_eq!(controller.failed_vmwrite_index(), None);
    }
}
