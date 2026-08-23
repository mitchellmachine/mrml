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
    InstructionFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmxInstructionError {
    Failed,
}

/// Intel VMX control MSRs encode bits that may be zero in the low half and
/// bits that may be one in the high half. Adjustment therefore forces required
/// ones and clears forbidden ones without trusting a caller-provided control.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmxControlMask {
    allowed_zero: u32,
    allowed_one: u32,
}

impl VmxControlMask {
    pub const fn new(msr: u64) -> Result<Self, VmxError> {
        let allowed_zero = msr as u32;
        let allowed_one = (msr >> 32) as u32;
        if (!allowed_zero) & (!allowed_one) != 0 {
            return Err(VmxError::InvalidControl);
        }
        Ok(Self {
            allowed_zero,
            allowed_one,
        })
    }

    pub const fn adjust(self, requested: u32) -> u32 {
        (requested | !self.allowed_zero) & self.allowed_one
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

    pub const fn validate(self) -> Result<(), VmxError> {
        const FEATURE_LOCK: u64 = 1;
        const VMX_OUTSIDE_SMX: u64 = 1 << 2;
        const CR4_VMXE: u64 = 1 << 13;
        if self.feature_control & (FEATURE_LOCK | VMX_OUTSIDE_SMX) != FEATURE_LOCK | VMX_OUTSIDE_SMX
        {
            return Err(VmxError::Unsupported);
        }
        if self.cr4 & CR4_VMXE == 0
            || (self.cr0 | self.cr0_fixed_zero) != self.cr0
            || self.cr0 & !self.cr0_fixed_one != 0
            || (self.cr4 | self.cr4_fixed_zero) != self.cr4
            || self.cr4 & !self.cr4_fixed_one != 0
        {
            return Err(VmxError::InvalidControl);
        }
        Ok(())
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
}

/// Narrow unsafe-instruction boundary. A bare-metal adapter implements these
/// operations; tests and hosted probes use a deterministic emulator.
pub trait VmxInstructions {
    fn vmxon(&mut self, region: PhysAddr) -> Result<(), VmxInstructionError>;
    fn vmxoff(&mut self) -> Result<(), VmxInstructionError>;
    fn vmclear(&mut self, vmcs: PhysAddr) -> Result<(), VmxInstructionError>;
    fn vmptrld(&mut self, vmcs: PhysAddr) -> Result<(), VmxInstructionError>;
    fn vmlaunch(&mut self) -> Result<(), VmxInstructionError>;
    fn vmresume(&mut self) -> Result<(), VmxInstructionError>;
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

impl VmxInstructions for NativeVmx {
    fn vmxon(&mut self, region: PhysAddr) -> Result<(), VmxInstructionError> {
        Self::physical_operand(native_vmxon, region)
    }

    fn vmxoff(&mut self) -> Result<(), VmxInstructionError> {
        unsafe { core::arch::asm!("vmxoff", options(nostack)) };
        Ok(())
    }

    fn vmclear(&mut self, vmcs: PhysAddr) -> Result<(), VmxInstructionError> {
        Self::physical_operand(native_vmclear, vmcs)
    }

    fn vmptrld(&mut self, vmcs: PhysAddr) -> Result<(), VmxInstructionError> {
        Self::physical_operand(native_vmptrld, vmcs)
    }

    fn vmlaunch(&mut self) -> Result<(), VmxInstructionError> {
        let failed: u8;
        unsafe {
            core::arch::asm!(
                "vmlaunch",
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

    fn vmresume(&mut self) -> Result<(), VmxInstructionError> {
        let failed: u8;
        unsafe {
            core::arch::asm!(
                "vmresume",
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
}

impl<I: VmxInstructions> VmxController<I> {
    pub const fn new(instructions: I, capabilities: VmxCapabilities) -> Self {
        Self {
            instructions,
            capabilities,
            state: VmxState::Disabled,
            active_vmcs: None,
            active_ept: None,
        }
    }

    pub const fn state(&self) -> VmxState {
        self.state
    }

    pub const fn capabilities(&self) -> VmxCapabilities {
        self.capabilities
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
        self.instructions
            .vmlaunch()
            .map_err(|_| VmxError::InstructionFailed)?;
        self.state = VmxState::GuestRunning;
        Ok(())
    }

    /// Records a VM exit before exit handling reads guest-controlled state.
    pub fn record_vm_exit(&mut self) -> Result<(), VmxError> {
        if self.state != VmxState::GuestRunning {
            return Err(VmxError::InvalidState);
        }
        self.state = VmxState::VmcsLoaded;
        Ok(())
    }

    pub fn resume(&mut self) -> Result<(), VmxError> {
        if self.state != VmxState::VmcsLoaded || self.active_ept.is_none() {
            return Err(VmxError::InvalidState);
        }
        self.instructions
            .vmresume()
            .map_err(|_| VmxError::InstructionFailed)?;
        self.state = VmxState::GuestRunning;
        Ok(())
    }

    pub fn leave_root(&mut self) -> Result<(), VmxError> {
        if self.state == VmxState::GuestRunning || self.state == VmxState::Disabled {
            return Err(VmxError::InvalidState);
        }
        self.instructions
            .vmxoff()
            .map_err(|_| VmxError::InstructionFailed)?;
        self.active_vmcs = None;
        self.active_ept = None;
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
        fn vmlaunch(&mut self) -> Result<(), VmxInstructionError> {
            self.step(6)
        }
        fn vmresume(&mut self) -> Result<(), VmxInstructionError> {
            self.step(7)
        }
        fn invept_single_context(&mut self, _: EptPointer) -> Result<(), VmxInstructionError> {
            self.step(5)
        }
    }

    fn capabilities() -> VmxCapabilities {
        VmxCapabilities::new(7, 4096, 6, true, true, true).unwrap()
    }

    #[test]
    fn controls_force_required_bits_and_clear_forbidden_bits() {
        let mask = VmxControlMask::new(0xffff_fff5_ffff_fffe).unwrap();
        let control = VmxControl::constrained(u32::MAX, mask);
        assert_eq!(control.bits(), 0xffff_fff5);
        assert!(mask.accepts(control.bits()));
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
        let valid = VmxPrerequisites::new(5, 0x21, 1 << 13, 0x21, u64::MAX, 0, u64::MAX);
        assert_eq!(valid.validate(), Ok(()));
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
            },
            capabilities(),
        );
        assert_eq!(
            controller.enter_root(PhysAddr::new(0x10_0000).unwrap()),
            Err(VmxError::InstructionFailed)
        );
        assert_eq!(controller.state(), VmxState::Disabled);
    }
}
