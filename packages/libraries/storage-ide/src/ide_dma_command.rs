//! Bounded classic bus-master IDE command execution.

use crate::{
    IdeChannelPortGrant, IdeDevice, IdeDeviceIdentity, IdeDmaDirection, IdePortIo, PreparedIdeDma,
};
use mrml_kernel::{Capability, CapabilityError, CapabilitySpace, ObjectId, Rights};

const READ_DMA: u8 = 0xc8;
const READ_DMA_EXT: u8 = 0x25;
const WRITE_DMA: u8 = 0xca;
const WRITE_DMA_EXT: u8 = 0x35;
const BM_START: u8 = 1;
const BM_ERROR: u8 = 1 << 1;
const BM_INTERRUPT: u8 = 1 << 2;
const BM_READ_FROM_DEVICE: u8 = 1 << 3;
const ATA_ERROR: u8 = 1;
const ATA_DEVICE_FAULT: u8 = 1 << 5;
const ATA_BUSY: u8 = 1 << 7;
const POLL_LIMIT: u32 = 2000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdeDmaOperation {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdeDmaCommandRequest {
    pub device_capability: Capability,
    pub device_object: ObjectId,
    pub identity: IdeDeviceIdentity,
    pub operation: IdeDmaOperation,
    pub starting_lba: u64,
    pub block_count: u32,
}

#[derive(Debug, Eq, PartialEq)]
pub struct CompletedIdeDma {
    pub grant: IdeChannelPortGrant,
    pub request: IdeDmaCommandRequest,
    pub dma: PreparedIdeDma,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdeDmaCommandError {
    DeviceCapability(CapabilityError),
    WrongDeviceObject,
    StaleIdentity,
    MissingBusMasterPorts,
    InvalidBlockRange,
    UnsupportedAddress,
    WrongDmaDirection,
    WrongTransferSize,
    EngineActive,
    PortRead,
    PortWrite,
    PrdtReadback,
    DmaError,
    MissingInterrupt,
    AtaError,
    AtaDeviceFault,
    AtaBusy,
    CompletionTimeout,
}

#[derive(Debug, Eq, PartialEq)]
pub enum IdeDmaCommandFailure {
    Untouched {
        grant: IdeChannelPortGrant,
        request: IdeDmaCommandRequest,
        dma: PreparedIdeDma,
        error: IdeDmaCommandError,
    },
    Quarantined {
        grant: IdeChannelPortGrant,
        request: IdeDmaCommandRequest,
        dma_layout: crate::IdeDmaLayout,
        error: IdeDmaCommandError,
    },
}

pub trait IdeDmaCommandIo: IdePortIo {
    fn read_bus_master_u8(&mut self, port: u16) -> Result<u8, ()>;
    fn write_bus_master_u8(&mut self, port: u16, value: u8) -> Result<(), ()>;
    fn read_bus_master_u32(&mut self, port: u16) -> Result<u32, ()>;
    fn write_bus_master_u32(&mut self, port: u16, value: u32) -> Result<(), ()>;
}

pub fn execute_ide_dma<const N: usize, I: IdeDmaCommandIo>(
    capabilities: &CapabilitySpace<N>,
    grant: IdeChannelPortGrant,
    request: IdeDmaCommandRequest,
    dma: PreparedIdeDma,
    io: &mut I,
) -> Result<CompletedIdeDma, IdeDmaCommandFailure> {
    if let Err(error) = validate(capabilities, grant, request, &dma) {
        return Err(untouched(grant, request, dma, error));
    }
    let bus = grant.bus_master.unwrap().base;
    let command = match io.read_bus_master_u8(bus) {
        Ok(command) => command,
        Err(()) => return Err(untouched(grant, request, dma, IdeDmaCommandError::PortRead)),
    };
    if command & BM_START != 0 {
        return Err(untouched(
            grant,
            request,
            dma,
            IdeDmaCommandError::EngineActive,
        ));
    }
    let dma_layout = dma.layout();
    io.write_bus_master_u8(bus, 0)
        .map_err(|_| quarantined(grant, request, dma_layout, IdeDmaCommandError::PortWrite))?;
    io.write_bus_master_u8(bus + 2, BM_ERROR | BM_INTERRUPT)
        .map_err(|_| quarantined(grant, request, dma_layout, IdeDmaCommandError::PortWrite))?;
    let prdt = dma.layout().prd_table.physical_base as u32;
    io.write_bus_master_u32(bus + 4, prdt)
        .map_err(|_| quarantined(grant, request, dma_layout, IdeDmaCommandError::PortWrite))?;
    if io.read_bus_master_u32(bus + 4) != Ok(prdt) {
        return Err(quarantined(
            grant,
            request,
            dma_layout,
            IdeDmaCommandError::PrdtReadback,
        ));
    }
    program_task_file(grant.command.base, request, io)
        .map_err(|error| quarantined(grant, request, dma_layout, error))?;
    let ata_command = match (request.operation, request.identity.lba48) {
        (IdeDmaOperation::Read, false) => READ_DMA,
        (IdeDmaOperation::Read, true) => READ_DMA_EXT,
        (IdeDmaOperation::Write, false) => WRITE_DMA,
        (IdeDmaOperation::Write, true) => WRITE_DMA_EXT,
    };
    io.write_u8(grant.command.base + 7, ata_command)
        .map_err(|_| quarantined(grant, request, dma_layout, IdeDmaCommandError::PortWrite))?;
    let engine = BM_START
        | if request.operation == IdeDmaOperation::Read {
            BM_READ_FROM_DEVICE
        } else {
            0
        };
    io.write_bus_master_u8(bus, engine)
        .map_err(|_| quarantined(grant, request, dma_layout, IdeDmaCommandError::PortWrite))?;
    let mut completed = false;
    for _ in 0..POLL_LIMIT {
        let status = io
            .read_bus_master_u8(bus + 2)
            .map_err(|_| quarantined(grant, request, dma_layout, IdeDmaCommandError::PortRead))?;
        if status & BM_ERROR != 0 {
            return Err(quarantined(
                grant,
                request,
                dma_layout,
                IdeDmaCommandError::DmaError,
            ));
        }
        if status & BM_START == 0 {
            if status & BM_INTERRUPT == 0 {
                return Err(quarantined(
                    grant,
                    request,
                    dma_layout,
                    IdeDmaCommandError::MissingInterrupt,
                ));
            }
            completed = true;
            break;
        }
        io.delay_500_micros();
    }
    if !completed {
        return Err(quarantined(
            grant,
            request,
            dma_layout,
            IdeDmaCommandError::CompletionTimeout,
        ));
    }
    let ata = io
        .read_u8(grant.command.base + 7)
        .map_err(|_| quarantined(grant, request, dma_layout, IdeDmaCommandError::PortRead))?;
    if ata & ATA_BUSY != 0 {
        return Err(quarantined(
            grant,
            request,
            dma_layout,
            IdeDmaCommandError::AtaBusy,
        ));
    }
    if ata & ATA_DEVICE_FAULT != 0 {
        return Err(quarantined(
            grant,
            request,
            dma_layout,
            IdeDmaCommandError::AtaDeviceFault,
        ));
    }
    if ata & ATA_ERROR != 0 {
        return Err(quarantined(
            grant,
            request,
            dma_layout,
            IdeDmaCommandError::AtaError,
        ));
    }
    io.write_bus_master_u8(bus, 0)
        .map_err(|_| quarantined(grant, request, dma_layout, IdeDmaCommandError::PortWrite))?;
    match io.read_bus_master_u8(bus) {
        Ok(value) if value & BM_START == 0 => {}
        Ok(_) => {
            return Err(quarantined(
                grant,
                request,
                dma_layout,
                IdeDmaCommandError::EngineActive,
            ))
        }
        Err(()) => {
            return Err(quarantined(
                grant,
                request,
                dma_layout,
                IdeDmaCommandError::PortRead,
            ))
        }
    }
    io.write_bus_master_u8(bus + 2, BM_ERROR | BM_INTERRUPT)
        .map_err(|_| quarantined(grant, request, dma_layout, IdeDmaCommandError::PortWrite))?;
    Ok(CompletedIdeDma {
        grant,
        request,
        dma,
    })
}

fn validate<const N: usize>(
    capabilities: &CapabilitySpace<N>,
    grant: IdeChannelPortGrant,
    request: IdeDmaCommandRequest,
    dma: &PreparedIdeDma,
) -> Result<(), IdeDmaCommandError> {
    let rights = match request.operation {
        IdeDmaOperation::Read => Rights::READ,
        IdeDmaOperation::Write => Rights::WRITE,
    };
    let object = capabilities
        .authorize_exact(request.device_capability, rights)
        .map_err(IdeDmaCommandError::DeviceCapability)?;
    if object != request.device_object {
        return Err(IdeDmaCommandError::WrongDeviceObject);
    }
    if grant.bus_master.is_none() {
        return Err(IdeDmaCommandError::MissingBusMasterPorts);
    }
    if request.identity.controller_generation != grant.controller_generation
        || request.identity.port_grant_generation != grant.grant_generation
        || request.identity.identity_generation == 0
    {
        return Err(IdeDmaCommandError::StaleIdentity);
    }
    if request.block_count == 0
        || request.block_count > request.identity.maximum_transfer_blocks
        || request
            .starting_lba
            .checked_add(u64::from(request.block_count))
            .is_none_or(|end| end > request.identity.block_count)
    {
        return Err(IdeDmaCommandError::InvalidBlockRange);
    }
    if !request.identity.lba48
        && (request.block_count > 256
            || request
                .starting_lba
                .checked_add(u64::from(request.block_count))
                .is_none_or(|end| end > 0x1000_0000))
    {
        return Err(IdeDmaCommandError::UnsupportedAddress);
    }
    let expected = u64::from(request.block_count)
        .checked_mul(u64::from(request.identity.logical_block_bytes))
        .ok_or(IdeDmaCommandError::WrongTransferSize)?;
    if expected != dma.layout().transfer_bytes {
        return Err(IdeDmaCommandError::WrongTransferSize);
    }
    let direction = match request.operation {
        IdeDmaOperation::Read => IdeDmaDirection::DeviceWrites,
        IdeDmaOperation::Write => IdeDmaDirection::DeviceReads,
    };
    if dma.layout().direction != direction {
        return Err(IdeDmaCommandError::WrongDmaDirection);
    }
    Ok(())
}

fn program_task_file<I: IdeDmaCommandIo>(
    base: u16,
    request: IdeDmaCommandRequest,
    io: &mut I,
) -> Result<(), IdeDmaCommandError> {
    let lba48 = request.identity.lba48;
    let drive = if request.identity.device == IdeDevice::Slave {
        0xf0
    } else {
        0xe0
    };
    let drive = if lba48 {
        drive
    } else {
        drive | ((request.starting_lba >> 24) as u8 & 0x0f)
    };
    io.write_u8(base + 6, drive)
        .map_err(|_| IdeDmaCommandError::PortWrite)?;
    if lba48 {
        for (port, value) in [
            (1, 0),
            (2, (request.block_count >> 8) as u8),
            (3, (request.starting_lba >> 24) as u8),
            (4, (request.starting_lba >> 32) as u8),
            (5, (request.starting_lba >> 40) as u8),
            (1, 0),
            (2, request.block_count as u8),
            (3, request.starting_lba as u8),
            (4, (request.starting_lba >> 8) as u8),
            (5, (request.starting_lba >> 16) as u8),
        ] {
            io.write_u8(base + port, value)
                .map_err(|_| IdeDmaCommandError::PortWrite)?;
        }
    } else {
        for (port, value) in [
            (1, 0),
            (2, request.block_count as u8),
            (3, request.starting_lba as u8),
            (4, (request.starting_lba >> 8) as u8),
            (5, (request.starting_lba >> 16) as u8),
        ] {
            io.write_u8(base + port, value)
                .map_err(|_| IdeDmaCommandError::PortWrite)?;
        }
    }
    Ok(())
}

const fn untouched(
    grant: IdeChannelPortGrant,
    request: IdeDmaCommandRequest,
    dma: PreparedIdeDma,
    error: IdeDmaCommandError,
) -> IdeDmaCommandFailure {
    IdeDmaCommandFailure::Untouched {
        grant,
        request,
        dma,
        error,
    }
}
const fn quarantined(
    grant: IdeChannelPortGrant,
    request: IdeDmaCommandRequest,
    dma_layout: crate::IdeDmaLayout,
    error: IdeDmaCommandError,
) -> IdeDmaCommandFailure {
    IdeDmaCommandFailure::Quarantined {
        grant,
        request,
        dma_layout,
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{prepare_ide_dma, IdeChannel, IdeDmaBackend, IdeDmaLayout, IdeDmaMemoryIo, IdeDmaRegion, IdeDmaRequest, IdePortRange};

    #[derive(Default)] struct DmaBackend(Option<IdeDmaLayout>);
    impl IdeDmaBackend for DmaBackend {
        fn install_zeroed(&mut self, layout: IdeDmaLayout) -> Result<(), ()> { self.0 = Some(layout); Ok(()) }
        fn remove(&mut self, layout: IdeDmaLayout) -> Result<(), ()> { if self.0 == Some(layout) { self.0 = None; Ok(()) } else { Err(()) } }
    }
    struct DmaMemory([u32; 1024]);
    impl Default for DmaMemory { fn default() -> Self { Self([0; 1024]) } }
    impl IdeDmaMemoryIo for DmaMemory {
        fn read_u32(&mut self, _: IdeDmaRegion, offset: u64) -> Result<u32, ()> { self.0.get(offset as usize / 4).copied().ok_or(()) }
        fn write_u32(&mut self, _: IdeDmaRegion, offset: u64, value: u32) -> Result<(), ()> { *self.0.get_mut(offset as usize / 4).ok_or(())? = value; Ok(()) }
    }
    struct Io { ata_status: u8, task: [Option<(u16,u8)>; 12], task_count: usize, bm_command: u8, bm_status: [u8;3], bm_status_index: usize, bm_writes: [Option<(u16,u8)>;5], bm_write_count: usize, prdt: u32, delays: u32 }
    impl IdePortIo for Io {
        fn read_u8(&mut self, port:u16)->Result<u8,()>{if port==0x1f7{Ok(self.ata_status)}else{Err(())}}
        fn read_u16(&mut self,_:u16)->Result<u16,()>{Err(())}
        fn write_u8(&mut self,port:u16,value:u8)->Result<(),()>{*self.task.get_mut(self.task_count).ok_or(())?=Some((port,value));self.task_count+=1;Ok(())}
        fn delay_500_micros(&mut self){self.delays+=1;}
    }
    impl IdeDmaCommandIo for Io {
        fn read_bus_master_u8(&mut self,port:u16)->Result<u8,()>{match port{0x2400=>Ok(self.bm_command),0x2402=>{let v=self.bm_status[self.bm_status_index.min(2)];self.bm_status_index+=1;Ok(v)},_=>Err(())}}
        fn write_bus_master_u8(&mut self,port:u16,value:u8)->Result<(),()>{*self.bm_writes.get_mut(self.bm_write_count).ok_or(())?=Some((port,value));self.bm_write_count+=1;if port==0x2400{self.bm_command=value&!BM_START;}Ok(())}
        fn read_bus_master_u32(&mut self,port:u16)->Result<u32,()>{if port==0x2404{Ok(self.prdt)}else{Err(())}}
        fn write_bus_master_u32(&mut self,port:u16,value:u32)->Result<(),()>{if port!=0x2404{return Err(());}self.prdt=value;Ok(())}
    }
    fn io()->Io{Io{ata_status:0,task:[None;12],task_count:0,bm_command:0,bm_status:[BM_START,BM_INTERRUPT,BM_INTERRUPT],bm_status_index:0,bm_writes:[None;5],bm_write_count:0,prdt:0,delays:0}}
    fn grant()->IdeChannelPortGrant{IdeChannelPortGrant{controller_generation:4,grant_generation:7,port_object:ObjectId(9),channel:IdeChannel::Primary,command:IdePortRange{base:0x1f0,bytes:8},control:IdePortRange{base:0x3f6,bytes:1},bus_master:Some(IdePortRange{base:0x2400,bytes:8})}}
    fn identity()->IdeDeviceIdentity{IdeDeviceIdentity{controller_generation:4,port_grant_generation:7,device:IdeDevice::Master,identity_generation:11,serial:[b' ';20],firmware:[b' ';8],model:[b' ';40],block_count:1_000_000,logical_block_bytes:512,maximum_transfer_blocks:2048,lba48:true,dma_supported:true,flush_supported:true}}
    fn fixture(operation:IdeDmaOperation)->(CapabilitySpace<3>,IdeDmaCommandRequest,PreparedIdeDma){
        let mut caps=CapabilitySpace::new();let dr=if operation==IdeDmaOperation::Read{Rights::READ}else{Rights::WRITE};let device_capability=caps.insert(ObjectId(20),dr).unwrap();let direction=if operation==IdeDmaOperation::Read{IdeDmaDirection::DeviceWrites}else{IdeDmaDirection::DeviceReads};let data_rights=match direction{IdeDmaDirection::DeviceReads=>Rights::PIN.union(Rights::MAP).union(Rights::READ),IdeDmaDirection::DeviceWrites=>Rights::PIN.union(Rights::MAP).union(Rights::READ).union(Rights::WRITE)};let data_capability=caps.insert(ObjectId(30),data_rights).unwrap();let prd_table_capability=caps.insert(ObjectId(31),Rights::PIN.union(Rights::MAP).union(Rights::READ).union(Rights::WRITE)).unwrap();let d=IdeDmaRequest{data_capability,prd_table_capability,data:IdeDmaRegion{memory_object:ObjectId(30),allocation_generation:2,physical_base:0x10_0000,bytes:1024},prd_table:IdeDmaRegion{memory_object:ObjectId(31),allocation_generation:3,physical_base:0x20_0000,bytes:4096},transfer_bytes:1024,direction,dma_generation:4};let dma=prepare_ide_dma(&caps,d,&mut DmaBackend::default(),&mut DmaMemory::default()).unwrap();(caps,IdeDmaCommandRequest{device_capability,device_object:ObjectId(20),identity:identity(),operation,starting_lba:0x1234,block_count:2},dma)
    }
    #[test] fn executes_lba48_read_with_prdt_then_bounded_completion_and_stop(){let(caps,request,dma)=fixture(IdeDmaOperation::Read);let mut ports=io();let done=execute_ide_dma(&caps,grant(),request,dma,&mut ports).unwrap();assert_eq!(ports.prdt,0x20_0000);assert_eq!(ports.task[11],Some((0x1f7,READ_DMA_EXT)));assert_eq!(ports.bm_writes[2],Some((0x2400,BM_START|BM_READ_FROM_DEVICE)));assert_eq!(ports.bm_writes[3],Some((0x2400,0)));assert_eq!(ports.delays,1);assert_eq!(done.dma.layout().direction,IdeDmaDirection::DeviceWrites);}
    #[test] fn executes_write_with_memory_to_device_direction(){let(caps,request,dma)=fixture(IdeDmaOperation::Write);let mut ports=io();execute_ide_dma(&caps,grant(),request,dma,&mut ports).unwrap();assert_eq!(ports.task[11],Some((0x1f7,WRITE_DMA_EXT)));assert_eq!(ports.bm_writes[2],Some((0x2400,BM_START)));}
    #[test] fn wrong_direction_is_untouched_and_faults_quarantine(){let(caps,mut request,dma)=fixture(IdeDmaOperation::Read);request.operation=IdeDmaOperation::Write;assert!(matches!(execute_ide_dma(&caps,grant(),request,dma,&mut io()),Err(IdeDmaCommandFailure::Untouched{..})));let(caps,request,dma)=fixture(IdeDmaOperation::Read);let mut ports=io();ports.bm_status=[BM_ERROR;3];assert!(matches!(execute_ide_dma(&caps,grant(),request,dma,&mut ports),Err(IdeDmaCommandFailure::Quarantined{error:IdeDmaCommandError::DmaError,..})));let(caps,request,dma)=fixture(IdeDmaOperation::Read);let mut ports=io();ports.bm_status=[0;3];assert!(matches!(execute_ide_dma(&caps,grant(),request,dma,&mut ports),Err(IdeDmaCommandFailure::Quarantined{error:IdeDmaCommandError::MissingInterrupt,..})));let(caps,request,dma)=fixture(IdeDmaOperation::Read);let mut ports=io();ports.bm_status=[BM_START;3];assert!(matches!(execute_ide_dma(&caps,grant(),request,dma,&mut ports),Err(IdeDmaCommandFailure::Quarantined{error:IdeDmaCommandError::CompletionTimeout,..})));}
}
