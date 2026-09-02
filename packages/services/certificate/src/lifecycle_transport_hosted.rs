use crate::{
    decode_backup_export_receipt, decode_backup_transfer_receipt, decode_managed_identity_status,
    dispatch_lifecycle_call, encode_backup_export_command, encode_backup_transfer_command,
    untrusted_backup_container_digest, BackupExportCommand, BackupExportReceipt,
    BackupTransferCommand, BackupTransferPurpose, BackupTransferReceipt,
    BackupTransferReceiptState, CertificateLifecycleAuthorizer, CertificateLifecycleProvider,
    ManagedIdentityStatus, ManagedStatusCodecError, TlsIdentityId, BACKUP_EXPORT_COMMAND_BYTES,
    BACKUP_EXPORT_RECEIPT_BYTES, BACKUP_TRANSFER_RECEIPT_BYTES, MAX_BACKUP_BYTES,
    MAX_BACKUP_EXPORT_CHUNK, MAX_BACKUP_WIRE_CHUNK, MAX_MANAGED_STATUS_BYTES,
};
use mrml_interface_certificate_lifecycle_v1 as abi;
use mrml_runtime::{NetError, TcpListener, TcpStream};

pub const MAX_HOSTED_LIFECYCLE_MEMORY: usize = 16 * 1024;
const HEADER_BYTES: usize = 16;
const REQUEST_MAGIC: &[u8; 8] = b"MRMLCLR1";
const RESPONSE_MAGIC: &[u8; 8] = b"MRMLCLS1";
const SESSION_MAGIC: &[u8; 8] = b"MRMLCAP1";
const SESSION_ACCEPTED: &[u8; 8] = b"MRMLOK01";
const IO_TIMEOUT_MILLIS: u64 = 2_000;
const MAX_FRAME_BYTES: usize = abi::IDENTITY_OPERATION_REQUEST_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedLifecycleTransportError {
    Network(NetError),
    InvalidHeader,
    InvalidFrame,
    MemoryLimit,
    OutputLengthMismatch,
    Protocol(abi::ProtocolError),
    RemoteStatus(abi::StatusError),
    RemoteAccountStatus(abi::AccountOperationError),
    RemoteIdentityStatus(abi::IdentityOperationError),
    RemoteBackupStatus(abi::BackupOperationError),
    Status(ManagedStatusCodecError),
    InvalidSessionCapability,
    SessionDenied,
}

/// One-use out-of-band authority for accepting a hosted lifecycle session.
/// The listener address identifies the service but does not authorize it.
pub struct HostedLifecycleSessionCapability {
    secret: [u8; 32],
    consumed: bool,
}

impl HostedLifecycleSessionCapability {
    pub fn new(secret: [u8; 32]) -> Result<Self, HostedLifecycleTransportError> {
        if secret == [0; 32] {
            return Err(HostedLifecycleTransportError::InvalidSessionCapability);
        }
        Ok(Self {
            secret,
            consumed: false,
        })
    }

    pub fn accept_one(
        &mut self,
        listener: &TcpListener,
    ) -> Result<HostedLifecycleServer, HostedLifecycleTransportError> {
        if self.consumed {
            return Err(HostedLifecycleTransportError::SessionDenied);
        }
        self.consumed = true;
        let mut stream = listener
            .accept()
            .map_err(HostedLifecycleTransportError::Network)?;
        configure(&mut stream)?;
        let mut request = [0u8; 40];
        let read_result = stream.read_exact(&mut request);
        let mut difference = 0u8;
        for (presented, expected) in request[8..].iter().zip(self.secret) {
            difference |= presented ^ expected;
        }
        self.secret.fill(0);
        let accepted = read_result.is_ok() && &request[..8] == SESSION_MAGIC && difference == 0;
        request.fill(0);
        if !accepted {
            return Err(HostedLifecycleTransportError::SessionDenied);
        }
        stream
            .write_all(SESSION_ACCEPTED)
            .map_err(HostedLifecycleTransportError::Network)?;
        Ok(HostedLifecycleServer { stream })
    }
}

impl Drop for HostedLifecycleSessionCapability {
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}

/// Client over one connection already authorized and delivered by the host
/// supervisor. Addresses, ports, paths, and request fields never authorize a
/// lifecycle operation.
pub struct HostedLifecycleClient {
    stream: TcpStream,
}

impl HostedLifecycleClient {
    pub fn connect_session(
        ip: [u8; 4],
        port: u16,
        mut capability: [u8; 32],
    ) -> Result<Self, HostedLifecycleTransportError> {
        if capability == [0; 32] || port == 0 {
            capability.fill(0);
            return Err(HostedLifecycleTransportError::InvalidSessionCapability);
        }
        let stream =
            TcpStream::connect(ip, port).map_err(HostedLifecycleTransportError::Network)?;
        let mut client = Self::from_authorized_stream(stream)?;
        let mut request = [0u8; 40];
        request[..8].copy_from_slice(SESSION_MAGIC);
        request[8..].copy_from_slice(&capability);
        capability.fill(0);
        let result = client.stream.write_all(&request);
        request.fill(0);
        result.map_err(HostedLifecycleTransportError::Network)?;
        let mut response = [0u8; 8];
        client
            .stream
            .read_exact(&mut response)
            .map_err(HostedLifecycleTransportError::Network)?;
        if &response != SESSION_ACCEPTED {
            response.fill(0);
            return Err(HostedLifecycleTransportError::SessionDenied);
        }
        response.fill(0);
        Ok(client)
    }

    pub fn from_authorized_stream(
        mut stream: TcpStream,
    ) -> Result<Self, HostedLifecycleTransportError> {
        configure(&mut stream)?;
        Ok(Self { stream })
    }

    pub fn call(
        &mut self,
        frame: &[u8],
        memory: &mut [u8],
    ) -> Result<[u8; abi::RESPONSE_BYTES], HostedLifecycleTransportError> {
        validate_frame_length(frame.len())?;
        if memory.is_empty() || memory.len() > MAX_HOSTED_LIFECYCLE_MEMORY {
            return Err(HostedLifecycleTransportError::MemoryLimit);
        }
        let mut header = [0u8; HEADER_BYTES];
        header[..8].copy_from_slice(REQUEST_MAGIC);
        header[8..10].copy_from_slice(&(frame.len() as u16).to_be_bytes());
        header[10..12].copy_from_slice(&(memory.len() as u16).to_be_bytes());
        self.stream
            .write_all(&header)
            .and_then(|_| self.stream.write_all(frame))
            .and_then(|_| self.stream.write_all(memory))
            .map_err(HostedLifecycleTransportError::Network)?;
        self.stream
            .read_exact(&mut header)
            .map_err(HostedLifecycleTransportError::Network)?;
        if &header[..8] != RESPONSE_MAGIC || header[12..] != [0; 4] {
            return Err(HostedLifecycleTransportError::InvalidHeader);
        }
        let response_length = usize::from(u16::from_be_bytes([header[8], header[9]]));
        let memory_length = usize::from(u16::from_be_bytes([header[10], header[11]]));
        if response_length != abi::RESPONSE_BYTES || memory_length != memory.len() {
            return Err(HostedLifecycleTransportError::OutputLengthMismatch);
        }
        let mut response = [0u8; abi::RESPONSE_BYTES];
        self.stream
            .read_exact(&mut response)
            .and_then(|_| self.stream.read_exact(memory))
            .map_err(HostedLifecycleTransportError::Network)?;
        Ok(response)
    }

    pub fn identity_status(
        &mut self,
        identity: TlsIdentityId,
    ) -> Result<ManagedIdentityStatus, HostedLifecycleTransportError> {
        const OUTPUT_AT: usize = 32;
        let mut memory = [0u8; OUTPUT_AT + MAX_MANAGED_STATUS_BYTES];
        memory[..16].copy_from_slice(&identity.0);
        let frame = abi::encode_status_request(abi::StatusRequest {
            scope: abi::SCOPE_IDENTITY,
            object_identity: abi::BorrowedReadView::within(0, 16, memory.len() as u64).unwrap(),
            output: abi::BorrowedWriteView::within(
                OUTPUT_AT as u64,
                MAX_MANAGED_STATUS_BYTES as u64,
                memory.len() as u64,
            )
            .unwrap(),
        })
        .map_err(HostedLifecycleTransportError::Protocol)?;
        let response = self.call(&frame, &mut memory)?;
        let response = abi::decode_status_response(&response, MAX_MANAGED_STATUS_BYTES as u64)
            .map_err(HostedLifecycleTransportError::Protocol)?
            .map_err(HostedLifecycleTransportError::RemoteStatus)?;
        let written = usize::try_from(response.written)
            .map_err(|_| HostedLifecycleTransportError::OutputLengthMismatch)?;
        decode_managed_identity_status(&memory[OUTPUT_AT..OUTPUT_AT + written])
            .map_err(HostedLifecycleTransportError::Status)
    }

    pub fn account_operation(
        &mut self,
        operation: u32,
        policy_generation: u64,
        request: &[u8],
        output: &mut [u8],
    ) -> Result<(usize, u64), HostedLifecycleTransportError> {
        if operation == 0
            || policy_generation == 0
            || request.is_empty()
            || request.len() > 4096
            || output.is_empty()
            || output.len() > 4096
            || request.len() + output.len() > 8192
        {
            return Err(HostedLifecycleTransportError::InvalidFrame);
        }
        let output_at = request.len();
        let memory_length = output_at + output.len();
        let mut memory = [0u8; 8192];
        memory[..request.len()].copy_from_slice(request);
        let frame = abi::encode_account_operation_request(abi::AccountOperationRequest {
            operation,
            policy_generation,
            request: abi::BorrowedReadView::within(0, request.len() as u64, memory_length as u64)
                .unwrap(),
            output: abi::BorrowedWriteView::within(
                output_at as u64,
                output.len() as u64,
                memory_length as u64,
            )
            .unwrap(),
        })
        .map_err(HostedLifecycleTransportError::Protocol)?;
        let result = (|| {
            let response = self.call(&frame, &mut memory[..memory_length])?;
            let response = abi::decode_account_operation_response(&response, output.len() as u64)
                .map_err(HostedLifecycleTransportError::Protocol)?
                .map_err(HostedLifecycleTransportError::RemoteAccountStatus)?;
            let written = usize::try_from(response.written)
                .map_err(|_| HostedLifecycleTransportError::OutputLengthMismatch)?;
            output[..written].copy_from_slice(&memory[output_at..output_at + written]);
            Ok((written, response.account_generation))
        })();
        memory.fill(0);
        if result.is_err() {
            output.fill(0);
        }
        result
    }

    pub fn identity_operation(
        &mut self,
        operation: u32,
        identity: TlsIdentityId,
        policy_generation: u64,
        request: &[u8],
        output: &mut [u8],
    ) -> Result<(usize, u64), HostedLifecycleTransportError> {
        const PAYLOAD_AT: usize = 16;
        if operation == 0
            || policy_generation == 0
            || request.is_empty()
            || request.len() > 8192
            || output.is_empty()
            || output.len() > 8192
            || PAYLOAD_AT + request.len() + output.len() > MAX_HOSTED_LIFECYCLE_MEMORY
        {
            return Err(HostedLifecycleTransportError::InvalidFrame);
        }
        let output_at = PAYLOAD_AT + request.len();
        let memory_length = output_at + output.len();
        let mut memory = [0u8; MAX_HOSTED_LIFECYCLE_MEMORY];
        memory[..PAYLOAD_AT].copy_from_slice(&identity.0);
        memory[PAYLOAD_AT..PAYLOAD_AT + request.len()].copy_from_slice(request);
        let frame = abi::encode_identity_operation_request(abi::IdentityOperationRequest {
            operation,
            identity: abi::BorrowedReadView::within(0, 16, memory_length as u64).unwrap(),
            policy_generation,
            request: abi::BorrowedReadView::within(
                PAYLOAD_AT as u64,
                request.len() as u64,
                memory_length as u64,
            )
            .unwrap(),
            output: abi::BorrowedWriteView::within(
                output_at as u64,
                output.len() as u64,
                memory_length as u64,
            )
            .unwrap(),
        })
        .map_err(HostedLifecycleTransportError::Protocol)?;
        let result = (|| {
            let response = self.call(&frame, &mut memory[..memory_length])?;
            let response = abi::decode_identity_operation_response(&response, output.len() as u64)
                .map_err(HostedLifecycleTransportError::Protocol)?
                .map_err(HostedLifecycleTransportError::RemoteIdentityStatus)?;
            let written = usize::try_from(response.written)
                .map_err(|_| HostedLifecycleTransportError::OutputLengthMismatch)?;
            output[..written].copy_from_slice(&memory[output_at..output_at + written]);
            Ok((written, response.identity_generation))
        })();
        memory.fill(0);
        if result.is_err() {
            output.fill(0);
        }
        result
    }

    pub fn backup_transfer(
        &mut self,
        operation: u32,
        policy_generation: u64,
        command: BackupTransferCommand<'_>,
    ) -> Result<BackupTransferReceipt, HostedLifecycleTransportError> {
        const OUTPUT_AT: usize = 4096;
        let mut memory = [0u8; OUTPUT_AT + BACKUP_TRANSFER_RECEIPT_BYTES];
        let request_length = encode_backup_transfer_command(command, &mut memory[..OUTPUT_AT])
            .map_err(|_| HostedLifecycleTransportError::InvalidFrame)?;
        let frame = abi::encode_backup_operation_request(abi::BackupOperationRequest {
            operation,
            policy_generation,
            request: abi::BorrowedReadView::within(0, request_length as u64, memory.len() as u64)
                .unwrap(),
            output: abi::BorrowedWriteView::within(
                OUTPUT_AT as u64,
                BACKUP_TRANSFER_RECEIPT_BYTES as u64,
                memory.len() as u64,
            )
            .unwrap(),
        })
        .map_err(HostedLifecycleTransportError::Protocol)?;
        let response = self.call(&frame, &mut memory)?;
        let result = (|| {
            let response = abi::decode_backup_operation_response(
                &response,
                BACKUP_TRANSFER_RECEIPT_BYTES as u64,
            )
            .map_err(HostedLifecycleTransportError::Protocol)?
            .map_err(HostedLifecycleTransportError::RemoteBackupStatus)?;
            if response.written != BACKUP_TRANSFER_RECEIPT_BYTES as u64 {
                return Err(HostedLifecycleTransportError::OutputLengthMismatch);
            }
            let receipt = decode_backup_transfer_receipt(
                &memory[OUTPUT_AT..OUTPUT_AT + BACKUP_TRANSFER_RECEIPT_BYTES],
            )
            .map_err(|_| HostedLifecycleTransportError::InvalidFrame)?;
            if response.backup_generation != receipt.transfer_generation {
                return Err(HostedLifecycleTransportError::OutputLengthMismatch);
            }
            Ok(receipt)
        })();
        memory.fill(0);
        result
    }

    pub fn verify_backup_container(
        &mut self,
        policy_generation: u64,
        transfer_generation: u64,
        input: &[u8],
    ) -> Result<BackupTransferReceipt, HostedLifecycleTransportError> {
        self.upload_backup_container(
            abi::BACKUP_VERIFY,
            BackupTransferPurpose::VerifyOnly,
            policy_generation,
            transfer_generation,
            input,
        )
    }

    pub fn restore_backup_container(
        &mut self,
        policy_generation: u64,
        transfer_generation: u64,
        input: &[u8],
        confirmed_digest: [u8; 32],
    ) -> Result<BackupTransferReceipt, HostedLifecycleTransportError> {
        if untrusted_backup_container_digest(input)
            .map_err(|_| HostedLifecycleTransportError::InvalidFrame)?
            != confirmed_digest
        {
            return Err(HostedLifecycleTransportError::InvalidFrame);
        }
        self.upload_backup_container(
            abi::RESTORE_VERIFY_ONLY,
            BackupTransferPurpose::Restore,
            policy_generation,
            transfer_generation,
            input,
        )?;
        let receipt = self.backup_transfer(
            abi::RESTORE_COMMIT,
            policy_generation,
            BackupTransferCommand::Restore {
                transfer_generation,
            },
        )?;
        validate_completed_receipt(
            receipt,
            BackupTransferReceiptState::Restored,
            BackupTransferPurpose::Restore,
            policy_generation,
            transfer_generation,
            input.len(),
            confirmed_digest,
        )?;
        Ok(receipt)
    }

    pub fn create_backup_container(
        &mut self,
        policy_generation: u64,
        export_generation: u64,
        output: &mut [u8],
    ) -> Result<(usize, BackupExportReceipt), HostedLifecycleTransportError> {
        if policy_generation == 0 || export_generation == 0 || output.is_empty() {
            return Err(HostedLifecycleTransportError::InvalidFrame);
        }
        let mut receipt_bytes = [0u8; BACKUP_EXPORT_RECEIPT_BYTES];
        let begin_written = self.backup_export_call(
            policy_generation,
            BackupExportCommand::Begin {
                export_generation,
                policy_generation,
            },
            &mut receipt_bytes,
        )?;
        let opened = decode_backup_export_receipt(&receipt_bytes[..begin_written])
            .map_err(|_| HostedLifecycleTransportError::InvalidFrame)?;
        validate_export_receipt(opened, policy_generation, export_generation, false)?;
        let total = opened.total_bytes as usize;
        if total > output.len() || total > MAX_BACKUP_BYTES {
            return Err(HostedLifecycleTransportError::MemoryLimit);
        }
        let mut offset = 0usize;
        while offset < total {
            let limit = (total - offset).min(MAX_BACKUP_EXPORT_CHUNK);
            let written = self.backup_export_call(
                policy_generation,
                BackupExportCommand::Read {
                    export_generation,
                    offset,
                },
                &mut output[offset..offset + limit],
            )?;
            if written == 0 || written > limit {
                output[..offset].fill(0);
                return Err(HostedLifecycleTransportError::OutputLengthMismatch);
            }
            offset += written;
        }
        if untrusted_backup_container_digest(&output[..total])
            .map_err(|_| HostedLifecycleTransportError::InvalidFrame)?
            != opened.backup_digest
        {
            output[..total].fill(0);
            return Err(HostedLifecycleTransportError::OutputLengthMismatch);
        }
        receipt_bytes.fill(0);
        let finish_written = self.backup_export_call(
            policy_generation,
            BackupExportCommand::Finish { export_generation },
            &mut receipt_bytes,
        )?;
        let completed = decode_backup_export_receipt(&receipt_bytes[..finish_written])
            .map_err(|_| HostedLifecycleTransportError::InvalidFrame)?;
        validate_export_receipt(completed, policy_generation, export_generation, true)?;
        if completed.export_generation != opened.export_generation
            || completed.policy_generation != opened.policy_generation
            || completed.offset != completed.total_bytes
            || completed.total_bytes != opened.total_bytes
            || completed.record_count != opened.record_count
            || completed.backup_digest != opened.backup_digest
        {
            output[..total].fill(0);
            return Err(HostedLifecycleTransportError::OutputLengthMismatch);
        }
        Ok((total, completed))
    }

    fn backup_export_call(
        &mut self,
        policy_generation: u64,
        command: BackupExportCommand,
        output: &mut [u8],
    ) -> Result<usize, HostedLifecycleTransportError> {
        const OUTPUT_AT: usize = 4096;
        let mut memory = [0u8; OUTPUT_AT + MAX_BACKUP_EXPORT_CHUNK];
        let request = encode_backup_export_command(command)
            .map_err(|_| HostedLifecycleTransportError::InvalidFrame)?;
        memory[..BACKUP_EXPORT_COMMAND_BYTES].copy_from_slice(&request);
        let output_length = output.len().min(MAX_BACKUP_EXPORT_CHUNK);
        if output_length == 0 {
            return Err(HostedLifecycleTransportError::MemoryLimit);
        }
        let frame = abi::encode_backup_operation_request(abi::BackupOperationRequest {
            operation: abi::BACKUP_CREATE,
            policy_generation,
            request: abi::BorrowedReadView::within(
                0,
                BACKUP_EXPORT_COMMAND_BYTES as u64,
                memory.len() as u64,
            )
            .unwrap(),
            output: abi::BorrowedWriteView::within(
                OUTPUT_AT as u64,
                output_length as u64,
                memory.len() as u64,
            )
            .unwrap(),
        })
        .map_err(HostedLifecycleTransportError::Protocol)?;
        let response = self.call(&frame, &mut memory)?;
        let response = abi::decode_backup_operation_response(&response, output_length as u64)
            .map_err(HostedLifecycleTransportError::Protocol)?
            .map_err(HostedLifecycleTransportError::RemoteBackupStatus)?;
        if response.backup_generation != command_export_generation(command) {
            return Err(HostedLifecycleTransportError::OutputLengthMismatch);
        }
        let written = usize::try_from(response.written)
            .map_err(|_| HostedLifecycleTransportError::OutputLengthMismatch)?;
        output[..written].copy_from_slice(&memory[OUTPUT_AT..OUTPUT_AT + written]);
        memory.fill(0);
        Ok(written)
    }

    fn upload_backup_container(
        &mut self,
        operation: u32,
        purpose: BackupTransferPurpose,
        policy_generation: u64,
        transfer_generation: u64,
        input: &[u8],
    ) -> Result<BackupTransferReceipt, HostedLifecycleTransportError> {
        if input.is_empty()
            || input.len() > MAX_BACKUP_BYTES
            || policy_generation == 0
            || transfer_generation == 0
        {
            return Err(HostedLifecycleTransportError::InvalidFrame);
        }
        let digest = untrusted_backup_container_digest(input)
            .map_err(|_| HostedLifecycleTransportError::InvalidFrame)?;
        let result = (|| {
            let begin = self.backup_transfer(
                operation,
                policy_generation,
                BackupTransferCommand::Begin {
                    purpose,
                    transfer_generation,
                    policy_generation,
                    total_bytes: input.len(),
                    expected_digest: digest,
                },
            )?;
            validate_progress(
                begin,
                purpose,
                policy_generation,
                transfer_generation,
                0,
                input.len(),
            )?;
            let mut accepted = 0usize;
            for chunk in input.chunks(MAX_BACKUP_WIRE_CHUNK) {
                let receipt = self.backup_transfer(
                    operation,
                    policy_generation,
                    BackupTransferCommand::Append {
                        purpose,
                        transfer_generation,
                        offset: accepted,
                        chunk,
                    },
                )?;
                accepted += chunk.len();
                validate_progress(
                    receipt,
                    purpose,
                    policy_generation,
                    transfer_generation,
                    accepted,
                    input.len(),
                )?;
            }
            let receipt = self.backup_transfer(
                operation,
                policy_generation,
                BackupTransferCommand::Verify {
                    purpose,
                    transfer_generation,
                },
            )?;
            validate_completed_receipt(
                receipt,
                BackupTransferReceiptState::Verified,
                purpose,
                policy_generation,
                transfer_generation,
                input.len(),
                digest,
            )?;
            Ok(receipt)
        })();
        if result.is_err() {
            let _ = self.backup_transfer(
                operation,
                policy_generation,
                BackupTransferCommand::Cancel {
                    purpose,
                    transfer_generation,
                },
            );
        }
        result
    }
}

fn command_export_generation(command: BackupExportCommand) -> u64 {
    match command {
        BackupExportCommand::Begin {
            export_generation, ..
        }
        | BackupExportCommand::Read {
            export_generation, ..
        }
        | BackupExportCommand::Finish { export_generation } => export_generation,
    }
}

fn validate_export_receipt(
    receipt: BackupExportReceipt,
    policy_generation: u64,
    export_generation: u64,
    finished: bool,
) -> Result<(), HostedLifecycleTransportError> {
    if receipt.policy_generation != policy_generation
        || receipt.export_generation != export_generation
        || receipt.finished != finished
        || receipt.total_bytes == 0
        || receipt.record_count == 0
        || receipt.backup_digest == [0; 32]
    {
        return Err(HostedLifecycleTransportError::OutputLengthMismatch);
    }
    Ok(())
}

fn validate_progress(
    receipt: BackupTransferReceipt,
    purpose: BackupTransferPurpose,
    policy_generation: u64,
    transfer_generation: u64,
    accepted: usize,
    total: usize,
) -> Result<(), HostedLifecycleTransportError> {
    if receipt.state != BackupTransferReceiptState::Accepted
        || receipt.purpose != purpose
        || receipt.policy_generation != policy_generation
        || receipt.transfer_generation != transfer_generation
        || receipt.accepted_bytes as usize != accepted
        || receipt.total_bytes as usize != total
        || receipt.record_count != 0
        || receipt.backup_digest != [0; 32]
    {
        return Err(HostedLifecycleTransportError::OutputLengthMismatch);
    }
    Ok(())
}

fn validate_completed_receipt(
    receipt: BackupTransferReceipt,
    state: BackupTransferReceiptState,
    purpose: BackupTransferPurpose,
    policy_generation: u64,
    transfer_generation: u64,
    total: usize,
    digest: [u8; 32],
) -> Result<(), HostedLifecycleTransportError> {
    if receipt.state != state
        || receipt.purpose != purpose
        || receipt.policy_generation != policy_generation
        || receipt.transfer_generation != transfer_generation
        || receipt.accepted_bytes as usize != total
        || receipt.total_bytes as usize != total
        || receipt.record_count == 0
        || receipt.backup_digest != digest
    {
        return Err(HostedLifecycleTransportError::OutputLengthMismatch);
    }
    Ok(())
}

/// Server over one connection already authorized and delivered by the host
/// supervisor. The operation authorizer remains mandatory and exact.
pub struct HostedLifecycleServer {
    stream: TcpStream,
}

impl HostedLifecycleServer {
    pub fn from_authorized_stream(
        mut stream: TcpStream,
    ) -> Result<Self, HostedLifecycleTransportError> {
        configure(&mut stream)?;
        Ok(Self { stream })
    }

    pub fn serve_one<A: CertificateLifecycleAuthorizer, P: CertificateLifecycleProvider>(
        &mut self,
        authorizer: &A,
        provider: &mut P,
    ) -> Result<(), HostedLifecycleTransportError> {
        let mut header = [0u8; HEADER_BYTES];
        self.stream
            .read_exact(&mut header)
            .map_err(HostedLifecycleTransportError::Network)?;
        if &header[..8] != REQUEST_MAGIC || header[12..] != [0; 4] {
            return Err(HostedLifecycleTransportError::InvalidHeader);
        }
        let frame_length = usize::from(u16::from_be_bytes([header[8], header[9]]));
        let memory_length = usize::from(u16::from_be_bytes([header[10], header[11]]));
        validate_frame_length(frame_length)?;
        if memory_length == 0 || memory_length > MAX_HOSTED_LIFECYCLE_MEMORY {
            return Err(HostedLifecycleTransportError::MemoryLimit);
        }
        let mut frame = [0u8; MAX_FRAME_BYTES];
        let mut memory = [0u8; MAX_HOSTED_LIFECYCLE_MEMORY];
        self.stream
            .read_exact(&mut frame[..frame_length])
            .and_then(|_| self.stream.read_exact(&mut memory[..memory_length]))
            .map_err(HostedLifecycleTransportError::Network)?;
        let response = dispatch_lifecycle_call(
            authorizer,
            provider,
            &frame[..frame_length],
            &mut memory[..memory_length],
        )
        .map_err(|_| HostedLifecycleTransportError::InvalidFrame)?;
        frame.fill(0);
        header.fill(0);
        header[..8].copy_from_slice(RESPONSE_MAGIC);
        header[8..10].copy_from_slice(&(abi::RESPONSE_BYTES as u16).to_be_bytes());
        header[10..12].copy_from_slice(&(memory_length as u16).to_be_bytes());
        let result = self
            .stream
            .write_all(&header)
            .and_then(|_| self.stream.write_all(&response))
            .and_then(|_| self.stream.write_all(&memory[..memory_length]))
            .map_err(HostedLifecycleTransportError::Network);
        memory.fill(0);
        result
    }
}

fn configure(stream: &mut TcpStream) -> Result<(), HostedLifecycleTransportError> {
    stream
        .set_read_timeout_millis(IO_TIMEOUT_MILLIS)
        .and_then(|_| stream.set_write_timeout_millis(IO_TIMEOUT_MILLIS))
        .map_err(HostedLifecycleTransportError::Network)
}

fn validate_frame_length(length: usize) -> Result<(), HostedLifecycleTransportError> {
    if length == abi::STATUS_REQUEST_BYTES
        || length == abi::ACCOUNT_OPERATION_REQUEST_BYTES
        || length == abi::IDENTITY_OPERATION_REQUEST_BYTES
    {
        Ok(())
    } else {
        Err(HostedLifecycleTransportError::InvalidFrame)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use mrml_runtime::{Shared, TcpListener};

    struct Authorizer;
    impl CertificateLifecycleAuthorizer for Authorizer {
        fn authorize_status(&self, _: u32, _: &[u8]) -> bool {
            true
        }
        fn authorize_account(&self, operation: u32, generation: u64, request: &[u8]) -> bool {
            operation == abi::ACCOUNT_UPDATE && generation == 7 && request == b"exact"
        }
        fn authorize_identity(
            &self,
            operation: u32,
            identity: &[u8],
            generation: u64,
            request: &[u8],
        ) -> bool {
            operation == abi::IDENTITY_RENEW
                && identity == [9; 16]
                && generation == 7
                && request == b"renew"
        }
        fn authorize_backup(&self, _: u32, _: u64, _: &[u8]) -> bool {
            false
        }
    }

    struct BackupAuthorizer;
    impl CertificateLifecycleAuthorizer for BackupAuthorizer {
        fn authorize_status(&self, _: u32, _: &[u8]) -> bool {
            false
        }
        fn authorize_account(&self, _: u32, _: u64, _: &[u8]) -> bool {
            false
        }
        fn authorize_identity(&self, _: u32, _: &[u8], _: u64, _: &[u8]) -> bool {
            false
        }
        fn authorize_backup(&self, operation: u32, policy: u64, _: &[u8]) -> bool {
            matches!(
                operation,
                abi::BACKUP_CREATE
                    | abi::BACKUP_VERIFY
                    | abi::RESTORE_VERIFY_ONLY
                    | abi::RESTORE_COMMIT
            ) && policy == 7
        }
    }

    struct TransferAuth;
    impl crate::DurableAuthenticator for TransferAuth {
        fn authenticate(&mut self, record: &[u8]) -> Result<[u8; 32], crate::DurableError> {
            let mut hash = mrml_crypto::Sha256::new();
            hash.update(b"hosted-backup-transfer-test");
            hash.update(record);
            Ok(hash.finalize())
        }
        fn verify(&mut self, record: &[u8], tag: &[u8; 32]) -> Result<bool, crate::DurableError> {
            Ok(self.authenticate(record)? == *tag)
        }
    }

    struct TransferTarget {
        committed: bool,
    }
    impl crate::BackupRestoreTarget for TransferTarget {
        fn require_empty(&mut self) -> Result<(), crate::BackupError> {
            (!self.committed)
                .then_some(())
                .ok_or(crate::BackupError::TargetNotEmpty)
        }
        fn begin(&mut self, _: crate::BackupDescriptor) -> Result<(), crate::BackupError> {
            Ok(())
        }
        fn import(&mut self, _: &crate::DurableRecord) -> Result<(), crate::BackupError> {
            Ok(())
        }
        fn commit(&mut self, _: crate::BackupDescriptor) -> Result<(), crate::BackupError> {
            self.committed = true;
            Ok(())
        }
        fn abort(&mut self) {}
    }

    struct TransferProvider<'a> {
        lifecycle: crate::BackupTransferLifecycle<'a>,
        authenticator: TransferAuth,
        target: TransferTarget,
    }
    impl CertificateLifecycleProvider for TransferProvider<'_> {
        fn status(
            &mut self,
            _: u32,
            _: &[u8],
            _: &mut [u8],
        ) -> Result<abi::StatusResponse, abi::StatusError> {
            Err(abi::StatusError::PermissionDenied)
        }
        fn account_operation(
            &mut self,
            _: u32,
            _: u64,
            _: &[u8],
            _: &mut [u8],
        ) -> Result<abi::AccountOperationResponse, abi::AccountOperationError> {
            Err(abi::AccountOperationError::PermissionDenied)
        }
        fn identity_operation(
            &mut self,
            _: u32,
            _: &[u8],
            _: u64,
            _: &[u8],
            _: &mut [u8],
        ) -> Result<abi::IdentityOperationResponse, abi::IdentityOperationError> {
            Err(abi::IdentityOperationError::PermissionDenied)
        }
        fn backup_operation(
            &mut self,
            operation: u32,
            policy_generation: u64,
            request: &[u8],
            output: &mut [u8],
        ) -> Result<abi::BackupOperationResponse, abi::BackupOperationError> {
            self.lifecycle.handle(
                operation,
                policy_generation,
                request,
                output,
                &mut self.authenticator,
                &mut self.target,
            )
        }
    }

    fn backup_fixture() -> (std::vec::Vec<u8>, [u8; 32]) {
        let mut authenticator = TransferAuth;
        let record = crate::DurableRecord::prepare(
            crate::DurableNamespace::PublicState,
            crate::DurableRecordKind::Account,
            crate::DurableObjectId([6; 16]),
            0,
            &[0x44; 4096],
            &mut authenticator,
        )
        .unwrap();
        let mut encoded = std::vec![0; crate::MAX_BACKUP_BYTES];
        let (written, descriptor) =
            crate::create_backup(7, &[&record], &mut encoded, &mut authenticator).unwrap();
        encoded.truncate(written);
        (encoded, descriptor.backup_digest)
    }

    struct ExportSource {
        bytes: std::vec::Vec<u8>,
        digest: [u8; 32],
    }
    impl crate::BackupExportSource for ExportSource {
        fn create_recoverable_backup(
            &mut self,
            policy_generation: u64,
            output: &mut [u8],
        ) -> Result<(usize, crate::BackupDescriptor), crate::BackupError> {
            output[..self.bytes.len()].copy_from_slice(&self.bytes);
            Ok((
                self.bytes.len(),
                crate::BackupDescriptor {
                    policy_generation,
                    record_count: 1,
                    backup_digest: self.digest,
                },
            ))
        }
    }

    struct ExportProvider<'a> {
        lifecycle: crate::BackupExportSession<'a>,
        source: ExportSource,
    }
    impl CertificateLifecycleProvider for ExportProvider<'_> {
        fn status(
            &mut self,
            _: u32,
            _: &[u8],
            _: &mut [u8],
        ) -> Result<abi::StatusResponse, abi::StatusError> {
            Err(abi::StatusError::PermissionDenied)
        }
        fn account_operation(
            &mut self,
            _: u32,
            _: u64,
            _: &[u8],
            _: &mut [u8],
        ) -> Result<abi::AccountOperationResponse, abi::AccountOperationError> {
            Err(abi::AccountOperationError::PermissionDenied)
        }
        fn identity_operation(
            &mut self,
            _: u32,
            _: &[u8],
            _: u64,
            _: &[u8],
            _: &mut [u8],
        ) -> Result<abi::IdentityOperationResponse, abi::IdentityOperationError> {
            Err(abi::IdentityOperationError::PermissionDenied)
        }
        fn backup_operation(
            &mut self,
            operation: u32,
            policy_generation: u64,
            request: &[u8],
            output: &mut [u8],
        ) -> Result<abi::BackupOperationResponse, abi::BackupOperationError> {
            self.lifecycle.handle(
                operation,
                policy_generation,
                request,
                output,
                &mut self.source,
            )
        }
    }

    struct Provider;
    impl CertificateLifecycleProvider for Provider {
        fn status(
            &mut self,
            _: u32,
            identity: &[u8],
            output: &mut [u8],
        ) -> Result<abi::StatusResponse, abi::StatusError> {
            let identity: [u8; 16] = identity
                .try_into()
                .map_err(|_| abi::StatusError::InvalidRequest)?;
            let written = crate::encode_managed_identity_status(
                crate::ManagedIdentityStatus {
                    identity: TlsIdentityId(identity),
                    policy_generation: 7,
                    active: None,
                    renewal: None,
                    renewal_lease: None,
                    replacement: None,
                },
                output,
            )
            .map_err(|_| abi::StatusError::OutputTooSmall)?;
            Ok(abi::StatusResponse {
                written: written as u64,
                state_generation: 7,
            })
        }
        fn account_operation(
            &mut self,
            _: u32,
            _: u64,
            _: &[u8],
            output: &mut [u8],
        ) -> Result<abi::AccountOperationResponse, abi::AccountOperationError> {
            output[..2].copy_from_slice(b"ok");
            Ok(abi::AccountOperationResponse {
                written: 2,
                account_generation: 8,
            })
        }
        fn identity_operation(
            &mut self,
            _: u32,
            _: &[u8],
            _: u64,
            _: &[u8],
            output: &mut [u8],
        ) -> Result<abi::IdentityOperationResponse, abi::IdentityOperationError> {
            output[..7].copy_from_slice(b"renewed");
            Ok(abi::IdentityOperationResponse {
                written: 7,
                identity_generation: 9,
            })
        }
        fn backup_operation(
            &mut self,
            operation: u32,
            policy_generation: u64,
            request: &[u8],
            output: &mut [u8],
        ) -> Result<abi::BackupOperationResponse, abi::BackupOperationError> {
            let crate::BackupTransferCommand::Begin {
                purpose: crate::BackupTransferPurpose::VerifyOnly,
                transfer_generation,
                policy_generation: command_policy,
                total_bytes,
                ..
            } = crate::decode_backup_transfer_command(request)
                .map_err(|_| abi::BackupOperationError::InvalidRequest)?
            else {
                return Err(abi::BackupOperationError::InvalidRequest);
            };
            if operation != abi::BACKUP_VERIFY || policy_generation != 7 || command_policy != 7 {
                return Err(abi::BackupOperationError::StalePolicy);
            }
            crate::encode_backup_transfer_receipt(
                crate::BackupTransferReceipt {
                    state: crate::BackupTransferReceiptState::Accepted,
                    purpose: crate::BackupTransferPurpose::VerifyOnly,
                    transfer_generation,
                    policy_generation,
                    accepted_bytes: 0,
                    total_bytes: total_bytes as u32,
                    record_count: 0,
                    backup_digest: [0; 32],
                },
                output,
            )
            .map_err(|_| abi::BackupOperationError::OperationFailed)?;
            Ok(abi::BackupOperationResponse {
                written: crate::BACKUP_TRANSFER_RECEIPT_BYTES as u64,
                backup_generation: transfer_generation,
            })
        }
    }

    #[test]
    fn preauthorized_stream_carries_exact_bounded_lifecycle_call() {
        let listener = TcpListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        let listener = Shared::new(listener);
        let server_listener = listener.clone();
        assert!(mrml_runtime::spawn_detached(move || {
            let stream = server_listener.accept().unwrap();
            let mut server = HostedLifecycleServer::from_authorized_stream(stream).unwrap();
            server.serve_one(&Authorizer, &mut Provider).unwrap();
        })
        .is_ok());
        let stream = TcpStream::connect([127, 0, 0, 1], port).unwrap();
        let mut client = HostedLifecycleClient::from_authorized_stream(stream).unwrap();
        let mut memory = [0u8; 64];
        memory[..5].copy_from_slice(b"exact");
        let frame = abi::encode_account_operation_request(abi::AccountOperationRequest {
            operation: abi::ACCOUNT_UPDATE,
            policy_generation: 7,
            request: abi::BorrowedReadView::within(0, 5, 64).unwrap(),
            output: abi::BorrowedWriteView::within(32, 32, 64).unwrap(),
        })
        .unwrap();
        let response = client.call(&frame, &mut memory).unwrap();
        assert_eq!(
            abi::decode_account_operation_response(&response, 32),
            Ok(Ok(abi::AccountOperationResponse {
                written: 2,
                account_generation: 8
            }))
        );
        assert_eq!(&memory[32..34], b"ok");
    }

    #[test]
    fn rejects_bounds_before_io() {
        let listener = TcpListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        let stream = TcpStream::connect([127, 0, 0, 1], port).unwrap();
        let mut client = HostedLifecycleClient::from_authorized_stream(stream).unwrap();
        let mut memory = [0u8; 1];
        assert_eq!(
            client.call(&[0; 7], &mut memory),
            Err(HostedLifecycleTransportError::InvalidFrame)
        );
        let mut oversized = [0u8; MAX_HOSTED_LIFECYCLE_MEMORY + 1];
        assert_eq!(
            client.call(&[0; abi::STATUS_REQUEST_BYTES], &mut oversized),
            Err(HostedLifecycleTransportError::MemoryLimit)
        );
    }

    #[test]
    fn typed_status_call_hides_borrowed_memory_layout_from_client() {
        let listener = TcpListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        let listener = Shared::new(listener);
        let server_listener = listener.clone();
        assert!(mrml_runtime::spawn_detached(move || {
            let stream = server_listener.accept().unwrap();
            let mut server = HostedLifecycleServer::from_authorized_stream(stream).unwrap();
            server.serve_one(&Authorizer, &mut Provider).unwrap();
        })
        .is_ok());
        let stream = TcpStream::connect([127, 0, 0, 1], port).unwrap();
        let mut client = HostedLifecycleClient::from_authorized_stream(stream).unwrap();
        let identity = TlsIdentityId([9; 16]);
        let status = client.identity_status(identity).unwrap();
        assert!(status.identity == identity);
        assert_eq!(status.policy_generation, 7);
        assert!(status.active.is_none());
    }

    #[test]
    fn typed_account_call_binds_operation_policy_and_bounded_output() {
        let listener = TcpListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        let listener = Shared::new(listener);
        let server_listener = listener.clone();
        assert!(mrml_runtime::spawn_detached(move || {
            let stream = server_listener.accept().unwrap();
            let mut server = HostedLifecycleServer::from_authorized_stream(stream).unwrap();
            server.serve_one(&Authorizer, &mut Provider).unwrap();
        })
        .is_ok());
        let stream = TcpStream::connect([127, 0, 0, 1], port).unwrap();
        let mut client = HostedLifecycleClient::from_authorized_stream(stream).unwrap();
        let mut output = [0u8; 8];
        assert_eq!(
            client
                .account_operation(abi::ACCOUNT_UPDATE, 7, b"exact", &mut output)
                .unwrap(),
            (2, 8)
        );
        assert_eq!(&output[..2], b"ok");
    }

    #[test]
    fn typed_identity_call_binds_identity_operation_and_policy() {
        let listener = TcpListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        let listener = Shared::new(listener);
        let server_listener = listener.clone();
        assert!(mrml_runtime::spawn_detached(move || {
            let stream = server_listener.accept().unwrap();
            let mut server = HostedLifecycleServer::from_authorized_stream(stream).unwrap();
            server.serve_one(&Authorizer, &mut Provider).unwrap();
        })
        .is_ok());
        let stream = TcpStream::connect([127, 0, 0, 1], port).unwrap();
        let mut client = HostedLifecycleClient::from_authorized_stream(stream).unwrap();
        let mut output = [0u8; 8];
        assert_eq!(
            client
                .identity_operation(
                    abi::IDENTITY_RENEW,
                    TlsIdentityId([9; 16]),
                    7,
                    b"renew",
                    &mut output,
                )
                .unwrap(),
            (7, 9)
        );
        assert_eq!(&output[..7], b"renewed");
    }

    #[test]
    fn one_use_session_capability_authorizes_live_status_without_address_authority() {
        let listener = TcpListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        let listener = Shared::new(listener);
        let server_listener = listener.clone();
        assert!(mrml_runtime::spawn_detached(move || {
            let mut capability = HostedLifecycleSessionCapability::new([0x5a; 32]).unwrap();
            let mut server = capability.accept_one(&server_listener).unwrap();
            server.serve_one(&Authorizer, &mut Provider).unwrap();
            assert!(matches!(
                capability.accept_one(&server_listener),
                Err(HostedLifecycleTransportError::SessionDenied)
            ));
        })
        .is_ok());
        let mut client =
            HostedLifecycleClient::connect_session([127, 0, 0, 1], port, [0x5a; 32]).unwrap();
        let status = client.identity_status(TlsIdentityId([9; 16])).unwrap();
        assert_eq!(status.policy_generation, 7);
    }

    #[test]
    fn typed_backup_call_validates_canonical_receipt_and_generation() {
        let listener = TcpListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        let listener = Shared::new(listener);
        let server_listener = listener.clone();
        assert!(mrml_runtime::spawn_detached(move || {
            let stream = server_listener.accept().unwrap();
            let mut server = HostedLifecycleServer::from_authorized_stream(stream).unwrap();
            server.serve_one(&BackupAuthorizer, &mut Provider).unwrap();
        })
        .is_ok());
        let stream = TcpStream::connect([127, 0, 0, 1], port).unwrap();
        let mut client = HostedLifecycleClient::from_authorized_stream(stream).unwrap();
        let receipt = client
            .backup_transfer(
                abi::BACKUP_VERIFY,
                7,
                crate::BackupTransferCommand::Begin {
                    purpose: crate::BackupTransferPurpose::VerifyOnly,
                    transfer_generation: 13,
                    policy_generation: 7,
                    total_bytes: 1024,
                    expected_digest: [9; 32],
                },
            )
            .unwrap();
        assert_eq!(receipt.transfer_generation, 13);
        assert_eq!(receipt.policy_generation, 7);
        assert_eq!(receipt.state, crate::BackupTransferReceiptState::Accepted);
    }

    #[test]
    fn hosted_client_streams_and_restores_complete_backup_transaction() {
        let (encoded, digest) = backup_fixture();
        assert!(encoded.len() > crate::MAX_BACKUP_WIRE_CHUNK);
        let listener = TcpListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        let listener = Shared::new(listener);
        let server_listener = listener.clone();
        assert!(mrml_runtime::spawn_detached(move || {
            let mut storage = std::vec![0; crate::MAX_BACKUP_BYTES];
            let mut provider = TransferProvider {
                lifecycle: crate::BackupTransferLifecycle::new(&mut storage).unwrap(),
                authenticator: TransferAuth,
                target: TransferTarget { committed: false },
            };
            let stream = server_listener.accept().unwrap();
            let mut server = HostedLifecycleServer::from_authorized_stream(stream).unwrap();
            for _ in 0..5 {
                server.serve_one(&BackupAuthorizer, &mut provider).unwrap();
            }
            assert!(provider.target.committed);
        })
        .is_ok());
        let stream = TcpStream::connect([127, 0, 0, 1], port).unwrap();
        let mut client = HostedLifecycleClient::from_authorized_stream(stream).unwrap();
        let receipt = client
            .restore_backup_container(7, 29, &encoded, digest)
            .unwrap();
        assert_eq!(receipt.state, crate::BackupTransferReceiptState::Restored);
        assert_eq!(receipt.backup_digest, digest);
    }

    #[test]
    fn hosted_client_downloads_exact_authenticated_backup_container() {
        let (expected, digest) = backup_fixture();
        let listener = TcpListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        let listener = Shared::new(listener);
        let server_listener = listener.clone();
        let expected_for_server = expected.clone();
        assert!(mrml_runtime::spawn_detached(move || {
            let mut storage = std::vec![0; crate::MAX_BACKUP_BYTES];
            let mut provider = ExportProvider {
                lifecycle: crate::BackupExportSession::new(&mut storage).unwrap(),
                source: ExportSource {
                    bytes: expected_for_server,
                    digest,
                },
            };
            let stream = server_listener.accept().unwrap();
            let mut server = HostedLifecycleServer::from_authorized_stream(stream).unwrap();
            for _ in 0..3 {
                server.serve_one(&BackupAuthorizer, &mut provider).unwrap();
            }
        })
        .is_ok());
        let stream = TcpStream::connect([127, 0, 0, 1], port).unwrap();
        let mut client = HostedLifecycleClient::from_authorized_stream(stream).unwrap();
        let mut output = std::vec![0; crate::MAX_BACKUP_BYTES];
        let (written, receipt) = client.create_backup_container(7, 31, &mut output).unwrap();
        assert_eq!(&output[..written], &expected);
        assert_eq!(receipt.backup_digest, digest);
        assert!(receipt.finished);
    }
}
