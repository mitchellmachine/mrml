#![no_std]
#![no_main]

use mrml_error::{Result, anyhow};
#[cfg(windows)]
use mrml_kernel::{AUTHORITY_RECEIPT_BYTES, AuthorityReceipt, LAUNCH_REQUEST_BYTES, LaunchRequest};
#[cfg(windows)]
use mrml_runtime::{Vector, mrml_println, read_file_bounded};

#[cfg(windows)]
const MAX_ENCLAVE_IMAGE_BYTES: usize = 16 * 1024 * 1024;
#[cfg(windows)]
const AUTHORITY_KEY: [u8; 32] = [0x39; 32];
#[cfg(windows)]
const AUTHORITY_MEASUREMENT: [u8; 64] = [0x51; 64];

#[cfg(windows)]
const AUTHORITY_CALL_MAGIC: u64 = u64::from_le_bytes(*b"MRMLAC01");

#[cfg(windows)]
fn application_main() -> Result<()> {
    let arguments = mrml_runtime::command_arguments();
    if arguments.len() != 2 {
        return Err(anyhow!("usage: mrml-vbs-host ENCLAVE.dll"));
    }
    let path = arguments[1].as_str();
    let image = read_file_bounded(path, MAX_ENCLAVE_IMAGE_BYTES)
        .map_err(|_| anyhow!("failed to read bounded enclave image"))?;
    let authority = mrml_windows::vbs_enclave_export_rva(&image, b"mrml_launch_authority")
        .map_err(|error| anyhow!("invalid authority export: {:?}", error))?;
    let mut wide = Vector::with_capacity(path.len() + 1)
        .map_err(|_| anyhow!("failed to allocate bounded UTF-16 path"))?;
    for unit in path.encode_utf16() {
        wide.push(unit);
    }
    wide.push(0);

    let apis = mrml_windows::vbs_enclave_apis();
    let support = mrml_windows::vbs_enclave_support();
    mrml_println!(
        "VBS support={:?} complete_abi={}",
        support,
        apis.is_complete()
    );
    let mut enclave = mrml_windows::VbsEnclaveReservation::reserve([0; 32])
        .map_err(|error| anyhow!("CreateEnclave failed: {:?}", error))?;
    mrml_println!("reserved {} byte non-debug VBS enclave", enclave.size());
    enclave
        .load_image_wide(&wide)
        .map_err(|error| anyhow!("LoadEnclaveImageW failed: {:?}", error))?;
    mrml_println!("Windows accepted signed enclave image");
    let threads = enclave
        .initialize(1)
        .map_err(|error| anyhow!("InitializeEnclave failed: {:?}", error))?;
    mrml_println!("initialized VBS enclave with {} thread(s)", threads);

    let mut nonce = [0; 32];
    mrml_runtime::fill_random(&mut nonce)
        .map_err(|_| anyhow!("cryptographic nonce generation failed"))?;
    let request = LaunchRequest::new(1, nonce, AUTHORITY_MEASUREMENT, [0x72; 64])
        .map_err(|error| anyhow!("launch request rejected: {:?}", error))?;
    let encoded_request: [u8; LAUNCH_REQUEST_BYTES] = request.encode();
    let mut receipt = [0; AUTHORITY_RECEIPT_BYTES];
    let mut call = [0; mrml_windows::VBS_AUTHORITY_CONTEXT_BYTES];
    call[..8].copy_from_slice(&AUTHORITY_CALL_MAGIC.to_le_bytes());
    call[8..16].copy_from_slice(&(encoded_request.as_ptr() as u64).to_le_bytes());
    call[16..24].copy_from_slice(&(encoded_request.len() as u64).to_le_bytes());
    call[24..32].copy_from_slice(&(receipt.as_mut_ptr() as u64).to_le_bytes());
    call[32..40].copy_from_slice(&(receipt.len() as u64).to_le_bytes());
    let authority_status = enclave
        .call_authority(authority, &mut call)
        .map_err(|error| anyhow!("CallEnclave failed: {:?}", error))?;
    if authority_status != 0 {
        return Err(anyhow!(
            "VTL1 launch authority rejected request with status {}",
            authority_status
        ));
    }
    let verified = AuthorityReceipt::verify(&AUTHORITY_KEY, request, &receipt)
        .map_err(|error| anyhow!("authority receipt verification failed: {:?}", error))?;
    mrml_println!(
        "verified VTL1 authority receipt: backend={:?} claims={:?}",
        verified.report().backend(),
        verified.report().claims()
    );
    Ok(())
}

#[cfg(not(windows))]
fn application_main() -> Result<()> {
    Err(anyhow!("VBS enclaves require Windows"))
}

mrml_runtime::mrml_entrypoint!(application_main);
