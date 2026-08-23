#![no_std]
#![no_main]

use mrml_error::{Result, anyhow};
#[cfg(windows)]
use mrml_runtime::{Vector, mrml_println};

#[cfg(windows)]
fn application_main() -> Result<()> {
    let arguments = mrml_runtime::command_arguments();
    if arguments.len() != 2 {
        return Err(anyhow!("usage: mrml-vbs-host ENCLAVE.dll"));
    }
    let path = arguments[1].as_str();
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
    Ok(())
}

#[cfg(not(windows))]
fn application_main() -> Result<()> {
    Err(anyhow!("VBS enclaves require Windows"))
}

mrml_runtime::mrml_entrypoint!(application_main);
