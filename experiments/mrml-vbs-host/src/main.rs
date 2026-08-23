#![no_std]
#![no_main]

use mrml_error::{Result, anyhow};
#[cfg(windows)]
use mrml_kernel::{
    AUTHORITY_RECEIPT_BYTES, AuthorityReceipt, LAUNCH_REQUEST_BYTES, LaunchRequest,
    ProtectionBackend, ProtectionPolicy, ProtectionSession, VBS_ATTESTATION_CHALLENGE_BYTES,
    VBS_ATTESTATION_DATA_BYTES, VBS_ATTESTATION_ENVELOPE_BYTES, VBS_AUTHORITY_CONTEXT_BYTES,
    VbsAttestationData, VbsAttestationEnvelope, VbsAuthorityContext, VbsAuthorityOperation,
};
#[cfg(windows)]
use mrml_runtime::{Vector, mrml_println, read_file_bounded};

#[cfg(windows)]
const MAX_ENCLAVE_IMAGE_BYTES: usize = 16 * 1024 * 1024;
#[cfg(windows)]
const AUTHORITY_KEY: [u8; 32] = [0x39; 32];
#[cfg(windows)]
const AUTHORITY_MEASUREMENT: [u8; 64] = [0x51; 64];
#[cfg(windows)]
const _: () = assert!(VBS_AUTHORITY_CONTEXT_BYTES == mrml_windows::VBS_AUTHORITY_CONTEXT_BYTES);

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

    let mut verifier = mrml_windows::VbsEnclaveReservation::reserve([0; 32])
        .map_err(|error| anyhow!("verifier CreateEnclave failed: {:?}", error))?;
    verifier
        .load_image_wide(&wide)
        .map_err(|error| anyhow!("verifier LoadEnclaveImageW failed: {:?}", error))?;
    let verifier_threads = verifier
        .initialize(1)
        .map_err(|error| anyhow!("verifier InitializeEnclave failed: {:?}", error))?;
    mrml_println!(
        "initialized independent verifier VBS enclave with {} thread(s)",
        verifier_threads
    );

    let mut host_nonce = [0; 32];
    mrml_runtime::fill_random(&mut host_nonce)
        .map_err(|_| anyhow!("cryptographic nonce generation failed"))?;
    let policy = ProtectionPolicy::new(
        ProtectionBackend::VbsEnclave,
        ProtectionBackend::VbsEnclave.maximum_claims(),
        false,
        1,
        AUTHORITY_MEASUREMENT,
    );
    let policy_measurement = policy.commitment();
    let seed_request = LaunchRequest::new(1, host_nonce, AUTHORITY_MEASUREMENT, policy_measurement)
        .map_err(|error| anyhow!("challenge seed request rejected: {:?}", error))?;
    let encoded_seed = seed_request.encode();
    let mut nonce = [0; VBS_ATTESTATION_CHALLENGE_BYTES];
    let challenge_context = VbsAuthorityContext::new(
        VbsAuthorityOperation::GenerateAttestationChallenge,
        encoded_seed.as_ptr() as usize as u64,
        encoded_seed.len() as u64,
        nonce.as_mut_ptr() as usize as u64,
        nonce.len() as u64,
    )
    .map_err(|error| anyhow!("challenge context rejected: {:?}", error))?;
    let mut challenge_call = challenge_context.encode();
    let challenge_status = verifier
        .call_authority(authority, &mut challenge_call)
        .map_err(|error| anyhow!("verifier challenge CallEnclave failed: {:?}", error))?;
    if challenge_status != 0 || nonce == [0; VBS_ATTESTATION_CHALLENGE_BYTES] {
        return Err(anyhow!(
            "VTL1 verifier rejected challenge generation with status {}",
            challenge_status
        ));
    }
    let request = LaunchRequest::new(1, nonce, AUTHORITY_MEASUREMENT, policy_measurement)
        .map_err(|error| anyhow!("launch request rejected: {:?}", error))?;
    let encoded_request: [u8; LAUNCH_REQUEST_BYTES] = request.encode();
    let mut receipt = [0; AUTHORITY_RECEIPT_BYTES];
    let context = VbsAuthorityContext::new(
        VbsAuthorityOperation::IssueReceipt,
        encoded_request.as_ptr() as usize as u64,
        encoded_request.len() as u64,
        receipt.as_mut_ptr() as usize as u64,
        receipt.len() as u64,
    )
    .map_err(|error| anyhow!("authority context rejected: {:?}", error))?;
    let mut call = context.encode();
    let authority_status = enclave
        .call_authority(authority, &mut call)
        .map_err(|error| anyhow!("CallEnclave failed: {:?}", error))?;
    if authority_status != 0 {
        return Err(anyhow!(
            "VTL1 launch authority rejected request with status {}",
            authority_status
        ));
    }
    let mut session = ProtectionSession::new(nonce)
        .map_err(|error| anyhow!("protection session rejected: {:?}", error))?;
    let admitted = AuthorityReceipt::verify_and_admit(
        &AUTHORITY_KEY,
        request,
        &receipt,
        policy_measurement,
        &mut session,
        policy,
    )
    .map_err(|error| anyhow!("authority receipt admission failed: {:?}", error))?;
    mrml_println!(
        "verified VTL1 authority receipt: source={:?} backend={:?} claims={:?}",
        admitted.evidence_source(),
        admitted.backend(),
        admitted.claims()
    );

    let mut attestation = Vector::with_capacity(VBS_ATTESTATION_ENVELOPE_BYTES)
        .map_err(|_| anyhow!("failed to allocate bounded attestation envelope"))?;
    attestation
        .try_resize(VBS_ATTESTATION_ENVELOPE_BYTES, 0)
        .map_err(|_| anyhow!("failed to initialize bounded attestation envelope"))?;
    let context = VbsAuthorityContext::new(
        VbsAuthorityOperation::IssueAttestationReport,
        encoded_request.as_ptr() as usize as u64,
        encoded_request.len() as u64,
        attestation.as_mut_ptr() as usize as u64,
        attestation.len() as u64,
    )
    .map_err(|error| anyhow!("attestation context rejected: {:?}", error))?;
    let mut call = context.encode();
    let attestation_status = enclave
        .call_authority(authority, &mut call)
        .map_err(|error| anyhow!("attestation CallEnclave failed: {:?}", error))?;
    if attestation_status != 0 {
        return Err(anyhow!(
            "VTL1 authority rejected attestation request with status {}",
            attestation_status
        ));
    }
    let report = VbsAttestationEnvelope::decode(&attestation)
        .map_err(|error| anyhow!("malformed attestation envelope: {:?}", error))?;
    mrml_println!(
        "transported {} byte local VBS attestation report for independent enclave verification",
        report.report().len()
    );
    let mut verified_binding = [0; VBS_ATTESTATION_DATA_BYTES];
    let verify_context = VbsAuthorityContext::new(
        VbsAuthorityOperation::VerifyAttestationReport,
        attestation.as_ptr() as usize as u64,
        attestation.len() as u64,
        verified_binding.as_mut_ptr() as usize as u64,
        verified_binding.len() as u64,
    )
    .map_err(|error| anyhow!("verifier context rejected: {:?}", error))?;
    let mut verify_call = verify_context.encode();
    let verify_status = verifier
        .call_authority(authority, &mut verify_call)
        .map_err(|error| anyhow!("verifier CallEnclave failed: {:?}", error))?;
    if verify_status != 0 {
        return Err(anyhow!(
            "independent VTL1 verifier rejected authority report with status {}",
            verify_status
        ));
    }
    let verified_binding = VbsAttestationData::decode(&verified_binding)
        .map_err(|error| anyhow!("verifier returned malformed binding: {:?}", error))?;
    let expected_binding = VbsAttestationData::for_policy(nonce, policy)
        .map_err(|error| anyhow!("expected binding rejected: {:?}", error))?;
    if verified_binding != expected_binding {
        return Err(anyhow!("verifier returned an unexpected authority binding"));
    }
    mrml_println!(
        "independent VTL1 enclave verified authority code identity, policy, and fresh challenge"
    );
    Ok(())
}

#[cfg(not(windows))]
fn application_main() -> Result<()> {
    Err(anyhow!("VBS enclaves require Windows"))
}

mrml_runtime::mrml_entrypoint!(application_main);
