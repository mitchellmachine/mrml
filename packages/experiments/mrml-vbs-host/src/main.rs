#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

use mrml_error::{Result, anyhow};
#[cfg(windows)]
use mrml_kernel::{
    AUTHORITY_RECEIPT_BYTES, LAUNCH_REQUEST_BYTES, LaunchRequest, ProtectionBackend,
    ProtectionPolicy, VBS_ATTESTATION_CHALLENGE_BYTES, VBS_ATTESTATION_DATA_BYTES,
    VBS_ATTESTATION_ENVELOPE_BYTES, VBS_AUTHORITY_CONTEXT_BYTES,
    VBS_RECEIPT_VERIFICATION_INPUT_BYTES, VBS_SEALED_KEY_CONFIRMATION_BYTES,
    VBS_SEALED_KEY_ENVELOPE_BYTES, VBS_WORKLOAD_CHALLENGE_BYTES, VBS_WORKLOAD_RESULT_BYTES,
    VBS_WORKLOAD_SECRET_REQUEST_BYTES, VbsAttestationData, VbsAttestationEnvelope,
    VbsAuthorityContext, VbsAuthorityOperation, VbsSealedKeyEnvelope,
};
#[cfg(windows)]
use mrml_runtime::{Vector, mrml_println, read_file_bounded};
#[cfg(windows)]
use mrml_whp::UntrustedLaunchBroker;

#[cfg(windows)]
const MAX_ENCLAVE_IMAGE_BYTES: usize = 16 * 1024 * 1024;
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
    let boundary_probe = mrml_windows::vbs_enclave_export_rva(&image, b"mrml_authority_probe")
        .map_err(|error| anyhow!("invalid boundary-probe export: {:?}", error))?;
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
    let mut probe_context = [0; VBS_AUTHORITY_CONTEXT_BYTES];
    let probe_input = probe_context.as_mut_ptr() as usize;
    let probe_result = verifier
        .call_authority(boundary_probe, c"mrml_authority_probe", &mut probe_context)
        .map_err(|error| anyhow!("boundary-probe CallEnclave failed: {:?}", error))?;
    if probe_result != (probe_input ^ 0x4d52_4d4c) {
        return Err(anyhow!(
            "boundary-probe result was not bound to its context"
        ));
    }
    mrml_println!("VTL1 boundary probe returned the exact context-bound result");

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
        .call_authority(authority, c"mrml_launch_authority", &mut challenge_call)
        .map_err(|error| anyhow!("verifier challenge CallEnclave failed: {:?}", error))?;
    if challenge_status != 0 || nonce == [0; VBS_ATTESTATION_CHALLENGE_BYTES] {
        return Err(anyhow!(
            "VTL1 verifier rejected challenge generation with status {}",
            challenge_status
        ));
    }
    let request = LaunchRequest::new(1, nonce, AUTHORITY_MEASUREMENT, policy_measurement)
        .map_err(|error| anyhow!("launch request rejected: {:?}", error))?;
    let mut broker = UntrustedLaunchBroker::<1>::new();
    let ticket = broker
        .submit(request)
        .map_err(|error| anyhow!("WHP broker rejected request: {:?}", error))?;
    let encoded_request: [u8; LAUNCH_REQUEST_BYTES] = request.encode();
    let mut workload_secret = [0; VBS_SEALED_KEY_ENVELOPE_BYTES];
    let workload_key_context = VbsAuthorityContext::new(
        VbsAuthorityOperation::GenerateWorkloadSecret,
        encoded_request.as_ptr() as usize as u64,
        encoded_request.len() as u64,
        workload_secret.as_mut_ptr() as usize as u64,
        workload_secret.len() as u64,
    )
    .map_err(|error| anyhow!("workload-secret context rejected: {:?}", error))?;
    let mut workload_key_call = workload_key_context.encode();
    let workload_key_status = enclave
        .call_authority(authority, c"mrml_launch_authority", &mut workload_key_call)
        .map_err(|error| anyhow!("workload-secret CallEnclave failed: {:?}", error))?;
    if workload_key_status != 0 || VbsSealedKeyEnvelope::decode(&workload_secret).is_err() {
        return Err(anyhow!(
            "VTL1 authority rejected workload-secret generation with status {}",
            workload_key_status
        ));
    }
    let mut sealed_key = [0; VBS_SEALED_KEY_ENVELOPE_BYTES];
    let key_context = VbsAuthorityContext::new(
        VbsAuthorityOperation::GenerateSealedKey,
        encoded_request.as_ptr() as usize as u64,
        encoded_request.len() as u64,
        sealed_key.as_mut_ptr() as usize as u64,
        sealed_key.len() as u64,
    )
    .map_err(|error| anyhow!("sealed-key context rejected: {:?}", error))?;
    let mut key_call = key_context.encode();
    let key_status = enclave
        .call_authority(authority, c"mrml_launch_authority", &mut key_call)
        .map_err(|error| anyhow!("sealed-key CallEnclave failed: {:?}", error))?;
    if key_status != 0 || VbsSealedKeyEnvelope::decode(&sealed_key).is_err() {
        return Err(anyhow!(
            "VTL1 authority rejected sealed-key generation with status {}",
            key_status
        ));
    }
    let mut key_confirmation = [0; VBS_SEALED_KEY_CONFIRMATION_BYTES];
    let load_context = VbsAuthorityContext::new(
        VbsAuthorityOperation::LoadSealedKey,
        sealed_key.as_ptr() as usize as u64,
        sealed_key.len() as u64,
        key_confirmation.as_mut_ptr() as usize as u64,
        key_confirmation.len() as u64,
    )
    .map_err(|error| anyhow!("sealed-key load context rejected: {:?}", error))?;
    let mut load_call = load_context.encode();
    let load_status = verifier
        .call_authority(authority, c"mrml_launch_authority", &mut load_call)
        .map_err(|error| anyhow!("sealed-key load CallEnclave failed: {:?}", error))?;
    if load_status != 0 || key_confirmation != [0xa5; VBS_SEALED_KEY_CONFIRMATION_BYTES] {
        return Err(anyhow!(
            "VTL1 verifier rejected sealed-key loading with status {}",
            load_status
        ));
    }
    let mut broker_receipt = [0; AUTHORITY_RECEIPT_BYTES];
    let context = {
        let broker_request = broker
            .authority_request(ticket)
            .map_err(|error| anyhow!("WHP broker lost pending request: {:?}", error))?;
        VbsAuthorityContext::new(
            VbsAuthorityOperation::IssueReceipt,
            broker_request.as_ptr() as usize as u64,
            broker_request.len() as u64,
            broker_receipt.as_mut_ptr() as usize as u64,
            broker_receipt.len() as u64,
        )
        .map_err(|error| anyhow!("authority context rejected: {:?}", error))?
    };
    let mut call = context.encode();
    let authority_status = enclave
        .call_authority(authority, c"mrml_launch_authority", &mut call)
        .map_err(|error| anyhow!("CallEnclave failed: {:?}", error))?;
    if authority_status != 0 {
        return Err(anyhow!(
            "VTL1 launch authority rejected request with status {}",
            authority_status
        ));
    }
    broker
        .publish_receipt(ticket, &broker_receipt)
        .map_err(|error| anyhow!("WHP broker rejected receipt: {:?}", error))?;
    let mut transported_request = [0; LAUNCH_REQUEST_BYTES];
    let mut transported_receipt = [0; AUTHORITY_RECEIPT_BYTES];
    broker
        .take_exchange(ticket, &mut transported_request, &mut transported_receipt)
        .map_err(|error| anyhow!("WHP broker exchange failed: {:?}", error))?;
    let mut verification_input = [0; VBS_RECEIPT_VERIFICATION_INPUT_BYTES];
    verification_input[..LAUNCH_REQUEST_BYTES].copy_from_slice(&transported_request);
    verification_input[LAUNCH_REQUEST_BYTES..].copy_from_slice(&transported_receipt);
    let mut receipt_confirmation = [0; VBS_SEALED_KEY_CONFIRMATION_BYTES];
    let receipt_context = VbsAuthorityContext::new(
        VbsAuthorityOperation::VerifyReceipt,
        verification_input.as_ptr() as usize as u64,
        verification_input.len() as u64,
        receipt_confirmation.as_mut_ptr() as usize as u64,
        receipt_confirmation.len() as u64,
    )
    .map_err(|error| anyhow!("receipt verifier context rejected: {:?}", error))?;
    let mut receipt_call = receipt_context.encode();
    let receipt_status = verifier
        .call_authority(authority, c"mrml_launch_authority", &mut receipt_call)
        .map_err(|error| anyhow!("receipt verifier CallEnclave failed: {:?}", error))?;
    if receipt_status != 0 || receipt_confirmation != [0x5a; VBS_SEALED_KEY_CONFIRMATION_BYTES] {
        return Err(anyhow!(
            "VTL1 verifier rejected authority receipt with status {}",
            receipt_status
        ));
    }
    mrml_println!("independent VTL1 enclave authenticated the exact authority receipt");

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
        .call_authority(authority, c"mrml_launch_authority", &mut call)
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
        .call_authority(authority, c"mrml_launch_authority", &mut verify_call)
        .map_err(|error| anyhow!("verifier CallEnclave failed: {:?}", error))?;
    if verify_status != 0 {
        return Err(anyhow!(
            "independent VTL1 verifier rejected authority report with status {}",
            verify_status
        ));
    }
    let verified_binding = VbsAttestationData::decode(&verified_binding)
        .map_err(|error| anyhow!("verifier returned malformed binding: {:?}", error))?;
    let expected_binding = VbsAttestationData::for_launch_request(nonce, request, policy)
        .map_err(|error| anyhow!("expected binding rejected: {:?}", error))?;
    if verified_binding != expected_binding {
        return Err(anyhow!("verifier returned an unexpected authority binding"));
    }
    mrml_println!(
        "independent VTL1 enclave verified authority code identity, policy, and fresh challenge"
    );
    let mut workload_challenge = [0; VBS_WORKLOAD_CHALLENGE_BYTES];
    mrml_runtime::fill_random(&mut workload_challenge)
        .map_err(|_| anyhow!("workload challenge generation failed"))?;
    let mut consume_input = [0; VBS_WORKLOAD_SECRET_REQUEST_BYTES];
    consume_input[..LAUNCH_REQUEST_BYTES].copy_from_slice(&encoded_request);
    let envelope_end = LAUNCH_REQUEST_BYTES + VBS_SEALED_KEY_ENVELOPE_BYTES;
    consume_input[LAUNCH_REQUEST_BYTES..envelope_end].copy_from_slice(&workload_secret);
    consume_input[envelope_end..].copy_from_slice(&workload_challenge);
    let mut workload_result = [0; VBS_WORKLOAD_RESULT_BYTES];
    let consume_context = VbsAuthorityContext::new(
        VbsAuthorityOperation::ConsumeWorkloadSecret,
        consume_input.as_ptr() as usize as u64,
        consume_input.len() as u64,
        workload_result.as_mut_ptr() as usize as u64,
        workload_result.len() as u64,
    )
    .map_err(|error| anyhow!("workload consumption context rejected: {:?}", error))?;
    let mut consume_call = consume_context.encode();
    let consume_status = verifier
        .call_authority(authority, c"mrml_launch_authority", &mut consume_call)
        .map_err(|error| anyhow!("workload consumption CallEnclave failed: {:?}", error))?;
    if consume_status != 0 || workload_result == [0; VBS_WORKLOAD_RESULT_BYTES] {
        return Err(anyhow!(
            "VTL1 verifier rejected workload-secret consumption with status {}",
            consume_status
        ));
    }
    mrml_println!(
        "VTL1 consumed a sealed workload secret after receipt and code-attestation gates"
    );
    Ok(())
}

#[cfg(not(windows))]
fn application_main() -> Result<()> {
    Err(anyhow!("VBS enclaves require Windows"))
}

mrml_runtime::mrml_entrypoint!(application_main);
