pub const BUILD_RECEIPT_MAX_BYTES: usize = 4096;

const HEADER: &str = "MRML-BUILD-RECEIPT-v1";
const MAX_VALUE_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildInputIdentity {
    length: u64,
    digest: [u8; 64],
}

impl BuildInputIdentity {
    pub const fn length(self) -> u64 {
        self.length
    }

    pub const fn digest(self) -> [u8; 64] {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildReceiptError {
    Malformed,
    IdentityMismatch,
}

/// Strict, borrowed view of one canonical release build receipt. Receipt data
/// is identity evidence only and grants no authority.
pub struct BuildReceipt<'a> {
    rustc: &'a str,
    cargo: &'a str,
    target: &'a str,
    profile: &'a str,
    inputs: [BuildInputIdentity; 6],
}

impl<'a> BuildReceipt<'a> {
    pub fn decode(input: &'a [u8]) -> Result<Self, BuildReceiptError> {
        if input.len() > BUILD_RECEIPT_MAX_BYTES
            || !input.ends_with(b"\n")
            || input.contains(&b'\r')
        {
            return Err(BuildReceiptError::Malformed);
        }
        let text = core::str::from_utf8(input).map_err(|_| BuildReceiptError::Malformed)?;
        let mut lines = text.lines();
        if lines.next() != Some(HEADER) {
            return Err(BuildReceiptError::Malformed);
        }
        let rustc = parse_value(&mut lines, "rustc")?;
        let cargo = parse_value(&mut lines, "cargo")?;
        let target = parse_value(&mut lines, "target")?;
        let profile = parse_value(&mut lines, "profile")?;
        let mut inputs = [BuildInputIdentity {
            length: 0,
            digest: [0; 64],
        }; 6];
        for (identity, name) in inputs.iter_mut().zip([
            "source-archive",
            "cargo-lock",
            "kernel",
            "service",
            "loader",
            "configuration",
        ]) {
            let length = parse_length(&mut lines, name)?;
            let digest = parse_digest(&mut lines, name)?;
            *identity = BuildInputIdentity { length, digest };
        }
        if lines.next().is_some() {
            return Err(BuildReceiptError::Malformed);
        }
        Ok(Self {
            rustc,
            cargo,
            target,
            profile,
            inputs,
        })
    }

    pub const fn rustc(&self) -> &str {
        self.rustc
    }

    pub const fn cargo(&self) -> &str {
        self.cargo
    }

    pub const fn target(&self) -> &str {
        self.target
    }

    pub const fn profile(&self) -> &str {
        self.profile
    }

    pub const fn source_archive(&self) -> BuildInputIdentity {
        self.inputs[0]
    }

    pub const fn cargo_lock(&self) -> BuildInputIdentity {
        self.inputs[1]
    }

    pub const fn kernel(&self) -> BuildInputIdentity {
        self.inputs[2]
    }

    pub const fn service(&self) -> BuildInputIdentity {
        self.inputs[3]
    }

    pub const fn loader(&self) -> BuildInputIdentity {
        self.inputs[4]
    }

    pub const fn configuration(&self) -> BuildInputIdentity {
        self.inputs[5]
    }

    /// Requires the receipt to describe the release UEFI target and bind the
    /// exact already-authenticated kernel and service payloads. Other receipt
    /// identities remain authenticated declarations for later inspection.
    pub fn validate_uefi_release(
        &self,
        kernel_length: u64,
        kernel_digest: [u8; 64],
        service_length: u64,
        service_digest: [u8; 64],
    ) -> Result<(), BuildReceiptError> {
        if self.target != "x86_64-unknown-uefi"
            || self.profile != "release"
            || self
                .inputs
                .iter()
                .any(|identity| identity.digest.iter().all(|byte| *byte == 0))
            || self.kernel().length != kernel_length
            || self.kernel().digest != kernel_digest
            || self.service().length != service_length
            || self.service().digest != service_digest
        {
            return Err(BuildReceiptError::IdentityMismatch);
        }
        Ok(())
    }
}

fn parse_value<'a>(
    lines: &mut core::str::Lines<'a>,
    name: &str,
) -> Result<&'a str, BuildReceiptError> {
    let line = lines.next().ok_or(BuildReceiptError::Malformed)?;
    let value = line
        .strip_prefix(name)
        .and_then(|suffix| suffix.strip_prefix('='))
        .ok_or(BuildReceiptError::Malformed)?;
    if value.is_empty()
        || value.len() > MAX_VALUE_BYTES
        || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err(BuildReceiptError::Malformed);
    }
    Ok(value)
}

fn parse_length(lines: &mut core::str::Lines<'_>, name: &str) -> Result<u64, BuildReceiptError> {
    let line = lines.next().ok_or(BuildReceiptError::Malformed)?;
    let value = line
        .strip_prefix(name)
        .and_then(|suffix| suffix.strip_prefix(".length="))
        .ok_or(BuildReceiptError::Malformed)?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(BuildReceiptError::Malformed);
    }
    value.parse().map_err(|_| BuildReceiptError::Malformed)
}

fn parse_digest(
    lines: &mut core::str::Lines<'_>,
    name: &str,
) -> Result<[u8; 64], BuildReceiptError> {
    let line = lines.next().ok_or(BuildReceiptError::Malformed)?;
    let value = line
        .strip_prefix(name)
        .and_then(|suffix| suffix.strip_prefix(".sha3-512="))
        .ok_or(BuildReceiptError::Malformed)?;
    if value.len() != 128 {
        return Err(BuildReceiptError::Malformed);
    }
    let bytes = value.as_bytes();
    let mut digest = [0; 64];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = lower_hex(bytes[index * 2])?
            .checked_mul(16)
            .and_then(|high| high.checked_add(lower_hex(bytes[index * 2 + 1]).ok()?))
            .ok_or(BuildReceiptError::Malformed)?;
    }
    Ok(digest)
}

fn lower_hex(byte: u8) -> Result<u8, BuildReceiptError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(BuildReceiptError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    const ZERO_DIGEST: &str = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    fn receipt() -> std::string::String {
        std::format!(
            "{HEADER}\nrustc=rustc fixture\ncargo=cargo fixture\ntarget=x86_64-unknown-uefi\nprofile=release\nsource-archive.length=1\nsource-archive.sha3-512={ZERO_DIGEST}\ncargo-lock.length=2\ncargo-lock.sha3-512={ZERO_DIGEST}\nkernel.length=3\nkernel.sha3-512={ZERO_DIGEST}\nservice.length=4\nservice.sha3-512={ZERO_DIGEST}\nloader.length=5\nloader.sha3-512={ZERO_DIGEST}\nconfiguration.length=0\nconfiguration.sha3-512={ZERO_DIGEST}\n"
        )
    }

    #[test]
    fn canonical_receipt_exposes_exact_ordered_identities() {
        let encoded = receipt();
        let receipt = BuildReceipt::decode(encoded.as_bytes()).unwrap();
        assert_eq!(receipt.target(), "x86_64-unknown-uefi");
        assert_eq!(receipt.profile(), "release");
        assert_eq!(receipt.kernel().length(), 3);
        assert_eq!(receipt.service().length(), 4);
        assert_eq!(receipt.configuration().length(), 0);
    }

    #[test]
    fn uefi_release_validation_binds_exact_authenticated_payloads() {
        let encoded = receipt().replace(ZERO_DIGEST, &"11".repeat(64));
        let receipt = BuildReceipt::decode(encoded.as_bytes()).unwrap();
        assert_eq!(
            receipt.validate_uefi_release(3, [0x11; 64], 4, [0x11; 64]),
            Ok(())
        );
        assert_eq!(
            receipt.validate_uefi_release(3, [0x12; 64], 4, [0x11; 64]),
            Err(BuildReceiptError::IdentityMismatch)
        );
        assert_eq!(
            receipt.validate_uefi_release(3, [0x11; 64], 5, [0x11; 64]),
            Err(BuildReceiptError::IdentityMismatch)
        );
    }

    #[test]
    fn receipt_rejects_ambiguous_fields_digests_and_extensions() {
        let canonical = receipt();
        for malformed in [
            canonical.replace("kernel.length=3", "kernel.length=03"),
            canonical.replace("kernel.sha3-512=0", "kernel.sha3-512=A"),
            canonical.replace("profile=release", "profile=release\r"),
            std::format!("{canonical}extra=value\n"),
            canonical.trim_end().into(),
        ] {
            assert_eq!(
                BuildReceipt::decode(malformed.as_bytes()).err(),
                Some(BuildReceiptError::Malformed)
            );
        }
    }
}
