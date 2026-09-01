use mrml_crypto::rsa_pkcs1_sha256_verify;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateError {
    Malformed,
    UnsupportedAlgorithm,
    InvalidSignature,
    HostnameMismatch,
    NotCertificateAuthority,
    InvalidPurpose,
    NotYetValid,
    Expired,
    ClockUnavailable,
    TrustStoreUnavailable,
    UntrustedIssuer,
    UnsupportedCriticalExtension,
    PathLengthExceeded,
    OcspMissing,
    OcspMalformed,
    OcspUnknown,
    Revoked,
    OcspStale,
}

#[derive(Clone, Copy)]
struct Element<'a> {
    tag: u8,
    value: &'a [u8],
    encoded: &'a [u8],
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn next(&mut self) -> Result<Element<'a>, CertificateError> {
        let start = self.position;
        let tag = *self
            .bytes
            .get(self.position)
            .ok_or(CertificateError::Malformed)?;
        self.position += 1;
        let first = *self
            .bytes
            .get(self.position)
            .ok_or(CertificateError::Malformed)?;
        self.position += 1;
        let length = if first & 0x80 == 0 {
            first as usize
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0
                || count > core::mem::size_of::<usize>()
                || self.position + count > self.bytes.len()
            {
                return Err(CertificateError::Malformed);
            }
            if self.bytes[self.position] == 0 {
                return Err(CertificateError::Malformed);
            }
            let mut value = 0usize;
            for byte in &self.bytes[self.position..self.position + count] {
                value = value
                    .checked_mul(256)
                    .and_then(|v| v.checked_add(*byte as usize))
                    .ok_or(CertificateError::Malformed)?;
            }
            self.position += count;
            if value < 128 {
                return Err(CertificateError::Malformed);
            }
            value
        };
        let end = self
            .position
            .checked_add(length)
            .ok_or(CertificateError::Malformed)?;
        if end > self.bytes.len() {
            return Err(CertificateError::Malformed);
        }
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(Element {
            tag,
            value,
            encoded: &self.bytes[start..end],
        })
    }
    fn finish(self) -> Result<(), CertificateError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(CertificateError::Malformed)
        }
    }
}

const SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const SHA256_WITH_ECDSA: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const SHA384_WITH_ECDSA: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const SECP384R1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const OCSP_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];
const ANY_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25, 0x00];

fn algorithm(element: Element<'_>, expected: &[u8]) -> Result<(), CertificateError> {
    if element.tag != 0x30 {
        return Err(CertificateError::Malformed);
    }
    let mut reader = Reader::new(element.value);
    let oid = reader.next()?;
    if oid.tag != 0x06 || oid.value != expected {
        return Err(CertificateError::UnsupportedAlgorithm);
    }
    if reader.position < reader.bytes.len() {
        let parameter = reader.next()?;
        if parameter.tag != 0x05 || !parameter.value.is_empty() {
            return Err(CertificateError::Malformed);
        }
    }
    reader.finish()
}

pub struct Certificate<'a> {
    tbs: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    spki: &'a [u8],
    public_key_bits: &'a [u8],
    public_key: PublicKey<'a>,
    signature_algorithm: SignatureAlgorithm,
    signature: &'a [u8],
    extensions: &'a [u8],
    not_before: u64,
    not_after: u64,
    serial: &'a [u8],
}

#[derive(Clone, Copy)]
enum PublicKey<'a> {
    Rsa {
        modulus: &'a [u8],
        exponent: &'a [u8],
    },
    P256(&'a [u8]),
    P384(&'a [u8]),
}

#[derive(Clone, Copy)]
enum SignatureAlgorithm {
    RsaSha256,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
}

impl<'a> Certificate<'a> {
    /// SHA-256 of the complete DER SubjectPublicKeyInfo, as used by CRLSets.
    pub fn spki_sha256(&self) -> [u8; 32] {
        mrml_crypto::Sha256::digest(self.spki)
    }

    pub(crate) fn verify_tls_pss(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CertificateError> {
        let PublicKey::Rsa { modulus, exponent } = self.public_key else {
            return Err(CertificateError::UnsupportedAlgorithm);
        };
        mrml_crypto::rsa_pss_sha256_verify(modulus, exponent, message, signature)
            .map_err(|_| CertificateError::InvalidSignature)
    }
    pub(crate) fn verify_tls_ecdsa(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CertificateError> {
        let PublicKey::P256(point) = self.public_key else {
            return Err(CertificateError::UnsupportedAlgorithm);
        };
        mrml_crypto::ecdsa_p256_sha256_verify(point, message, signature)
            .map_err(|_| CertificateError::InvalidSignature)
    }
    pub(crate) fn verify_tls_ecdsa_p384(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CertificateError> {
        let PublicKey::P384(point) = self.public_key else {
            return Err(CertificateError::UnsupportedAlgorithm);
        };
        mrml_crypto::ecdsa_p384_sha384_verify(point, message, signature)
            .map_err(|_| CertificateError::InvalidSignature)
    }
    pub fn parse(der: &'a [u8]) -> Result<Self, CertificateError> {
        let mut outer = Reader::new(der);
        let certificate = outer.next()?;
        outer.finish()?;
        if certificate.tag != 0x30 {
            return Err(CertificateError::Malformed);
        }
        let mut fields = Reader::new(certificate.value);
        let tbs = fields.next()?;
        let signature_algorithm = fields.next()?;
        let signature = fields.next()?;
        fields.finish()?;
        if tbs.tag != 0x30 || signature.tag != 0x03 || signature.value.first() != Some(&0) {
            return Err(CertificateError::Malformed);
        }
        let signature_algorithm = if algorithm(signature_algorithm, SHA256_WITH_RSA).is_ok() {
            SignatureAlgorithm::RsaSha256
        } else if algorithm(signature_algorithm, SHA256_WITH_ECDSA).is_ok() {
            SignatureAlgorithm::EcdsaP256Sha256
        } else if algorithm(signature_algorithm, SHA384_WITH_ECDSA).is_ok() {
            SignatureAlgorithm::EcdsaP384Sha384
        } else {
            return Err(CertificateError::UnsupportedAlgorithm);
        };
        let mut body = Reader::new(tbs.value);
        let first = body.next()?;
        if first.tag != 0xa0 {
            return Err(CertificateError::Malformed);
        }
        let serial = body.next()?;
        if serial.tag != 0x02 || serial.value.is_empty() {
            return Err(CertificateError::Malformed);
        }
        let tbs_signature = body.next()?;
        match signature_algorithm {
            SignatureAlgorithm::RsaSha256 => algorithm(tbs_signature, SHA256_WITH_RSA)?,
            SignatureAlgorithm::EcdsaP256Sha256 => algorithm(tbs_signature, SHA256_WITH_ECDSA)?,
            SignatureAlgorithm::EcdsaP384Sha384 => algorithm(tbs_signature, SHA384_WITH_ECDSA)?,
        }
        let issuer = body.next()?;
        if issuer.tag != 0x30 {
            return Err(CertificateError::Malformed);
        }
        let validity = body.next()?;
        if validity.tag != 0x30 {
            return Err(CertificateError::Malformed);
        }
        let mut times = Reader::new(validity.value);
        let not_before = certificate_time(times.next()?)?;
        let not_after = certificate_time(times.next()?)?;
        times.finish()?;
        if not_after < not_before {
            return Err(CertificateError::Malformed);
        }
        let subject = body.next()?;
        if subject.tag != 0x30 {
            return Err(CertificateError::Malformed);
        }
        let spki = body.next()?;
        if spki.tag != 0x30 {
            return Err(CertificateError::Malformed);
        }
        let mut public = Reader::new(spki.value);
        let public_algorithm = public.next()?;
        let bits = public.next()?;
        public.finish()?;
        if bits.tag != 0x03 || bits.value.first() != Some(&0) {
            return Err(CertificateError::Malformed);
        }
        let public_key = if algorithm(public_algorithm, RSA_ENCRYPTION).is_ok() {
            let mut key_outer = Reader::new(&bits.value[1..]);
            let key = key_outer.next()?;
            key_outer.finish()?;
            if key.tag != 0x30 {
                return Err(CertificateError::Malformed);
            }
            let mut key_fields = Reader::new(key.value);
            let modulus = key_fields.next()?;
            let exponent = key_fields.next()?;
            key_fields.finish()?;
            if modulus.tag != 0x02 || exponent.tag != 0x02 {
                return Err(CertificateError::Malformed);
            }
            let modulus = modulus.value.strip_prefix(&[0]).unwrap_or(modulus.value);
            let exponent = exponent.value.strip_prefix(&[0]).unwrap_or(exponent.value);
            if !(256..=512).contains(&modulus.len())
                || exponent.is_empty()
                || exponent.len() > 8
                || exponent.last().is_none_or(|value| value & 1 == 0)
            {
                return Err(CertificateError::UnsupportedAlgorithm);
            }
            PublicKey::Rsa { modulus, exponent }
        } else {
            let mut parameters = Reader::new(public_algorithm.value);
            let oid = parameters.next()?;
            let curve = parameters.next()?;
            parameters.finish()?;
            if oid.tag != 0x06 || oid.value != EC_PUBLIC_KEY || curve.tag != 0x06 {
                return Err(CertificateError::UnsupportedAlgorithm);
            }
            if curve.value == PRIME256V1 && bits.value.len() == 66 && bits.value[1] == 4 {
                PublicKey::P256(&bits.value[1..])
            } else if curve.value == SECP384R1 && bits.value.len() == 98 && bits.value[1] == 4 {
                PublicKey::P384(&bits.value[1..])
            } else {
                return Err(CertificateError::UnsupportedAlgorithm);
            }
        };
        let mut extensions = &[][..];
        while body.position < body.bytes.len() {
            let element = body.next()?;
            if element.tag == 0xa3 {
                extensions = element.value;
            } else if element.tag != 0x81 && element.tag != 0x82 {
                return Err(CertificateError::Malformed);
            }
        }
        validate_extensions(extensions)?;
        Ok(Self {
            tbs: tbs.encoded,
            issuer: issuer.encoded,
            subject: subject.encoded,
            spki: spki.encoded,
            public_key_bits: &bits.value[1..],
            public_key,
            signature_algorithm,
            signature: &signature.value[1..],
            extensions,
            not_before,
            not_after,
            serial: serial.value,
        })
    }

    pub fn verify_signed_by(&self, issuer: &Certificate<'_>) -> Result<(), CertificateError> {
        match (self.signature_algorithm, issuer.public_key) {
            (SignatureAlgorithm::RsaSha256, PublicKey::Rsa { modulus, exponent }) => {
                rsa_pkcs1_sha256_verify(modulus, exponent, self.tbs, self.signature)
                    .map_err(|_| CertificateError::InvalidSignature)
            }
            (SignatureAlgorithm::EcdsaP256Sha256, PublicKey::P256(point)) => {
                mrml_crypto::ecdsa_p256_sha256_verify(point, self.tbs, self.signature)
                    .map_err(|_| CertificateError::InvalidSignature)
            }
            (SignatureAlgorithm::EcdsaP384Sha384, PublicKey::P384(point)) => {
                mrml_crypto::ecdsa_p384_sha384_verify(point, self.tbs, self.signature)
                    .map_err(|_| CertificateError::InvalidSignature)
            }
            _ => Err(CertificateError::UnsupportedAlgorithm),
        }
    }

    pub(crate) fn same_trust_identity(&self, other: &Certificate<'_>) -> bool {
        self.subject == other.subject && self.spki == other.spki
    }

    /// The DER INTEGER contents of the certificate serial number.
    pub fn serial(&self) -> &'a [u8] {
        self.serial
    }

    pub(crate) fn subject_name_der(&self) -> &'a [u8] {
        self.subject
    }

    pub(crate) fn issuer_name_der(&self) -> &'a [u8] {
        self.issuer
    }

    pub(crate) fn subject_public_key_bits(&self) -> &'a [u8] {
        self.public_key_bits
    }

    pub(crate) fn verify_pkcs1_sha256(
        &self,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), CertificateError> {
        let PublicKey::Rsa { modulus, exponent } = self.public_key else {
            return Err(CertificateError::UnsupportedAlgorithm);
        };
        rsa_pkcs1_sha256_verify(modulus, exponent, data, signature)
            .map_err(|_| CertificateError::InvalidSignature)
    }

    fn extension(&self, wanted: &[u8]) -> Result<Option<&'a [u8]>, CertificateError> {
        if self.extensions.is_empty() {
            return Ok(None);
        }
        let mut wrapper = Reader::new(self.extensions);
        let sequence = wrapper.next()?;
        wrapper.finish()?;
        if sequence.tag != 0x30 {
            return Err(CertificateError::Malformed);
        }
        let mut entries = Reader::new(sequence.value);
        while entries.position < entries.bytes.len() {
            let entry = entries.next()?;
            if entry.tag != 0x30 {
                return Err(CertificateError::Malformed);
            }
            let mut fields = Reader::new(entry.value);
            let oid = fields.next()?;
            if oid.tag != 0x06 {
                return Err(CertificateError::Malformed);
            }
            let mut value = fields.next()?;
            if value.tag == 0x01 {
                if value.value != [0xff] {
                    return Err(CertificateError::Malformed);
                }
                value = fields.next()?;
            }
            fields.finish()?;
            if value.tag != 0x04 {
                return Err(CertificateError::Malformed);
            }
            if oid.value == wanted {
                return Ok(Some(value.value));
            }
        }
        Ok(None)
    }

    pub fn require_ca(&self) -> Result<(), CertificateError> {
        let (ca, _) = self
            .basic_constraints()?
            .ok_or(CertificateError::NotCertificateAuthority)?;
        if ca {
            Ok(())
        } else {
            Err(CertificateError::NotCertificateAuthority)
        }
    }

    fn basic_constraints(&self) -> Result<Option<(bool, Option<u32>)>, CertificateError> {
        let Some(value) = self.extension(BASIC_CONSTRAINTS)? else {
            return Ok(None);
        };
        let mut outer = Reader::new(value);
        let sequence = outer.next()?;
        outer.finish()?;
        if sequence.tag != 0x30 {
            return Err(CertificateError::Malformed);
        }
        let mut fields = Reader::new(sequence.value);
        if fields.position == fields.bytes.len() {
            return Ok(Some((false, None)));
        }
        let ca = fields.next()?;
        if ca.tag != 0x01 || ca.value.len() != 1 || !matches!(ca.value[0], 0 | 0xff) {
            return Err(CertificateError::Malformed);
        }
        let path_length = if fields.position < fields.bytes.len() {
            Some(nonnegative_u32(fields.next()?)?)
        } else {
            None
        };
        fields.finish()?;
        if ca.value[0] == 0 && path_length.is_some() {
            return Err(CertificateError::Malformed);
        }
        Ok(Some((ca.value[0] == 0xff, path_length)))
    }

    pub(crate) fn enforce_ca_path_length(
        &self,
        subordinate_ca_count: usize,
    ) -> Result<(), CertificateError> {
        let (ca, path_length) = self
            .basic_constraints()?
            .ok_or(CertificateError::NotCertificateAuthority)?;
        if !ca {
            return Err(CertificateError::NotCertificateAuthority);
        }
        if path_length.is_some_and(|limit| subordinate_ca_count > limit as usize) {
            return Err(CertificateError::PathLengthExceeded);
        }
        Ok(())
    }

    fn require_usage_bit(&self, bit: usize) -> Result<(), CertificateError> {
        let Some(value) = self.extension(KEY_USAGE)? else {
            return Ok(());
        };
        let mut outer = Reader::new(value);
        let usage = outer.next()?;
        outer.finish()?;
        if usage.tag != 0x03 || usage.value.len() < 2 || usage.value[0] > 7 {
            return Err(CertificateError::Malformed);
        }
        let byte = bit / 8 + 1;
        let mask = 0x80 >> (bit & 7);
        if usage.value.get(byte).is_some_and(|value| value & mask != 0) {
            Ok(())
        } else {
            Err(CertificateError::InvalidPurpose)
        }
    }

    pub fn require_certificate_signing(&self) -> Result<(), CertificateError> {
        self.require_ca()?;
        self.require_usage_bit(5)
    }

    pub fn require_server_auth(&self) -> Result<(), CertificateError> {
        self.require_usage_bit(0)?;
        match self.require_ca() {
            Ok(()) => return Err(CertificateError::InvalidPurpose),
            Err(CertificateError::NotCertificateAuthority) => {}
            Err(error) => return Err(error),
        }
        let Some(value) = self.extension(EXTENDED_KEY_USAGE)? else {
            return Ok(());
        };
        let mut outer = Reader::new(value);
        let sequence = outer.next()?;
        outer.finish()?;
        if sequence.tag != 0x30 {
            return Err(CertificateError::Malformed);
        }
        let mut usages = Reader::new(sequence.value);
        while usages.position < usages.bytes.len() {
            let usage = usages.next()?;
            if usage.tag != 0x06 {
                return Err(CertificateError::Malformed);
            }
            if usage.value == SERVER_AUTH || usage.value == ANY_EXTENDED_KEY_USAGE {
                return Ok(());
            }
        }
        Err(CertificateError::InvalidPurpose)
    }

    pub(crate) fn require_ocsp_signing(&self) -> Result<(), CertificateError> {
        self.require_usage_bit(0)?;
        match self.require_ca() {
            Ok(()) => return Err(CertificateError::InvalidPurpose),
            Err(CertificateError::NotCertificateAuthority) => {}
            Err(error) => return Err(error),
        }
        let value = self
            .extension(EXTENDED_KEY_USAGE)?
            .ok_or(CertificateError::InvalidPurpose)?;
        let mut outer = Reader::new(value);
        let sequence = outer.next()?;
        outer.finish()?;
        if sequence.tag != 0x30 {
            return Err(CertificateError::Malformed);
        }
        let mut usages = Reader::new(sequence.value);
        while usages.position < usages.bytes.len() {
            let usage = usages.next()?;
            if usage.tag != 0x06 {
                return Err(CertificateError::Malformed);
            }
            if usage.value == OCSP_SIGNING {
                return Ok(());
            }
        }
        Err(CertificateError::InvalidPurpose)
    }

    pub fn verify_hostname(&self, hostname: &str) -> Result<(), CertificateError> {
        let value = self
            .extension(SUBJECT_ALT_NAME)?
            .ok_or(CertificateError::HostnameMismatch)?;
        let mut outer = Reader::new(value);
        let names = outer.next()?;
        outer.finish()?;
        if names.tag != 0x30 {
            return Err(CertificateError::Malformed);
        }
        let mut entries = Reader::new(names.value);
        while entries.position < entries.bytes.len() {
            let name = entries.next()?;
            if name.tag == 0x82 && dns_matches(name.value, hostname.as_bytes()) {
                return Ok(());
            }
        }
        Err(CertificateError::HostnameMismatch)
    }

    pub fn verify_time(&self, now: u64) -> Result<(), CertificateError> {
        if now < self.not_before {
            Err(CertificateError::NotYetValid)
        } else if now > self.not_after {
            Err(CertificateError::Expired)
        } else {
            Ok(())
        }
    }

    pub fn verify_time_now(&self) -> Result<(), CertificateError> {
        self.verify_time(
            mrml_runtime::unix_time_seconds().ok_or(CertificateError::ClockUnavailable)?,
        )
    }
}

fn nonnegative_u32(element: Element<'_>) -> Result<u32, CertificateError> {
    if element.tag != 0x02
        || element.value.is_empty()
        || element.value[0] & 0x80 != 0
        || (element.value.len() > 1 && element.value[0] == 0 && element.value[1] & 0x80 == 0)
        || element.value.len() > 5
    {
        return Err(CertificateError::Malformed);
    }
    let bytes = if element.value.first() == Some(&0) {
        &element.value[1..]
    } else {
        element.value
    };
    let mut value = 0u32;
    for byte in bytes {
        value = value
            .checked_mul(256)
            .and_then(|value| value.checked_add(u32::from(*byte)))
            .ok_or(CertificateError::Malformed)?;
    }
    Ok(value)
}

fn validate_extensions(extensions: &[u8]) -> Result<(), CertificateError> {
    if extensions.is_empty() {
        return Ok(());
    }
    let mut wrapper = Reader::new(extensions);
    let sequence = wrapper.next()?;
    wrapper.finish()?;
    if sequence.tag != 0x30 {
        return Err(CertificateError::Malformed);
    }
    let mut entries = Reader::new(sequence.value);
    let mut seen = [&[][..]; 64];
    let mut seen_count = 0usize;
    while entries.position < entries.bytes.len() {
        if seen_count == seen.len() {
            return Err(CertificateError::Malformed);
        }
        let entry = entries.next()?;
        if entry.tag != 0x30 {
            return Err(CertificateError::Malformed);
        }
        let mut fields = Reader::new(entry.value);
        let oid = fields.next()?;
        if oid.tag != 0x06 || oid.value.is_empty() || seen[..seen_count].contains(&oid.value) {
            return Err(CertificateError::Malformed);
        }
        seen[seen_count] = oid.value;
        seen_count += 1;
        let mut value = fields.next()?;
        let critical = if value.tag == 0x01 {
            if value.value != [0xff] {
                return Err(CertificateError::Malformed);
            }
            value = fields.next()?;
            true
        } else {
            false
        };
        fields.finish()?;
        if value.tag != 0x04 {
            return Err(CertificateError::Malformed);
        }
        let supported = oid.value == SUBJECT_ALT_NAME
            || oid.value == BASIC_CONSTRAINTS
            || oid.value == KEY_USAGE
            || oid.value == EXTENDED_KEY_USAGE;
        if critical && !supported {
            return Err(CertificateError::UnsupportedCriticalExtension);
        }
    }
    Ok(())
}

fn decimal(bytes: &[u8]) -> Result<u32, CertificateError> {
    let mut value = 0u32;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return Err(CertificateError::Malformed);
        }
        value = value * 10 + (byte - b'0') as u32;
    }
    Ok(value)
}

fn certificate_time(element: Element<'_>) -> Result<u64, CertificateError> {
    let (year, rest) = match (element.tag, element.value.len()) {
        (0x17, 13) => {
            let short = decimal(&element.value[..2])?;
            (
                if short >= 50 {
                    1900 + short
                } else {
                    2000 + short
                },
                &element.value[2..],
            )
        }
        (0x18, 15) => (decimal(&element.value[..4])?, &element.value[4..]),
        _ => return Err(CertificateError::Malformed),
    };
    if rest[10] != b'Z' {
        return Err(CertificateError::Malformed);
    }
    let month = decimal(&rest[..2])?;
    let day = decimal(&rest[2..4])?;
    let hour = decimal(&rest[4..6])?;
    let minute = decimal(&rest[6..8])?;
    let second = decimal(&rest[8..10])?;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(CertificateError::Malformed);
    }
    let mut y = year as i64;
    let m = month as i64;
    y -= (m <= 2) as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let shifted = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * shifted + 2) / 5 + day as i64 - 1;
    let days = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    if days < 0 {
        return Err(CertificateError::Malformed);
    }
    Ok(days as u64 * 86400 + hour as u64 * 3600 + minute as u64 * 60 + second as u64)
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn dns_matches(pattern: &[u8], hostname: &[u8]) -> bool {
    if pattern.iter().any(|b| !b.is_ascii()) || hostname.iter().any(|b| !b.is_ascii()) {
        return false;
    }
    if pattern.starts_with(b"*.") {
        let Some(dot) = hostname.iter().position(|byte| *byte == b'.') else {
            return false;
        };
        dot != 0 && hostname[dot + 1..].eq_ignore_ascii_case(&pattern[2..])
    } else {
        hostname.eq_ignore_ascii_case(pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate_with_extensions(extensions: &[u8]) -> Certificate<'_> {
        Certificate {
            tbs: &[],
            issuer: &[],
            subject: &[],
            spki: &[],
            public_key_bits: &[],
            public_key: PublicKey::Rsa {
                modulus: &[],
                exponent: &[],
            },
            signature_algorithm: SignatureAlgorithm::RsaSha256,
            signature: &[],
            extensions,
            not_before: 0,
            not_after: 0,
            serial: &[1],
        }
    }
    #[test]
    fn external_certificate_parses_when_configured() {
        let Some(path) = mrml_runtime::environment_variable("MRML_X509_TEST_CERT") else {
            return;
        };
        let bytes = mrml_runtime::read_file(&path).unwrap();
        Certificate::parse(&bytes).unwrap();
    }
    #[test]
    fn external_certificate_signature_verifies_when_configured() {
        let Some(child_path) = mrml_runtime::environment_variable("MRML_X509_TEST_CHILD") else {
            return;
        };
        let Some(issuer_path) = mrml_runtime::environment_variable("MRML_X509_TEST_ISSUER") else {
            return;
        };
        let child_bytes = mrml_runtime::read_file(&child_path).unwrap();
        let issuer_bytes = mrml_runtime::read_file(&issuer_path).unwrap();
        let child = Certificate::parse(&child_bytes).unwrap();
        let issuer = Certificate::parse(&issuer_bytes).unwrap();
        child.verify_signed_by(&issuer).unwrap();
    }
    #[test]
    fn trust_identity_binds_subject_and_public_key() {
        let mut presented = certificate_with_extensions(&[]);
        presented.subject = b"subject";
        presented.spki = b"key";
        let mut anchor = certificate_with_extensions(&[]);
        anchor.subject = b"subject";
        anchor.spki = b"key";
        assert!(presented.same_trust_identity(&anchor));
        anchor.subject = b"other";
        assert!(!presented.same_trust_identity(&anchor));
        anchor.subject = b"subject";
        anchor.spki = b"other";
        assert!(!presented.same_trust_identity(&anchor));
    }
    #[test]
    fn wildcard_matches_exactly_one_label() {
        assert!(dns_matches(b"*.example.com", b"api.example.com"));
        assert!(!dns_matches(b"*.example.com", b"a.b.example.com"));
        assert!(!dns_matches(b"*.example.com", b"example.com"));
    }
    #[test]
    fn der_rejects_nonminimal_and_truncated_lengths() {
        assert!(Reader::new(&[0x30, 0x81, 0x01, 0]).next().is_err());
        assert!(Reader::new(&[0x30, 2, 0]).next().is_err());
    }
    #[test]
    fn rejects_unknown_critical_and_duplicate_extensions() {
        let unknown_critical = [
            0x30, 0x0b, 0x30, 0x09, 0x06, 0x02, 0x2a, 0x03, 0x01, 0x01, 0xff, 0x04, 0x00,
        ];
        assert_eq!(
            validate_extensions(&unknown_critical),
            Err(CertificateError::UnsupportedCriticalExtension)
        );
        let unknown_noncritical = [0x30, 0x08, 0x30, 0x06, 0x06, 0x02, 0x2a, 0x03, 0x04, 0x00];
        assert_eq!(validate_extensions(&unknown_noncritical), Ok(()));
        let duplicate = [
            0x30, 0x10, 0x30, 0x06, 0x06, 0x02, 0x2a, 0x03, 0x04, 0x00, 0x30, 0x06, 0x06, 0x02,
            0x2a, 0x03, 0x04, 0x00,
        ];
        assert_eq!(
            validate_extensions(&duplicate),
            Err(CertificateError::Malformed)
        );
        let known_critical = [
            0x30, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x01, 0x01, 0xff, 0x04, 0x00,
        ];
        assert_eq!(validate_extensions(&known_critical), Ok(()));
    }

    #[test]
    fn delegated_ocsp_requires_the_exact_signing_eku() {
        let ocsp_signing = [
            0x30, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06,
            0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09,
        ];
        let server_auth = [
            0x30, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06,
            0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
        ];
        assert_eq!(
            certificate_with_extensions(&ocsp_signing).require_ocsp_signing(),
            Ok(())
        );
        assert_eq!(
            certificate_with_extensions(&server_auth).require_ocsp_signing(),
            Err(CertificateError::InvalidPurpose)
        );
        assert_eq!(
            certificate_with_extensions(&[]).require_ocsp_signing(),
            Err(CertificateError::InvalidPurpose)
        );
    }

    #[test]
    fn enforces_basic_constraints_path_length() {
        let path_zero = [
            0x30, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x08, 0x30, 0x06, 0x01,
            0x01, 0xff, 0x02, 0x01, 0x00,
        ];
        let certificate = certificate_with_extensions(&path_zero);
        assert_eq!(certificate.enforce_ca_path_length(0), Ok(()));
        assert_eq!(
            certificate.enforce_ca_path_length(1),
            Err(CertificateError::PathLengthExceeded)
        );
    }
    #[test]
    fn external_public_chain_when_configured() {
        let Some(directory) = mrml_runtime::environment_variable("MRML_TLS_FIXTURES") else {
            return;
        };
        let leaf_bytes =
            mrml_runtime::read_file(&mrml_runtime::join_path(&directory, "leaf.der")).unwrap();
        let issuer_bytes =
            mrml_runtime::read_file(&mrml_runtime::join_path(&directory, "intermediate.der"))
                .unwrap();
        let leaf = Certificate::parse(&leaf_bytes).unwrap();
        let issuer = Certificate::parse(&issuer_bytes).unwrap();
        leaf.verify_hostname("huggingface.co").unwrap();
        leaf.verify_signed_by(&issuer).unwrap();
        issuer.require_ca().unwrap();
        leaf.verify_time_now().unwrap();
        issuer.verify_time_now().unwrap();
        crate::verify_server_chain("huggingface.co", &[&leaf_bytes, &issuer_bytes]).unwrap();
        assert_eq!(
            leaf.verify_hostname("attacker.example"),
            Err(CertificateError::HostnameMismatch)
        );
    }
    #[test]
    fn parses_utc_and_generalized_certificate_times() {
        assert_eq!(
            certificate_time(Element {
                tag: 0x17,
                value: b"700101000000Z",
                encoded: &[]
            })
            .unwrap(),
            0
        );
        assert_eq!(
            certificate_time(Element {
                tag: 0x18,
                value: b"20000229000000Z",
                encoded: &[]
            })
            .unwrap(),
            951782400
        );
        assert!(
            certificate_time(Element {
                tag: 0x18,
                value: b"21000229000000Z",
                encoded: &[]
            })
            .is_err()
        );
    }
}
