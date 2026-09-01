use crate::{
    ExpiryHealth, MAX_IDENTITY_NAMES, ManagedIdentityStatus, RenewalLease, RenewalSchedule,
    RenewalSource, TlsIdentityDescriptor, TlsIdentityId, TlsKeyIdentity,
};
use mrml_acme::{
    AcmeIdentifier, AriCertificateId, CertificateProfile, DnsIdentifier, IpIdentifier,
    MAX_ARI_CERTIFICATE_ID, MAX_DNS_NAME, MAX_IP_IDENTIFIER_TEXT, MAX_PROFILE_NAME,
};

pub const MAX_MANAGED_STATUS_BYTES: usize = 4096;
const MAGIC: &[u8; 8] = b"MRMLCST1";
const VERSION: u16 = 1;
const FLAG_ACTIVE: u16 = 1;
const FLAG_RENEWAL: u16 = 2;
const FLAG_LEASE: u16 = 4;
const FLAG_REPLACEMENT: u16 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedStatusCodecError {
    OutputTooSmall,
    TooLarge,
    Malformed,
    UnsupportedVersion,
    InvalidIdentity,
    InvalidProfile,
    InvalidIdentifier,
    InvalidSchedule,
    TrailingData,
}

pub fn encode_managed_identity_status(
    status: ManagedIdentityStatus,
    output: &mut [u8],
) -> Result<usize, ManagedStatusCodecError> {
    if status.identity == TlsIdentityId([0; 16]) || status.policy_generation == 0 {
        return Err(ManagedStatusCodecError::InvalidIdentity);
    }
    let mut flags = 0u16;
    flags |= status.active.is_some().then_some(FLAG_ACTIVE).unwrap_or(0);
    flags |= status
        .renewal
        .is_some()
        .then_some(FLAG_RENEWAL)
        .unwrap_or(0);
    flags |= status
        .renewal_lease
        .is_some()
        .then_some(FLAG_LEASE)
        .unwrap_or(0);
    flags |= status
        .replacement
        .is_some()
        .then_some(FLAG_REPLACEMENT)
        .unwrap_or(0);
    let mut writer = Writer::new(output);
    writer.bytes(MAGIC)?;
    writer.u16(VERSION)?;
    writer.u16(flags)?;
    let length_at = writer.position();
    writer.u32(0)?;
    writer.bytes(&status.identity.0)?;
    writer.u64(status.policy_generation)?;
    if let Some(active) = status.active {
        if active.identity != status.identity
            || active.policy_generation != status.policy_generation
        {
            return Err(ManagedStatusCodecError::InvalidIdentity);
        }
        write_descriptor(&mut writer, active)?;
    }
    if let Some(renewal) = status.renewal {
        write_schedule(
            &mut writer,
            renewal,
            status.identity,
            status.policy_generation,
        )?;
    }
    if let Some(lease) = status.renewal_lease {
        write_lease(
            &mut writer,
            lease,
            status.identity,
            status.policy_generation,
        )?;
    }
    if let Some(replacement) = status.replacement {
        write_schedule(
            &mut writer,
            replacement,
            status.identity,
            status.policy_generation,
        )?;
    }
    let written = writer.position();
    if written > MAX_MANAGED_STATUS_BYTES || written > u32::MAX as usize {
        return Err(ManagedStatusCodecError::TooLarge);
    }
    output[length_at..length_at + 4].copy_from_slice(&(written as u32).to_be_bytes());
    Ok(written)
}

pub fn decode_managed_identity_status(
    input: &[u8],
) -> Result<ManagedIdentityStatus, ManagedStatusCodecError> {
    if input.len() > MAX_MANAGED_STATUS_BYTES {
        return Err(ManagedStatusCodecError::TooLarge);
    }
    let mut reader = Reader::new(input);
    if reader.bytes(8)? != MAGIC {
        return Err(ManagedStatusCodecError::Malformed);
    }
    if reader.u16()? != VERSION {
        return Err(ManagedStatusCodecError::UnsupportedVersion);
    }
    let flags = reader.u16()?;
    if flags & !(FLAG_ACTIVE | FLAG_RENEWAL | FLAG_LEASE | FLAG_REPLACEMENT) != 0 {
        return Err(ManagedStatusCodecError::Malformed);
    }
    if reader.u32()? as usize != input.len() {
        return Err(ManagedStatusCodecError::Malformed);
    }
    let mut identity = [0; 16];
    identity.copy_from_slice(reader.bytes(16)?);
    let identity = TlsIdentityId(identity);
    let policy_generation = reader.u64()?;
    if identity == TlsIdentityId([0; 16]) || policy_generation == 0 {
        return Err(ManagedStatusCodecError::InvalidIdentity);
    }
    let active = if flags & FLAG_ACTIVE != 0 {
        Some(read_descriptor(&mut reader, identity, policy_generation)?)
    } else {
        None
    };
    let renewal = if flags & FLAG_RENEWAL != 0 {
        Some(read_schedule(&mut reader, identity, policy_generation)?)
    } else {
        None
    };
    let renewal_lease = if flags & FLAG_LEASE != 0 {
        Some(read_lease(&mut reader, identity, policy_generation)?)
    } else {
        None
    };
    let replacement = if flags & FLAG_REPLACEMENT != 0 {
        Some(read_schedule(&mut reader, identity, policy_generation)?)
    } else {
        None
    };
    if !reader.finished() {
        return Err(ManagedStatusCodecError::TrailingData);
    }
    Ok(ManagedIdentityStatus {
        identity,
        policy_generation,
        active,
        renewal,
        renewal_lease,
        replacement,
    })
}

fn write_descriptor(
    writer: &mut Writer<'_>,
    value: TlsIdentityDescriptor,
) -> Result<(), ManagedStatusCodecError> {
    if value.identity == TlsIdentityId([0; 16])
        || value.policy_generation == 0
        || value.generation == 0
        || value.identifier_count == 0
        || usize::from(value.identifier_count) > MAX_IDENTITY_NAMES
    {
        return Err(ManagedStatusCodecError::Malformed);
    }
    writer.u64(value.generation)?;
    writer.bytes(&value.chain_digest)?;
    writer.bytes(&value.leaf_spki_digest)?;
    writer.bytes(&value.key_identity.0)?;
    writer.u64(value.not_before)?;
    writer.u64(value.not_after)?;
    writer.u64(value.profile.directory_generation())?;
    writer.text8(value.profile.name(), MAX_PROFILE_NAME)?;
    writer.u8(value.identifier_count)?;
    for identifier in value.identifiers[..usize::from(value.identifier_count)].iter() {
        let identifier = identifier.ok_or(ManagedStatusCodecError::InvalidIdentifier)?;
        let mut text = [0u8; MAX_DNS_NAME];
        let value = identifier
            .write_value(&mut text)
            .map_err(|_| ManagedStatusCodecError::InvalidIdentifier)?;
        writer.u8(match identifier {
            AcmeIdentifier::Dns(_) => 1,
            AcmeIdentifier::Ip(_) => 2,
        })?;
        writer.text16(value, MAX_DNS_NAME)?;
    }
    Ok(())
}

fn read_descriptor(
    reader: &mut Reader<'_>,
    identity: TlsIdentityId,
    policy_generation: u64,
) -> Result<TlsIdentityDescriptor, ManagedStatusCodecError> {
    let generation = reader.u64()?;
    let mut chain_digest = [0; 32];
    chain_digest.copy_from_slice(reader.bytes(32)?);
    let mut leaf_spki_digest = [0; 32];
    leaf_spki_digest.copy_from_slice(reader.bytes(32)?);
    let mut key_identity = [0; 32];
    key_identity.copy_from_slice(reader.bytes(32)?);
    let not_before = reader.u64()?;
    let not_after = reader.u64()?;
    let directory_generation = reader.u64()?;
    let profile = CertificateProfile::parse(reader.text8(MAX_PROFILE_NAME)?, directory_generation)
        .map_err(|_| ManagedStatusCodecError::InvalidProfile)?;
    let identifier_count = reader.u8()?;
    if generation == 0
        || identifier_count == 0
        || usize::from(identifier_count) > MAX_IDENTITY_NAMES
        || not_after <= not_before
        || key_identity == [0; 32]
    {
        return Err(ManagedStatusCodecError::Malformed);
    }
    let mut identifiers = [None; MAX_IDENTITY_NAMES];
    for slot in identifiers.iter_mut().take(usize::from(identifier_count)) {
        let kind = reader.u8()?;
        let text = reader.text16(MAX_DNS_NAME)?;
        *slot = Some(match kind {
            1 => AcmeIdentifier::Dns(
                DnsIdentifier::parse(text, true)
                    .map_err(|_| ManagedStatusCodecError::InvalidIdentifier)?,
            ),
            2 if text.len() <= MAX_IP_IDENTIFIER_TEXT => AcmeIdentifier::Ip(
                IpIdentifier::parse(text)
                    .map_err(|_| ManagedStatusCodecError::InvalidIdentifier)?,
            ),
            _ => return Err(ManagedStatusCodecError::InvalidIdentifier),
        });
    }
    if identifiers[..usize::from(identifier_count)]
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(ManagedStatusCodecError::InvalidIdentifier);
    }
    Ok(TlsIdentityDescriptor {
        identity,
        generation,
        policy_generation,
        identifiers,
        identifier_count,
        chain_digest,
        leaf_spki_digest,
        key_identity: TlsKeyIdentity(key_identity),
        not_before,
        not_after,
        profile,
    })
}

fn write_schedule(
    writer: &mut Writer<'_>,
    value: RenewalSchedule,
    identity: TlsIdentityId,
    policy: u64,
) -> Result<(), ManagedStatusCodecError> {
    if value.identity != identity
        || value.policy_generation != policy
        || value.identity_generation == 0
        || value.not_after_unix == 0
    {
        return Err(ManagedStatusCodecError::InvalidSchedule);
    }
    writer.u64(value.identity_generation)?;
    writer.text8(value.certificate_id.as_str(), MAX_ARI_CERTIFICATE_ID)?;
    writer.u8(match value.source {
        RenewalSource::Ari => 1,
        RenewalSource::LifetimeFallback => 2,
    })?;
    writer.u8(match value.health {
        ExpiryHealth::Healthy => 1,
        ExpiryHealth::Warning => 2,
        ExpiryHealth::Critical => 3,
        ExpiryHealth::Expired => 4,
    })?;
    writer.u8(value.failure_count)?;
    writer.u8(0)?;
    writer.u64(value.renew_at_unix)?;
    writer.u64(value.requery_ari_at_unix)?;
    writer.u64(value.not_after_unix)
}

fn read_schedule(
    reader: &mut Reader<'_>,
    identity: TlsIdentityId,
    policy_generation: u64,
) -> Result<RenewalSchedule, ManagedStatusCodecError> {
    let identity_generation = reader.u64()?;
    let certificate_id = AriCertificateId::parse(reader.text8(MAX_ARI_CERTIFICATE_ID)?)
        .map_err(|_| ManagedStatusCodecError::InvalidSchedule)?;
    let source = match reader.u8()? {
        1 => RenewalSource::Ari,
        2 => RenewalSource::LifetimeFallback,
        _ => return Err(ManagedStatusCodecError::InvalidSchedule),
    };
    let health = match reader.u8()? {
        1 => ExpiryHealth::Healthy,
        2 => ExpiryHealth::Warning,
        3 => ExpiryHealth::Critical,
        4 => ExpiryHealth::Expired,
        _ => return Err(ManagedStatusCodecError::InvalidSchedule),
    };
    let failure_count = reader.u8()?;
    if reader.u8()? != 0 {
        return Err(ManagedStatusCodecError::Malformed);
    }
    let renew_at_unix = reader.u64()?;
    let requery_ari_at_unix = reader.u64()?;
    let not_after_unix = reader.u64()?;
    if identity_generation == 0 || not_after_unix == 0 {
        return Err(ManagedStatusCodecError::InvalidSchedule);
    }
    Ok(RenewalSchedule {
        identity,
        identity_generation,
        policy_generation,
        certificate_id,
        source,
        renew_at_unix,
        requery_ari_at_unix,
        not_after_unix,
        failure_count,
        health,
    })
}

fn write_lease(
    writer: &mut Writer<'_>,
    value: RenewalLease,
    identity: TlsIdentityId,
    policy: u64,
) -> Result<(), ManagedStatusCodecError> {
    if value.identity != identity
        || value.policy_generation != policy
        || value.identity_generation == 0
        || value.lease_generation == 0
        || value.expires_at_unix == 0
    {
        return Err(ManagedStatusCodecError::InvalidSchedule);
    }
    writer.u64(value.identity_generation)?;
    writer.u64(value.lease_generation)?;
    writer.u64(value.expires_at_unix)
}

fn read_lease(
    reader: &mut Reader<'_>,
    identity: TlsIdentityId,
    policy_generation: u64,
) -> Result<RenewalLease, ManagedStatusCodecError> {
    let identity_generation = reader.u64()?;
    let lease_generation = reader.u64()?;
    let expires_at_unix = reader.u64()?;
    if identity_generation == 0 || lease_generation == 0 || expires_at_unix == 0 {
        return Err(ManagedStatusCodecError::InvalidSchedule);
    }
    Ok(RenewalLease {
        identity,
        identity_generation,
        policy_generation,
        lease_generation,
        expires_at_unix,
    })
}

struct Writer<'a> {
    output: &'a mut [u8],
    cursor: usize,
}
impl<'a> Writer<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self { output, cursor: 0 }
    }
    fn position(&self) -> usize {
        self.cursor
    }
    fn bytes(&mut self, value: &[u8]) -> Result<(), ManagedStatusCodecError> {
        let end = self
            .cursor
            .checked_add(value.len())
            .ok_or(ManagedStatusCodecError::TooLarge)?;
        self.output
            .get_mut(self.cursor..end)
            .ok_or(ManagedStatusCodecError::OutputTooSmall)?
            .copy_from_slice(value);
        self.cursor = end;
        Ok(())
    }
    fn u8(&mut self, v: u8) -> Result<(), ManagedStatusCodecError> {
        self.bytes(&[v])
    }
    fn u16(&mut self, v: u16) -> Result<(), ManagedStatusCodecError> {
        self.bytes(&v.to_be_bytes())
    }
    fn u32(&mut self, v: u32) -> Result<(), ManagedStatusCodecError> {
        self.bytes(&v.to_be_bytes())
    }
    fn u64(&mut self, v: u64) -> Result<(), ManagedStatusCodecError> {
        self.bytes(&v.to_be_bytes())
    }
    fn text8(&mut self, v: &str, max: usize) -> Result<(), ManagedStatusCodecError> {
        if v.is_empty() || v.len() > max || v.len() > u8::MAX as usize {
            return Err(ManagedStatusCodecError::Malformed);
        }
        self.u8(v.len() as u8)?;
        self.bytes(v.as_bytes())
    }
    fn text16(&mut self, v: &str, max: usize) -> Result<(), ManagedStatusCodecError> {
        if v.is_empty() || v.len() > max || v.len() > u16::MAX as usize {
            return Err(ManagedStatusCodecError::Malformed);
        }
        self.u16(v.len() as u16)?;
        self.bytes(v.as_bytes())
    }
}

struct Reader<'a> {
    input: &'a [u8],
    cursor: usize,
}
impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, cursor: 0 }
    }
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], ManagedStatusCodecError> {
        let end = self
            .cursor
            .checked_add(n)
            .ok_or(ManagedStatusCodecError::Malformed)?;
        let value = self
            .input
            .get(self.cursor..end)
            .ok_or(ManagedStatusCodecError::Malformed)?;
        self.cursor = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, ManagedStatusCodecError> {
        Ok(self.bytes(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ManagedStatusCodecError> {
        Ok(u16::from_be_bytes(self.bytes(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, ManagedStatusCodecError> {
        Ok(u32::from_be_bytes(self.bytes(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, ManagedStatusCodecError> {
        Ok(u64::from_be_bytes(self.bytes(8)?.try_into().unwrap()))
    }
    fn text8(&mut self, max: usize) -> Result<&'a str, ManagedStatusCodecError> {
        let n = usize::from(self.u8()?);
        self.text(n, max)
    }
    fn text16(&mut self, max: usize) -> Result<&'a str, ManagedStatusCodecError> {
        let n = usize::from(self.u16()?);
        self.text(n, max)
    }
    fn text(&mut self, n: usize, max: usize) -> Result<&'a str, ManagedStatusCodecError> {
        if n == 0 || n > max {
            return Err(ManagedStatusCodecError::Malformed);
        }
        core::str::from_utf8(self.bytes(n)?).map_err(|_| ManagedStatusCodecError::Malformed)
    }
    fn finished(&self) -> bool {
        self.cursor == self.input.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_acme::CertificateProfile;

    fn status() -> ManagedIdentityStatus {
        let identity = TlsIdentityId([1; 16]);
        let mut identifiers = [None; MAX_IDENTITY_NAMES];
        identifiers[0] = Some(AcmeIdentifier::Dns(
            DnsIdentifier::parse("git.example", false).unwrap(),
        ));
        identifiers[1] = Some(AcmeIdentifier::Ip(
            IpIdentifier::parse("192.0.2.1").unwrap(),
        ));
        let certificate_id = AriCertificateId::derive(&[1], &[2]).unwrap();
        let renewal = RenewalSchedule {
            identity,
            identity_generation: 3,
            policy_generation: 7,
            certificate_id,
            source: RenewalSource::Ari,
            renew_at_unix: 80,
            requery_ari_at_unix: 60,
            not_after_unix: 100,
            failure_count: 2,
            health: ExpiryHealth::Warning,
        };
        ManagedIdentityStatus {
            identity,
            policy_generation: 7,
            active: Some(TlsIdentityDescriptor {
                identity,
                generation: 3,
                policy_generation: 7,
                identifiers,
                identifier_count: 2,
                chain_digest: [2; 32],
                leaf_spki_digest: [3; 32],
                key_identity: TlsKeyIdentity([4; 32]),
                not_before: 10,
                not_after: 100,
                profile: CertificateProfile::parse("classic", 5).unwrap(),
            }),
            renewal: Some(renewal),
            renewal_lease: Some(RenewalLease {
                identity,
                identity_generation: 3,
                policy_generation: 7,
                lease_generation: 9,
                expires_at_unix: 70,
            }),
            replacement: None,
        }
    }

    #[test]
    fn canonical_status_round_trips_exact_public_state() {
        let expected = status();
        let mut output = [0u8; MAX_MANAGED_STATUS_BYTES];
        let written = encode_managed_identity_status(expected, &mut output).unwrap();
        let decoded = decode_managed_identity_status(&output[..written]).unwrap();
        assert!(decoded == expected);
    }

    #[test]
    fn mutation_truncation_and_trailing_data_fail_closed() {
        let mut output = [0u8; MAX_MANAGED_STATUS_BYTES];
        let written = encode_managed_identity_status(status(), &mut output).unwrap();
        for length in 0..written {
            assert!(decode_managed_identity_status(&output[..length]).is_err());
        }
        output[written] = 1;
        assert!(matches!(
            decode_managed_identity_status(&output[..written + 1]),
            Err(ManagedStatusCodecError::Malformed)
        ));
        output[0] ^= 1;
        assert!(matches!(
            decode_managed_identity_status(&output[..written]),
            Err(ManagedStatusCodecError::Malformed)
        ));
    }
}
