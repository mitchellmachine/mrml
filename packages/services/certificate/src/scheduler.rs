use crate::{TlsIdentityId, VerifiedCertificateReceipt};
use mrml_acme::{AriCertificateId, AriError, RenewalInfo};

const SCHEDULE_MAGIC: &[u8; 8] = b"MRMLRNS1";
pub const RENEWAL_SCHEDULE_BYTES: usize = 192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerError {
    ClockUnavailable,
    EntropyUnavailable,
    InvalidPolicy,
    CertificateMismatch,
    InvalidWindow,
    Expired,
    ArithmeticOverflow,
    OutputTooSmall,
    Malformed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenewalSource {
    Ari,
    LifetimeFallback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpiryHealth {
    Healthy,
    Warning,
    Critical,
    Expired,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RenewalPolicy {
    pub generation: u64,
    pub fallback_elapsed_numerator: u32,
    pub fallback_elapsed_denominator: u32,
    pub minimum_renewal_lead_seconds: u64,
    pub warning_lead_seconds: u64,
    pub critical_lead_seconds: u64,
    pub initial_backoff_seconds: u64,
    pub maximum_backoff_seconds: u64,
    pub ari_requery_min_seconds: u64,
    pub ari_requery_max_seconds: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RenewalSchedule {
    pub identity: TlsIdentityId,
    pub identity_generation: u64,
    pub policy_generation: u64,
    pub certificate_id: AriCertificateId,
    pub source: RenewalSource,
    pub renew_at_unix: u64,
    pub requery_ari_at_unix: u64,
    pub not_after_unix: u64,
    pub failure_count: u8,
    pub health: ExpiryHealth,
}

pub trait RenewalEntropy {
    fn random_u64(&mut self) -> Result<u64, SchedulerError>;
}

impl RenewalSchedule {
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, SchedulerError> {
        let certificate_id = self.certificate_id.as_str().as_bytes();
        if output.len() < RENEWAL_SCHEDULE_BYTES
            || self.identity == TlsIdentityId([0; 16])
            || self.identity_generation == 0
            || self.policy_generation == 0
            || self.renew_at_unix == 0
            || self.requery_ari_at_unix == 0
            || self.not_after_unix == 0
            || certificate_id.is_empty()
            || certificate_id.len() > mrml_acme::MAX_ARI_CERTIFICATE_ID
        {
            return Err(if output.len() < RENEWAL_SCHEDULE_BYTES {
                SchedulerError::OutputTooSmall
            } else {
                SchedulerError::Malformed
            });
        }
        output[..RENEWAL_SCHEDULE_BYTES].fill(0);
        output[..8].copy_from_slice(SCHEDULE_MAGIC);
        output[8..10].copy_from_slice(&1u16.to_be_bytes());
        output[10] = match self.source {
            RenewalSource::Ari => 1,
            RenewalSource::LifetimeFallback => 2,
        };
        output[11] = match self.health {
            ExpiryHealth::Healthy => 1,
            ExpiryHealth::Warning => 2,
            ExpiryHealth::Critical => 3,
            ExpiryHealth::Expired => 4,
        };
        output[12] = self.failure_count;
        output[13] = certificate_id.len() as u8;
        output[16..32].copy_from_slice(&self.identity.0);
        output[32..40].copy_from_slice(&self.identity_generation.to_be_bytes());
        output[40..48].copy_from_slice(&self.policy_generation.to_be_bytes());
        output[48..56].copy_from_slice(&self.renew_at_unix.to_be_bytes());
        output[56..64].copy_from_slice(&self.requery_ari_at_unix.to_be_bytes());
        output[64..72].copy_from_slice(&self.not_after_unix.to_be_bytes());
        output[72..72 + certificate_id.len()].copy_from_slice(certificate_id);
        Ok(RENEWAL_SCHEDULE_BYTES)
    }

    pub fn decode(input: &[u8]) -> Result<Self, SchedulerError> {
        if input.len() != RENEWAL_SCHEDULE_BYTES
            || input.get(..8) != Some(SCHEDULE_MAGIC)
            || input[8..10] != 1u16.to_be_bytes()
            || input[14..16].iter().any(|byte| *byte != 0)
        {
            return Err(SchedulerError::Malformed);
        }
        let id_length = usize::from(input[13]);
        if id_length == 0
            || id_length > mrml_acme::MAX_ARI_CERTIFICATE_ID
            || input[72 + id_length..].iter().any(|byte| *byte != 0)
        {
            return Err(SchedulerError::Malformed);
        }
        let id = core::str::from_utf8(&input[72..72 + id_length])
            .map_err(|_| SchedulerError::Malformed)?;
        let schedule = Self {
            identity: TlsIdentityId(copy(&input[16..32])?),
            identity_generation: number(&input[32..40])?,
            policy_generation: number(&input[40..48])?,
            certificate_id: AriCertificateId::parse(id).map_err(|_| SchedulerError::Malformed)?,
            source: match input[10] {
                1 => RenewalSource::Ari,
                2 => RenewalSource::LifetimeFallback,
                _ => return Err(SchedulerError::Malformed),
            },
            renew_at_unix: number(&input[48..56])?,
            requery_ari_at_unix: number(&input[56..64])?,
            not_after_unix: number(&input[64..72])?,
            failure_count: input[12],
            health: match input[11] {
                1 => ExpiryHealth::Healthy,
                2 => ExpiryHealth::Warning,
                3 => ExpiryHealth::Critical,
                4 => ExpiryHealth::Expired,
                _ => return Err(SchedulerError::Malformed),
            },
        };
        let mut canonical = [0u8; RENEWAL_SCHEDULE_BYTES];
        schedule.encode(&mut canonical)?;
        if canonical != input {
            return Err(SchedulerError::Malformed);
        }
        Ok(schedule)
    }

    pub fn from_ari(
        identity: TlsIdentityId,
        identity_generation: u64,
        certificate: &VerifiedCertificateReceipt,
        requested_certificate_id: AriCertificateId,
        info: RenewalInfo,
        policy: RenewalPolicy,
        now_unix: u64,
        entropy: &mut impl RenewalEntropy,
    ) -> Result<Self, SchedulerError> {
        validate_policy(policy)?;
        if certificate.ari_certificate_id != requested_certificate_id {
            return Err(SchedulerError::CertificateMismatch);
        }
        let renew_at = info
            .suggested_window
            .select(entropy.random_u64()?)
            .map_err(map_ari)?;
        if renew_at >= certificate.not_after {
            return Err(SchedulerError::InvalidWindow);
        }
        let requery_span = policy.ari_requery_max_seconds - policy.ari_requery_min_seconds;
        let random_offset = if requery_span == 0 {
            0
        } else {
            entropy.random_u64()? % requery_span
        };
        let requery = now_unix
            .checked_add(policy.ari_requery_min_seconds)
            .and_then(|base| base.checked_add(random_offset))
            .ok_or(SchedulerError::ArithmeticOverflow)?;
        Ok(Self {
            identity,
            identity_generation,
            policy_generation: policy.generation,
            certificate_id: requested_certificate_id,
            source: RenewalSource::Ari,
            renew_at_unix: renew_at,
            requery_ari_at_unix: requery.min(renew_at),
            not_after_unix: certificate.not_after,
            failure_count: 0,
            health: health(certificate.not_after, now_unix, policy),
        })
    }

    pub fn fallback(
        identity: TlsIdentityId,
        identity_generation: u64,
        certificate: &VerifiedCertificateReceipt,
        policy: RenewalPolicy,
        now_unix: u64,
        entropy: &mut impl RenewalEntropy,
    ) -> Result<Self, SchedulerError> {
        Self::fallback_for_certificate(
            identity,
            identity_generation,
            certificate.ari_certificate_id,
            certificate.not_before,
            certificate.not_after,
            policy,
            now_unix,
            entropy,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn fallback_for_certificate(
        identity: TlsIdentityId,
        identity_generation: u64,
        certificate_id: AriCertificateId,
        not_before: u64,
        not_after: u64,
        policy: RenewalPolicy,
        now_unix: u64,
        entropy: &mut impl RenewalEntropy,
    ) -> Result<Self, SchedulerError> {
        validate_policy(policy)?;
        if identity == TlsIdentityId([0; 16])
            || identity_generation == 0
            || now_unix >= not_after
            || not_before >= not_after
        {
            return Err(SchedulerError::Expired);
        }
        let lifetime = not_after
            .checked_sub(not_before)
            .ok_or(SchedulerError::InvalidPolicy)?;
        let elapsed = (u128::from(lifetime) * u128::from(policy.fallback_elapsed_numerator)
            / u128::from(policy.fallback_elapsed_denominator)) as u64;
        let nominal = not_before
            .checked_add(elapsed)
            .ok_or(SchedulerError::ArithmeticOverflow)?;
        let latest = not_after.saturating_sub(policy.minimum_renewal_lead_seconds);
        let renew_at = if latest <= now_unix {
            now_unix
        } else {
            let base = nominal.min(latest).max(now_unix);
            let span = latest.saturating_sub(base);
            if span == 0 {
                base
            } else {
                base.saturating_add(entropy.random_u64()? % (span / 8).max(1))
                    .min(latest)
            }
        };
        Ok(Self {
            identity,
            identity_generation,
            policy_generation: policy.generation,
            certificate_id,
            source: RenewalSource::LifetimeFallback,
            renew_at_unix: renew_at,
            requery_ari_at_unix: now_unix
                .checked_add(policy.ari_requery_min_seconds)
                .ok_or(SchedulerError::ArithmeticOverflow)?,
            not_after_unix: not_after,
            failure_count: 0,
            health: health(not_after, now_unix, policy),
        })
    }

    pub fn record_failure(
        &mut self,
        now_unix: u64,
        retry_after_seconds: Option<u64>,
        policy: RenewalPolicy,
        entropy: &mut impl RenewalEntropy,
    ) -> Result<(), SchedulerError> {
        if self.policy_generation != policy.generation {
            return Err(SchedulerError::InvalidPolicy);
        }
        self.failure_count = self
            .failure_count
            .checked_add(1)
            .ok_or(SchedulerError::ArithmeticOverflow)?;
        let shift = u32::from(self.failure_count.saturating_sub(1).min(31));
        let exponential = policy
            .initial_backoff_seconds
            .checked_mul(1u64 << shift)
            .unwrap_or(policy.maximum_backoff_seconds)
            .min(policy.maximum_backoff_seconds);
        let jitter = if exponential > 1 {
            entropy.random_u64()? % (exponential / 2)
        } else {
            0
        };
        let delay = exponential.saturating_sub(jitter);
        let retry = retry_after_seconds.unwrap_or(0).max(delay);
        let latest = self
            .not_after_unix
            .saturating_sub(policy.critical_lead_seconds.max(1));
        self.renew_at_unix = if latest <= now_unix {
            now_unix
        } else {
            now_unix.saturating_add(retry).min(latest)
        };
        self.health = health(self.not_after_unix, now_unix, policy);
        Ok(())
    }

    pub fn refresh_health(
        &mut self,
        now_unix: u64,
        policy: RenewalPolicy,
    ) -> Result<ExpiryHealth, SchedulerError> {
        if self.policy_generation != policy.generation {
            return Err(SchedulerError::InvalidPolicy);
        }
        self.health = health(self.not_after_unix, now_unix, policy);
        Ok(self.health)
    }
}

fn copy<const N: usize>(input: &[u8]) -> Result<[u8; N], SchedulerError> {
    input.try_into().map_err(|_| SchedulerError::Malformed)
}

fn number(input: &[u8]) -> Result<u64, SchedulerError> {
    let value = u64::from_be_bytes(copy(input)?);
    if value == 0 {
        Err(SchedulerError::Malformed)
    } else {
        Ok(value)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ReplacementBinding {
    pub previous_certificate_id: AriCertificateId,
    pub replacement_order_url_digest: [u8; 32],
    pub policy_generation: u64,
}

fn validate_policy(p: RenewalPolicy) -> Result<(), SchedulerError> {
    if p.fallback_elapsed_denominator == 0
        || p.fallback_elapsed_numerator >= p.fallback_elapsed_denominator
        || p.minimum_renewal_lead_seconds == 0
        || p.critical_lead_seconds == 0
        || p.warning_lead_seconds <= p.critical_lead_seconds
        || p.initial_backoff_seconds == 0
        || p.maximum_backoff_seconds < p.initial_backoff_seconds
        || p.ari_requery_max_seconds < p.ari_requery_min_seconds
    {
        return Err(SchedulerError::InvalidPolicy);
    }
    Ok(())
}
fn health(not_after: u64, now: u64, p: RenewalPolicy) -> ExpiryHealth {
    if now >= not_after {
        ExpiryHealth::Expired
    } else {
        let remaining = not_after - now;
        if remaining <= p.critical_lead_seconds {
            ExpiryHealth::Critical
        } else if remaining <= p.warning_lead_seconds {
            ExpiryHealth::Warning
        } else {
            ExpiryHealth::Healthy
        }
    }
}
fn map_ari(_: AriError) -> SchedulerError {
    SchedulerError::InvalidWindow
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_acme::{CaClass, CertificateProfile};
    struct Entropy(u64);
    impl RenewalEntropy for Entropy {
        fn random_u64(&mut self) -> Result<u64, SchedulerError> {
            Ok(self.0)
        }
    }
    fn receipt() -> VerifiedCertificateReceipt {
        VerifiedCertificateReceipt {
            policy_generation: 1,
            ca_class: CaClass::Staging,
            profile: CertificateProfile::parse("classic", 1).unwrap(),
            order_url_digest: [1; 32],
            chain_digest: [2; 32],
            leaf_spki_digest: [3; 32],
            not_before: 100,
            not_after: 1000,
            trust_store_digest: [4; 32],
            ari_certificate_id: AriCertificateId::derive(&[5], &[6]).unwrap(),
        }
    }
    fn policy() -> RenewalPolicy {
        RenewalPolicy {
            generation: 3,
            fallback_elapsed_numerator: 2,
            fallback_elapsed_denominator: 3,
            minimum_renewal_lead_seconds: 100,
            warning_lead_seconds: 200,
            critical_lead_seconds: 50,
            initial_backoff_seconds: 10,
            maximum_backoff_seconds: 200,
            ari_requery_min_seconds: 20,
            ari_requery_max_seconds: 40,
        }
    }
    #[test]
    fn fallback_uses_actual_lifetime_and_backoff_respects_retry_after() {
        let r = receipt();
        let mut e = Entropy(7);
        let mut s = RenewalSchedule::fallback(TlsIdentityId([1; 16]), 2, &r, policy(), 200, &mut e)
            .unwrap();
        assert!((700..900).contains(&s.renew_at_unix));
        s.record_failure(750, Some(100), policy(), &mut e).unwrap();
        assert_eq!(s.renew_at_unix, 850);
    }
    #[test]
    fn ari_rejects_replacement_identity_substitution() {
        let r = receipt();
        let info = RenewalInfo {
            suggested_window: mrml_acme::RenewalWindow::validate(300, 500, 200, 10).unwrap(),
        };
        let mut e = Entropy(3);
        assert!(matches!(
            RenewalSchedule::from_ari(
                TlsIdentityId([1; 16]),
                2,
                &r,
                AriCertificateId::derive(&[9], &[9]).unwrap(),
                info,
                policy(),
                200,
                &mut e
            ),
            Err(SchedulerError::CertificateMismatch)
        ));
    }

    #[test]
    fn renewal_schedule_round_trips_canonically() {
        let r = receipt();
        let mut entropy = Entropy(7);
        let schedule =
            RenewalSchedule::fallback(TlsIdentityId([1; 16]), 2, &r, policy(), 200, &mut entropy)
                .unwrap();
        let mut encoded = [0u8; RENEWAL_SCHEDULE_BYTES];
        schedule.encode(&mut encoded).unwrap();
        assert!(RenewalSchedule::decode(&encoded).unwrap() == schedule);
        encoded[14] = 1;
        assert!(RenewalSchedule::decode(&encoded).is_err());
    }
}
