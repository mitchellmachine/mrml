use crate::{TlsIdentityId, VerifiedCertificateReceipt};
use mrml_acme::{AriCertificateId, AriError, RenewalInfo};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerError {
    ClockUnavailable,
    EntropyUnavailable,
    InvalidPolicy,
    CertificateMismatch,
    InvalidWindow,
    Expired,
    ArithmeticOverflow,
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
        validate_policy(policy)?;
        if now_unix >= certificate.not_after {
            return Err(SchedulerError::Expired);
        }
        let lifetime = certificate
            .not_after
            .checked_sub(certificate.not_before)
            .ok_or(SchedulerError::InvalidPolicy)?;
        let elapsed = (u128::from(lifetime) * u128::from(policy.fallback_elapsed_numerator)
            / u128::from(policy.fallback_elapsed_denominator)) as u64;
        let nominal = certificate
            .not_before
            .checked_add(elapsed)
            .ok_or(SchedulerError::ArithmeticOverflow)?;
        let latest = certificate
            .not_after
            .saturating_sub(policy.minimum_renewal_lead_seconds);
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
            certificate_id: certificate.ari_certificate_id,
            source: RenewalSource::LifetimeFallback,
            renew_at_unix: renew_at,
            requery_ari_at_unix: now_unix
                .checked_add(policy.ari_requery_min_seconds)
                .ok_or(SchedulerError::ArithmeticOverflow)?,
            not_after_unix: certificate.not_after,
            failure_count: 0,
            health: health(certificate.not_after, now_unix, policy),
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
}
