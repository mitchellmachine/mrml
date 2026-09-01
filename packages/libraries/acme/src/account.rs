use crate::{AcmeDirectory, AcmeUrl, JwkThumbprint, P256Jwk};
use mrml_crypto::Sha256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaClass {
    Staging,
    Production,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountError {
    TermsApprovalRequired,
    TermsApprovalMismatch,
    ExternalAccountBindingRequired,
    InvalidState,
    StaleGeneration,
    ReceiptMismatch,
    AccountUrlPolicy,
    ResolutionMismatch,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct OwnerTermsApproval {
    pub directory_generation: u64,
    pub terms_url_digest: [u8; 32],
    pub terms_content_digest: [u8; 32],
}

impl OwnerTermsApproval {
    pub fn new(directory_generation: u64, terms_url: &AcmeUrl, content: &[u8]) -> Self {
        Self {
            directory_generation,
            terms_url_digest: Sha256::digest(terms_url.as_str().as_bytes()),
            terms_content_digest: Sha256::digest(content),
        }
    }
    fn matches(&self, directory: &AcmeDirectory) -> bool {
        self.directory_generation == directory.generation
            && directory
                .terms_of_service
                .is_some_and(|url| self.terms_url_digest == Sha256::digest(url.as_str().as_bytes()))
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AccountPolicy {
    pub ca_class: CaClass,
    pub policy_generation: u64,
    pub contact_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountOperation {
    None,
    CreatePrepared,
    ContactUpdatePrepared,
    RolloverPrepared,
    DeactivationPrepared,
    Uncertain,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PreparedAccountAction {
    pub account_generation: u64,
    pub directory_generation: u64,
    pub policy_generation: u64,
    pub action: AccountOperation,
    pub old_key: Option<JwkThumbprint>,
    pub new_key: Option<JwkThumbprint>,
    pub contact_digest: [u8; 32],
}

pub struct AccountLifecycle {
    pub ca_class: CaClass,
    pub generation: u64,
    pub directory_generation: u64,
    pub policy_generation: u64,
    pub account_url: Option<AcmeUrl>,
    pub key: JwkThumbprint,
    pub contact_digest: [u8; 32],
    pub active: bool,
    pub operation: AccountOperation,
    prepared: Option<PreparedAccountAction>,
}

impl AccountLifecycle {
    pub fn prepare_create(
        directory: &AcmeDirectory,
        policy: AccountPolicy,
        key: &P256Jwk,
        terms: Option<&OwnerTermsApproval>,
        external_account_binding_present: bool,
    ) -> Result<(Self, PreparedAccountAction), AccountError> {
        if directory.terms_of_service.is_some() {
            let approval = terms.ok_or(AccountError::TermsApprovalRequired)?;
            if !approval.matches(directory) {
                return Err(AccountError::TermsApprovalMismatch);
            }
        }
        if directory.external_account_required && !external_account_binding_present {
            return Err(AccountError::ExternalAccountBindingRequired);
        }
        let key = key.thumbprint().map_err(|_| AccountError::InvalidState)?;
        let prepared = PreparedAccountAction {
            account_generation: 1,
            directory_generation: directory.generation,
            policy_generation: policy.policy_generation,
            action: AccountOperation::CreatePrepared,
            old_key: None,
            new_key: Some(key),
            contact_digest: policy.contact_digest,
        };
        Ok((
            Self {
                ca_class: policy.ca_class,
                generation: 0,
                directory_generation: directory.generation,
                policy_generation: policy.policy_generation,
                account_url: None,
                key,
                contact_digest: policy.contact_digest,
                active: false,
                operation: AccountOperation::CreatePrepared,
                prepared: Some(prepared),
            },
            prepared,
        ))
    }

    pub fn commit_created(
        &mut self,
        receipt: PreparedAccountAction,
        account_url: AcmeUrl,
        directory: &AcmeDirectory,
    ) -> Result<(), AccountError> {
        self.require_prepared(receipt, AccountOperation::CreatePrepared)?;
        account_url
            .require_origin(directory.new_account.origin())
            .map_err(|_| AccountError::AccountUrlPolicy)?;
        self.account_url = Some(account_url);
        self.generation = receipt.account_generation;
        self.active = true;
        self.operation = AccountOperation::None;
        self.prepared = None;
        Ok(())
    }

    pub fn prepare_contact_update(
        &mut self,
        contact_digest: [u8; 32],
        policy_generation: u64,
    ) -> Result<PreparedAccountAction, AccountError> {
        self.require_idle_active()?;
        if policy_generation <= self.policy_generation {
            return Err(AccountError::StaleGeneration);
        }
        let prepared = PreparedAccountAction {
            account_generation: self
                .generation
                .checked_add(1)
                .ok_or(AccountError::StaleGeneration)?,
            directory_generation: self.directory_generation,
            policy_generation,
            action: AccountOperation::ContactUpdatePrepared,
            old_key: Some(self.key),
            new_key: Some(self.key),
            contact_digest,
        };
        self.operation = prepared.action;
        self.prepared = Some(prepared);
        Ok(prepared)
    }

    pub fn prepare_rollover(
        &mut self,
        new_key: &P256Jwk,
        policy_generation: u64,
    ) -> Result<PreparedAccountAction, AccountError> {
        self.require_idle_active()?;
        if policy_generation < self.policy_generation {
            return Err(AccountError::StaleGeneration);
        }
        let new_key = new_key
            .thumbprint()
            .map_err(|_| AccountError::InvalidState)?;
        if new_key == self.key {
            return Err(AccountError::InvalidState);
        }
        let prepared = PreparedAccountAction {
            account_generation: self
                .generation
                .checked_add(1)
                .ok_or(AccountError::StaleGeneration)?,
            directory_generation: self.directory_generation,
            policy_generation,
            action: AccountOperation::RolloverPrepared,
            old_key: Some(self.key),
            new_key: Some(new_key),
            contact_digest: self.contact_digest,
        };
        self.operation = prepared.action;
        self.prepared = Some(prepared);
        Ok(prepared)
    }

    pub fn prepare_deactivation(
        &mut self,
        policy_generation: u64,
    ) -> Result<PreparedAccountAction, AccountError> {
        self.require_idle_active()?;
        if policy_generation < self.policy_generation {
            return Err(AccountError::StaleGeneration);
        }
        let prepared = PreparedAccountAction {
            account_generation: self
                .generation
                .checked_add(1)
                .ok_or(AccountError::StaleGeneration)?,
            directory_generation: self.directory_generation,
            policy_generation,
            action: AccountOperation::DeactivationPrepared,
            old_key: Some(self.key),
            new_key: None,
            contact_digest: self.contact_digest,
        };
        self.operation = prepared.action;
        self.prepared = Some(prepared);
        Ok(prepared)
    }

    pub fn commit(&mut self, receipt: PreparedAccountAction) -> Result<(), AccountError> {
        let action = receipt.action;
        self.require_prepared(receipt, action)?;
        match action {
            AccountOperation::ContactUpdatePrepared => self.contact_digest = receipt.contact_digest,
            AccountOperation::RolloverPrepared => {
                self.key = receipt.new_key.ok_or(AccountError::ReceiptMismatch)?
            }
            AccountOperation::DeactivationPrepared => self.active = false,
            _ => return Err(AccountError::InvalidState),
        }
        self.generation = receipt.account_generation;
        self.policy_generation = receipt.policy_generation;
        self.operation = AccountOperation::None;
        self.prepared = None;
        Ok(())
    }

    pub fn mark_uncertain(&mut self) -> Result<(), AccountError> {
        if self.prepared.is_none() {
            return Err(AccountError::InvalidState);
        }
        self.operation = AccountOperation::Uncertain;
        Ok(())
    }

    pub fn abort_prepared(&mut self, receipt: PreparedAccountAction) -> Result<(), AccountError> {
        self.require_prepared(receipt, receipt.action)?;
        self.operation = AccountOperation::None;
        self.prepared = None;
        Ok(())
    }

    pub fn abort_uncertain(&mut self, receipt: PreparedAccountAction) -> Result<(), AccountError> {
        if self.operation != AccountOperation::Uncertain || self.prepared != Some(receipt) {
            return Err(AccountError::ReceiptMismatch);
        }
        self.operation = AccountOperation::None;
        self.prepared = None;
        Ok(())
    }

    pub fn resolve_created_authoritative(
        &mut self,
        receipt: PreparedAccountAction,
        account_url: AcmeUrl,
        directory: &AcmeDirectory,
        contact_digest: [u8; 32],
    ) -> Result<(), AccountError> {
        if self.operation != AccountOperation::Uncertain
            || self.prepared != Some(receipt)
            || receipt.action != AccountOperation::CreatePrepared
            || receipt.account_generation != 1
            || receipt.new_key != Some(self.key)
            || receipt.contact_digest != contact_digest
        {
            return Err(AccountError::ResolutionMismatch);
        }
        account_url
            .require_origin(directory.new_account.origin())
            .map_err(|_| AccountError::AccountUrlPolicy)?;
        self.account_url = Some(account_url);
        self.resolve_authoritative(1, true, self.key, contact_digest)
    }

    pub fn resolve_authoritative(
        &mut self,
        authoritative_generation: u64,
        active: bool,
        key: JwkThumbprint,
        contact_digest: [u8; 32],
    ) -> Result<(), AccountError> {
        let prepared = self.prepared.ok_or(AccountError::InvalidState)?;
        if self.operation != AccountOperation::Uncertain {
            return Err(AccountError::InvalidState);
        }
        if authoritative_generation == self.generation {
            if active != self.active || key != self.key || contact_digest != self.contact_digest {
                return Err(AccountError::ResolutionMismatch);
            }
            self.operation = AccountOperation::None;
            self.prepared = None;
            return Ok(());
        }
        if authoritative_generation != prepared.account_generation {
            return Err(AccountError::ResolutionMismatch);
        }
        let expected_key = prepared
            .new_key
            .or(prepared.old_key)
            .ok_or(AccountError::ResolutionMismatch)?;
        if expected_key != key || prepared.contact_digest != contact_digest {
            return Err(AccountError::ResolutionMismatch);
        }
        self.generation = authoritative_generation;
        self.active = active;
        self.key = key;
        self.contact_digest = contact_digest;
        self.policy_generation = prepared.policy_generation;
        self.operation = AccountOperation::None;
        self.prepared = None;
        Ok(())
    }

    fn require_idle_active(&self) -> Result<(), AccountError> {
        if self.active && self.operation == AccountOperation::None && self.prepared.is_none() {
            Ok(())
        } else {
            Err(AccountError::InvalidState)
        }
    }
    fn require_prepared(
        &self,
        receipt: PreparedAccountAction,
        action: AccountOperation,
    ) -> Result<(), AccountError> {
        if self.operation != action || self.prepared != Some(receipt) {
            Err(AccountError::ReceiptMismatch)
        } else if Some(receipt.account_generation) != self.generation.checked_add(1)
            || receipt.directory_generation != self.directory_generation
        {
            Err(AccountError::StaleGeneration)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(last: u8) -> P256Jwk {
        let (x, y) = if last == 1 {
            (
                [
                    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
                    0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1,
                    0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
                ],
                [
                    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c,
                    0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6,
                    0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
                ],
            )
        } else {
            (
                [
                    0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e, 0x8a, 0x52, 0x38, 0x03, 0x04,
                    0xb5, 0x1a, 0xc3, 0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35, 0xa6, 0x0b,
                    0x48, 0xfc, 0x47, 0x66, 0x99, 0x78,
                ],
                [
                    0x07, 0x77, 0x55, 0x10, 0xdb, 0x8e, 0xd0, 0x40, 0x29, 0x3d, 0x9a, 0xc6, 0x9f,
                    0x74, 0x30, 0xdb, 0xba, 0x7d, 0xad, 0xe6, 0x3c, 0xe9, 0x82, 0x29, 0x9e, 0x04,
                    0xb7, 0x9d, 0x22, 0x78, 0x73, 0xd1,
                ],
            )
        };
        P256Jwk::from_coordinates(x, y).unwrap()
    }
    fn directory() -> AcmeDirectory {
        AcmeDirectory::parse(r#"{"newNonce":"https://ca.example/n","newAccount":"https://ca.example/a","newOrder":"https://ca.example/o","revokeCert":"https://ca.example/r","keyChange":"https://ca.example/k"}"#,&AcmeUrl::parse("https://ca.example/d",false).unwrap(),4).unwrap()
    }
    #[test]
    fn create_rollover_and_uncertain_resolution_are_generation_bound() {
        let d = directory();
        let policy = AccountPolicy {
            ca_class: CaClass::Staging,
            policy_generation: 2,
            contact_digest: [3; 32],
        };
        let (mut account, receipt) =
            AccountLifecycle::prepare_create(&d, policy, &key(1), None, false).unwrap();
        account
            .commit_created(
                receipt,
                AcmeUrl::parse("https://ca.example/acct/1", false).unwrap(),
                &d,
            )
            .unwrap();
        let rollover = account.prepare_rollover(&key(2), 3).unwrap();
        account.mark_uncertain().unwrap();
        account
            .resolve_authoritative(
                rollover.account_generation,
                true,
                rollover.new_key.unwrap(),
                rollover.contact_digest,
            )
            .unwrap();
        assert_eq!(account.generation, 2);
        assert!(account.active);
        assert_eq!(account.operation, AccountOperation::None);
    }
    #[test]
    fn eab_and_terms_fail_closed_when_required() {
        let d=AcmeDirectory::parse(r#"{"newNonce":"https://ca.example/n","newAccount":"https://ca.example/a","newOrder":"https://ca.example/o","revokeCert":"https://ca.example/r","keyChange":"https://ca.example/k","meta":{"termsOfService":"https://legal.example/t","externalAccountRequired":true}}"#,&AcmeUrl::parse("https://ca.example/d",false).unwrap(),4).unwrap();
        let policy = AccountPolicy {
            ca_class: CaClass::Production,
            policy_generation: 1,
            contact_digest: [0; 32],
        };
        assert!(matches!(
            AccountLifecycle::prepare_create(&d, policy, &key(1), None, false),
            Err(AccountError::TermsApprovalRequired)
        ));
        let wrong = OwnerTermsApproval::new(3, &d.terms_of_service.unwrap(), b"terms");
        assert!(matches!(
            AccountLifecycle::prepare_create(&d, policy, &key(1), Some(&wrong), true),
            Err(AccountError::TermsApprovalMismatch)
        ));
        let approval = OwnerTermsApproval::new(4, &d.terms_of_service.unwrap(), b"terms");
        assert!(matches!(
            AccountLifecycle::prepare_create(&d, policy, &key(1), Some(&approval), false),
            Err(AccountError::ExternalAccountBindingRequired)
        ));
    }
}
