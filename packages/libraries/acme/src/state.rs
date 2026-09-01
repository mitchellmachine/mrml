#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateError {
    InvalidTransition,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountState {
    PendingOwnerTerms,
    Active,
    KeyRolloverPrepared,
    DeactivationPrepared,
    Deactivated,
}
impl AccountState {
    pub fn transition(self, next: Self) -> Result<Self, StateError> {
        use AccountState::*;
        match (self, next) {
            (PendingOwnerTerms, Active)
            | (Active, KeyRolloverPrepared)
            | (KeyRolloverPrepared, Active)
            | (Active, DeactivationPrepared)
            | (DeactivationPrepared, Deactivated) => Ok(next),
            _ => Err(StateError::InvalidTransition),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrderState {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
}
impl OrderState {
    pub fn transition(self, next: Self) -> Result<Self, StateError> {
        use OrderState::*;
        match (self, next) {
            (Pending, Pending | Ready | Invalid | Deactivated | Expired)
            | (Ready, Ready | Processing | Invalid | Deactivated | Expired)
            | (Processing, Processing | Valid | Invalid)
            | (Valid, Valid | Revoked)
            | (Invalid, Invalid)
            | (Deactivated, Deactivated)
            | (Expired, Expired)
            | (Revoked, Revoked) => Ok(next),
            _ => Err(StateError::InvalidTransition),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_states_do_not_resurrect() {
        assert_eq!(
            OrderState::Invalid.transition(OrderState::Pending),
            Err(StateError::InvalidTransition)
        );
        assert_eq!(
            OrderState::Valid.transition(OrderState::Revoked),
            Ok(OrderState::Revoked)
        );
    }
    #[test]
    fn account_rollover_is_prepared() {
        assert_eq!(
            AccountState::Active
                .transition(AccountState::KeyRolloverPrepared)
                .unwrap()
                .transition(AccountState::Active),
            Ok(AccountState::Active)
        );
        assert_eq!(
            AccountState::Active.transition(AccountState::Deactivated),
            Err(StateError::InvalidTransition)
        );
    }
}
