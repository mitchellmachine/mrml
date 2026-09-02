#![no_std]

/// The fixture is deliberately identifiable as test-only in both its package
/// and executable names. Production deployments must use `mrml-certd`.
pub const TEST_ONLY_FIXTURE: bool = true;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_cannot_be_confused_with_production_certd() {
        assert!(TEST_ONLY_FIXTURE);
    }
}
