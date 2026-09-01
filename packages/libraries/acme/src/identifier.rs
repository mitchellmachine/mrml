pub const MAX_DNS_NAME: usize = 253;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentifierError {
    Empty,
    TooLong,
    EmptyLabel,
    LabelTooLong,
    InvalidCharacter,
    InvalidHyphen,
    WildcardNotAllowed,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DnsIdentifier {
    bytes: [u8; MAX_DNS_NAME],
    len: u8,
}

impl DnsIdentifier {
    pub fn parse(input: &str, allow_wildcard: bool) -> Result<Self, IdentifierError> {
        let input = input.strip_suffix('.').unwrap_or(input);
        if input.is_empty() {
            return Err(IdentifierError::Empty);
        }
        if input.len() > MAX_DNS_NAME {
            return Err(IdentifierError::TooLong);
        }
        if input == "*" {
            return Err(IdentifierError::WildcardNotAllowed);
        }
        let mut out = Self {
            bytes: [0; MAX_DNS_NAME],
            len: input.len() as u8,
        };
        let mut label_start = 0usize;
        for (index, byte) in input.bytes().enumerate() {
            let normalized = match byte {
                b'A'..=b'Z' => byte + (b'a' - b'A'),
                b'a'..=b'z' | b'0'..=b'9' | b'-' => byte,
                b'.' => {
                    Self::validate_label(
                        &out.bytes[label_start..index],
                        label_start == 0,
                        allow_wildcard,
                    )?;
                    label_start = index + 1;
                    byte
                }
                b'*' if index == 0 && allow_wildcard => byte,
                b'*' => return Err(IdentifierError::WildcardNotAllowed),
                _ => return Err(IdentifierError::InvalidCharacter),
            };
            out.bytes[index] = normalized;
        }
        Self::validate_label(
            &out.bytes[label_start..input.len()],
            label_start == 0,
            allow_wildcard,
        )?;
        Ok(out)
    }

    fn validate_label(
        label: &[u8],
        first: bool,
        allow_wildcard: bool,
    ) -> Result<(), IdentifierError> {
        if label.is_empty() {
            return Err(IdentifierError::EmptyLabel);
        }
        if label.len() > 63 {
            return Err(IdentifierError::LabelTooLong);
        }
        if label == b"*" {
            return if first && allow_wildcard {
                Ok(())
            } else {
                Err(IdentifierError::WildcardNotAllowed)
            };
        }
        if label[0] == b'-' || label[label.len() - 1] == b'-' {
            return Err(IdentifierError::InvalidHyphen);
        }
        Ok(())
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or("")
    }
    pub fn is_wildcard(&self) -> bool {
        self.as_str().starts_with("*.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonicalizes_ascii_dns_names() {
        assert_eq!(
            DnsIdentifier::parse("Git.MRML.CA.", false)
                .unwrap()
                .as_str(),
            "git.mrml.ca"
        );
    }
    #[test]
    fn rejects_ambiguous_names() {
        assert!(matches!(
            DnsIdentifier::parse("a..b", false),
            Err(IdentifierError::EmptyLabel)
        ));
        assert!(matches!(
            DnsIdentifier::parse("-a.example", false),
            Err(IdentifierError::InvalidHyphen)
        ));
        assert!(matches!(
            DnsIdentifier::parse("*.example", false),
            Err(IdentifierError::WildcardNotAllowed)
        ));
    }
    #[test]
    fn wildcard_is_explicit() {
        assert!(DnsIdentifier::parse("*.example", true)
            .unwrap()
            .is_wildcard());
        assert!(matches!(
            DnsIdentifier::parse("*", true),
            Err(IdentifierError::WildcardNotAllowed)
        ));
    }
}
