use core::net::IpAddr;
use core::str::FromStr;

pub const MAX_IP_IDENTIFIER_TEXT: usize = 39;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpIdentifierError {
    Empty,
    Invalid,
    ZoneIdentifierNotAllowed,
    OutputTooSmall,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct IpIdentifier {
    octets: [u8; 16],
    length: u8,
}

impl IpIdentifier {
    pub fn parse(input: &str) -> Result<Self, IpIdentifierError> {
        if input.is_empty() {
            return Err(IpIdentifierError::Empty);
        }
        if input.contains('%') {
            return Err(IpIdentifierError::ZoneIdentifierNotAllowed);
        }
        match IpAddr::from_str(input).map_err(|_| IpIdentifierError::Invalid)? {
            IpAddr::V4(address) => {
                let mut octets = [0; 16];
                octets[..4].copy_from_slice(&address.octets());
                Ok(Self { octets, length: 4 })
            }
            IpAddr::V6(address) => Ok(Self {
                octets: address.octets(),
                length: 16,
            }),
        }
    }

    pub const fn is_ipv4(&self) -> bool {
        self.length == 4
    }

    pub fn octets(&self) -> &[u8] {
        &self.octets[..usize::from(self.length)]
    }

    pub fn write_canonical<'a>(&self, output: &'a mut [u8]) -> Result<&'a str, IpIdentifierError> {
        let length = if self.is_ipv4() {
            write_ipv4(&self.octets[..4], output)?
        } else {
            write_ipv6(&self.octets, output)?
        };
        core::str::from_utf8(&output[..length]).map_err(|_| IpIdentifierError::Invalid)
    }
}

fn push(output: &mut [u8], cursor: &mut usize, byte: u8) -> Result<(), IpIdentifierError> {
    *output
        .get_mut(*cursor)
        .ok_or(IpIdentifierError::OutputTooSmall)? = byte;
    *cursor += 1;
    Ok(())
}

fn write_decimal(
    value: u8,
    output: &mut [u8],
    cursor: &mut usize,
) -> Result<(), IpIdentifierError> {
    if value >= 100 {
        push(output, cursor, b'0' + value / 100)?;
        push(output, cursor, b'0' + (value / 10) % 10)?;
    } else if value >= 10 {
        push(output, cursor, b'0' + value / 10)?;
    }
    push(output, cursor, b'0' + value % 10)
}

fn write_ipv4(octets: &[u8], output: &mut [u8]) -> Result<usize, IpIdentifierError> {
    let mut cursor = 0;
    for (index, octet) in octets.iter().enumerate() {
        if index != 0 {
            push(output, &mut cursor, b'.')?;
        }
        write_decimal(*octet, output, &mut cursor)?;
    }
    Ok(cursor)
}

fn write_ipv6(octets: &[u8; 16], output: &mut [u8]) -> Result<usize, IpIdentifierError> {
    let mut words = [0u16; 8];
    for (index, word) in words.iter_mut().enumerate() {
        *word = u16::from_be_bytes([octets[index * 2], octets[index * 2 + 1]]);
    }
    let mut best_start = 8;
    let mut best_len = 0;
    let mut index = 0;
    while index < words.len() {
        if words[index] != 0 {
            index += 1;
            continue;
        }
        let start = index;
        while index < words.len() && words[index] == 0 {
            index += 1;
        }
        if index - start > best_len && index - start >= 2 {
            best_start = start;
            best_len = index - start;
        }
    }

    let mut cursor = 0;
    index = 0;
    while index < words.len() {
        if index == best_start {
            push(output, &mut cursor, b':')?;
            push(output, &mut cursor, b':')?;
            index += best_len;
            continue;
        }
        if index != 0 && index != best_start + best_len {
            push(output, &mut cursor, b':')?;
        }
        let word = words[index];
        let first_nibble = if word >= 0x1000 {
            3
        } else if word >= 0x100 {
            2
        } else if word >= 0x10 {
            1
        } else {
            0
        };
        for shift in (0..=first_nibble).rev() {
            let nibble = ((word >> (shift * 4)) & 0xf) as u8;
            push(
                output,
                &mut cursor,
                if nibble < 10 {
                    b'0' + nibble
                } else {
                    b'a' + nibble - 10
                },
            )?;
        }
        index += 1;
    }
    Ok(cursor)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical(input: &str) -> Result<([u8; MAX_IP_IDENTIFIER_TEXT], usize), IpIdentifierError> {
        let identifier = IpIdentifier::parse(input)?;
        let mut output = [0; MAX_IP_IDENTIFIER_TEXT];
        let length = identifier.write_canonical(&mut output)?.len();
        Ok((output, length))
    }

    #[test]
    fn normalizes_ipv4_and_ipv6_without_ambiguous_forms() {
        let (v4, length) = canonical("192.0.2.1").unwrap();
        assert_eq!(&v4[..length], b"192.0.2.1");
        let (v6, length) = canonical("2001:0DB8:0:0:0:0:0:1").unwrap();
        assert_eq!(&v6[..length], b"2001:db8::1");
        let (unspecified, length) = canonical("0:0:0:0:0:0:0:0").unwrap();
        assert_eq!(&unspecified[..length], b"::");
    }

    #[test]
    fn rejects_ports_brackets_zones_and_noncanonical_ipv4_syntax() {
        for invalid in [
            "",
            "192.0.2.1:443",
            "[2001:db8::1]",
            "fe80::1%eth0",
            "192.168.001.1",
        ] {
            assert!(IpIdentifier::parse(invalid).is_err());
        }
    }

    #[test]
    fn canonical_output_is_bounded() {
        let identifier =
            IpIdentifier::parse("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255").unwrap();
        let mut output = [0; MAX_IP_IDENTIFIER_TEXT];
        assert_eq!(identifier.write_canonical(&mut output).unwrap().len(), 39);
        assert_eq!(
            identifier.write_canonical(&mut output[..38]),
            Err(IpIdentifierError::OutputTooSmall)
        );
    }
}
