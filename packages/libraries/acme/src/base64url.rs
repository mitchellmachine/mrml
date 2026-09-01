#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Base64UrlError {
    PaddingForbidden,
    InvalidCharacter,
    InvalidLength,
    NonCanonical,
    OutputTooSmall,
    LengthOverflow,
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn encode_base64url<'a>(input: &[u8], output: &'a mut [u8]) -> Result<&'a str, Base64UrlError> {
    let groups = input
        .len()
        .checked_add(2)
        .ok_or(Base64UrlError::LengthOverflow)?
        / 3;
    let padded = groups
        .checked_mul(4)
        .ok_or(Base64UrlError::LengthOverflow)?;
    let omitted = match input.len() % 3 {
        0 => 0,
        1 => 2,
        _ => 1,
    };
    let needed = padded
        .checked_sub(omitted)
        .ok_or(Base64UrlError::LengthOverflow)?;
    if output.len() < needed {
        return Err(Base64UrlError::OutputTooSmall);
    }
    let mut read = 0usize;
    let mut written = 0usize;
    while read + 3 <= input.len() {
        let value = (u32::from(input[read]) << 16)
            | (u32::from(input[read + 1]) << 8)
            | u32::from(input[read + 2]);
        output[written] = ALPHABET[((value >> 18) & 63) as usize];
        output[written + 1] = ALPHABET[((value >> 12) & 63) as usize];
        output[written + 2] = ALPHABET[((value >> 6) & 63) as usize];
        output[written + 3] = ALPHABET[(value & 63) as usize];
        read += 3;
        written += 4;
    }
    if input.len() - read == 1 {
        let value = u16::from(input[read]) << 4;
        output[written] = ALPHABET[((value >> 6) & 63) as usize];
        output[written + 1] = ALPHABET[(value & 63) as usize];
    } else if input.len() - read == 2 {
        let value = (u32::from(input[read]) << 10) | (u32::from(input[read + 1]) << 2);
        output[written] = ALPHABET[((value >> 12) & 63) as usize];
        output[written + 1] = ALPHABET[((value >> 6) & 63) as usize];
        output[written + 2] = ALPHABET[(value & 63) as usize];
    }
    core::str::from_utf8(&output[..needed]).map_err(|_| Base64UrlError::InvalidCharacter)
}

fn value(byte: u8) -> Result<u8, Base64UrlError> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'-' => Ok(62),
        b'_' => Ok(63),
        b'=' => Err(Base64UrlError::PaddingForbidden),
        _ => Err(Base64UrlError::InvalidCharacter),
    }
}

pub fn decode_base64url<'a>(input: &str, output: &'a mut [u8]) -> Result<&'a [u8], Base64UrlError> {
    if input.len() % 4 == 1 {
        return Err(Base64UrlError::InvalidLength);
    }
    let needed = input
        .len()
        .checked_mul(3)
        .ok_or(Base64UrlError::LengthOverflow)?
        / 4;
    if output.len() < needed {
        return Err(Base64UrlError::OutputTooSmall);
    }
    let bytes = input.as_bytes();
    let mut read = 0usize;
    let mut written = 0usize;
    while read + 4 <= bytes.len() {
        let a = value(bytes[read])?;
        let b = value(bytes[read + 1])?;
        let c = value(bytes[read + 2])?;
        let d = value(bytes[read + 3])?;
        output[written] = (a << 2) | (b >> 4);
        output[written + 1] = (b << 4) | (c >> 2);
        output[written + 2] = (c << 6) | d;
        read += 4;
        written += 3;
    }
    match bytes.len() - read {
        0 => {}
        2 => {
            let a = value(bytes[read])?;
            let b = value(bytes[read + 1])?;
            if b & 0x0f != 0 {
                return Err(Base64UrlError::NonCanonical);
            }
            output[written] = (a << 2) | (b >> 4);
        }
        3 => {
            let a = value(bytes[read])?;
            let b = value(bytes[read + 1])?;
            let c = value(bytes[read + 2])?;
            if c & 0x03 != 0 {
                return Err(Base64UrlError::NonCanonical);
            }
            output[written] = (a << 2) | (b >> 4);
            output[written + 1] = (b << 4) | (c >> 2);
        }
        _ => return Err(Base64UrlError::InvalidLength),
    }
    Ok(&output[..needed])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc4648_vectors() {
        for (input, expected) in [
            (b"".as_slice(), ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foobar", "Zm9vYmFy"),
        ] {
            let mut encoded = [0u8; 16];
            assert_eq!(encode_base64url(input, &mut encoded), Ok(expected));
            let mut decoded = [0u8; 16];
            assert_eq!(decode_base64url(expected, &mut decoded).unwrap(), input);
        }
    }
    #[test]
    fn rejects_padding_and_noncanonical_tail() {
        let mut out = [0u8; 8];
        assert_eq!(
            decode_base64url("Zg==", &mut out),
            Err(Base64UrlError::PaddingForbidden)
        );
        assert_eq!(
            decode_base64url("Zh", &mut out),
            Err(Base64UrlError::NonCanonical)
        );
        assert_eq!(
            decode_base64url("A", &mut out),
            Err(Base64UrlError::InvalidLength)
        );
    }
}
