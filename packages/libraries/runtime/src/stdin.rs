use crate::{Text, Vector};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StdinError {
    ReadFailed,
    InvalidUtf8,
    TooLarge,
}

fn read_native(buffer: &mut [u8]) -> Option<usize> {
    #[cfg(windows)]
    {
        mrml_windows::read_stdin(buffer)
    }
    #[cfg(unix)]
    {
        mrml_linux::read_stdin(buffer)
    }
}

pub fn read_stdin_line() -> Result<Option<Text>, StdinError> {
    let mut bytes = Vector::new();
    let mut byte = [0u8; 1];
    loop {
        match read_native(&mut byte).ok_or(StdinError::ReadFailed)? {
            0 if bytes.is_empty() => return Ok(None),
            0 => break,
            _ if byte[0] == b'\n' => break,
            _ => bytes.push(byte[0]),
        }
        if bytes.len() > 1024 * 1024 {
            return Err(StdinError::TooLarge);
        }
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    Text::try_from_utf8(bytes)
        .map(Some)
        .map_err(|_| StdinError::InvalidUtf8)
}

pub fn read_stdin_to_end() -> Result<Text, StdinError> {
    let mut bytes = Vector::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = read_native(&mut chunk).ok_or(StdinError::ReadFailed)?;
        if read == 0 {
            break;
        }
        if bytes
            .len()
            .checked_add(read)
            .is_none_or(|length| length > 64 * 1024 * 1024)
        {
            return Err(StdinError::TooLarge);
        }
        bytes
            .try_extend_from_slice(&chunk[..read])
            .map_err(|_| StdinError::ReadFailed)?;
    }
    Text::try_from_utf8(bytes).map_err(|_| StdinError::InvalidUtf8)
}

/// Reads an exact, caller-bounded secret payload without converting it into
/// cloneable text. The caller remains responsible for volatile erasure.
pub fn read_stdin_secret_bounded(maximum: usize) -> Result<Vector<u8>, StdinError> {
    if maximum == 0 || maximum > 4096 {
        return Err(StdinError::TooLarge);
    }
    let mut bytes = Vector::new();
    let mut chunk = [0u8; 128];
    loop {
        let read = read_native(&mut chunk).ok_or(StdinError::ReadFailed)?;
        if read == 0 {
            break;
        }
        if bytes
            .len()
            .checked_add(read)
            .is_none_or(|length| length > maximum)
        {
            for byte in &mut bytes {
                unsafe { core::ptr::write_volatile(byte, 0) };
            }
            for byte in &mut chunk[..read] {
                unsafe { core::ptr::write_volatile(byte, 0) };
            }
            return Err(StdinError::TooLarge);
        }
        let extended = bytes
            .try_extend_from_slice(&chunk[..read])
            .map_err(|_| StdinError::ReadFailed);
        for byte in &mut chunk[..read] {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        if let Err(error) = extended {
            for byte in &mut bytes {
                unsafe { core::ptr::write_volatile(byte, 0) };
            }
            return Err(error);
        }
    }
    Ok(bytes)
}
