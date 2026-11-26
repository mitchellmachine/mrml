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
    read_secret_with(maximum, read_native)
}

fn read_secret_with(
    maximum: usize,
    mut read_native: impl FnMut(&mut [u8]) -> Option<usize>,
) -> Result<Vector<u8>, StdinError> {
    if maximum == 0 || maximum > 4096 {
        return Err(StdinError::TooLarge);
    }
    // Reserve before reading any bytes, so growing the buffer cannot leave
    // prior copies of received secrets in abandoned heap allocations.
    let mut bytes = Vector::with_capacity(maximum).map_err(|_| StdinError::ReadFailed)?;
    let mut chunk = [0u8; 128];
    let result = loop {
        let Some(read) = read_native(&mut chunk).filter(|&read| read <= chunk.len()) else {
            break Err(StdinError::ReadFailed);
        };
        if read == 0 {
            break Ok(());
        }
        if read > maximum - bytes.len() {
            break Err(StdinError::TooLarge);
        }
        let extended = bytes.try_extend_from_slice(&chunk[..read]);
        erase_read_buffer(&mut chunk);
        if extended.is_err() {
            break Err(StdinError::ReadFailed);
        }
    };
    erase_read_buffer(&mut chunk);
    if let Err(error) = result {
        erase_read_buffer(&mut bytes);
        return Err(error);
    }
    Ok(bytes)
}

// Kept local: mrml-crypto already depends on this runtime on hosted platforms.
fn erase_read_buffer(buffer: &mut [u8]) {
    for byte in buffer {
        // SAFETY: Byte is initialized, aligned and exclusively borrowed.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_secret_reads_clear_scratch_between_reads() {
        let mut call = 0;
        let secret = read_secret_with(4, |scratch| {
            assert!(scratch.iter().all(|&byte| byte == 0));
            call += 1;
            match call {
                1 => {
                    scratch[..4].copy_from_slice(b"test");
                    Some(4)
                }
                _ => Some(0),
            }
        })
        .unwrap();
        assert_eq!(&*secret, b"test");
    }

    #[test]
    fn bounded_secret_reads_reject_oversized_and_failed_reads() {
        assert_eq!(
            read_secret_with(1, |scratch| {
                scratch[..2].fill(7);
                Some(2)
            })
            .err(),
            Some(StdinError::TooLarge)
        );
        let mut first = true;
        assert_eq!(
            read_secret_with(2, |scratch| {
                let result = if first { Some(1) } else { None };
                scratch[0] = 7;
                first = false;
                result
            })
            .err(),
            Some(StdinError::ReadFailed)
        );
        assert_eq!(
            read_secret_with(1, |scratch| Some(scratch.len() + 1)).err(),
            Some(StdinError::ReadFailed)
        );
    }
}
