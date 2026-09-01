#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AriError {
    Reversed,
    Past,
    TooNarrow,
    Overflow,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenewalWindow {
    pub start: u64,
    pub end: u64,
}
impl RenewalWindow {
    pub fn validate(start: u64, end: u64, now: u64, minimum_width: u64) -> Result<Self, AriError> {
        if end <= start {
            return Err(AriError::Reversed);
        }
        if end <= now {
            return Err(AriError::Past);
        }
        if end - start < minimum_width {
            return Err(AriError::TooNarrow);
        }
        Ok(Self {
            start: start.max(now),
            end,
        })
    }
    pub fn select(&self, random: u64) -> Result<u64, AriError> {
        let width = self.end.checked_sub(self.start).ok_or(AriError::Reversed)?;
        if width == 0 {
            return Err(AriError::TooNarrow);
        }
        Ok(self.start + (random % width))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_bad_windows_and_selects_inside() {
        assert_eq!(
            RenewalWindow::validate(20, 10, 0, 1),
            Err(AriError::Reversed)
        );
        assert_eq!(RenewalWindow::validate(1, 2, 3, 1), Err(AriError::Past));
        let w = RenewalWindow::validate(10, 20, 12, 2).unwrap();
        assert_eq!(w.select(99), Ok(15));
    }
}
