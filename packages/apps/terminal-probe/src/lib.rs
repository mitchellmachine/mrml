#![no_std]
#![forbid(unsafe_code)]

//! Bounded terminal display and echo-only shell.

mod clishell;
pub use clishell::CliShell;

const COLUMNS: usize = 48;
const ROWS: usize = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Key {
    Text(char),
    Backspace,
    Enter,
}

pub struct Terminal {
    lines: [[char; COLUMNS]; ROWS],
    lengths: [usize; ROWS],
    row: usize,
}

impl Default for Terminal {
    fn default() -> Self {
        Self::new()
    }
}

impl Terminal {
    pub const fn new() -> Self {
        Self {
            lines: [[' '; COLUMNS]; ROWS],
            lengths: [0; ROWS],
            row: 0,
        }
    }

    pub fn rows(&self) -> impl Iterator<Item = &[char]> {
        self.lines[..=self.row]
            .iter()
            .zip(&self.lengths)
            .map(|(line, &len)| &line[..len])
    }

    pub fn key(&mut self, key: Key) {
        let column = self.lengths[self.row];
        match key {
            Key::Text(ch) if !ch.is_control() && column < COLUMNS => {
                self.lines[self.row][column] = ch;
                self.lengths[self.row] += 1;
            }
            Key::Backspace if column > 0 => {
                self.lengths[self.row] -= 1;
                self.lines[self.row][column - 1] = ' ';
            }
            Key::Enter => {
                if self.row + 1 == ROWS {
                    self.lines.rotate_left(1);
                    self.lengths.rotate_left(1);
                } else {
                    self.row += 1;
                }
                self.lines[self.row].fill(' ');
                self.lengths[self.row] = 0;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_edits_unicode_and_keeps_only_six_bounded_lines() {
        let mut app = Terminal::new();
        app.key(Key::Text('é'));
        app.key(Key::Text('λ'));
        app.key(Key::Backspace);
        app.key(Key::Text('\u{1b}'));
        assert_eq!(app.rows().next(), Some(&['é'][..]));
        for ch in 'a'..='h' {
            app.key(Key::Enter);
            app.key(Key::Text(ch));
        }
        assert_eq!(app.rows().count(), 6);
        assert_eq!(app.rows().next(), Some(&['c'][..]));
        for _ in 0..100 {
            app.key(Key::Text('x'));
        }
        assert_eq!(app.rows().last().unwrap().len(), COLUMNS);
    }
}
