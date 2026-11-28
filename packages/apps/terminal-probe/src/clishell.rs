//! Fixed-size line shell. Only the built-in echo command is recognized.

use crate::Key;

const LIMIT: usize = 32;
const UNKNOWN: [char; 15] = [
    'U', 'N', 'K', 'N', 'O', 'W', 'N', ' ', 'C', 'O', 'M', 'M', 'A', 'N', 'D',
];

pub struct CliShell {
    input: [char; LIMIT],
    input_len: usize,
    output: [char; LIMIT],
    output_len: usize,
}

impl Default for CliShell {
    fn default() -> Self {
        Self::new()
    }
}

impl CliShell {
    pub const fn new() -> Self {
        Self {
            input: [' '; LIMIT],
            input_len: 0,
            output: [' '; LIMIT],
            output_len: 0,
        }
    }

    /// Current editable command line, without the prompt.
    pub fn input(&self) -> &[char] {
        &self.input[..self.input_len]
    }

    /// Most recent command output, without the implicit line break.
    pub fn output(&self) -> &[char] {
        &self.output[..self.output_len]
    }

    pub fn key(&mut self, key: Key) {
        match key {
            Key::Text(ch) if (' '..='~').contains(&ch) && self.input_len < LIMIT => {
                self.input[self.input_len] = ch;
                self.input_len += 1;
            }
            Key::Backspace if self.input_len != 0 => {
                self.input_len -= 1;
                self.input[self.input_len] = ' ';
            }
            Key::Enter => self.submit(),
            _ => {}
        }
    }

    fn submit(&mut self) {
        let line = &self.input[..self.input_len];
        self.output.fill(' ');
        self.output_len = 0;
        if let Some(start) = line.iter().position(|&ch| ch != ' ') {
            let line = &line[start..];
            let end = line.iter().position(|&ch| ch == ' ').unwrap_or(line.len());
            let (command, rest) = line.split_at(end);
            let echo = command.len() == 4
                && command
                    .iter()
                    .map(char::to_ascii_lowercase)
                    .eq(['e', 'c', 'h', 'o']);
            let result = if echo {
                // There are no expansions, escapes, flags, operators, or external
                // commands: the remainder of the line is just printable text.
                let first = rest.iter().position(|&ch| ch != ' ').unwrap_or(rest.len());
                &rest[first..]
            } else {
                &UNKNOWN[..]
            };
            self.output_len = result.len();
            self.output[..self.output_len].copy_from_slice(result);
        }
        self.input.fill(' ');
        self.input_len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::string::String;

    fn type_line(shell: &mut CliShell, line: &str) {
        for ch in line.chars() {
            shell.key(Key::Text(ch));
        }
    }

    #[test]
    fn only_echo_executes_and_treats_arguments_as_text() {
        let mut shell = CliShell::new();
        type_line(&mut shell, " ECHO   a | b; $x > y");
        assert!(shell.output().is_empty());
        shell.key(Key::Enter);
        assert_eq!(shell.output().iter().collect::<String>(), "a | b; $x > y");
        assert!(shell.input().is_empty());
        type_line(&mut shell, "echoes hello");
        shell.key(Key::Enter);
        assert_eq!(shell.output(), UNKNOWN);
        type_line(&mut shell, "echo");
        shell.key(Key::Enter);
        assert!(shell.output().is_empty());
    }

    #[test]
    fn line_length_ascii_and_edits_are_bounded() {
        let mut shell = CliShell::new();
        shell.key(Key::Backspace);
        type_line(&mut shell, "é\n\u{1b}echo ");
        for _ in 0..100 {
            shell.key(Key::Text('x'));
        }
        assert_eq!(shell.input().len(), LIMIT);
        shell.key(Key::Backspace);
        shell.key(Key::Text('y'));
        shell.key(Key::Enter);
        assert_eq!(&shell.output()[..26], &['x'; 26]);
        assert_eq!(shell.output()[26], 'y');
        shell.key(Key::Enter);
        assert!(shell.output().is_empty());
    }
}
