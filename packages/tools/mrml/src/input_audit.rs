use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

pub const MAX_AUDITED_SOURCE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BuildInputKind {
    NativeLink,
    CompileEnv,
    IncludedFile,
    ExternalCommand,
}

impl BuildInputKind {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "native-link" => Ok(Self::NativeLink),
            "compile-env" => Ok(Self::CompileEnv),
            "included-file" => Ok(Self::IncludedFile),
            "external-command" => Ok(Self::ExternalCommand),
            other => Err(format!("ManifestBuildInputInvalid {{ kind: {other} }}")),
        }
    }

    pub const fn token(self) -> &'static str {
        match self {
            Self::NativeLink => "native-link",
            Self::CompileEnv => "compile-env",
            Self::IncludedFile => "included-file",
            Self::ExternalCommand => "external-command",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclaredInputSite {
    pub id: String,
    pub kind: BuildInputKind,
    pub path: String,
    pub line: usize,
    pub fingerprint: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedInputSite {
    pub kind: BuildInputKind,
    pub path: String,
    pub line: usize,
    pub fingerprint: String,
    pub context: String,
    pub expression: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenKind {
    Identifier,
    Literal,
    Punctuation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Token {
    text: String,
    line: usize,
    kind: TokenKind,
}

#[derive(Clone, Debug)]
struct Candidate {
    kind: BuildInputKind,
    line: usize,
    context: String,
    expression: String,
}

pub fn validate_declarations(
    package: &str,
    member: &str,
    root: &Path,
    declarations: &[DeclaredInputSite],
) -> Result<(), String> {
    let mut ids = BTreeSet::new();
    let mut sites = BTreeSet::new();
    let member_prefix = format!("{member}/");
    for declaration in declarations {
        if !valid_site_id(&declaration.id) {
            return Err(format!(
                "ManifestBuildInputIdInvalid {{ package: {package}, id: {} }}",
                declaration.id
            ));
        }
        if !ids.insert(declaration.id.as_str()) {
            return Err(format!(
                "ManifestBuildInputIdDuplicate {{ package: {package}, id: {} }}",
                declaration.id
            ));
        }
        if !declaration.path.starts_with(&member_prefix)
            || !safe_relative_source_path(&declaration.path)
            || !root.join(&declaration.path).is_file()
        {
            return Err(format!(
                "ManifestBuildInputPathInvalid {{ package: {package}, id: {}, path: {} }}",
                declaration.id, declaration.path
            ));
        }
        if declaration.line == 0 {
            return Err(format!(
                "ManifestBuildInputLineInvalid {{ package: {package}, id: {} }}",
                declaration.id
            ));
        }
        if !valid_fingerprint(&declaration.fingerprint) {
            return Err(format!(
                "ManifestBuildInputFingerprintInvalid {{ package: {package}, id: {}, fingerprint: {} }}",
                declaration.id, declaration.fingerprint
            ));
        }
        let reason = declaration.reason.trim();
        if reason.len() < 16
            || matches!(
                reason,
                "reviewed repository build input" | "migrated v1 declared input"
            )
        {
            return Err(format!(
                "ManifestBuildInputReasonInvalid {{ package: {package}, id: {} }}",
                declaration.id
            ));
        }
        let key = (
            declaration.kind,
            declaration.path.as_str(),
            declaration.fingerprint.as_str(),
        );
        if !sites.insert(key) {
            return Err(format!(
                "ManifestBuildInputSiteDuplicate {{ package: {package}, id: {} }}",
                declaration.id
            ));
        }
    }
    Ok(())
}

pub fn verify_declarations(
    package: &str,
    declarations: &[DeclaredInputSite],
    observed: &[ObservedInputSite],
) -> Result<(), String> {
    let mut declared_by_site = BTreeMap::new();
    for declaration in declarations {
        let key = (
            declaration.kind,
            declaration.path.as_str(),
            declaration.fingerprint.as_str(),
        );
        if declared_by_site.insert(key, declaration).is_some() {
            return Err(format!(
                "InputSiteDuplicateDeclaration {{ component: {package}, path: {}, fingerprint: {} }}",
                declaration.path, declaration.fingerprint
            ));
        }
    }

    let mut observed_sites = BTreeSet::new();
    for site in observed {
        let key = (site.kind, site.path.as_str(), site.fingerprint.as_str());
        if !observed_sites.insert(key) {
            return Err(format!(
                "InputSiteDuplicateObservation {{ component: {package}, kind: {}, path: {}, line: {}, fingerprint: {} }}",
                site.kind.token(),
                site.path,
                site.line,
                site.fingerprint
            ));
        }
        if !declared_by_site.contains_key(&key) {
            return Err(format!(
                "InputSiteUndeclared {{ component: {package}, kind: {}, path: {}, line: {}, fingerprint: {}, context: {}, expression: {} }}",
                site.kind.token(),
                site.path,
                site.line,
                site.fingerprint,
                clean_diagnostic(&site.context),
                clean_diagnostic(&site.expression)
            ));
        }
    }

    for declaration in declarations {
        let key = (
            declaration.kind,
            declaration.path.as_str(),
            declaration.fingerprint.as_str(),
        );
        if !observed_sites.contains(&key) {
            return Err(format!(
                "InputSiteStale {{ component: {package}, id: {}, kind: {}, path: {}, last_line: {}, fingerprint: {} }}",
                declaration.id,
                declaration.kind.token(),
                declaration.path,
                declaration.line,
                declaration.fingerprint
            ));
        }
    }
    Ok(())
}

pub fn scan_package(root: &Path, member: &str) -> Result<Vec<ObservedInputSite>, String> {
    let mut pending = vec![root.join(member)];
    let mut visited = 0_usize;
    let mut observed = Vec::new();
    while let Some(path) = pending.pop() {
        visited = visited.checked_add(1).ok_or("AuditPathCountOverflow")?;
        if visited > 20_000 {
            return Err(format!("AuditPathLimit {{ component: {member} }}"));
        }
        let mut entries: Vec<_> = fs::read_dir(&path)
            .map_err(|error| {
                format!(
                    "AuditReadDirectory {{ path: {}, detail: {error} }}",
                    clean_diagnostic(&path.display().to_string())
                )
            })?
            .collect::<Result<_, _>>()
            .map_err(|error| {
                format!(
                    "AuditReadDirectory {{ path: {}, detail: {error} }}",
                    clean_diagnostic(&path.display().to_string())
                )
            })?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let entry_path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|error| format!("AuditFileType {{ detail: {error} }}"))?;
            if file_type.is_symlink() {
                return Err(format!(
                    "AuditSymlinkRejected {{ path: {} }}",
                    clean_diagnostic(&entry_path.display().to_string())
                ));
            }
            if file_type.is_dir() {
                pending.push(entry_path);
            } else if entry_path.extension().and_then(|value| value.to_str()) == Some("rs") {
                observed.extend(scan_file(root, &entry_path)?);
            }
        }
    }
    observed.sort_by(|left, right| {
        (&left.path, left.line, left.kind, &left.fingerprint).cmp(&(
            &right.path,
            right.line,
            right.kind,
            &right.fingerprint,
        ))
    });
    Ok(observed)
}

fn scan_file(root: &Path, path: &Path) -> Result<Vec<ObservedInputSite>, String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("AuditFileMetadata {{ detail: {error} }}"))?;
    if metadata.len() > MAX_AUDITED_SOURCE_BYTES {
        return Err(format!(
            "AuditSourceTooLarge {{ path: {}, bytes: {}, limit: {} }}",
            clean_diagnostic(&path.display().to_string()),
            metadata.len(),
            MAX_AUDITED_SOURCE_BYTES
        ));
    }
    let text = fs::read_to_string(path)
        .map_err(|error| format!("AuditSourceRead {{ detail: {error} }}"))?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "AuditPathOutsideWorkspace")?
        .display()
        .to_string()
        .replace('\\', "/");
    Ok(scan_rust_source(&text)?
        .into_iter()
        .map(|mut site| {
            site.path = relative.clone();
            site
        })
        .collect())
}

fn scan_rust_source(text: &str) -> Result<Vec<ObservedInputSite>, String> {
    let tokens = lex(text)?;
    reject_process_command_aliases(&tokens)?;
    let contexts = function_contexts(&tokens);
    let attributes = attribute_flags(&tokens);
    let mut candidates = Vec::new();

    for (index, token) in tokens.iter().enumerate() {
        let matched = if token.kind == TokenKind::Identifier
            && token.text == "Command"
            && token_sequence(&tokens, index, &["Command", ":", ":", "new", "("])
        {
            Some((BuildInputKind::ExternalCommand, index + 4))
        } else if token.kind == TokenKind::Identifier
            && matches!(token.text.as_str(), "env" | "option_env")
            && token_sequence(&tokens, index, &[token.text.as_str(), "!", "("])
        {
            Some((BuildInputKind::CompileEnv, index + 2))
        } else if token.kind == TokenKind::Identifier
            && matches!(token.text.as_str(), "include_bytes" | "include_str")
            && token_sequence(&tokens, index, &[token.text.as_str(), "!", "("])
        {
            Some((BuildInputKind::IncludedFile, index + 2))
        } else if token.kind == TokenKind::Identifier
            && token.text == "link"
            && tokens.get(index + 1).is_some_and(|next| next.text == "(")
            && attributes[index]
        {
            Some((BuildInputKind::NativeLink, index + 1))
        } else {
            None
        };
        let Some((kind, open_parenthesis)) = matched else {
            continue;
        };
        let end = matching_parenthesis(&tokens, open_parenthesis)?;
        let expression = tokens[index..=end]
            .iter()
            .map(|item| item.text.as_str())
            .collect::<Vec<_>>()
            .join("\u{1f}");
        candidates.push(Candidate {
            kind,
            line: token.line,
            context: contexts[index].clone(),
            expression,
        });
    }

    let mut duplicates: BTreeMap<(BuildInputKind, String, String), usize> = BTreeMap::new();
    let mut observed = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let duplicate_key = (
            candidate.kind,
            candidate.context.clone(),
            candidate.expression.clone(),
        );
        let ordinal = duplicates.entry(duplicate_key).or_default();
        let material = format!(
            "{}\0{}\0{}\0{}",
            candidate.kind.token(),
            candidate.context,
            candidate.expression,
            *ordinal
        );
        *ordinal = ordinal.checked_add(1).ok_or("AuditCountOverflow")?;
        observed.push(ObservedInputSite {
            kind: candidate.kind,
            path: String::new(),
            line: candidate.line,
            fingerprint: format!("fnv1a64:{:016x}", fnv1a64(material.as_bytes())),
            context: candidate.context,
            expression: truncate_expression(&candidate.expression),
        });
    }
    Ok(observed)
}

fn reject_process_command_aliases(tokens: &[Token]) -> Result<(), String> {
    for (index, token) in tokens.iter().enumerate() {
        if token.text == "use" {
            let end = tokens[index..]
                .iter()
                .position(|candidate| candidate.text == ";")
                .map(|offset| index + offset)
                .unwrap_or(tokens.len());
            let statement = &tokens[index..end];
            let process_import = statement
                .iter()
                .any(|candidate| candidate.text == "process");
            if process_import {
                for (offset, candidate) in statement.iter().enumerate() {
                    if candidate.text == "Command"
                        && statement
                            .get(offset + 1)
                            .is_some_and(|next| next.text == "as")
                        && statement
                            .get(offset + 2)
                            .is_some_and(|alias| alias.text != "Command")
                    {
                        return Err(format!(
                            "AuditCommandAliasUnsupported {{ line: {} }}",
                            candidate.line
                        ));
                    }
                }
            }
        }
        if token.text == "type"
            && tokens
                .get(index + 1)
                .is_some_and(|candidate| candidate.kind == TokenKind::Identifier)
        {
            let end = tokens[index..]
                .iter()
                .position(|candidate| candidate.text == ";")
                .map(|offset| index + offset)
                .unwrap_or(tokens.len());
            let statement = &tokens[index..end];
            let has_assignment = statement.iter().any(|candidate| candidate.text == "=");
            let aliases_command = statement
                .iter()
                .any(|candidate| candidate.text == "Command");
            if has_assignment && aliases_command {
                return Err(format!(
                    "AuditCommandAliasUnsupported {{ line: {} }}",
                    token.line
                ));
            }
        }
    }
    Ok(())
}

fn lex(text: &str) -> Result<Vec<Token>, String> {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0_usize;
    let mut line = 1_usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            if byte == b'\n' {
                line = line.checked_add(1).ok_or("AuditLineOverflow")?;
            }
            index += 1;
            continue;
        }
        if bytes
            .get(index + 1)
            .is_some_and(|next| byte == b'/' && *next == b'/')
        {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if bytes
            .get(index + 1)
            .is_some_and(|next| byte == b'/' && *next == b'*')
        {
            index += 2;
            let mut depth = 1_usize;
            while index < bytes.len() && depth != 0 {
                if bytes
                    .get(index + 1)
                    .is_some_and(|next| bytes[index] == b'/' && *next == b'*')
                {
                    depth = depth.checked_add(1).ok_or("AuditCommentDepthOverflow")?;
                    index += 2;
                } else if bytes
                    .get(index + 1)
                    .is_some_and(|next| bytes[index] == b'*' && *next == b'/')
                {
                    depth -= 1;
                    index += 2;
                } else {
                    if bytes[index] == b'\n' {
                        line = line.checked_add(1).ok_or("AuditLineOverflow")?;
                    }
                    index += 1;
                }
            }
            if depth != 0 {
                return Err("AuditUnterminatedBlockComment".into());
            }
            continue;
        }
        if let Some(end) = raw_string_end(bytes, index)? {
            let literal = &text[index..end];
            tokens.push(Token {
                text: literal.to_owned(),
                line,
                kind: TokenKind::Literal,
            });
            line = line
                .checked_add(literal.bytes().filter(|value| *value == b'\n').count())
                .ok_or("AuditLineOverflow")?;
            index = end;
            continue;
        }
        if let Some(end) = normal_string_end(bytes, index)? {
            let literal = &text[index..end];
            tokens.push(Token {
                text: literal.to_owned(),
                line,
                kind: TokenKind::Literal,
            });
            line = line
                .checked_add(literal.bytes().filter(|value| *value == b'\n').count())
                .ok_or("AuditLineOverflow")?;
            index = end;
            continue;
        }
        if let Some(end) = character_literal_end(bytes, index) {
            tokens.push(Token {
                text: text[index..end].to_owned(),
                line,
                kind: TokenKind::Literal,
            });
            index = end;
            continue;
        }
        if ascii_identifier_start(byte) {
            let start = index;
            index += 1;
            while index < bytes.len() && ascii_identifier_continue(bytes[index]) {
                index += 1;
            }
            tokens.push(Token {
                text: text[start..index].to_owned(),
                line,
                kind: TokenKind::Identifier,
            });
            continue;
        }
        if byte.is_ascii_digit() {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (ascii_identifier_continue(bytes[index]) || bytes[index] == b'.')
            {
                index += 1;
            }
            tokens.push(Token {
                text: text[start..index].to_owned(),
                line,
                kind: TokenKind::Literal,
            });
            continue;
        }
        let character = text[index..]
            .chars()
            .next()
            .ok_or("AuditTokenizationFailure")?;
        tokens.push(Token {
            text: character.to_string(),
            line,
            kind: TokenKind::Punctuation,
        });
        index += character.len_utf8();
    }
    Ok(tokens)
}

fn raw_string_end(bytes: &[u8], start: usize) -> Result<Option<usize>, String> {
    if start != 0 && ascii_identifier_continue(bytes[start - 1]) {
        return Ok(None);
    }
    let mut index = start;
    if bytes.get(index..index + 2) == Some(&b"br"[..])
        || bytes.get(index..index + 2) == Some(&b"cr"[..])
    {
        index += 2;
    } else if bytes.get(index) == Some(&b'r') {
        index += 1;
    } else {
        return Ok(None);
    }
    let mut hashes = 0_usize;
    while bytes.get(index) == Some(&b'#') {
        hashes = hashes
            .checked_add(1)
            .ok_or("AuditRawStringDelimiterOverflow")?;
        index += 1;
    }
    if bytes.get(index) != Some(&b'"') {
        return Ok(None);
    }
    index += 1;
    while index < bytes.len() {
        if bytes[index] == b'"'
            && (0..hashes).all(|offset| bytes.get(index + 1 + offset) == Some(&b'#'))
        {
            return Ok(Some(index + 1 + hashes));
        }
        index += 1;
    }
    Err(format!("AuditUnterminatedRawString {{ byte: {start} }}"))
}

fn normal_string_end(bytes: &[u8], start: usize) -> Result<Option<usize>, String> {
    let mut quote = start;
    if (bytes.get(start) == Some(&b'b') || bytes.get(start) == Some(&b'c'))
        && bytes.get(start + 1) == Some(&b'"')
    {
        quote += 1;
    }
    if bytes.get(quote) != Some(&b'"') {
        return Ok(None);
    }
    let mut index = quote + 1;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return Ok(Some(index + 1));
        }
        index += 1;
    }
    Err(format!("AuditUnterminatedString {{ byte: {start} }}"))
}

fn character_literal_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut quote = start;
    if bytes.get(start) == Some(&b'b') && bytes.get(start + 1) == Some(&b'\'') {
        if start != 0 && ascii_identifier_continue(bytes[start - 1]) {
            return None;
        }
        quote += 1;
    }
    if bytes.get(quote) != Some(&b'\'') {
        return None;
    }
    let mut index = quote + 1;
    let byte = *bytes.get(index)?;
    if matches!(byte, b'\n' | b'\r' | b'\'') {
        return None;
    }
    if byte == b'\\' {
        index += 1;
        match *bytes.get(index)? {
            b'u' if bytes.get(index + 1) == Some(&b'{') => {
                index += 2;
                while bytes.get(index).copied() != Some(b'}') {
                    if matches!(bytes.get(index).copied(), None | Some(b'\n' | b'\r')) {
                        return None;
                    }
                    index += 1;
                }
                index += 1;
            }
            b'x' => index = index.checked_add(3)?,
            _ => index += 1,
        }
    } else {
        let width = utf8_scalar_width(byte)?;
        index = index.checked_add(width)?;
    }
    (bytes.get(index) == Some(&b'\'')).then_some(index + 1)
}

const fn utf8_scalar_width(first: u8) -> Option<usize> {
    if first < 0x80 {
        Some(1)
    } else if first & 0xe0 == 0xc0 {
        Some(2)
    } else if first & 0xf0 == 0xe0 {
        Some(3)
    } else if first & 0xf8 == 0xf0 {
        Some(4)
    } else {
        None
    }
}

fn ascii_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn ascii_identifier_continue(byte: u8) -> bool {
    ascii_identifier_start(byte) || byte.is_ascii_digit()
}

fn function_contexts(tokens: &[Token]) -> Vec<String> {
    let mut contexts = Vec::with_capacity(tokens.len());
    let mut brace_depth = 0_usize;
    let mut stack: Vec<(usize, String)> = Vec::new();
    let mut pending_function: Option<String> = None;
    for (index, token) in tokens.iter().enumerate() {
        contexts.push(
            stack
                .last()
                .map(|(_, name)| name.clone())
                .unwrap_or_else(|| "<module>".into()),
        );
        if token.text == "fn"
            && tokens
                .get(index + 1)
                .is_some_and(|next| next.kind == TokenKind::Identifier)
        {
            pending_function = tokens.get(index + 1).map(|next| next.text.clone());
        }
        match token.text.as_str() {
            "{" => {
                brace_depth += 1;
                if let Some(function) = pending_function.take() {
                    stack.push((brace_depth, function));
                }
            }
            "}" => {
                if stack.last().is_some_and(|(depth, _)| *depth == brace_depth) {
                    stack.pop();
                }
                brace_depth = brace_depth.saturating_sub(1);
            }
            ";" => {
                pending_function = None;
            }
            _ => {}
        }
    }
    contexts
}

fn attribute_flags(tokens: &[Token]) -> Vec<bool> {
    let mut flags = vec![false; tokens.len()];
    let mut depth = 0_usize;
    let mut pending_hash = false;
    for (index, token) in tokens.iter().enumerate() {
        flags[index] = depth != 0;
        if depth != 0 {
            if token.text == "[" {
                depth += 1;
            } else if token.text == "]" {
                depth -= 1;
            }
            continue;
        }
        if pending_hash {
            if token.text == "[" {
                depth = 1;
                flags[index] = true;
            }
            pending_hash = false;
        }
        if token.text == "#" {
            pending_hash = true;
        }
    }
    flags
}

fn token_sequence(tokens: &[Token], start: usize, expected: &[&str]) -> bool {
    tokens
        .get(start..start + expected.len())
        .is_some_and(|actual| {
            actual
                .iter()
                .zip(expected)
                .all(|(token, expected)| token.text == *expected)
        })
}

fn matching_parenthesis(tokens: &[Token], open: usize) -> Result<usize, String> {
    let mut depth = 0_usize;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        if token.text == "(" {
            depth = depth
                .checked_add(1)
                .ok_or("AuditParenthesisDepthOverflow")?;
        } else if token.text == ")" {
            if depth == 0 {
                return Err(format!(
                    "AuditParenthesisUnderflow {{ line: {} }}",
                    token.line
                ));
            }
            depth -= 1;
            if depth == 0 {
                return Ok(index);
            }
        }
    }
    Err(format!(
        "AuditUnterminatedInputExpression {{ line: {} }}",
        tokens.get(open).map_or(0, |token| token.line)
    ))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn truncate_expression(expression: &str) -> String {
    let normalized = expression.replace('\u{1f}', " ");
    let mut output = normalized.chars().take(180).collect::<String>();
    if normalized.chars().count() > 180 {
        output.push_str("...");
    }
    output
}

fn valid_site_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index != 0 && matches!(byte, b'.' | b'-' | b'_'))
        })
}

fn valid_fingerprint(value: &str) -> bool {
    value.strip_prefix("fnv1a64:").is_some_and(|digest| {
        digest.len() == 16
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn safe_relative_source_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && path.extension().and_then(|extension| extension.to_str()) == Some("rs")
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn clean_diagnostic(value: &str) -> String {
    value.trim().replace(['|', '='], "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sites(source: &str) -> Vec<ObservedInputSite> {
        scan_rust_source(source).expect("scan Rust source")
    }

    #[test]
    fn scanner_ignores_comments_strings_and_raw_strings() {
        let source = r###"
// Command::new("comment")
const SAMPLE: &str = "env!(\"STRING\")";
const RAW: &str = r#"include_bytes!(\"raw\")"#;
fn run() { let _ = Command::new("real"); }
"###;
        let found = sites(source);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, BuildInputKind::ExternalCommand);
    }

    #[test]
    fn scanner_accepts_multiline_sensitive_expressions() {
        let source = r#"
fn run() {
    let _ = Command
        :: new(
            "git"
        );
    let _ = include_bytes!(
        "fixture.bin"
    );
}
"#;
        let found = sites(source);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].kind, BuildInputKind::ExternalCommand);
        assert_eq!(found[1].kind, BuildInputKind::IncludedFile);
    }

    #[test]
    fn line_movement_does_not_change_fingerprint() {
        let first = sites("fn run() { let _ = Command::new(\"git\"); }");
        let second = sites("\n\nfn run() {\n let _ = Command :: new ( \"git\" );\n}");
        assert_eq!(first[0].fingerprint, second[0].fingerprint);
        assert_ne!(first[0].line, second[0].line);
    }

    #[test]
    fn same_count_substitution_changes_fingerprint() {
        let allowed = sites("fn run() { let _ = Command::new(\"git\"); }");
        let substituted = sites("fn run() { let _ = Command::new(\"sh\"); }");
        assert_eq!(allowed.len(), substituted.len());
        assert_ne!(allowed[0].fingerprint, substituted[0].fingerprint);
    }

    #[test]
    fn function_context_distinguishes_equal_expressions() {
        let found = sites(
            "fn first() { let _ = Command::new(program); }\nfn second() { let _ = Command::new(program); }",
        );
        assert_eq!(found.len(), 2);
        assert_ne!(found[0].fingerprint, found[1].fingerprint);
    }

    #[test]
    fn lifetimes_are_not_misclassified_as_character_literals() {
        let found = sites(
            "fn run<'a, 'b>(left: &'a str, right: &'b str) { let _ = (left, right, Command::new(\"git\")); }",
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, BuildInputKind::ExternalCommand);
    }

    #[test]
    fn process_command_aliases_fail_closed() {
        for source in [
            "use std::process::Command as Runner; fn run() { let _ = Runner::new(\"git\"); }",
            "use std::process::Command; type Runner = Command; fn run() { let _ = Runner::new(\"git\"); }",
        ] {
            assert!(
                scan_rust_source(source)
                    .unwrap_err()
                    .starts_with("AuditCommandAliasUnsupported")
            );
        }
    }

    #[test]
    fn exact_verification_rejects_substitution_stale_and_duplicate_sites() {
        let allowed = sites("fn run() { let _ = Command::new(\"git\"); }");
        let substituted = sites("fn run() { let _ = Command::new(\"sh\"); }");
        let declaration = DeclaredInputSite {
            id: "run-git".to_owned(),
            kind: allowed[0].kind,
            path: allowed[0].path.clone(),
            line: allowed[0].line,
            fingerprint: allowed[0].fingerprint.clone(),
            reason: "The test fixture admits one exact external tool invocation.".to_owned(),
        };
        assert_eq!(
            verify_declarations(
                "org.mrml.test",
                core::slice::from_ref(&declaration),
                &allowed
            ),
            Ok(())
        );
        assert!(
            verify_declarations(
                "org.mrml.test",
                core::slice::from_ref(&declaration),
                &substituted,
            )
            .unwrap_err()
            .starts_with("InputSiteUndeclared")
        );
        assert!(
            verify_declarations("org.mrml.test", core::slice::from_ref(&declaration), &[])
                .unwrap_err()
                .starts_with("InputSiteStale")
        );
        assert!(
            verify_declarations(
                "org.mrml.test",
                &[declaration.clone(), declaration],
                &allowed,
            )
            .unwrap_err()
            .starts_with("InputSiteDuplicateDeclaration")
        );
    }

    #[test]
    fn exact_verification_rejects_kind_and_path_changes() {
        let allowed = sites("fn run() { let _ = Command::new(\"git\"); }");
        let declaration = DeclaredInputSite {
            id: "run-git".to_owned(),
            kind: allowed[0].kind,
            path: allowed[0].path.clone(),
            line: allowed[0].line,
            fingerprint: allowed[0].fingerprint.clone(),
            reason: "The test fixture admits one exact external tool invocation.".to_owned(),
        };
        let mut changed_kind = allowed[0].clone();
        changed_kind.kind = BuildInputKind::IncludedFile;
        assert!(
            verify_declarations(
                "org.mrml.test",
                core::slice::from_ref(&declaration),
                &[changed_kind],
            )
            .unwrap_err()
            .starts_with("InputSiteUndeclared")
        );
        let mut changed_path = allowed[0].clone();
        changed_path.path = "packages/other/src/lib.rs".to_owned();
        assert!(
            verify_declarations(
                "org.mrml.test",
                core::slice::from_ref(&declaration),
                &[changed_path],
            )
            .unwrap_err()
            .starts_with("InputSiteUndeclared")
        );
    }

    #[test]
    fn native_links_inside_cfg_attributes_are_detected() {
        let found =
            sites("#[cfg_attr(target_os = \"linux\", link(name = \"c\"))]\nunsafe extern \"C\" {}");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, BuildInputKind::NativeLink);
    }
}
