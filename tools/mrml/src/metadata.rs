use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

const MAX_METADATA_BYTES: usize = 4 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 32;

#[derive(Debug)]
enum Json {
    Null,
    Bool,
    Number,
    String(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

#[derive(Debug)]
pub(crate) struct CargoPackage {
    pub(crate) name: String,
    pub(crate) manifest_path: String,
    pub(crate) dependencies: Vec<String>,
    pub(crate) features: Vec<String>,
    pub(crate) targets: Vec<CargoTarget>,
}

#[derive(Debug)]
pub(crate) struct CargoTarget {
    pub(crate) name: String,
    pub(crate) kinds: Vec<String>,
}

pub(crate) fn load(root: &Path) -> Result<Vec<CargoPackage>, String> {
    let output = Command::new("cargo")
        .current_dir(root)
        .args(["metadata", "--locked", "--no-deps", "--format-version", "1"])
        .output()
        .map_err(|error| format!("CargoMetadataUnavailable {{ detail: {error} }}"))?;
    if !output.status.success() {
        return Err(format!(
            "CargoMetadataFailed {{ status: {:?} }}",
            output.status.code()
        ));
    }
    if output.stdout.len() > MAX_METADATA_BYTES {
        return Err(format!(
            "CargoMetadataTooLarge {{ bytes: {}, limit: {MAX_METADATA_BYTES} }}",
            output.stdout.len()
        ));
    }
    let text =
        std::str::from_utf8(&output.stdout).map_err(|_| "CargoMetadataInvalidUtf8".to_owned())?;
    parse_packages(text)
}

fn parse_packages(text: &str) -> Result<Vec<CargoPackage>, String> {
    let root = Parser::new(text).parse()?;
    let packages = field(&root, "packages")?
        .array()
        .ok_or("CargoMetadataTypeError { field: packages }")?;
    let mut result = Vec::with_capacity(packages.len());
    for package in packages {
        let name = string_field(package, "name")?.to_owned();
        let manifest_path = string_field(package, "manifest_path")?.to_owned();
        let mut dependencies = Vec::new();
        for dependency in array_field(package, "dependencies")? {
            if matches!(field(dependency, "source")?, Json::Null) {
                dependencies.push(string_field(dependency, "name")?.to_owned());
            }
        }
        dependencies.sort();
        dependencies.dedup();

        let features_object = field(package, "features")?
            .object()
            .ok_or("CargoMetadataTypeError { field: features }")?;
        let features = features_object.keys().cloned().collect();

        let mut targets = Vec::new();
        for target in array_field(package, "targets")? {
            let mut kinds = string_array_field(target, "kind")?;
            kinds.sort();
            targets.push(CargoTarget {
                name: string_field(target, "name")?.to_owned(),
                kinds,
            });
        }
        targets.sort_by(|left, right| left.name.cmp(&right.name));
        result.push(CargoPackage {
            name,
            manifest_path,
            dependencies,
            features,
            targets,
        });
    }
    result.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(result)
}

fn field<'a>(value: &'a Json, name: &str) -> Result<&'a Json, String> {
    value
        .object()
        .and_then(|object| object.get(name))
        .ok_or_else(|| format!("CargoMetadataMissingField {{ field: {name} }}"))
}

fn string_field<'a>(value: &'a Json, name: &str) -> Result<&'a str, String> {
    field(value, name)?
        .string()
        .ok_or_else(|| format!("CargoMetadataTypeError {{ field: {name} }}"))
}

fn array_field<'a>(value: &'a Json, name: &str) -> Result<&'a [Json], String> {
    field(value, name)?
        .array()
        .ok_or_else(|| format!("CargoMetadataTypeError {{ field: {name} }}"))
}

fn string_array_field(value: &Json, name: &str) -> Result<Vec<String>, String> {
    array_field(value, name)?
        .iter()
        .map(|entry| {
            entry
                .string()
                .map(str::to_owned)
                .ok_or_else(|| format!("CargoMetadataTypeError {{ field: {name}[] }}"))
        })
        .collect()
}

impl Json {
    fn string(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    fn array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(value) => Some(value),
            _ => None,
        }
    }

    fn object(&self) -> Option<&BTreeMap<String, Self>> {
        match self {
            Self::Object(value) => Some(value),
            _ => None,
        }
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            bytes: text.as_bytes(),
            offset: 0,
        }
    }

    fn parse(mut self) -> Result<Json, String> {
        let value = self.value(0)?;
        self.whitespace();
        if self.offset != self.bytes.len() {
            return Err(format!(
                "CargoMetadataTrailingData {{ offset: {} }}",
                self.offset
            ));
        }
        Ok(value)
    }

    fn value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > MAX_JSON_DEPTH {
            return Err("CargoMetadataNestingLimit".to_owned());
        }
        self.whitespace();
        match self.peek() {
            Some(b'n') => {
                self.literal(b"null")?;
                Ok(Json::Null)
            }
            Some(b't') => {
                self.literal(b"true")?;
                Ok(Json::Bool)
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Ok(Json::Bool)
            }
            Some(b'"') => self.string().map(Json::String),
            Some(b'[') => self.array(depth + 1),
            Some(b'{') => self.object(depth + 1),
            Some(b'-' | b'0'..=b'9') => {
                self.number()?;
                Ok(Json::Number)
            }
            _ => Err(format!(
                "CargoMetadataSyntaxError {{ offset: {} }}",
                self.offset
            )),
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, String> {
        self.expect(b'[')?;
        let mut values = Vec::new();
        self.whitespace();
        if self.take(b']') {
            return Ok(Json::Array(values));
        }
        loop {
            values.push(self.value(depth)?);
            self.whitespace();
            if self.take(b']') {
                break;
            }
            self.expect(b',')?;
        }
        Ok(Json::Array(values))
    }

    fn object(&mut self, depth: usize) -> Result<Json, String> {
        self.expect(b'{')?;
        let mut values = BTreeMap::new();
        self.whitespace();
        if self.take(b'}') {
            return Ok(Json::Object(values));
        }
        loop {
            self.whitespace();
            let key = self.string()?;
            self.whitespace();
            self.expect(b':')?;
            if values.insert(key, self.value(depth)?).is_some() {
                return Err("CargoMetadataDuplicateKey".to_owned());
            }
            self.whitespace();
            if self.take(b'}') {
                break;
            }
            self.expect(b',')?;
        }
        Ok(Json::Object(values))
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut value = String::new();
        loop {
            let byte = self.next().ok_or("CargoMetadataUnterminatedString")?;
            match byte {
                b'"' => return Ok(value),
                b'\\' => {
                    let escaped = self.next().ok_or("CargoMetadataUnterminatedEscape")?;
                    match escaped {
                        b'"' | b'\\' | b'/' => value.push(char::from(escaped)),
                        b'b' => value.push('\u{0008}'),
                        b'f' => value.push('\u{000c}'),
                        b'n' => value.push('\n'),
                        b'r' => value.push('\r'),
                        b't' => value.push('\t'),
                        b'u' => value.push(self.unicode_escape()?),
                        _ => return Err("CargoMetadataInvalidEscape".to_owned()),
                    }
                }
                0..=31 => return Err("CargoMetadataControlCharacter".to_owned()),
                32..=127 => value.push(char::from(byte)),
                _ => {
                    let start = self.offset - 1;
                    let width = utf8_width(byte).ok_or("CargoMetadataInvalidUtf8")?;
                    let end = start
                        .checked_add(width)
                        .ok_or("CargoMetadataOffsetOverflow")?;
                    let slice = self
                        .bytes
                        .get(start..end)
                        .ok_or("CargoMetadataInvalidUtf8")?;
                    value.push_str(
                        std::str::from_utf8(slice).map_err(|_| "CargoMetadataInvalidUtf8")?,
                    );
                    self.offset = end;
                }
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<char, String> {
        let first = self.hex_quad()?;
        if (0xd800..=0xdbff).contains(&first) {
            self.expect(b'\\')?;
            self.expect(b'u')?;
            let second = self.hex_quad()?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err("CargoMetadataInvalidSurrogate".to_owned());
            }
            let scalar =
                0x10000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00);
            char::from_u32(scalar).ok_or_else(|| "CargoMetadataInvalidUnicode".to_owned())
        } else if (0xdc00..=0xdfff).contains(&first) {
            Err("CargoMetadataInvalidSurrogate".to_owned())
        } else {
            char::from_u32(u32::from(first)).ok_or_else(|| "CargoMetadataInvalidUnicode".to_owned())
        }
    }

    fn hex_quad(&mut self) -> Result<u16, String> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let digit = self.next().and_then(|byte| char::from(byte).to_digit(16));
            value = value
                .checked_mul(16)
                .and_then(|current| digit.and_then(|digit| current.checked_add(digit as u16)))
                .ok_or("CargoMetadataInvalidUnicodeEscape")?;
        }
        Ok(value)
    }

    fn number(&mut self) -> Result<(), String> {
        let start = self.offset;
        while matches!(
            self.peek(),
            Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
        ) {
            self.offset += 1;
        }
        let value = std::str::from_utf8(&self.bytes[start..self.offset])
            .map_err(|_| "CargoMetadataInvalidNumber")?;
        value
            .parse::<f64>()
            .map(|_| ())
            .map_err(|_| "CargoMetadataInvalidNumber".to_owned())
    }

    fn literal(&mut self, literal: &[u8]) -> Result<(), String> {
        if self.bytes.get(self.offset..self.offset + literal.len()) == Some(literal) {
            self.offset += literal.len();
            Ok(())
        } else {
            Err("CargoMetadataInvalidLiteral".to_owned())
        }
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.offset += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.take(byte) {
            Ok(())
        } else {
            Err(format!(
                "CargoMetadataSyntaxError {{ offset: {}, expected: {} }}",
                self.offset,
                char::from(byte)
            ))
        }
    }

    fn take(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let value = self.peek()?;
        self.offset += 1;
        Some(value)
    }
}

fn utf8_width(first: u8) -> Option<usize> {
    match first {
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bounded_metadata_subset() {
        let packages = parse_packages(
            r#"{"packages":[{"name":"a","manifest_path":"C:\\a\\Cargo.toml","dependencies":[{"name":"b","source":null},{"name":"x","source":"registry"}],"features":{"default":[]},"targets":[{"name":"a","kind":["lib"]}]}]}"#,
        )
        .unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].dependencies, ["b"]);
        assert_eq!(packages[0].features, ["default"]);
        assert_eq!(packages[0].targets[0].kinds, ["lib"]);
    }

    #[test]
    fn rejects_duplicate_keys_and_excessive_nesting() {
        assert!(Parser::new(r#"{"a":1,"a":2}"#).parse().is_err());
        let nested = format!("{}null{}", "[".repeat(34), "]".repeat(34));
        assert!(Parser::new(&nested).parse().is_err());
    }
}
