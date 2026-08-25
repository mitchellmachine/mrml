use std::collections::BTreeMap;

pub const MAX_DOCUMENT_BYTES: usize = 256 * 1024;
pub const MAX_SECTIONS: usize = 1024;
pub const MAX_FIELDS_PER_SECTION: usize = 128;
pub const MAX_ARRAY_ITEMS: usize = 256;
pub const MAX_STRING_BYTES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    String(String),
    Integer(u64),
    Boolean(bool),
    Strings(Vec<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Section {
    pub name: String,
    pub array: bool,
    pub fields: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Document {
    pub sections: Vec<Section>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Size,
    Syntax { line: usize },
    InvalidName { line: usize },
    InvalidValue { line: usize },
    DuplicateField { line: usize },
    Limit { line: usize },
    MissingSchema,
    WrongSchema,
}

impl Document {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(Error::Size);
        }
        let text = core::str::from_utf8(bytes).map_err(|_| Error::Syntax { line: 0 })?;
        let mut sections: Vec<Section> = Vec::new();
        for (offset, raw) in text.lines().enumerate() {
            let line_number = offset + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') {
                let (array, name) = if let Some(name) = line
                    .strip_prefix("[[")
                    .and_then(|value| value.strip_suffix("]]"))
                {
                    (true, name)
                } else if let Some(name) = line
                    .strip_prefix('[')
                    .and_then(|value| value.strip_suffix(']'))
                {
                    (false, name)
                } else {
                    return Err(Error::Syntax { line: line_number });
                };
                if !valid_dotted_name(name) {
                    return Err(Error::InvalidName { line: line_number });
                }
                if !array && sections.iter().any(|section| section.name == name) {
                    return Err(Error::DuplicateField { line: line_number });
                }
                if sections.len() >= MAX_SECTIONS {
                    return Err(Error::Limit { line: line_number });
                }
                sections.push(Section {
                    name: name.to_owned(),
                    array,
                    fields: BTreeMap::new(),
                });
                continue;
            }
            let Some(section) = sections.last_mut() else {
                return Err(Error::Syntax { line: line_number });
            };
            let Some((key, value)) = line.split_once('=') else {
                return Err(Error::Syntax { line: line_number });
            };
            let key = key.trim();
            if !valid_name(key) {
                return Err(Error::InvalidName { line: line_number });
            }
            if section.fields.len() >= MAX_FIELDS_PER_SECTION {
                return Err(Error::Limit { line: line_number });
            }
            let value = parse_value(value.trim(), line_number)?;
            if section.fields.insert(key.to_owned(), value).is_some() {
                return Err(Error::DuplicateField { line: line_number });
            }
        }
        let document = Self { sections };
        document.require_v2()?;
        Ok(document)
    }

    pub fn require_v2(&self) -> Result<(), Error> {
        let Some(schema) = self
            .sections
            .iter()
            .find(|section| section.name == "manifest")
        else {
            return Err(Error::MissingSchema);
        };
        if schema.array
            || schema.fields.get("format") != Some(&Value::String("mrml".into()))
            || schema.fields.get("version") != Some(&Value::Integer(2))
        {
            return Err(Error::WrongSchema);
        }
        Ok(())
    }

    pub fn canonical(&self) -> String {
        let mut output = String::new();
        for (index, section) in self.sections.iter().enumerate() {
            if index != 0 {
                output.push('\n');
            }
            if section.array {
                output.push_str("[[");
                output.push_str(&section.name);
                output.push_str("]]\n");
            } else {
                output.push('[');
                output.push_str(&section.name);
                output.push_str("]\n");
            }
            for (key, value) in &section.fields {
                output.push_str(key);
                output.push_str(" = ");
                render_value(value, &mut output);
                output.push('\n');
            }
        }
        output
    }

    pub fn section(&self, name: &str) -> Result<&Section, Error> {
        let mut matches = self.sections.iter().filter(|section| section.name == name);
        let Some(section) = matches.next() else {
            return Err(Error::MissingSchema);
        };
        if section.array || matches.next().is_some() {
            return Err(Error::WrongSchema);
        }
        Ok(section)
    }

    pub fn array_sections<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Section> {
        self.sections
            .iter()
            .filter(move |section| section.array && section.name == name)
    }
}

impl Section {
    pub fn string(&self, key: &str) -> Result<&str, Error> {
        match self.fields.get(key) {
            Some(Value::String(value)) => Ok(value),
            _ => Err(Error::WrongSchema),
        }
    }

    pub fn optional_string(&self, key: &str) -> Result<Option<&str>, Error> {
        match self.fields.get(key) {
            Some(Value::String(value)) => Ok(Some(value)),
            None => Ok(None),
            _ => Err(Error::WrongSchema),
        }
    }

    pub fn boolean(&self, key: &str) -> Result<bool, Error> {
        match self.fields.get(key) {
            Some(Value::Boolean(value)) => Ok(*value),
            _ => Err(Error::WrongSchema),
        }
    }

    pub fn optional_boolean(&self, key: &str) -> Result<Option<bool>, Error> {
        match self.fields.get(key) {
            Some(Value::Boolean(value)) => Ok(Some(*value)),
            None => Ok(None),
            _ => Err(Error::WrongSchema),
        }
    }

    pub fn integer(&self, key: &str) -> Result<u64, Error> {
        match self.fields.get(key) {
            Some(Value::Integer(value)) => Ok(*value),
            _ => Err(Error::WrongSchema),
        }
    }

    pub fn strings(&self, key: &str) -> Result<&[String], Error> {
        match self.fields.get(key) {
            Some(Value::Strings(value)) => Ok(value),
            _ => Err(Error::WrongSchema),
        }
    }

    pub fn optional_strings(&self, key: &str) -> Result<&[String], Error> {
        match self.fields.get(key) {
            Some(Value::Strings(value)) => Ok(value),
            None => Ok(&[]),
            _ => Err(Error::WrongSchema),
        }
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
}

fn valid_dotted_name(value: &str) -> bool {
    value.len() <= 128 && value.split('.').all(valid_name)
}

fn parse_value(value: &str, line: usize) -> Result<Value, Error> {
    if value == "true" {
        return Ok(Value::Boolean(true));
    }
    if value == "false" {
        return Ok(Value::Boolean(false));
    }
    if let Ok(integer) = value.parse::<u64>() {
        return Ok(Value::Integer(integer));
    }
    if value.starts_with('"') {
        return parse_string(value, line).map(Value::String);
    }
    if let Some(inner) = value
        .strip_prefix('[')
        .and_then(|item| item.strip_suffix(']'))
    {
        if inner.trim().is_empty() {
            return Ok(Value::Strings(Vec::new()));
        }
        let mut result = Vec::new();
        for item in inner.split(',') {
            if result.len() >= MAX_ARRAY_ITEMS {
                return Err(Error::Limit { line });
            }
            result.push(parse_string(item.trim(), line)?);
        }
        return Ok(Value::Strings(result));
    }
    Err(Error::InvalidValue { line })
}

fn parse_string(value: &str, line: usize) -> Result<String, Error> {
    let Some(inner) = value
        .strip_prefix('"')
        .and_then(|item| item.strip_suffix('"'))
    else {
        return Err(Error::InvalidValue { line });
    };
    if inner.len() > MAX_STRING_BYTES
        || inner
            .bytes()
            .any(|byte| byte < 0x20 || byte == b'"' || byte == b'\\')
    {
        return Err(Error::InvalidValue { line });
    }
    Ok(inner.to_owned())
}

fn render_value(value: &Value, output: &mut String) {
    match value {
        Value::String(value) => {
            output.push('"');
            output.push_str(value);
            output.push('"');
        }
        Value::Integer(value) => output.push_str(&value.to_string()),
        Value::Boolean(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Strings(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push_str(", ");
                }
                output.push('"');
                output.push_str(value);
                output.push('"');
            }
            output.push(']');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "[manifest]\nformat = \"mrml\"\nversion = 2\n\n[package]\nid = \"org.mrml.zstd\"\nname = \"mrml-zstd\"\n\n[[target]]\narch = \"x86_64\"\nenvironment = \"windows\"\n\n[[dependency]]\npackage = \"org.mrml.runtime\"\nscope = \"compile\"\ntargets = [\"windows-x86_64\"]\n";

    #[test]
    fn parses_and_canonicalizes_v2() {
        let document = Document::parse(VALID.as_bytes()).unwrap();
        assert_eq!(
            Document::parse(document.canonical().as_bytes()),
            Ok(document)
        );
    }

    #[test]
    fn rejects_wrong_schema_duplicates_and_secondary_strings() {
        assert_eq!(
            Document::parse(VALID.replace("version = 2", "version = 1").as_bytes()),
            Err(Error::WrongSchema)
        );
        assert!(
            Document::parse(
                VALID
                    .replace("name = \"mrml-zstd\"", "name = \"a|b\"")
                    .as_bytes()
            )
            .is_ok()
        );
        assert!(
            Document::parse(
                VALID
                    .replace("name = \"mrml-zstd\"", "name = \"a\\\\b\"")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(Document::parse(format!("{VALID}\n[package]\n").as_bytes()).is_err());
    }

    #[test]
    fn bounded_mutation_corpus_preserves_parse_and_canonicalization_bounds() {
        let corpus = concat!(
            "[manifest]\nformat = \"mrml\"\nversion = 2\n\n",
            "[package]\nid = \"org.mrml.zstd\"\nkind = \"library\"\n",
            "name = \"mrml-zstd\"\nprofile = \"library\"\n\n",
            "[[target]]\narch = \"x86_64\"\nenvironment = \"windows\"\n\n",
            "[[feature]]\nname = \"runtime\"\n\n",
            "[[dependency]]\nalias = \"mrml_runtime\"\n",
            "package = \"org.mrml.runtime\"\nscope = \"compile\"\n",
            "targets = [\"windows-x86_64\"]\n\n",
            "[[provides]]\nfingerprint = \"abc123\"\n",
            "interface = \"org.mrml.interface.compression.zstd\"\n",
            "generation = 3\ntargets = [\"windows-x86_64\"]\n\n",
            "[[artifact]]\ncrate_name = \"mrml_zstd\"\nkind = \"library\"\n",
            "name = \"mrml_zstd\"\nsource = \"src/lib.rs\"\n\n",
            "[[test]]\nname = \"round_trip\"\nsource = \"tests/round_trip.rs\"\n",
            "execution = \"host\"\n\n",
            "[policy]\nbuild_scripts = \"deny\"\nexternal_commands = \"deny\"\n",
        )
        .as_bytes();
        for truncated in (0..corpus.len()).step_by(17) {
            let _ = Document::parse(&corpus[..truncated]);
        }
        let mut state = 0x6d72_6d6c_7632_u64;
        for _ in 0..512 {
            state = state
                .wrapping_mul(2_862_933_555_777_941_757)
                .wrapping_add(3_037_000_493);
            let mut mutated = corpus.to_vec();
            let offset = (state as usize) % mutated.len();
            mutated[offset] ^= 1 << ((state >> 40) & 7);
            if let Ok(document) = Document::parse(&mutated) {
                assert_eq!(
                    Document::parse(document.canonical().as_bytes()),
                    Ok(document)
                );
            }
        }
    }
}
