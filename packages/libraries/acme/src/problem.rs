use crate::directory::{Token, Tokens};

pub const MAX_PROBLEM_BYTES: usize = 16_384;
pub const MAX_PROBLEM_TYPE: usize = 256;
pub const MAX_PROBLEM_DETAIL: usize = 1024;
pub const MAX_SUBPROBLEMS: usize = 8;
const MAX_PROBLEM_TOKENS: usize = 256;
const MAX_PROBLEM_DEPTH: usize = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProblemError {
    Oversized,
    Malformed,
    TooComplex,
    DuplicateField,
    MissingType,
    InvalidType,
    DetailTooLong,
    InvalidStatus,
    TooManySubproblems,
    TrailingData,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ProblemText<const N: usize> {
    bytes: [u8; N],
    len: u16,
}

impl<const N: usize> ProblemText<N> {
    fn parse(value: &str, error: ProblemError) -> Result<Self, ProblemError> {
        if value.len() > N || value.contains('\\') || value.bytes().any(|byte| byte < 0x20) {
            return Err(error);
        }
        let mut bytes = [0; N];
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        Ok(Self {
            bytes,
            len: value.len() as u16,
        })
    }
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or("")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AcmeSubproblem {
    pub problem_type: ProblemText<MAX_PROBLEM_TYPE>,
    pub detail: Option<ProblemText<MAX_PROBLEM_DETAIL>>,
    pub status: Option<u16>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AcmeProblem {
    pub problem_type: ProblemText<MAX_PROBLEM_TYPE>,
    pub detail: Option<ProblemText<MAX_PROBLEM_DETAIL>>,
    pub status: Option<u16>,
    pub subproblems: [Option<AcmeSubproblem>; MAX_SUBPROBLEMS],
    pub subproblem_count: u8,
}

struct Cursor<'a> {
    tokens: Tokens<'a>,
    count: usize,
    put_back: Option<Token<'a>>,
}

impl<'a> Cursor<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            tokens: Tokens::new(source),
            count: 0,
            put_back: None,
        }
    }
    fn next(&mut self) -> Result<Option<Token<'a>>, ProblemError> {
        if let Some(token) = self.put_back.take() {
            return Ok(Some(token));
        }
        self.count = self.count.checked_add(1).ok_or(ProblemError::TooComplex)?;
        if self.count > MAX_PROBLEM_TOKENS {
            return Err(ProblemError::TooComplex);
        }
        self.tokens
            .next()
            .transpose()
            .map_err(|_| ProblemError::Malformed)
    }
    fn expect(&mut self, expected: Token<'a>) -> Result<(), ProblemError> {
        if self.next()? == Some(expected) {
            Ok(())
        } else {
            Err(ProblemError::Malformed)
        }
    }
    fn string(&mut self) -> Result<&'a str, ProblemError> {
        match self.next()? {
            Some(Token::String(value)) => Ok(value),
            _ => Err(ProblemError::Malformed),
        }
    }
    fn skip(&mut self, depth: usize) -> Result<(), ProblemError> {
        if depth > MAX_PROBLEM_DEPTH {
            return Err(ProblemError::TooComplex);
        }
        match self.next()?.ok_or(ProblemError::Malformed)? {
            Token::ArrayStart => {
                match self.next()? {
                    Some(Token::ArrayEnd) => return Ok(()),
                    Some(token) => self.put_back = Some(token),
                    None => return Err(ProblemError::Malformed),
                }
                loop {
                    self.skip(depth + 1)?;
                    match self.next()? {
                        Some(Token::Comma) => {}
                        Some(Token::ArrayEnd) => return Ok(()),
                        _ => return Err(ProblemError::Malformed),
                    }
                }
            }
            Token::ObjectStart => {
                match self.next()? {
                    Some(Token::ObjectEnd) => return Ok(()),
                    Some(token) => self.put_back = Some(token),
                    None => return Err(ProblemError::Malformed),
                }
                loop {
                    self.string()?;
                    self.expect(Token::Colon)?;
                    self.skip(depth + 1)?;
                    match self.next()? {
                        Some(Token::Comma) => {}
                        Some(Token::ObjectEnd) => return Ok(()),
                        _ => return Err(ProblemError::Malformed),
                    }
                }
            }
            _ => Ok(()),
        }
    }
}

impl AcmeProblem {
    pub fn parse(source: &str) -> Result<Self, ProblemError> {
        if source.len() > MAX_PROBLEM_BYTES {
            return Err(ProblemError::Oversized);
        }
        let mut cursor = Cursor::new(source);
        let parsed = parse_problem_object(&mut cursor, true)?;
        if cursor.next()?.is_some() {
            return Err(ProblemError::TrailingData);
        }
        Ok(parsed)
    }
    pub fn is_bad_nonce(&self) -> bool {
        self.problem_type.as_str() == "urn:ietf:params:acme:error:badNonce"
    }
}

fn parse_problem_object(
    cursor: &mut Cursor<'_>,
    allow_subproblems: bool,
) -> Result<AcmeProblem, ProblemError> {
    cursor.expect(Token::ObjectStart)?;
    let mut problem_type = None;
    let mut detail = None;
    let mut status = None;
    let mut subproblems = [None; MAX_SUBPROBLEMS];
    let mut subproblem_count = 0u8;
    let mut seen = 0u8;
    match cursor.next()? {
        Some(Token::ObjectEnd) => return Err(ProblemError::MissingType),
        Some(token) => cursor.put_back = Some(token),
        None => return Err(ProblemError::Malformed),
    }
    return parse_members(
        cursor,
        allow_subproblems,
        &mut problem_type,
        &mut detail,
        &mut status,
        &mut subproblems,
        &mut subproblem_count,
        &mut seen,
    );
}

fn parse_members(
    cursor: &mut Cursor<'_>,
    allow_subproblems: bool,
    problem_type: &mut Option<ProblemText<MAX_PROBLEM_TYPE>>,
    detail: &mut Option<ProblemText<MAX_PROBLEM_DETAIL>>,
    status: &mut Option<u16>,
    subproblems: &mut [Option<AcmeSubproblem>; MAX_SUBPROBLEMS],
    subproblem_count: &mut u8,
    seen: &mut u8,
) -> Result<AcmeProblem, ProblemError> {
    loop {
        let key = cursor.string()?;
        cursor.expect(Token::Colon)?;
        let bit = match key {
            "type" => 1,
            "detail" => 2,
            "status" => 4,
            "subproblems" => 8,
            _ => 0,
        };
        if bit != 0 && *seen & bit != 0 {
            return Err(ProblemError::DuplicateField);
        }
        *seen |= bit;
        match key {
            "type" => {
                *problem_type = Some(ProblemText::parse(
                    cursor.string()?,
                    ProblemError::InvalidType,
                )?)
            }
            "detail" => {
                *detail = Some(ProblemText::parse(
                    cursor.string()?,
                    ProblemError::DetailTooLong,
                )?)
            }
            "status" => {
                *status = Some(match cursor.next()? {
                    Some(Token::Number(value)) if value.len() <= 3 => {
                        let parsed = value
                            .parse::<u16>()
                            .map_err(|_| ProblemError::InvalidStatus)?;
                        if !(100..=599).contains(&parsed) {
                            return Err(ProblemError::InvalidStatus);
                        }
                        parsed
                    }
                    _ => return Err(ProblemError::InvalidStatus),
                })
            }
            "subproblems" if allow_subproblems => {
                cursor.expect(Token::ArrayStart)?;
                match cursor.next()? {
                    Some(Token::ArrayEnd) => {}
                    Some(token) => {
                        cursor.put_back = Some(token);
                        loop {
                            if usize::from(*subproblem_count) >= MAX_SUBPROBLEMS {
                                return Err(ProblemError::TooManySubproblems);
                            }
                            let sub = parse_problem_object(cursor, false)?;
                            subproblems[usize::from(*subproblem_count)] = Some(AcmeSubproblem {
                                problem_type: sub.problem_type,
                                detail: sub.detail,
                                status: sub.status,
                            });
                            *subproblem_count += 1;
                            match cursor.next()? {
                                Some(Token::Comma) => {}
                                Some(Token::ArrayEnd) => break,
                                _ => return Err(ProblemError::Malformed),
                            }
                        }
                    }
                    None => return Err(ProblemError::Malformed),
                }
            }
            _ => cursor.skip(1)?,
        }
        match cursor.next()? {
            Some(Token::Comma) => {}
            Some(Token::ObjectEnd) => break,
            _ => return Err(ProblemError::Malformed),
        }
    }
    Ok(AcmeProblem {
        problem_type: problem_type.ok_or(ProblemError::MissingType)?,
        detail: *detail,
        status: *status,
        subproblems: *subproblems,
        subproblem_count: *subproblem_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_typed_problem_and_subproblem() {
        let p=AcmeProblem::parse(r#"{"type":"urn:ietf:params:acme:error:badNonce","detail":"retry","status":400,"subproblems":[{"type":"urn:example:name","detail":"bad name","status":403}]}"#).unwrap();
        assert!(p.is_bad_nonce());
        assert_eq!(p.status, Some(400));
        assert_eq!(p.subproblem_count, 1);
        assert_eq!(
            p.subproblems[0].unwrap().detail.unwrap().as_str(),
            "bad name"
        );
    }
    #[test]
    fn rejects_duplicates_malformed_status_and_trailing_data() {
        assert_eq!(
            AcmeProblem::parse(r#"{"type":"a","type":"b"}"#).err(),
            Some(ProblemError::DuplicateField)
        );
        assert_eq!(
            AcmeProblem::parse(r#"{"type":"a","status":999}"#).err(),
            Some(ProblemError::InvalidStatus)
        );
        assert_eq!(
            AcmeProblem::parse(r#"{"type":"a"}{}"#).err(),
            Some(ProblemError::TrailingData)
        );
    }
    #[test]
    fn skips_bounded_unknown_values() {
        let problem =
            AcmeProblem::parse(r#"{"unknown":{"nested":[1,true,null]},"type":"urn:example:test"}"#)
                .unwrap();
        assert_eq!(problem.problem_type.as_str(), "urn:example:test");
    }
}
