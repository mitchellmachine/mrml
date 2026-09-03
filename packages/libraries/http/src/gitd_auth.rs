use core::fmt;

use mrml_crypto::hmac_sha256;
use mrml_runtime::{SpinMutex, Text, Vector};

use crate::{Header, RepositoryIdentity};

const TOKEN_BYTES: usize = 32;
const TOKEN_TEXT_BYTES: usize = TOKEN_BYTES * 2;
const MAX_LABEL_BYTES: usize = 96;
const RECORD_VERSION: u8 = 1;
const TOKEN_STORE_MAGIC: &[u8; 8] = b"MRMLTRV1";
const TOKEN_STORE_TAG_BYTES: usize = 32;
const MAX_TOKEN_RECORDS: usize = 1_000_000;
const AUTH_FAILURE_BUCKETS: usize = 4_096;
const AUTH_FAILURE_WINDOW_SECONDS: u64 = 60;
const AUTH_FAILURES_PER_WINDOW: u16 = 32;
pub const MAX_TOKEN_STORE_BYTES: usize = 256 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryProfile {
    PublicRead,
    Private,
    Protected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryAction {
    Read,
    Write,
    Administer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessScopes(u8);

impl AccessScopes {
    pub const READ: Self = Self(1);
    pub const WRITE: Self = Self(2);
    pub const ADMINISTER: Self = Self(4);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    const fn allows(self, action: RepositoryAction) -> bool {
        let required = match action {
            RepositoryAction::Read => Self::READ.0,
            RepositoryAction::Write => Self::WRITE.0,
            RepositoryAction::Administer => Self::ADMINISTER.0,
        };
        self.0 & required == required
    }
}

pub struct OneTimeAccessToken {
    bytes: [u8; TOKEN_TEXT_BYTES],
    available: bool,
}

impl OneTimeAccessToken {
    pub fn expose_once<R>(&mut self, use_token: impl FnOnce(&str) -> R) -> Option<R> {
        if !self.available {
            return None;
        }
        self.available = false;
        let token = core::str::from_utf8(&self.bytes).ok()?;
        let result = use_token(token);
        erase(&mut self.bytes);
        Some(result)
    }

    pub fn reveal_once(&mut self) -> Option<Text> {
        self.expose_once(|value| Text::from(value))
    }
}

impl fmt::Debug for OneTimeAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OneTimeAccessToken(<redacted>)")
    }
}

impl Drop for OneTimeAccessToken {
    fn drop(&mut self) {
        erase(&mut self.bytes);
    }
}

pub struct TokenRecord {
    repository: RepositoryIdentity,
    scopes: AccessScopes,
    valid_from: u64,
    expires_at: u64,
    revocation_generation: u64,
    label: Text,
    verifier: [u8; 32],
    integrity: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryAccessPolicy {
    pub repository: RepositoryIdentity,
    pub profile: RepositoryProfile,
    pub revocation_generation: u64,
}

pub struct GitdAuthentication {
    authority: TokenAuthority,
    policies: Vector<RepositoryAccessPolicy>,
    records: Vector<TokenRecord>,
    failures: SpinMutex<AuthenticationFailures>,
}

#[derive(Clone, Copy)]
struct AuthenticationFailureBucket {
    window_started: u64,
    failures: u16,
}

struct AuthenticationFailures {
    buckets: Vector<AuthenticationFailureBucket>,
}

impl AuthenticationFailures {
    fn new() -> Result<Self, AuthenticationError> {
        let mut buckets = Vector::new();
        buckets
            .try_reserve_exact(AUTH_FAILURE_BUCKETS)
            .map_err(|_| AuthenticationError::Resource)?;
        buckets.resize(
            AUTH_FAILURE_BUCKETS,
            AuthenticationFailureBucket {
                window_started: 0,
                failures: 0,
            },
        );
        Ok(Self { buckets })
    }

    fn limited(&mut self, bucket: usize, now: u64) -> bool {
        let state = &mut self.buckets[bucket];
        if now.saturating_sub(state.window_started) >= AUTH_FAILURE_WINDOW_SECONDS {
            state.window_started = now;
            state.failures = 0;
        }
        state.failures >= AUTH_FAILURES_PER_WINDOW
    }

    fn record(&mut self, bucket: usize, now: u64) {
        let state = &mut self.buckets[bucket];
        if now.saturating_sub(state.window_started) >= AUTH_FAILURE_WINDOW_SECONDS {
            state.window_started = now;
            state.failures = 0;
        }
        state.failures = state.failures.saturating_add(1);
    }
}

impl GitdAuthentication {
    pub fn new(
        authority: TokenAuthority,
        mut policies: Vector<RepositoryAccessPolicy>,
        mut records: Vector<TokenRecord>,
    ) -> Result<Self, AuthenticationError> {
        if policies.is_empty()
            || policies.len() > 100_000
            || records.len() > 1_000_000
            || policies
                .iter()
                .any(|policy| policy.revocation_generation == 0)
        {
            return Err(AuthenticationError::InvalidConfiguration);
        }
        policies.sort_unstable_by(|left, right| left.repository.cmp(&right.repository));
        if policies
            .windows(2)
            .any(|pair| pair[0].repository == pair[1].repository)
        {
            return Err(AuthenticationError::InvalidConfiguration);
        }
        for record in &records {
            if !constant_time_equal(&authority.record_integrity(record)?, &record.integrity) {
                return Err(AuthenticationError::InvalidConfiguration);
            }
        }
        records.sort_unstable_by(|left, right| left.verifier.cmp(&right.verifier));
        if records
            .windows(2)
            .any(|pair| pair[0].verifier == pair[1].verifier)
        {
            return Err(AuthenticationError::InvalidConfiguration);
        }
        Ok(Self {
            authority,
            policies,
            records,
            failures: SpinMutex::new(AuthenticationFailures::new()?),
        })
    }

    pub fn authorize(
        &self,
        headers: &[Header],
        repository: &RepositoryIdentity,
        action: RepositoryAction,
        now: u64,
    ) -> Result<AuthenticatedAccess, AuthenticationError> {
        let failure_bucket = self.authority.failure_bucket(headers, repository);
        if self.failures.lock().limited(failure_bucket, now) {
            return Err(AuthenticationError::Denied);
        }
        let result = self
            .policies
            .binary_search_by(|policy| policy.repository.cmp(repository))
            .ok()
            .map(|index| &self.policies[index])
            .ok_or(AuthenticationError::Denied)
            .and_then(|policy| {
                self.authority.authorize(
                    headers,
                    repository,
                    action,
                    policy.profile,
                    now,
                    policy.revocation_generation,
                    &self.records,
                )
            });
        if result == Err(AuthenticationError::Denied) {
            self.failures.lock().record(failure_bucket, now);
        }
        result
    }
}

impl fmt::Debug for TokenRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenRecord")
            .field("repository", &self.repository)
            .field("scopes", &self.scopes)
            .field("valid_from", &self.valid_from)
            .field("expires_at", &self.expires_at)
            .field("revocation_generation", &self.revocation_generation)
            .field("label", &self.label)
            .field("verifier", &"<redacted>")
            .field("integrity", &"<redacted>")
            .finish()
    }
}

pub struct TokenAuthority {
    pepper: [u8; 32],
}

impl TokenAuthority {
    pub fn new(pepper: [u8; 32]) -> Result<Self, AuthenticationError> {
        if pepper.iter().all(|byte| *byte == 0) {
            return Err(AuthenticationError::InvalidConfiguration);
        }
        Ok(Self { pepper })
    }

    pub fn issue(
        &self,
        repository: RepositoryIdentity,
        scopes: AccessScopes,
        valid_from: u64,
        expires_at: u64,
        revocation_generation: u64,
        label: &str,
    ) -> Result<(OneTimeAccessToken, TokenRecord), AuthenticationError> {
        if scopes.0 == 0
            || scopes.0 & !7 != 0
            || valid_from >= expires_at
            || revocation_generation == 0
            || label.is_empty()
            || label.len() > MAX_LABEL_BYTES
            || label.bytes().any(|byte| !(b' '..=b'~').contains(&byte))
        {
            return Err(AuthenticationError::InvalidConfiguration);
        }
        let mut raw = [0u8; TOKEN_BYTES];
        mrml_runtime::fill_random(&mut raw).map_err(|_| AuthenticationError::Entropy)?;
        let verifier = hmac_sha256(&self.pepper, &[b"mrml-git-token-v1", &raw]);
        let mut encoded = [0u8; TOKEN_TEXT_BYTES];
        encode_hex(&raw, &mut encoded);
        erase(&mut raw);
        let mut record = TokenRecord {
            repository,
            scopes,
            valid_from,
            expires_at,
            revocation_generation,
            label: label.into(),
            verifier,
            integrity: [0; 32],
        };
        record.integrity = self.record_integrity(&record)?;
        Ok((
            OneTimeAccessToken {
                bytes: encoded,
                available: true,
            },
            record,
        ))
    }

    pub fn authorize(
        &self,
        headers: &[Header],
        repository: &RepositoryIdentity,
        action: RepositoryAction,
        profile: RepositoryProfile,
        now: u64,
        current_revocation_generation: u64,
        records: &[TokenRecord],
    ) -> Result<AuthenticatedAccess, AuthenticationError> {
        let authorization = single_authorization(headers)?;
        if authorization.is_none()
            && profile == RepositoryProfile::PublicRead
            && action == RepositoryAction::Read
        {
            return Ok(AuthenticatedAccess::AnonymousRead);
        }
        let encoded = authorization
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or(AuthenticationError::Denied)?;
        let mut raw = decode_token(encoded)?;
        let actual = hmac_sha256(&self.pepper, &[b"mrml-git-token-v1", &raw]);
        erase(&mut raw);
        let (record, _) = indexed_record(records, &actual);
        let record = record.ok_or(AuthenticationError::Denied)?;
        if !constant_time_equal(&actual, &record.verifier) {
            return Err(AuthenticationError::Denied);
        }
        if &record.repository != repository
            || !record.scopes.allows(action)
            || now < record.valid_from
            || now >= record.expires_at
            || record.revocation_generation != current_revocation_generation
        {
            return Err(AuthenticationError::Denied);
        }
        Ok(AuthenticatedAccess::Token)
    }

    fn failure_bucket(&self, headers: &[Header], repository: &RepositoryIdentity) -> usize {
        let authorization = headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("authorization"))
            .map_or(&[][..], |header| header.value.as_bytes());
        let digest = hmac_sha256(
            &self.pepper,
            &[
                b"mrml-git-auth-failure-bucket-v1",
                repository.as_str().as_bytes(),
                authorization,
            ],
        );
        usize::from(u16::from_be_bytes([digest[0], digest[1]])) % AUTH_FAILURE_BUCKETS
    }

    pub fn revoke_encoded_token(
        &self,
        records: &mut Vector<TokenRecord>,
        encoded: &str,
    ) -> Result<bool, AuthenticationError> {
        let mut raw = decode_token(encoded)?;
        let verifier = hmac_sha256(&self.pepper, &[b"mrml-git-token-v1", &raw]);
        erase(&mut raw);
        let mut selected = None;
        for (index, record) in records.iter().enumerate() {
            if constant_time_equal(&verifier, &record.verifier) {
                if selected.is_some() {
                    return Err(AuthenticationError::Denied);
                }
                selected = Some(index);
            }
        }
        if let Some(index) = selected {
            records.remove(index);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn record_integrity(&self, record: &TokenRecord) -> Result<[u8; 32], AuthenticationError> {
        let mut canonical = Vector::new();
        canonical.push(RECORD_VERSION);
        append_field(&mut canonical, record.repository.as_str().as_bytes())?;
        canonical.push(record.scopes.0);
        canonical.extend(record.valid_from.to_be_bytes());
        canonical.extend(record.expires_at.to_be_bytes());
        canonical.extend(record.revocation_generation.to_be_bytes());
        append_field(&mut canonical, record.label.as_bytes())?;
        canonical.extend(record.verifier);
        Ok(hmac_sha256(
            &self.pepper,
            &[b"mrml-git-token-record-v1", &canonical],
        ))
    }

    pub fn encode_records(
        &self,
        records: &[TokenRecord],
    ) -> Result<Vector<u8>, AuthenticationError> {
        if records.len() > MAX_TOKEN_RECORDS {
            return Err(AuthenticationError::Resource);
        }
        let mut order: Vector<usize> = (0..records.len()).collect();
        order.sort_unstable_by(|left, right| {
            (&records[*left].repository, &records[*left].verifier)
                .cmp(&(&records[*right].repository, &records[*right].verifier))
        });
        for pair in order.windows(2) {
            if records[pair[0]].repository == records[pair[1]].repository
                && records[pair[0]].verifier == records[pair[1]].verifier
            {
                return Err(AuthenticationError::InvalidConfiguration);
            }
        }
        let mut output = Vector::new();
        output
            .try_reserve_exact(12 + records.len().saturating_mul(128))
            .map_err(|_| AuthenticationError::Resource)?;
        output.extend(*TOKEN_STORE_MAGIC);
        output.extend(
            u32::try_from(records.len())
                .map_err(|_| AuthenticationError::Resource)?
                .to_be_bytes(),
        );
        for index in order {
            let record = &records[index];
            if !constant_time_equal(&self.record_integrity(record)?, &record.integrity) {
                return Err(AuthenticationError::InvalidConfiguration);
            }
            append_field(&mut output, record.repository.as_str().as_bytes())?;
            output.push(record.scopes.0);
            output.extend(record.valid_from.to_be_bytes());
            output.extend(record.expires_at.to_be_bytes());
            output.extend(record.revocation_generation.to_be_bytes());
            append_field(&mut output, record.label.as_bytes())?;
            output.extend(record.verifier);
            output.extend(record.integrity);
            if output.len() > MAX_TOKEN_STORE_BYTES - TOKEN_STORE_TAG_BYTES {
                return Err(AuthenticationError::Resource);
            }
        }
        let tag = hmac_sha256(&self.pepper, &[b"mrml-git-token-store-v1", &output]);
        output.extend(tag);
        Ok(output)
    }

    pub fn decode_records(&self, input: &[u8]) -> Result<Vector<TokenRecord>, AuthenticationError> {
        if input.len() < 12 + TOKEN_STORE_TAG_BYTES || input.len() > MAX_TOKEN_STORE_BYTES {
            return Err(AuthenticationError::InvalidConfiguration);
        }
        let authenticated_length = input.len() - TOKEN_STORE_TAG_BYTES;
        let expected = hmac_sha256(
            &self.pepper,
            &[b"mrml-git-token-store-v1", &input[..authenticated_length]],
        );
        let supplied: &[u8; 32] = input[authenticated_length..]
            .try_into()
            .map_err(|_| AuthenticationError::InvalidConfiguration)?;
        if !constant_time_equal(&expected, supplied) || &input[..8] != TOKEN_STORE_MAGIC {
            return Err(AuthenticationError::InvalidConfiguration);
        }
        let count = u32::from_be_bytes(
            input[8..12]
                .try_into()
                .map_err(|_| AuthenticationError::InvalidConfiguration)?,
        ) as usize;
        if count > MAX_TOKEN_RECORDS {
            return Err(AuthenticationError::Resource);
        }
        let mut at = 12usize;
        let mut records = Vector::new();
        records
            .try_reserve_exact(count)
            .map_err(|_| AuthenticationError::Resource)?;
        for _ in 0..count {
            let repository = read_field(input, &mut at, authenticated_length)?;
            let repository = core::str::from_utf8(repository)
                .ok()
                .and_then(|value| RepositoryIdentity::parse(value).ok())
                .ok_or(AuthenticationError::InvalidConfiguration)?;
            let scopes = AccessScopes(read_byte(input, &mut at, authenticated_length)?);
            let valid_from = read_u64(input, &mut at, authenticated_length)?;
            let expires_at = read_u64(input, &mut at, authenticated_length)?;
            let revocation_generation = read_u64(input, &mut at, authenticated_length)?;
            let label = read_field(input, &mut at, authenticated_length)?;
            let label = core::str::from_utf8(label)
                .map_err(|_| AuthenticationError::InvalidConfiguration)?;
            let verifier = read_array32(input, &mut at, authenticated_length)?;
            let integrity = read_array32(input, &mut at, authenticated_length)?;
            if scopes.0 == 0
                || scopes.0 & !7 != 0
                || valid_from >= expires_at
                || revocation_generation == 0
                || label.is_empty()
                || label.len() > MAX_LABEL_BYTES
                || label.bytes().any(|byte| !(b' '..=b'~').contains(&byte))
                || verifier == [0; 32]
            {
                return Err(AuthenticationError::InvalidConfiguration);
            }
            let record = TokenRecord {
                repository,
                scopes,
                valid_from,
                expires_at,
                revocation_generation,
                label: label.into(),
                verifier,
                integrity,
            };
            if !constant_time_equal(&self.record_integrity(&record)?, &record.integrity) {
                return Err(AuthenticationError::InvalidConfiguration);
            }
            records.push(record);
        }
        if at != authenticated_length {
            return Err(AuthenticationError::InvalidConfiguration);
        }
        validate_record_order(&records)?;
        Ok(records)
    }
}

fn indexed_record<'a>(
    records: &'a [TokenRecord],
    verifier: &[u8; 32],
) -> (Option<&'a TokenRecord>, usize) {
    let mut low = 0usize;
    let mut high = records.len();
    let mut probes = 0usize;
    while low < high {
        probes += 1;
        let middle = low + (high - low) / 2;
        match records[middle].verifier.cmp(verifier) {
            core::cmp::Ordering::Less => low = middle + 1,
            core::cmp::Ordering::Greater => high = middle,
            core::cmp::Ordering::Equal => return (Some(&records[middle]), probes),
        }
    }
    (None, probes)
}

impl fmt::Debug for TokenAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenAuthority(<redacted>)")
    }
}

impl Drop for TokenAuthority {
    fn drop(&mut self) {
        erase(&mut self.pepper);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedAccess {
    AnonymousRead,
    Token,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationError {
    InvalidConfiguration,
    Entropy,
    Denied,
    Resource,
}

fn single_authorization(headers: &[Header]) -> Result<Option<&str>, AuthenticationError> {
    let mut values = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("authorization"));
    let value = values.next().map(|header| header.value.as_str());
    if values.next().is_some() {
        return Err(AuthenticationError::Denied);
    }
    Ok(value)
}

fn append_field(output: &mut Vector<u8>, value: &[u8]) -> Result<(), AuthenticationError> {
    let length = u16::try_from(value.len()).map_err(|_| AuthenticationError::Resource)?;
    output.extend(length.to_be_bytes());
    output
        .try_extend_from_slice(value)
        .map_err(|_| AuthenticationError::Resource)
}

fn validate_record_order(records: &[TokenRecord]) -> Result<(), AuthenticationError> {
    for pair in records.windows(2) {
        let left = (&pair[0].repository, &pair[0].verifier);
        let right = (&pair[1].repository, &pair[1].verifier);
        if left >= right {
            return Err(AuthenticationError::InvalidConfiguration);
        }
    }
    Ok(())
}

fn read_field<'a>(
    input: &'a [u8],
    at: &mut usize,
    end: usize,
) -> Result<&'a [u8], AuthenticationError> {
    let length = usize::from(read_u16(input, at, end)?);
    let next = at
        .checked_add(length)
        .ok_or(AuthenticationError::InvalidConfiguration)?;
    if next > end {
        return Err(AuthenticationError::InvalidConfiguration);
    }
    let value = &input[*at..next];
    *at = next;
    Ok(value)
}

fn read_byte(input: &[u8], at: &mut usize, end: usize) -> Result<u8, AuthenticationError> {
    if *at >= end {
        return Err(AuthenticationError::InvalidConfiguration);
    }
    let value = input[*at];
    *at += 1;
    Ok(value)
}

fn read_u16(input: &[u8], at: &mut usize, end: usize) -> Result<u16, AuthenticationError> {
    let next = at
        .checked_add(2)
        .ok_or(AuthenticationError::InvalidConfiguration)?;
    let bytes = input
        .get(*at..next.min(end))
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(AuthenticationError::InvalidConfiguration)?;
    *at = next;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u64(input: &[u8], at: &mut usize, end: usize) -> Result<u64, AuthenticationError> {
    let next = at
        .checked_add(8)
        .ok_or(AuthenticationError::InvalidConfiguration)?;
    if next > end {
        return Err(AuthenticationError::InvalidConfiguration);
    }
    let bytes = input[*at..next]
        .try_into()
        .map_err(|_| AuthenticationError::InvalidConfiguration)?;
    *at = next;
    Ok(u64::from_be_bytes(bytes))
}

fn read_array32(input: &[u8], at: &mut usize, end: usize) -> Result<[u8; 32], AuthenticationError> {
    let next = at
        .checked_add(32)
        .ok_or(AuthenticationError::InvalidConfiguration)?;
    if next > end {
        return Err(AuthenticationError::InvalidConfiguration);
    }
    let value = input[*at..next]
        .try_into()
        .map_err(|_| AuthenticationError::InvalidConfiguration)?;
    *at = next;
    Ok(value)
}

fn decode_token(value: &str) -> Result<[u8; TOKEN_BYTES], AuthenticationError> {
    if value.len() != TOKEN_TEXT_BYTES {
        return Err(AuthenticationError::Denied);
    }
    let mut output = [0u8; TOKEN_BYTES];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex(pair[0])? << 4) | hex(pair[1])?;
    }
    Ok(output)
}

fn hex(value: u8) -> Result<u8, AuthenticationError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(AuthenticationError::Denied),
    }
}

fn encode_hex(input: &[u8; TOKEN_BYTES], output: &mut [u8; TOKEN_TEXT_BYTES]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in input.iter().enumerate() {
        output[index * 2] = HEX[(byte >> 4) as usize];
        output[index * 2 + 1] = HEX[(byte & 15) as usize];
    }
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

#[inline(never)]
fn erase(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorization(token: &str) -> Vector<Header> {
        [Header {
            name: "authorization".into(),
            value: mrml_runtime::mrml_format!("Bearer {token}"),
        }]
        .into()
    }

    #[test]
    fn tokens_are_one_time_scoped_expiring_and_revocable() {
        let authority = TokenAuthority::new([7; 32]).unwrap();
        let repository = RepositoryIdentity::parse("owner/private").unwrap();
        let (mut token, record) = authority
            .issue(
                repository.clone(),
                AccessScopes::READ.union(AccessScopes::WRITE),
                100,
                200,
                9,
                "deployment token",
            )
            .unwrap();
        assert_eq!(
            mrml_runtime::mrml_format!("{:?}", token),
            "OneTimeAccessToken(<redacted>)"
        );
        assert!(mrml_runtime::mrml_format!("{:?}", record).contains("<redacted>"));
        let revealed = token
            .expose_once(|value| {
                assert_eq!(value.len(), 64);
                Text::from(value)
            })
            .unwrap();
        assert_eq!(revealed.len(), 64);
        assert!(token.reveal_once().is_none());
        let headers = authorization(&revealed);
        assert_eq!(
            authority.authorize(
                &headers,
                &repository,
                RepositoryAction::Write,
                RepositoryProfile::Private,
                150,
                9,
                core::slice::from_ref(&record),
            ),
            Ok(AuthenticatedAccess::Token)
        );
        for (candidate, action, now, generation) in [
            (
                RepositoryIdentity::parse("owner/other").unwrap(),
                RepositoryAction::Read,
                150,
                9,
            ),
            (repository.clone(), RepositoryAction::Administer, 150, 9),
            (repository.clone(), RepositoryAction::Read, 200, 9),
            (repository.clone(), RepositoryAction::Read, 150, 10),
        ] {
            assert_eq!(
                authority.authorize(
                    &headers,
                    &candidate,
                    action,
                    RepositoryProfile::Private,
                    now,
                    generation,
                    core::slice::from_ref(&record),
                ),
                Err(AuthenticationError::Denied)
            );
        }
        let mut records: Vector<TokenRecord> = [record].into();
        assert_eq!(
            authority.revoke_encoded_token(&mut records, &revealed),
            Ok(true)
        );
        assert!(records.is_empty());
        assert_eq!(
            authority.revoke_encoded_token(&mut records, &revealed),
            Ok(false)
        );
    }

    #[test]
    fn profiles_and_duplicate_headers_fail_closed() {
        let authority = TokenAuthority::new([9; 32]).unwrap();
        let repository = RepositoryIdentity::parse("owner/repo").unwrap();
        assert_eq!(
            authority.authorize(
                &[],
                &repository,
                RepositoryAction::Read,
                RepositoryProfile::PublicRead,
                1,
                1,
                &[],
            ),
            Ok(AuthenticatedAccess::AnonymousRead)
        );
        for profile in [RepositoryProfile::Private, RepositoryProfile::Protected] {
            assert_eq!(
                authority.authorize(&[], &repository, RepositoryAction::Read, profile, 1, 1, &[],),
                Err(AuthenticationError::Denied)
            );
        }
        let duplicate: Vector<Header> = [
            Header {
                name: "Authorization".into(),
                value: "Bearer 00".into(),
            },
            Header {
                name: "authorization".into(),
                value: "Bearer 00".into(),
            },
        ]
        .into();
        assert_eq!(
            authority.authorize(
                &duplicate,
                &repository,
                RepositoryAction::Read,
                RepositoryProfile::PublicRead,
                1,
                1,
                &[],
            ),
            Err(AuthenticationError::Denied)
        );
    }

    #[test]
    fn failed_authentication_is_bounded_before_repository_access() {
        let repository = RepositoryIdentity::parse("owner/private").unwrap();
        let invalid = authorization(
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        let authentication = GitdAuthentication::new(
            TokenAuthority::new([0x19; 32]).unwrap(),
            [RepositoryAccessPolicy {
                repository: repository.clone(),
                profile: RepositoryProfile::Private,
                revocation_generation: 1,
            }]
            .into(),
            Vector::new(),
        )
        .unwrap();
        let bucket = authentication
            .authority
            .failure_bucket(&invalid, &repository);
        for _ in 0..AUTH_FAILURES_PER_WINDOW {
            assert_eq!(
                authentication.authorize(&invalid, &repository, RepositoryAction::Read, 100),
                Err(AuthenticationError::Denied)
            );
        }
        assert_eq!(
            authentication.failures.lock().buckets[bucket].failures,
            AUTH_FAILURES_PER_WINDOW
        );
        assert_eq!(
            authentication.authorize(&invalid, &repository, RepositoryAction::Read, 100),
            Err(AuthenticationError::Denied)
        );
        assert_eq!(
            authentication.failures.lock().buckets[bucket].failures,
            AUTH_FAILURES_PER_WINDOW
        );
        assert_eq!(
            authentication.authorize(&invalid, &repository, RepositoryAction::Read, 160),
            Err(AuthenticationError::Denied)
        );
        assert_eq!(authentication.failures.lock().buckets[bucket].failures, 1);
    }

    #[test]
    fn verifier_lookup_is_logarithmic_at_configured_scale() {
        let repository = RepositoryIdentity::parse("owner/repository").unwrap();
        for count in [1usize, 1_000, 100_000, MAX_TOKEN_RECORDS] {
            let mut records = Vector::new();
            records.try_reserve_exact(count).unwrap();
            for value in 0..count {
                let mut verifier = [0u8; 32];
                verifier[24..].copy_from_slice(&(value as u64).to_be_bytes());
                records.push(TokenRecord {
                    repository: repository.clone(),
                    scopes: AccessScopes::READ,
                    valid_from: 1,
                    expires_at: 2,
                    revocation_generation: 1,
                    label: "scale".into(),
                    verifier,
                    integrity: [1; 32],
                });
            }
            let selected = records[count / 2].verifier;
            let (found, found_probes) = indexed_record(&records, &selected);
            assert_eq!(found.map(|record| record.verifier), Some(selected));
            let mut absent = [0xff; 32];
            absent[24..].copy_from_slice(&(count as u64).to_be_bytes());
            let (missing, missing_probes) = indexed_record(&records, &absent);
            assert!(missing.is_none());
            let maximum_probes = usize::BITS as usize - count.leading_zeros() as usize + 1;
            assert!(found_probes <= maximum_probes);
            assert!(missing_probes <= maximum_probes);
        }
    }

    #[test]
    fn canonical_token_store_round_trips_and_tampering_fails_closed() {
        let authority = TokenAuthority::new([0x31; 32]).unwrap();
        let repository = RepositoryIdentity::parse("owner/stored").unwrap();
        let (mut token, record) = authority
            .issue(
                repository.clone(),
                AccessScopes::READ,
                10,
                20,
                4,
                "stored token",
            )
            .unwrap();
        let (_, earlier_record) = authority
            .issue(
                RepositoryIdentity::parse("owner/aaa").unwrap(),
                AccessScopes::READ,
                10,
                20,
                4,
                "sort predecessor",
            )
            .unwrap();
        let encoded = authority.encode_records(&[record, earlier_record]).unwrap();
        let decoded = authority.decode_records(&encoded).unwrap();
        assert_eq!(decoded.len(), 2);
        let headers = authorization(&token.reveal_once().unwrap());
        assert_eq!(
            authority.authorize(
                &headers,
                &repository,
                RepositoryAction::Read,
                RepositoryProfile::Private,
                15,
                4,
                &decoded,
            ),
            Ok(AuthenticatedAccess::Token)
        );

        let mut tampered = encoded.clone();
        tampered[20] ^= 1;
        assert!(authority.decode_records(&tampered).is_err());
        assert!(
            authority
                .decode_records(&encoded[..encoded.len() - 1])
                .is_err()
        );
        assert!(
            TokenAuthority::new([0x32; 32])
                .unwrap()
                .decode_records(&encoded)
                .is_err()
        );
        let empty = authority.encode_records(&[]).unwrap();
        assert!(authority.decode_records(&empty).unwrap().is_empty());
    }
}
