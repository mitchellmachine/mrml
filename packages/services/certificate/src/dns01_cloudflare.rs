extern crate std;

use crate::{
    Dns01Provider, Dns01ProviderError, Dns01PublicationReceipt, Dns01PublicationRequest,
    Dns01RecordName, Dns01TxtValue, HostedSecret, MAX_DNS01_PROVIDER_RECORD_ID_BYTES,
    PRODUCTION_SECRET_MODE, dns01_publication_binding,
};
use mrml_acme::DnsIdentifier;
use mrml_crypto::erase_secret_bytes;
use mrml_http::{Client, HttpError, Response};
use mrml_json::Value;
use std::format;
use std::path::Path;
use std::string::String;

const API_ORIGIN: &str = "https://api.cloudflare.com";
const MAX_CLOUDFLARE_TOKEN_BYTES: usize = 512;
const MAX_CLOUDFLARE_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_CLOUDFLARE_RECORDS_PER_NAME: usize = 100;

pub struct CloudflareDns01Provider {
    client: Client,
    token: HostedSecret,
    zone_id: [u8; 32],
    zone: DnsIdentifier,
}

impl CloudflareDns01Provider {
    pub fn open(
        token_path: &Path,
        expected_uid: u32,
        zone_id: &str,
        zone: DnsIdentifier,
    ) -> Result<Self, Dns01ProviderError> {
        if zone.is_wildcard() || !valid_hex_identifier(zone_id) {
            return Err(Dns01ProviderError::InvalidRequest);
        }
        let token = HostedSecret::open(
            token_path,
            expected_uid,
            PRODUCTION_SECRET_MODE,
            MAX_CLOUDFLARE_TOKEN_BYTES,
        )
        .map_err(|_| Dns01ProviderError::ProviderUnavailable)?;
        if token.expose().len() < 20
            || !token
                .expose()
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(Dns01ProviderError::ProviderUnavailable);
        }
        let mut encoded_zone = [0u8; 32];
        encoded_zone.copy_from_slice(zone_id.as_bytes());
        Ok(Self {
            client: Client::new().user_agent("mrml-acmed/0.1"),
            token,
            zone_id: encoded_zone,
            zone,
        })
    }

    fn list_exact(
        &self,
        name: Dns01RecordName,
        value: Dns01TxtValue,
    ) -> Result<Option<String>, Dns01ProviderError> {
        let url = format!(
            "{API_ORIGIN}/client/v4/zones/{}/dns_records?name={}&per_page=100",
            self.zone_id(),
            name.as_str()
        );
        let response = self.request(Request::Get(&url))?;
        let body = response_body(response)?;
        parse_list_response(&body, name.as_str(), value.as_str())
    }

    fn create_exact(
        &self,
        name: Dns01RecordName,
        value: Dns01TxtValue,
    ) -> Result<String, Dns01ProviderError> {
        let url = format!(
            "{API_ORIGIN}/client/v4/zones/{}/dns_records",
            self.zone_id()
        );
        let body = format!(
            "{{\"type\":\"TXT\",\"name\":\"{}\",\"content\":\"{}\",\"ttl\":60}}",
            name.as_str(),
            value.as_str()
        );
        let response = self.request(Request::Post(&url, body.as_bytes()))?;
        let body = response_body(response)?;
        parse_single_response(&body, name.as_str(), value.as_str())
    }

    fn record_still_matches(
        &self,
        record_id: &str,
        name: Dns01RecordName,
        value: Dns01TxtValue,
    ) -> Result<bool, Dns01ProviderError> {
        if !valid_hex_identifier(record_id) {
            return Err(Dns01ProviderError::InvalidReceipt);
        }
        let url = format!(
            "{API_ORIGIN}/client/v4/zones/{}/dns_records/{record_id}",
            self.zone_id()
        );
        let response = self.request_allow_not_found(Request::Get(&url))?;
        let Some(response) = response else {
            return Ok(false);
        };
        let body = response_body(response)?;
        Ok(parse_single_response(&body, name.as_str(), value.as_str())? == record_id)
    }

    fn delete_record(&self, record_id: &str) -> Result<(), Dns01ProviderError> {
        let url = format!(
            "{API_ORIGIN}/client/v4/zones/{}/dns_records/{record_id}",
            self.zone_id()
        );
        let response = self.request_allow_not_found(Request::Delete(&url))?;
        let Some(response) = response else {
            return Ok(());
        };
        let body = response_body(response)?;
        let value = parse_json(&body)?;
        if value.get("success").and_then(Value::as_bool) != Some(true)
            || value
                .get("result")
                .and_then(|result| result.get("id"))
                .and_then(Value::as_str)
                != Some(record_id)
        {
            return Err(Dns01ProviderError::ProviderUnavailable);
        }
        Ok(())
    }

    fn request(&self, request: Request<'_>) -> Result<Response, Dns01ProviderError> {
        self.request_allow_not_found(request)?
            .ok_or(Dns01ProviderError::ProviderUnavailable)
    }

    fn request_allow_not_found(
        &self,
        request: Request<'_>,
    ) -> Result<Option<Response>, Dns01ProviderError> {
        let mut authorization = [0u8; 7 + MAX_CLOUDFLARE_TOKEN_BYTES];
        authorization[..7].copy_from_slice(b"Bearer ");
        let token = self.token.expose();
        authorization[7..7 + token.len()].copy_from_slice(token);
        let header = core::str::from_utf8(&authorization[..7 + token.len()])
            .map_err(|_| Dns01ProviderError::ProviderUnavailable)?;
        let result = match request {
            Request::Get(url) => self.client.get(url, &[("Authorization", header)]),
            Request::Post(url, body) => self.client.post(
                url,
                &[
                    ("Authorization", header),
                    ("Content-Type", "application/json"),
                ],
                body,
            ),
            Request::Delete(url) => self.client.delete(url, &[("Authorization", header)]),
        };
        erase_secret_bytes(&mut authorization);
        let response = result.map_err(map_http)?;
        match response.status {
            200..=299 => Ok(Some(response)),
            404 => Ok(None),
            429 => Err(Dns01ProviderError::RateLimited),
            _ => Err(Dns01ProviderError::ProviderUnavailable),
        }
    }

    fn zone_id(&self) -> &str {
        core::str::from_utf8(&self.zone_id).expect("validated Cloudflare zone ID is ASCII")
    }
}

impl Dns01Provider for CloudflareDns01Provider {
    fn publish(
        &mut self,
        request: Dns01PublicationRequest,
    ) -> Result<Dns01PublicationReceipt, Dns01ProviderError> {
        if request.operation_id == [0; 16]
            || request.generation == 0
            || !inside_zone(request.identifier, self.zone)
        {
            return Err(Dns01ProviderError::InvalidRequest);
        }
        let name = Dns01RecordName::for_identifier(request.identifier)?;
        let value = Dns01TxtValue::from_key_authorization_digest(request.key_authorization_digest);
        let record_id = match self.list_exact(name, value)? {
            Some(record_id) => record_id,
            None => self.create_exact(name, value)?,
        };
        make_receipt(request, name, value, &record_id)
    }

    fn cleanup(&mut self, receipt: Dns01PublicationReceipt) -> Result<(), Dns01ProviderError> {
        let record_id = receipt.provider_record_id()?;
        let request = Dns01PublicationRequest {
            operation_id: receipt.operation_id,
            generation: receipt.generation,
            identifier: receipt.identifier,
            key_authorization_digest: receipt.key_authorization_digest,
        };
        if receipt.binding_digest
            != dns01_publication_binding(request, receipt.name, receipt.value, record_id)
        {
            return Err(Dns01ProviderError::InvalidReceipt);
        }
        if self.record_still_matches(record_id, receipt.name, receipt.value)? {
            self.delete_record(record_id)?;
        }
        Ok(())
    }
}

enum Request<'a> {
    Get(&'a str),
    Post(&'a str, &'a [u8]),
    Delete(&'a str),
}

fn response_body(mut response: Response) -> Result<mrml_runtime::Vector<u8>, Dns01ProviderError> {
    response
        .read_to_end(MAX_CLOUDFLARE_RESPONSE_BYTES)
        .map_err(map_http)
}

fn parse_json(body: &[u8]) -> Result<Value, Dns01ProviderError> {
    let text = core::str::from_utf8(body).map_err(|_| Dns01ProviderError::ProviderUnavailable)?;
    mrml_json::parse(text).map_err(|_| Dns01ProviderError::ProviderUnavailable)
}

fn parse_list_response(
    body: &[u8],
    expected_name: &str,
    expected_value: &str,
) -> Result<Option<String>, Dns01ProviderError> {
    let value = parse_json(body)?;
    if value.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(Dns01ProviderError::ProviderUnavailable);
    }
    let records = value
        .get("result")
        .and_then(Value::as_array)
        .ok_or(Dns01ProviderError::ProviderUnavailable)?;
    if records.len() > MAX_CLOUDFLARE_RECORDS_PER_NAME {
        return Err(Dns01ProviderError::Capacity);
    }
    let mut matching = None;
    for record in records {
        if record.get("name").and_then(Value::as_str) != Some(expected_name) {
            continue;
        }
        match record.get("type").and_then(Value::as_str) {
            Some("CNAME") => return Err(Dns01ProviderError::AmbiguousRecord),
            Some("TXT") => {}
            _ => continue,
        }
        if record.get("content").and_then(Value::as_str) == Some(expected_value) {
            let id = validated_record_id(record)?;
            if matching.replace(String::from(id)).is_some() {
                return Err(Dns01ProviderError::AmbiguousRecord);
            }
        }
    }
    Ok(matching)
}

fn parse_single_response(
    body: &[u8],
    expected_name: &str,
    expected_value: &str,
) -> Result<String, Dns01ProviderError> {
    let value = parse_json(body)?;
    if value.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(Dns01ProviderError::ProviderUnavailable);
    }
    let record = value
        .get("result")
        .ok_or(Dns01ProviderError::ProviderUnavailable)?;
    if record.get("type").and_then(Value::as_str) != Some("TXT")
        || record.get("name").and_then(Value::as_str) != Some(expected_name)
        || record.get("content").and_then(Value::as_str) != Some(expected_value)
    {
        return Err(Dns01ProviderError::InvalidReceipt);
    }
    Ok(String::from(validated_record_id(record)?))
}

fn validated_record_id(record: &Value) -> Result<&str, Dns01ProviderError> {
    let id = record
        .get("id")
        .and_then(Value::as_str)
        .ok_or(Dns01ProviderError::InvalidReceipt)?;
    valid_hex_identifier(id)
        .then_some(id)
        .ok_or(Dns01ProviderError::InvalidReceipt)
}

fn make_receipt(
    request: Dns01PublicationRequest,
    name: Dns01RecordName,
    value: Dns01TxtValue,
    record_id: &str,
) -> Result<Dns01PublicationReceipt, Dns01ProviderError> {
    if record_id.len() > MAX_DNS01_PROVIDER_RECORD_ID_BYTES || !record_id.is_ascii() {
        return Err(Dns01ProviderError::InvalidReceipt);
    }
    let mut provider_record_id = [0u8; MAX_DNS01_PROVIDER_RECORD_ID_BYTES];
    provider_record_id[..record_id.len()].copy_from_slice(record_id.as_bytes());
    Ok(Dns01PublicationReceipt {
        operation_id: request.operation_id,
        generation: request.generation,
        identifier: request.identifier,
        key_authorization_digest: request.key_authorization_digest,
        name,
        value,
        provider_record_id,
        provider_record_id_length: record_id.len() as u8,
        binding_digest: dns01_publication_binding(request, name, value, record_id),
    })
}

fn inside_zone(identifier: DnsIdentifier, zone: DnsIdentifier) -> bool {
    let name = identifier
        .as_str()
        .strip_prefix("*.")
        .unwrap_or(identifier.as_str());
    name == zone.as_str()
        || name
            .strip_suffix(zone.as_str())
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn valid_hex_identifier(value: &str) -> bool {
    value.len() == 32
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn map_http(error: HttpError) -> Dns01ProviderError {
    match error {
        HttpError::BodyTooLarge => Dns01ProviderError::Capacity,
        _ => Dns01ProviderError::ProviderUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_preserves_unrelated_txt_and_rejects_cname_or_duplicates() {
        let value = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let body = format!(
            "{{\"success\":true,\"result\":[{{\"id\":\"0123456789abcdef0123456789abcdef\",\"type\":\"TXT\",\"name\":\"_acme-challenge.example.com\",\"content\":\"unrelated\"}},{{\"id\":\"fedcba9876543210fedcba9876543210\",\"type\":\"TXT\",\"name\":\"_acme-challenge.example.com\",\"content\":\"{value}\"}}]}}"
        );
        assert_eq!(
            parse_list_response(body.as_bytes(), "_acme-challenge.example.com", value)
                .unwrap()
                .as_deref(),
            Some("fedcba9876543210fedcba9876543210")
        );
        let cname = b"{\"success\":true,\"result\":[{\"id\":\"0123456789abcdef0123456789abcdef\",\"type\":\"CNAME\",\"name\":\"_acme-challenge.example.com\",\"content\":\"target.example\"}]}";
        assert_eq!(
            parse_list_response(cname, "_acme-challenge.example.com", value),
            Err(Dns01ProviderError::AmbiguousRecord)
        );
    }

    #[test]
    fn zones_and_provider_receipts_are_exact() {
        let zone = DnsIdentifier::parse("example.com", false).unwrap();
        assert!(inside_zone(
            DnsIdentifier::parse("*.git.example.com", true).unwrap(),
            zone
        ));
        assert!(!inside_zone(
            DnsIdentifier::parse("notexample.com", false).unwrap(),
            zone
        ));
        assert!(valid_hex_identifier("0123456789abcdef0123456789abcdef"));
        assert!(!valid_hex_identifier("0123456789ABCDEF0123456789ABCDEF"));
    }
}
