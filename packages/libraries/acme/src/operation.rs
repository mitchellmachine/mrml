use crate::{
    AccountError, AccountLifecycle, AccountOperation, AcmeDirectory, AcmeJwsSigner, AcmePostError,
    AcmeProblem, AcmeTransport, AcmeUrl, CertificateProfile, ChallengeError, ChallengeKind,
    ChallengeLifecycle, DnsIdentifier, JwkThumbprint, OrderError, OrderLifecycle, P256Jwk,
    ParsedAccountStatus, ParsedAuthorizationResponse, ParsedChallenge, PayloadError,
    PreparedAccountAction, PreparedFinalization, PublicationReceipt, ResponseError,
    account_contacts_digest, parse_account_response, parse_authorization_response,
    parse_order_response, post_jws, write_account_contacts_payload, write_account_status_payload,
    write_finalize_payload, write_key_change_inner_jws, write_new_account_payload,
    write_new_order_payload, write_preauthorization_payload, write_revocation_payload,
};
use mrml_crypto::Sha256;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CreateAccountError<E> {
    Payload(PayloadError),
    Post(AcmePostError<E>),
    Response(ResponseError),
    Lifecycle(AccountError),
    Server(AcmeProblem),
    UnexpectedStatus,
    MissingLocation,
    AccountNotValid,
    ContactMismatch,
    KeyMismatch,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum AccountUpdateError<E> {
    PreparedMismatch,
    Payload(PayloadError),
    Post(AcmePostError<E>),
    Server(AcmeProblem),
    UnexpectedStatus,
    Response(ResponseError),
    Lifecycle(AccountError),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum AccountUpdateFailure<E> {
    Definitive(AccountUpdateError<E>),
    Uncertain(AccountUpdateError<E>),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum AccountRecoveryError<E> {
    PreparedMismatch,
    Payload(PayloadError),
    Post(AcmePostError<E>),
    Server(AcmeProblem),
    UnexpectedStatus,
    MissingLocation,
    Response(ResponseError),
    Lifecycle(AccountError),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum AccountRolloverError<E> {
    PreparedMismatch,
    Jose(crate::JoseError),
    Post(AcmePostError<E>),
    Server(AcmeProblem),
    UnexpectedStatus,
    Response(ResponseError),
    Lifecycle(AccountError),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum AccountRolloverFailure<E> {
    Definitive(AccountRolloverError<E>),
    Uncertain(AccountRolloverError<E>),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum AccountActionResolutionError<E> {
    PreparedMismatch,
    Post(AcmePostError<E>),
    Server(AcmeProblem),
    UnexpectedStatus,
    Response(ResponseError),
    Lifecycle(AccountError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryFetchError<E> {
    Transport(crate::TransportError<E>),
    UnexpectedStatus,
    UnexpectedContentType,
    Encoding,
    Directory(crate::DirectoryError),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum OrderPollError<E> {
    ResourceMismatch,
    Post(AcmePostError<E>),
    Server(AcmeProblem),
    UnexpectedStatus,
    Response(ResponseError),
    Lifecycle(OrderError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderPollReceipt {
    pub order_generation: u64,
    pub has_retry_after: bool,
}

pub struct AccountCreateBuffers<'a> {
    pub payload: &'a mut [u8],
    pub response: &'a mut [u8],
    pub jws: &'a mut [u8],
}

pub fn fetch_directory<T: AcmeTransport>(
    configured_url: &AcmeUrl,
    generation: u64,
    exchange: &mut crate::AcmeExchange,
    transport: &mut T,
    response_body: &mut [u8],
) -> Result<AcmeDirectory, DirectoryFetchError<T::Error>> {
    let metadata = exchange
        .execute(
            transport,
            crate::AcmeTransportRequest {
                method: crate::AcmeHttpMethod::Get,
                url: configured_url,
                content_type: crate::AcmeContentType::Empty,
                body: &[],
            },
            response_body,
        )
        .map_err(DirectoryFetchError::Transport)?;
    if metadata.status != 200 {
        return Err(DirectoryFetchError::UnexpectedStatus);
    }
    if metadata.response_type != crate::AcmeResponseType::Json {
        return Err(DirectoryFetchError::UnexpectedContentType);
    }
    let source = core::str::from_utf8(&response_body[..metadata.body_length])
        .map_err(|_| DirectoryFetchError::Encoding)?;
    AcmeDirectory::parse(source, configured_url, generation).map_err(DirectoryFetchError::Directory)
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PreparedOrderCreation {
    pub directory_generation: u64,
    pub account_generation: u64,
    pub account_key: JwkThumbprint,
    pub request_digest: [u8; 32],
    pub deadline_unix: u64,
    pub retry_limit: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrepareOrderError {
    AccountInactive,
    DirectoryGenerationMismatch,
    ProfileGenerationMismatch,
    Payload(PayloadError),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum OrderCreateError<E> {
    PreparedMismatch,
    Payload(PayloadError),
    Post(AcmePostError<E>),
    Response(ResponseError),
    Lifecycle(OrderError),
    Server(AcmeProblem),
    UnexpectedStatus,
    MissingLocation,
    AuthorizationOutputTooSmall,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum OrderCreateFailure<E> {
    Definitive(OrderCreateError<E>),
    Uncertain(OrderCreateError<E>),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AuthorizationResource {
    pub url: AcmeUrl,
    pub order_url_digest: [u8; 32],
    pub directory_generation: u64,
    pub account_generation: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PreparedPreauthorization {
    pub directory_generation: u64,
    pub account_generation: u64,
    pub identifier: DnsIdentifier,
    pub request_digest: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PreauthorizationResource {
    pub url: AcmeUrl,
    pub identifier: DnsIdentifier,
    pub directory_generation: u64,
    pub account_generation: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum PreauthorizationError<E> {
    Unsupported,
    PreparedMismatch,
    Payload(PayloadError),
    Post(AcmePostError<E>),
    Server(AcmeProblem),
    UnexpectedStatus,
    MissingLocation,
    Response(ResponseError),
}

pub fn prepare_preauthorization(
    directory: &AcmeDirectory,
    account: &AccountLifecycle,
    identifier: DnsIdentifier,
    payload_scratch: &mut [u8],
) -> Result<PreparedPreauthorization, PreauthorizationError<core::convert::Infallible>> {
    if directory.new_authz.is_none() {
        return Err(PreauthorizationError::Unsupported);
    }
    if !account.active || account.directory_generation != directory.generation {
        return Err(PreauthorizationError::PreparedMismatch);
    }
    let payload = write_preauthorization_payload(&identifier, payload_scratch)
        .map_err(PreauthorizationError::Payload)?;
    Ok(PreparedPreauthorization {
        directory_generation: directory.generation,
        account_generation: account.generation,
        identifier,
        request_digest: Sha256::digest(payload.as_bytes()),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn execute_prepared_preauthorization<T: AcmeTransport>(
    prepared: PreparedPreauthorization,
    directory: &AcmeDirectory,
    account: &AccountLifecycle,
    exchange: &mut crate::AcmeExchange,
    transport: &mut T,
    signer: &mut impl AcmeJwsSigner,
    payload_scratch: &mut [u8],
    response_body: &mut [u8],
    jws_scratch: &mut [u8],
) -> Result<(PreauthorizationResource, ParsedAuthorizationResponse), PreauthorizationError<T::Error>>
{
    if !account.active
        || prepared.directory_generation != directory.generation
        || prepared.account_generation != account.generation
    {
        return Err(PreauthorizationError::PreparedMismatch);
    }
    let endpoint = directory
        .new_authz
        .as_ref()
        .ok_or(PreauthorizationError::Unsupported)?;
    let account_url = account
        .account_url
        .as_ref()
        .ok_or(PreauthorizationError::PreparedMismatch)?;
    let payload = write_preauthorization_payload(&prepared.identifier, payload_scratch)
        .map_err(PreauthorizationError::Payload)?;
    if Sha256::digest(payload.as_bytes()) != prepared.request_digest {
        return Err(PreauthorizationError::PreparedMismatch);
    }
    let result = post_jws(
        exchange,
        transport,
        &directory.new_nonce,
        endpoint,
        crate::ProtectedKey::Kid(account_url),
        payload.as_bytes(),
        account.generation,
        signer,
        response_body,
        jws_scratch,
    )
    .map_err(PreauthorizationError::Post)?;
    if let Some(problem) = result.problem {
        return Err(PreauthorizationError::Server(problem));
    }
    if result.metadata.status != 201
        || result.metadata.response_type != crate::AcmeResponseType::Json
    {
        return Err(PreauthorizationError::UnexpectedStatus);
    }
    let url = result
        .metadata
        .location
        .ok_or(PreauthorizationError::MissingLocation)?;
    let body = core::str::from_utf8(&response_body[..result.metadata.body_length])
        .map_err(|_| PreauthorizationError::Response(ResponseError::Malformed))?;
    let parsed = parse_authorization_response(body, endpoint.origin(), prepared.identifier)
        .map_err(PreauthorizationError::Response)?;
    Ok((
        PreauthorizationResource {
            url,
            identifier: prepared.identifier,
            directory_generation: directory.generation,
            account_generation: account.generation,
        },
        parsed,
    ))
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum AuthorizationFetchError<E> {
    ResourceMismatch,
    Post(AcmePostError<E>),
    Server(AcmeProblem),
    UnexpectedStatus,
    Response(ResponseError),
    ChallengeUnavailable,
    Lifecycle(OrderError),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ChallengeSubmitError<E> {
    ResourceMismatch,
    Publication(ChallengeError),
    Post(AcmePostError<E>),
    Server(AcmeProblem),
    UnexpectedStatus,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ChallengeSubmission {
    pub publication: PublicationReceipt,
    pub challenge_url_digest: [u8; 32],
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum FinalizeError<E> {
    PreparedMismatch,
    Payload(PayloadError),
    Post(AcmePostError<E>),
    Server(AcmeProblem),
    UnexpectedStatus,
    Response(ResponseError),
    Lifecycle(OrderError),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum FinalizeFailure<E> {
    Definitive(FinalizeError<E>),
    Uncertain(FinalizeError<E>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationOutcome {
    Submitted,
    AlreadyRevoked,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RevokeCertificateError<E> {
    Payload(PayloadError),
    Post(AcmePostError<E>),
    Server(AcmeProblem),
    UnexpectedStatus,
    UnexpectedResponse,
}

/// Submits an RFC 8555 certificate-revocation request with either the account
/// `kid` or the certificate JWK selected by the caller's use-only signing
/// route. Transport and malformed-success failures are deliberately ambiguous:
/// callers must retain their prepared revocation and resolve it by retrying the
/// exact request. `alreadyRevoked` is an authoritative successful resolution.
#[allow(clippy::too_many_arguments)]
pub fn revoke_certificate<T: AcmeTransport>(
    directory: &AcmeDirectory,
    certificate_der: &[u8],
    reason: Option<u8>,
    protected_key: crate::ProtectedKey<'_>,
    signing_generation: u64,
    exchange: &mut crate::AcmeExchange,
    transport: &mut T,
    signer: &mut impl AcmeJwsSigner,
    payload_scratch: &mut [u8],
    response_body: &mut [u8],
    jws_scratch: &mut [u8],
) -> Result<RevocationOutcome, RevokeCertificateError<T::Error>> {
    if exchange.directory_generation() != directory.generation {
        return Err(RevokeCertificateError::UnexpectedResponse);
    }
    let payload = write_revocation_payload(certificate_der, reason, payload_scratch)
        .map_err(RevokeCertificateError::Payload)?;
    let result = post_jws(
        exchange,
        transport,
        &directory.new_nonce,
        &directory.revoke_cert,
        protected_key,
        payload.as_bytes(),
        signing_generation,
        signer,
        response_body,
        jws_scratch,
    )
    .map_err(RevokeCertificateError::Post)?;
    if let Some(problem) = result.problem {
        return if problem.problem_type.as_str() == "urn:ietf:params:acme:error:alreadyRevoked" {
            Ok(RevocationOutcome::AlreadyRevoked)
        } else {
            Err(RevokeCertificateError::Server(problem))
        };
    }
    if result.metadata.status != 200 {
        return Err(RevokeCertificateError::UnexpectedStatus);
    }
    if result.metadata.body_length != 0
        || result.metadata.response_type != crate::AcmeResponseType::Missing
    {
        return Err(RevokeCertificateError::UnexpectedResponse);
    }
    Ok(RevocationOutcome::Submitted)
}

pub struct OrderCreateBuffers<'a> {
    pub payload: &'a mut [u8],
    pub response: &'a mut [u8],
    pub jws: &'a mut [u8],
    pub authorizations: &'a mut [Option<AuthorizationResource>],
}

pub fn prepare_order_creation(
    directory: &AcmeDirectory,
    account: &AccountLifecycle,
    identifiers: &[DnsIdentifier],
    profile: &CertificateProfile,
    replaces: Option<&str>,
    deadline_unix: u64,
    retry_limit: u8,
    payload_scratch: &mut [u8],
) -> Result<PreparedOrderCreation, PrepareOrderError> {
    if !account.active || account.account_url.is_none() {
        return Err(PrepareOrderError::AccountInactive);
    }
    if account.directory_generation != directory.generation {
        return Err(PrepareOrderError::DirectoryGenerationMismatch);
    }
    if profile.directory_generation() != directory.generation {
        return Err(PrepareOrderError::ProfileGenerationMismatch);
    }
    let payload = write_new_order_payload(identifiers, profile, replaces, payload_scratch)
        .map_err(PrepareOrderError::Payload)?;
    Ok(PreparedOrderCreation {
        directory_generation: directory.generation,
        account_generation: account.generation,
        account_key: account.key,
        request_digest: Sha256::digest(payload.as_bytes()),
        deadline_unix,
        retry_limit,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn execute_prepared_order_create<T: AcmeTransport>(
    prepared: PreparedOrderCreation,
    directory: &AcmeDirectory,
    account: &AccountLifecycle,
    identifiers: &[DnsIdentifier],
    profile: CertificateProfile,
    replaces: Option<&str>,
    now_unix: u64,
    exchange: &mut crate::AcmeExchange,
    transport: &mut T,
    signer: &mut impl AcmeJwsSigner,
    buffers: OrderCreateBuffers<'_>,
) -> Result<OrderLifecycle, OrderCreateFailure<T::Error>> {
    if !account.active
        || account.directory_generation != prepared.directory_generation
        || directory.generation != prepared.directory_generation
        || account.generation != prepared.account_generation
        || account.key != prepared.account_key
        || profile.directory_generation() != prepared.directory_generation
        || now_unix > prepared.deadline_unix
    {
        return Err(OrderCreateFailure::Definitive(
            OrderCreateError::PreparedMismatch,
        ));
    }
    let account_url = account
        .account_url
        .as_ref()
        .ok_or(OrderCreateFailure::Definitive(
            OrderCreateError::PreparedMismatch,
        ))?;
    if buffers.authorizations.len() < identifiers.len() {
        return Err(OrderCreateFailure::Definitive(
            OrderCreateError::AuthorizationOutputTooSmall,
        ));
    }
    let payload = write_new_order_payload(identifiers, &profile, replaces, buffers.payload)
        .map_err(|error| OrderCreateFailure::Definitive(OrderCreateError::Payload(error)))?;
    if Sha256::digest(payload.as_bytes()) != prepared.request_digest {
        return Err(OrderCreateFailure::Definitive(
            OrderCreateError::PreparedMismatch,
        ));
    }
    let result = post_jws(
        exchange,
        transport,
        &directory.new_nonce,
        &directory.new_order,
        crate::ProtectedKey::Kid(account_url),
        payload.as_bytes(),
        account.generation,
        signer,
        buffers.response,
        buffers.jws,
    )
    .map_err(|error| OrderCreateFailure::Uncertain(OrderCreateError::Post(error)))?;
    if let Some(problem) = result.problem {
        return Err(OrderCreateFailure::Definitive(OrderCreateError::Server(
            problem,
        )));
    }
    if result.metadata.response_type != crate::AcmeResponseType::Json {
        return Err(OrderCreateFailure::Uncertain(
            OrderCreateError::UnexpectedStatus,
        ));
    }
    if result.metadata.status != 201 {
        return Err(OrderCreateFailure::Uncertain(
            OrderCreateError::UnexpectedStatus,
        ));
    }
    let order_url = result
        .metadata
        .location
        .ok_or(OrderCreateFailure::Uncertain(
            OrderCreateError::MissingLocation,
        ))?;
    let body =
        core::str::from_utf8(&buffers.response[..result.metadata.body_length]).map_err(|_| {
            OrderCreateFailure::Uncertain(OrderCreateError::Response(ResponseError::Malformed))
        })?;
    let response = parse_order_response(
        body,
        directory.new_order.origin(),
        identifiers,
        profile.name(),
    )
    .map_err(|error| OrderCreateFailure::Uncertain(OrderCreateError::Response(error)))?;
    buffers.authorizations.fill(None);
    for (slot, url) in buffers
        .authorizations
        .iter_mut()
        .zip(response.authorizations())
    {
        *slot = Some(AuthorizationResource {
            url: *url,
            order_url_digest: Sha256::digest(order_url.as_str().as_bytes()),
            directory_generation: directory.generation,
            account_generation: account.generation,
        });
    }
    let response_status = response.status;
    let finalize_url = response.finalize;
    let certificate_url = response.certificate;
    let mut lifecycle = OrderLifecycle::create(
        directory,
        account.generation,
        account.key,
        order_url,
        finalize_url,
        profile,
        identifiers,
        prepared.deadline_unix,
        prepared.retry_limit,
    )
    .map_err(|error| OrderCreateFailure::Uncertain(OrderCreateError::Lifecycle(error)))?;
    lifecycle
        .apply_order_response(1, response_status, certificate_url, now_unix)
        .map_err(|error| OrderCreateFailure::Uncertain(OrderCreateError::Lifecycle(error)))?;
    Ok(lifecycle)
}

#[allow(clippy::too_many_arguments)]
pub fn fetch_authorization<T: AcmeTransport>(
    resource: AuthorizationResource,
    expected_identifier: DnsIdentifier,
    selected_challenge: Option<ChallengeKind>,
    response_generation: u64,
    now_unix: u64,
    directory: &AcmeDirectory,
    account: &AccountLifecycle,
    order: &mut OrderLifecycle,
    exchange: &mut crate::AcmeExchange,
    transport: &mut T,
    signer: &mut impl AcmeJwsSigner,
    response_body: &mut [u8],
    jws_scratch: &mut [u8],
) -> Result<ParsedAuthorizationResponse, AuthorizationFetchError<T::Error>> {
    if !account.active
        || resource.directory_generation != directory.generation
        || resource.directory_generation != order.directory_generation
        || resource.account_generation != account.generation
        || resource.account_generation != order.account_generation
        || resource.order_url_digest != Sha256::digest(order.order_url.as_str().as_bytes())
        || resource.url.origin() != order.order_url.origin()
    {
        return Err(AuthorizationFetchError::ResourceMismatch);
    }
    let account_url = account
        .account_url
        .as_ref()
        .ok_or(AuthorizationFetchError::ResourceMismatch)?;
    let result = post_jws(
        exchange,
        transport,
        &directory.new_nonce,
        &resource.url,
        crate::ProtectedKey::Kid(account_url),
        b"",
        account.generation,
        signer,
        response_body,
        jws_scratch,
    )
    .map_err(AuthorizationFetchError::Post)?;
    if let Some(problem) = result.problem {
        return Err(AuthorizationFetchError::Server(problem));
    }
    if result.metadata.response_type != crate::AcmeResponseType::Json {
        return Err(AuthorizationFetchError::UnexpectedStatus);
    }
    if result.metadata.status != 200 {
        return Err(AuthorizationFetchError::UnexpectedStatus);
    }
    let body = core::str::from_utf8(&response_body[..result.metadata.body_length])
        .map_err(|_| AuthorizationFetchError::Response(ResponseError::Malformed))?;
    let parsed =
        parse_authorization_response(body, directory.new_order.origin(), expected_identifier)
            .map_err(AuthorizationFetchError::Response)?;
    if selected_challenge.is_some_and(|selected| {
        !parsed
            .challenges()
            .any(|challenge| challenge.kind == selected)
    }) {
        return Err(AuthorizationFetchError::ChallengeUnavailable);
    }
    let url_digest = Sha256::digest(resource.url.as_str().as_bytes());
    if let Some(existing) = order.authorization_by_url_digest(url_digest) {
        if existing.identifier != expected_identifier {
            return Err(AuthorizationFetchError::ResourceMismatch);
        }
    } else {
        order
            .bind_authorization(
                resource.url,
                expected_identifier,
                parsed.wildcard,
                response_generation,
            )
            .map_err(AuthorizationFetchError::Lifecycle)?;
    }
    order
        .update_authorization(
            url_digest,
            response_generation,
            parsed.status,
            selected_challenge,
            now_unix,
        )
        .map_err(AuthorizationFetchError::Lifecycle)?;
    Ok(parsed)
}

#[allow(clippy::too_many_arguments)]
pub fn poll_order<T: AcmeTransport>(
    response_generation: u64,
    now_unix: u64,
    identifiers: &[DnsIdentifier],
    authorization_resources: &[AuthorizationResource],
    directory: &AcmeDirectory,
    account: &AccountLifecycle,
    order: &mut OrderLifecycle,
    exchange: &mut crate::AcmeExchange,
    transport: &mut T,
    signer: &mut impl AcmeJwsSigner,
    response_body: &mut [u8],
    jws_scratch: &mut [u8],
) -> Result<OrderPollReceipt, OrderPollError<T::Error>> {
    let order_digest = Sha256::digest(order.order_url.as_str().as_bytes());
    if !account.active
        || directory.generation != order.directory_generation
        || account.generation != order.account_generation
        || account.key != order.account_key
        || identifiers.len() != order.identifiers().count()
        || !identifiers
            .iter()
            .zip(order.identifiers())
            .all(|(provided, expected)| provided == expected)
        || authorization_resources.len() != identifiers.len()
        || authorization_resources.iter().any(|resource| {
            resource.order_url_digest != order_digest
                || resource.directory_generation != directory.generation
                || resource.account_generation != account.generation
        })
    {
        return Err(OrderPollError::ResourceMismatch);
    }
    order
        .consume_retry(now_unix)
        .map_err(OrderPollError::Lifecycle)?;
    let account_url = account
        .account_url
        .as_ref()
        .ok_or(OrderPollError::ResourceMismatch)?;
    let result = post_jws(
        exchange,
        transport,
        &directory.new_nonce,
        &order.order_url,
        crate::ProtectedKey::Kid(account_url),
        b"",
        account.generation,
        signer,
        response_body,
        jws_scratch,
    )
    .map_err(OrderPollError::Post)?;
    if let Some(problem) = result.problem {
        return Err(OrderPollError::Server(problem));
    }
    if result.metadata.status != 200
        || result.metadata.response_type != crate::AcmeResponseType::Json
    {
        return Err(OrderPollError::UnexpectedStatus);
    }
    let body = core::str::from_utf8(&response_body[..result.metadata.body_length])
        .map_err(|_| OrderPollError::Response(ResponseError::Malformed))?;
    let response = parse_order_response(
        body,
        order.order_url.origin(),
        identifiers,
        order.profile.name(),
    )
    .map_err(OrderPollError::Response)?;
    if response.finalize != order.finalize_url
        || !response
            .authorizations()
            .zip(authorization_resources)
            .all(|(returned, expected)| returned == &expected.url)
    {
        return Err(OrderPollError::ResourceMismatch);
    }
    order
        .apply_order_response(
            response_generation,
            response.status,
            response.certificate,
            now_unix,
        )
        .map_err(OrderPollError::Lifecycle)?;
    Ok(OrderPollReceipt {
        order_generation: response_generation,
        has_retry_after: result.metadata.has_retry_after,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn trigger_published_challenge<T: AcmeTransport>(
    resource: AuthorizationResource,
    challenge: ParsedChallenge,
    publication: &ChallengeLifecycle,
    now_unix: u64,
    directory: &AcmeDirectory,
    account: &AccountLifecycle,
    order: &OrderLifecycle,
    exchange: &mut crate::AcmeExchange,
    transport: &mut T,
    signer: &mut impl AcmeJwsSigner,
    response_body: &mut [u8],
    jws_scratch: &mut [u8],
) -> Result<ChallengeSubmission, ChallengeSubmitError<T::Error>> {
    let authorization_digest = Sha256::digest(resource.url.as_str().as_bytes());
    if !account.active
        || resource.directory_generation != directory.generation
        || resource.account_generation != account.generation
        || resource.order_url_digest != Sha256::digest(order.order_url.as_str().as_bytes())
        || publication.request.order_url_digest != resource.order_url_digest
        || publication.request.authorization_url_digest != authorization_digest
        || publication.request.identifier
            != order
                .authorization_by_url_digest(authorization_digest)
                .ok_or(ChallengeSubmitError::ResourceMismatch)?
                .identifier
        || publication.request.kind != challenge.kind
        || publication.request.token != challenge.token
    {
        return Err(ChallengeSubmitError::ResourceMismatch);
    }
    let publication_receipt = publication
        .require_active(now_unix)
        .map_err(ChallengeSubmitError::Publication)?;
    let account_url = account
        .account_url
        .as_ref()
        .ok_or(ChallengeSubmitError::ResourceMismatch)?;
    let result = post_jws(
        exchange,
        transport,
        &directory.new_nonce,
        &challenge.url,
        crate::ProtectedKey::Kid(account_url),
        b"{}",
        account.generation,
        signer,
        response_body,
        jws_scratch,
    )
    .map_err(ChallengeSubmitError::Post)?;
    if let Some(problem) = result.problem {
        return Err(ChallengeSubmitError::Server(problem));
    }
    if result.metadata.response_type != crate::AcmeResponseType::Json {
        return Err(ChallengeSubmitError::UnexpectedStatus);
    }
    if result.metadata.status != 200 {
        return Err(ChallengeSubmitError::UnexpectedStatus);
    }
    Ok(ChallengeSubmission {
        publication: publication_receipt,
        challenge_url_digest: Sha256::digest(challenge.url.as_str().as_bytes()),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn execute_prepared_finalize<T: AcmeTransport>(
    receipt: PreparedFinalization,
    csr_der: &[u8],
    identifiers: &[DnsIdentifier],
    now_unix: u64,
    directory: &AcmeDirectory,
    account: &AccountLifecycle,
    order: &mut OrderLifecycle,
    exchange: &mut crate::AcmeExchange,
    transport: &mut T,
    signer: &mut impl AcmeJwsSigner,
    buffers: AccountCreateBuffers<'_>,
) -> Result<(), FinalizeFailure<T::Error>> {
    if !account.active
        || account.generation != order.account_generation
        || account.key != order.account_key
        || account.key != receipt.account_key
        || directory.generation != order.directory_generation
        || receipt.csr_digest != Sha256::digest(csr_der)
        || receipt.finalize_url_digest != Sha256::digest(order.finalize_url.as_str().as_bytes())
        || identifiers.len() != order.identifiers().count()
        || !identifiers
            .iter()
            .zip(order.identifiers())
            .all(|(provided, expected)| provided == expected)
    {
        return Err(FinalizeFailure::Definitive(FinalizeError::PreparedMismatch));
    }
    let account_url = account
        .account_url
        .as_ref()
        .ok_or(FinalizeFailure::Definitive(FinalizeError::PreparedMismatch))?;
    let payload = write_finalize_payload(csr_der, buffers.payload)
        .map_err(|error| FinalizeFailure::Definitive(FinalizeError::Payload(error)))?;
    let result = post_jws(
        exchange,
        transport,
        &directory.new_nonce,
        &order.finalize_url,
        crate::ProtectedKey::Kid(account_url),
        payload.as_bytes(),
        account.generation,
        signer,
        buffers.response,
        buffers.jws,
    )
    .map_err(|error| FinalizeFailure::Uncertain(FinalizeError::Post(error)))?;
    if let Some(problem) = result.problem {
        order
            .abort_finalize(receipt)
            .map_err(|error| FinalizeFailure::Definitive(FinalizeError::Lifecycle(error)))?;
        return Err(FinalizeFailure::Definitive(FinalizeError::Server(problem)));
    }
    if result.metadata.response_type != crate::AcmeResponseType::Json {
        return Err(FinalizeFailure::Uncertain(FinalizeError::UnexpectedStatus));
    }
    if result.metadata.status != 200 {
        return Err(FinalizeFailure::Uncertain(FinalizeError::UnexpectedStatus));
    }
    let body =
        core::str::from_utf8(&buffers.response[..result.metadata.body_length]).map_err(|_| {
            FinalizeFailure::Uncertain(FinalizeError::Response(ResponseError::Malformed))
        })?;
    let response = parse_order_response(
        body,
        order.order_url.origin(),
        identifiers,
        order.profile.name(),
    )
    .map_err(|error| FinalizeFailure::Uncertain(FinalizeError::Response(error)))?;
    if !matches!(
        response.status,
        crate::OrderState::Processing | crate::OrderState::Valid
    ) {
        return Err(FinalizeFailure::Uncertain(FinalizeError::UnexpectedStatus));
    }
    order
        .commit_finalize(receipt)
        .map_err(|error| FinalizeFailure::Uncertain(FinalizeError::Lifecycle(error)))?;
    order
        .apply_order_response(
            receipt.order_generation,
            response.status,
            response.certificate,
            now_unix,
        )
        .map_err(|error| FinalizeFailure::Uncertain(FinalizeError::Lifecycle(error)))?;
    Ok(())
}

pub fn execute_prepared_account_create<T: AcmeTransport>(
    lifecycle: &mut AccountLifecycle,
    receipt: PreparedAccountAction,
    directory: &AcmeDirectory,
    contacts: &[&str],
    external_account_binding: Option<&str>,
    public_key: &P256Jwk,
    exchange: &mut crate::AcmeExchange,
    transport: &mut T,
    signer: &mut impl AcmeJwsSigner,
    buffers: AccountCreateBuffers<'_>,
) -> Result<AcmeUrl, CreateAccountError<T::Error>> {
    let expected_contacts =
        account_contacts_digest(contacts).map_err(CreateAccountError::Payload)?;
    if expected_contacts != receipt.contact_digest {
        return Err(CreateAccountError::ContactMismatch);
    }
    if public_key.thumbprint().ok() != receipt.new_key {
        return Err(CreateAccountError::KeyMismatch);
    }
    let payload = write_new_account_payload(
        contacts,
        directory.terms_of_service.is_some(),
        false,
        external_account_binding,
        buffers.payload,
    )
    .map_err(CreateAccountError::Payload)?;
    let result = post_jws(
        exchange,
        transport,
        &directory.new_nonce,
        &directory.new_account,
        crate::ProtectedKey::Jwk(public_key),
        payload.as_bytes(),
        0,
        signer,
        buffers.response,
        buffers.jws,
    );
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            lifecycle
                .mark_uncertain()
                .map_err(CreateAccountError::Lifecycle)?;
            return Err(CreateAccountError::Post(error));
        }
    };
    if let Some(problem) = result.problem {
        lifecycle
            .abort_prepared(receipt)
            .map_err(CreateAccountError::Lifecycle)?;
        return Err(CreateAccountError::Server(problem));
    }
    if result.metadata.response_type != crate::AcmeResponseType::Json {
        return uncertain(lifecycle, CreateAccountError::UnexpectedStatus);
    }
    let account_url = match result.metadata.location {
        Some(url) if result.metadata.status == 201 => url,
        Some(_) => return uncertain(lifecycle, CreateAccountError::UnexpectedStatus),
        None if result.metadata.status == 201 => {
            return uncertain(lifecycle, CreateAccountError::MissingLocation);
        }
        None => return uncertain(lifecycle, CreateAccountError::UnexpectedStatus),
    };
    let body = core::str::from_utf8(&buffers.response[..result.metadata.body_length])
        .map_err(|_| CreateAccountError::Response(ResponseError::Malformed));
    let body = match body {
        Ok(body) => body,
        Err(error) => return uncertain(lifecycle, error),
    };
    let parsed = match parse_account_response(body, directory.new_account.origin()) {
        Ok(parsed) => parsed,
        Err(error) => return uncertain(lifecycle, CreateAccountError::Response(error)),
    };
    if parsed.status != ParsedAccountStatus::Valid {
        return uncertain(lifecycle, CreateAccountError::AccountNotValid);
    }
    if parsed.contacts_digest != expected_contacts {
        return uncertain(lifecycle, CreateAccountError::ContactMismatch);
    }
    if let Err(error) = lifecycle.commit_created(receipt, account_url, directory) {
        return uncertain(lifecycle, CreateAccountError::Lifecycle(error));
    }
    Ok(account_url)
}

#[allow(clippy::too_many_arguments)]
pub fn execute_prepared_account_update<T: AcmeTransport>(
    lifecycle: &mut AccountLifecycle,
    receipt: PreparedAccountAction,
    directory: &AcmeDirectory,
    contacts: Option<&[&str]>,
    exchange: &mut crate::AcmeExchange,
    transport: &mut T,
    signer: &mut impl AcmeJwsSigner,
    buffers: AccountCreateBuffers<'_>,
) -> Result<(), AccountUpdateFailure<T::Error>> {
    if !lifecycle.active
        || lifecycle.account_url.is_none()
        || lifecycle.directory_generation != directory.generation
        || receipt.directory_generation != directory.generation
        || receipt.account_generation != lifecycle.generation.checked_add(1).unwrap_or(0)
        || receipt.old_key != Some(lifecycle.key)
        || receipt.new_key != Some(lifecycle.key)
            && receipt.action != AccountOperation::DeactivationPrepared
    {
        return Err(AccountUpdateFailure::Definitive(
            AccountUpdateError::PreparedMismatch,
        ));
    }
    let payload = match receipt.action {
        AccountOperation::ContactUpdatePrepared => {
            let contacts = contacts.ok_or(AccountUpdateFailure::Definitive(
                AccountUpdateError::PreparedMismatch,
            ))?;
            if account_contacts_digest(contacts).map_err(|error| {
                AccountUpdateFailure::Definitive(AccountUpdateError::Payload(error))
            })? != receipt.contact_digest
            {
                return Err(AccountUpdateFailure::Definitive(
                    AccountUpdateError::PreparedMismatch,
                ));
            }
            write_account_contacts_payload(contacts, buffers.payload).map_err(|error| {
                AccountUpdateFailure::Definitive(AccountUpdateError::Payload(error))
            })?
        }
        AccountOperation::DeactivationPrepared
            if contacts.is_none() && receipt.new_key.is_none() =>
        {
            write_account_status_payload(false, buffers.payload).map_err(|error| {
                AccountUpdateFailure::Definitive(AccountUpdateError::Payload(error))
            })?
        }
        _ => {
            return Err(AccountUpdateFailure::Definitive(
                AccountUpdateError::PreparedMismatch,
            ));
        }
    };
    let account_url = lifecycle.account_url.as_ref().unwrap();
    let result = post_jws(
        exchange,
        transport,
        &directory.new_nonce,
        account_url,
        crate::ProtectedKey::Kid(account_url),
        payload.as_bytes(),
        lifecycle.generation,
        signer,
        buffers.response,
        buffers.jws,
    );
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            lifecycle.mark_uncertain().map_err(|lifecycle_error| {
                AccountUpdateFailure::Uncertain(AccountUpdateError::Lifecycle(lifecycle_error))
            })?;
            return Err(AccountUpdateFailure::Uncertain(AccountUpdateError::Post(
                error,
            )));
        }
    };
    if let Some(problem) = result.problem {
        lifecycle.abort_prepared(receipt).map_err(|error| {
            AccountUpdateFailure::Definitive(AccountUpdateError::Lifecycle(error))
        })?;
        return Err(AccountUpdateFailure::Definitive(
            AccountUpdateError::Server(problem),
        ));
    }
    if result.metadata.status != 200
        || result.metadata.response_type != crate::AcmeResponseType::Json
    {
        lifecycle.mark_uncertain().map_err(|error| {
            AccountUpdateFailure::Uncertain(AccountUpdateError::Lifecycle(error))
        })?;
        return Err(AccountUpdateFailure::Uncertain(
            AccountUpdateError::UnexpectedStatus,
        ));
    }
    let body =
        core::str::from_utf8(&buffers.response[..result.metadata.body_length]).map_err(|_| {
            AccountUpdateFailure::Uncertain(AccountUpdateError::Response(ResponseError::Malformed))
        });
    let parsed = match body.and_then(|body| {
        parse_account_response(body, account_url.origin())
            .map_err(|error| AccountUpdateFailure::Uncertain(AccountUpdateError::Response(error)))
    }) {
        Ok(parsed) => parsed,
        Err(error) => {
            lifecycle.mark_uncertain().map_err(|lifecycle_error| {
                AccountUpdateFailure::Uncertain(AccountUpdateError::Lifecycle(lifecycle_error))
            })?;
            return Err(error);
        }
    };
    let response_matches = match receipt.action {
        AccountOperation::ContactUpdatePrepared => {
            parsed.status == ParsedAccountStatus::Valid
                && parsed.contacts_digest == receipt.contact_digest
        }
        AccountOperation::DeactivationPrepared => parsed.status == ParsedAccountStatus::Deactivated,
        _ => false,
    };
    if !response_matches {
        lifecycle.mark_uncertain().map_err(|error| {
            AccountUpdateFailure::Uncertain(AccountUpdateError::Lifecycle(error))
        })?;
        return Err(AccountUpdateFailure::Uncertain(
            AccountUpdateError::PreparedMismatch,
        ));
    }
    lifecycle
        .commit(receipt)
        .map_err(|error| AccountUpdateFailure::Uncertain(AccountUpdateError::Lifecycle(error)))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn recover_uncertain_account_creation<T: AcmeTransport>(
    lifecycle: &mut AccountLifecycle,
    receipt: PreparedAccountAction,
    directory: &AcmeDirectory,
    contacts: &[&str],
    public_key: &P256Jwk,
    exchange: &mut crate::AcmeExchange,
    transport: &mut T,
    signer: &mut impl AcmeJwsSigner,
    buffers: AccountCreateBuffers<'_>,
) -> Result<AcmeUrl, AccountRecoveryError<T::Error>> {
    if lifecycle.operation != AccountOperation::Uncertain
        || lifecycle.account_url.is_some()
        || receipt.action != AccountOperation::CreatePrepared
        || receipt.directory_generation != directory.generation
        || public_key.thumbprint().ok() != receipt.new_key
        || account_contacts_digest(contacts).ok() != Some(receipt.contact_digest)
    {
        return Err(AccountRecoveryError::PreparedMismatch);
    }
    let payload = write_new_account_payload(
        contacts,
        directory.terms_of_service.is_some(),
        true,
        None,
        buffers.payload,
    )
    .map_err(AccountRecoveryError::Payload)?;
    let result = post_jws(
        exchange,
        transport,
        &directory.new_nonce,
        &directory.new_account,
        crate::ProtectedKey::Jwk(public_key),
        payload.as_bytes(),
        0,
        signer,
        buffers.response,
        buffers.jws,
    )
    .map_err(AccountRecoveryError::Post)?;
    if let Some(problem) = result.problem {
        if problem.problem_type.as_str() == "urn:ietf:params:acme:error:accountDoesNotExist" {
            lifecycle
                .abort_uncertain(receipt)
                .map_err(AccountRecoveryError::Lifecycle)?;
        }
        return Err(AccountRecoveryError::Server(problem));
    }
    if result.metadata.status != 200
        || result.metadata.response_type != crate::AcmeResponseType::Json
    {
        return Err(AccountRecoveryError::UnexpectedStatus);
    }
    let account_url = result
        .metadata
        .location
        .ok_or(AccountRecoveryError::MissingLocation)?;
    let body = core::str::from_utf8(&buffers.response[..result.metadata.body_length])
        .map_err(|_| AccountRecoveryError::Response(ResponseError::Malformed))?;
    let parsed = parse_account_response(body, directory.new_account.origin())
        .map_err(AccountRecoveryError::Response)?;
    if parsed.status != ParsedAccountStatus::Valid
        || parsed.contacts_digest != receipt.contact_digest
    {
        return Err(AccountRecoveryError::PreparedMismatch);
    }
    lifecycle
        .resolve_created_authoritative(receipt, account_url, directory, parsed.contacts_digest)
        .map_err(AccountRecoveryError::Lifecycle)?;
    Ok(account_url)
}

/// Resolves an ambiguous contact update, deactivation, or key rollover by
/// authenticating POST-as-GET with the caller-selected old or new use-only key
/// route and comparing the authoritative account representation with both the
/// committed and prepared generations.
#[allow(clippy::too_many_arguments)]
pub fn resolve_uncertain_account_action<T: AcmeTransport>(
    lifecycle: &mut AccountLifecycle,
    receipt: PreparedAccountAction,
    directory: &AcmeDirectory,
    signing_key: &P256Jwk,
    exchange: &mut crate::AcmeExchange,
    transport: &mut T,
    signer: &mut impl AcmeJwsSigner,
    response_body: &mut [u8],
    jws_scratch: &mut [u8],
) -> Result<u64, AccountActionResolutionError<T::Error>> {
    let signing_thumbprint = signing_key
        .thumbprint()
        .map_err(|_| AccountActionResolutionError::PreparedMismatch)?;
    if lifecycle.operation != AccountOperation::Uncertain
        || lifecycle.directory_generation != directory.generation
        || receipt.directory_generation != directory.generation
        || !matches!(
            receipt.action,
            AccountOperation::ContactUpdatePrepared
                | AccountOperation::DeactivationPrepared
                | AccountOperation::RolloverPrepared
        )
        || (receipt.old_key != Some(signing_thumbprint)
            && receipt.new_key != Some(signing_thumbprint))
    {
        return Err(AccountActionResolutionError::PreparedMismatch);
    }
    let account_url = lifecycle
        .account_url
        .as_ref()
        .ok_or(AccountActionResolutionError::PreparedMismatch)?;
    let result = post_jws(
        exchange,
        transport,
        &directory.new_nonce,
        account_url,
        crate::ProtectedKey::Kid(account_url),
        b"",
        if signing_thumbprint == lifecycle.key {
            lifecycle.generation
        } else {
            receipt.account_generation
        },
        signer,
        response_body,
        jws_scratch,
    )
    .map_err(AccountActionResolutionError::Post)?;
    if let Some(problem) = result.problem {
        return Err(AccountActionResolutionError::Server(problem));
    }
    if result.metadata.status != 200
        || result.metadata.response_type != crate::AcmeResponseType::Json
    {
        return Err(AccountActionResolutionError::UnexpectedStatus);
    }
    let body = core::str::from_utf8(&response_body[..result.metadata.body_length])
        .map_err(|_| AccountActionResolutionError::Response(ResponseError::Malformed))?;
    let parsed = parse_account_response(body, account_url.origin())
        .map_err(AccountActionResolutionError::Response)?;
    let prepared_active = receipt.action != AccountOperation::DeactivationPrepared;
    let prepared_key = receipt
        .new_key
        .or(receipt.old_key)
        .ok_or(AccountActionResolutionError::PreparedMismatch)?;
    let prepared_matches = parsed.contacts_digest == receipt.contact_digest
        && parsed.status
            == if prepared_active {
                ParsedAccountStatus::Valid
            } else {
                ParsedAccountStatus::Deactivated
            }
        && signing_thumbprint == prepared_key;
    let committed_matches = parsed.contacts_digest == lifecycle.contact_digest
        && parsed.status
            == if lifecycle.active {
                ParsedAccountStatus::Valid
            } else {
                ParsedAccountStatus::Deactivated
            }
        && signing_thumbprint == lifecycle.key;
    let authoritative_generation = if prepared_matches {
        receipt.account_generation
    } else if committed_matches {
        lifecycle.generation
    } else {
        return Err(AccountActionResolutionError::PreparedMismatch);
    };
    lifecycle
        .resolve_authoritative(
            authoritative_generation,
            if prepared_matches {
                prepared_active
            } else {
                lifecycle.active
            },
            if prepared_matches {
                prepared_key
            } else {
                lifecycle.key
            },
            parsed.contacts_digest,
        )
        .map_err(AccountActionResolutionError::Lifecycle)?;
    Ok(authoritative_generation)
}

#[allow(clippy::too_many_arguments)]
pub fn execute_prepared_account_rollover<T: AcmeTransport>(
    lifecycle: &mut AccountLifecycle,
    receipt: PreparedAccountAction,
    directory: &AcmeDirectory,
    old_public_key: &P256Jwk,
    new_public_key: &P256Jwk,
    old_key_signer: &mut impl AcmeJwsSigner,
    new_key_signer: &mut impl AcmeJwsSigner,
    exchange: &mut crate::AcmeExchange,
    transport: &mut T,
    buffers: AccountCreateBuffers<'_>,
) -> Result<(), AccountRolloverFailure<T::Error>> {
    if !lifecycle.active
        || lifecycle.operation != AccountOperation::RolloverPrepared
        || lifecycle.directory_generation != directory.generation
        || receipt.action != AccountOperation::RolloverPrepared
        || receipt.account_generation != lifecycle.generation.checked_add(1).unwrap_or(0)
        || old_public_key.thumbprint().ok() != receipt.old_key
        || new_public_key.thumbprint().ok() != receipt.new_key
        || receipt.old_key != Some(lifecycle.key)
    {
        return Err(AccountRolloverFailure::Definitive(
            AccountRolloverError::PreparedMismatch,
        ));
    }
    let account_url = lifecycle
        .account_url
        .as_ref()
        .ok_or(AccountRolloverFailure::Definitive(
            AccountRolloverError::PreparedMismatch,
        ))?;
    let inner = write_key_change_inner_jws(
        new_public_key,
        old_public_key,
        account_url,
        &directory.key_change,
        directory.generation,
        lifecycle.generation,
        new_key_signer,
        buffers.payload,
    )
    .map_err(|error| AccountRolloverFailure::Definitive(AccountRolloverError::Jose(error)))?;
    let result = post_jws(
        exchange,
        transport,
        &directory.new_nonce,
        &directory.key_change,
        crate::ProtectedKey::Kid(account_url),
        inner,
        lifecycle.generation,
        old_key_signer,
        buffers.response,
        buffers.jws,
    );
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            lifecycle.mark_uncertain().map_err(|lifecycle_error| {
                AccountRolloverFailure::Uncertain(AccountRolloverError::Lifecycle(lifecycle_error))
            })?;
            return Err(AccountRolloverFailure::Uncertain(
                AccountRolloverError::Post(error),
            ));
        }
    };
    if let Some(problem) = result.problem {
        lifecycle.abort_prepared(receipt).map_err(|error| {
            AccountRolloverFailure::Definitive(AccountRolloverError::Lifecycle(error))
        })?;
        return Err(AccountRolloverFailure::Definitive(
            AccountRolloverError::Server(problem),
        ));
    }
    if result.metadata.status != 200
        || result.metadata.response_type != crate::AcmeResponseType::Json
    {
        lifecycle.mark_uncertain().map_err(|error| {
            AccountRolloverFailure::Uncertain(AccountRolloverError::Lifecycle(error))
        })?;
        return Err(AccountRolloverFailure::Uncertain(
            AccountRolloverError::UnexpectedStatus,
        ));
    }
    let body = core::str::from_utf8(&buffers.response[..result.metadata.body_length])
        .map_err(|_| AccountRolloverError::Response(ResponseError::Malformed));
    let parsed = match body.and_then(|body| {
        parse_account_response(body, account_url.origin()).map_err(AccountRolloverError::Response)
    }) {
        Ok(parsed) => parsed,
        Err(error) => {
            lifecycle.mark_uncertain().map_err(|lifecycle_error| {
                AccountRolloverFailure::Uncertain(AccountRolloverError::Lifecycle(lifecycle_error))
            })?;
            return Err(AccountRolloverFailure::Uncertain(error));
        }
    };
    if parsed.status != ParsedAccountStatus::Valid
        || parsed.contacts_digest != receipt.contact_digest
    {
        lifecycle.mark_uncertain().map_err(|error| {
            AccountRolloverFailure::Uncertain(AccountRolloverError::Lifecycle(error))
        })?;
        return Err(AccountRolloverFailure::Uncertain(
            AccountRolloverError::PreparedMismatch,
        ));
    }
    lifecycle.commit(receipt).map_err(|error| {
        AccountRolloverFailure::Uncertain(AccountRolloverError::Lifecycle(error))
    })?;
    Ok(())
}

fn uncertain<E>(
    lifecycle: &mut AccountLifecycle,
    error: CreateAccountError<E>,
) -> Result<AcmeUrl, CreateAccountError<E>> {
    lifecycle
        .mark_uncertain()
        .map_err(CreateAccountError::Lifecycle)?;
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AccountOperation, AccountPolicy, AcmeHttpMethod, AcmeTransportRequest,
        AcmeTransportResponse, ApprovedAcmeJwsDigest, CaClass, ChallengePublicationRequest,
        ChallengePublisher, Es256Signature, JoseError, PublicationState,
        publication_binding_digest,
    };

    struct Signer;
    impl AcmeJwsSigner for Signer {
        fn sign_acme_jws(
            &mut self,
            _: &ApprovedAcmeJwsDigest,
        ) -> Result<Es256Signature, JoseError> {
            Es256Signature::from_raw([1; 64])
        }
    }

    struct Transport {
        fail_post: bool,
    }

    struct RecoveryTransport {
        calls: usize,
    }
    struct DirectoryTransport;
    impl AcmeTransport for DirectoryTransport {
        type Error = ();
        fn exchange(
            &mut self,
            _request: AcmeTransportRequest<'_>,
            output: &mut [u8],
        ) -> Result<AcmeTransportResponse<'_>, Self::Error> {
            let body = br#"{"newNonce":"https://ca.example/new-nonce","newAccount":"https://ca.example/new-account","newOrder":"https://ca.example/new-order","revokeCert":"https://ca.example/revoke","keyChange":"https://ca.example/key-change"}"#;
            output[..body.len()].copy_from_slice(body);
            Ok(AcmeTransportResponse {
                status: 200,
                effective_url: "https://ca.example/directory",
                replay_nonce: None,
                retry_after: None,
                location: None,
                content_type: Some("application/json"),
                body_length: body.len(),
            })
        }
    }
    impl AcmeTransport for RecoveryTransport {
        type Error = ();
        fn exchange(
            &mut self,
            request: AcmeTransportRequest<'_>,
            output: &mut [u8],
        ) -> Result<AcmeTransportResponse<'_>, Self::Error> {
            self.calls += 1;
            if request.method == AcmeHttpMethod::Head {
                return Ok(AcmeTransportResponse {
                    status: 200,
                    effective_url: "https://ca.example/new-nonce",
                    replay_nonce: Some(if self.calls == 1 {
                        "recovery-nonce-1"
                    } else {
                        "recovery-nonce-2"
                    }),
                    retry_after: None,
                    location: None,
                    content_type: None,
                    body_length: 0,
                });
            }
            if self.calls == 2 {
                return Err(());
            }
            let body = br#"{"status":"valid","contact":["mailto:owner@example.com"],"orders":"https://ca.example/orders/1"}"#;
            output[..body.len()].copy_from_slice(body);
            Ok(AcmeTransportResponse {
                status: 200,
                effective_url: "https://ca.example/new-account",
                replay_nonce: Some("recovery-nonce-3"),
                retry_after: None,
                location: Some("https://ca.example/account/1"),
                content_type: Some("application/json"),
                body_length: body.len(),
            })
        }
    }

    struct OrderTransport {
        fail_post: bool,
    }

    struct Publisher;
    impl ChallengePublisher for Publisher {
        fn prepare(
            &mut self,
            request: ChallengePublicationRequest,
        ) -> Result<PublicationReceipt, ChallengeError> {
            Ok(PublicationReceipt {
                challenge_generation: request.challenge_generation,
                publisher_generation: 1,
                binding_digest: publication_binding_digest(&request),
                kind: request.kind,
            })
        }
        fn activate(&mut self, _: PublicationReceipt) -> Result<(), ChallengeError> {
            Ok(())
        }
        fn prepare_removal(
            &mut self,
            receipt: PublicationReceipt,
        ) -> Result<PublicationReceipt, ChallengeError> {
            Ok(receipt)
        }
        fn commit_removal(&mut self, _: PublicationReceipt) -> Result<(), ChallengeError> {
            Ok(())
        }
        fn authoritative_state(
            &mut self,
            _: PublicationReceipt,
        ) -> Result<PublicationState, ChallengeError> {
            Ok(PublicationState::Active)
        }
    }
    impl AcmeTransport for OrderTransport {
        type Error = ();
        fn exchange(
            &mut self,
            request: AcmeTransportRequest<'_>,
            output: &mut [u8],
        ) -> Result<AcmeTransportResponse<'_>, Self::Error> {
            if request.method == AcmeHttpMethod::Head {
                return Ok(AcmeTransportResponse {
                    status: 200,
                    effective_url: "https://ca.example/new-nonce",
                    replay_nonce: Some("order-nonce-1"),
                    retry_after: None,
                    location: None,
                    content_type: None,
                    body_length: 0,
                });
            }
            if self.fail_post {
                return Err(());
            }
            if request.url.as_str() == "https://ca.example/authz/1" {
                let body = br#"{"identifier":{"type":"dns","value":"example.com"},"status":"pending","challenges":[{"type":"http-01","url":"https://ca.example/challenge/1","status":"pending","token":"token-1"}]}"#;
                output[..body.len()].copy_from_slice(body);
                return Ok(AcmeTransportResponse {
                    status: 200,
                    effective_url: "https://ca.example/authz/1",
                    replay_nonce: Some("authz-nonce-1"),
                    retry_after: None,
                    location: None,
                    content_type: Some("application/json"),
                    body_length: body.len(),
                });
            }
            if request.url.as_str() == "https://ca.example/challenge/1" {
                let body = br#"{"type":"http-01","url":"https://ca.example/challenge/1","status":"processing","token":"token-1"}"#;
                output[..body.len()].copy_from_slice(body);
                return Ok(AcmeTransportResponse {
                    status: 200,
                    effective_url: "https://ca.example/challenge/1",
                    replay_nonce: Some("challenge-nonce-1"),
                    retry_after: None,
                    location: None,
                    content_type: Some("application/json"),
                    body_length: body.len(),
                });
            }
            if request.url.as_str() == "https://ca.example/order/1/finalize" {
                let body = br#"{"status":"valid","identifiers":[{"type":"dns","value":"example.com"}],"authorizations":["https://ca.example/authz/1"],"finalize":"https://ca.example/order/1/finalize","certificate":"https://ca.example/certificate/1","profile":"classic"}"#;
                output[..body.len()].copy_from_slice(body);
                return Ok(AcmeTransportResponse {
                    status: 200,
                    effective_url: "https://ca.example/order/1/finalize",
                    replay_nonce: Some("finalize-nonce-1"),
                    retry_after: None,
                    location: None,
                    content_type: Some("application/json"),
                    body_length: body.len(),
                });
            }
            if request.url.as_str() == "https://ca.example/order/1" {
                let body = br#"{"status":"ready","identifiers":[{"type":"dns","value":"example.com"}],"authorizations":["https://ca.example/authz/1"],"finalize":"https://ca.example/order/1/finalize","profile":"classic"}"#;
                output[..body.len()].copy_from_slice(body);
                return Ok(AcmeTransportResponse {
                    status: 200,
                    effective_url: "https://ca.example/order/1",
                    replay_nonce: Some("order-poll-nonce-1"),
                    retry_after: Some("5"),
                    location: None,
                    content_type: Some("application/json"),
                    body_length: body.len(),
                });
            }
            let body = br#"{"status":"pending","identifiers":[{"type":"dns","value":"example.com"}],"authorizations":["https://ca.example/authz/1"],"finalize":"https://ca.example/order/1/finalize","profile":"classic"}"#;
            output[..body.len()].copy_from_slice(body);
            Ok(AcmeTransportResponse {
                status: 201,
                effective_url: "https://ca.example/new-order",
                replay_nonce: Some("order-nonce-2"),
                retry_after: None,
                location: Some("https://ca.example/order/1"),
                content_type: Some("application/json"),
                body_length: body.len(),
            })
        }
    }
    impl AcmeTransport for Transport {
        type Error = ();
        fn exchange(
            &mut self,
            request: AcmeTransportRequest<'_>,
            output: &mut [u8],
        ) -> Result<AcmeTransportResponse<'_>, Self::Error> {
            if request.method == AcmeHttpMethod::Head {
                return Ok(AcmeTransportResponse {
                    status: 200,
                    effective_url: "https://ca.example/new-nonce",
                    replay_nonce: Some("nonce-1"),
                    retry_after: None,
                    location: None,
                    content_type: None,
                    body_length: 0,
                });
            }
            if self.fail_post {
                return Err(());
            }
            if request.url.as_str() == "https://ca.example/account/1" {
                let body = br#"{"status":"deactivated"}"#;
                output[..body.len()].copy_from_slice(body);
                return Ok(AcmeTransportResponse {
                    status: 200,
                    effective_url: "https://ca.example/account/1",
                    replay_nonce: Some("nonce-3"),
                    retry_after: None,
                    location: None,
                    content_type: Some("application/json"),
                    body_length: body.len(),
                });
            }
            if request.url.as_str() == "https://ca.example/key-change" {
                let body = br#"{"status":"valid","contact":["mailto:owner@example.com"],"orders":"https://ca.example/orders/1"}"#;
                output[..body.len()].copy_from_slice(body);
                return Ok(AcmeTransportResponse {
                    status: 200,
                    effective_url: "https://ca.example/key-change",
                    replay_nonce: Some("nonce-key-change"),
                    retry_after: None,
                    location: None,
                    content_type: Some("application/json"),
                    body_length: body.len(),
                });
            }
            let body = br#"{"status":"valid","contact":["mailto:owner@example.com"],"orders":"https://ca.example/orders/1"}"#;
            output[..body.len()].copy_from_slice(body);
            Ok(AcmeTransportResponse {
                status: 201,
                effective_url: "https://ca.example/new-account",
                replay_nonce: Some("nonce-2"),
                retry_after: None,
                location: Some("https://ca.example/account/1"),
                content_type: Some("application/json"),
                body_length: body.len(),
            })
        }
    }

    fn directory() -> AcmeDirectory {
        let url = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        AcmeDirectory::parse(
            r#"{"newNonce":"https://ca.example/new-nonce","newAccount":"https://ca.example/new-account","newOrder":"https://ca.example/new-order","revokeCert":"https://ca.example/revoke","keyChange":"https://ca.example/key-change","meta":{"profiles":{"classic":"https://docs.example/classic"}}}"#,
            &url,
            9,
        )
        .unwrap()
    }

    fn key() -> P256Jwk {
        P256Jwk::from_coordinates(
            [
                0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
                0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
                0xd8, 0x98, 0xc2, 0x96,
            ],
            [
                0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
                0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
                0x37, 0xbf, 0x51, 0xf5,
            ],
        )
        .unwrap()
    }

    fn replacement_key() -> P256Jwk {
        P256Jwk::from_coordinates(
            [
                0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e, 0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5,
                0x1a, 0xc3, 0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35, 0xa6, 0x0b, 0x48, 0xfc,
                0x47, 0x66, 0x99, 0x78,
            ],
            [
                0x07, 0x77, 0x55, 0x10, 0xdb, 0x8e, 0xd0, 0x40, 0x29, 0x3d, 0x9a, 0xc6, 0x9f, 0x74,
                0x30, 0xdb, 0xba, 0x7d, 0xad, 0xe6, 0x3c, 0xe9, 0x82, 0x29, 0x9e, 0x04, 0xb7, 0x9d,
                0x22, 0x78, 0x73, 0xd1,
            ],
        )
        .unwrap()
    }

    fn prepared() -> (
        AcmeDirectory,
        P256Jwk,
        AccountLifecycle,
        PreparedAccountAction,
    ) {
        let directory = directory();
        let key = key();
        let contacts = ["mailto:owner@example.com"];
        let policy = AccountPolicy {
            ca_class: CaClass::Staging,
            policy_generation: 4,
            contact_digest: account_contacts_digest(&contacts).unwrap(),
        };
        let (lifecycle, receipt) =
            AccountLifecycle::prepare_create(&directory, policy, &key, None, false).unwrap();
        (directory, key, lifecycle, receipt)
    }

    #[test]
    fn directory_fetch_is_authenticated_generation_input() {
        let url = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let mut exchange = crate::AcmeExchange::new(11, url);
        let mut transport = DirectoryTransport;
        let mut response = [0; 2048];
        let directory =
            fetch_directory(&url, 11, &mut exchange, &mut transport, &mut response).unwrap();
        assert_eq!(directory.generation, 11);
        assert_eq!(directory.new_order.as_str(), "https://ca.example/new-order");
    }

    fn creation_binds_signed_response_location_and_contacts_impl() {
        let (directory, key, mut lifecycle, receipt) = prepared();
        let origin = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let mut exchange = crate::AcmeExchange::new(directory.generation, origin);
        let mut transport = Transport { fail_post: false };
        let mut signer = Signer;
        let mut payload = [0; 2048];
        let mut response = [0; 2048];
        let mut jws = [0; 8192];
        let result = execute_prepared_account_create(
            &mut lifecycle,
            receipt,
            &directory,
            &["mailto:owner@example.com"],
            None,
            &key,
            &mut exchange,
            &mut transport,
            &mut signer,
            AccountCreateBuffers {
                payload: &mut payload,
                response: &mut response,
                jws: &mut jws,
            },
        );
        let url = match result {
            Ok(url) => url,
            Err(_) => panic!("prepared account creation failed"),
        };
        assert_eq!(url.as_str(), "https://ca.example/account/1");
        assert!(lifecycle.active);
        assert_eq!(lifecycle.generation, 1);
        assert_eq!(lifecycle.operation, AccountOperation::None);
        let deactivation = lifecycle.prepare_deactivation(5).unwrap();
        let result = execute_prepared_account_update(
            &mut lifecycle,
            deactivation,
            &directory,
            None,
            &mut exchange,
            &mut transport,
            &mut signer,
            AccountCreateBuffers {
                payload: &mut payload,
                response: &mut response,
                jws: &mut jws,
            },
        );
        assert!(result.is_ok());
        assert!(!lifecycle.active);
        assert_eq!(lifecycle.generation, 2);
    }

    #[test]
    fn ambiguous_post_failure_enters_uncertain_state() {
        let (directory, key, mut lifecycle, receipt) = prepared();
        let origin = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let mut exchange = crate::AcmeExchange::new(directory.generation, origin);
        let mut transport = Transport { fail_post: true };
        let mut signer = Signer;
        let mut payload = [0; 2048];
        let mut response = [0; 2048];
        let mut jws = [0; 8192];
        assert!(
            execute_prepared_account_create(
                &mut lifecycle,
                receipt,
                &directory,
                &["mailto:owner@example.com"],
                None,
                &key,
                &mut exchange,
                &mut transport,
                &mut signer,
                AccountCreateBuffers {
                    payload: &mut payload,
                    response: &mut response,
                    jws: &mut jws,
                },
            )
            .is_err()
        );
        assert_eq!(lifecycle.operation, AccountOperation::Uncertain);
    }

    fn lost_creation_response_recovers_existing_account_impl() {
        let (directory, key, mut lifecycle, receipt) = prepared();
        let origin = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let mut exchange = crate::AcmeExchange::new(directory.generation, origin);
        let mut transport = RecoveryTransport { calls: 0 };
        let mut signer = Signer;
        let mut payload = [0; 2048];
        let mut response = [0; 2048];
        let mut jws = [0; 8192];
        assert!(
            execute_prepared_account_create(
                &mut lifecycle,
                receipt,
                &directory,
                &["mailto:owner@example.com"],
                None,
                &key,
                &mut exchange,
                &mut transport,
                &mut signer,
                AccountCreateBuffers {
                    payload: &mut payload,
                    response: &mut response,
                    jws: &mut jws,
                },
            )
            .is_err()
        );
        let recovered = recover_uncertain_account_creation(
            &mut lifecycle,
            receipt,
            &directory,
            &["mailto:owner@example.com"],
            &key,
            &mut exchange,
            &mut transport,
            &mut signer,
            AccountCreateBuffers {
                payload: &mut payload,
                response: &mut response,
                jws: &mut jws,
            },
        );
        assert!(recovered.is_ok());
        assert!(lifecycle.active);
        assert_eq!(lifecycle.generation, 1);
        assert_eq!(lifecycle.operation, AccountOperation::None);
    }

    fn active_account() -> (AcmeDirectory, AccountLifecycle) {
        let (directory, _, mut lifecycle, receipt) = prepared();
        lifecycle
            .commit_created(
                receipt,
                AcmeUrl::parse("https://ca.example/account/1", false).unwrap(),
                &directory,
            )
            .unwrap();
        (directory, lifecycle)
    }

    fn account_rollover_uses_nested_new_and_old_key_signatures_impl() {
        let (directory, mut account) = active_account();
        let old_key = key();
        let new_key = replacement_key();
        let receipt = account.prepare_rollover(&new_key, 5).unwrap();
        let origin = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let mut exchange = crate::AcmeExchange::new(directory.generation, origin);
        let mut transport = Transport { fail_post: false };
        let mut old_signer = Signer;
        let mut new_signer = Signer;
        let mut payload = [0; 8192];
        let mut response = [0; 2048];
        let mut jws = [0; 16384];
        let result = execute_prepared_account_rollover(
            &mut account,
            receipt,
            &directory,
            &old_key,
            &new_key,
            &mut old_signer,
            &mut new_signer,
            &mut exchange,
            &mut transport,
            AccountCreateBuffers {
                payload: &mut payload,
                response: &mut response,
                jws: &mut jws,
            },
        );
        assert!(result.is_ok());
        assert!(account.key == new_key.thumbprint().unwrap());
        assert_eq!(account.generation, 2);
    }

    struct AccountResolutionTransport {
        calls: u8,
    }
    impl AcmeTransport for AccountResolutionTransport {
        type Error = ();
        fn exchange(
            &mut self,
            request: AcmeTransportRequest<'_>,
            output: &mut [u8],
        ) -> Result<AcmeTransportResponse<'_>, Self::Error> {
            self.calls += 1;
            if request.method == AcmeHttpMethod::Head {
                return Ok(AcmeTransportResponse {
                    status: 200,
                    effective_url: "https://ca.example/new-nonce",
                    replay_nonce: Some("resolution-nonce-1"),
                    retry_after: None,
                    location: None,
                    content_type: None,
                    body_length: 0,
                });
            }
            assert_eq!(request.url.as_str(), "https://ca.example/account/1");
            let body = br#"{"status":"valid","contact":["mailto:owner@example.com"],"orders":"https://ca.example/orders/1"}"#;
            output[..body.len()].copy_from_slice(body);
            Ok(AcmeTransportResponse {
                status: 200,
                effective_url: "https://ca.example/account/1",
                replay_nonce: Some("resolution-nonce-2"),
                retry_after: None,
                location: None,
                content_type: Some("application/json"),
                body_length: body.len(),
            })
        }
    }

    fn uncertain_rollover_resolves_with_new_use_only_key_impl() {
        let (directory, mut account) = active_account();
        let new_key = replacement_key();
        let receipt = account.prepare_rollover(&new_key, 5).unwrap();
        account.mark_uncertain().unwrap();
        let origin = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let mut exchange = crate::AcmeExchange::new(directory.generation, origin);
        let mut transport = AccountResolutionTransport { calls: 0 };
        let mut signer = Signer;
        let mut response = [0; 2048];
        let mut jws = [0; 8192];
        let resolved = resolve_uncertain_account_action(
            &mut account,
            receipt,
            &directory,
            &new_key,
            &mut exchange,
            &mut transport,
            &mut signer,
            &mut response,
            &mut jws,
        );
        assert!(matches!(resolved, Ok(2)));
        assert_eq!(account.operation, AccountOperation::None);
        assert_eq!(account.generation, 2);
        assert!(account.key == new_key.thumbprint().unwrap());
        assert_eq!(transport.calls, 2);
        assert!(jws.iter().all(|byte| *byte == 0));
    }

    fn order_creation_binds_prepared_payload_and_resource_impl() {
        let (directory, account) = active_account();
        let identifiers = [DnsIdentifier::parse("example.com", false).unwrap()];
        let profile = directory.profiles().next().unwrap().profile;
        let mut prepare_scratch = [0; 2048];
        let prepared = prepare_order_creation(
            &directory,
            &account,
            &identifiers,
            &profile,
            None,
            200,
            4,
            &mut prepare_scratch,
        )
        .unwrap();
        let origin = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let mut exchange = crate::AcmeExchange::new(directory.generation, origin);
        let mut transport = OrderTransport { fail_post: false };
        let mut signer = Signer;
        let mut payload = [0; 2048];
        let mut response = [0; 2048];
        let mut jws = [0; 8192];
        let mut authorizations = [None; 1];
        let created = execute_prepared_order_create(
            prepared,
            &directory,
            &account,
            &identifiers,
            profile,
            None,
            100,
            &mut exchange,
            &mut transport,
            &mut signer,
            OrderCreateBuffers {
                payload: &mut payload,
                response: &mut response,
                jws: &mut jws,
                authorizations: &mut authorizations,
            },
        );
        let mut created = match created {
            Ok(created) => created,
            Err(_) => panic!("prepared order creation failed"),
        };
        assert_eq!(created.order_url.as_str(), "https://ca.example/order/1");
        assert_eq!(created.state, crate::OrderState::Pending);
        assert_eq!(
            authorizations[0].unwrap().url.as_str(),
            "https://ca.example/authz/1"
        );
        let parsed = fetch_authorization(
            authorizations[0].unwrap(),
            identifiers[0],
            Some(ChallengeKind::Http01),
            1,
            100,
            &directory,
            &account,
            &mut created,
            &mut exchange,
            &mut transport,
            &mut signer,
            &mut response,
            &mut jws,
        );
        let parsed = match parsed {
            Ok(parsed) => parsed,
            Err(_) => panic!("authorization fetch failed"),
        };
        assert!(parsed.identifier == identifiers[0]);
        assert_eq!(created.authorizations().count(), 1);
        let challenge = *parsed.challenges().next().unwrap();
        let mut publication = ChallengeLifecycle::new(
            1,
            &created.order_url,
            &authorizations[0].unwrap().url,
            identifiers[0],
            ChallengeKind::Http01,
            challenge.token,
            account.key,
            90,
            150,
            3,
        )
        .unwrap();
        publication.publish(&mut Publisher).unwrap();
        let submitted = trigger_published_challenge(
            authorizations[0].unwrap(),
            challenge,
            &publication,
            100,
            &directory,
            &account,
            &created,
            &mut exchange,
            &mut transport,
            &mut signer,
            &mut response,
            &mut jws,
        );
        assert!(submitted.is_ok());
        let authorization_digest =
            Sha256::digest(authorizations[0].unwrap().url.as_str().as_bytes());
        created
            .update_authorization(
                authorization_digest,
                2,
                crate::AuthorizationState::Valid,
                Some(ChallengeKind::Http01),
                110,
            )
            .unwrap();
        let authorization_resources = [authorizations[0].unwrap()];
        let polled = poll_order(
            2,
            110,
            &identifiers,
            &authorization_resources,
            &directory,
            &account,
            &mut created,
            &mut exchange,
            &mut transport,
            &mut signer,
            &mut response,
            &mut jws,
        );
        let polled = match polled {
            Ok(polled) => polled,
            Err(_) => panic!("order poll failed"),
        };
        assert!(polled.has_retry_after);
        let csr = [1u8, 2, 3, 4];
        let finalize = created.prepare_finalize(&csr).unwrap();
        let finalized = execute_prepared_finalize(
            finalize,
            &csr,
            &identifiers,
            110,
            &directory,
            &account,
            &mut created,
            &mut exchange,
            &mut transport,
            &mut signer,
            AccountCreateBuffers {
                payload: &mut payload,
                response: &mut response,
                jws: &mut jws,
            },
        );
        assert!(finalized.is_ok());
        assert_eq!(created.state, crate::OrderState::Valid);
        assert_eq!(
            created.certificate_url.unwrap().as_str(),
            "https://ca.example/certificate/1"
        );
    }

    fn order_post_failure_is_explicitly_uncertain_impl() {
        let (directory, account) = active_account();
        let identifiers = [DnsIdentifier::parse("example.com", false).unwrap()];
        let profile = directory.profiles().next().unwrap().profile;
        let mut prepare_scratch = [0; 2048];
        let prepared = prepare_order_creation(
            &directory,
            &account,
            &identifiers,
            &profile,
            None,
            200,
            4,
            &mut prepare_scratch,
        )
        .unwrap();
        let origin = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let mut exchange = crate::AcmeExchange::new(directory.generation, origin);
        let mut transport = OrderTransport { fail_post: true };
        let mut signer = Signer;
        let mut payload = [0; 2048];
        let mut response = [0; 2048];
        let mut jws = [0; 8192];
        let mut authorizations = [None; 1];
        assert!(matches!(
            execute_prepared_order_create(
                prepared,
                &directory,
                &account,
                &identifiers,
                profile,
                None,
                100,
                &mut exchange,
                &mut transport,
                &mut signer,
                OrderCreateBuffers {
                    payload: &mut payload,
                    response: &mut response,
                    jws: &mut jws,
                    authorizations: &mut authorizations,
                },
            ),
            Err(OrderCreateFailure::Uncertain(OrderCreateError::Post(_)))
        ));
    }

    struct RevocationTransport {
        calls: u8,
        already_revoked: bool,
    }

    struct PreauthorizationTransport {
        calls: u8,
    }
    impl AcmeTransport for PreauthorizationTransport {
        type Error = ();
        fn exchange(
            &mut self,
            request: AcmeTransportRequest<'_>,
            output: &mut [u8],
        ) -> Result<AcmeTransportResponse<'_>, Self::Error> {
            self.calls += 1;
            if request.method == AcmeHttpMethod::Head {
                return Ok(AcmeTransportResponse {
                    status: 200,
                    effective_url: "https://ca.example/new-nonce",
                    replay_nonce: Some("preauth-nonce-1"),
                    retry_after: None,
                    location: None,
                    content_type: None,
                    body_length: 0,
                });
            }
            assert_eq!(request.url.as_str(), "https://ca.example/new-authz");
            let body = br#"{"identifier":{"type":"dns","value":"example.com"},"status":"pending","challenges":[{"type":"dns-01","url":"https://ca.example/challenge/preauth-1","status":"pending","token":"token-preauth"}]}"#;
            output[..body.len()].copy_from_slice(body);
            Ok(AcmeTransportResponse {
                status: 201,
                effective_url: "https://ca.example/new-authz",
                replay_nonce: Some("preauth-nonce-2"),
                retry_after: None,
                location: Some("https://ca.example/authz/preauth-1"),
                content_type: Some("application/json"),
                body_length: body.len(),
            })
        }
    }

    fn optional_preauthorization_is_prepared_and_resource_bound_impl() {
        let directory_url = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
        let directory = AcmeDirectory::parse(
            r#"{"newNonce":"https://ca.example/new-nonce","newAccount":"https://ca.example/new-account","newOrder":"https://ca.example/new-order","newAuthz":"https://ca.example/new-authz","revokeCert":"https://ca.example/revoke","keyChange":"https://ca.example/key-change"}"#,
            &directory_url,
            9,
        )
        .unwrap();
        let (_, account) = active_account();
        let identifier = DnsIdentifier::parse("example.com", false).unwrap();
        let mut payload = [0; 1024];
        let prepared =
            match prepare_preauthorization(&directory, &account, identifier, &mut payload) {
                Ok(value) => value,
                Err(_) => panic!("preauthorization preparation failed"),
            };
        let mut exchange = crate::AcmeExchange::new(directory.generation, directory_url);
        let mut transport = PreauthorizationTransport { calls: 0 };
        let mut signer = Signer;
        let mut response = [0; 2048];
        let mut jws = [0; 8192];
        let result = execute_prepared_preauthorization(
            prepared,
            &directory,
            &account,
            &mut exchange,
            &mut transport,
            &mut signer,
            &mut payload,
            &mut response,
            &mut jws,
        );
        let (resource, authorization) = match result {
            Ok(value) => value,
            Err(_) => panic!("preauthorization failed"),
        };
        assert_eq!(resource.url.as_str(), "https://ca.example/authz/preauth-1");
        assert!(resource.identifier == identifier);
        assert_eq!(authorization.status, crate::AuthorizationState::Pending);
        assert_eq!(transport.calls, 2);
    }

    impl AcmeTransport for RevocationTransport {
        type Error = ();

        fn exchange(
            &mut self,
            request: AcmeTransportRequest<'_>,
            output: &mut [u8],
        ) -> Result<AcmeTransportResponse<'_>, Self::Error> {
            self.calls += 1;
            if request.method == AcmeHttpMethod::Head {
                return Ok(AcmeTransportResponse {
                    status: 200,
                    effective_url: "https://ca.example/new-nonce",
                    replay_nonce: Some("revoke-nonce-1"),
                    retry_after: None,
                    location: None,
                    content_type: None,
                    body_length: 0,
                });
            }
            assert_eq!(request.url.as_str(), "https://ca.example/revoke");
            assert_eq!(request.content_type, crate::AcmeContentType::JoseJson);
            assert!(!request.body.is_empty());
            if self.already_revoked {
                let body = br#"{"type":"urn:ietf:params:acme:error:alreadyRevoked","status":400}"#;
                output[..body.len()].copy_from_slice(body);
                Ok(AcmeTransportResponse {
                    status: 400,
                    effective_url: "https://ca.example/revoke",
                    replay_nonce: Some("revoke-nonce-2"),
                    retry_after: None,
                    location: None,
                    content_type: Some("application/problem+json"),
                    body_length: body.len(),
                })
            } else {
                Ok(AcmeTransportResponse {
                    status: 200,
                    effective_url: "https://ca.example/revoke",
                    replay_nonce: Some("revoke-nonce-2"),
                    retry_after: None,
                    location: None,
                    content_type: None,
                    body_length: 0,
                })
            }
        }
    }

    fn revocation_accepts_exact_empty_success_and_authoritative_replay_impl() {
        for (already_revoked, expected) in [
            (false, RevocationOutcome::Submitted),
            (true, RevocationOutcome::AlreadyRevoked),
        ] {
            let directory = directory();
            let origin = AcmeUrl::parse("https://ca.example/directory", false).unwrap();
            let mut exchange = crate::AcmeExchange::new(directory.generation, origin);
            let mut transport = RevocationTransport {
                calls: 0,
                already_revoked,
            };
            let mut signer = Signer;
            let mut payload = [0; 1024];
            let mut response = [0; 1024];
            let mut jws = [0; 8192];
            let result = revoke_certificate(
                &directory,
                &[0x30, 0x01, 0x00],
                Some(1),
                crate::ProtectedKey::Jwk(&key()),
                12,
                &mut exchange,
                &mut transport,
                &mut signer,
                &mut payload,
                &mut response,
                &mut jws,
            );
            assert!(matches!(result, Ok(actual) if actual == expected));
            assert_eq!(transport.calls, 2);
            assert!(jws.iter().all(|byte| *byte == 0));
        }
    }

    fn run_order_test(test: fn()) {
        // Debug builds retain several 2 KiB fixed-capacity URL values while
        // crossing the parser/lifecycle boundary. Exercise that bounded path
        // on an explicitly provisioned service-sized stack on every host.
        std::thread::Builder::new()
            .name("acme-order-operation".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(test)
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn order_creation_binds_prepared_payload_and_resource() {
        run_order_test(order_creation_binds_prepared_payload_and_resource_impl);
    }

    #[test]
    fn order_post_failure_is_explicitly_uncertain() {
        run_order_test(order_post_failure_is_explicitly_uncertain_impl);
    }

    #[test]
    fn creation_binds_signed_response_location_and_contacts() {
        run_order_test(creation_binds_signed_response_location_and_contacts_impl);
    }

    #[test]
    fn lost_creation_response_recovers_existing_account() {
        run_order_test(lost_creation_response_recovers_existing_account_impl);
    }

    #[test]
    fn account_rollover_uses_nested_new_and_old_key_signatures() {
        run_order_test(account_rollover_uses_nested_new_and_old_key_signatures_impl);
    }

    #[test]
    fn uncertain_rollover_resolves_with_new_use_only_key() {
        run_order_test(uncertain_rollover_resolves_with_new_use_only_key_impl);
    }

    #[test]
    fn revocation_accepts_exact_empty_success_and_authoritative_replay() {
        run_order_test(revocation_accepts_exact_empty_success_and_authoritative_replay_impl);
    }

    #[test]
    fn optional_preauthorization_is_prepared_and_resource_bound() {
        run_order_test(optional_preauthorization_is_prepared_and_resource_bound_impl);
    }
}
