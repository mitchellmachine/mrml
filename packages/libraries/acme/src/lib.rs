#![no_std]

#[cfg(test)]
extern crate std;

mod account;
mod ari;
mod base64url;
mod challenge;
mod challenge_http;
mod challenge_tls_alpn;
mod csr;
mod directory;
mod identifier;
mod jose;
mod local_authority;
mod nonce;
mod operation;
mod order;
mod payload;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod platform;
mod problem;
mod profile;
mod response;
mod state;
mod transaction;
mod transport;
mod url;

pub use account::{
    AccountError, AccountLifecycle, AccountOperation, AccountPolicy, CaClass, OwnerTermsApproval,
    PreparedAccountAction, PreparedTermsTransition,
};
pub use ari::{
    AriCertificateId, AriError, AriFetchError, MAX_ARI_CERTIFICATE_ID, MAX_ARI_RESPONSE_BYTES,
    RenewalInfo, RenewalWindow, fetch_renewal_info,
};
pub use base64url::{Base64UrlError, decode_base64url, encode_base64url};
pub use challenge::{
    ChallengeError, ChallengeLifecycle, ChallengePublicationRequest, ChallengePublisher,
    ChallengeToken, MAX_CHALLENGE_TOKEN, MAX_KEY_AUTHORIZATION, PublicationReceipt,
    PublicationState, dns01_txt_digest, publication_binding_digest, write_key_authorization,
};
pub use challenge_http::{
    Http01Error, MAX_HTTP01_HEADERS, MAX_HTTP01_REQUEST, validate_http01_request,
};
pub use challenge_tls_alpn::{
    ACME_TLS_ALPN_PROTOCOL, ApprovedTlsAlpnCertificateDigest, MAX_TLS_ALPN_CERTIFICATE,
    TlsAlpnCertificateSigner, TlsAlpnError, TlsAlpnSelection, select_tls_alpn01,
    write_tls_alpn01_certificate,
};
pub use csr::{
    ApprovedCsrDigest, CsrError, MAX_CSR_BYTES, MAX_CSR_IDENTIFIERS, Pkcs10Signer, write_pkcs10_csr,
};
pub use directory::{
    AcmeDirectory, DirectoryError, MAX_CAA_IDENTITIES, MAX_DIRECTORY_BYTES, MAX_DIRECTORY_PROFILES,
    ProfileAdvertisement,
};
pub use identifier::{DnsIdentifier, IdentifierError, MAX_DNS_NAME};
pub use jose::{
    AcmeJwsSigner, ApprovedAcmeJwsDigest, ApprovedEabMac, Es256Signature, ExternalAccountMac,
    JoseError, JwkThumbprint, P256Jwk, ProtectedKey, write_external_account_binding,
    write_flattened_jws, write_key_change_inner_jws,
};
pub use local_authority::{
    DeterministicAcmeAuthority, FirstPartyP256JwsVerifier, LOCAL_ACCOUNT_URL,
    LOCAL_AUTHORIZATION_URL, LOCAL_CERTIFICATE_URL, LOCAL_CHALLENGE_URL, LOCAL_DIRECTORY_URL,
    LOCAL_FINALIZE_URL, LOCAL_KEY_CHANGE_URL, LOCAL_NEW_ACCOUNT_URL, LOCAL_NEW_NONCE_URL,
    LOCAL_NEW_ORDER_URL, LOCAL_ORDER_URL, LOCAL_RENEWAL_INFO_CERTIFICATE_URL,
    LOCAL_RENEWAL_INFO_URL, LOCAL_REVOKE_URL, LocalAuthorityChallenge, LocalAuthorityError,
    LocalAuthorityFault, LocalAuthorityState, LocalJwsVerifier,
};
pub use nonce::{MAX_NONCE_BYTES, MAX_NONCES, MAX_SEEN_NONCES, NonceError, NoncePool, ReplayNonce};
pub use operation::{
    AccountActionResolutionError, AccountCreateBuffers, AccountRecoveryError, AccountRolloverError,
    AccountRolloverFailure, AccountUpdateError, AccountUpdateFailure, AuthorizationFetchError,
    AuthorizationResource, ChallengeSubmission, ChallengeSubmitError, CreateAccountError,
    DirectoryFetchError, FinalizeError, FinalizeFailure, OrderCreateBuffers, OrderCreateError,
    OrderCreateFailure, OrderPollError, OrderPollReceipt, PreauthorizationError,
    PreauthorizationResource, PrepareOrderError, PreparedOrderCreation, PreparedPreauthorization,
    RevocationOutcome, RevokeCertificateError, TermsTransitionError, TermsTransitionFailure,
    execute_prepared_account_create, execute_prepared_account_rollover,
    execute_prepared_account_update, execute_prepared_finalize, execute_prepared_order_create,
    execute_prepared_preauthorization, execute_prepared_terms_transition, fetch_authorization,
    fetch_directory, poll_order, prepare_order_creation, prepare_preauthorization,
    recover_uncertain_account_creation, resolve_uncertain_account_action, revoke_certificate,
    trigger_published_challenge,
};
pub use order::{
    AuthorizationBinding, AuthorizationState, ChallengeKind, ChallengeState, MAX_AUTHORIZATIONS,
    MAX_CHALLENGES_PER_AUTHORIZATION, MAX_ORDER_IDENTIFIERS, OrderError, OrderLifecycle,
    PreparedFinalization,
};
pub use payload::{
    MAX_ACCOUNT_CONTACT_BYTES, MAX_ACCOUNT_CONTACTS, MAX_ACME_PAYLOAD_BYTES, PayloadError,
    account_contacts_digest, write_account_contacts_payload, write_account_status_payload,
    write_finalize_payload, write_new_account_payload, write_new_order_payload,
    write_preauthorization_payload, write_revocation_payload, write_terms_agreement_payload,
};
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use platform::{HostedAcmeTransport, HostedTransportError};
pub use problem::{
    AcmeProblem, AcmeSubproblem, MAX_PROBLEM_BYTES, MAX_PROBLEM_DETAIL, MAX_PROBLEM_TYPE,
    MAX_SUBPROBLEMS, ProblemError, ProblemText,
};
pub use profile::{CertificateProfile, MAX_PROFILE_NAME, ProfileError};
pub use response::{
    AccountContact, ParsedAccountResponse, ParsedAccountStatus, ParsedAuthorizationResponse,
    ParsedChallenge, ParsedOrderResponse, ResponseError, parse_account_response,
    parse_authorization_response, parse_order_response,
};
pub use state::{AccountState, OrderState, StateError};
pub use transaction::{AcmePostError, AcmePostResponse, MAX_JWS_REQUEST_BYTES, post_jws};
pub use transport::{
    AcmeContentType, AcmeExchange, AcmeHttpMethod, AcmeResponseMetadata, AcmeResponseType,
    AcmeTransport, AcmeTransportRequest, AcmeTransportResponse, BadNonceRetry,
    MAX_ACME_RESPONSE_BODY, MAX_ALTERNATE_LINK_BYTES, MAX_ALTERNATE_LINKS, MAX_BAD_NONCE_RETRIES,
    MAX_CONTENT_TYPE_BYTES, MAX_RETRY_AFTER_BYTES, TransportError,
};
pub use url::{AcmeOrigin, AcmeScheme, AcmeUrl, MAX_URL_BYTES, UrlError};
