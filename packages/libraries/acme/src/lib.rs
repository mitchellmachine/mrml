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
    PreparedAccountAction,
};
pub use ari::{
    AriCertificateId, AriError, MAX_ARI_CERTIFICATE_ID, MAX_ARI_RESPONSE_BYTES, RenewalInfo,
    RenewalWindow,
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
    write_flattened_jws,
};
pub use nonce::{MAX_NONCE_BYTES, MAX_NONCES, NonceError, NoncePool, ReplayNonce};
pub use operation::{
    AccountCreateBuffers, CreateAccountError, OrderCreateBuffers, OrderCreateError,
    OrderCreateFailure, PrepareOrderError, PreparedOrderCreation, execute_prepared_account_create,
    execute_prepared_order_create, prepare_order_creation,
};
pub use order::{
    AuthorizationBinding, AuthorizationState, ChallengeKind, ChallengeState, MAX_AUTHORIZATIONS,
    MAX_CHALLENGES_PER_AUTHORIZATION, MAX_ORDER_IDENTIFIERS, OrderError, OrderLifecycle,
    PreparedFinalization,
};
pub use payload::{
    MAX_ACCOUNT_CONTACT_BYTES, MAX_ACCOUNT_CONTACTS, MAX_ACME_PAYLOAD_BYTES, PayloadError,
    account_contacts_digest, write_account_status_payload, write_finalize_payload,
    write_new_account_payload, write_new_order_payload, write_revocation_payload,
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
    AcmeContentType, AcmeExchange, AcmeHttpMethod, AcmeResponseMetadata, AcmeTransport,
    AcmeTransportRequest, AcmeTransportResponse, BadNonceRetry, MAX_ACME_RESPONSE_BODY,
    MAX_BAD_NONCE_RETRIES, MAX_RETRY_AFTER_BYTES, TransportError,
};
pub use url::{AcmeOrigin, AcmeScheme, AcmeUrl, MAX_URL_BYTES, UrlError};
