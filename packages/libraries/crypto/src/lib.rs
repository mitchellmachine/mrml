#![no_std]

#[cfg(feature = "runtime")]
mod aead;
mod aes_gcm;
mod chacha20;
mod ed25519;
#[cfg(feature = "runtime")]
mod hkdf;
mod hmac;
mod lamport;
mod ml_dsa;
#[cfg(feature = "runtime")]
mod ml_kem;
#[cfg(feature = "runtime")]
mod p256;
#[cfg(feature = "runtime")]
mod p384;
mod poly1305;
#[cfg(feature = "runtime")]
mod rsa;
mod sha256;
mod sha3;
mod sha512;
mod signing_key_cache;
mod x25519;
mod zeroize;

#[cfg(feature = "runtime")]
pub use aead::{chacha20_poly1305_open, chacha20_poly1305_seal};
pub use aes_gcm::{aes128_ctr_xor, aes128_encrypt_block, aes128_gcm_open, aes128_gcm_seal};
pub use chacha20::{chacha20_block, chacha20_xor};
pub use ed25519::{ed25519_public, ed25519_public_is_valid, ed25519_sign, ed25519_verify};
#[cfg(feature = "runtime")]
pub use hkdf::{hkdf_expand, hkdf_expand_label, hkdf_extract};
pub use hmac::hmac_sha256;
pub use lamport::{
    LAMPORT_PRIVATE_KEY_BYTES, LAMPORT_PUBLIC_KEY_BYTES, LAMPORT_SIGNATURE_BYTES, LamportError,
    lamport_public_key, lamport_sign, lamport_verify,
};
pub use ml_dsa::{
    ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SECRET_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES, MlDsaError,
    ml_dsa_65_keygen, ml_dsa_65_sign, ml_dsa_65_verify,
};
#[cfg(feature = "runtime")]
pub use ml_dsa::{ml_dsa_65_keygen_random, ml_dsa_65_sign_randomized};
#[cfg(feature = "runtime")]
pub use ml_kem::{
    MlKem768Ciphertext, MlKem768DecapsulationKey, MlKem768EncapsulationKey, MlKemError,
    ml_kem_768_decapsulate, ml_kem_768_encapsulate, ml_kem_768_keygen,
};
#[cfg(feature = "runtime")]
pub use p256::{P256Error, ecdsa_p256_sha256_verify};
#[cfg(feature = "runtime")]
pub use p384::{P384Error, ecdsa_p384_sha384_verify};
pub use poly1305::poly1305;
#[cfg(feature = "runtime")]
pub use rsa::{
    RsaError, rsa_pkcs1_sha256_sign, rsa_pkcs1_sha256_verify, rsa_pss_sha256_sign,
    rsa_pss_sha256_verify,
};
pub use sha3::{Sha3_256, Sha3_512, Shake128, Shake256};
pub use sha256::Sha256;
pub use sha512::{Sha384, Sha512};
pub use signing_key_cache::{SigningKeyCacheError, UnlockedSigningKeyCache};
pub use x25519::{x25519, x25519_public, x25519_shared};
