#![no_std]

mod challenge_dns;
mod challenge_publisher;

pub use challenge_dns::{
    AuthoritativeChallengeZone, DnsChallengeError, MAX_DNS_PACKET, MAX_DNS_TXT_RECORDS,
};
pub use challenge_publisher::DnsChallengePublisher;
