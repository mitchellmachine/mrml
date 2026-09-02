use crate::{
    challenge_dns::{decode_name, encode_name},
    DnsChallengeError, DnsObservationClass, DnsObservationRoute, DnsPropagationQuery,
    DnsTxtObservationReceipt, DnsTxtObservationRequest, MAX_DNS_PACKET,
};
use mrml_acme::decode_base64url;
use mrml_runtime::{NetError, TcpStream};

const DNS_HEADER_BYTES: usize = 12;
const DNS_TCP_TIMEOUT_MILLIS: u64 = 2_000;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct HostedDnsObservationEndpoint {
    pub route: DnsObservationRoute,
    pub ipv4: [u8; 4],
    pub port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedDnsPropagationError {
    InvalidConfiguration,
    UnauthorizedRoute,
    Network(NetError),
    Malformed,
    Truncated,
}

pub struct HostedDnsPropagationQuery {
    authoritative: HostedDnsObservationEndpoint,
    resolver: HostedDnsObservationEndpoint,
    next_transaction: u16,
    now_unix: u64,
}

impl HostedDnsPropagationQuery {
    pub fn new(
        authoritative: HostedDnsObservationEndpoint,
        resolver: HostedDnsObservationEndpoint,
        now_unix: u64,
    ) -> Result<Self, HostedDnsPropagationError> {
        if authoritative.route.class != DnsObservationClass::Authoritative
            || resolver.route.class != DnsObservationClass::RecursiveResolver
            || authoritative.route.capability_id == 0
            || resolver.route.capability_id == 0
            || authoritative.route.capability_id == resolver.route.capability_id
            || authoritative.route.route_generation == 0
            || resolver.route.route_generation == 0
            || authoritative.port == 0
            || resolver.port == 0
            || now_unix == 0
        {
            return Err(HostedDnsPropagationError::InvalidConfiguration);
        }
        Ok(Self {
            authoritative,
            resolver,
            next_transaction: 1,
            now_unix,
        })
    }

    pub fn set_observed_time(&mut self, now_unix: u64) -> Result<(), HostedDnsPropagationError> {
        if now_unix == 0 {
            return Err(HostedDnsPropagationError::InvalidConfiguration);
        }
        self.now_unix = now_unix;
        Ok(())
    }

    fn endpoint(
        &self,
        route: DnsObservationRoute,
    ) -> Result<HostedDnsObservationEndpoint, HostedDnsPropagationError> {
        [self.authoritative, self.resolver]
            .into_iter()
            .find(|endpoint| endpoint.route == route)
            .ok_or(HostedDnsPropagationError::UnauthorizedRoute)
    }

    fn query_txt(
        &mut self,
        endpoint: HostedDnsObservationEndpoint,
        request: DnsTxtObservationRequest,
    ) -> Result<bool, HostedDnsPropagationError> {
        let transaction = self.next_transaction;
        self.next_transaction = self.next_transaction.wrapping_add(1).max(1);
        let mut packet = [0u8; MAX_DNS_PACKET];
        packet[..2].copy_from_slice(&transaction.to_be_bytes());
        packet[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
        packet[4..6].copy_from_slice(&1u16.to_be_bytes());
        let mut cursor = DNS_HEADER_BYTES;
        let prefix = b"_acme-challenge.";
        packet[cursor] = 15;
        cursor += 1;
        packet[cursor..cursor + 15].copy_from_slice(&prefix[..15]);
        cursor += 15;
        cursor +=
            encode_name(request.identifier.as_str(), &mut packet[cursor..]).map_err(map_dns)?;
        packet[cursor..cursor + 4].copy_from_slice(&[0, 16, 0, 1]);
        cursor += 4;

        let mut stream = TcpStream::connect(endpoint.ipv4, endpoint.port)
            .map_err(HostedDnsPropagationError::Network)?;
        stream
            .set_read_timeout_millis(DNS_TCP_TIMEOUT_MILLIS)
            .map_err(HostedDnsPropagationError::Network)?;
        stream
            .set_write_timeout_millis(DNS_TCP_TIMEOUT_MILLIS)
            .map_err(HostedDnsPropagationError::Network)?;
        stream
            .write_all(&(cursor as u16).to_be_bytes())
            .and_then(|_| stream.write_all(&packet[..cursor]))
            .map_err(HostedDnsPropagationError::Network)?;
        let mut length = [0u8; 2];
        stream
            .read_exact(&mut length)
            .map_err(HostedDnsPropagationError::Network)?;
        let length = usize::from(u16::from_be_bytes(length));
        if length < DNS_HEADER_BYTES || length > MAX_DNS_PACKET {
            return Err(HostedDnsPropagationError::Malformed);
        }
        stream
            .read_exact(&mut packet[..length])
            .map_err(HostedDnsPropagationError::Network)?;
        response_contains_digest(&packet[..length], transaction, request.expected_digest)
    }
}

impl DnsPropagationQuery for HostedDnsPropagationQuery {
    type Error = HostedDnsPropagationError;

    fn observe_txt(
        &mut self,
        request: DnsTxtObservationRequest,
    ) -> Result<Option<DnsTxtObservationReceipt>, Self::Error> {
        let endpoint = self.endpoint(request.route)?;
        Ok(self
            .query_txt(endpoint, request)?
            .then_some(DnsTxtObservationReceipt {
                challenge_generation: request.challenge_generation,
                publisher_generation: request.publisher_generation,
                route_generation: request.route.route_generation,
                class: request.route.class,
                observed_digest: request.expected_digest,
                observed_unix: self.now_unix,
            }))
    }
}

fn response_contains_digest(
    packet: &[u8],
    transaction: u16,
    expected: [u8; 32],
) -> Result<bool, HostedDnsPropagationError> {
    if packet.len() < DNS_HEADER_BYTES || u16::from_be_bytes([packet[0], packet[1]]) != transaction
    {
        return Err(HostedDnsPropagationError::Malformed);
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 == 0 || flags & 0x0200 != 0 || flags & 0x000f != 0 {
        return Err(if flags & 0x0200 != 0 {
            HostedDnsPropagationError::Truncated
        } else {
            HostedDnsPropagationError::Malformed
        });
    }
    let questions = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let answers = usize::from(u16::from_be_bytes([packet[6], packet[7]]));
    if questions != 1 || answers > 32 {
        return Err(HostedDnsPropagationError::Malformed);
    }
    let mut name = [0u8; 253];
    let (_, after_name) = decode_name(packet, DNS_HEADER_BYTES, &mut name).map_err(map_dns)?;
    let mut cursor = after_name
        .checked_add(4)
        .ok_or(HostedDnsPropagationError::Malformed)?;
    if cursor > packet.len() {
        return Err(HostedDnsPropagationError::Malformed);
    }
    for _ in 0..answers {
        let (_, after_name) = decode_name(packet, cursor, &mut name).map_err(map_dns)?;
        let fixed_end = after_name
            .checked_add(10)
            .ok_or(HostedDnsPropagationError::Malformed)?;
        let fixed = packet
            .get(after_name..fixed_end)
            .ok_or(HostedDnsPropagationError::Malformed)?;
        let record_type = u16::from_be_bytes([fixed[0], fixed[1]]);
        let class = u16::from_be_bytes([fixed[2], fixed[3]]);
        let rdlength = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let rdata_end = fixed_end
            .checked_add(rdlength)
            .ok_or(HostedDnsPropagationError::Malformed)?;
        let rdata = packet
            .get(fixed_end..rdata_end)
            .ok_or(HostedDnsPropagationError::Malformed)?;
        cursor = rdata_end;
        if record_type == 16 && class == 1 && txt_matches(rdata, expected)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn txt_matches(rdata: &[u8], expected: [u8; 32]) -> Result<bool, HostedDnsPropagationError> {
    if rdata.len() != 44 || usize::from(rdata[0]) != 43 {
        return Ok(false);
    }
    let text =
        core::str::from_utf8(&rdata[1..]).map_err(|_| HostedDnsPropagationError::Malformed)?;
    let mut decoded = [0u8; 32];
    let decoded =
        decode_base64url(text, &mut decoded).map_err(|_| HostedDnsPropagationError::Malformed)?;
    Ok(decoded == expected)
}

fn map_dns(_: DnsChallengeError) -> HostedDnsPropagationError {
    HostedDnsPropagationError::Malformed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthoritativeChallengeZone, HostedDnsChallengeSockets};
    use mrml_acme::DnsIdentifier;
    use mrml_runtime::{Shared, SpinMutex};

    #[test]
    fn observes_exact_digest_through_independent_exact_routes() {
        let identifier = DnsIdentifier::parse("exa", false).unwrap();
        let digest = [7; 32];
        let mut zone = AuthoritativeChallengeZone::new(
            identifier,
            DnsIdentifier::parse("ns.exa", false).unwrap(),
            [127, 0, 0, 1],
            1,
            1,
        );
        zone.insert_txt(identifier, digest, 3, 30, 1).unwrap();
        let zone = Shared::new(SpinMutex::new(zone));
        let authoritative =
            Shared::new(HostedDnsChallengeSockets::bind([127, 0, 0, 1], 0).unwrap());
        let resolver = Shared::new(HostedDnsChallengeSockets::bind([127, 0, 0, 1], 0).unwrap());
        for sockets in [authoritative.clone(), resolver.clone()] {
            let zone = zone.clone();
            assert!(mrml_runtime::spawn_detached(move || sockets
                .serve_tcp_one(&zone, 10)
                .unwrap())
            .is_ok());
        }
        let authoritative_route = DnsObservationRoute {
            class: DnsObservationClass::Authoritative,
            capability_id: 11,
            route_generation: 2,
        };
        let resolver_route = DnsObservationRoute {
            class: DnsObservationClass::RecursiveResolver,
            capability_id: 12,
            route_generation: 4,
        };
        let mut query = HostedDnsPropagationQuery::new(
            HostedDnsObservationEndpoint {
                route: authoritative_route,
                ipv4: [127, 0, 0, 1],
                port: authoritative.port(),
            },
            HostedDnsObservationEndpoint {
                route: resolver_route,
                ipv4: [127, 0, 0, 1],
                port: resolver.port(),
            },
            10,
        )
        .unwrap();
        for route in [authoritative_route, resolver_route] {
            let receipt = query
                .observe_txt(DnsTxtObservationRequest {
                    identifier,
                    expected_digest: digest,
                    challenge_generation: 3,
                    publisher_generation: 9,
                    route,
                })
                .unwrap()
                .unwrap();
            assert_eq!(receipt.observed_digest, digest);
            assert_eq!(receipt.route_generation, route.route_generation);
        }
    }

    #[test]
    fn rejects_unconfigured_route_without_network_access() {
        let authoritative = DnsObservationRoute {
            class: DnsObservationClass::Authoritative,
            capability_id: 1,
            route_generation: 1,
        };
        let resolver = DnsObservationRoute {
            class: DnsObservationClass::RecursiveResolver,
            capability_id: 2,
            route_generation: 1,
        };
        let mut query = HostedDnsPropagationQuery::new(
            HostedDnsObservationEndpoint {
                route: authoritative,
                ipv4: [127, 0, 0, 1],
                port: 53,
            },
            HostedDnsObservationEndpoint {
                route: resolver,
                ipv4: [127, 0, 0, 1],
                port: 53,
            },
            1,
        )
        .unwrap();
        let result = query.observe_txt(DnsTxtObservationRequest {
            identifier: DnsIdentifier::parse("exa", false).unwrap(),
            expected_digest: [1; 32],
            challenge_generation: 1,
            publisher_generation: 1,
            route: DnsObservationRoute {
                class: DnsObservationClass::Authoritative,
                capability_id: 9,
                route_generation: 1,
            },
        });
        assert!(matches!(
            result,
            Err(HostedDnsPropagationError::UnauthorizedRoute)
        ));
    }
}
