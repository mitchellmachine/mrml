use mrml_acme::DnsIdentifier;

pub const MAX_PROPAGATION_ATTEMPTS: u8 = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsObservationClass {
    Authoritative,
    RecursiveResolver,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DnsObservationRoute {
    pub class: DnsObservationClass,
    pub capability_id: u64,
    pub route_generation: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DnsTxtObservationRequest {
    pub identifier: DnsIdentifier,
    pub expected_digest: [u8; 32],
    pub challenge_generation: u64,
    pub publisher_generation: u64,
    pub route: DnsObservationRoute,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DnsTxtObservationReceipt {
    pub challenge_generation: u64,
    pub publisher_generation: u64,
    pub route_generation: u64,
    pub class: DnsObservationClass,
    pub observed_digest: [u8; 32],
    pub observed_unix: u64,
}

pub trait DnsPropagationQuery {
    type Error;

    fn observe_txt(
        &mut self,
        request: DnsTxtObservationRequest,
    ) -> Result<Option<DnsTxtObservationReceipt>, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsPropagationError<E> {
    InvalidPolicy,
    Expired,
    AttemptLimit,
    Query(E),
    ReceiptMismatch,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DnsPropagationPolicy {
    pub authoritative: DnsObservationRoute,
    pub resolver: DnsObservationRoute,
    pub maximum_attempts: u8,
    pub deadline_unix: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DnsPropagationReceipt {
    pub challenge_generation: u64,
    pub publisher_generation: u64,
    pub authoritative: DnsTxtObservationReceipt,
    pub resolver: DnsTxtObservationReceipt,
}

pub struct DnsPropagationObserver {
    request_identifier: DnsIdentifier,
    expected_digest: [u8; 32],
    challenge_generation: u64,
    publisher_generation: u64,
    policy: DnsPropagationPolicy,
    attempts: u8,
    authoritative: Option<DnsTxtObservationReceipt>,
    resolver: Option<DnsTxtObservationReceipt>,
}

impl DnsPropagationObserver {
    pub fn new(
        identifier: DnsIdentifier,
        expected_digest: [u8; 32],
        challenge_generation: u64,
        publisher_generation: u64,
        policy: DnsPropagationPolicy,
    ) -> Result<Self, DnsPropagationError<core::convert::Infallible>> {
        if policy.authoritative.class != DnsObservationClass::Authoritative
            || policy.resolver.class != DnsObservationClass::RecursiveResolver
            || policy.authoritative.capability_id == 0
            || policy.resolver.capability_id == 0
            || policy.authoritative.capability_id == policy.resolver.capability_id
            || policy.authoritative.route_generation == 0
            || policy.resolver.route_generation == 0
            || policy.maximum_attempts == 0
            || policy.maximum_attempts > MAX_PROPAGATION_ATTEMPTS
        {
            return Err(DnsPropagationError::InvalidPolicy);
        }
        Ok(Self {
            request_identifier: identifier,
            expected_digest,
            challenge_generation,
            publisher_generation,
            policy,
            attempts: 0,
            authoritative: None,
            resolver: None,
        })
    }

    pub fn poll<Q: DnsPropagationQuery>(
        &mut self,
        now_unix: u64,
        query: &mut Q,
    ) -> Result<Option<DnsPropagationReceipt>, DnsPropagationError<Q::Error>> {
        if now_unix >= self.policy.deadline_unix {
            return Err(DnsPropagationError::Expired);
        }
        if self.attempts >= self.policy.maximum_attempts {
            return Err(DnsPropagationError::AttemptLimit);
        }
        self.attempts += 1;
        if self.authoritative.is_none() {
            self.authoritative = self.observe(self.policy.authoritative, query)?;
        }
        if self.resolver.is_none() {
            self.resolver = self.observe(self.policy.resolver, query)?;
        }
        Ok(match (self.authoritative, self.resolver) {
            (Some(authoritative), Some(resolver)) => Some(DnsPropagationReceipt {
                challenge_generation: self.challenge_generation,
                publisher_generation: self.publisher_generation,
                authoritative,
                resolver,
            }),
            _ => None,
        })
    }

    fn observe<Q: DnsPropagationQuery>(
        &self,
        route: DnsObservationRoute,
        query: &mut Q,
    ) -> Result<Option<DnsTxtObservationReceipt>, DnsPropagationError<Q::Error>> {
        let receipt = query
            .observe_txt(DnsTxtObservationRequest {
                identifier: self.request_identifier,
                expected_digest: self.expected_digest,
                challenge_generation: self.challenge_generation,
                publisher_generation: self.publisher_generation,
                route,
            })
            .map_err(DnsPropagationError::Query)?;
        if receipt.is_some_and(|receipt| {
            receipt.challenge_generation != self.challenge_generation
                || receipt.publisher_generation != self.publisher_generation
                || receipt.route_generation != route.route_generation
                || receipt.class != route.class
                || receipt.observed_digest != self.expected_digest
        }) {
            return Err(DnsPropagationError::ReceiptMismatch);
        }
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Query {
        authoritative: bool,
        resolver: bool,
    }
    impl DnsPropagationQuery for Query {
        type Error = ();
        fn observe_txt(
            &mut self,
            request: DnsTxtObservationRequest,
        ) -> Result<Option<DnsTxtObservationReceipt>, Self::Error> {
            let observed = match request.route.class {
                DnsObservationClass::Authoritative => self.authoritative,
                DnsObservationClass::RecursiveResolver => self.resolver,
            };
            Ok(observed.then_some(DnsTxtObservationReceipt {
                challenge_generation: request.challenge_generation,
                publisher_generation: request.publisher_generation,
                route_generation: request.route.route_generation,
                class: request.route.class,
                observed_digest: request.expected_digest,
                observed_unix: 10,
            }))
        }
    }

    fn make_observer() -> DnsPropagationObserver {
        DnsPropagationObserver::new(
            DnsIdentifier::parse("example.com", false).unwrap(),
            [4; 32],
            3,
            7,
            DnsPropagationPolicy {
                authoritative: DnsObservationRoute {
                    class: DnsObservationClass::Authoritative,
                    capability_id: 1,
                    route_generation: 2,
                },
                resolver: DnsObservationRoute {
                    class: DnsObservationClass::RecursiveResolver,
                    capability_id: 2,
                    route_generation: 5,
                },
                maximum_attempts: 2,
                deadline_unix: 20,
            },
        )
        .unwrap()
    }

    #[test]
    fn requires_exact_authoritative_and_resolver_observations() {
        let mut observer = make_observer();
        let mut query = Query {
            authoritative: true,
            resolver: false,
        };
        assert!(observer.poll(10, &mut query).unwrap().is_none());
        query.resolver = true;
        let receipt = observer.poll(11, &mut query).unwrap().unwrap();
        assert_eq!(receipt.challenge_generation, 3);
        assert_eq!(
            receipt.authoritative.class,
            DnsObservationClass::Authoritative
        );
        assert_eq!(
            receipt.resolver.class,
            DnsObservationClass::RecursiveResolver
        );
    }

    #[test]
    fn fails_closed_at_attempt_and_time_bounds() {
        let mut observer = make_observer();
        let mut query = Query {
            authoritative: false,
            resolver: false,
        };
        assert!(observer.poll(10, &mut query).unwrap().is_none());
        assert!(observer.poll(11, &mut query).unwrap().is_none());
        assert!(matches!(
            observer.poll(12, &mut query),
            Err(DnsPropagationError::AttemptLimit)
        ));
        let mut observer = make_observer();
        assert!(matches!(
            observer.poll(20, &mut query),
            Err(DnsPropagationError::Expired)
        ));
    }
}
