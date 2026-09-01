use crate::{AuthoritativeChallengeZone, MAX_DNS_PACKET};
use mrml_runtime::{NetError, SpinMutex, TcpListener, UdpSocket};

pub const DNS_IO_TIMEOUT_MILLIS: u64 = 2_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedDnsChallengeError {
    Network(NetError),
    Malformed,
    Response,
}

pub struct HostedDnsChallengeSockets {
    udp: UdpSocket,
    tcp: TcpListener,
    port: u16,
}

impl HostedDnsChallengeSockets {
    pub fn bind(ip: [u8; 4], port: u16) -> Result<Self, HostedDnsChallengeError> {
        let tcp = TcpListener::bind(ip, port).map_err(HostedDnsChallengeError::Network)?;
        let actual_port = tcp.local_port().map_err(HostedDnsChallengeError::Network)?;
        let udp = UdpSocket::bind(ip, actual_port).map_err(HostedDnsChallengeError::Network)?;
        udp.set_read_timeout_millis(DNS_IO_TIMEOUT_MILLIS)
            .map_err(HostedDnsChallengeError::Network)?;
        udp.set_write_timeout_millis(DNS_IO_TIMEOUT_MILLIS)
            .map_err(HostedDnsChallengeError::Network)?;
        Ok(Self {
            udp,
            tcp,
            port: actual_port,
        })
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    pub fn serve_udp_one(
        &self,
        zone: &SpinMutex<AuthoritativeChallengeZone>,
        now_unix: u64,
    ) -> Result<(), HostedDnsChallengeError> {
        let mut request = [0; MAX_DNS_PACKET];
        let (length, peer) = self
            .udp
            .receive_from(&mut request)
            .map_err(HostedDnsChallengeError::Network)?;
        let mut response = [0; MAX_DNS_PACKET];
        let written = zone
            .lock()
            .answer_udp(&request[..length], now_unix, &mut response)
            .map_err(|_| HostedDnsChallengeError::Response)?;
        let sent = self
            .udp
            .send_to(&response[..written], peer)
            .map_err(HostedDnsChallengeError::Network)?;
        if sent != written {
            return Err(HostedDnsChallengeError::Network(NetError::WriteFailed));
        }
        Ok(())
    }

    pub fn serve_tcp_one(
        &self,
        zone: &SpinMutex<AuthoritativeChallengeZone>,
        now_unix: u64,
    ) -> Result<(), HostedDnsChallengeError> {
        let mut stream = self
            .tcp
            .accept()
            .map_err(HostedDnsChallengeError::Network)?;
        stream
            .set_read_timeout_millis(DNS_IO_TIMEOUT_MILLIS)
            .map_err(HostedDnsChallengeError::Network)?;
        stream
            .set_write_timeout_millis(DNS_IO_TIMEOUT_MILLIS)
            .map_err(HostedDnsChallengeError::Network)?;
        let mut framed = [0; MAX_DNS_PACKET + 2];
        stream
            .read_exact(&mut framed[..2])
            .map_err(HostedDnsChallengeError::Network)?;
        let length = usize::from(u16::from_be_bytes([framed[0], framed[1]]));
        if length == 0 || length > MAX_DNS_PACKET {
            return Err(HostedDnsChallengeError::Malformed);
        }
        stream
            .read_exact(&mut framed[2..2 + length])
            .map_err(HostedDnsChallengeError::Network)?;
        let mut response = [0; MAX_DNS_PACKET + 2];
        let written = zone
            .lock()
            .answer_tcp(&framed[..2 + length], now_unix, &mut response)
            .map_err(|_| HostedDnsChallengeError::Response)?;
        stream
            .write_all(&response[..written])
            .map_err(HostedDnsChallengeError::Network)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mrml_acme::DnsIdentifier;
    use mrml_runtime::{Shared, SocketAddress, TcpStream};

    fn query() -> [u8; 40] {
        [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 15, b'_', b'a', b'c', b'm', b'e',
            b'-', b'c', b'h', b'a', b'l', b'l', b'e', b'n', b'g', b'e', 3, b'e', b'x', b'a', 0, 0,
            16, 0, 1, 0, 0, 0,
        ]
    }

    #[test]
    fn authoritative_role_answers_udp_and_tcp_on_one_port() {
        let mut zone = AuthoritativeChallengeZone::new(
            DnsIdentifier::parse("exa", false).unwrap(),
            DnsIdentifier::parse("ns.exa", false).unwrap(),
            [127, 0, 0, 1],
            1,
            1,
        );
        zone.insert_txt(
            DnsIdentifier::parse("exa", false).unwrap(),
            [4; 32],
            1,
            20,
            1,
        )
        .unwrap();
        let zone = Shared::new(SpinMutex::new(zone));
        let sockets = Shared::new(HostedDnsChallengeSockets::bind([127, 0, 0, 1], 0).unwrap());
        let port = sockets.port();
        let udp_server = sockets.clone();
        let udp_zone = zone.clone();
        assert!(mrml_runtime::spawn_detached(move || {
            udp_server.serve_udp_one(&udp_zone, 10).unwrap();
        })
        .is_ok());
        let udp = UdpSocket::bind([127, 0, 0, 1], 0).unwrap();
        udp.set_read_timeout_millis(1000).unwrap();
        udp.send_to(
            &query(),
            SocketAddress {
                ip: [127, 0, 0, 1],
                port,
            },
        )
        .unwrap();
        let mut answer = [0; MAX_DNS_PACKET];
        let (written, _) = udp.receive_from(&mut answer).unwrap();
        assert_eq!(&answer[..2], &[0x12, 0x34]);
        assert!(written > 40);

        let tcp_server = sockets.clone();
        let tcp_zone = zone.clone();
        assert!(mrml_runtime::spawn_detached(move || {
            tcp_server.serve_tcp_one(&tcp_zone, 10).unwrap();
        })
        .is_ok());
        let mut tcp = TcpStream::connect([127, 0, 0, 1], port).unwrap();
        tcp.set_read_timeout_millis(1000).unwrap();
        tcp.write_all(&(query().len() as u16).to_be_bytes())
            .unwrap();
        tcp.write_all(&query()).unwrap();
        let mut prefix = [0; 2];
        tcp.read_exact(&mut prefix).unwrap();
        let length = usize::from(u16::from_be_bytes(prefix));
        assert!(length > query().len());
        tcp.read_exact(&mut answer[..length]).unwrap();
        assert_eq!(&answer[..2], &[0x12, 0x34]);
    }
}
