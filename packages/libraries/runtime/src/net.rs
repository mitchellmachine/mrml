use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetError {
    InvalidAddress,
    BindFailed,
    ConnectFailed,
    AcceptFailed,
    ReadFailed,
    WriteFailed,
    TimeoutFailed,
    ResolveFailed,
}

impl fmt::Display for NetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidAddress => "invalid IPv4 address",
            Self::BindFailed => "failed to bind TCP listener",
            Self::ConnectFailed => "failed to connect TCP stream",
            Self::AcceptFailed => "failed to accept TCP connection",
            Self::ReadFailed => "failed to read TCP stream",
            Self::WriteFailed => "failed to write TCP stream",
            Self::TimeoutFailed => "failed to configure TCP timeout",
            Self::ResolveFailed => "failed to resolve IPv4 host name",
        })
    }
}

impl core::error::Error for NetError {}

pub struct TcpListener {
    #[cfg(windows)]
    native: mrml_windows::NativeTcpListener,
    #[cfg(unix)]
    native: mrml_linux::NativeTcpListener,
}

impl TcpListener {
    pub fn bind(ip: [u8; 4], port: u16) -> Result<Self, NetError> {
        #[cfg(windows)]
        let native = mrml_windows::NativeTcpListener::bind(ip, port);
        #[cfg(unix)]
        let native = mrml_linux::NativeTcpListener::bind(ip, port);
        native
            .map(|native| Self { native })
            .ok_or(NetError::BindFailed)
    }

    pub fn local_port(&self) -> Result<u16, NetError> {
        self.native.local_port().ok_or(NetError::BindFailed)
    }

    pub fn accept(&self) -> Result<TcpStream, NetError> {
        self.native
            .accept()
            .map(|native| TcpStream { native })
            .ok_or(NetError::AcceptFailed)
    }
}

pub struct TcpStream {
    #[cfg(windows)]
    native: mrml_windows::NativeTcpStream,
    #[cfg(unix)]
    native: mrml_linux::NativeTcpStream,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketAddress {
    pub ip: [u8; 4],
    pub port: u16,
}

pub struct UdpSocket {
    #[cfg(windows)]
    native: mrml_windows::NativeUdpSocket,
    #[cfg(unix)]
    native: mrml_linux::NativeUdpSocket,
}

impl UdpSocket {
    pub fn bind(ip: [u8; 4], port: u16) -> Result<Self, NetError> {
        #[cfg(windows)]
        let native = mrml_windows::NativeUdpSocket::bind(ip, port);
        #[cfg(unix)]
        let native = mrml_linux::NativeUdpSocket::bind(ip, port);
        native
            .map(|native| Self { native })
            .ok_or(NetError::BindFailed)
    }

    pub fn local_port(&self) -> Result<u16, NetError> {
        self.native.local_port().ok_or(NetError::BindFailed)
    }

    pub fn receive_from(&self, buffer: &mut [u8]) -> Result<(usize, SocketAddress), NetError> {
        self.native
            .receive_from(buffer)
            .map(|(amount, ip, port)| (amount, SocketAddress { ip, port }))
            .ok_or(NetError::ReadFailed)
    }

    pub fn send_to(&self, buffer: &[u8], peer: SocketAddress) -> Result<usize, NetError> {
        self.native
            .send_to(buffer, peer.ip, peer.port)
            .ok_or(NetError::WriteFailed)
    }
}

impl TcpStream {
    /// Resolve a host once so callers can validate the exact IPv4 endpoint before connecting.
    pub fn resolve_host(host: &str) -> Result<[u8; 4], NetError> {
        let mut name = crate::Vector::new();
        name.try_extend_from_slice(host.as_bytes())
            .map_err(|_| NetError::ResolveFailed)?;
        name.push(0);
        #[cfg(windows)]
        let ip = mrml_windows::resolve_ipv4(&name);
        #[cfg(unix)]
        let ip = mrml_linux::resolve_ipv4(&name);
        ip.ok_or(NetError::ResolveFailed)
    }

    pub fn connect_host(host: &str, port: u16) -> Result<Self, NetError> {
        Self::connect(Self::resolve_host(host)?, port)
    }
    pub fn connect(ip: [u8; 4], port: u16) -> Result<Self, NetError> {
        #[cfg(windows)]
        let native = mrml_windows::NativeTcpStream::connect(ip, port);
        #[cfg(unix)]
        let native = mrml_linux::NativeTcpStream::connect(ip, port);
        native
            .map(|native| Self { native })
            .ok_or(NetError::ConnectFailed)
    }

    pub fn read(&mut self, buffer: &mut [u8]) -> Result<usize, NetError> {
        self.native.read(buffer).ok_or(NetError::ReadFailed)
    }

    pub fn read_exact(&mut self, mut buffer: &mut [u8]) -> Result<(), NetError> {
        while !buffer.is_empty() {
            let read = self.read(buffer)?;
            if read == 0 {
                return Err(NetError::ReadFailed);
            }
            buffer = &mut buffer[read..];
        }
        Ok(())
    }

    pub fn write_all(&mut self, mut buffer: &[u8]) -> Result<(), NetError> {
        while !buffer.is_empty() {
            let written = self.native.write(buffer).ok_or(NetError::WriteFailed)?;
            if written == 0 {
                return Err(NetError::WriteFailed);
            }
            buffer = &buffer[written..];
        }
        Ok(())
    }

    pub fn set_read_timeout_millis(&self, milliseconds: u64) -> Result<(), NetError> {
        self.native
            .set_timeout_millis(true, milliseconds)
            .then_some(())
            .ok_or(NetError::TimeoutFailed)
    }

    pub fn set_write_timeout_millis(&self, milliseconds: u64) -> Result<(), NetError> {
        self.native
            .set_timeout_millis(false, milliseconds)
            .then_some(())
            .ok_or(NetError::TimeoutFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_listener_exchanges_bytes() {
        let listener = TcpListener::bind([127, 0, 0, 1], 0).unwrap();
        let port = listener.local_port().unwrap();
        assert!(
            crate::spawn_detached(move || {
                let mut stream = listener.accept().unwrap();
                let mut request = [0u8; 5];
                stream.read_exact(&mut request).unwrap();
                assert_eq!(&request, b"hello");
                stream.write_all(b"world").unwrap();
            })
            .is_ok()
        );
        let mut stream = TcpStream::connect([127, 0, 0, 1], port).unwrap();
        stream.set_read_timeout_millis(1000).unwrap();
        stream.set_write_timeout_millis(1000).unwrap();
        stream.write_all(b"hello").unwrap();
        let mut response = [0u8; 5];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"world");
    }

    #[test]
    fn resolves_localhost() {
        assert!(TcpStream::resolve_host("localhost").is_ok());
    }

    #[test]
    fn loopback_udp_preserves_datagram_and_peer_identity() {
        let server = UdpSocket::bind([127, 0, 0, 1], 0).unwrap();
        let client = UdpSocket::bind([127, 0, 0, 1], 0).unwrap();
        let server_port = server.local_port().unwrap();
        let client_port = client.local_port().unwrap();
        assert_eq!(
            client
                .send_to(
                    b"quic",
                    SocketAddress {
                        ip: [127, 0, 0, 1],
                        port: server_port,
                    },
                )
                .unwrap(),
            4
        );
        let mut input = [0u8; 16];
        let (amount, peer) = server.receive_from(&mut input).unwrap();
        assert_eq!(&input[..amount], b"quic");
        assert_eq!(peer.ip, [127, 0, 0, 1]);
        assert_eq!(peer.port, client_port);
    }
}
