use mrml_http::{QuicError, QuicServerEndpoint};
use mrml_runtime::TcpListener;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitdListenerError {
    Limit,
    Tcp,
    Port,
    Udp,
}

pub struct GitdBoundListeners {
    tcp: TcpListener,
    quic: QuicServerEndpoint,
    port: u16,
}

impl GitdBoundListeners {
    pub fn bind(
        ip: [u8; 4],
        requested_port: u16,
        maximum_connections: u32,
    ) -> Result<Self, GitdListenerError> {
        let maximum_connections =
            usize::try_from(maximum_connections).map_err(|_| GitdListenerError::Limit)?;
        if maximum_connections == 0 || maximum_connections > 65_536 {
            return Err(GitdListenerError::Limit);
        }
        let maximum_retired_ids = maximum_connections
            .checked_mul(2)
            .unwrap_or(65_536)
            .min(65_536);
        let tcp = TcpListener::bind(ip, requested_port).map_err(|_| GitdListenerError::Tcp)?;
        let port = tcp.local_port().map_err(|_| GitdListenerError::Port)?;
        let quic = QuicServerEndpoint::bind(ip, port, maximum_connections, maximum_retired_ids)
            .map_err(map_quic)?;
        Ok(Self { tcp, quic, port })
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    pub const fn tcp(&self) -> &TcpListener {
        &self.tcp
    }

    pub const fn quic(&self) -> &QuicServerEndpoint {
        &self.quic
    }

    pub fn quic_mut(&mut self) -> &mut QuicServerEndpoint {
        &mut self.quic
    }
}

fn map_quic(error: QuicError) -> GitdListenerError {
    match error {
        QuicError::Limit => GitdListenerError::Limit,
        _ => GitdListenerError::Udp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_tcp_and_udp_own_one_exact_ephemeral_port() {
        let listeners = GitdBoundListeners::bind([127, 0, 0, 1], 0, 32).unwrap();
        assert_ne!(listeners.port(), 0);
        assert!(matches!(
            GitdBoundListeners::bind([127, 0, 0, 1], 0, 65_537),
            Err(GitdListenerError::Limit)
        ));
    }
}
