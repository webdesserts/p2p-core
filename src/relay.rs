//! Embedded iroh relay server for LAN and WAN peer relaying.
//!
//! When `--relay-listen` is passed to the daemon, an iroh-relay HTTP server is
//! started on the specified address. WASM/browser peers that can't bind raw QUIC
//! sockets can route traffic through this relay. No TLS is required for LAN use;
//! for internet exposure, sit a reverse proxy (e.g. Caddy) in front.

use anyhow::{Context, Result};
use iroh::RelayUrl;
use iroh_relay::server::{RelayConfig, Server, ServerConfig};
use std::net::SocketAddr;
use tracing::info;

/// An embedded iroh relay server running inside the daemon process.
///
/// Dropping this shuts down the server (via `AbortOnDrop` internally).
/// For a clean shutdown, call [`EmbeddedRelay::shutdown`] instead.
pub struct EmbeddedRelay {
    server: Server,
    url: RelayUrl,
}

impl EmbeddedRelay {
    /// Start an embedded relay server bound to `bind_addr`.
    ///
    /// The advertised relay URL is derived from the bound address, so binding to
    /// `0.0.0.0:3340` advertises `http://0.0.0.0:3340/` — useless to remote peers.
    /// Use [`EmbeddedRelay::start_with_advertised_url`] when the bind address differs
    /// from the address peers should dial (e.g., when binding to `0.0.0.0`).
    ///
    /// Pass `0` as the port to get a random available port — the actual bound
    /// address is accessible via [`EmbeddedRelay::relay_url`].
    pub async fn start(bind_addr: SocketAddr) -> Result<Self> {
        let server = Self::spawn_server(bind_addr).await?;

        let addr = server
            .http_addr()
            .context("Relay server has no HTTP address")?;

        // Construct the relay URL manually — http_url() is gated behind test-utils feature.
        let url: RelayUrl = format!("http://{addr}/")
            .parse()
            .context("Failed to parse relay URL")?;

        info!(url = %url, "Embedded relay server started");

        Ok(Self { server, url })
    }

    /// Start an embedded relay server bound to `bind_addr`, advertising `advertised_url`
    /// to peers instead of the bound address.
    ///
    /// Use this when the bind address is not dialable by peers — for example, when
    /// binding to `0.0.0.0:3340` on a machine with LAN IP `192.168.68.59`:
    ///
    /// ```text
    /// EmbeddedRelay::start_with_advertised_url(
    ///     "0.0.0.0:3340".parse()?,
    ///     "http://192.168.68.59:3340/",
    /// )
    /// ```
    ///
    /// The caller is responsible for providing a reachable `advertised_url` — this
    /// function does not verify connectivity.
    pub async fn start_with_advertised_url(
        bind_addr: SocketAddr,
        advertised_url: &str,
    ) -> Result<Self> {
        let server = Self::spawn_server(bind_addr).await?;

        let url: RelayUrl = advertised_url
            .parse()
            .context("Failed to parse advertised relay URL")?;

        info!(url = %url, "Embedded relay server started (advertised URL differs from bind address)");

        Ok(Self { server, url })
    }

    /// Spawn the iroh relay server on `bind_addr`.
    async fn spawn_server(bind_addr: SocketAddr) -> Result<Server> {
        let relay_config = RelayConfig::new(bind_addr);
        let mut config = ServerConfig::default();
        config.relay = Some(relay_config);

        Server::spawn(config)
            .await
            .context("Failed to spawn relay server")
    }

    /// The URL of this relay server.
    ///
    /// Pass this to the node constructor so the iroh endpoint advertises and uses
    /// the embedded relay for peer connections.
    pub fn relay_url(&self) -> &RelayUrl {
        &self.url
    }

    /// Gracefully shut down the relay server.
    pub async fn shutdown(self) {
        if let Err(e) = self.server.shutdown().await {
            tracing::warn!("Relay server shutdown error: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_relay_starts_and_binds() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let relay = EmbeddedRelay::start(addr).await.unwrap();

        // The server must have bound to some real port (not 0).
        let url = relay.relay_url();
        let host = url.host_str().unwrap();
        assert_eq!(host, "127.0.0.1");

        let port = url.port().unwrap();
        assert!(port > 0, "expected non-zero port, got {port}");

        relay.shutdown().await;
    }

    #[tokio::test]
    async fn test_relay_url_format() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let relay = EmbeddedRelay::start(addr).await.unwrap();

        let url_str = relay.relay_url().to_string();
        assert!(
            url_str.starts_with("http://"),
            "expected http://, got {url_str}"
        );
        assert!(
            url_str.ends_with('/'),
            "expected trailing slash, got {url_str}"
        );

        relay.shutdown().await;
    }

    #[tokio::test]
    async fn test_relay_shutdown() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let relay = EmbeddedRelay::start(addr).await.unwrap();

        // Shutdown should complete without panicking.
        relay.shutdown().await;
    }

    /// start_with_advertised_url returns the caller-supplied URL, not the bound address.
    ///
    /// This is the case where the daemon binds to 0.0.0.0 but advertises its LAN IP.
    #[tokio::test]
    async fn test_start_with_advertised_url() {
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let advertised = "http://192.168.68.59:3340/";

        let relay = EmbeddedRelay::start_with_advertised_url(bind_addr, advertised)
            .await
            .unwrap();

        // The relay_url() must return the advertised URL, not the bound address.
        assert_eq!(relay.relay_url().to_string(), advertised);

        relay.shutdown().await;
    }
}
