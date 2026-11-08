//! Integration test for p2p-core multi-ALPN router + allowlist gate.
//!
//! Proves four things on a live QUIC endpoint:
//! 1. Multiple custom ALPNs dispatch to their own handlers.
//! 2. `with_protocol` (un-gated) accepts any peer.
//! 3. `with_allowlisted_protocol` refuses unpaired peers, and refuses a peer
//!    revoked while connected on its next *connection*.
//! 4. The refusal is our allowlist gate: close code `1` / "not in allowlist".
//!
//! A rejected peer still completes the QUIC handshake — `accept` closes the
//! connection with `VarInt(1)` / "not in allowlist" — so the assertion is on
//! the connection close, not on `connect()` (C2).
//!
//! Case 3 also pins the *current* revocation boundary: `AllowlistProtocolHandler`
//! checks the allowlist once per connection, so a second bi-stream on an
//! already-open connection still succeeds after revocation. That gap is closed
//! in Phase 2B by `MeshHttpProxyHandler` per-bi-stream re-check (C1(a)) and/or
//! `P2pNode::disconnect_peer` (C1(b)); when that lands, this assertion flips.

#![cfg(feature = "test-util")]

use std::sync::Arc;

use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::{ConnectionError, VarInt};
use p2p_core::{
    AcceptError, AllowlistStorage, Connection, InMemoryAllowlist, PeerAddr, ProtocolHandler, P2pNode,
};

/// Reads one bi-stream and echoes a fixed response, then keeps the connection
/// open until the peer closes it.
#[derive(Debug)]
struct EchoHandler(&'static [u8]);

impl ProtocolHandler for EchoHandler {
    #[allow(clippy::manual_async_fn)]
    fn accept(
        &self,
        connection: Connection,
    ) -> impl std::future::Future<Output = Result<(), AcceptError>> + Send {
        let resp = self.0;
        async move {
            let (mut send, mut recv) = connection
                .accept_bi()
                .await
                .map_err(AcceptError::from_err)?;
            let _ = recv.read_to_end(64).await;
            send.write_all(resp).await.map_err(AcceptError::from_err)?;
            send.finish().map_err(AcceptError::from_err)?;
            // Keep the connection open until the peer closes it. Returning
            // immediately makes iroh close with code 0 and race the client read.
            let _ = connection.closed().await;
            Ok(())
        }
    }
}

/// Accepts bi-streams in a loop until the peer closes, echoing a fixed response.
///
/// Needed by case 3: proving that a second bi-stream on an *already-open*
/// connection still succeeds after revocation requires a handler that accepts
/// more than one stream.
#[derive(Debug)]
struct LoopingEchoHandler(&'static [u8]);

impl ProtocolHandler for LoopingEchoHandler {
    #[allow(clippy::manual_async_fn)]
    fn accept(
        &self,
        connection: Connection,
    ) -> impl std::future::Future<Output = Result<(), AcceptError>> + Send {
        let resp = self.0;
        async move {
            loop {
                let (mut send, mut recv) = match connection.accept_bi().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let _ = recv.read_to_end(64).await;
                send.write_all(resp).await.map_err(AcceptError::from_err)?;
                send.finish().map_err(AcceptError::from_err)?;
            }
            let _ = connection.closed().await;
            Ok(())
        }
    }
}

const OPEN_ALPN: &[u8] = b"test/open-ping/1";
const RPC_ALPN: &[u8] = b"test/mesh-rpc/1";
const META_ALPN: &[u8] = b"test/mesh-meta/1";

fn seed(n: u8) -> [u8; 32] {
    [n; 32]
}

/// Dial `alpn` and return the established connection.
///
/// The handshake completes even for a peer the server will reject: the
/// allowlist gate runs in `accept`, after the handshake, and closes the
/// connection with code `1`.
async fn dial(node: &P2pNode, peer: PeerAddr, alpn: &[u8]) -> anyhow::Result<Connection> {
    Ok(node.connect(&peer, alpn).await?)
}

/// Open one bi-stream on an established connection and read the response.
async fn read_one(conn: &Connection) -> anyhow::Result<Vec<u8>> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"ping").await?;
    send.finish()?;
    Ok(recv.read_to_end(64).await?)
}

/// Dial `alpn`, open one bi-stream, and read the handler response.
async fn dial_and_read(node: &P2pNode, peer: PeerAddr, alpn: &[u8]) -> anyhow::Result<Vec<u8>> {
    let conn = dial(node, peer, alpn).await?;
    read_one(&conn).await
}

/// Assert the server refused this connection through our allowlist gate:
/// `ApplicationClosed` with code `1` and reason `"not in allowlist"`.
///
/// Checking the close code (not just `.is_err()`) rules out an unreachable
/// peer, a timeout, or any other transport failure.
async fn assert_refused_with_code_1(conn: Connection) {
    match conn.closed().await {
        ConnectionError::ApplicationClosed(close) => {
            assert_eq!(
                close.error_code,
                VarInt::from_u32(1),
                "allowlist gate must close with code 1"
            );
            assert_eq!(
                close.reason.as_ref(),
                b"not in allowlist".as_slice(),
                "allowlist gate must close with reason not in allowlist"
            );
        }
        other => panic!("expected ApplicationClosed code 1, got {other:?}"),
    }
    // The connection is closed, so a bi-stream on it must fail too.
    assert!(
        conn.open_bi().await.is_err(),
        "a refused connection must not accept a new bi-stream"
    );
}

/// A client node that can reach `server` directly (in-process, no relay).
async fn make_client(n: u8, server: &P2pNode) -> anyhow::Result<P2pNode> {
    let node = P2pNode::builder(seed(n), &[], Arc::new(InMemoryAllowlist::new()))
        .mdns_service_name("wd-mesh-test")
        .build()
        .await?;
    let lookup = MemoryLookup::new();
    lookup.add_endpoint_info(server.endpoint_for_test().addr());
    node.endpoint_for_test().address_lookup()?.add(lookup);
    Ok(node)
}

#[tokio::test]
async fn multi_alpn_router_dispatches_multiple_protocols_and_enforces_allowlist(
) -> anyhow::Result<()> {
    let server_allowlist = Arc::new(InMemoryAllowlist::new());
    let server = P2pNode::builder(seed(1), &[], server_allowlist.clone())
        .mdns_service_name("wd-mesh-test")
        .with_protocol(OPEN_ALPN, EchoHandler(b"pong-open"))
        .with_allowlisted_protocol(RPC_ALPN, LoopingEchoHandler(b"pong-rpc"))
        .with_allowlisted_protocol(META_ALPN, EchoHandler(b"pong-meta"))
        .build()
        .await?;
    let server_peer = PeerAddr::new(server.node_id());

    // 1. An allowed peer reaches every registered ALPN.
    let allowed = make_client(2, &server).await?;
    server_allowlist.add_peer(allowed.node_id(), "allowed").await?;
    assert_eq!(
        dial_and_read(&allowed, server_peer.clone(), OPEN_ALPN).await?,
        b"pong-open"
    );
    assert_eq!(
        dial_and_read(&allowed, server_peer.clone(), RPC_ALPN).await?,
        b"pong-rpc"
    );
    assert_eq!(
        dial_and_read(&allowed, server_peer.clone(), META_ALPN).await?,
        b"pong-meta"
    );

    // 2. An unpaired peer: un-gated ALPN works, allowlisted ALPN is refused
    //    with our close code.
    let unpaired = make_client(3, &server).await?;
    assert_eq!(
        dial_and_read(&unpaired, server_peer.clone(), OPEN_ALPN).await?,
        b"pong-open"
    );
    let refused = dial(&unpaired, server_peer.clone(), RPC_ALPN).await?;
    assert_refused_with_code_1(refused).await;

    // 3. Revoked while connected.
    let revoked = make_client(4, &server).await?;
    server_allowlist.add_peer(revoked.node_id(), "revoked").await?;
    let conn = dial(&revoked, server_peer.clone(), RPC_ALPN).await?;
    assert_eq!(read_one(&conn).await?, b"pong-rpc");

    server_allowlist.remove_peer(&revoked.node_id()).await?;

    // 3a. Documented 2A boundary: the gate runs once per connection, so a
    //     second bi-stream on the already-open connection still succeeds.
    //     2B per-bi-stream re-check (C1(a)) flips this assertion.
    assert_eq!(
        read_one(&conn).await?,
        b"pong-rpc",
        "2A gates per connection, not per bi-stream: an open connection is not re-checked"
    );

    // 3b. A NEW connection is refused by the gate, with close code 1.
    let refused = dial(&revoked, server_peer.clone(), RPC_ALPN).await?;
    assert_refused_with_code_1(refused).await;

    Ok(())
}
