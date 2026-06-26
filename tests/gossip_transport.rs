//! Integration test for p2p-core's generic gossip byte-transport.
//!
//! Two in-process `P2pNode`s subscribe to the same topic; one broadcasts an
//! opaque payload, the other receives it. The transport-level pass-through
//! assertion (received bytes == broadcast bytes, byte-for-byte) is the proof that
//! `P2pNode::subscribe` / `GossipSubscription::broadcast` adds NO envelope,
//! length-prefix, or re-framing of its own — the wire-critical property the
//! mixed-version fleet depends on. p2p-core is payload-opaque: it never decodes
//! the bytes, so this test passes arbitrary bytes, not a `GossipMessage`.

#![cfg(feature = "test-util")]

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use iroh::address_lookup::memory::MemoryLookup;
use p2p_core::{
    AcceptError, AllowlistStorage, Connection, GossipEvent, InMemoryAllowlist, P2pNode,
    ProtocolHandler, Topic,
};

/// A sync ALPN handler that does nothing — gossip tests register a sync ALPN
/// (the node always wants one) but never open a sync stream.
#[derive(Debug)]
struct NoopHandler;

impl ProtocolHandler for NoopHandler {
    // The trait requires `impl Future + Send` (not `async fn`) so the future is
    // provably `Send` for iroh's cross-thread Router; mirror that shape here.
    #[allow(clippy::manual_async_fn)]
    fn accept(
        &self,
        _connection: Connection,
    ) -> impl std::future::Future<Output = Result<(), AcceptError>> + Send {
        async { Ok(()) }
    }
}

const TEST_SYNC_ALPN: &[u8] = b"p2p-core-test/sync/1";

/// Deterministic 32-byte key seed from a small integer.
fn seed(n: u8) -> [u8; 32] {
    [n; 32]
}

/// Build a `P2pNode` with a no-op sync handler and the given allowlist, plus a
/// `MemoryLookup` on its endpoint for in-process direct connectivity (no relay).
async fn make_node(
    secret_key_bytes: [u8; 32],
    allowlist: Arc<InMemoryAllowlist>,
) -> anyhow::Result<P2pNode> {
    let node = P2pNode::with_sync_alpn(
        secret_key_bytes,
        &[],
        allowlist,
        TEST_SYNC_ALPN,
        NoopHandler,
    )
    .await?;
    let memory_lookup = MemoryLookup::new();
    node.endpoint_for_test()
        .address_lookup()?
        .add(memory_lookup);
    Ok(node)
}

/// Two nodes that can reach each other directly (no relay), each in the other's
/// allowlist so gossip connections are accepted.
async fn make_pair() -> anyhow::Result<(P2pNode, P2pNode)> {
    let allowlist_a = Arc::new(InMemoryAllowlist::new());
    let allowlist_b = Arc::new(InMemoryAllowlist::new());

    let node_a = make_node(seed(1), allowlist_a.clone()).await?;
    let node_b = make_node(seed(2), allowlist_b.clone()).await?;

    let peer_a = node_a.node_id();
    let peer_b = node_b.node_id();
    allowlist_a.add_peer(peer_b, "node-b").await?;
    allowlist_b.add_peer(peer_a, "node-a").await?;

    // Teach each node how to reach the other (direct in-process addresses).
    let addr_a = node_a.endpoint_for_test().addr();
    let addr_b = node_b.endpoint_for_test().addr();

    let lookup_a = MemoryLookup::new();
    lookup_a.add_endpoint_info(addr_b);
    node_a.endpoint_for_test().address_lookup()?.add(lookup_a);

    let lookup_b = MemoryLookup::new();
    lookup_b.add_endpoint_info(addr_a);
    node_b.endpoint_for_test().address_lookup()?.add(lookup_b);

    Ok((node_a, node_b))
}

/// The transport carries an opaque payload byte-for-byte: what B broadcasts is
/// exactly what A receives, with no envelope or re-framing added by p2p-core.
#[tokio::test]
async fn subscribe_broadcasts_opaque_bytes_unchanged() -> anyhow::Result<()> {
    let (node_a, node_b) = make_pair().await?;

    let topic = Topic::from_u64(0xdead_beef_dead_beef);
    let node_a_id = node_a.node_id();
    let node_b_id = node_b.node_id();

    // A subscribes with no bootstrap peers — it waits for B to join.
    let mut sub_a = node_a.subscribe(topic, vec![]).await?;
    // B subscribes and bootstraps off A.
    let mut sub_b = node_b.subscribe(topic, vec![node_a.node_id()]).await?;

    // Wait for B (the broadcaster) to see A as a live neighbor before it
    // broadcasts — PlumTree's eager push only reaches peers already in B's active
    // view, so gating the broadcast on B's own NeighborUp avoids a pre-membership
    // push that would silently go nowhere.
    let neighbor = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match sub_b.recv().await {
                Some(GossipEvent::NeighborUp(id)) => break id,
                Some(_) => continue,
                None => panic!("sub_b event channel closed"),
            }
        }
    })
    .await
    .expect("timed out waiting for B's NeighborUp");
    assert_eq!(neighbor, node_a_id, "B's NeighborUp should identify A");

    // B broadcasts arbitrary bytes — deliberately NOT a GossipMessage, so this
    // proves the transport never depends on (or alters) any codec framing.
    let payload = Bytes::from_static(&[0x00, 0x01, 0xFE, 0xFF, 0x42, 0x7F, 0x80, 0xA5]);
    sub_b.broadcast(payload.clone()).await?;

    // A receives the exact bytes B broadcast.
    let (from, received) = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match sub_a.recv().await {
                Some(GossipEvent::Data { from, bytes }) => break (from, bytes),
                Some(_) => continue,
                None => panic!("sub_a event channel closed"),
            }
        }
    })
    .await
    .expect("timed out waiting for A to receive the payload");

    assert_eq!(from, node_b_id, "Data.from should be B's id");
    assert_eq!(
        received, payload,
        "received bytes must equal broadcast bytes — p2p-core adds no envelope"
    );

    Ok(())
}
