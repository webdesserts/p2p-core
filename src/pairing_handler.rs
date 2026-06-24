//! Pairing QUIC protocol handler.
//!
//! `PairingStreamHandler` implements iroh's `ProtocolHandler` trait for
//! `PAIRING_ALPN`. It runs the mesh-member side of the 4-message pairing
//! exchange on an incoming QUIC connection.
//!
//! # Handler flow (mesh-member side)
//!
//! 1. Read `PairingHello` from stream
//! 2. Send `PairingEvent::InboundRequest` to the daemon event loop
//! 3. Wait for a `PairingApproval` response (or 5-minute timeout)
//! 4. Write `PairingChallenge` to stream
//! 5. Read `PairingResponse` from stream
//! 6. Verify HMAC using the code in the approval + the requester's NodeId
//! 7. Write `PairingResult` (success or failure) to stream
//! 8. On success, send `PairingEvent::PairingCompleted` to the daemon
//!
//! # Client-side
//!
//! [`pair_with_mesh`] is the outbound function — it runs the new-device side
//! of the same exchange on a connection opened to a known mesh member.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use tokio::sync::{Mutex, mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::pairing::{PairingChallenge, PairingHello, PairingResponse, PairingResult, verify_hmac};
use crate::peer_id::PeerId;
use crate::streams::{read_length_prefixed, write_length_prefixed};

/// ALPN for the pairing protocol.
pub const PAIRING_ALPN: &[u8] = b"obsidian-memory/pair/1";

/// How long the handler waits for the daemon to produce a `PairingApproval`.
///
/// This is the 5-minute window for the user to read the code from the mesh
/// member's console and enter it on the new device.
const APPROVAL_TIMEOUT_SECS: u64 = 5 * 60;

/// Maximum failed pairing attempts per peer before rate limiting kicks in.
const MAX_FAILED_ATTEMPTS: u32 = 5;

/// Window over which failed attempts are counted, in seconds.
const RATE_LIMIT_WINDOW_SECS: u64 = 5 * 60;

// NOTE: Rate limiting is keyed by PeerId (= QUIC transport identity), so an attacker
// can bypass it by generating fresh key pairs. Per-IP limiting would be stronger but
// iroh may not expose the remote IP when traffic is routed through a relay. In practice,
// the physical proximity requirement (reading a code from a screen) and the 5-minute
// code expiry make brute-force attacks impractical even without IP-level limiting.

// ── Events produced by PairingStreamHandler ───────────────────────────────────

/// Events emitted by the pairing handler to the daemon event loop.
pub enum PairingEvent {
    /// A new device wants to pair — the daemon must reply with a `PairingApproval`.
    InboundRequest(InboundPairingExchange),
    /// Pairing completed successfully — add the peer to the allowlist.
    PairingCompleted {
        peer_id: PeerId,
        device_name: String,
    },
    /// Pairing failed (wrong code, timeout, or stream error).
    PairingFailed { peer_id: PeerId, reason: String },
}

/// An in-progress pairing request handed to the daemon for approval.
///
/// The daemon generates a code, logs it, and sends back a `PairingApproval`
/// via `reply_tx`. Dropping `reply_tx` without sending causes the handler to
/// reject the pairing request immediately.
pub struct InboundPairingExchange {
    /// The `PairingHello` received from the new device.
    pub hello: PairingHello,
    /// The remote peer's EndpointId (= PeerId bytes).
    pub remote_id: PeerId,
    /// Channel to send the approval (code + mesh info) back to the handler.
    pub reply_tx: oneshot::Sender<PairingApproval>,
}

/// Approval data returned by the daemon to the pairing handler.
///
/// The handler uses this to write the `PairingChallenge` and verify the response.
pub struct PairingApproval {
    /// The plaintext 6-digit code the daemon logged for the user.
    pub code: String,
    /// The `PairingChallenge` to send to the new device.
    pub challenge: PairingChallenge,
    /// The vault's gossip topic bytes (sent in `PairingResult` on success).
    pub vault_topic: [u8; 32],
    /// Relay URLs to include in `PairingResult`.
    pub relay_urls: Vec<String>,
    /// All current mesh members' NodeIds for the new device to bootstrap gossip.
    pub mesh_members: Vec<PeerId>,
}

// ── PairingStreamHandler ──────────────────────────────────────────────────────

/// Failed attempt tracking entry for a single peer.
type FailedAttempts = HashMap<PeerId, (u32, Instant)>;

/// QUIC pairing protocol handler (mesh-member side).
///
/// Registered with iroh's Router for `PAIRING_ALPN`. When a new device
/// connects, the router calls `accept()` which runs the full pairing exchange.
///
/// Clone-safe — cloning shares the same underlying channel sender and rate
/// limit state.
#[derive(Debug, Clone)]
pub struct PairingStreamHandler {
    inbound_tx: Arc<mpsc::UnboundedSender<PairingEvent>>,
    /// Tracks failed attempts per peer for rate limiting.
    ///
    /// Each entry holds (count, window_start). Entries older than
    /// `RATE_LIMIT_WINDOW_SECS` are evicted on next access.
    failed_attempts: Arc<Mutex<FailedAttempts>>,
}

impl PairingStreamHandler {
    /// Create a new handler and return the event receiver.
    ///
    /// Drive the returned receiver in a task to process pairing events.
    pub fn new() -> (Self, mpsc::UnboundedReceiver<PairingEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Self {
                inbound_tx: Arc::new(tx),
                failed_attempts: Arc::new(Mutex::new(HashMap::new())),
            },
            rx,
        )
    }

    /// Check whether a peer has exceeded the failed-attempt rate limit.
    ///
    /// Evicts stale entries (older than `RATE_LIMIT_WINDOW_SECS`) on each
    /// call to prevent unbounded map growth.
    async fn is_rate_limited(&self, peer_id: &PeerId) -> bool {
        let mut map = self.failed_attempts.lock().await;
        let now = Instant::now();
        let window = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        // Evict entries outside the current window.
        map.retain(|_, (_, started_at)| now.duration_since(*started_at) < window);

        match map.get(peer_id) {
            Some((count, _)) => *count >= MAX_FAILED_ATTEMPTS,
            None => false,
        }
    }

    /// Record a failed attempt for a peer. Must be called after HMAC verification fails.
    async fn record_failure(&self, peer_id: &PeerId) {
        let mut map = self.failed_attempts.lock().await;
        let now = Instant::now();
        let window = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        let entry = map.entry(*peer_id).or_insert((0, now));
        // Reset the window if the existing entry has expired.
        if now.duration_since(entry.1) >= window {
            *entry = (0, now);
        }
        entry.0 += 1;
    }
}

impl ProtocolHandler for PairingStreamHandler {
    /// Accept an incoming pairing connection.
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote_endpoint_id = connection.remote_id();
        let remote_id = PeerId::from_bytes(*remote_endpoint_id.as_bytes());

        // Reject immediately if this peer has exceeded the failed-attempt limit.
        if self.is_rate_limited(&remote_id).await {
            warn!(peer = %remote_endpoint_id, "Pairing rate limit exceeded, dropping connection");
            connection.close(0u32.into(), b"rate limited");
            return Ok(());
        }

        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(AcceptError::from_err)?;

        // Step 1: Read PairingHello
        let hello_bytes = read_length_prefixed(&mut recv)
            .await
            .map_err(|e| AcceptError::from_boxed(e.into()))?;
        let hello: PairingHello = bincode::deserialize(&hello_bytes).map_err(|e| {
            AcceptError::from_boxed(anyhow::anyhow!("PairingHello deserialize: {e}").into())
        })?;

        debug!(peer = %remote_endpoint_id, device = %hello.device_name, "Inbound pairing hello");

        // Step 2: Send InboundRequest to the daemon, await approval
        let (reply_tx, reply_rx) = oneshot::channel();
        let request = PairingEvent::InboundRequest(InboundPairingExchange {
            hello: hello.clone(),
            remote_id,
            reply_tx,
        });

        if self.inbound_tx.send(request).is_err() {
            warn!("Pairing inbound request dropped: no receiver");
            return Ok(());
        }

        // Wait up to 5 minutes for the daemon to generate and return the code.
        let approval = match tokio::time::timeout(
            std::time::Duration::from_secs(APPROVAL_TIMEOUT_SECS),
            reply_rx,
        )
        .await
        {
            Ok(Ok(approval)) => approval,
            Ok(Err(_)) => {
                // reply_tx was dropped — daemon rejected or has no active session.
                debug!(peer = %remote_endpoint_id, "Pairing approval channel dropped, rejecting");
                let _ = self.inbound_tx.send(PairingEvent::PairingFailed {
                    peer_id: remote_id,
                    reason: "rejected by daemon".to_string(),
                });
                return Ok(());
            }
            Err(_) => {
                // 5-minute timeout waiting for approval
                warn!(peer = %remote_endpoint_id, "Pairing approval timed out");
                let _ = self.inbound_tx.send(PairingEvent::PairingFailed {
                    peer_id: remote_id,
                    reason: "approval timeout".to_string(),
                });
                return Ok(());
            }
        };

        // Step 4: Write PairingChallenge
        let challenge_bytes = bincode::serialize(&approval.challenge).map_err(|e| {
            AcceptError::from_boxed(anyhow::anyhow!("PairingChallenge serialize: {e}").into())
        })?;
        write_length_prefixed(&mut send, &challenge_bytes)
            .await
            .map_err(|e| AcceptError::from_boxed(e.into()))?;

        // Step 5: Read PairingResponse
        let response_bytes = read_length_prefixed(&mut recv)
            .await
            .map_err(|e| AcceptError::from_boxed(e.into()))?;
        let response: PairingResponse = bincode::deserialize(&response_bytes).map_err(|e| {
            AcceptError::from_boxed(anyhow::anyhow!("PairingResponse deserialize: {e}").into())
        })?;

        // Step 6: Verify HMAC
        let success = verify_hmac(&approval.code, remote_id.as_bytes(), &response.hmac);

        // Step 7: Write PairingResult
        let result = if success {
            PairingResult {
                success: true,
                vault_topic: Some(approval.vault_topic),
                relay_urls: approval.relay_urls.clone(),
                mesh_members: approval.mesh_members.clone(),
            }
        } else {
            PairingResult {
                success: false,
                vault_topic: None,
                relay_urls: vec![],
                mesh_members: vec![],
            }
        };

        let result_bytes = bincode::serialize(&result).map_err(|e| {
            AcceptError::from_boxed(anyhow::anyhow!("PairingResult serialize: {e}").into())
        })?;
        write_length_prefixed(&mut send, &result_bytes)
            .await
            .map_err(|e| AcceptError::from_boxed(e.into()))?;
        send.finish().map_err(AcceptError::from_err)?;

        // Step 8: Notify daemon of the outcome
        if success {
            info!(peer = %remote_endpoint_id, device = %hello.device_name, "Pairing succeeded");
            let _ = self.inbound_tx.send(PairingEvent::PairingCompleted {
                peer_id: remote_id,
                device_name: hello.device_name,
            });
        } else {
            warn!(peer = %remote_endpoint_id, "Pairing failed: HMAC mismatch");
            self.record_failure(&remote_id).await;
            let _ = self.inbound_tx.send(PairingEvent::PairingFailed {
                peer_id: remote_id,
                reason: "HMAC verification failed".to_string(),
            });
        }

        // Wait for the client to close so they can finish reading.
        tokio::select! {
            _ = connection.closed() => {}
            _ = tokio::time::sleep(crate::time_scale::scaled(std::time::Duration::from_secs(30))) => {
                debug!("Closing idle pairing connection after 30s");
                connection.close(0u32.into(), b"timeout");
            }
        }

        Ok(())
    }
}

// ── Client-side: pair_with_mesh ───────────────────────────────────────────────

/// Open a pairing connection to a mesh member and complete the 4-message exchange.
///
/// `hello` describes the new device. `code` is the 6-digit value the user read
/// from the mesh member's console. Returns `PairingResult` from the mesh member.
///
/// The `node_id` in `hello` is overridden with the endpoint's actual identity so
/// the HMAC is bound to the same key that authenticates the QUIC connection. This
/// ensures the mesh member can verify us using the transport identity, not a
/// caller-supplied value.
///
/// # Errors
///
/// Returns an error if the QUIC connection fails, a message cannot be serialized
/// or deserialized, or the stream ends unexpectedly.
pub async fn pair_with_mesh(
    endpoint: &iroh::Endpoint,
    peer: impl Into<iroh::EndpointAddr>,
    hello: &PairingHello,
    code: &str,
) -> Result<PairingResult> {
    // Derive node_id from the endpoint's actual identity, not the caller's hello.
    let node_id = PeerId::from_bytes(*endpoint.id().as_bytes());
    let hello = PairingHello {
        node_id,
        device_name: hello.device_name.clone(),
    };

    let connection = endpoint
        .connect(peer, PAIRING_ALPN)
        .await
        .context("Failed to connect to mesh member for pairing")?;

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .context("Failed to open bi-stream for pairing")?;

    // Step 1: Send PairingHello
    let hello_bytes = bincode::serialize(&hello).context("Failed to serialize PairingHello")?;
    write_length_prefixed(&mut send, &hello_bytes)
        .await
        .context("Failed to send PairingHello")?;

    // Step 2: Receive PairingChallenge
    let challenge_bytes = read_length_prefixed(&mut recv)
        .await
        .context("Failed to read PairingChallenge")?;
    let challenge: PairingChallenge =
        bincode::deserialize(&challenge_bytes).context("Failed to deserialize PairingChallenge")?;

    debug!(
        mesh_device = %challenge.device_name,
        "Received pairing challenge, computing HMAC"
    );

    // Step 3: Compute HMAC bound to our transport identity.
    let hmac = crate::pairing::compute_hmac(code, hello.node_id.as_bytes());
    let response = PairingResponse { hmac };
    let response_bytes =
        bincode::serialize(&response).context("Failed to serialize PairingResponse")?;
    write_length_prefixed(&mut send, &response_bytes)
        .await
        .context("Failed to send PairingResponse")?;
    send.finish().context("Failed to finish send stream")?;

    // Step 4: Receive PairingResult
    let result_bytes = read_length_prefixed(&mut recv)
        .await
        .context("Failed to read PairingResult")?;
    let result: PairingResult =
        bincode::deserialize(&result_bytes).context("Failed to deserialize PairingResult")?;

    Ok(result)
}

/// Open a pairing connection and complete the exchange interactively.
///
/// Like [`pair_with_mesh`], but instead of taking the code upfront, it calls
/// `get_code` after receiving the `PairingChallenge`. This lets the caller
/// prompt the user for the code after the challenge is received — which is
/// when the mesh member generates and displays it.
///
/// The `get_code` future receives the challenge for display (e.g., to show the
/// mesh member's device name) and returns the code the user typed.
///
/// # Errors
///
/// Returns an error if the QUIC connection fails, a message cannot be
/// serialized/deserialized, the stream ends unexpectedly, or `get_code` returns
/// an error.
pub async fn pair_with_mesh_interactive<F, Fut>(
    endpoint: &iroh::Endpoint,
    peer: impl Into<iroh::EndpointAddr>,
    hello: &PairingHello,
    get_code: F,
) -> Result<PairingResult>
where
    F: FnOnce(PairingChallenge) -> Fut,
    Fut: std::future::Future<Output = Result<String>>,
{
    // Derive node_id from the endpoint's actual identity, not the caller's hello.
    let node_id = PeerId::from_bytes(*endpoint.id().as_bytes());
    let hello = PairingHello {
        node_id,
        device_name: hello.device_name.clone(),
    };

    let connection = endpoint
        .connect(peer, PAIRING_ALPN)
        .await
        .context("Failed to connect to mesh member for pairing")?;

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .context("Failed to open bi-stream for pairing")?;

    // Step 1: Send PairingHello
    let hello_bytes = bincode::serialize(&hello).context("Failed to serialize PairingHello")?;
    write_length_prefixed(&mut send, &hello_bytes)
        .await
        .context("Failed to send PairingHello")?;

    // Step 2: Receive PairingChallenge — the mesh member generates the code here.
    let challenge_bytes = read_length_prefixed(&mut recv)
        .await
        .context("Failed to read PairingChallenge")?;
    let challenge: PairingChallenge =
        bincode::deserialize(&challenge_bytes).context("Failed to deserialize PairingChallenge")?;

    debug!(
        mesh_device = %challenge.device_name,
        "Received pairing challenge, prompting user for code"
    );

    // Step 3: Ask the caller for the code (e.g., prompt the user).
    let code = get_code(challenge).await?;

    // Step 4: Compute HMAC bound to our transport identity.
    let hmac = crate::pairing::compute_hmac(&code, hello.node_id.as_bytes());
    let response = PairingResponse { hmac };
    let response_bytes =
        bincode::serialize(&response).context("Failed to serialize PairingResponse")?;
    write_length_prefixed(&mut send, &response_bytes)
        .await
        .context("Failed to send PairingResponse")?;
    send.finish().context("Failed to finish send stream")?;

    // Step 5: Receive PairingResult
    let result_bytes = read_length_prefixed(&mut recv)
        .await
        .context("Failed to read PairingResult")?;
    let result: PairingResult =
        bincode::deserialize(&result_bytes).context("Failed to deserialize PairingResult")?;

    Ok(result)
}

// ── Integration tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use iroh::protocol::Router;
    use iroh::{RelayMode, address_lookup::memory::MemoryLookup, endpoint::presets};

    fn seed(n: u8) -> [u8; 32] {
        [n; 32]
    }

    /// Build a test endpoint registered with the pairing ALPN.
    ///
    /// Returns the endpoint, the pairing event receiver, and the router
    /// (kept alive to maintain the protocol handler).
    async fn make_pairing_test_node(
        secret_key_bytes: [u8; 32],
    ) -> anyhow::Result<(
        iroh::Endpoint,
        mpsc::UnboundedReceiver<PairingEvent>,
        Router,
    )> {
        use ed25519_dalek::SigningKey;
        use iroh::{Endpoint, SecretKey};

        let signing_key = SigningKey::from_bytes(&secret_key_bytes);
        let secret_key = SecretKey::from_bytes(&signing_key.to_bytes());

        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(secret_key)
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;

        // The pairing tests only drive PAIRING_ALPN; the gossip/sync handlers that
        // the production router also registers live in sync-core and aren't
        // exercised here, so this router accepts the pairing protocol alone.
        let (pairing_handler, pairing_rx) = PairingStreamHandler::new();

        let router = Router::builder(endpoint.clone())
            .accept(PAIRING_ALPN, pairing_handler)
            .spawn();

        let memory_lookup = MemoryLookup::new();
        endpoint.address_lookup()?.add(memory_lookup);

        Ok((endpoint, pairing_rx, router))
    }

    /// Teach two endpoints how to reach each other directly (no relay).
    async fn connect_pair(ep_a: &iroh::Endpoint, ep_b: &iroh::Endpoint) -> anyhow::Result<()> {
        let addr_a = ep_a.addr();
        let addr_b = ep_b.addr();

        let lookup_a = MemoryLookup::new();
        lookup_a.add_endpoint_info(addr_b.clone());
        ep_a.address_lookup()?.add(lookup_a);

        let lookup_b = MemoryLookup::new();
        lookup_b.add_endpoint_info(addr_a.clone());
        ep_b.address_lookup()?.add(lookup_b);

        Ok(())
    }

    /// Happy path: new device pairs successfully with the correct code.
    ///
    /// Both sides agree on the code ahead of time — the mesh side uses it as the
    /// approval code, and the client side enters the same code. This mirrors
    /// the real-world flow where the user reads the code from the mesh device's
    /// console and types it into the new device.
    #[tokio::test]
    async fn successful_pairing_with_correct_code() -> anyhow::Result<()> {
        let (mesh_ep, mut mesh_rx, _mesh_router) = make_pairing_test_node(seed(1)).await?;
        let (new_ep, _new_rx, _new_router) = make_pairing_test_node(seed(2)).await?;
        connect_pair(&mesh_ep, &new_ep).await?;

        let mesh_addr = mesh_ep.addr();
        let new_peer_id = PeerId::from_bytes(*new_ep.id().as_bytes());
        let mesh_peer_id = PeerId::from_bytes(*mesh_ep.id().as_bytes());

        // Pre-agreed code for the test (normally the user reads this from the console).
        let test_code = "042817";

        // Mesh side: approve using the test code, then confirm completion.
        let mesh_task = tokio::spawn(async move {
            let event = tokio::time::timeout(Duration::from_secs(10), mesh_rx.recv())
                .await
                .expect("timeout waiting for pairing event")
                .expect("channel closed");

            let PairingEvent::InboundRequest(exchange) = event else {
                return false;
            };

            let approval = PairingApproval {
                code: test_code.to_string(),
                challenge: PairingChallenge {
                    node_id: mesh_peer_id,
                    device_name: "umbra".to_string(),
                },
                vault_topic: [0xAAu8; 32],
                relay_urls: vec!["https://relay.example.com".to_string()],
                mesh_members: vec![mesh_peer_id],
            };
            let _ = exchange.reply_tx.send(approval);

            // Expect PairingCompleted
            let completion = tokio::time::timeout(Duration::from_secs(10), mesh_rx.recv())
                .await
                .expect("timeout waiting for completion")
                .expect("channel closed");

            matches!(completion, PairingEvent::PairingCompleted { .. })
        });

        // New device side: connect and enter the same code.
        let hello = PairingHello {
            node_id: new_peer_id,
            device_name: "MacBook Pro".to_string(),
        };
        let client_task = tokio::spawn(async move {
            let result = tokio::time::timeout(
                Duration::from_secs(10),
                pair_with_mesh(&new_ep, mesh_addr, &hello, test_code),
            )
            .await
            .expect("client timeout")?;

            anyhow::Ok(result)
        });

        let mesh_completed = tokio::time::timeout(Duration::from_secs(15), mesh_task)
            .await
            .expect("test timed out")
            .expect("mesh task panicked");

        let client_result = tokio::time::timeout(Duration::from_secs(15), client_task)
            .await
            .expect("client timed out")
            .expect("client task panicked")?;

        assert!(mesh_completed, "Mesh side should report PairingCompleted");
        assert!(client_result.success, "Client should receive success=true");
        assert_eq!(client_result.vault_topic, Some([0xAAu8; 32]));
        assert_eq!(client_result.mesh_members, vec![mesh_peer_id]);

        Ok(())
    }

    /// Wrong code: HMAC mismatch causes pairing to fail on both sides.
    #[tokio::test]
    async fn failed_pairing_with_wrong_code() -> anyhow::Result<()> {
        let (mesh_ep, mut mesh_rx, _mesh_router) = make_pairing_test_node(seed(3)).await?;
        let (new_ep, _new_rx, _new_router) = make_pairing_test_node(seed(4)).await?;
        connect_pair(&mesh_ep, &new_ep).await?;

        let mesh_addr = mesh_ep.addr();
        let new_peer_id = PeerId::from_bytes(*new_ep.id().as_bytes());
        let mesh_peer_id = PeerId::from_bytes(*mesh_ep.id().as_bytes());

        // Mesh side: approve with code "123456" and expect PairingFailed.
        let mesh_task = tokio::spawn(async move {
            let event = tokio::time::timeout(Duration::from_secs(10), mesh_rx.recv())
                .await
                .expect("timeout")
                .expect("channel closed");

            let PairingEvent::InboundRequest(exchange) = event else {
                return false;
            };

            let approval = PairingApproval {
                code: "123456".to_string(),
                challenge: PairingChallenge {
                    node_id: mesh_peer_id,
                    device_name: "umbra".to_string(),
                },
                vault_topic: [0xBBu8; 32],
                relay_urls: vec![],
                mesh_members: vec![],
            };
            let _ = exchange.reply_tx.send(approval);

            let outcome = tokio::time::timeout(Duration::from_secs(10), mesh_rx.recv())
                .await
                .expect("timeout")
                .expect("channel closed");

            matches!(outcome, PairingEvent::PairingFailed { .. })
        });

        // New device: enter the wrong code.
        let hello = PairingHello {
            node_id: new_peer_id,
            device_name: "iPhone".to_string(),
        };
        let client_task = tokio::spawn(async move {
            let result = tokio::time::timeout(
                Duration::from_secs(10),
                pair_with_mesh(&new_ep, mesh_addr, &hello, "999999"),
            )
            .await
            .expect("client timeout")?;

            anyhow::Ok(result)
        });

        let mesh_failed = tokio::time::timeout(Duration::from_secs(15), mesh_task)
            .await
            .expect("test timed out")
            .expect("mesh task panicked");

        let client_result = tokio::time::timeout(Duration::from_secs(15), client_task)
            .await
            .expect("client timed out")
            .expect("client task panicked")?;

        assert!(mesh_failed, "Mesh side should report PairingFailed");
        assert!(
            !client_result.success,
            "Client should receive success=false"
        );

        Ok(())
    }

    /// When the mesh side drops the approval channel without responding,
    /// the handler times out and sends PairingFailed.
    ///
    /// We test the instant-reject path (dropping reply_tx immediately) since
    /// a 5-minute timeout would make the test impractical.
    #[tokio::test]
    async fn rejected_when_approval_dropped() -> anyhow::Result<()> {
        let (mesh_ep, mut mesh_rx, _mesh_router) = make_pairing_test_node(seed(5)).await?;
        let (new_ep, _new_rx, _new_router) = make_pairing_test_node(seed(6)).await?;
        connect_pair(&mesh_ep, &new_ep).await?;

        let mesh_addr = mesh_ep.addr();
        let new_peer_id = PeerId::from_bytes(*new_ep.id().as_bytes());

        // Mesh side: drop the reply_tx immediately (simulates daemon rejection).
        tokio::spawn(async move {
            while let Some(event) = mesh_rx.recv().await {
                if let PairingEvent::InboundRequest(exchange) = event {
                    // Dropping reply_tx causes the handler to see Err on recv
                    drop(exchange.reply_tx);
                }
            }
        });

        // New device: connect and expect to be rejected.
        let hello = PairingHello {
            node_id: new_peer_id,
            device_name: "laptop".to_string(),
        };

        // The client side sees the stream close without a challenge — this should
        // produce an error (not a successful PairingResult with success=false).
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            pair_with_mesh(&new_ep, mesh_addr, &hello, "000000"),
        )
        .await
        .expect("test timed out");

        // The mesh side closed without sending a challenge, so the client
        // gets an IO error trying to read the challenge.
        assert!(
            result.is_err(),
            "Client should get an error when mesh rejects"
        );

        Ok(())
    }

    /// A client that sends a `PairingHello` with a node_id that doesn't match
    /// its QUIC identity fails HMAC verification.
    ///
    /// The mesh member verifies the HMAC against the transport-authenticated
    /// `remote_id`, not the self-reported `hello.node_id`. So a client that
    /// claims to be a different peer and computes the HMAC over that fake identity
    /// will fail — the mesh member binds the HMAC to the actual QUIC identity.
    #[tokio::test]
    async fn pairing_fails_when_node_id_mismatches_quic_identity() -> anyhow::Result<()> {
        let (mesh_ep, mut mesh_rx, _mesh_router) = make_pairing_test_node(seed(7)).await?;
        let (new_ep, _new_rx, _new_router) = make_pairing_test_node(seed(8)).await?;
        connect_pair(&mesh_ep, &new_ep).await?;

        let mesh_addr = mesh_ep.addr();
        let mesh_peer_id = PeerId::from_bytes(*mesh_ep.id().as_bytes());

        // A fake identity that doesn't match the QUIC connection's actual remote_id.
        let fake_peer_id = PeerId::from_bytes([0xFFu8; 32]);
        let test_code = "112233";

        // Mesh side: approve and expect PairingFailed.
        let mesh_task = tokio::spawn(async move {
            let event = tokio::time::timeout(Duration::from_secs(10), mesh_rx.recv())
                .await
                .expect("timeout")
                .expect("channel closed");

            let PairingEvent::InboundRequest(exchange) = event else {
                return false;
            };

            // The transport-authenticated remote_id is the real identity — not fake_peer_id.
            let approval = PairingApproval {
                code: test_code.to_string(),
                challenge: PairingChallenge {
                    node_id: mesh_peer_id,
                    device_name: "umbra".to_string(),
                },
                vault_topic: [0xCCu8; 32],
                relay_urls: vec![],
                mesh_members: vec![],
            };
            let _ = exchange.reply_tx.send(approval);

            let outcome = tokio::time::timeout(Duration::from_secs(10), mesh_rx.recv())
                .await
                .expect("timeout")
                .expect("channel closed");

            matches!(outcome, PairingEvent::PairingFailed { .. })
        });

        // Client side: open a raw QUIC connection and send a hello claiming a fake
        // node_id, then compute the HMAC over that fake identity. The mesh member
        // will verify against the real transport identity and reject.
        let client_task = tokio::spawn(async move {
            let connection = new_ep
                .connect(mesh_addr, PAIRING_ALPN)
                .await
                .expect("connect failed");

            let (mut send, mut recv) = connection.open_bi().await.expect("open_bi failed");

            // Claim to be `fake_peer_id` in the hello.
            let hello = PairingHello {
                node_id: fake_peer_id,
                device_name: "impersonator".to_string(),
            };
            let hello_bytes = bincode::serialize(&hello).expect("serialize failed");
            write_length_prefixed(&mut send, &hello_bytes)
                .await
                .expect("send hello failed");

            // Read challenge.
            let challenge_bytes = read_length_prefixed(&mut recv)
                .await
                .expect("read challenge failed");
            let _challenge: PairingChallenge =
                bincode::deserialize(&challenge_bytes).expect("deserialize failed");

            // Compute HMAC over the fake node_id — this won't match what the mesh expects
            // (which is HMAC over the real QUIC transport identity).
            let hmac = crate::pairing::compute_hmac(test_code, fake_peer_id.as_bytes());
            let response = PairingResponse { hmac };
            let response_bytes = bincode::serialize(&response).expect("serialize failed");
            write_length_prefixed(&mut send, &response_bytes)
                .await
                .expect("send response failed");
            send.finish().expect("finish failed");

            // Read result — should be success=false.
            let result_bytes = read_length_prefixed(&mut recv)
                .await
                .expect("read result failed");
            let result: PairingResult =
                bincode::deserialize(&result_bytes).expect("deserialize failed");
            result
        });

        let mesh_failed = tokio::time::timeout(Duration::from_secs(15), mesh_task)
            .await
            .expect("test timed out")
            .expect("mesh task panicked");

        let client_result = tokio::time::timeout(Duration::from_secs(15), client_task)
            .await
            .expect("client timed out")
            .expect("client task panicked");

        assert!(mesh_failed, "Mesh side should report PairingFailed");
        assert!(
            !client_result.success,
            "Client should receive success=false for mismatched identity"
        );

        Ok(())
    }
}
