//! Pairing protocol types and crypto.
//!
//! Defines the 4-message exchange used to add a new device to an existing
//! sync mesh over a QUIC connection with ALPN `obsidian-memory/pair/1`.
//!
//! # Protocol flow
//!
//! 1. New device → mesh member: [`PairingHello`]
//! 2. Mesh member generates 6-digit code, logs it, → new device: [`PairingChallenge`]
//! 3. User reads code from mesh device and types it into the new device
//! 4. New device computes HMAC-SHA256 → mesh member: [`PairingResponse`]
//! 5. Mesh member verifies HMAC → new device: [`PairingResult`]
//! 6. Both sides add each other to their allowlists on success
//!
//! The code entry is the only approval mechanism — there is no auto-approval bypass.

use serde::{Deserialize, Serialize};
use web_time::Instant;

use crate::peer_id::PeerId;

// ── Protocol messages ─────────────────────────────────────────────────────────

/// Sent by the new device to initiate a pairing request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PairingHello {
    /// The new device's ed25519 public key.
    pub node_id: PeerId,
    /// Human-readable name of the new device (e.g., "MacBook Pro").
    pub device_name: String,
}

/// Sent by the mesh member in response to a [`PairingHello`].
///
/// The actual code is logged on the mesh member's console for the user to
/// read and type into the new device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PairingChallenge {
    /// The mesh member's ed25519 public key.
    pub node_id: PeerId,
    /// Human-readable name of the mesh member (e.g., "umbra").
    pub device_name: String,
}

/// Sent by the new device to prove knowledge of the code.
///
/// `hmac` = HMAC-SHA256(key=code_bytes, msg=requester_node_id_bytes).
/// Binding the HMAC to the requester's NodeId prevents a different peer from
/// reusing the same code during the 5-minute validity window.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PairingResponse {
    /// HMAC-SHA256(key=code_bytes, msg=requesting_node_id_bytes).
    pub hmac: [u8; 32],
}

/// Sent by the mesh member after verifying the [`PairingResponse`].
///
/// On success, the new device uses `vault_topic`, `relay_urls`, and
/// `mesh_members` to join the sync mesh immediately.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PairingResult {
    /// Whether pairing succeeded (HMAC was valid).
    pub success: bool,
    /// The vault's gossip topic ID (32 bytes). `None` on failure.
    pub vault_topic: Option<[u8; 32]>,
    /// Relay URLs for NAT traversal. May be empty if direct connections work.
    pub relay_urls: Vec<String>,
    /// All current mesh members' NodeIds so the new device can bootstrap gossip.
    pub mesh_members: Vec<PeerId>,
}

// ── Session state ─────────────────────────────────────────────────────────────

/// How long a pairing code remains valid.
const PAIRING_TIMEOUT_SECS: u64 = 5 * 60;

/// Active pairing session on the mesh member side.
///
/// Created when an inbound [`PairingHello`] arrives. The mesh member logs the
/// code and waits for the new device to submit it. Expires after 5 minutes.
///
/// The `remote_id` is the transport-verified PeerId from the QUIC connection,
/// not the self-reported `node_id` from `PairingHello`. HMAC verification
/// must use this transport identity to prevent impersonation.
pub struct PairingSession {
    /// The plaintext 6-digit code (e.g. `"042817"`).
    pub code: String,
    /// The transport-verified PeerId of the requesting device.
    ///
    /// Derived from the QUIC connection's remote identity — not from
    /// the self-reported `node_id` in `PairingHello`. Use this for HMAC verification.
    pub remote_id: PeerId,
    /// Human-readable name of the requesting device.
    pub requester_device_name: String,
    /// When this session was created, for expiry checks.
    pub created_at: Instant,
}

impl PairingSession {
    /// Create a new session for the given requester.
    ///
    /// `remote_id` must come from the QUIC transport layer, not from
    /// `PairingHello::node_id` (which is self-reported and untrusted).
    /// Generates a fresh random 6-digit code.
    pub fn new(remote_id: PeerId, requester_device_name: impl Into<String>) -> Self {
        let code = generate_pairing_code();
        Self {
            code,
            remote_id,
            requester_device_name: requester_device_name.into(),
            created_at: Instant::now(),
        }
    }

    /// Whether this session has passed the 5-minute expiry window.
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed().as_secs() >= PAIRING_TIMEOUT_SECS
    }
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

/// Generate a random 6-digit zero-padded confirmation code (e.g., `"042817"`).
///
/// Uses `getrandom` for OS-level randomness, consistent with the rest of the
/// codebase. The result is in the range `000000`–`999999`.
pub fn generate_pairing_code() -> String {
    let mut buf = [0u8; 4];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    let n = u32::from_le_bytes(buf) % 1_000_000;
    format!("{:06}", n)
}

/// Compute HMAC-SHA256(key=code_bytes, msg=node_id_bytes).
pub fn compute_hmac(code: &str, node_id_bytes: &[u8; 32]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(code.as_bytes()).expect("HMAC accepts any key length");
    mac.update(node_id_bytes);
    mac.finalize().into_bytes().into()
}

/// Verify an HMAC-SHA256 value in constant time.
///
/// Returns `true` if `hmac == HMAC-SHA256(key=code, msg=node_id_bytes)`.
pub fn verify_hmac(code: &str, node_id_bytes: &[u8; 32], hmac: &[u8; 32]) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(code.as_bytes()).expect("HMAC accepts any key length");
    mac.update(node_id_bytes);
    mac.verify_slice(hmac).is_ok()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_pairing_code_is_six_digits() {
        for _ in 0..20 {
            let code = generate_pairing_code();
            assert_eq!(code.len(), 6, "code should be 6 chars: {code}");
            assert!(
                code.chars().all(|c| c.is_ascii_digit()),
                "non-digit in code: {code}"
            );
        }
    }

    #[test]
    fn hmac_round_trip_succeeds() {
        let code = "042817";
        let node_id_bytes = [0xABu8; 32];
        let hmac = compute_hmac(code, &node_id_bytes);
        assert!(verify_hmac(code, &node_id_bytes, &hmac));
    }

    #[test]
    fn verify_hmac_rejects_wrong_code() {
        let node_id_bytes = [0x01u8; 32];
        let hmac = compute_hmac("123456", &node_id_bytes);
        assert!(!verify_hmac("999999", &node_id_bytes, &hmac));
    }

    #[test]
    fn verify_hmac_rejects_wrong_node_id() {
        let code = "555555";
        let correct_id = [0x01u8; 32];
        let wrong_id = [0x02u8; 32];
        let hmac = compute_hmac(code, &correct_id);
        assert!(!verify_hmac(code, &wrong_id, &hmac));
    }

    #[test]
    fn pairing_session_is_not_expired_immediately() {
        let session = PairingSession::new(PeerId::generate(), "test");
        assert!(!session.is_expired());
    }

    // Note: testing expiry at 5 minutes would require mocking time;
    // the is_expired() logic is straightforward (elapsed >= 300s).

    #[test]
    fn serde_round_trip_pairing_hello() {
        let msg = PairingHello {
            node_id: PeerId::generate(),
            device_name: "MacBook Pro".to_string(),
        };
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: PairingHello = bincode::deserialize(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn serde_round_trip_pairing_challenge() {
        let msg = PairingChallenge {
            node_id: PeerId::generate(),
            device_name: "umbra".to_string(),
        };
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: PairingChallenge = bincode::deserialize(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn serde_round_trip_pairing_response() {
        let msg = PairingResponse { hmac: [0xCCu8; 32] };
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: PairingResponse = bincode::deserialize(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn serde_round_trip_pairing_result_success() {
        let msg = PairingResult {
            success: true,
            vault_topic: Some([0xDDu8; 32]),
            relay_urls: vec!["https://relay.example.com".to_string()],
            mesh_members: vec![PeerId::generate(), PeerId::generate()],
        };
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: PairingResult = bincode::deserialize(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn serde_round_trip_pairing_result_failure() {
        let msg = PairingResult {
            success: false,
            vault_topic: None,
            relay_urls: vec![],
            mesh_members: vec![],
        };
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: PairingResult = bincode::deserialize(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }
}
