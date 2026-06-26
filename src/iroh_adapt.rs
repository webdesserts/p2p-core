//! Private adapters between p2p-core's `PeerId` and iroh's `EndpointId`.
//!
//! p2p-core's public API speaks `PeerId`; iroh's transport layer speaks
//! `EndpointId`. The two are byte-identical (both are the 32-byte ed25519 public
//! key), so converting is just a re-wrap of the same bytes — done here, at the
//! iroh boundary, so no `EndpointId` leaks into a public signature.
//!
//! ## Fallibility asymmetry
//!
//! `EndpointId::from_bytes` (iroh's `PublicKey::from_bytes`) VALIDATES that the
//! bytes are a real ed25519 curve point — it is NOT a blind re-wrap. A `PeerId`,
//! by contrast, can be constructed from a LEGACY string format (16-char hex,
//! UUID — see [`crate::peer_id::PeerIdError`]) whose bytes are not a curve point.
//! So `PeerId → EndpointId` is FALLIBLE; the reverse (any 32 bytes → `PeerId`) is
//! infallible.

use crate::peer_id::PeerId;

/// FALLIBLE `PeerId → iroh::EndpointId`. Use this wherever the `PeerId` may not be
/// a real key — allowlist / registry / liveness signals — so the caller can
/// degrade gracefully (e.g. an `Unknown` connection path) instead of panicking on
/// a legacy/non-curve-point id.
pub(crate) fn try_peer_to_endpoint(p: PeerId) -> Result<iroh::EndpointId, iroh::KeyParsingError> {
    iroh::EndpointId::from_bytes(p.as_bytes())
}

/// Infallible-on-trusted-input `PeerId → iroh::EndpointId`. ONLY for `PeerId`s
/// known to be transport-sourced from a real key — `self.node_id()`, or a peer we
/// hold a live iroh connection to (its bytes provably round-tripped from a real
/// `EndpointId`). Per iroh's contract this `.expect()` cannot fire for such bytes.
/// Do NOT call this on allowlist/registry/liveness ids — use
/// [`try_peer_to_endpoint`] there.
///
/// `allow(dead_code)`: this is the transport-sourced half of the documented
/// two-variant adapter. p2p-core's own public methods all take possibly-legacy
/// ids (so they use the fallible variant); the daemon's transport-sourced
/// `.expect()` sites inline the same conversion because this adapter is crate-
/// private. Kept (and unit-tested) so the design's API is complete and the
/// byte-identity round-trip stays pinned.
#[allow(dead_code)]
pub(crate) fn peer_to_endpoint(p: PeerId) -> iroh::EndpointId {
    try_peer_to_endpoint(p).expect("transport-sourced PeerId is a valid ed25519 key")
}

/// INFALLIBLE `iroh::EndpointId → PeerId`. Any 32 bytes is a valid `PeerId`.
pub(crate) fn endpoint_to_peer(e: iroh::EndpointId) -> PeerId {
    PeerId::from_bytes(*e.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The A2 crux: `PeerId ↔ iroh::EndpointId` round-trips losslessly for a real
    /// key. Pins the byte-identity claim so a future iroh upgrade that changed
    /// `EndpointId`'s representation would fail loudly here.
    #[test]
    fn peer_id_iroh_endpoint_id_round_trips() {
        let p = PeerId::generate();
        // PeerId -> iroh::EndpointId -> PeerId must be identity.
        let e = peer_to_endpoint(p);
        assert_eq!(e.as_bytes(), p.as_bytes()); // same 32 bytes
        assert_eq!(endpoint_to_peer(e), p); // round-trip identity
    }

    /// A `PeerId` generated from a real ed25519 keypair is always a valid curve
    /// point, so the fallible conversion succeeds for it.
    #[test]
    fn try_peer_to_endpoint_accepts_real_key() {
        let p = PeerId::generate();
        assert!(try_peer_to_endpoint(p).is_ok());
    }
}
