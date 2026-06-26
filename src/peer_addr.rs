//! The dial-target value type.
//!
//! `PeerAddr` bundles a peer's identity with an optional relay hint — the two
//! pieces a dial needs. It wraps the construction of `iroh::EndpointAddr` so that
//! type never appears in a public or cross-crate signature: consumers build a
//! `PeerAddr` from a [`PeerId`] (+ optional [`RelayAddr`]) and hand it to
//! `P2pNode::connect` / `pair_with_mesh*`, which convert to iroh's `EndpointAddr`
//! only inside p2p-core.

use crate::peer_id::PeerId;
use crate::relay_addr::RelayAddr;

/// A dial target: a peer's identity plus an optional relay hint.
///
/// Built from a [`PeerId`] and an optional [`RelayAddr`]. A bare `PeerAddr` (no
/// relay) is resolved via address-lookup / mDNS; attaching a relay hint lets the
/// dial resolve immediately through that relay. Converts to iroh's `EndpointAddr`
/// only inside p2p-core (at the dial boundary), so the iroh type stays out of
/// public signatures.
#[derive(Clone, Debug)]
pub struct PeerAddr {
    peer: PeerId,
    relay: Option<RelayAddr>,
}

impl PeerAddr {
    /// A bare peer with no relay hint (resolved via address-lookup / mDNS).
    pub fn new(peer: PeerId) -> Self {
        Self { peer, relay: None }
    }

    /// Attach a relay hint so the dial resolves immediately via this relay.
    pub fn with_relay(mut self, relay: RelayAddr) -> Self {
        self.relay = Some(relay);
        self
    }

    /// The peer's identity.
    pub fn peer(&self) -> PeerId {
        self.peer
    }

    /// FALLIBLE conversion to iroh's `EndpointAddr`.
    ///
    /// Fails iff `peer` is a legacy / non-curve-point id (mirrors
    /// [`crate::iroh_adapt::try_peer_to_endpoint`]) — a `PeerAddr` may carry an
    /// allowlist-sourced id in the reconnect-supervisor path, so the conversion
    /// must degrade rather than panic. p2p-core-internal (used by the dial path:
    /// `DialHandle::connect` / `pair_with_mesh*`).
    pub(crate) fn try_into_iroh(&self) -> Result<iroh::EndpointAddr, iroh::KeyParsingError> {
        let endpoint_id = crate::iroh_adapt::try_peer_to_endpoint(self.peer)?;
        let mut addr = iroh::EndpointAddr::new(endpoint_id);
        if let Some(ref r) = self.relay {
            addr = addr.with_relay_url(r.as_iroh().clone());
        }
        Ok(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `PeerAddr` over a real key converts to a valid `EndpointAddr` and
    /// round-trips its peer; a `PeerAddr` over a legacy id fails the conversion
    /// (the graceful-degrade path the supervisor relies on).
    #[test]
    fn peer_addr_builds_iroh_endpoint_addr() {
        let peer = PeerId::generate();
        let addr = PeerAddr::new(peer).with_relay(RelayAddr::parse("https://r.example/").unwrap());
        assert_eq!(addr.peer(), peer); // peer round-trips
        let iroh_addr = addr.try_into_iroh().expect("real key converts");
        assert_eq!(iroh_addr.id.as_bytes(), peer.as_bytes()); // same 32 bytes

        // A legacy/non-curve-point id cannot be a dial target.
        let legacy: PeerId = "a1b2c3d4e5f67890".parse().unwrap();
        assert!(PeerAddr::new(legacy).try_into_iroh().is_err());
    }
}
