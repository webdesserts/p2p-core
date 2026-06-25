//! Peer connection-type classification.
//!
//! Decodes iroh's per-peer transport snapshot (`remote_info`) into a small,
//! application-agnostic description of *how* we are reaching a peer: directly
//! over the LAN/IP, through a relay, or via an unknown/not-yet-settled path.
//!
//! This lives in p2p-core because the iroh `Endpoint` and its `TransportAddr`
//! types do — the daemon composes the friendly device name (from its allowlist)
//! on top of the `PeerConnType` this module produces, so the classifier stays
//! free of any sync- or app-level types.

use std::net::SocketAddr;

use iroh::RelayUrl;
use iroh::TransportAddr;
use iroh::endpoint::{RemoteInfo, TransportAddrUsage};

/// How we are currently reaching a peer.
///
/// `Lan` is the operationally interesting "we got off the relay" state and is
/// preferred whenever a direct path is active, even if a relay path is also
/// active mid-holepunch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerConnType {
    /// Direct IP/LAN path — carries the remote socket address.
    Lan { addr: SocketAddr },
    /// Relay-routed path — carries the relay URL.
    Relay { url: RelayUrl },
    /// No active transport path is known (e.g. `remote_info` returned `None`,
    /// the peer is mid-holepunch, or only a test/custom transport is active).
    Unknown,
}

/// A snapshot of how we are reaching a peer.
///
/// Returned by [`crate::P2pNode::peer_conn_info`]. Currently just the
/// connection type; wrapped in a struct so future fields (latency, path count)
/// can be added without changing the accessor's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConnInfo {
    pub conn_type: PeerConnType,
}

/// Classify a peer's connection type from its active transport addresses.
///
/// Pure over an iterator of `(TransportAddr, TransportAddrUsage)` so it is
/// unit-testable without a live endpoint. The decision:
///
/// - Any `Active` `Ip` path → `Lan` (LAN-preferred: report that IP). A direct
///   path means we successfully got off the relay, which is the interesting
///   state to surface even if a relay path is also active.
/// - Else any `Active` `Relay` path → `Relay` (report the relay URL).
/// - Else (no active addr, or only `Custom`/test transports) → `Unknown`.
///
/// `Inactive` addresses are ignored entirely — they are stale or unusable.
fn classify_conn_type<I>(addrs: I) -> PeerConnType
where
    I: IntoIterator<Item = (TransportAddr, TransportAddrUsage)>,
{
    let mut relay_url: Option<RelayUrl> = None;

    for (addr, usage) in addrs {
        if !matches!(usage, TransportAddrUsage::Active) {
            continue;
        }
        match addr {
            // Direct path wins immediately — LAN-preferred.
            TransportAddr::Ip(socket) => return PeerConnType::Lan { addr: socket },
            // Remember the first active relay, but keep scanning in case a
            // direct path appears later in the iterator.
            TransportAddr::Relay(url) => {
                if relay_url.is_none() {
                    relay_url = Some(url);
                }
            }
            // `Custom` is a test-only transport; treat as unknown.
            _ => {}
        }
    }

    match relay_url {
        Some(url) => PeerConnType::Relay { url },
        None => PeerConnType::Unknown,
    }
}

/// Classify a [`RemoteInfo`] snapshot into a [`PeerConnType`].
///
/// Thin adapter over [`classify_conn_type`] that pulls the
/// `(addr, usage)` pairs out of the iroh snapshot.
pub(crate) fn classify_remote_info(info: &RemoteInfo) -> PeerConnType {
    classify_conn_type(info.addrs().map(|a| (a.addr().clone(), a.usage())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> TransportAddr {
        TransportAddr::Ip(s.parse().unwrap())
    }

    fn relay(s: &str) -> TransportAddr {
        TransportAddr::Relay(s.parse().unwrap())
    }

    #[test]
    fn active_ip_classifies_as_lan() {
        let conn = classify_conn_type([(ip("192.168.10.226:11204"), TransportAddrUsage::Active)]);
        assert_eq!(
            conn,
            PeerConnType::Lan {
                addr: "192.168.10.226:11204".parse().unwrap()
            }
        );
    }

    #[test]
    fn active_relay_only_classifies_as_relay() {
        let conn =
            classify_conn_type([(relay("https://umbra.computer/"), TransportAddrUsage::Active)]);
        assert_eq!(
            conn,
            PeerConnType::Relay {
                url: "https://umbra.computer/".parse().unwrap()
            }
        );
    }

    #[test]
    fn both_active_prefers_lan() {
        // Order the relay first to prove the scan still prefers the later direct
        // path — LAN preference is not an artifact of iteration order.
        let conn = classify_conn_type([
            (relay("https://umbra.computer/"), TransportAddrUsage::Active),
            (ip("192.168.10.226:11204"), TransportAddrUsage::Active),
        ]);
        assert_eq!(
            conn,
            PeerConnType::Lan {
                addr: "192.168.10.226:11204".parse().unwrap()
            }
        );
    }

    #[test]
    fn all_inactive_classifies_as_unknown() {
        let conn = classify_conn_type([
            (ip("192.168.10.226:11204"), TransportAddrUsage::Inactive),
            (
                relay("https://umbra.computer/"),
                TransportAddrUsage::Inactive,
            ),
        ]);
        assert_eq!(conn, PeerConnType::Unknown);
    }

    #[test]
    fn empty_classifies_as_unknown() {
        let conn = classify_conn_type(std::iter::empty());
        assert_eq!(conn, PeerConnType::Unknown);
    }

    #[test]
    fn inactive_ip_ignored_active_relay_wins() {
        // A stale direct path must not be reported as LAN when the only live
        // route is the relay.
        let conn = classify_conn_type([
            (ip("192.168.10.226:11204"), TransportAddrUsage::Inactive),
            (relay("https://umbra.computer/"), TransportAddrUsage::Active),
        ]);
        assert_eq!(
            conn,
            PeerConnType::Relay {
                url: "https://umbra.computer/".parse().unwrap()
            }
        );
    }
}
