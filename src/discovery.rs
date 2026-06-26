//! Local network mesh discovery via mDNS.
//!
//! Devices advertise their mesh (vault) on the LAN using `MeshMdns` — a V4-only
//! swarm-discovery wrapper — with a custom service name `obsidian-sync`. Devices
//! sharing the same `VaultId` form a single mesh — this is the foundation for the
//! pairing flow.
//!
//! mDNS is native-only (requires OS-level networking) and is gated by the `native`
//! feature set.

use iroh::address_lookup::UserData;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::peer_id::PeerId;

/// Metadata broadcast via mDNS to identify a mesh (vault).
///
/// Serialized as compact JSON and carried in the mDNS `UserData` TXT record.
/// The total serialized size must stay well under 245 bytes (the `UserData` limit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshMetadata {
    /// Human-readable mesh name (e.g., "Michael's Notes").
    pub mesh: String,
    /// VaultId hex string — groups devices into the same mesh.
    pub vid: String,
    /// Protocol version for forward compatibility.
    pub ver: u32,
}

/// Data about a discovered endpoint — analogous to `iroh_mdns_address_lookup`'s
/// `EndpointData` but lives here so daemon code can import it without depending on
/// the upstream crate.
#[derive(Debug, Clone)]
pub struct EndpointData {
    user_data: Option<UserData>,
}

impl EndpointData {
    pub fn new(user_data: Option<UserData>) -> Self {
        Self { user_data }
    }

    /// Returns the optional user-defined data of the endpoint.
    pub fn user_data(&self) -> Option<&UserData> {
        self.user_data.as_ref()
    }
}

/// An endpoint's ID paired with its discovery data.
#[derive(Debug, Clone)]
pub struct EndpointInfo {
    pub endpoint_id: PeerId,
    pub data: EndpointData,
}

/// An event from the mDNS discovery stream.
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    /// A new or updated peer was discovered.
    Discovered { endpoint_info: EndpointInfo },
    /// A previously-discovered peer has expired off the LAN.
    Expired { endpoint_id: PeerId },
}

/// A discovered mesh on the local network.
///
/// Aggregates all devices that share the same `VaultId` into one mesh entry.
/// Built from `DiscoveryEvent::Discovered` events by the caller.
#[derive(Debug, Clone)]
pub struct DiscoveredMesh {
    /// Mesh name from the metadata.
    pub mesh_name: String,
    /// VaultId for grouping (hex string).
    pub vault_id: String,
    /// Discovered peers in this mesh (their `PeerId`s).
    pub peers: Vec<PeerId>,
    /// Number of online devices (equal to `peers.len()` at discovery time).
    pub online_count: usize,
}

/// Parse a `DiscoveryEvent::Discovered` into a single-peer `DiscoveredMesh`.
///
/// Returns `None` for `DiscoveryEvent::Expired` or when the peer's user-data
/// cannot be parsed as `MeshMetadata`. Malformed metadata is logged as a warning
/// (peer id + parse error + raw user-data) so operators can diagnose mDNS issues
/// without needing a debugger.
///
/// Callers that need to accumulate multiple peers per mesh (e.g. the CLI scanner)
/// should fold successive calls into their own `HashMap` keyed by `vault_id`.
pub fn mesh_from_discovery_event(event: &DiscoveryEvent) -> Option<DiscoveredMesh> {
    let DiscoveryEvent::Discovered { endpoint_info } = event else {
        return None;
    };

    let raw = endpoint_info.data.user_data()?;
    let s = raw.as_ref();

    let meta: MeshMetadata = match serde_json::from_str(s) {
        Ok(m) => m,
        Err(e) => {
            warn!(
                peer = %endpoint_info.endpoint_id,
                err = %e,
                user_data = %s,
                "mDNS: discarding peer with malformed mesh metadata"
            );
            return None;
        }
    };

    Some(DiscoveredMesh {
        mesh_name: meta.mesh.clone(),
        vault_id: meta.vid.clone(),
        peers: vec![endpoint_info.endpoint_id],
        online_count: 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a deterministic test `PeerId` from a seed byte.
    fn test_peer_id(seed: u8) -> PeerId {
        PeerId::from_secret_bytes([seed; 32])
    }

    /// Build a `DiscoveryEvent::Discovered` with `user_data` set to the given string.
    fn discovered_event(endpoint_id: PeerId, user_data_str: &str) -> DiscoveryEvent {
        DiscoveryEvent::Discovered {
            endpoint_info: EndpointInfo {
                endpoint_id,
                data: EndpointData::new(Some(user_data_str.parse().unwrap())),
            },
        }
    }

    #[test]
    fn valid_metadata_returns_single_peer_mesh() {
        let id = test_peer_id(1);
        let meta = MeshMetadata {
            mesh: "Michael's Notes".into(),
            vid: "deadbeef".into(),
            ver: 1,
        };
        let event = discovered_event(id, &serde_json::to_string(&meta).unwrap());

        let mesh = mesh_from_discovery_event(&event).expect("should parse valid metadata");
        assert_eq!(mesh.mesh_name, "Michael's Notes");
        assert_eq!(mesh.vault_id, "deadbeef");
        assert_eq!(mesh.peers, vec![id]);
        assert_eq!(mesh.online_count, 1);
    }

    #[test]
    fn malformed_json_returns_none() {
        let id = test_peer_id(2);
        let event = discovered_event(id, "not valid json {{{");
        assert!(mesh_from_discovery_event(&event).is_none());
    }

    #[test]
    fn missing_required_field_returns_none() {
        // Missing `vid` — serde will fail to deserialize.
        let id = test_peer_id(3);
        let event = discovered_event(id, r#"{"mesh":"My Notes","ver":1}"#);
        assert!(mesh_from_discovery_event(&event).is_none());
    }

    #[test]
    fn expired_event_returns_none() {
        let event = DiscoveryEvent::Expired {
            endpoint_id: test_peer_id(4),
        };
        assert!(mesh_from_discovery_event(&event).is_none());
    }

    #[test]
    fn no_user_data_returns_none() {
        let event = DiscoveryEvent::Discovered {
            endpoint_info: EndpointInfo {
                endpoint_id: test_peer_id(5),
                data: EndpointData::new(None),
            },
        };
        assert!(mesh_from_discovery_event(&event).is_none());
    }

    /// Wire-contract guard: `MeshMetadata` is serialized to JSON and broadcast as
    /// live mDNS user-data across the running fleet. The Rust field names ARE the
    /// JSON keys (no `#[serde(rename)]`), so renaming a field silently changes the
    /// wire format and breaks discovery mid-migration. This test fails loudly if a
    /// future refactor renames a field without adding a `#[serde(rename = "...")]`
    /// to preserve the key.
    #[test]
    fn mesh_metadata_wire_keys_are_stable() {
        let m = MeshMetadata {
            mesh: "x".into(),
            vid: "deadbeef".into(),
            ver: 1,
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("\"mesh\":"));
        assert!(json.contains("\"vid\":"));
        assert!(json.contains("\"ver\":"));
        // Round-trip stability.
        let back: MeshMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.vid, "deadbeef");
    }
}
