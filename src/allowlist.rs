//! AllowlistStorage trait for managing authorized peers.
//!
//! Implementations:
//! - `FileAllowlistStorage` — reads/writes `.sync/allowlist.json`
//! - Plugin implementation (future) — reads/writes via Obsidian's localStorage bridge

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::warn;
use web_time::SystemTime;

use crate::peer_id::PeerId;

#[derive(Debug, Error)]
pub enum AllowlistError {
    #[error("Allowlist file is corrupt or invalid JSON")]
    InvalidData,

    #[error("IO error: {0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, AllowlistError>;

/// An authorized peer stored in the allowlist.
///
/// Each entry represents a device that has been paired and is allowed to sync.
///
/// Removed peers are kept as **tombstones** (`removed = true`) rather than being
/// dropped from storage. This is required for revocation to converge across the
/// mesh: the roster is exchanged by union-merge, so a removal that simply dropped
/// the row would be re-added by any peer that still held it. A tombstone travels
/// in the roster and wins over a live re-add (see `merge_roster`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AllowedPeer {
    /// The peer's ed25519 public key (64-char hex).
    pub node_id: PeerId,
    /// Human-readable device name (e.g., "umbra", "MacBook Pro").
    pub device_name: String,
    /// When the peer was paired (Unix timestamp milliseconds).
    pub paired_at: u64,
    /// When we last saw this peer online (Unix timestamp milliseconds), if ever.
    pub last_seen: Option<u64>,
    /// Whether this peer has been revoked. A tombstoned entry is kept in storage
    /// so the revocation propagates, but is never treated as trusted.
    ///
    /// `#[serde(default)]` keeps older `allowlist.json` files (written before
    /// tombstones existed) loadable — a missing field deserializes to `false`,
    /// i.e. a live peer.
    #[serde(default)]
    pub removed: bool,
    /// When the peer was revoked (Unix timestamp milliseconds), if ever.
    #[serde(default)]
    pub removed_at: Option<u64>,
}

impl AllowedPeer {
    /// Create a new allowed peer entry with the current time as `paired_at`.
    pub fn new(node_id: PeerId, device_name: impl Into<String>) -> Self {
        Self {
            node_id,
            device_name: device_name.into(),
            paired_at: now_ms(),
            last_seen: None,
            removed: false,
            removed_at: None,
        }
    }
}

/// Current Unix time in milliseconds, or 0 if the clock is before the epoch.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Union `incoming` into `existing`, resolving same-`node_id` conflicts so the
/// mesh converges to one roster regardless of who paired whom.
///
/// The merge is the CRDT-ish rule the allowlist relies on for convergence:
///
/// - **Tombstone precedence.** A removal must win over a re-add, otherwise any
///   peer that still holds the live row would resurrect a revoked peer. So a
///   tombstone beats a live row, and a tombstone is never resurrected by a stale
///   live row. Between two tombstones the later `removed_at` wins (equal
///   `removed_at` are equivalent — either may win).
/// - **Live vs live** (same `node_id`, neither removed): `device_name` takes the
///   incoming value (preserves `add_peer`'s name-update and the placeholder
///   "unknown" self-heal), `paired_at` takes the MIN (the earliest pairing is the
///   truest origin), `last_seen` takes the MAX (most recent sighting).
///
/// Entries present in only one side are carried through unchanged.
fn merge_roster_entries(existing: &[AllowedPeer], incoming: &[AllowedPeer]) -> Vec<AllowedPeer> {
    let mut merged = existing.to_vec();

    for inc in incoming {
        match merged.iter_mut().find(|p| p.node_id == inc.node_id) {
            None => merged.push(inc.clone()),
            Some(local) => *local = merge_pair(local, inc),
        }
    }

    merged
}

/// Resolve a single same-`node_id` conflict per the rules in `merge_roster_entries`.
fn merge_pair(local: &AllowedPeer, incoming: &AllowedPeer) -> AllowedPeer {
    match (local.removed, incoming.removed) {
        // Both tombstones: keep the later removal (equal removed_at: equivalent).
        (true, true) => {
            if incoming.removed_at >= local.removed_at {
                incoming.clone()
            } else {
                local.clone()
            }
        }
        // A tombstone on either side wins — a removal is never undone by a live row.
        (true, false) => local.clone(),
        (false, true) => incoming.clone(),
        // Live vs live: name<-incoming, paired_at<-min, last_seen<-max.
        (false, false) => AllowedPeer {
            node_id: local.node_id,
            device_name: incoming.device_name.clone(),
            paired_at: local.paired_at.min(incoming.paired_at),
            last_seen: max_opt(local.last_seen, incoming.last_seen),
            removed: false,
            removed_at: None,
        },
    }
}

/// Maximum of two optional timestamps, treating `None` as "no value".
fn max_opt(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (some, None) | (None, some) => some,
    }
}

/// Abstracts loading and persisting the allowlist of authorized peers.
///
/// The allowlist controls which devices are permitted to sync with this vault.
/// Only peers whose `node_id` appears in the allowlist will be accepted.
#[async_trait]
pub trait AllowlistStorage: Send + Sync {
    /// Load all allowed peers from storage.
    async fn list_peers(&self) -> Result<Vec<AllowedPeer>>;

    /// Save the full allowlist to storage.
    async fn save_peers(&self, peers: &[AllowedPeer]) -> Result<()>;

    /// Add a peer to the allowlist.
    ///
    /// If a peer with this `node_id` already exists, updates the device name.
    async fn add_peer(&self, node_id: PeerId, device_name: impl Into<String> + Send) -> Result<()> {
        let mut peers = self.list_peers().await?;
        let device_name = device_name.into();

        if let Some(existing) = peers.iter_mut().find(|p| p.node_id == node_id) {
            existing.device_name = device_name;
        } else {
            peers.push(AllowedPeer::new(node_id, device_name));
        }

        self.save_peers(&peers).await
    }

    /// Revoke a peer by writing a tombstone.
    ///
    /// The entry stays in storage with `removed = true` (rather than being dropped)
    /// so the revocation propagates across the mesh and wins over any peer that
    /// still holds a live row (see `merge_roster`). If the peer is not present,
    /// this is a no-op.
    async fn remove_peer(&self, node_id: &PeerId) -> Result<()> {
        let mut peers = self.list_peers().await?;
        if let Some(peer) = peers.iter_mut().find(|p| &p.node_id == node_id) {
            peer.removed = true;
            peer.removed_at = Some(now_ms());
            self.save_peers(&peers).await?;
        }
        Ok(())
    }

    /// Check whether a peer is authorized to connect.
    ///
    /// Tombstoned (revoked) entries are not trusted, even though they remain in
    /// storage. This trait is the single source of truth for trust decisions.
    async fn is_allowed(&self, node_id: &PeerId) -> Result<bool> {
        let peers = self.list_peers().await?;
        Ok(peers.iter().any(|p| &p.node_id == node_id && !p.removed))
    }

    /// Update the last-seen timestamp for a peer.
    ///
    /// If the peer is not in the allowlist, this is a no-op.
    async fn update_last_seen(&self, node_id: &PeerId, timestamp_ms: u64) -> Result<()> {
        let mut peers = self.list_peers().await?;
        if let Some(peer) = peers.iter_mut().find(|p| &p.node_id == node_id) {
            peer.last_seen = Some(timestamp_ms);
            self.save_peers(&peers).await?;
        }
        Ok(())
    }

    /// Merge an incoming roster (e.g. received from a mesh peer) into local storage.
    ///
    /// Unions by `node_id` with tombstone-precedence so the mesh converges to one
    /// roster (see `merge_roster_entries` for the full rule). Idempotent: re-merging
    /// the same roster is a no-op. Saves only when the merge changed something.
    async fn merge_roster(&self, incoming: &[AllowedPeer]) -> Result<()> {
        let existing = self.list_peers().await?;
        let merged = merge_roster_entries(&existing, incoming);
        if merged != existing {
            self.save_peers(&merged).await?;
        }
        Ok(())
    }
}

/// In-memory implementation of `AllowlistStorage` for testing.
///
/// Thread-safe, zero-I/O — suitable for integration tests that need
/// a real `AllowlistStorage` without touching the filesystem.
pub struct InMemoryAllowlist {
    peers: std::sync::RwLock<Vec<AllowedPeer>>,
}

impl std::fmt::Debug for InMemoryAllowlist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryAllowlist").finish()
    }
}

impl InMemoryAllowlist {
    /// Create a new empty in-memory allowlist.
    pub fn new() -> Self {
        Self {
            peers: std::sync::RwLock::new(Vec::new()),
        }
    }
}

impl Default for InMemoryAllowlist {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AllowlistStorage for InMemoryAllowlist {
    async fn list_peers(&self) -> Result<Vec<AllowedPeer>> {
        Ok(self.peers.read().unwrap().clone())
    }

    async fn save_peers(&self, peers: &[AllowedPeer]) -> Result<()> {
        *self.peers.write().unwrap() = peers.to_vec();
        Ok(())
    }
}

/// Filesystem implementation of `AllowlistStorage`.
///
/// Reads and writes `.sync/allowlist.json` within the vault directory.
/// Each call reads/writes the full file — the list is short enough that
/// in-memory caching is not needed.
#[derive(Debug)]
pub struct FileAllowlistStorage {
    path: PathBuf,
}

impl FileAllowlistStorage {
    /// Create storage pointing at `.sync/allowlist.json` within `vault_path`.
    pub fn new(vault_path: &Path) -> Self {
        Self {
            path: vault_path.join(".sync/allowlist.json"),
        }
    }
}

#[async_trait]
impl AllowlistStorage for FileAllowlistStorage {
    async fn list_peers(&self) -> Result<Vec<AllowedPeer>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let contents =
            fs::read_to_string(&self.path).map_err(|e| AllowlistError::Io(e.to_string()))?;

        serde_json::from_str(&contents).map_err(|_| AllowlistError::InvalidData)
    }

    async fn save_peers(&self, peers: &[AllowedPeer]) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| AllowlistError::Io(e.to_string()))?;
        }

        let contents =
            serde_json::to_string_pretty(peers).map_err(|_| AllowlistError::InvalidData)?;

        fs::write(&self.path, contents).map_err(|e| AllowlistError::Io(e.to_string()))
    }
}

/// Write the mesh roster into the local allowlist after a successful pair.
///
/// On the very first pair (empty allowlist) the device adds *itself* so the
/// responder's sync requests are accepted once gossip joins. Every mesh member
/// returned by the pairing exchange is then added under the placeholder name
/// "unknown"; the real device names self-heal once a gossip `AllowlistUpdate`
/// arrives from the mesh. Failures are logged, not fatal — a missing allowlist
/// entry degrades to "this peer can't sync yet", not a broken pairing.
pub async fn write_pair_allowlist<AL: AllowlistStorage>(
    allowlist: &AL,
    self_peer_id: PeerId,
    self_device_name: &str,
    mesh_members: &[PeerId],
) {
    // Bootstrap the allowlist on first pair: add self so the responder side's
    // sync requests are accepted once gossip joins.
    if matches!(allowlist.list_peers().await, Ok(peers) if peers.is_empty())
        && let Err(e) = allowlist.add_peer(self_peer_id, self_device_name).await
    {
        warn!("Failed to add self to allowlist on first pair: {}", e);
    }

    for member_id in mesh_members {
        let peer = AllowedPeer::new(*member_id, "unknown");
        if let Err(e) = allowlist.add_peer(peer.node_id, &peer.device_name).await {
            warn!(
                "Failed to add mesh member {} to allowlist: {}",
                member_id, e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn peer_a() -> PeerId {
        PeerId::generate()
    }

    fn peer_b() -> PeerId {
        PeerId::generate()
    }

    #[tokio::test]
    async fn test_list_peers_empty() {
        let storage = InMemoryAllowlist::new();
        let peers = storage.list_peers().await.unwrap();
        assert!(peers.is_empty());
    }

    #[tokio::test]
    async fn test_add_and_list_peer() {
        let storage = InMemoryAllowlist::new();
        let id = peer_a();

        storage.add_peer(id, "umbra").await.unwrap();

        let peers = storage.list_peers().await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].node_id, id);
        assert_eq!(peers[0].device_name, "umbra");
        assert!(peers[0].last_seen.is_none());
    }

    #[tokio::test]
    async fn test_add_peer_updates_existing() {
        let storage = InMemoryAllowlist::new();
        let id = peer_a();

        storage.add_peer(id, "old-name").await.unwrap();
        storage.add_peer(id, "new-name").await.unwrap();

        let peers = storage.list_peers().await.unwrap();
        assert_eq!(peers.len(), 1, "should not duplicate");
        assert_eq!(peers[0].device_name, "new-name");
    }

    #[tokio::test]
    async fn test_remove_peer() {
        let storage = InMemoryAllowlist::new();
        let a = peer_a();
        let b = peer_b();

        storage.add_peer(a, "device-a").await.unwrap();
        storage.add_peer(b, "device-b").await.unwrap();
        storage.remove_peer(&a).await.unwrap();

        // A revoked peer is no longer trusted...
        assert!(!storage.is_allowed(&a).await.unwrap());
        assert!(storage.is_allowed(&b).await.unwrap());

        // ...but stays in storage as a tombstone so the revocation can propagate.
        let peers = storage.list_peers().await.unwrap();
        assert_eq!(peers.len(), 2);
        let tombstone = peers.iter().find(|p| p.node_id == a).unwrap();
        assert!(tombstone.removed);
        assert!(tombstone.removed_at.is_some());
    }

    #[tokio::test]
    async fn test_remove_peer_unknown_is_noop() {
        let storage = InMemoryAllowlist::new();
        let unknown = peer_a();

        // Revoking a peer that was never added should not error or create a row.
        storage.remove_peer(&unknown).await.unwrap();

        let peers = storage.list_peers().await.unwrap();
        assert!(peers.is_empty());
    }

    #[tokio::test]
    async fn test_old_format_entry_loads_as_live() {
        // An allowlist.json written before tombstones existed has no `removed`
        // field. `#[serde(default)]` must load it as a LIVE (trusted) peer.
        let json = r#"[{
            "node_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "device_name": "legacy-device",
            "paired_at": 1700000000000,
            "last_seen": null
        }]"#;

        let peers: Vec<AllowedPeer> = serde_json::from_str(json).unwrap();
        assert_eq!(peers.len(), 1);
        assert!(
            !peers[0].removed,
            "missing `removed` field must default to live"
        );
        assert_eq!(peers[0].removed_at, None);

        let storage = InMemoryAllowlist::new();
        storage.save_peers(&peers).await.unwrap();
        assert!(
            storage.is_allowed(&peers[0].node_id).await.unwrap(),
            "a legacy entry must be trusted after load"
        );
    }

    #[tokio::test]
    async fn test_is_allowed() {
        let storage = InMemoryAllowlist::new();
        let a = peer_a();
        let b = peer_b();

        storage.add_peer(a, "device-a").await.unwrap();

        assert!(storage.is_allowed(&a).await.unwrap());
        assert!(!storage.is_allowed(&b).await.unwrap());
    }

    #[tokio::test]
    async fn test_update_last_seen() {
        let storage = InMemoryAllowlist::new();
        let id = peer_a();

        storage.add_peer(id, "umbra").await.unwrap();
        storage
            .update_last_seen(&id, 1_700_000_000_000)
            .await
            .unwrap();

        let peers = storage.list_peers().await.unwrap();
        assert_eq!(peers[0].last_seen, Some(1_700_000_000_000));
    }

    #[tokio::test]
    async fn test_update_last_seen_noop_for_unknown() {
        let storage = InMemoryAllowlist::new();
        let unknown = peer_a();

        // Should not error — just silently ignore unknown peers
        storage.update_last_seen(&unknown, 1_000).await.unwrap();

        let peers = storage.list_peers().await.unwrap();
        assert!(peers.is_empty());
    }

    // --- merge_roster (union with tombstone-precedence) ---

    fn live(id: PeerId, name: &str, paired_at: u64) -> AllowedPeer {
        AllowedPeer {
            node_id: id,
            device_name: name.into(),
            paired_at,
            last_seen: None,
            removed: false,
            removed_at: None,
        }
    }

    fn tombstone(id: PeerId, removed_at: u64) -> AllowedPeer {
        AllowedPeer {
            node_id: id,
            device_name: "gone".into(),
            paired_at: 1,
            last_seen: None,
            removed: true,
            removed_at: Some(removed_at),
        }
    }

    #[tokio::test]
    async fn test_merge_roster_adds_unknown_peer() {
        let storage = InMemoryAllowlist::new();
        let a = peer_a();
        let c = peer_b();
        storage.save_peers(&[live(a, "a", 100)]).await.unwrap();

        // A roster from a peer that knows C (which we don't) converges us to {A, C}.
        storage.merge_roster(&[live(c, "c", 200)]).await.unwrap();

        assert!(storage.is_allowed(&a).await.unwrap());
        assert!(storage.is_allowed(&c).await.unwrap());
    }

    #[tokio::test]
    async fn test_merge_roster_incoming_tombstone_revokes_live() {
        // Local has C live; an incoming roster carries C as a tombstone (someone
        // revoked C). The tombstone must win — C becomes untrusted.
        let storage = InMemoryAllowlist::new();
        let c = peer_a();
        storage.save_peers(&[live(c, "c", 100)]).await.unwrap();

        storage.merge_roster(&[tombstone(c, 500)]).await.unwrap();

        assert!(!storage.is_allowed(&c).await.unwrap());
        let peers = storage.list_peers().await.unwrap();
        assert_eq!(
            peers.len(),
            1,
            "tombstone replaces the live row, not appends"
        );
        assert!(peers[0].removed);
    }

    #[tokio::test]
    async fn test_merge_roster_stale_live_does_not_resurrect_tombstone() {
        // Local has C tombstoned (we revoked C). An incoming roster from a peer
        // that still has C live must NOT bring C back — removals win over re-adds.
        let storage = InMemoryAllowlist::new();
        let c = peer_a();
        storage.save_peers(&[tombstone(c, 500)]).await.unwrap();

        storage.merge_roster(&[live(c, "c", 100)]).await.unwrap();

        assert!(!storage.is_allowed(&c).await.unwrap());
        let peers = storage.list_peers().await.unwrap();
        assert!(
            peers[0].removed,
            "a stale live row must not resurrect a tombstone"
        );
    }

    #[tokio::test]
    async fn test_merge_roster_later_tombstone_wins() {
        // Two tombstones for the same peer: the later removed_at wins.
        let storage = InMemoryAllowlist::new();
        let c = peer_a();
        storage.save_peers(&[tombstone(c, 100)]).await.unwrap();

        storage.merge_roster(&[tombstone(c, 900)]).await.unwrap();

        let peers = storage.list_peers().await.unwrap();
        assert_eq!(peers[0].removed_at, Some(900));
    }

    #[tokio::test]
    async fn test_merge_roster_live_vs_live_tiebreak() {
        // Same live peer on both sides: device_name<-incoming, paired_at<-min,
        // last_seen<-max (the S1 live-vs-live rule).
        let storage = InMemoryAllowlist::new();
        let c = peer_a();
        let mut local = live(c, "old-name", 200);
        local.last_seen = Some(50);
        storage.save_peers(&[local]).await.unwrap();

        let mut incoming = live(c, "new-name", 100);
        incoming.last_seen = Some(80);
        storage.merge_roster(&[incoming]).await.unwrap();

        let peers = storage.list_peers().await.unwrap();
        assert_eq!(peers[0].device_name, "new-name", "name takes incoming");
        assert_eq!(peers[0].paired_at, 100, "paired_at takes the earliest");
        assert_eq!(
            peers[0].last_seen,
            Some(80),
            "last_seen takes the most recent"
        );
    }

    #[tokio::test]
    async fn test_merge_roster_is_idempotent() {
        // Re-merging an identical roster must not change anything.
        let storage = InMemoryAllowlist::new();
        let a = peer_a();
        let c = peer_b();
        let roster = vec![live(a, "a", 100), tombstone(c, 500)];
        storage.save_peers(&roster).await.unwrap();

        storage.merge_roster(&roster).await.unwrap();
        storage.merge_roster(&roster).await.unwrap();

        let peers = storage.list_peers().await.unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers, roster);
    }

    #[tokio::test]
    async fn test_merge_roster_back_compat_entry() {
        // An old-format entry (no `removed` field) deserializes as live and merges
        // as a live peer — a tombstone for it would still win, but on its own it's
        // trusted.
        let json = r#"[{
            "node_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "device_name": "legacy",
            "paired_at": 1,
            "last_seen": null
        }]"#;
        let incoming: Vec<AllowedPeer> = serde_json::from_str(json).unwrap();

        let storage = InMemoryAllowlist::new();
        storage.merge_roster(&incoming).await.unwrap();

        assert!(storage.is_allowed(&incoming[0].node_id).await.unwrap());
    }

    // --- FileAllowlistStorage (file-backed .sync/allowlist.json) ---

    fn make_storage(dir: &TempDir) -> FileAllowlistStorage {
        FileAllowlistStorage::new(dir.path())
    }

    #[tokio::test]
    async fn test_list_empty_when_no_file() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir);

        let peers = storage.list_peers().await.unwrap();
        assert!(peers.is_empty());
    }

    #[tokio::test]
    async fn test_add_and_persist_peer() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir);
        let id = PeerId::generate();

        storage.add_peer(id, "umbra").await.unwrap();

        // File should exist
        let path = dir.path().join(".sync/allowlist.json");
        assert!(path.exists());

        // Reload in a new instance — should find the peer
        let storage2 = make_storage(&dir);
        let peers = storage2.list_peers().await.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].node_id, id);
        assert_eq!(peers[0].device_name, "umbra");
    }

    #[tokio::test]
    async fn test_remove_peer_persists() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir);
        let a = PeerId::generate();
        let b = PeerId::generate();

        storage.add_peer(a, "device-a").await.unwrap();
        storage.add_peer(b, "device-b").await.unwrap();
        storage.remove_peer(&a).await.unwrap();

        // Reload from disk: the revocation must survive, with A no longer trusted
        // but kept as a tombstone (so the removal can propagate across the mesh).
        let storage2 = make_storage(&dir);
        assert!(!storage2.is_allowed(&a).await.unwrap());
        assert!(storage2.is_allowed(&b).await.unwrap());

        let peers = storage2.list_peers().await.unwrap();
        assert_eq!(peers.len(), 2);
        let tombstone = peers.iter().find(|p| p.node_id == a).unwrap();
        assert!(tombstone.removed);
        assert!(tombstone.removed_at.is_some());
    }

    #[tokio::test]
    async fn test_is_allowed_checks_file() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir);
        let id = PeerId::generate();
        let other = PeerId::generate();

        storage.add_peer(id, "my-device").await.unwrap();

        let storage2 = make_storage(&dir);
        assert!(storage2.is_allowed(&id).await.unwrap());
        assert!(!storage2.is_allowed(&other).await.unwrap());
    }

    #[tokio::test]
    async fn test_update_last_seen_persists() {
        let dir = TempDir::new().unwrap();
        let storage = make_storage(&dir);
        let id = PeerId::generate();

        storage.add_peer(id, "umbra").await.unwrap();
        storage.update_last_seen(&id, 9_999_999).await.unwrap();

        let storage2 = make_storage(&dir);
        let peers = storage2.list_peers().await.unwrap();
        assert_eq!(peers[0].last_seen, Some(9_999_999));
    }

    #[tokio::test]
    async fn test_creates_sync_dir_if_missing() {
        let dir = TempDir::new().unwrap();
        // Don't pre-create .sync dir
        let storage = make_storage(&dir);
        let id = PeerId::generate();

        storage.add_peer(id, "device").await.unwrap();

        assert!(dir.path().join(".sync").is_dir());
    }

    // --- write_pair_allowlist (post-pairing roster bootstrap) ---

    fn peer(byte: u8) -> PeerId {
        PeerId::from_secret_bytes([byte; 32])
    }

    /// First pair into an empty allowlist bootstraps self so the responder's
    /// sync requests are accepted, then adds the mesh member.
    #[tokio::test]
    async fn first_pair_adds_self_and_mesh_member() {
        let allowlist = InMemoryAllowlist::new();
        let self_id = peer(1);
        let member = peer(2);

        write_pair_allowlist(&allowlist, self_id, "this-device", &[member]).await;

        let peers = allowlist.list_peers().await.unwrap();
        assert_eq!(peers.len(), 2, "self + one mesh member");

        let self_entry = peers
            .iter()
            .find(|p| p.node_id == self_id)
            .expect("self should be in the allowlist after first pair");
        assert_eq!(self_entry.device_name, "this-device");

        assert!(
            peers.iter().any(|p| p.node_id == member),
            "mesh member should be in the allowlist"
        );
    }

    /// When the allowlist already has entries, pairing does NOT re-add self —
    /// the self-bootstrap is a first-pair-only step — but still adds new members.
    #[tokio::test]
    async fn re_pair_with_nonempty_allowlist_skips_self_bootstrap() {
        let allowlist = InMemoryAllowlist::new();
        let self_id = peer(1);
        let existing_member = peer(2);
        let new_member = peer(3);

        // Pre-seed a member so the allowlist is non-empty going in.
        allowlist
            .add_peer(existing_member, "existing")
            .await
            .unwrap();

        write_pair_allowlist(&allowlist, self_id, "this-device", &[new_member]).await;

        let peers = allowlist.list_peers().await.unwrap();
        assert!(
            !peers.iter().any(|p| p.node_id == self_id),
            "self is only bootstrapped on the first (empty) pair, not re-pairs"
        );
        assert!(peers.iter().any(|p| p.node_id == existing_member));
        assert!(peers.iter().any(|p| p.node_id == new_member));
        assert_eq!(peers.len(), 2, "existing member + new member, no self");
    }

    /// Re-running the same pair is idempotent: members are keyed by node_id, so
    /// a repeated write updates names in place rather than duplicating entries.
    #[tokio::test]
    async fn re_pair_is_idempotent() {
        let allowlist = InMemoryAllowlist::new();
        let self_id = peer(1);
        let member = peer(2);

        write_pair_allowlist(&allowlist, self_id, "this-device", &[member]).await;
        write_pair_allowlist(&allowlist, self_id, "this-device", &[member]).await;

        let peers = allowlist.list_peers().await.unwrap();
        assert_eq!(
            peers.len(),
            2,
            "re-running the pair must not duplicate self or the mesh member"
        );
    }
}
