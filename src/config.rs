//! Daemon config + relay-hint persistence.
//!
//! - **`IdentityKey`** (`.sync/daemon.key`, in [`crate::identity`]): Ed25519 secret key for the daemon's network identity
//! - **`DaemonConfig`** (`.sync/daemon.toml`): Daemon config including the derived PeerId
//!
//! This is the generic config substrate for any p2p-core consumer; the daemon
//! re-exports it via `sync_daemon::persistence` for backward compatibility. The
//! on-disk `.sync/daemon.toml` format is owned here.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing::{info, warn};

use crate::IdentityKey;
use crate::PeerId;

const DAEMON_KEY_FILE: &str = ".sync/daemon.key";
const DAEMON_CONFIG_FILE: &str = ".sync/daemon.toml";

/// A learned relay URL for a specific peer — the reconnect supervisor's
/// in-memory working-entry type.
///
/// Hints are keyed by the peer's `EndpointId` (64-char hex). The relay URL is
/// stored as-is and parsed at dial time so invalid entries can be skipped
/// gracefully rather than failing.
///
/// **Runtime state, not a persisted store.** The supervisor's working set
/// (`Daemon::peer_relays`) is seeded at startup from the
/// `allowlist × known_public_relays` cross-product — `known_public_relays` is
/// the sole durable networking store. A restart resetting this working set's
/// freshness is fine: the cross-product re-seeds it, and learn-on-exchange
/// re-stamps freshness the instant a peer reconnects. `PeerRelay` still derives
/// `Serialize`/`Deserialize` only so an old `daemon.toml` carrying a retired
/// `[[peer_relays]]` block can be parsed-and-discarded on load (see
/// `DaemonConfigRaw`).
///
/// ## Freshness fields
///
/// The supervisor uses `last_success_ms` / `failure_count` / `last_attempt_ms`
/// to back off and EVICT a hint that keeps failing — a stale coffeeshop relay
/// would otherwise be re-dialed forever. Wall-clock milliseconds (not monotonic
/// `Instant`) so seeded test values land on the same clock the supervisor reads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerRelay {
    /// The peer's iroh `EndpointId` as a 64-char lowercase hex string.
    pub endpoint_id: String,
    /// The peer's advertised relay URL (e.g. `http://umbra.computer:3340/`).
    pub relay_url: String,
    /// Wall-clock ms of the last successful reach (exchange or fresh pair).
    /// `None` = never reached.
    #[serde(default)]
    pub last_success_ms: Option<u64>,
    /// Consecutive failed reconnect attempts since the last success. Reset to
    /// `0` on success; drives the per-hint exponential backoff.
    #[serde(default)]
    pub failure_count: u32,
    /// Wall-clock ms of the last reconnect ATTEMPT (re-add + re-dial), for
    /// backoff windowing. `None` = never attempted (so the hint is due now).
    #[serde(default)]
    pub last_attempt_ms: Option<u64>,
}

impl PeerRelay {
    /// Construct a fresh hint with no recorded attempt or success yet.
    ///
    /// Use this instead of a struct literal so the freshness fields stay an
    /// implementation detail of one place.
    pub fn new(endpoint_id: String, relay_url: String) -> Self {
        Self {
            endpoint_id,
            relay_url,
            last_success_ms: None,
            failure_count: 0,
            last_attempt_ms: None,
        }
    }
}

/// Daemon-specific configuration persisted in `.sync/daemon.toml`.
///
/// Contains the daemon's PeerId (derived from the identity key). Separate from
/// vault-level metadata (VaultId in `metadata.toml`).
///
/// On upgrade from old u64 PeerIds, the old value is saved as `legacy_peer_id`
/// for reference. New peer_id is the 64-char hex ed25519 pubkey.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Daemon's network identity (64-char hex ed25519 pubkey)
    pub peer_id: PeerId,
    /// The old u64-based PeerId from before the ed25519 migration, if any.
    /// Stored for reference only — orphaned Loro version-vector entries are harmless.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legacy_peer_id: Option<String>,
    /// URL of the embedded relay server, written on startup and cleared on shutdown.
    ///
    /// Plugin peers read this to discover the daemon's relay and route through it.
    /// Absent when the relay is not running (relay_listen was not set).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    /// Human-readable name for this mesh, broadcast via mDNS.
    ///
    /// Defaults to `None`, which causes the daemon to fall back to the vault
    /// directory name when advertising. Set this to override the displayed name
    /// on peer devices during discovery and pairing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mesh_name: Option<String>,
    /// The set of PUBLIC relay URLs this node homes on.
    ///
    /// This is the ONLY persisted networking store: it populates the endpoint's
    /// `RelayMap` at construction (this node's home + failover + cold rendezvous)
    /// and, crossed with the allowlist, seeds peer-reaching at startup. A laptop
    /// learns the set at pairing (the paired server's public relay) and expands it
    /// via gossip; a server's set is its own public relay so it homes on itself.
    ///
    /// Only off-LAN-reachable URLs belong here (gated by
    /// [`crate::relay_is_offlan_reachable`]): a private
    /// LAN-IP relay must never be homed on off-LAN.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_public_relays: Vec<String>,
}

impl DaemonConfig {
    /// Load or generate daemon config, deriving PeerId from the identity key.
    ///
    /// Returns `(config, identity_key)` so the caller can access the raw secret
    /// key bytes needed to initialize the iroh `SyncNode`.
    ///
    /// `identity_key_path` — if provided, loads a custom key file instead of the
    /// default `.sync/daemon.key`. This replaces the old `--peer-id` flag.
    pub async fn load_or_generate(
        data_dir: &Path,
        identity_key_path: Option<&Path>,
    ) -> Result<(Self, IdentityKey)> {
        let config_path = data_dir.join(DAEMON_CONFIG_FILE);
        let key_path = data_dir.join(DAEMON_KEY_FILE);

        // Detect legacy upgrade: daemon.toml exists but daemon.key doesn't.
        // This means the daemon was previously running with the old u64 PeerId format.
        let is_legacy_upgrade =
            config_path.exists() && !key_path.exists() && identity_key_path.is_none();

        // Load the identity key (custom path, or generate/load default)
        let identity_key = match identity_key_path {
            Some(path) => {
                let key = IdentityKey::load_from(path)?;
                info!(peer_id = %key.peer_id(), key_path = %path.display(), "Loaded custom identity key");
                key
            }
            None => IdentityKey::load_or_generate(data_dir).await?,
        };

        let new_peer_id = identity_key.peer_id();

        let config = if config_path.exists() {
            let contents = fs::read_to_string(&config_path)?;
            // Parse with optional incarnation field for migration from older config files
            let mut existing: DaemonConfigRaw = toml::from_str(&contents)
                .map_err(|e| anyhow::anyhow!("Corrupt daemon.toml: {}", e))?;

            if is_legacy_upgrade {
                // Read the raw peer_id string from TOML to capture the old 16-char value
                // before PeerId::from_str converts it to 64-char representation.
                let raw: toml::Value = toml::from_str(&contents)
                    .map_err(|e| anyhow::anyhow!("Corrupt daemon.toml: {}", e))?;
                let old_peer_id_str = raw
                    .get("peer_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                warn!(
                    old_peer_id = %old_peer_id_str,
                    new_peer_id = %new_peer_id,
                    "Upgrading from legacy u64 PeerId to ed25519 PeerId — clearing known_peers.json"
                );
                existing.legacy_peer_id = Some(old_peer_id_str);
                existing.peer_id = new_peer_id;
                clear_known_peers(data_dir);
            } else if existing.peer_id != new_peer_id {
                // Key file was swapped (e.g., --identity-key flag)
                info!(old = %existing.peer_id, new = %new_peer_id, "Identity key changed, updating PeerId");
                existing.peer_id = new_peer_id;
            }

            let config = DaemonConfig {
                peer_id: existing.peer_id,
                legacy_peer_id: existing.legacy_peer_id,
                // Relay URL is runtime state — always start with None and let the
                // daemon write it after the relay starts. A stale URL left from a
                // previous (crashed) run is meaningless after restart.
                relay_url: None,
                mesh_name: existing.mesh_name,
                // The public-relay set is durable — it survives restarts so the
                // laptop can rebuild its RelayMap and reach off-LAN peers.
                known_public_relays: existing.known_public_relays,
            };
            info!(peer_id = %config.peer_id, "Loaded daemon config");
            config
        } else {
            let config = DaemonConfig {
                peer_id: new_peer_id,
                legacy_peer_id: None,
                relay_url: None,
                mesh_name: None,
                known_public_relays: vec![],
            };
            info!(peer_id = %config.peer_id, "Generated new daemon config");
            config
        };

        // Always save (creates file on first run, applies migrations)
        config.save(data_dir)?;

        Ok((config, identity_key))
    }

    /// Write the relay URL to daemon.toml.
    ///
    /// Called after the embedded relay starts so plugin peers can discover it.
    /// Pass `None` to clear (written on daemon shutdown).
    pub fn set_relay_url(&mut self, url: Option<String>, vault_path: &Path) -> Result<()> {
        self.relay_url = url;
        self.save(vault_path)
    }

    /// Add a PUBLIC relay URL to the persisted `known_public_relays` set (in memory).
    ///
    /// This is the cold-bootstrap writer — called when pairing hands over a
    /// server's public relay. The URL must be off-LAN-reachable: a private
    /// LAN-IP relay is rejected outright (`relay_is_offlan_reachable` guard) so a
    /// laptop can never home on a relay that's useless once it leaves that LAN.
    ///
    /// **Dedup:** a URL already present is a no-op, so re-pairing or re-learning
    /// the same server doesn't grow the set.
    ///
    /// Mutates the in-memory config only; the caller persists (via
    /// [`persist_config_change`], which applies the `relay_url` clobber-guard).
    pub fn add_known_public_relay(&mut self, url: &str) {
        if !crate::relay_is_offlan_reachable(url) {
            return;
        }
        if self.known_public_relays.iter().any(|u| u == url) {
            return;
        }
        self.known_public_relays.push(url.to_string());
    }

    /// Save the current config to `.sync/daemon.toml`.
    pub fn save(&self, vault_path: &Path) -> Result<()> {
        let config_path = vault_path.join(DAEMON_CONFIG_FILE);
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let contents = toml::to_string(self)?;
        fs::write(&config_path, contents)?;
        Ok(())
    }
}

/// Load the on-disk config, mutate it, and persist — with the `relay_url`
/// clobber-guard always applied.
///
/// The daemon does not hold a long-lived `DaemonConfig` in memory, so every
/// peer-relay write is a load → mutate → save round-trip against `daemon.toml`.
/// All such writes share one hazard: [`DaemonConfig::load_or_generate`] returns
/// `relay_url = None` (the daemon's own advertised relay is runtime state, not
/// persisted), so a naive save would DROP the advertised URL out of the file.
/// This helper re-stamps `relay_url` before running `mutate`, guaranteeing no
/// caller can forget the guard — which is exactly the bug `persist_adopted_relay`
/// shipped with (it omitted the re-stamp and clobbered the URL on pairing).
///
/// `relay_url` is the daemon's currently-advertised relay URL to preserve
/// (`self.relay_url.clone()` for an active daemon; `None` for flows with no
/// running relay, e.g. CLI pairing).
///
/// `mutate` performs the in-memory change (e.g.
/// [`DaemonConfig::add_known_public_relay`]). A single `save` follows, so the
/// persisted file reflects the mutation plus the preserved `relay_url`.
pub async fn persist_config_change(
    vault_path: &Path,
    relay_url: Option<String>,
    mutate: impl FnOnce(&mut DaemonConfig),
) -> Result<()> {
    let (mut config, _identity) = DaemonConfig::load_or_generate(vault_path, None).await?;
    // Clobber-guard: load_or_generate discarded the daemon's own relay_url as
    // runtime state — restore it so the save below doesn't drop it from disk.
    config.relay_url = relay_url;
    mutate(&mut config);
    config.save(vault_path)
}

/// Raw deserialization type for migration — accepts optional `incarnation`,
/// `legacy_peer_id`, `relay_url`, `mesh_name`, `peer_relays`, and
/// `known_public_relays` fields from older `daemon.toml` files without failing.
#[derive(Deserialize)]
struct DaemonConfigRaw {
    peer_id: PeerId,
    legacy_peer_id: Option<String>,
    /// Parsed from disk but intentionally discarded on load — relay URL is runtime state
    /// that gets re-written after the relay starts. A stale URL from a crashed run is meaningless.
    #[allow(dead_code)]
    relay_url: Option<String>,
    /// Parsed from disk but discarded — incarnation was removed with the SWIM protocol.
    #[allow(dead_code)]
    incarnation: Option<u64>,
    mesh_name: Option<String>,
    /// Parsed from disk but discarded — the persisted per-peer hint store was
    /// retired once `known_public_relays` became the sole durable networking
    /// store (the supervisor's working set is now seeded from the
    /// `allowlist × known_public_relays` cross-product, not from disk). Kept here
    /// purely as a tolerant-load shim so an old `daemon.toml` carrying
    /// `[[peer_relays]]` blocks still deserializes instead of erroring.
    #[serde(default)]
    #[allow(dead_code)]
    peer_relays: Vec<PeerRelay>,
    /// Preserved on load — the public-relay set survives restarts so the laptop
    /// can rebuild its RelayMap before re-pairing.
    #[serde(default)]
    known_public_relays: Vec<String>,
}

/// Clear `known_peers.json` after a PeerId migration.
///
/// Peer entries are keyed by old PeerIds that no longer match after migration.
/// Clearing is simpler than re-keying.
fn clear_known_peers(vault_path: &Path) {
    let peers_path = vault_path.join(".sync/known_peers.json");
    if peers_path.exists() {
        if let Err(e) = fs::remove_file(&peers_path) {
            warn!("Failed to clear known_peers.json during migration: {}", e);
        } else {
            info!("Cleared known_peers.json after PeerId migration");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ==================== DaemonConfig tests ====================

    #[tokio::test]
    async fn test_daemon_config_generates_new() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        let (config, _key) = DaemonConfig::load_or_generate(vault_path, None)
            .await
            .unwrap();

        // Should have a valid PeerId (64-char hex, non-zero as_u64)
        assert_eq!(config.peer_id.to_string().len(), 64);
        assert_ne!(config.peer_id.as_u64(), 0);
        assert!(config.legacy_peer_id.is_none());

        // Both key file and config file should exist
        assert!(vault_path.join(".sync/daemon.key").exists());
        assert!(vault_path.join(".sync/daemon.toml").exists());
    }

    #[tokio::test]
    async fn test_daemon_config_persists_across_restarts() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        let (config1, _) = DaemonConfig::load_or_generate(vault_path, None)
            .await
            .unwrap();

        // Simulate restart — should load same PeerId from key file
        let (config2, _) = DaemonConfig::load_or_generate(vault_path, None)
            .await
            .unwrap();

        assert_eq!(config1.peer_id, config2.peer_id);
    }

    #[tokio::test]
    async fn test_daemon_config_identity_key_override() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        // First start with default key
        let (config1, _) = DaemonConfig::load_or_generate(vault_path, None)
            .await
            .unwrap();

        // Generate an alternate key in a separate location
        let alt_dir = TempDir::new().unwrap();
        let alt_key = IdentityKey::load_or_generate(alt_dir.path()).await.unwrap();
        let alt_peer_id = alt_key.peer_id();
        assert_ne!(alt_peer_id, config1.peer_id);

        // Start with alternate key — should update PeerId in config
        let alt_key_path = alt_dir.path().join(".sync/daemon.key");
        let (config2, _) = DaemonConfig::load_or_generate(vault_path, Some(&alt_key_path))
            .await
            .unwrap();
        assert_eq!(config2.peer_id, alt_peer_id);

        // After using the alternate key, the config reflects the alternate PeerId.
        // Default restart now uses the default key again (config tracks last used PeerId).
        let (config3, _) = DaemonConfig::load_or_generate(vault_path, None)
            .await
            .unwrap();
        assert_eq!(config3.peer_id, config1.peer_id);
    }

    #[tokio::test]
    async fn test_daemon_config_migrates_legacy_peer_id() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        // Simulate an old install: daemon.toml exists but daemon.key does not
        let sync_dir = vault_path.join(".sync");
        fs::create_dir_all(&sync_dir).unwrap();
        let old_config = r#"peer_id = "a1b2c3d4e5f67890"
incarnation = 3
"#;
        fs::write(sync_dir.join("daemon.toml"), old_config).unwrap();

        // Also create a fake known_peers.json to verify it gets cleared
        fs::write(sync_dir.join("known_peers.json"), r#"{"peers":[]}"#).unwrap();

        // Load with new code — should generate a new ed25519 key and migrate
        let (config, _) = DaemonConfig::load_or_generate(vault_path, None)
            .await
            .unwrap();

        // New PeerId should be 64-char hex (ed25519)
        assert_eq!(config.peer_id.to_string().len(), 64);

        // Legacy peer_id should be recorded (the raw 16-char string from the old config)
        assert_eq!(config.legacy_peer_id.as_deref(), Some("a1b2c3d4e5f67890"));

        // known_peers.json should be cleared
        assert!(!sync_dir.join("known_peers.json").exists());

        // daemon.key should now exist
        assert!(sync_dir.join("daemon.key").exists());
    }

    #[tokio::test]
    async fn test_daemon_config_relay_url_persists() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        let (mut config, _) = DaemonConfig::load_or_generate(vault_path, None)
            .await
            .unwrap();

        // Write relay URL
        config
            .set_relay_url(Some("http://127.0.0.1:3340/".into()), vault_path)
            .unwrap();

        // Reload and verify the URL is stored in the file
        let contents = fs::read_to_string(vault_path.join(".sync/daemon.toml")).unwrap();
        assert!(
            contents.contains("relay_url"),
            "relay_url should be in daemon.toml"
        );
        assert!(contents.contains("3340"), "relay URL should contain port");

        // Clear the URL
        config.set_relay_url(None, vault_path).unwrap();

        let contents = fs::read_to_string(vault_path.join(".sync/daemon.toml")).unwrap();
        assert!(
            !contents.contains("relay_url"),
            "relay_url should be absent after clearing"
        );
    }

    #[tokio::test]
    async fn test_daemon_config_loads_without_relay_url() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        // Simulate an older daemon.toml without relay_url
        let sync_dir = vault_path.join(".sync");
        fs::create_dir_all(&sync_dir).unwrap();

        let key = IdentityKey::load_or_generate(vault_path).await.unwrap();
        let peer_id = key.peer_id();
        fs::write(
            sync_dir.join("daemon.toml"),
            format!("peer_id = \"{peer_id}\"\n"),
        )
        .unwrap();

        // Should load without error — relay_url field is optional
        let (config, _) = DaemonConfig::load_or_generate(vault_path, None)
            .await
            .unwrap();
        assert!(config.relay_url.is_none());
    }

    #[tokio::test]
    async fn test_daemon_config_ignores_incarnation_field() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        // Write an old-style daemon.toml with incarnation field and a pre-existing key
        let sync_dir = vault_path.join(".sync");
        fs::create_dir_all(&sync_dir).unwrap();

        // Generate a key first so this isn't treated as a legacy upgrade
        let key = IdentityKey::load_or_generate(vault_path).await.unwrap();
        let peer_id = key.peer_id();

        let config_path = sync_dir.join("daemon.toml");
        fs::write(
            &config_path,
            format!("peer_id = \"{peer_id}\"\nincarnation = 5\n"),
        )
        .unwrap();

        // Should load without error, ignoring incarnation
        let (config, _) = DaemonConfig::load_or_generate(vault_path, None)
            .await
            .unwrap();
        assert_eq!(config.peer_id, peer_id);

        // Saved file should no longer have incarnation field
        let contents = fs::read_to_string(&config_path).unwrap();
        assert!(!contents.contains("incarnation"));
    }

    // ==================== peer_relays tolerant-load test ====================

    /// An existing-mesh `daemon.toml` carrying a retired `[[peer_relays]]` block
    /// still loads cleanly after the persisted `peer_relays` field was dropped.
    ///
    /// The supervisor's working set is now seeded from the
    /// `allowlist × known_public_relays` cross-product, so the per-peer hint
    /// store no longer persists — but a config written by a pre-upgrade daemon
    /// must not error on load (the `peer_relays` key is parsed-and-discarded via
    /// `DaemonConfigRaw`, since `DaemonConfigRaw` does not `deny_unknown_fields`).
    /// A botched load here would strand an upgrading machine.
    #[tokio::test]
    async fn old_config_with_peer_relays_loads_without_error() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        let sync_dir = vault_path.join(".sync");
        fs::create_dir_all(&sync_dir).unwrap();

        // A daemon.toml written by the previous daemon: a full `[[peer_relays]]`
        // entry (endpoint_id + relay_url + freshness fields) plus an already-
        // populated `known_public_relays`. The peer_relays block is exactly what
        // an existing paired mesh has on disk at upgrade time.
        let key = IdentityKey::load_or_generate(vault_path).await.unwrap();
        let peer_id = key.peer_id();
        let peer_hex = "a".repeat(64);
        fs::write(
            sync_dir.join("daemon.toml"),
            format!(
                "peer_id = \"{peer_id}\"\n\
                 known_public_relays = [\"https://umbra.computer/\"]\n\n\
                 [[peer_relays]]\n\
                 endpoint_id = \"{peer_hex}\"\n\
                 relay_url = \"http://umbra.computer:3340/\"\n\
                 last_success_ms = 1234\n\
                 failure_count = 3\n\
                 last_attempt_ms = 5678\n"
            ),
        )
        .unwrap();

        // Loads without error — the stale per-peer block is ignored, and the
        // durable public-relay set survives.
        let (config, _) = DaemonConfig::load_or_generate(vault_path, None)
            .await
            .unwrap();
        assert_eq!(config.peer_id, peer_id);
        assert_eq!(
            config.known_public_relays,
            vec!["https://umbra.computer/".to_string()],
            "the durable public-relay set must survive a load that ignores peer_relays"
        );

        // The save that load_or_generate runs no longer writes the retired field.
        let contents = fs::read_to_string(sync_dir.join("daemon.toml")).unwrap();
        assert!(
            !contents.contains("peer_relays"),
            "the resaved config must not re-emit the retired peer_relays field; \
             daemon.toml was:\n{contents}"
        );
    }

    // ==================== known_public_relays tests ====================

    /// The public-relay set round-trips through save/load and dedups: the same
    /// URL added twice yields a single entry, and both distinct URLs survive a
    /// restart.
    #[tokio::test]
    async fn known_public_relays_round_trip() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        let (mut config, _) = DaemonConfig::load_or_generate(vault_path, None)
            .await
            .unwrap();

        config.add_known_public_relay("https://umbra.computer/");
        config.add_known_public_relay("https://relay.example.com/");
        // Duplicate — must not grow the set.
        config.add_known_public_relay("https://umbra.computer/");
        config.save(vault_path).unwrap();

        let (loaded, _) = DaemonConfig::load_or_generate(vault_path, None)
            .await
            .unwrap();

        assert_eq!(
            loaded.known_public_relays.len(),
            2,
            "two distinct public relays, deduped; set was {:?}",
            loaded.known_public_relays
        );
        assert!(
            loaded
                .known_public_relays
                .contains(&"https://umbra.computer/".to_string())
        );
        assert!(
            loaded
                .known_public_relays
                .contains(&"https://relay.example.com/".to_string())
        );
    }

    /// An old daemon.toml without `known_public_relays` loads fine — the field
    /// defaults to empty (the same migration story as `peer_relays`).
    #[tokio::test]
    async fn known_public_relays_migration_from_old_config() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        let sync_dir = vault_path.join(".sync");
        fs::create_dir_all(&sync_dir).unwrap();

        // A daemon.toml that predates the known_public_relays field.
        let key = IdentityKey::load_or_generate(vault_path).await.unwrap();
        let peer_id = key.peer_id();
        fs::write(
            sync_dir.join("daemon.toml"),
            format!("peer_id = \"{peer_id}\"\n"),
        )
        .unwrap();

        let (config, _) = DaemonConfig::load_or_generate(vault_path, None)
            .await
            .unwrap();
        assert!(
            config.known_public_relays.is_empty(),
            "known_public_relays should be empty when absent from the file"
        );
    }

    /// A private LAN-IP relay is NEVER added to the public set — homing a laptop
    /// on such a relay would strand it the moment it leaves that LAN.
    #[tokio::test]
    async fn add_known_public_relay_rejects_private_lan_ip() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        let (mut config, _) = DaemonConfig::load_or_generate(vault_path, None)
            .await
            .unwrap();

        config.add_known_public_relay("http://192.168.68.52:3340/");
        assert!(
            config.known_public_relays.is_empty(),
            "a private LAN-IP relay must be rejected by the off-LAN-reachable guard"
        );

        // A public/domain relay alongside it is still accepted.
        config.add_known_public_relay("https://umbra.computer/");
        assert_eq!(config.known_public_relays.len(), 1);
        assert_eq!(config.known_public_relays[0], "https://umbra.computer/");
    }

    /// `relay_url` (this node's own relay) is discarded on load — runtime state
    /// that gets re-written after the relay starts, never preserved across loads.
    #[tokio::test]
    async fn test_relay_url_still_discarded_on_load() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        let (mut config, _) = DaemonConfig::load_or_generate(vault_path, None)
            .await
            .unwrap();

        // Simulate a relay starting and writing its URL to daemon.toml.
        config
            .set_relay_url(Some("http://127.0.0.1:3340/".into()), vault_path)
            .unwrap();

        // The file should contain the relay_url.
        let contents = fs::read_to_string(vault_path.join(".sync/daemon.toml")).unwrap();
        assert!(
            contents.contains("relay_url"),
            "relay_url should be written"
        );

        // Reload — relay_url must come back as None (runtime state, not preserved).
        let (reloaded, _) = DaemonConfig::load_or_generate(vault_path, None)
            .await
            .unwrap();
        assert!(
            reloaded.relay_url.is_none(),
            "relay_url must be discarded on load (runtime state)"
        );
    }

    // ==================== persist_config_change tests ====================

    /// The clobber-guard at the heart of `persist_config_change`: a config
    /// mutation must persist AND keep the daemon's advertised `relay_url` in
    /// `daemon.toml`. Without the guard, `load_or_generate`'s discard of
    /// `relay_url` would silently drop the advertised URL on every persisted
    /// write. Exercised here via the public-relay-set write (the surviving
    /// `persist_config_change` caller after the per-peer hint store was retired).
    #[tokio::test]
    async fn test_persist_config_change_preserves_relay_url_and_mutation() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        // Seed the daemon's identity (so subsequent loads are stable).
        let _ = DaemonConfig::load_or_generate(vault_path, None)
            .await
            .unwrap();

        // Persist a public-relay-set write while the daemon is advertising its
        // own relay URL.
        persist_config_change(
            vault_path,
            Some("http://umbra.computer:3340/".to_string()),
            |config| config.add_known_public_relay("https://relay.example.com/"),
        )
        .await
        .unwrap();

        // The advertised relay_url must be written to disk alongside the mutation.
        let contents = fs::read_to_string(vault_path.join(".sync/daemon.toml")).unwrap();
        assert!(
            contents.contains("relay_url = \"http://umbra.computer:3340/\""),
            "the advertised relay_url must survive a config write, not be clobbered"
        );

        // Re-read through the config layer: the mutation persisted. (relay_url
        // itself is runtime state and is intentionally discarded on load — its
        // presence ON DISK above is what proves the guard worked.)
        let (reloaded, _) = DaemonConfig::load_or_generate(vault_path, None)
            .await
            .unwrap();
        assert_eq!(
            reloaded.known_public_relays,
            vec!["https://relay.example.com/".to_string()]
        );
    }

    /// Passing `relay_url = None` (a flow with no running relay, e.g. CLI
    /// pairing) persists the mutation and writes no top-level relay_url — the
    /// helper does not invent one. This is the byte-identical behavior for
    /// relay-less flows.
    #[tokio::test]
    async fn test_persist_config_change_no_relay_url() {
        let temp_dir = TempDir::new().unwrap();
        let vault_path = temp_dir.path();

        let _ = DaemonConfig::load_or_generate(vault_path, None)
            .await
            .unwrap();

        persist_config_change(vault_path, None, |config| {
            config.add_known_public_relay("https://relay.example.com/")
        })
        .await
        .unwrap();

        let contents = fs::read_to_string(vault_path.join(".sync/daemon.toml")).unwrap();
        let parsed: toml::Value = toml::from_str(&contents).unwrap();
        assert!(
            parsed.get("relay_url").is_none(),
            "no top-level relay_url should be written when the daemon has none to advertise"
        );

        let (reloaded, _) = DaemonConfig::load_or_generate(vault_path, None)
            .await
            .unwrap();
        assert_eq!(
            reloaded.known_public_relays,
            vec!["https://relay.example.com/".to_string()]
        );
    }
}
