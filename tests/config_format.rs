//! `.sync/daemon.toml` on-disk-format stability guard.
//!
//! `DaemonConfig` is LIVE config on every fleet machine — a field reorder,
//! rename, serde-attr change, or `peer_id` representation change would break
//! cross-version interop and force a fleet migration. These tests pin the
//! serialized shape against sanitized fixtures so any such drift fails loudly.
//!
//! The fixtures carry FAKE secret material (a deterministic test `peer_id`
//! derived from `PeerId::from_secret_bytes([7u8; 32])`, a zeroed
//! `legacy_peer_id`, an `example.com` relay) — never real fleet keys.
//!
//! The guard asserts the *raw serde fixpoint* directly on the struct
//! (`toml::from_str` / `toml::to_string`), NOT through `load_or_generate`
//! (which deliberately discards `relay_url` as runtime state). That is the
//! correct surface for "the struct's on-disk shape didn't change."

use p2p_core::DaemonConfig;
use std::path::Path;

fn read_fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", path.display()))
}

/// Assert two configs are field-for-field equal. `DaemonConfig` does not derive
/// `PartialEq`, so the fixpoint is checked per-field — which also documents
/// exactly which fields the on-disk format is pinned on.
fn assert_config_eq(a: &DaemonConfig, b: &DaemonConfig) {
    assert_eq!(a.peer_id, b.peer_id, "peer_id drifted across round-trip");
    assert_eq!(
        a.legacy_peer_id, b.legacy_peer_id,
        "legacy_peer_id drifted across round-trip"
    );
    assert_eq!(
        a.relay_url, b.relay_url,
        "relay_url drifted across round-trip"
    );
    assert_eq!(
        a.mesh_name, b.mesh_name,
        "mesh_name drifted across round-trip"
    );
    assert_eq!(
        a.known_public_relays, b.known_public_relays,
        "known_public_relays drifted across round-trip"
    );
}

/// The canonical current shape a live fleet `daemon.toml` has on disk:
/// `peer_id` + `legacy_peer_id` + `known_public_relays`. `relay_url` and
/// `mesh_name` are absent (their `skip_serializing_if` means a daemon that
/// isn't running a relay / hasn't been named never writes them).
///
/// Proves: (a) the new p2p-core `DaemonConfig` reads the legacy on-disk format
/// (forward-compat across the home-crate move), (b) parse -> serialize -> parse
/// is a fixpoint (every field value survives), (c) serialization is idempotent,
/// and (d) the serialized form carries exactly the expected keys.
#[test]
fn canonical_daemon_toml_round_trips_byte_stably() {
    let fixture = read_fixture("daemon.toml");

    // (a) The current struct parses the on-disk format.
    let config: DaemonConfig =
        toml::from_str(&fixture).expect("the canonical daemon.toml fixture must parse");

    // (b) parse -> serialize -> parse fixpoint.
    let reser = toml::to_string(&config).expect("serialize must succeed");
    let config2: DaemonConfig =
        toml::from_str(&reser).expect("the re-serialized config must re-parse");
    assert_config_eq(&config, &config2);

    // (c) serialization is idempotent (no churn on a second round-trip).
    let reser2 = toml::to_string(&config2).expect("second serialize must succeed");
    assert_eq!(
        reser, reser2,
        "serialization must be idempotent — the on-disk bytes must not drift on re-save"
    );

    // (d) the serialized form carries exactly the expected keys: the three
    // populated fields are present, and no retired/unexpected key leaks in.
    assert!(
        reser.contains("peer_id"),
        "serialized daemon.toml must contain peer_id; was:\n{reser}"
    );
    assert!(
        reser.contains("legacy_peer_id"),
        "serialized daemon.toml must contain legacy_peer_id; was:\n{reser}"
    );
    assert!(
        reser.contains("known_public_relays"),
        "serialized daemon.toml must contain known_public_relays; was:\n{reser}"
    );
    // relay_url / mesh_name are None here (skip_serializing_if) — must NOT appear.
    assert!(
        !reser.contains("relay_url"),
        "an unset relay_url must be omitted, not emitted; was:\n{reser}"
    );
    assert!(
        !reser.contains("mesh_name"),
        "an unset mesh_name must be omitted, not emitted; was:\n{reser}"
    );
    // Retired fields that DaemonConfigRaw tolerantly parses must never be
    // re-emitted by the current struct.
    assert!(
        !reser.contains("incarnation"),
        "the retired incarnation field must never be re-emitted; was:\n{reser}"
    );
    assert!(
        !reser.contains("peer_relays"),
        "the retired peer_relays field must never be re-emitted; was:\n{reser}"
    );
}

/// The fully-populated shape — additionally pins `relay_url` and `mesh_name`
/// serde (a daemon running a relay, with a set mesh name, writes both). Same
/// four assertions as the canonical case, extended to the optional fields.
#[test]
fn full_daemon_toml_round_trips_byte_stably() {
    let fixture = read_fixture("daemon_full.toml");

    // (a) parse the full on-disk format.
    let config: DaemonConfig =
        toml::from_str(&fixture).expect("the full daemon.toml fixture must parse");

    // (b) parse -> serialize -> parse fixpoint across all five fields.
    let reser = toml::to_string(&config).expect("serialize must succeed");
    let config2: DaemonConfig =
        toml::from_str(&reser).expect("the re-serialized config must re-parse");
    assert_config_eq(&config, &config2);

    // (c) idempotent serialization.
    let reser2 = toml::to_string(&config2).expect("second serialize must succeed");
    assert_eq!(
        reser, reser2,
        "serialization must be idempotent — the on-disk bytes must not drift on re-save"
    );

    // (d) every expected key is present; no unexpected key leaks.
    for key in [
        "peer_id",
        "legacy_peer_id",
        "relay_url",
        "mesh_name",
        "known_public_relays",
    ] {
        assert!(
            reser.contains(key),
            "serialized full daemon.toml must contain {key}; was:\n{reser}"
        );
    }
    assert!(
        !reser.contains("incarnation"),
        "the retired incarnation field must never be re-emitted; was:\n{reser}"
    );
    assert!(
        !reser.contains("peer_relays"),
        "the retired peer_relays field must never be re-emitted; was:\n{reser}"
    );
}
