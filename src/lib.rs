//! p2p-core: the native peer-to-peer networking substrate for the obsidian-memory
//! sync stack.
//!
//! This crate owns the generic, application-agnostic pieces of the iroh-based mesh:
//! peer identity, key storage, the embedded relay, and (in later increments) the
//! node, pairing, and discovery layers. `sync-core` depends on `p2p-core` and
//! layers the vault-sync wire protocol on top of it.
//!
//! p2p-core is **native-only** — it carries no `cfg(target_arch = "wasm32")`
//! branches and no `native` feature gate; it simply *is* the native networking
//! crate.

pub mod allowlist;
pub mod config;
pub mod daemon_lock;
pub mod discovery;
pub mod identity;
pub mod key_storage;
pub mod mesh_mdns;
pub mod node;
pub mod pairing;
pub mod pairing_handler;
pub mod peer_id;
pub mod relay;
pub mod relay_class;
pub mod streams;
pub mod time_scale;

pub use allowlist::{
    AllowedPeer, AllowlistError, AllowlistStorage, FileAllowlistStorage, InMemoryAllowlist,
    write_pair_allowlist,
};
pub use config::{DaemonConfig, PeerRelay, persist_config_change};
pub use daemon_lock::{DaemonLock, LockError};
pub use discovery::{
    DiscoveredMesh, DiscoveryEvent, EndpointData, EndpointInfo, MeshMetadata,
    mesh_from_discovery_event,
};
pub use identity::{FileKeyStorage, IdentityKey};
pub use key_storage::{KeyStorage, KeyStorageError};
pub use mesh_mdns::{MeshMdns, socket_addrs_to_port_addrs};
pub use node::{P2pNode, topic_from_u64, u64_from_topic};
pub use pairing::{
    PairingChallenge, PairingHello, PairingResponse, PairingResult, PairingSession, compute_hmac,
    generate_pairing_code, verify_hmac,
};
pub use pairing_handler::{
    InboundPairingExchange, PAIRING_ALPN, PairingApproval, PairingEvent, PairingStreamHandler,
    pair_with_mesh, pair_with_mesh_interactive,
};
pub use peer_id::{PeerId, PeerIdError};
pub use relay::EmbeddedRelay;
pub use relay_class::relay_is_offlan_reachable;

/// The gossip protocol ALPN, re-exported so sync-core (and the daemon's reconnect
/// supervisor) can open gossip-bound connections without taking a direct
/// dependency on `iroh-gossip`.
pub use iroh_gossip::net::GOSSIP_ALPN;
