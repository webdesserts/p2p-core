//! p2p-core: the native peer-to-peer networking substrate for the obsidian-memory
//! sync stack.
//!
//! This crate owns the generic, application-agnostic pieces of the iroh-based mesh:
//! peer identity, key storage, and (in later increments) the node, pairing, relay,
//! and discovery layers. `sync-core` depends on `p2p-core` and layers the
//! vault-sync wire protocol on top of it.
//!
//! p2p-core is **native-only** — it carries no `cfg(target_arch = "wasm32")`
//! branches and no `native` feature gate; it simply *is* the native networking
//! crate.

pub mod allowlist;
pub mod identity;
pub mod key_storage;
pub mod pairing;
pub mod peer_id;

pub use allowlist::{AllowedPeer, AllowlistError, AllowlistStorage, InMemoryAllowlist};
pub use identity::{FileKeyStorage, IdentityKey};
pub use key_storage::{KeyStorage, KeyStorageError};
pub use pairing::{
    PairingChallenge, PairingHello, PairingResponse, PairingResult, PairingSession, compute_hmac,
    generate_pairing_code, verify_hmac,
};
pub use peer_id::{PeerId, PeerIdError};
