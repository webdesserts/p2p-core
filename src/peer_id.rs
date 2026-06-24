//! PeerId: Unique identifier for a peer/device in the sync network.
//!
//! Wraps an ed25519 public key (`[u8; 32]`) internally. Displays as a
//! 64-character hex string for human readability, and derives a `u64` via
//! FNV-1a hash for Loro compatibility.

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PeerIdError {
    #[error(
        "Invalid ID format: expected 64 hex chars (ed25519 pubkey), 16 hex chars (legacy), or UUID (legacy)"
    )]
    InvalidFormat,
    #[error("Invalid hex: {0}")]
    InvalidHex(String),
}

/// A unique identifier for a peer/device in the sync network.
///
/// Wraps an ed25519 public key (`[u8; 32]`), displayed as a 64-character hex
/// string. The `as_u64()` method returns an FNV-1a hash of the key bytes for
/// Loro CRDT compatibility.
///
/// When parsing, accepts:
/// - 64-char hex: the canonical ed25519 pubkey format
/// - 16-char hex: legacy format (backward compat for old daemon.toml and wire protocol)
/// - UUID (36-char): legacy format (backward compat for old configs)
///
/// # Examples
/// ```
/// use p2p_core::PeerId;
///
/// let peer_id = PeerId::generate();
/// let s = peer_id.to_string();
/// assert_eq!(s.len(), 64);
///
/// let parsed: PeerId = s.parse().unwrap();
/// assert_eq!(parsed, peer_id);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId([u8; 32]);

impl PeerId {
    /// Generate a new random PeerId backed by an ed25519 keypair.
    ///
    /// For the daemon, prefer `IdentityKey::generate()` and derive the PeerId
    /// from it so the secret key can be persisted. This method is for cases
    /// where only a PeerId is needed (e.g., tests, WASM plugin).
    pub fn generate() -> Self {
        use ed25519_dalek::SigningKey;
        // Use getrandom directly to avoid rand_core version conflicts between
        // rand 0.9 (rand_core 0.9) and ed25519-dalek 2.x (rand_core 0.6).
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("getrandom failed");
        let signing_key = SigningKey::from_bytes(&seed);
        Self(signing_key.verifying_key().to_bytes())
    }

    /// Construct a PeerId directly from raw bytes (ed25519 public key).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Derive the device PeerId from a 32-byte ed25519 secret (signing) key.
    ///
    /// This is the canonical "device secret → Loro author" derivation: both the
    /// daemon (via its persisted `IdentityKey`) and the WASM plugin (via its
    /// per-device secret key in `localStorage`) use it so a device authors Loro
    /// operations under a single stable, device-unique PeerId. See
    /// [[Loro Peer ID Semantics]].
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&bytes);
        Self(signing_key.verifying_key().to_bytes())
    }

    /// Get the raw ed25519 public key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive a stable u64 for use as a Loro peer ID.
    ///
    /// Uses FNV-1a hash of the 32-byte pubkey. This is stable across Rust
    /// versions and guaranteed non-zero (see implementation).
    pub fn as_u64(&self) -> u64 {
        let hash = fnv1a_hash_bytes(&self.0);
        // FNV-1a can theoretically return zero for some inputs. Avoid zero since
        // Loro treats 0 as an invalid peer ID.
        if hash == 0 { 1 } else { hash }
    }
}

impl Display for PeerId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl FromStr for PeerId {
    type Err = PeerIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Canonical format: 64 hex chars (32 bytes = ed25519 pubkey)
        if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            let mut bytes = [0u8; 32];
            for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
                let hi = hex_nibble(chunk[0])? as u8;
                let lo = hex_nibble(chunk[1])? as u8;
                bytes[i] = (hi << 4) | lo;
            }
            return Ok(Self(bytes));
        }

        // Legacy format: 16 hex chars (old u64 PeerId stored as hex)
        // Reconstruct a deterministic 32-byte value from the u64.
        if s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            let id = u64::from_str_radix(&s.to_ascii_lowercase(), 16)
                .map_err(|e| PeerIdError::InvalidHex(e.to_string()))?;
            return Ok(Self(u64_to_legacy_bytes(id)));
        }

        // Legacy format: UUID (36 chars with dashes at positions 8, 13, 18, 23)
        // Lowercase for consistency (same UUID with different case → same bytes)
        if s.len() == 36 {
            let bytes = s.as_bytes();
            if bytes[8] == b'-' && bytes[13] == b'-' && bytes[18] == b'-' && bytes[23] == b'-' {
                let hash = fnv1a_hash(&s.to_ascii_lowercase());
                return Ok(Self(u64_to_legacy_bytes(hash)));
            }
        }

        Err(PeerIdError::InvalidFormat)
    }
}

// Serialize as 64-char hex string for consistency in logs, errors, JSON, and TOML
impl serde::Serialize for PeerId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for PeerId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Expand a u64 into 32 bytes for legacy PeerId migration.
///
/// The u64 is stored in the first 8 bytes (big-endian); the remaining 24 bytes
/// are zero. This is deterministic so old configs parse consistently.
fn u64_to_legacy_bytes(id: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&id.to_be_bytes());
    bytes
}

/// FNV-1a hash over raw bytes. Used for `PeerId::as_u64()` and legacy migration.
/// Stable across Rust versions (unlike DefaultHasher).
pub(crate) fn fnv1a_hash_bytes(bytes: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET;
    for &byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// FNV-1a hash over a string. Used for legacy UUID migration.
fn fnv1a_hash(s: &str) -> u64 {
    fnv1a_hash_bytes(s.as_bytes())
}

fn hex_nibble(b: u8) -> Result<u32, PeerIdError> {
    match b {
        b'0'..=b'9' => Ok((b - b'0') as u32),
        b'a'..=b'f' => Ok((b - b'a' + 10) as u32),
        b'A'..=b'F' => Ok((b - b'A' + 10) as u32),
        _ => Err(PeerIdError::InvalidHex(format!(
            "invalid hex char: {}",
            b as char
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_produces_64_char_hex() {
        let peer_id = PeerId::generate();
        let s = peer_id.to_string();
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_roundtrip() {
        let original = PeerId::generate();
        let serialized = original.to_string();
        let parsed: PeerId = serialized.parse().unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_parse_64_char_hex() {
        let s = "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890";
        let peer_id: PeerId = s.parse().unwrap();
        assert_eq!(peer_id.to_string(), s);
    }

    #[test]
    fn test_parse_uppercase_hex() {
        let lower = "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890";
        let upper = lower.to_uppercase();
        let p1: PeerId = lower.parse().unwrap();
        let p2: PeerId = upper.parse().unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_as_u64_is_stable() {
        let peer_id = PeerId::generate();
        assert_eq!(peer_id.as_u64(), peer_id.as_u64());
    }

    #[test]
    fn test_as_u64_not_zero() {
        for _ in 0..100 {
            assert_ne!(PeerId::generate().as_u64(), 0);
        }
    }

    #[test]
    fn test_parse_legacy_16_char_hex() {
        // Legacy format: old u64 peer IDs stored as 16-char hex
        let peer_id: PeerId = "a1b2c3d4e5f67890".parse().unwrap();
        // Should round-trip through its 64-char representation
        let s = peer_id.to_string();
        assert_eq!(s.len(), 64);
        let parsed2: PeerId = s.parse().unwrap();
        assert_eq!(peer_id, parsed2);
    }

    #[test]
    fn test_parse_legacy_uuid() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let p1: PeerId = uuid.parse().unwrap();
        let p2: PeerId = uuid.parse().unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_parse_uuid_case_insensitive() {
        let lower = "550e8400-e29b-41d4-a716-446655440000";
        let upper = "550E8400-E29B-41D4-A716-446655440000";
        let mixed = "550e8400-E29B-41d4-A716-446655440000";

        let p1: PeerId = lower.parse().unwrap();
        let p2: PeerId = upper.parse().unwrap();
        let p3: PeerId = mixed.parse().unwrap();

        assert_eq!(p1, p2);
        assert_eq!(p2, p3);
    }

    #[test]
    fn test_invalid_format() {
        assert!("too_short".parse::<PeerId>().is_err());
        assert!("not-a-valid-format-at-all".parse::<PeerId>().is_err());
        // 64 chars but not hex
        assert!(
            "ghijklmnopqrstuvghijklmnopqrstuvghijklmnopqrstuvghijklmnopqrstuv"
                .parse::<PeerId>()
                .is_err()
        );
    }

    #[test]
    fn test_reject_wrong_length() {
        assert!("a1b2c3d4e5f6789".parse::<PeerId>().is_err()); // 15 chars
        assert!("a1b2c3d4e5f678901".parse::<PeerId>().is_err()); // 17 chars
        assert!("".parse::<PeerId>().is_err()); // empty
    }

    #[test]
    fn test_reject_invalid_uuid() {
        // Wrong number of dashes
        assert!(
            "550e8400e29b-41d4-a716-446655440000"
                .parse::<PeerId>()
                .is_err()
        );
        // Wrong positions
        assert!(
            "550e8400-e29b41d4-a716-4466-55440000"
                .parse::<PeerId>()
                .is_err()
        );
    }

    #[test]
    fn test_serde_roundtrip() {
        let original = PeerId::generate();
        let json = serde_json::to_string(&original).unwrap();
        // Should serialize as 64-char hex string
        let s: String = serde_json::from_str(&json).unwrap();
        assert_eq!(s.len(), 64);
        let parsed: PeerId = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_from_bytes_roundtrip() {
        let peer_id = PeerId::generate();
        let bytes = *peer_id.as_bytes();
        let reconstructed = PeerId::from_bytes(bytes);
        assert_eq!(peer_id, reconstructed);
    }
}
