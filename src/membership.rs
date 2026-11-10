//! Peer-equal signed membership log CRDT.
//!
//! Every membership change is an Ed25519-signed entry in a causally-linked DAG
//! rooted at a `Genesis` entry. `mesh_id` is the `entry_id` of that genesis, so
//! it is a name (a hash), not a key: the genesis device has no special authority
//! after genesis.
//!
//! Evaluation is a deterministic canonical replay: the reachable DAG is put in
//! Kahn topological order (ties broken by `entry_id`), then replayed in one
//! forward pass with a monotonically growing `voided` set. That terminates and is
//! permutation-invariant, so every peer computes the same roster.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::verify_peer_signature;
use crate::peer_id::PeerId;

/// Domain separator for canonical membership signing payloads.
pub const DOMAIN_SEP: &[u8] = b"webdesserts-mesh-membership-v1\0";

/// How a member relates to the mesh owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Relationship {
    /// One of the owner's own devices.
    #[default]
    #[serde(rename = "self")]
    SelfDevice,
    /// A friend's device (proxy-only isolation in Phase 4).
    Friend,
}

/// A membership operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum MembershipOp {
    Genesis { nonce: String, device_name: String },
    Add {
        mesh_id: String,
        subject: PeerId,
        device_name: String,
        #[serde(default)]
        relationship: Relationship,
        parent_heads: Vec<String>,
    },
    Remove {
        mesh_id: String,
        subject: PeerId,
        parent_heads: Vec<String>,
        active_after: Vec<PeerId>,
    },
}

/// A signed membership entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedMembershipEntry {
    /// 64-char lowercase hex SHA-256 of `DOMAIN_SEP || canonical_payload_json`.
    /// For `MembershipOp::Genesis`, `mesh_id == entry_id`.
    pub entry_id: String,
    pub signer: PeerId,
    /// Signer-claimed timestamp. Display only — never used for ordering.
    pub created_at: u64,
    pub op: MembershipOp,
    /// 128-char lowercase hex Ed25519 signature over the canonical payload.
    pub signature: String,
}

/// Canonical signing payload (deterministic field order, no maps).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalPayload {
    signer: PeerId,
    created_at: u64,
    op: MembershipOp,
}

/// Errors from membership verification / merge.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MembershipError {
    #[error("invalid membership entry: {0}")]
    Invalid(String),
    #[error("mesh_id mismatch: expected {expected}, got {got}")]
    MeshIdMismatch { expected: String, got: String },
    #[error("canonical payload could not be serialized: {0}")]
    Canonical(String),
}

fn hex_lower(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}

/// Normalize an op for canonical signing: sort + dedup `parent_heads`
/// lexicographically and `active_after` by `PeerId` hex.
fn normalize_op(op: &MembershipOp) -> MembershipOp {
    let mut out = op.clone();
    match &mut out {
        MembershipOp::Genesis { .. } => {}
        MembershipOp::Add { parent_heads, .. } => {
            parent_heads.sort();
            parent_heads.dedup();
        }
        MembershipOp::Remove {
            parent_heads,
            active_after,
            ..
        } => {
            parent_heads.sort();
            parent_heads.dedup();
            active_after.sort_by_key(|p| p.to_string());
            active_after.dedup();
        }
    }
    out
}

/// Canonical bytes for `(signer, created_at, op)`.
pub fn canonical_bytes(
    signer: &PeerId,
    created_at: u64,
    op: &MembershipOp,
) -> Result<Vec<u8>, MembershipError> {
    let payload = CanonicalPayload {
        signer: *signer,
        created_at,
        op: normalize_op(op),
    };
    serde_json::to_vec(&payload).map_err(|e| MembershipError::Canonical(e.to_string()))
}

/// `entry_id` for a canonical payload: hex SHA-256 of `DOMAIN_SEP || bytes`.
pub fn entry_id_for(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SEP);
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

impl SignedMembershipEntry {
    /// Build and sign an entry.
    pub fn sign(
        identity: &crate::identity::IdentityKey,
        created_at: u64,
        op: MembershipOp,
    ) -> Result<Self, MembershipError> {
        let signer = identity.peer_id();
        let bytes = canonical_bytes(&signer, created_at, &op)?;
        let entry_id = entry_id_for(&bytes);
        let signature = hex_lower(&identity.sign(&bytes));
        Ok(Self {
            entry_id,
            signer,
            created_at,
            op: normalize_op(&op),
            signature,
        })
    }

    /// Recompute the canonical bytes and verify `entry_id` + signature.
    pub fn verify(&self) -> bool {
        let Ok(bytes) = canonical_bytes(&self.signer, self.created_at, &self.op) else {
            return false;
        };
        if entry_id_for(&bytes) != self.entry_id {
            return false;
        }
        let Ok(sig_bytes) = data_encoding::HEXLOWER.decode(self.signature.as_bytes()) else {
            return false;
        };
        let Ok(sig) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
            return false;
        };
        verify_peer_signature(&self.signer, &bytes, &sig)
    }

    /// The `mesh_id` this entry belongs to (`entry_id` for `Genesis`).
    pub fn mesh_id(&self) -> &str {
        match &self.op {
            MembershipOp::Genesis { .. } => &self.entry_id,
            MembershipOp::Add { mesh_id, .. } | MembershipOp::Remove { mesh_id, .. } => mesh_id,
        }
    }

    /// Causal parents (empty for `Genesis`).
    pub fn parent_heads(&self) -> Vec<String> {
        match &self.op {
            MembershipOp::Genesis { .. } => Vec::new(),
            MembershipOp::Add { parent_heads, .. } | MembershipOp::Remove { parent_heads, .. } => {
                parent_heads.clone()
            }
        }
    }
}

/// An active member of the mesh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveMember {
    pub peer_id: PeerId,
    pub device_name: String,
    pub relationship: Relationship,
    pub paired_at: u64,
}

/// The materialized roster produced by `MembershipLog::evaluate`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EvaluatedMembership {
    pub mesh_id: String,
    pub active: BTreeMap<PeerId, ActiveMember>,
    pub revoked: BTreeMap<PeerId, u64>,
    /// Heads over ALL verified reachable entries (not just valid ones).
    pub heads: Vec<String>,
    /// Entry ids that survived replay.
    pub valid: BTreeSet<String>,
}

impl EvaluatedMembership {
    fn empty(mesh_id: &str) -> Self {
        Self {
            mesh_id: mesh_id.to_string(),
            ..Default::default()
        }
    }

    /// Project active + revoked peers into `AllowedPeer` rows (excluding `local`).
    pub fn to_allowed_peers(
        &self,
        local: &PeerId,
        existing_last_seen: &HashMap<PeerId, Option<u64>>,
    ) -> Vec<crate::allowlist::AllowedPeer> {
        let mut out = Vec::new();
        for (peer_id, member) in &self.active {
            if peer_id == local {
                continue;
            }
            out.push(crate::allowlist::AllowedPeer {
                node_id: *peer_id,
                device_name: member.device_name.clone(),
                paired_at: member.paired_at,
                last_seen: existing_last_seen.get(peer_id).copied().flatten(),
                removed: false,
                removed_at: None,
            });
        }
        for (peer_id, removed_at) in &self.revoked {
            if peer_id == local {
                continue;
            }
            out.push(crate::allowlist::AllowedPeer {
                node_id: *peer_id,
                device_name: String::new(),
                paired_at: 0,
                last_seen: existing_last_seen.get(peer_id).copied().flatten(),
                removed: true,
                removed_at: Some(*removed_at),
            });
        }
        out
    }
}

/// A peer-equal signed membership log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipLog {
    pub mesh_id: String,
    pub entries: BTreeMap<String, SignedMembershipEntry>,
}

impl MembershipLog {
    /// Create a solo genesis log signed by `identity`.
    pub fn new_genesis(
        identity: &crate::identity::IdentityKey,
        device_name: &str,
        nonce: &str,
        created_at: u64,
    ) -> Result<Self, MembershipError> {
        let op = MembershipOp::Genesis {
            nonce: nonce.to_string(),
            device_name: device_name.to_string(),
        };
        let entry = SignedMembershipEntry::sign(identity, created_at, op)?;
        let mesh_id = entry.entry_id.clone();
        let mut entries = BTreeMap::new();
        entries.insert(entry.entry_id.clone(), entry);
        Ok(Self { mesh_id, entries })
    }

    /// Sign an `Add` for `subject` on top of the current heads.
    pub fn sign_add(
        &self,
        identity: &crate::identity::IdentityKey,
        subject: PeerId,
        device_name: &str,
        relationship: Relationship,
        created_at: u64,
    ) -> Result<SignedMembershipEntry, MembershipError> {
        let op = MembershipOp::Add {
            mesh_id: self.mesh_id.clone(),
            subject,
            device_name: device_name.to_string(),
            relationship,
            parent_heads: self.evaluate().heads,
        };
        SignedMembershipEntry::sign(identity, created_at, op)
    }

    /// Sign a `Remove` for `subject` on top of the current heads.
    pub fn sign_remove(
        &self,
        identity: &crate::identity::IdentityKey,
        subject: PeerId,
        created_at: u64,
    ) -> Result<SignedMembershipEntry, MembershipError> {
        let eval = self.evaluate();
        let mut active_after: Vec<PeerId> = eval.active.keys().copied().collect();
        active_after.retain(|p| *p != subject);
        let op = MembershipOp::Remove {
            mesh_id: self.mesh_id.clone(),
            subject,
            parent_heads: eval.heads,
            active_after,
        };
        SignedMembershipEntry::sign(identity, created_at, op)
    }

    /// Verify and union incoming entries (G-Set merge).
    pub fn merge_entries(
        &mut self,
        incoming: &[SignedMembershipEntry],
    ) -> Result<(), MembershipError> {
        for entry in incoming {
            if !entry.verify() {
                return Err(MembershipError::Invalid(entry.entry_id.clone()));
            }
            if entry.mesh_id() != self.mesh_id {
                return Err(MembershipError::MeshIdMismatch {
                    expected: self.mesh_id.clone(),
                    got: entry.mesh_id().to_string(),
                });
            }
            self.entries.insert(entry.entry_id.clone(), entry.clone());
        }
        Ok(())
    }
}

impl MembershipLog {
    /// Deterministic canonical-replay evaluation.
    pub fn evaluate(&self) -> EvaluatedMembership {
        let empty = EvaluatedMembership::empty(&self.mesh_id);
        let Some(genesis) = self.entries.get(&self.mesh_id) else {
            return empty;
        };
        if !matches!(genesis.op, MembershipOp::Genesis { .. })
            || genesis.entry_id != self.mesh_id
            || !genesis.verify()
        {
            return empty;
        }
        let genesis_signer = genesis.signer;

        // 1–3. Single-pass Kahn reachability, canonical topological order, and strict ancestors.
        let mut parent_map: HashMap<String, BTreeSet<String>> = HashMap::new();
        let mut rem_parents: HashMap<String, usize> = HashMap::new();
        let mut children: HashMap<String, Vec<String>> = HashMap::new();
        for (id, entry) in &self.entries {
            if id == &self.mesh_id {
                continue;
            }
            if entry.entry_id != *id || entry.mesh_id() != self.mesh_id {
                continue;
            }
            let parents: BTreeSet<String> = entry.parent_heads().into_iter().collect();
            if parents.is_empty() || !parents.iter().all(|p| self.entries.contains_key(p)) {
                continue;
            }
            rem_parents.insert(id.clone(), parents.len());
            for p in &parents {
                children.entry(p.clone()).or_default().push(id.clone());
            }
            parent_map.insert(id.clone(), parents);
        }

        let mut reachable: BTreeSet<String> = BTreeSet::new();
        let mut order: Vec<String> = Vec::new();
        let mut ancestors: HashMap<String, BTreeSet<String>> = HashMap::new();
        let mut ready: BTreeSet<String> = BTreeSet::new();
        ready.insert(self.mesh_id.clone());

        while let Some(id) = ready.pop_first() {
            if id != self.mesh_id {
                let Some(entry) = self.entries.get(&id) else {
                    continue;
                };
                if !entry.verify() {
                    continue;
                }
            }
            let mut anc: BTreeSet<String> = BTreeSet::new();
            if let Some(ps) = parent_map.get(&id) {
                for p in ps {
                    anc.insert(p.clone());
                    if let Some(p_anc) = ancestors.get(p) {
                        anc.extend(p_anc.iter().cloned());
                    }
                }
            }
            ancestors.insert(id.clone(), anc);
            reachable.insert(id.clone());
            order.push(id.clone());

            if let Some(cs) = children.get(&id) {
                for c in cs {
                    if let Some(rem) = rem_parents.get_mut(c) {
                        *rem -= 1;
                        if *rem == 0 {
                            ready.insert(c.clone());
                        }
                    }
                }
            }
        }
        // 4. Pure causal validity over `ancestors` (order-independent, cycle-safe memoized).
        let remove_ids: Vec<String> = order
            .iter()
            .filter(|id| {
                self.entries
                    .get(*id)
                    .is_some_and(|e| matches!(e.op, MembershipOp::Remove { .. }))
            })
            .cloned()
            .collect();
        let mut memo: HashMap<String, bool> = HashMap::new();
        let mut voided: BTreeSet<String> = BTreeSet::new();
        for id in &order {
            let mut visiting = HashSet::new();
            if !is_entry_valid(
                id,
                &self.mesh_id,
                &genesis_signer,
                &order,
                &remove_ids,
                &self.entries,
                &ancestors,
                &mut visiting,
                &mut memo,
            )
            .0
            {
                voided.insert(id.clone());
            }
        }

        // 5. Materialize roster + heads over all reachable entries.
        let mut valid: BTreeSet<String> = BTreeSet::new();
        for id in &order {
            if !voided.contains(id) {
                valid.insert(id.clone());
            }
        }
        let mut revoked: BTreeMap<PeerId, u64> = BTreeMap::new();
        let mut active: BTreeMap<PeerId, ActiveMember> = BTreeMap::new();
        for id in &order {
            if !valid.contains(id) {
                continue;
            }
            let Some(e) = self.entries.get(id) else {
                continue;
            };
            match &e.op {
                MembershipOp::Genesis { device_name, .. } => {
                    active.insert(
                        e.signer,
                        ActiveMember {
                            peer_id: e.signer,
                            device_name: device_name.clone(),
                            relationship: Relationship::SelfDevice,
                            paired_at: e.created_at,
                        },
                    );
                }
                MembershipOp::Add {
                    subject,
                    device_name,
                    relationship,
                    ..
                } => {
                    let entry = active.entry(*subject).or_insert(ActiveMember {
                        peer_id: *subject,
                        device_name: device_name.clone(),
                        relationship: *relationship,
                        paired_at: e.created_at,
                    });
                    entry.device_name = device_name.clone();
                    entry.relationship = *relationship;
                }
                MembershipOp::Remove { subject, .. } => {
                    revoked.insert(*subject, e.created_at);
                }
            }
        }
        for p in revoked.keys() {
            active.remove(p);
        }

        let mut cited: BTreeSet<String> = BTreeSet::new();
        for id in &reachable {
            if let Some(e) = self.entries.get(id) {
                for p in e.parent_heads() {
                    cited.insert(p);
                }
            }
        }
        let heads: Vec<String> = reachable
            .iter()
            .filter(|id| !cited.contains(*id))
            .cloned()
            .collect();

        EvaluatedMembership {
            mesh_id: self.mesh_id.clone(),
            active,
            revoked,
            heads,
            valid,
        }
    }
}

/// Does a valid `Remove` entry `r_id` cut off entry `e_id` (signed by `r`'s subject)?
fn cuts_off(
    r_id: &str,
    e_id: &str,
    entries: &BTreeMap<String, SignedMembershipEntry>,
    ancestors: &HashMap<String, BTreeSet<String>>,
) -> bool {
    let (Some(r), Some(e)) = (entries.get(r_id), entries.get(e_id)) else {
        return false;
    };
    let MembershipOp::Remove {
        subject: r_subj,
        active_after,
        ..
    } = &r.op
    else {
        return false;
    };
    if e.signer != *r_subj {
        return false;
    }
    let in_r_anc = ancestors
        .get(r_id)
        .map_or(false, |anc| anc.contains(e_id));
    match &e.op {
        MembershipOp::Genesis { .. } => false,
        MembershipOp::Add { subject: u, .. } => !(in_r_anc && active_after.contains(u)),
        MembershipOp::Remove { subject: y, .. } => {
            let r_in_e_anc = ancestors
                .get(e_id)
                .map_or(false, |anc| anc.contains(r_id));
            let concurrent_mutual = !r_in_e_anc && *y == r.signer;
            !(in_r_anc || concurrent_mutual)
        }
    }
}

/// Is `peer` active within a subset of already-validated ancestor entries?
/// Iterates `order` (topological order) so a single forward pass suffices.
fn is_active_in_valid_subset(
    peer: &PeerId,
    valid_subset: &HashSet<&str>,
    order: &[String],
    entries: &BTreeMap<String, SignedMembershipEntry>,
    genesis_signer: &PeerId,
) -> bool {
    let mut removed: HashSet<PeerId> = HashSet::new();
    for id in valid_subset {
        if let Some(e) = entries.get(*id) {
            if let MembershipOp::Remove { subject, .. } = &e.op {
                removed.insert(*subject);
            }
        }
    }
    if removed.contains(peer) {
        return false;
    }
    if peer == genesis_signer {
        return true;
    }
    let mut active: HashSet<PeerId> = HashSet::new();
    active.insert(*genesis_signer);
    for id in order {
        if !valid_subset.contains(id.as_str()) {
            continue;
        }
        let Some(e) = entries.get(id) else {
            continue;
        };
        if let MembershipOp::Add {
            subject,
            relationship: Relationship::SelfDevice,
            ..
        } = &e.op
        {
            if active.contains(&e.signer) && !removed.contains(subject) {
                active.insert(*subject);
                if subject == peer {
                    return true;
                }
            }
        }
    }
    active.contains(peer)
}

/// Order-independent recursive causal validity check for a reachable entry.
/// Returns `(is_valid, hit_cycle)`; results with `!hit_cycle` are independent of
/// `visiting` and safely memoized across the evaluation pass.
fn is_entry_valid(
    id: &str,
    mesh_id: &str,
    genesis_signer: &PeerId,
    order: &[String],
    remove_ids: &[String],
    entries: &BTreeMap<String, SignedMembershipEntry>,
    ancestors: &HashMap<String, BTreeSet<String>>,
    visiting: &mut HashSet<String>,
    memo: &mut HashMap<String, bool>,
) -> (bool, bool) {
    if id == mesh_id {
        return (true, false);
    }
    if let Some(&cached) = memo.get(id) {
        return (cached, false);
    }
    if !visiting.insert(id.to_string()) {
        // Cycle of concurrent checks fails closed.
        return (false, true);
    }
    let (res, tainted) = (|| {
        let Some(e) = entries.get(id) else {
            return (false, false);
        };
        let signer = e.signer;
        let is_remove = matches!(e.op, MembershipOp::Remove { .. });
        let mut tainted = false;

        // Step A: signer must be active in the valid subset of `anc(id)`.
        let mut anc_valid: HashSet<&str> = HashSet::new();
        if let Some(anc) = ancestors.get(id) {
            for a_id in anc {
                if is_remove && cuts_off(id, a_id, entries, ancestors) {
                    continue;
                }
                let (ok, cyc) = is_entry_valid(
                    a_id,
                    mesh_id,
                    genesis_signer,
                    order,
                    remove_ids,
                    entries,
                    ancestors,
                    visiting,
                    memo,
                );
                tainted |= cyc;
                if ok {
                    anc_valid.insert(a_id.as_str());
                }
            }
        }
        if !is_active_in_valid_subset(&signer, &anc_valid, order, entries, genesis_signer) {
            return (false, tainted);
        }

        // Step B: no valid Remove targeting `signer` in `reachable` cuts off `id`.
        for r_id in remove_ids {
            let Some(r) = entries.get(r_id) else {
                continue;
            };
            if let MembershipOp::Remove { subject, .. } = &r.op {
                if *subject == signer && cuts_off(r_id, id, entries, ancestors) {
                    let (r_ok, cyc) = is_entry_valid(
                        r_id,
                        mesh_id,
                        genesis_signer,
                        order,
                        remove_ids,
                        entries,
                        ancestors,
                        visiting,
                        memo,
                    );
                    tainted |= cyc;
                    if r_ok {
                        return (false, tainted);
                    }
                }
            }
        }
        (true, tainted)
    })();
    visiting.remove(id);
    if !tainted {
        memo.insert(id.to_string(), res);
    }
    (res, tainted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKey;
    use tempfile::TempDir;

    async fn ident(dir: &TempDir, name: &str) -> IdentityKey {
        let path = dir.path().join(format!("{name}.key"));
        IdentityKey::load_or_generate_at(&path).await.unwrap()
    }

    fn add_op(mesh_id: &str, subject: PeerId, name: &str, parents: Vec<String>) -> MembershipOp {
        MembershipOp::Add {
            mesh_id: mesh_id.to_string(),
            subject,
            device_name: name.to_string(),
            relationship: Relationship::SelfDevice,
            parent_heads: parents,
        }
    }

    fn remove_op(
        mesh_id: &str,
        subject: PeerId,
        parents: Vec<String>,
        active_after: Vec<PeerId>,
    ) -> MembershipOp {
        MembershipOp::Remove {
            mesh_id: mesh_id.to_string(),
            subject,
            parent_heads: parents,
            active_after,
        }
    }

    #[tokio::test]
    async fn membership_genesis_add_remove_happy_path() {
        let dir = TempDir::new().unwrap();
        let a = ident(&dir, "a").await;
        let b = ident(&dir, "b").await;
        let c = ident(&dir, "c").await;

        let mut log_a = MembershipLog::new_genesis(&a, "A", "n1", 1).unwrap();
        let add_b = log_a
            .sign_add(&a, b.peer_id(), "B", Relationship::SelfDevice, 2)
            .unwrap();
        log_a.merge_entries(&[add_b.clone()]).unwrap();

        let mut log_b = log_a.clone();
        let add_c = log_b
            .sign_add(&b, c.peer_id(), "C", Relationship::SelfDevice, 3)
            .unwrap();
        log_b.merge_entries(&[add_c.clone()]).unwrap();
        log_a.merge_entries(&[add_c.clone()]).unwrap();

        let rm_c = log_a.sign_remove(&a, c.peer_id(), 4).unwrap();
        log_a.merge_entries(&[rm_c.clone()]).unwrap();
        log_b.merge_entries(&[rm_c.clone()]).unwrap();

        let ea = log_a.evaluate();
        let eb = log_b.evaluate();
        assert_eq!(ea, eb);
        assert_eq!(ea.mesh_id, log_a.mesh_id);
        assert!(ea.active.contains_key(&a.peer_id()));
        assert!(ea.active.contains_key(&b.peer_id()));
        assert!(!ea.active.contains_key(&c.peer_id()));
        assert!(ea.revoked.contains_key(&c.peer_id()));
    }

    #[tokio::test]
    async fn membership_revoked_peer_backdated_sockpuppet_add_is_nullified() {
        let dir = TempDir::new().unwrap();
        let a = ident(&dir, "a").await;
        let b = ident(&dir, "b").await;
        let c = ident(&dir, "c").await;
        let sock = ident(&dir, "sock").await;

        let mut log = MembershipLog::new_genesis(&a, "A", "n1", 1).unwrap();
        let add_b = log
            .sign_add(&a, b.peer_id(), "B", Relationship::SelfDevice, 2)
            .unwrap();
        log.merge_entries(&[add_b.clone()]).unwrap();
        let add_c = log
            .sign_add(&a, c.peer_id(), "C", Relationship::SelfDevice, 3)
            .unwrap();
        log.merge_entries(&[add_c.clone()]).unwrap();
        let rm_c = log.sign_remove(&a, c.peer_id(), 4).unwrap();
        log.merge_entries(&[rm_c.clone()]).unwrap();

        let sock_add = SignedMembershipEntry::sign(
            &c,
            5,
            add_op(&log.mesh_id, sock.peer_id(), "Sock", vec![add_b.entry_id.clone()]),
        )
        .unwrap();
        let rm_a = SignedMembershipEntry::sign(
            &sock,
            6,
            remove_op(
                &log.mesh_id,
                a.peer_id(),
                vec![sock_add.entry_id.clone()],
                vec![sock.peer_id()],
            ),
        )
        .unwrap();

        log.merge_entries(&[sock_add.clone(), rm_a.clone()]).unwrap();
        let e = log.evaluate();
        assert!(e.active.contains_key(&a.peer_id()));
        assert!(e.active.contains_key(&b.peer_id()));
        assert!(!e.active.contains_key(&c.peer_id()));
        assert!(!e.active.contains_key(&sock.peer_id()));
        assert!(e.revoked.contains_key(&c.peer_id()));
        assert!(!e.revoked.contains_key(&a.peer_id()));
    }

    #[tokio::test]
    async fn revoked_peer_backdated_remove_of_third_party_is_void() {
        let dir = TempDir::new().unwrap();
        let a = ident(&dir, "a").await;
        let b = ident(&dir, "b").await;
        let c = ident(&dir, "c").await;

        let mut log = MembershipLog::new_genesis(&a, "A", "n1", 1).unwrap();
        let add_b = log
            .sign_add(&a, b.peer_id(), "B", Relationship::SelfDevice, 2)
            .unwrap();
        log.merge_entries(&[add_b.clone()]).unwrap();
        let add_c = log
            .sign_add(&a, c.peer_id(), "C", Relationship::SelfDevice, 3)
            .unwrap();
        log.merge_entries(&[add_c.clone()]).unwrap();
        let rm_b = log.sign_remove(&a, b.peer_id(), 4).unwrap();
        log.merge_entries(&[rm_b.clone()]).unwrap();

        let rm_c_by_b = SignedMembershipEntry::sign(
            &b,
            5,
            remove_op(
                &log.mesh_id,
                c.peer_id(),
                vec![add_b.entry_id.clone(), add_c.entry_id.clone()],
                vec![b.peer_id()],
            ),
        )
        .unwrap();
        log.merge_entries(&[rm_c_by_b]).unwrap();

        let e = log.evaluate();
        assert!(e.active.contains_key(&c.peer_id()));
        assert!(!e.active.contains_key(&b.peer_id()));
        assert!(e.revoked.contains_key(&b.peer_id()));
        assert!(!e.revoked.contains_key(&c.peer_id()));
    }

    #[tokio::test]
    async fn membership_legitimate_add_before_signer_removal_survives() {
        let dir = TempDir::new().unwrap();
        let a = ident(&dir, "a").await;
        let b = ident(&dir, "b").await;
        let c = ident(&dir, "c").await;

        let mut log = MembershipLog::new_genesis(&a, "A", "n1", 1).unwrap();
        let add_b = log
            .sign_add(&a, b.peer_id(), "B", Relationship::SelfDevice, 2)
            .unwrap();
        log.merge_entries(&[add_b.clone()]).unwrap();

        let add_c = SignedMembershipEntry::sign(
            &b,
            3,
            add_op(&log.mesh_id, c.peer_id(), "C", vec![add_b.entry_id.clone()]),
        )
        .unwrap();
        log.merge_entries(&[add_c.clone()]).unwrap();

        let rm_b = SignedMembershipEntry::sign(
            &a,
            4,
            remove_op(
                &log.mesh_id,
                b.peer_id(),
                vec![add_c.entry_id.clone()],
                vec![a.peer_id(), c.peer_id()],
            ),
        )
        .unwrap();
        log.merge_entries(&[rm_b]).unwrap();

        let e = log.evaluate();
        assert!(e.active.contains_key(&c.peer_id()));
        assert!(!e.active.contains_key(&b.peer_id()));
        assert!(e.revoked.contains_key(&b.peer_id()));
    }

    #[tokio::test]
    async fn membership_concurrent_mutual_removal_fails_closed() {
        let dir = TempDir::new().unwrap();
        let a = ident(&dir, "a").await;
        let b = ident(&dir, "b").await;

        let mut log = MembershipLog::new_genesis(&a, "A", "n1", 1).unwrap();
        let add_b = log
            .sign_add(&a, b.peer_id(), "B", Relationship::SelfDevice, 2)
            .unwrap();
        log.merge_entries(&[add_b.clone()]).unwrap();

        let rm_ab = SignedMembershipEntry::sign(
            &a,
            3,
            remove_op(
                &log.mesh_id,
                b.peer_id(),
                vec![add_b.entry_id.clone()],
                vec![a.peer_id()],
            ),
        )
        .unwrap();
        let rm_ba = SignedMembershipEntry::sign(
            &b,
            3,
            remove_op(
                &log.mesh_id,
                a.peer_id(),
                vec![add_b.entry_id.clone()],
                vec![b.peer_id()],
            ),
        )
        .unwrap();
        log.merge_entries(&[rm_ab, rm_ba]).unwrap();

        let e = log.evaluate();
        assert!(e.active.is_empty());
        assert!(e.revoked.contains_key(&a.peer_id()));
        assert!(e.revoked.contains_key(&b.peer_id()));
    }

    #[tokio::test]
    async fn membership_merge_random_dags_and_arrival_orders_converge() {
        let dir = TempDir::new().unwrap();
        let mut ids = Vec::new();
        for i in 0..5 {
            ids.push(ident(&dir, &format!("p{i}")).await);
        }
        let mut log = MembershipLog::new_genesis(&ids[0], "P0", "n1", 1).unwrap();

        let mut rng: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = || {
            rng = rng
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (rng >> 33) as usize
        };

        for step in 0..40u64 {
            let signer = ids[next() % ids.len()].clone();
            let subject = ids[next() % ids.len()].peer_id();
            let keys: Vec<String> = log.entries.keys().cloned().collect();
            let mut parents = Vec::new();
            let want = next() % 4;
            for _ in 0..want {
                if keys.is_empty() {
                    break;
                }
                parents.push(keys[next() % keys.len()].clone());
            }
            let op = if next() % 2 == 0 {
                add_op(&log.mesh_id, subject, "R", parents)
            } else {
                remove_op(&log.mesh_id, subject, parents, vec![ids[0].peer_id()])
            };
            let entry = SignedMembershipEntry::sign(&signer, step + 2, op).unwrap();
            log.merge_entries(&[entry]).unwrap();
        }

        let baseline = log.evaluate();
        let genesis_entry = log.entries.get(&log.mesh_id).cloned().unwrap();
        let mut pool: Vec<SignedMembershipEntry> = log
            .entries
            .values()
            .filter(|e| e.entry_id != log.mesh_id)
            .cloned()
            .collect();

        for _ in 0..20 {
            for i in (1..pool.len()).rev() {
                let j = next() % (i + 1);
                pool.swap(i, j);
            }
            let mut fresh = MembershipLog {
                mesh_id: log.mesh_id.clone(),
                entries: BTreeMap::new(),
            };
            fresh
                .entries
                .insert(genesis_entry.entry_id.clone(), genesis_entry.clone());
            fresh.merge_entries(&pool).unwrap();
            assert_eq!(fresh.evaluate(), baseline);
        }
    }

    #[tokio::test]
    async fn membership_tampered_signature_or_wrong_mesh_id_rejected() {
        let dir = TempDir::new().unwrap();
        let a = ident(&dir, "a").await;
        let b = ident(&dir, "b").await;
        let c = ident(&dir, "c").await;

        let mut log = MembershipLog::new_genesis(&a, "A", "n1", 1).unwrap();
        let add_b = log
            .sign_add(&a, b.peer_id(), "B", Relationship::SelfDevice, 2)
            .unwrap();
        log.merge_entries(&[add_b.clone()]).unwrap();

        let mut bad_sig = add_b.clone();
        bad_sig.signature = "00".repeat(64);
        assert!(log.merge_entries(&[bad_sig]).is_err());

        let mut bad_ts = add_b.clone();
        bad_ts.created_at += 1;
        assert!(log.merge_entries(&[bad_ts]).is_err());

        let mut bad_signer = add_b.clone();
        bad_signer.signer = c.peer_id();
        assert!(log.merge_entries(&[bad_signer]).is_err());

        let other = MembershipLog::new_genesis(&c, "C", "n2", 1).unwrap();
        let foreign = other
            .sign_add(&c, a.peer_id(), "A", Relationship::SelfDevice, 2)
            .unwrap();
        assert!(log.merge_entries(&[foreign]).is_err());

        let mut json = serde_json::to_value(&add_b).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("unknown_field".to_string(), serde_json::json!(1));
        assert!(serde_json::from_value::<SignedMembershipEntry>(json).is_err());
    }

    #[tokio::test]
    async fn peri_revoked_peer_cannot_erase_third_party_or_its_adds() {
        let dir = TempDir::new().unwrap();
        let a = ident(&dir, "a").await;
        let b = ident(&dir, "b").await;
        let c = ident(&dir, "c").await;
        let d = ident(&dir, "d").await;
        let mut failures = Vec::new();
        for ts in 0..40u64 {
            let mut log = MembershipLog::new_genesis(&a, "A", "n1", 1).unwrap();
            let add_b = log
                .sign_add(&a, b.peer_id(), "B", Relationship::SelfDevice, 2)
                .unwrap();
            log.merge_entries(&[add_b.clone()]).unwrap();
            let add_c = log
                .sign_add(&a, c.peer_id(), "C", Relationship::SelfDevice, 3)
                .unwrap();
            log.merge_entries(&[add_c.clone()]).unwrap();
            let add_d = log
                .sign_add(&c, d.peer_id(), "D", Relationship::SelfDevice, 4)
                .unwrap();
            log.merge_entries(&[add_d.clone()]).unwrap();
            let rm_b = log.sign_remove(&a, b.peer_id(), 5).unwrap();
            log.merge_entries(&[rm_b.clone()]).unwrap();
            let rm_c_by_b = SignedMembershipEntry::sign(
                &b,
                100 + ts,
                remove_op(
                    &log.mesh_id,
                    c.peer_id(),
                    vec![add_b.entry_id.clone(), add_c.entry_id.clone()],
                    vec![b.peer_id()],
                ),
            )
            .unwrap();
            let pre = log.evaluate();
            assert!(
                pre.active.contains_key(&c.peer_id()) && pre.active.contains_key(&d.peer_id()),
                "control failed"
            );
            log.merge_entries(&[rm_c_by_b.clone()]).unwrap();
            let e = log.evaluate();
            let c_ok = e.active.contains_key(&c.peer_id());
            let d_ok = e.active.contains_key(&d.peer_id());
            if !c_ok || !d_ok {
                failures.push((
                    ts,
                    c_ok,
                    d_ok,
                    rm_c_by_b.entry_id < add_d.entry_id,
                    rm_c_by_b.entry_id < rm_b.entry_id,
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "{} of 40 failed (ts, C active, D active, rmC<addD, rmC<rmB): {:?}",
            failures.len(),
            failures
        );
    }

    #[tokio::test]
    async fn revoked_signer_entry_outside_revocation_ancestors_never_changes_state() {
        let dir = TempDir::new().unwrap();
        let a = ident(&dir, "a").await;
        let b = ident(&dir, "b").await;
        let c = ident(&dir, "c").await;
        let d = ident(&dir, "d").await;
        let e_peer = ident(&dir, "e").await;

        let mut base = MembershipLog::new_genesis(&a, "A", "n1", 1).unwrap();
        let add_b = base
            .sign_add(&a, b.peer_id(), "B", Relationship::SelfDevice, 2)
            .unwrap();
        base.merge_entries(&[add_b.clone()]).unwrap();
        let add_c = base
            .sign_add(&a, c.peer_id(), "C", Relationship::SelfDevice, 3)
            .unwrap();
        base.merge_entries(&[add_c.clone()]).unwrap();
        let add_d = base
            .sign_add(&c, d.peer_id(), "D", Relationship::SelfDevice, 4)
            .unwrap();
        base.merge_entries(&[add_d.clone()]).unwrap();
        let rm_b = base.sign_remove(&a, b.peer_id(), 5).unwrap();
        base.merge_entries(&[rm_b.clone()]).unwrap();

        let baseline = base.evaluate();

        for ts in 0..30u64 {
            let forged_add = SignedMembershipEntry::sign(
                &b,
                50 + ts,
                add_op(
                    &base.mesh_id,
                    e_peer.peer_id(),
                    "E",
                    vec![add_b.entry_id.clone(), add_c.entry_id.clone()],
                ),
            )
            .unwrap();
            let forged_rm_c = SignedMembershipEntry::sign(
                &b,
                200 + ts,
                remove_op(
                    &base.mesh_id,
                    c.peer_id(),
                    vec![add_b.entry_id.clone(), add_c.entry_id.clone()],
                    vec![b.peer_id()],
                ),
            )
            .unwrap();
            let forged_rm_d = SignedMembershipEntry::sign(
                &b,
                400 + ts,
                remove_op(
                    &base.mesh_id,
                    d.peer_id(),
                    vec![add_b.entry_id.clone(), add_d.entry_id.clone()],
                    vec![b.peer_id()],
                ),
            )
            .unwrap();

            let mut log = base.clone();
            log.merge_entries(&[forged_add, forged_rm_c, forged_rm_d])
                .unwrap();
            let eval = log.evaluate();
            assert_eq!(eval.active, baseline.active, "active changed at ts={ts}");
            assert_eq!(eval.revoked, baseline.revoked, "revoked changed at ts={ts}");
        }
    }

    #[tokio::test]
    async fn membership_concurrent_three_way_removal_ring_fails_closed() {
        // Intended result: when three active peers concurrently remove each other in a ring
        // (A removes B, B removes C, C removes A), the cycle guard fails closed so none of the
        // ring members can use its own revoked status to shield itself — all three Remove entries
        // remain valid and all three peers (A, B, C) are revoked, matching 2-way mutual removal.
        let dir = TempDir::new().unwrap();
        let a = ident(&dir, "a").await;
        let b = ident(&dir, "b").await;
        let c = ident(&dir, "c").await;

        let mut base = MembershipLog::new_genesis(&a, "A", "n1", 1).unwrap();
        let add_b = base
            .sign_add(&a, b.peer_id(), "B", Relationship::SelfDevice, 2)
            .unwrap();
        base.merge_entries(&[add_b.clone()]).unwrap();
        let add_c = base
            .sign_add(&a, c.peer_id(), "C", Relationship::SelfDevice, 3)
            .unwrap();
        base.merge_entries(&[add_c.clone()]).unwrap();

        let parents = vec![add_b.entry_id.clone(), add_c.entry_id.clone()];
        for ts in 0..10u64 {
            let rm_ab = SignedMembershipEntry::sign(
                &a,
                10 + ts,
                remove_op(
                    &base.mesh_id,
                    b.peer_id(),
                    parents.clone(),
                    vec![a.peer_id(), c.peer_id()],
                ),
            )
            .unwrap();
            let rm_bc = SignedMembershipEntry::sign(
                &b,
                20 + ts * 3,
                remove_op(
                    &base.mesh_id,
                    c.peer_id(),
                    parents.clone(),
                    vec![a.peer_id(), b.peer_id()],
                ),
            )
            .unwrap();
            let rm_ca = SignedMembershipEntry::sign(
                &c,
                30 + ts * 7,
                remove_op(
                    &base.mesh_id,
                    a.peer_id(),
                    parents.clone(),
                    vec![b.peer_id(), c.peer_id()],
                ),
            )
            .unwrap();

            let perms = [
                vec![rm_ab.clone(), rm_bc.clone(), rm_ca.clone()],
                vec![rm_ab.clone(), rm_ca.clone(), rm_bc.clone()],
                vec![rm_bc.clone(), rm_ab.clone(), rm_ca.clone()],
                vec![rm_bc.clone(), rm_ca.clone(), rm_ab.clone()],
                vec![rm_ca.clone(), rm_ab.clone(), rm_bc.clone()],
                vec![rm_ca.clone(), rm_bc.clone(), rm_ab.clone()],
            ];
            for p in perms {
                let mut log = base.clone();
                log.merge_entries(&p).unwrap();
                let ev = log.evaluate();
                assert!(ev.active.is_empty(), "expected all 3 revoked at ts={ts}");
                assert!(ev.valid.contains(&rm_ab.entry_id));
                assert!(ev.valid.contains(&rm_bc.entry_id));
                assert!(ev.valid.contains(&rm_ca.entry_id));
                assert!(ev.revoked.contains_key(&a.peer_id()));
                assert!(ev.revoked.contains_key(&b.peer_id()));
                assert!(ev.revoked.contains_key(&c.peer_id()));
            }
        }
    }

    #[tokio::test]
    async fn membership_evaluate_200_entry_chain_under_100ms() {
        let dir = TempDir::new().unwrap();
        let a = ident(&dir, "a").await;
        let mut log = MembershipLog::new_genesis(&a, "A", "n1", 1).unwrap();

        // Build a 200-entry linear chain of SelfDevice adds without calling evaluate() per step.
        let mut head = log.mesh_id.clone();
        for i in 0..200u64 {
            let mut raw = [0u8; 32];
            raw[0..8].copy_from_slice(&(i + 1).to_le_bytes());
            let subj = PeerId::from_bytes(raw);
            let e = SignedMembershipEntry::sign(
                &a,
                2 + i,
                add_op(&log.mesh_id, subj, "S", vec![head]),
            )
            .unwrap();
            head = e.entry_id.clone();
            log.entries.insert(e.entry_id.clone(), e);
        }

        let t0 = std::time::Instant::now();
        let ev = log.evaluate();
        let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(ev.active.len(), 201);
        assert!(
            elapsed_ms < 100.0,
            "evaluate() on 200-entry chain took {elapsed_ms:.2} ms (limit 100 ms)"
        );
    }
}