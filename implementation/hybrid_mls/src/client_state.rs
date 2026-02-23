use crate::key_schedule::{tree_snapshot_hash, EpochDerivedSecrets, KeyScheduleState};
use crate::transcript::derive_confirmation_tag;
use crate::transcript::TranscriptState;
use crate::tree::{Proposal, RatchetTree};
use std::fs;
use std::path::Path;
use thiserror::Error;

const CLIENT_STATE_VERSION_V1: u8 = 1;
const CLIENT_STATE_VERSION_V2: u8 = 2;
const CLIENT_STATE_VERSION_V3: u8 = 3;
const CLIENT_STATE_VERSION_V4: u8 = 4;
const CLIENT_STATE_VERSION_V5: u8 = 5;
const CLIENT_STATE_VERSION: u8 = CLIENT_STATE_VERSION_V5;
const MAX_RECENT_APPLIED_COMMITS: usize = 1024;

#[derive(Clone, Debug, PartialEq)]
pub struct ClientGroupState {
    pub group_id: String,
    pub ratchet_tree: RatchetTree,
    pub own_leaf_index: usize,
    pub epoch: u64,
    pub pending_proposals: Vec<Vec<u8>>,
    pub last_applied_commit_id: Option<i64>,
    pub recent_applied_commit_ids: Vec<i64>,
    pub group_context_extensions: Vec<u8>,
    pub key_schedule: KeyScheduleState,
    pub transcript_state: TranscriptState,
}

#[derive(Debug, Error)]
pub enum ClientStateError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("corrupt client state")]
    CorruptState,
}

impl ClientGroupState {
    pub fn new(
        group_id: impl Into<String>,
        ratchet_tree: RatchetTree,
        own_leaf_index: usize,
    ) -> Self {
        let group_id = group_id.into();
        let tree_hash = current_tree_hash(&ratchet_tree);
        let key_schedule = KeyScheduleState::new(&group_id, tree_hash);
        let transcript_state = TranscriptState::new(&group_id, tree_hash);
        Self {
            group_id,
            ratchet_tree,
            own_leaf_index,
            epoch: 0,
            pending_proposals: Vec::new(),
            last_applied_commit_id: None,
            recent_applied_commit_ids: Vec::new(),
            group_context_extensions: Vec::new(),
            key_schedule,
            transcript_state,
        }
    }

    pub fn queue_proposal(&mut self, proposal: &Proposal) {
        self.pending_proposals.push(proposal.encode());
    }

    pub fn clear_pending_proposals(&mut self) {
        self.pending_proposals.clear();
    }

    pub fn decoded_pending_proposals(&self) -> Option<Vec<Proposal>> {
        let mut out = Vec::with_capacity(self.pending_proposals.len());
        for proposal_bytes in &self.pending_proposals {
            out.push(Proposal::decode(proposal_bytes)?);
        }
        Some(out)
    }

    pub fn has_applied_commit_id(&self, commit_id: i64) -> bool {
        if self.recent_applied_commit_ids.contains(&commit_id) {
            return true;
        }
        match self.last_applied_commit_id {
            Some(last) => commit_id <= last,
            None => false,
        }
    }

    pub fn mark_applied_commit_id(&mut self, commit_id: i64) {
        if self.recent_applied_commit_ids.contains(&commit_id) {
            return;
        }
        self.recent_applied_commit_ids.push(commit_id);
        if self.recent_applied_commit_ids.len() > MAX_RECENT_APPLIED_COMMITS {
            let overflow = self.recent_applied_commit_ids.len() - MAX_RECENT_APPLIED_COMMITS;
            self.recent_applied_commit_ids.drain(0..overflow);
        }
        self.last_applied_commit_id = Some(match self.last_applied_commit_id {
            Some(last) => last.max(commit_id),
            None => commit_id,
        });
    }

    pub fn set_epoch(&mut self, epoch: u64) {
        self.epoch = epoch;
        self.sync_key_schedule_epoch(None, None);
    }

    pub fn advance_epoch_with_context(&mut self, commit_context: Option<&[u8]>) {
        self.advance_epoch_internal(commit_context, None, None);
    }

    pub fn advance_epoch_with_context_and_confirmation(
        &mut self,
        commit_context: Option<&[u8]>,
        confirmation_tag: Option<&[u8; 32]>,
    ) {
        self.advance_epoch_internal(commit_context, confirmation_tag, None);
    }

    pub fn advance_epoch_with_context_and_tree_commit_secret(
        &mut self,
        commit_context: Option<&[u8]>,
        tree_commit_secret: Option<[u8; 32]>,
    ) {
        self.advance_epoch_internal(commit_context, None, tree_commit_secret);
    }

    fn advance_epoch_internal(
        &mut self,
        commit_context: Option<&[u8]>,
        confirmation_tag: Option<&[u8; 32]>,
        tree_commit_secret: Option<[u8; 32]>,
    ) {
        if let Some(context) = commit_context {
            let predicted_confirmed = self
                .transcript_state
                .predict_confirmed_after_commit(context);
            self.epoch = self.epoch.saturating_add(1);
            self.sync_key_schedule_epoch(commit_context, tree_commit_secret);

            let derived_tag = match confirmation_tag {
                Some(tag) => Some(*tag),
                None => self
                    .key_schedule
                    .derive_secrets_for_epoch(&self.group_id, self.epoch)
                    .map(|derived| {
                        derive_confirmation_tag(&derived.confirmation_key, &predicted_confirmed)
                    }),
            };
            let _ = self
                .transcript_state
                .apply_commit(context, derived_tag.as_ref());
            return;
        }
        self.epoch = self.epoch.saturating_add(1);
        self.sync_key_schedule_epoch(commit_context, None);
    }

    pub fn current_epoch_derived_secrets(&self) -> Option<EpochDerivedSecrets> {
        self.key_schedule
            .derive_current_epoch_secrets(&self.group_id)
    }

    pub fn ensure_key_schedule_consistency(&self) -> Result<(), &'static str> {
        if !self.key_schedule.is_well_formed() {
            return Err("malformed key schedule chain");
        }
        if !self.key_schedule.is_epoch_aligned(self.epoch) {
            return Err("key schedule epoch does not match group epoch");
        }
        Ok(())
    }

    pub fn predict_confirmed_transcript_after_commit(&self, commit_context: &[u8]) -> [u8; 32] {
        self.transcript_state
            .predict_confirmed_after_commit(commit_context)
    }

    pub fn confirmed_transcript_hash(&self) -> [u8; 32] {
        self.transcript_state.confirmed_transcript_hash()
    }

    pub fn interim_transcript_hash(&self) -> [u8; 32] {
        self.transcript_state.interim_transcript_hash()
    }

    pub fn membership_key_for_epoch(&self, epoch: u64) -> Option<[u8; 32]> {
        self.key_schedule
            .derive_secrets_for_epoch(&self.group_id, epoch)
            .map(|derived| derived.membership_key)
    }

    pub fn confirmation_key_for_epoch(&self, epoch: u64) -> Option<[u8; 32]> {
        self.key_schedule
            .derive_secrets_for_epoch(&self.group_id, epoch)
            .map(|derived| derived.confirmation_key)
    }

    pub fn sender_data_key_for_epoch(&self, epoch: u64) -> Option<[u8; 32]> {
        self.key_schedule
            .derive_secrets_for_epoch(&self.group_id, epoch)
            .map(|derived| derived.sender_data_key)
    }

    pub fn current_membership_key(&self) -> Option<[u8; 32]> {
        self.membership_key_for_epoch(self.epoch)
    }

    pub fn current_confirmation_key(&self) -> Option<[u8; 32]> {
        self.confirmation_key_for_epoch(self.epoch)
    }

    pub fn current_sender_data_key(&self) -> Option<[u8; 32]> {
        self.sender_data_key_for_epoch(self.epoch)
    }

    pub fn apply_group_context_extensions_from_proposals(&mut self, proposals: &[Proposal]) {
        for proposal in proposals {
            if let Proposal::GroupContextExtensions { extensions } = proposal {
                self.group_context_extensions = extensions.clone();
            }
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_u8(&mut out, CLIENT_STATE_VERSION);
        encode_bytes(&mut out, self.group_id.as_bytes());
        encode_u64(&mut out, self.epoch);
        encode_u32(&mut out, self.own_leaf_index as u32);
        encode_bytes(&mut out, &self.ratchet_tree.encode());
        encode_u32(&mut out, self.pending_proposals.len() as u32);
        for proposal in &self.pending_proposals {
            encode_bytes(&mut out, proposal);
        }
        match self.last_applied_commit_id {
            Some(value) => {
                encode_u8(&mut out, 1);
                encode_i64(&mut out, value);
            }
            None => {
                encode_u8(&mut out, 0);
            }
        }
        encode_u32(&mut out, self.recent_applied_commit_ids.len() as u32);
        for id in &self.recent_applied_commit_ids {
            encode_i64(&mut out, *id);
        }
        encode_bytes(&mut out, &self.key_schedule.encode());
        encode_bytes(&mut out, &self.transcript_state.encode());
        encode_bytes(&mut out, &self.group_context_extensions);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.read_u8()?;
        if version != CLIENT_STATE_VERSION_V1
            && version != CLIENT_STATE_VERSION_V2
            && version != CLIENT_STATE_VERSION_V3
            && version != CLIENT_STATE_VERSION_V4
            && version != CLIENT_STATE_VERSION_V5
        {
            return None;
        }

        let group_id = String::from_utf8(decoder.read_bytes()?).ok()?;
        let epoch = decoder.read_u64()?;
        let own_leaf_index = decoder.read_u32()? as usize;
        let tree_bytes = decoder.read_bytes()?;
        let ratchet_tree = RatchetTree::decode(&tree_bytes)?;

        let proposal_count = decoder.read_u32()? as usize;
        let mut pending_proposals = Vec::with_capacity(proposal_count);
        for _ in 0..proposal_count {
            pending_proposals.push(decoder.read_bytes()?);
        }

        let (
            last_applied_commit_id,
            recent_applied_commit_ids,
            key_schedule,
            transcript_state,
            group_context_extensions,
        ) = if version == CLIENT_STATE_VERSION_V5 {
            let has_last = decoder.read_u8()?;
            let last_applied_commit_id = match has_last {
                0 => None,
                1 => Some(decoder.read_i64()?),
                _ => return None,
            };
            let replay_count = decoder.read_u32()? as usize;
            let mut recent = Vec::with_capacity(replay_count);
            for _ in 0..replay_count {
                recent.push(decoder.read_i64()?);
            }
            let key_schedule_bytes = decoder.read_bytes()?;
            let key_schedule = KeyScheduleState::decode(&key_schedule_bytes)?;
            let transcript_bytes = decoder.read_bytes()?;
            let transcript_state = TranscriptState::decode(&transcript_bytes)?;
            let group_context_extensions = decoder.read_bytes()?;
            (
                last_applied_commit_id,
                recent,
                key_schedule,
                transcript_state,
                group_context_extensions,
            )
        } else if version == CLIENT_STATE_VERSION_V4 {
            let has_last = decoder.read_u8()?;
            let last_applied_commit_id = match has_last {
                0 => None,
                1 => Some(decoder.read_i64()?),
                _ => return None,
            };
            let replay_count = decoder.read_u32()? as usize;
            let mut recent = Vec::with_capacity(replay_count);
            for _ in 0..replay_count {
                recent.push(decoder.read_i64()?);
            }
            let key_schedule_bytes = decoder.read_bytes()?;
            let key_schedule = KeyScheduleState::decode(&key_schedule_bytes)?;
            let transcript_bytes = decoder.read_bytes()?;
            let transcript_state = TranscriptState::decode(&transcript_bytes)?;
            (
                last_applied_commit_id,
                recent,
                key_schedule,
                transcript_state,
                Vec::new(),
            )
        } else if version == CLIENT_STATE_VERSION_V3 {
            let has_last = decoder.read_u8()?;
            let last_applied_commit_id = match has_last {
                0 => None,
                1 => Some(decoder.read_i64()?),
                _ => return None,
            };
            let replay_count = decoder.read_u32()? as usize;
            let mut recent = Vec::with_capacity(replay_count);
            for _ in 0..replay_count {
                recent.push(decoder.read_i64()?);
            }
            let key_schedule_bytes = decoder.read_bytes()?;
            let key_schedule = KeyScheduleState::decode(&key_schedule_bytes)?;
            let transcript_state = TranscriptState::bootstrap_legacy(
                &group_id,
                current_tree_hash(&ratchet_tree),
                epoch,
                &[],
            );
            (
                last_applied_commit_id,
                recent,
                key_schedule,
                transcript_state,
                Vec::new(),
            )
        } else if version == CLIENT_STATE_VERSION_V2 {
            let has_last = decoder.read_u8()?;
            let last_applied_commit_id = match has_last {
                0 => None,
                1 => Some(decoder.read_i64()?),
                _ => return None,
            };
            let replay_count = decoder.read_u32()? as usize;
            let mut recent = Vec::with_capacity(replay_count);
            for _ in 0..replay_count {
                recent.push(decoder.read_i64()?);
            }
            let key_schedule = KeyScheduleState::bootstrap_to_epoch(
                &group_id,
                epoch,
                current_tree_hash(&ratchet_tree),
            );
            let transcript_state = TranscriptState::bootstrap_legacy(
                &group_id,
                current_tree_hash(&ratchet_tree),
                epoch,
                &[],
            );
            (
                last_applied_commit_id,
                recent,
                key_schedule,
                transcript_state,
                Vec::new(),
            )
        } else {
            let key_schedule = KeyScheduleState::bootstrap_to_epoch(
                &group_id,
                epoch,
                current_tree_hash(&ratchet_tree),
            );
            let transcript_state = TranscriptState::bootstrap_legacy(
                &group_id,
                current_tree_hash(&ratchet_tree),
                epoch,
                &[],
            );
            (None, Vec::new(), key_schedule, transcript_state, Vec::new())
        };

        if decoder.remaining() != 0 {
            return None;
        }

        let mut decoded = Self {
            group_id,
            ratchet_tree,
            own_leaf_index,
            epoch,
            pending_proposals,
            last_applied_commit_id,
            recent_applied_commit_ids,
            group_context_extensions,
            key_schedule,
            transcript_state,
        };
        if version == CLIENT_STATE_VERSION_V3
            || version == CLIENT_STATE_VERSION_V4
            || version == CLIENT_STATE_VERSION_V5
        {
            if decoded.ensure_key_schedule_consistency().is_err() {
                return None;
            }
        } else {
            decoded.sync_key_schedule_epoch(None, None);
        }
        if decoded.ensure_key_schedule_consistency().is_err() {
            return None;
        }
        Some(decoded)
    }

    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), ClientStateError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, self.encode())?;
        Ok(())
    }

    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, ClientStateError> {
        let bytes = fs::read(path)?;
        Self::decode(&bytes).ok_or(ClientStateError::CorruptState)
    }

    fn sync_key_schedule_epoch(
        &mut self,
        commit_context: Option<&[u8]>,
        tree_commit_secret: Option<[u8; 32]>,
    ) {
        let tree_hash = current_tree_hash(&self.ratchet_tree);
        if self.key_schedule.current_epoch > self.epoch {
            self.key_schedule =
                KeyScheduleState::bootstrap_to_epoch(&self.group_id, self.epoch, tree_hash);
        } else {
            let _ = self.key_schedule.ensure_epoch_with_tree_commit_secret(
                self.epoch,
                &self.group_id,
                tree_hash,
                commit_context,
                tree_commit_secret.as_ref(),
            );
        }
    }
}

fn current_tree_hash(tree: &RatchetTree) -> [u8; 32] {
    tree_snapshot_hash(&tree.encode())
}

fn encode_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn encode_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn encode_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn encode_i64(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    encode_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Option<u8> {
        if self.remaining() < 1 {
            return None;
        }
        let value = self.data[self.pos];
        self.pos += 1;
        Some(value)
    }

    fn read_u32(&mut self) -> Option<u32> {
        if self.remaining() < 4 {
            return None;
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 4]);
        self.pos += 4;
        Some(u32::from_be_bytes(buf))
    }

    fn read_u64(&mut self) -> Option<u64> {
        if self.remaining() < 8 {
            return None;
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        Some(u64::from_be_bytes(buf))
    }

    fn read_i64(&mut self) -> Option<i64> {
        if self.remaining() < 8 {
            return None;
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        Some(i64::from_be_bytes(buf))
    }

    fn read_bytes(&mut self) -> Option<Vec<u8>> {
        let len = self.read_u32()? as usize;
        if self.remaining() < len {
            return None;
        }
        let out = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{HybridPublicKey, HybridSignPrivKey, HybridSignPubKey, KyberPriv};
    use crate::tree::{KeyPackage, LeafNode};
    use ed25519_dalek::{SigningKey as EdSecret, VerifyingKey as EdPublic};
    use ml_dsa::{KeyGen, MlDsa65};
    use ml_kem::Seed;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};
    use x25519_dalek::{PublicKey as X25519Pub, StaticSecret as X25519Priv};

    fn hybrid_public_key(seed: u8) -> HybridPublicKey {
        let classic_priv = X25519Priv::from([seed; 32]);
        let classic_pub = X25519Pub::from(&classic_priv);

        let kem_seed = Seed::from([seed; 64]);
        let kyber_priv = KyberPriv::from_seed(kem_seed);
        let kyber_pub = kyber_priv.encapsulation_key().clone();

        HybridPublicKey {
            classic: classic_pub,
            pq: kyber_pub,
        }
    }

    fn hybrid_signing_keys(seed: u8) -> (HybridSignPubKey, HybridSignPrivKey) {
        let classic_priv = EdSecret::from_bytes(&[seed; 32]);
        let classic_pub = EdPublic::from(&classic_priv);

        let mut rng = StdRng::seed_from_u64(seed as u64);
        let kp = MlDsa65::key_gen(&mut rng);

        let pub_key = HybridSignPubKey {
            classic: classic_pub,
            pq: kp.verifying_key().clone(),
        };

        let priv_key = HybridSignPrivKey {
            classic: classic_priv,
            pq: kp.signing_key().clone(),
        };

        (pub_key, priv_key)
    }

    fn make_key_package(seed: u8) -> KeyPackage {
        let (identity, priv_key) = hybrid_signing_keys(seed);
        let init_key = hybrid_public_key(seed);
        let signature = priv_key.sign(&init_key.to_bytes());
        KeyPackage {
            identity,
            init_key,
            signature,
        }
    }

    fn make_leaf(seed: u8) -> LeafNode {
        let (identity, _) = hybrid_signing_keys(seed);
        LeafNode {
            public_key: hybrid_public_key(seed),
            credential: identity,
        }
    }

    fn encode_v1_state_for_test(state: &ClientGroupState) -> Vec<u8> {
        let mut out = Vec::new();
        encode_u8(&mut out, CLIENT_STATE_VERSION_V1);
        encode_bytes(&mut out, state.group_id.as_bytes());
        encode_u64(&mut out, state.epoch);
        encode_u32(&mut out, state.own_leaf_index as u32);
        encode_bytes(&mut out, &state.ratchet_tree.encode());
        encode_u32(&mut out, state.pending_proposals.len() as u32);
        for proposal in &state.pending_proposals {
            encode_bytes(&mut out, proposal);
        }
        out
    }

    fn encode_v2_state_for_test(state: &ClientGroupState) -> Vec<u8> {
        let mut out = Vec::new();
        encode_u8(&mut out, CLIENT_STATE_VERSION_V2);
        encode_bytes(&mut out, state.group_id.as_bytes());
        encode_u64(&mut out, state.epoch);
        encode_u32(&mut out, state.own_leaf_index as u32);
        encode_bytes(&mut out, &state.ratchet_tree.encode());
        encode_u32(&mut out, state.pending_proposals.len() as u32);
        for proposal in &state.pending_proposals {
            encode_bytes(&mut out, proposal);
        }
        match state.last_applied_commit_id {
            Some(value) => {
                encode_u8(&mut out, 1);
                encode_i64(&mut out, value);
            }
            None => encode_u8(&mut out, 0),
        }
        encode_u32(&mut out, state.recent_applied_commit_ids.len() as u32);
        for id in &state.recent_applied_commit_ids {
            encode_i64(&mut out, *id);
        }
        out
    }

    fn encode_v4_state_for_test(state: &ClientGroupState) -> Vec<u8> {
        let mut out = Vec::new();
        encode_u8(&mut out, CLIENT_STATE_VERSION_V4);
        encode_bytes(&mut out, state.group_id.as_bytes());
        encode_u64(&mut out, state.epoch);
        encode_u32(&mut out, state.own_leaf_index as u32);
        encode_bytes(&mut out, &state.ratchet_tree.encode());
        encode_u32(&mut out, state.pending_proposals.len() as u32);
        for proposal in &state.pending_proposals {
            encode_bytes(&mut out, proposal);
        }
        match state.last_applied_commit_id {
            Some(value) => {
                encode_u8(&mut out, 1);
                encode_i64(&mut out, value);
            }
            None => encode_u8(&mut out, 0),
        }
        encode_u32(&mut out, state.recent_applied_commit_ids.len() as u32);
        for id in &state.recent_applied_commit_ids {
            encode_i64(&mut out, *id);
        }
        encode_bytes(&mut out, &state.key_schedule.encode());
        encode_bytes(&mut out, &state.transcript_state.encode());
        out
    }

    #[test]
    fn client_group_state_encode_decode_roundtrip() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(1), make_leaf(2)]);
        let mut state = ClientGroupState::new("group-1", tree, 0);
        state.set_epoch(3);
        let proposal = Proposal::Add(make_key_package(3));
        state.queue_proposal(&proposal);
        state.mark_applied_commit_id(42);

        let encoded = state.encode();
        let decoded = ClientGroupState::decode(&encoded).expect("decode state");
        assert_eq!(decoded, state);

        let decoded_props = decoded
            .decoded_pending_proposals()
            .expect("decode proposals");
        assert_eq!(decoded_props.len(), 1);
        assert_eq!(decoded_props[0].encode(), proposal.encode());
    }

    #[test]
    fn client_group_state_save_load_file() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(10)]);
        let mut state = ClientGroupState::new("group-2", tree, 0);
        state.set_epoch(1);

        let path = std::env::temp_dir().join(format!(
            "hybrid-mls-client-state-{}.bin",
            rand::random::<u64>()
        ));
        state.save_to_file(&path).expect("save");
        let loaded = ClientGroupState::load_from_file(&path).expect("load");
        assert_eq!(loaded, state);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn client_group_state_rejects_corrupt_bytes() {
        let mut bytes = vec![0u8; 16];
        StdRng::seed_from_u64(42).fill_bytes(&mut bytes);
        assert!(ClientGroupState::decode(&bytes).is_none());
    }

    #[test]
    fn replay_markers_are_persisted_and_checked() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(9)]);
        let mut state = ClientGroupState::new("group-r", tree, 0);
        state.mark_applied_commit_id(10);
        state.mark_applied_commit_id(14);

        let encoded = state.encode();
        let decoded = ClientGroupState::decode(&encoded).expect("decode replay state");

        assert_eq!(decoded.last_applied_commit_id, Some(14));
        assert!(decoded.has_applied_commit_id(10));
        assert!(decoded.has_applied_commit_id(12));
        assert!(!decoded.has_applied_commit_id(15));
    }

    #[test]
    fn mark_applied_commit_id_dedups_and_keeps_bounded_window() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(7)]);
        let mut state = ClientGroupState::new("group-w", tree, 0);

        for id in 1..=(MAX_RECENT_APPLIED_COMMITS as i64 + 20) {
            state.mark_applied_commit_id(id);
        }
        state.mark_applied_commit_id(MAX_RECENT_APPLIED_COMMITS as i64 + 20);

        assert_eq!(
            state.recent_applied_commit_ids.len(),
            MAX_RECENT_APPLIED_COMMITS
        );
        assert_eq!(
            state.last_applied_commit_id,
            Some(MAX_RECENT_APPLIED_COMMITS as i64 + 20)
        );
        assert!(state.has_applied_commit_id(5));
        assert!(!state
            .recent_applied_commit_ids
            .windows(2)
            .any(|w| w[0] == w[1]));
    }

    #[test]
    fn decode_v1_state_defaults_replay_markers() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(4)]);
        let mut state = ClientGroupState::new("group-v1", tree, 0);
        state.set_epoch(2);

        let bytes = encode_v1_state_for_test(&state);
        let decoded = ClientGroupState::decode(&bytes).expect("decode v1 state");

        assert_eq!(decoded.group_id, state.group_id);
        assert_eq!(decoded.epoch, state.epoch);
        assert_eq!(decoded.last_applied_commit_id, None);
        assert!(decoded.recent_applied_commit_ids.is_empty());
        assert_eq!(decoded.key_schedule.current_epoch, state.epoch);
    }

    #[test]
    fn decode_v2_state_bootstraps_key_schedule() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(5)]);
        let mut state = ClientGroupState::new("group-v2", tree, 0);
        state.set_epoch(4);
        state.mark_applied_commit_id(11);

        let bytes = encode_v2_state_for_test(&state);
        let decoded = ClientGroupState::decode(&bytes).expect("decode v2 state");

        assert_eq!(decoded.epoch, 4);
        assert_eq!(decoded.key_schedule.current_epoch, 4);
        assert_eq!(decoded.last_applied_commit_id, Some(11));
    }

    #[test]
    fn advance_epoch_updates_key_schedule() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(6)]);
        let mut state = ClientGroupState::new("group-k", tree, 0);
        let root0 = state
            .key_schedule
            .current_root_secret()
            .expect("initial root secret");

        state.advance_epoch_with_context(Some(b"commit-epoch-1"));
        let root1 = state
            .key_schedule
            .current_root_secret()
            .expect("root secret epoch 1");

        assert_eq!(state.epoch, 1);
        assert_eq!(state.key_schedule.current_epoch, 1);
        assert_ne!(root0, root1);
    }

    #[test]
    fn advance_epoch_with_tree_commit_secret_changes_key_schedule_chain() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(16)]);
        let mut default_state = ClientGroupState::new("group-lineage-state", tree.clone(), 0);
        let mut lineage_state = ClientGroupState::new("group-lineage-state", tree, 0);
        let tree_commit_secret = [0x3Cu8; 32];

        default_state.advance_epoch_with_context(Some(b"commit-lineage-1"));
        lineage_state.advance_epoch_with_context_and_tree_commit_secret(
            Some(b"commit-lineage-1"),
            Some(tree_commit_secret),
        );

        let default_chain = default_state
            .key_schedule
            .chain_secrets_for_epoch(1)
            .expect("default epoch 1 chain");
        let lineage_chain = lineage_state
            .key_schedule
            .chain_secrets_for_epoch(1)
            .expect("lineage epoch 1 chain");

        assert_ne!(default_chain.commit_secret, lineage_chain.commit_secret);
        assert_ne!(default_chain.joiner_secret, lineage_chain.joiner_secret);
        assert_ne!(default_chain.root_secret, lineage_chain.root_secret);
    }

    #[test]
    fn current_epoch_derived_secrets_rotate_across_epoch_advance() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(8)]);
        let mut state = ClientGroupState::new("group-secrets", tree, 0);
        let epoch0 = state
            .current_epoch_derived_secrets()
            .expect("epoch 0 derived secrets");

        state.advance_epoch_with_context(Some(b"commit-secrets-1"));
        let epoch1 = state
            .current_epoch_derived_secrets()
            .expect("epoch 1 derived secrets");

        assert_eq!(epoch0.epoch, 0);
        assert_eq!(epoch1.epoch, 1);
        assert_ne!(epoch0.handshake_secret, epoch1.handshake_secret);
        assert_ne!(epoch0.application_secret, epoch1.application_secret);
        assert_ne!(epoch0.exporter_secret, epoch1.exporter_secret);
    }

    #[test]
    fn current_membership_key_rotates_across_epoch_advance() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(13)]);
        let mut state = ClientGroupState::new("group-membership", tree, 0);
        let key0 = state
            .current_membership_key()
            .expect("membership key epoch 0");

        state.advance_epoch_with_context(Some(b"commit-membership-1"));
        let key1 = state
            .current_membership_key()
            .expect("membership key epoch 1");

        assert_ne!(key0, key1);
    }

    #[test]
    fn current_confirmation_and_sender_data_keys_rotate_across_epoch_advance() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(15)]);
        let mut state = ClientGroupState::new("group-stage-keys", tree, 0);
        let confirmation0 = state
            .current_confirmation_key()
            .expect("confirmation key epoch 0");
        let sender_data0 = state
            .current_sender_data_key()
            .expect("sender-data key epoch 0");

        state.advance_epoch_with_context(Some(b"commit-stage-1"));
        let confirmation1 = state
            .current_confirmation_key()
            .expect("confirmation key epoch 1");
        let sender_data1 = state
            .current_sender_data_key()
            .expect("sender-data key epoch 1");

        assert_ne!(confirmation0, confirmation1);
        assert_ne!(sender_data0, sender_data1);
        assert_ne!(confirmation0, sender_data0);
    }

    #[test]
    fn apply_group_context_extensions_from_proposals_updates_state() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(14)]);
        let mut state = ClientGroupState::new("group-gce", tree, 0);
        assert!(state.group_context_extensions.is_empty());

        let proposals = vec![
            Proposal::PreSharedKey {
                psk_id: b"psk-ref".to_vec(),
            },
            Proposal::GroupContextExtensions {
                extensions: vec![0xAA, 0xBB, 0xCC],
            },
        ];
        state.apply_group_context_extensions_from_proposals(&proposals);
        assert_eq!(state.group_context_extensions, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn decode_v4_state_defaults_group_context_extensions() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(15)]);
        let mut state = ClientGroupState::new("group-v4", tree, 0);
        state.set_epoch(2);
        state.group_context_extensions = vec![0x01, 0x02];

        let bytes = encode_v4_state_for_test(&state);
        let decoded = ClientGroupState::decode(&bytes).expect("decode v4 state");
        assert_eq!(decoded.epoch, 2);
        assert!(decoded.group_context_extensions.is_empty());
    }

    #[test]
    fn decode_v3_rejects_key_schedule_epoch_mismatch() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(11)]);
        let mut state = ClientGroupState::new("group-v3-mismatch", tree, 0);
        state.set_epoch(2);
        state.key_schedule.current_epoch = 1;

        let bytes = state.encode();
        assert!(ClientGroupState::decode(&bytes).is_none());
    }

    #[test]
    fn ensure_key_schedule_consistency_rejects_malformed_chain() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(12)]);
        let mut state = ClientGroupState::new("group-malformed-ks", tree, 0);
        state.set_epoch(2);
        state.key_schedule.epoch_secret_nodes[2].parent_epoch = Some(0);

        assert!(state.ensure_key_schedule_consistency().is_err());
    }
}
