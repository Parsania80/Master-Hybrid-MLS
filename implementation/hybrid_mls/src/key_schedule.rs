use sha3::{Digest, Sha3_256};

use crate::stage_keys::derive_epoch_stage_keys;

const KEY_SCHEDULE_STATE_VERSION_V1: u8 = 1;
const KEY_SCHEDULE_STATE_VERSION_V2: u8 = 2;
const KEY_SCHEDULE_STATE_VERSION: u8 = KEY_SCHEDULE_STATE_VERSION_V2;

#[derive(Clone, Debug, PartialEq)]
pub struct EpochSecretNode {
    pub epoch: u64,
    pub parent_epoch: Option<u64>,
    pub commit_secret: [u8; 32],
    pub joiner_secret: [u8; 32],
    pub welcome_secret: [u8; 32],
    pub epoch_secret: [u8; 32],
    pub root_secret: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochChainSecrets {
    pub epoch: u64,
    pub commit_secret: [u8; 32],
    pub joiner_secret: [u8; 32],
    pub welcome_secret: [u8; 32],
    pub epoch_secret: [u8; 32],
    pub root_secret: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochDerivedSecrets {
    pub epoch: u64,
    pub confirmation_key: [u8; 32],
    pub membership_key: [u8; 32],
    pub sender_data_key: [u8; 32],
    pub handshake_secret: [u8; 32],
    pub application_secret: [u8; 32],
    pub exporter_secret: [u8; 32],
}

#[derive(Clone, Debug, PartialEq)]
pub struct KeyScheduleState {
    pub current_epoch: u64,
    pub init_secret: [u8; 32],
    pub epoch_secret_nodes: Vec<EpochSecretNode>,
}

impl KeyScheduleState {
    pub fn new(group_id: &str, tree_hash: [u8; 32]) -> Self {
        let init_secret = labeled_hash(
            b"init epoch secret",
            group_id.as_bytes(),
            &[group_id.as_bytes(), &tree_hash],
        );
        let epoch0 = derive_epoch_chain_secrets(&init_secret, group_id, 0, &tree_hash, None);
        Self {
            current_epoch: 0,
            init_secret,
            epoch_secret_nodes: vec![EpochSecretNode {
                epoch: 0,
                parent_epoch: None,
                commit_secret: epoch0.commit_secret,
                joiner_secret: epoch0.joiner_secret,
                welcome_secret: epoch0.welcome_secret,
                epoch_secret: epoch0.epoch_secret,
                root_secret: epoch0.root_secret,
            }],
        }
    }

    pub fn bootstrap_to_epoch(group_id: &str, epoch: u64, tree_hash: [u8; 32]) -> Self {
        let mut state = Self::new(group_id, tree_hash);
        state.ensure_epoch(epoch, group_id, tree_hash, None);
        state
    }

    pub fn current_root_secret(&self) -> Option<[u8; 32]> {
        self.epoch_secret_nodes.last().map(|node| node.root_secret)
    }

    pub fn root_secret_for_epoch(&self, epoch: u64) -> Option<[u8; 32]> {
        self.epoch_secret_nodes
            .iter()
            .find(|node| node.epoch == epoch)
            .map(|node| node.root_secret)
    }

    pub fn derive_secrets_for_epoch(
        &self,
        group_id: &str,
        epoch: u64,
    ) -> Option<EpochDerivedSecrets> {
        let node = self
            .epoch_secret_nodes
            .iter()
            .find(|node| node.epoch == epoch)?;
        Some(derive_epoch_secrets(&node.epoch_secret, group_id, epoch))
    }

    pub fn derive_current_epoch_secrets(&self, group_id: &str) -> Option<EpochDerivedSecrets> {
        self.derive_secrets_for_epoch(group_id, self.current_epoch)
    }

    pub fn chain_secrets_for_epoch(&self, epoch: u64) -> Option<EpochChainSecrets> {
        self.epoch_secret_nodes
            .iter()
            .find(|node| node.epoch == epoch)
            .map(|node| EpochChainSecrets {
                epoch,
                commit_secret: node.commit_secret,
                joiner_secret: node.joiner_secret,
                welcome_secret: node.welcome_secret,
                epoch_secret: node.epoch_secret,
                root_secret: node.root_secret,
            })
    }

    pub fn is_well_formed(&self) -> bool {
        if self.epoch_secret_nodes.is_empty() {
            return false;
        }
        let first = &self.epoch_secret_nodes[0];
        if first.epoch != 0 || first.parent_epoch.is_some() {
            return false;
        }
        for pair in self.epoch_secret_nodes.windows(2) {
            let prev = &pair[0];
            let next = &pair[1];
            if next.epoch != prev.epoch.saturating_add(1) {
                return false;
            }
            if next.parent_epoch != Some(prev.epoch) {
                return false;
            }
        }
        match self.epoch_secret_nodes.last() {
            Some(last) => last.epoch == self.current_epoch,
            None => false,
        }
    }

    pub fn is_epoch_aligned(&self, epoch: u64) -> bool {
        self.current_epoch == epoch
            && self
                .epoch_secret_nodes
                .last()
                .map(|node| node.epoch == epoch)
                .unwrap_or(false)
            && self.root_secret_for_epoch(epoch).is_some()
    }

    pub fn ensure_epoch(
        &mut self,
        target_epoch: u64,
        group_id: &str,
        tree_hash: [u8; 32],
        commit_context: Option<&[u8]>,
    ) -> [u8; 32] {
        while self.current_epoch < target_epoch {
            let previous_root = self.current_root_secret().unwrap_or(self.init_secret);
            let next_epoch = self.current_epoch.saturating_add(1);
            let next_chain = derive_epoch_chain_secrets(
                &previous_root,
                group_id,
                next_epoch,
                &tree_hash,
                commit_context,
            );

            self.epoch_secret_nodes.push(EpochSecretNode {
                epoch: next_epoch,
                parent_epoch: Some(self.current_epoch),
                commit_secret: next_chain.commit_secret,
                joiner_secret: next_chain.joiner_secret,
                welcome_secret: next_chain.welcome_secret,
                epoch_secret: next_chain.epoch_secret,
                root_secret: next_chain.root_secret,
            });
            self.current_epoch = next_epoch;
        }

        self.current_root_secret().unwrap_or(self.init_secret)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_u8(&mut out, KEY_SCHEDULE_STATE_VERSION);
        encode_u64(&mut out, self.current_epoch);
        out.extend_from_slice(&self.init_secret);

        encode_u32(&mut out, self.epoch_secret_nodes.len() as u32);
        for node in &self.epoch_secret_nodes {
            encode_u64(&mut out, node.epoch);
            match node.parent_epoch {
                Some(parent) => {
                    encode_u8(&mut out, 1);
                    encode_u64(&mut out, parent);
                }
                None => encode_u8(&mut out, 0),
            }
            out.extend_from_slice(&node.commit_secret);
            out.extend_from_slice(&node.joiner_secret);
            out.extend_from_slice(&node.welcome_secret);
            out.extend_from_slice(&node.epoch_secret);
            out.extend_from_slice(&node.root_secret);
        }

        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.read_u8()?;
        if version != KEY_SCHEDULE_STATE_VERSION_V1 && version != KEY_SCHEDULE_STATE_VERSION_V2 {
            return None;
        }

        let current_epoch = decoder.read_u64()?;
        let init_secret = decoder.read_array_32()?;
        let node_count = decoder.read_u32()? as usize;
        if node_count == 0 {
            return None;
        }

        let mut epoch_secret_nodes = Vec::with_capacity(node_count);
        for _ in 0..node_count {
            let epoch = decoder.read_u64()?;
            let parent_epoch = match decoder.read_u8()? {
                0 => None,
                1 => Some(decoder.read_u64()?),
                _ => return None,
            };
            let (commit_secret, joiner_secret, welcome_secret, epoch_secret, root_secret) =
                if version == KEY_SCHEDULE_STATE_VERSION_V2 {
                    (
                        decoder.read_array_32()?,
                        decoder.read_array_32()?,
                        decoder.read_array_32()?,
                        decoder.read_array_32()?,
                        decoder.read_array_32()?,
                    )
                } else {
                    let root_secret = decoder.read_array_32()?;
                    let legacy = derive_legacy_chain_from_root(&root_secret, epoch);
                    (
                        legacy.commit_secret,
                        legacy.joiner_secret,
                        legacy.welcome_secret,
                        legacy.epoch_secret,
                        root_secret,
                    )
                };
            epoch_secret_nodes.push(EpochSecretNode {
                epoch,
                parent_epoch,
                commit_secret,
                joiner_secret,
                welcome_secret,
                epoch_secret,
                root_secret,
            });
        }

        if decoder.remaining() != 0 {
            return None;
        }

        let last = epoch_secret_nodes.last()?;
        if last.epoch != current_epoch {
            return None;
        }

        Some(Self {
            current_epoch,
            init_secret,
            epoch_secret_nodes,
        })
    }
}

pub fn tree_snapshot_hash(tree_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(tree_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn derive_epoch_secrets(
    epoch_secret: &[u8; 32],
    group_id: &str,
    epoch: u64,
) -> EpochDerivedSecrets {
    let mut epoch_bytes = [0u8; 8];
    epoch_bytes.copy_from_slice(&epoch.to_be_bytes());
    let context = group_id.as_bytes();

    let stage_keys = derive_epoch_stage_keys(epoch_secret);
    let handshake_secret =
        labeled_hash(b"handshake secret", context, &[epoch_secret, &epoch_bytes]);
    let application_secret = labeled_hash(
        b"application secret",
        context,
        &[epoch_secret, &epoch_bytes],
    );
    let exporter_secret = labeled_hash(b"exporter secret", context, &[epoch_secret, &epoch_bytes]);

    EpochDerivedSecrets {
        epoch,
        confirmation_key: stage_keys.confirmation_key,
        membership_key: stage_keys.membership_key,
        sender_data_key: stage_keys.sender_data_key,
        handshake_secret,
        application_secret,
        exporter_secret,
    }
}

fn derive_epoch_chain_secrets(
    previous_root_secret: &[u8; 32],
    group_id: &str,
    epoch: u64,
    tree_hash: &[u8; 32],
    commit_context: Option<&[u8]>,
) -> EpochChainSecrets {
    let mut epoch_bytes = [0u8; 8];
    epoch_bytes.copy_from_slice(&epoch.to_be_bytes());
    let commit_secret = labeled_hash(
        b"commit secret",
        group_id.as_bytes(),
        &[
            previous_root_secret,
            &epoch_bytes,
            tree_hash,
            commit_context.unwrap_or(&[]),
        ],
    );
    let joiner_secret = labeled_hash(
        b"joiner secret",
        group_id.as_bytes(),
        &[previous_root_secret, &commit_secret, &epoch_bytes],
    );
    let welcome_secret = labeled_hash(
        b"welcome secret",
        group_id.as_bytes(),
        &[&joiner_secret, tree_hash, commit_context.unwrap_or(&[])],
    );
    let epoch_secret = labeled_hash(
        b"epoch secret",
        group_id.as_bytes(),
        &[&joiner_secret, tree_hash, &epoch_bytes],
    );
    let root_secret = labeled_hash(
        b"epoch root secret",
        group_id.as_bytes(),
        &[&epoch_secret, &welcome_secret, &epoch_bytes],
    );

    EpochChainSecrets {
        epoch,
        commit_secret,
        joiner_secret,
        welcome_secret,
        epoch_secret,
        root_secret,
    }
}

fn derive_legacy_chain_from_root(root_secret: &[u8; 32], epoch: u64) -> EpochChainSecrets {
    let mut epoch_bytes = [0u8; 8];
    epoch_bytes.copy_from_slice(&epoch.to_be_bytes());

    let commit_secret = labeled_hash(
        b"legacy commit secret",
        b"legacy-key-schedule",
        &[root_secret, &epoch_bytes],
    );
    let joiner_secret = labeled_hash(
        b"legacy joiner secret",
        b"legacy-key-schedule",
        &[root_secret, &epoch_bytes],
    );
    let welcome_secret = labeled_hash(
        b"legacy welcome secret",
        b"legacy-key-schedule",
        &[root_secret, &epoch_bytes],
    );
    let epoch_secret = labeled_hash(
        b"legacy epoch secret",
        b"legacy-key-schedule",
        &[root_secret, &epoch_bytes],
    );

    EpochChainSecrets {
        epoch,
        commit_secret,
        joiner_secret,
        welcome_secret,
        epoch_secret,
        root_secret: *root_secret,
    }
}

fn labeled_hash(label: &[u8], context: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut input = Vec::new();
    encode_u32_prefixed(&mut input, b"MLS 1.0");
    encode_u32_prefixed(&mut input, label);
    encode_u32_prefixed(&mut input, context);
    for part in parts {
        encode_u32_prefixed(&mut input, part);
    }

    let mut hasher = Sha3_256::new();
    hasher.update(&input);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
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

fn encode_u32_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
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
        let out = self.data[self.pos];
        self.pos += 1;
        Some(out)
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

    fn read_array_32(&mut self) -> Option<[u8; 32]> {
        if self.remaining() < 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.data[self.pos..self.pos + 32]);
        self.pos += 32;
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_schedule_roundtrip() {
        let tree_hash = tree_snapshot_hash(b"tree-v1");
        let mut state = KeyScheduleState::new("group-a", tree_hash);
        state.ensure_epoch(3, "group-a", tree_hash, Some(b"commit-3"));

        let encoded = state.encode();
        let decoded = KeyScheduleState::decode(&encoded).expect("decode key schedule");
        assert_eq!(decoded, state);
    }

    #[test]
    fn key_schedule_epoch_chain_has_parent_links() {
        let tree_hash = tree_snapshot_hash(b"tree-v2");
        let mut state = KeyScheduleState::new("group-b", tree_hash);
        let root0 = state.current_root_secret().expect("epoch0 root");

        let root2 = state.ensure_epoch(2, "group-b", tree_hash, Some(b"commit-2"));
        assert_ne!(root0, root2);
        assert_eq!(state.current_epoch, 2);
        assert_eq!(state.epoch_secret_nodes.len(), 3);
        assert_eq!(state.epoch_secret_nodes[1].parent_epoch, Some(0));
        assert_eq!(state.epoch_secret_nodes[2].parent_epoch, Some(1));
    }

    #[test]
    fn bootstrap_to_epoch_matches_target_epoch() {
        let tree_hash = tree_snapshot_hash(b"tree-v3");
        let state = KeyScheduleState::bootstrap_to_epoch("group-c", 5, tree_hash);
        assert_eq!(state.current_epoch, 5);
        assert_eq!(state.epoch_secret_nodes.last().expect("last").epoch, 5);
    }

    #[test]
    fn decode_rejects_mismatched_current_epoch() {
        let tree_hash = tree_snapshot_hash(b"tree-v4");
        let state = KeyScheduleState::new("group-d", tree_hash);
        let mut encoded = state.encode();

        // Mutate current_epoch field while keeping node list unchanged.
        encoded[1..9].copy_from_slice(&7u64.to_be_bytes());
        assert!(KeyScheduleState::decode(&encoded).is_none());
    }

    #[test]
    fn derive_current_epoch_secrets_are_domain_separated() {
        let tree_hash = tree_snapshot_hash(b"tree-v5");
        let state = KeyScheduleState::new("group-e", tree_hash);
        let secrets = state
            .derive_current_epoch_secrets("group-e")
            .expect("derive current epoch secrets");

        assert_ne!(secrets.handshake_secret, secrets.application_secret);
        assert_ne!(secrets.handshake_secret, secrets.exporter_secret);
        assert_ne!(secrets.application_secret, secrets.exporter_secret);
        assert_ne!(secrets.confirmation_key, secrets.membership_key);
        assert_ne!(secrets.confirmation_key, secrets.sender_data_key);
        assert_ne!(secrets.membership_key, secrets.sender_data_key);
    }

    #[test]
    fn derive_epoch_secrets_change_across_epochs() {
        let tree_hash = tree_snapshot_hash(b"tree-v6");
        let mut state = KeyScheduleState::new("group-f", tree_hash);
        let epoch0 = state
            .derive_current_epoch_secrets("group-f")
            .expect("derive epoch 0 secrets");
        state.ensure_epoch(1, "group-f", tree_hash, Some(b"commit-1"));
        let epoch1 = state
            .derive_current_epoch_secrets("group-f")
            .expect("derive epoch 1 secrets");

        assert_ne!(epoch0.handshake_secret, epoch1.handshake_secret);
        assert_ne!(epoch0.application_secret, epoch1.application_secret);
        assert_ne!(epoch0.exporter_secret, epoch1.exporter_secret);
        assert_ne!(epoch0.confirmation_key, epoch1.confirmation_key);
        assert_ne!(epoch0.membership_key, epoch1.membership_key);
        assert_ne!(epoch0.sender_data_key, epoch1.sender_data_key);
    }

    #[test]
    fn derive_secrets_for_missing_epoch_returns_none() {
        let tree_hash = tree_snapshot_hash(b"tree-v7");
        let state = KeyScheduleState::new("group-g", tree_hash);
        assert!(state.derive_secrets_for_epoch("group-g", 9).is_none());
    }

    #[test]
    fn malformed_epoch_chain_is_detected() {
        let tree_hash = tree_snapshot_hash(b"tree-v8");
        let mut state = KeyScheduleState::bootstrap_to_epoch("group-h", 2, tree_hash);
        assert!(state.is_well_formed());

        // Break parent linkage.
        state.epoch_secret_nodes[2].parent_epoch = Some(0);
        assert!(!state.is_well_formed());
    }

    #[test]
    fn epoch_alignment_detects_mismatch() {
        let tree_hash = tree_snapshot_hash(b"tree-v9");
        let state = KeyScheduleState::bootstrap_to_epoch("group-i", 2, tree_hash);
        assert!(state.is_epoch_aligned(2));
        assert!(!state.is_epoch_aligned(1));
    }

    #[test]
    fn chain_secrets_for_epoch_are_available_and_distinct() {
        let tree_hash = tree_snapshot_hash(b"tree-v10");
        let mut state = KeyScheduleState::new("group-j", tree_hash);
        state.ensure_epoch(2, "group-j", tree_hash, Some(b"commit-2"));

        let chain = state.chain_secrets_for_epoch(2).expect("chain epoch 2");
        assert_eq!(chain.epoch, 2);
        assert_ne!(chain.commit_secret, chain.joiner_secret);
        assert_ne!(chain.joiner_secret, chain.welcome_secret);
        assert_ne!(chain.welcome_secret, chain.epoch_secret);
        assert_ne!(chain.epoch_secret, chain.root_secret);
    }

    #[test]
    fn decode_v1_payload_derives_legacy_chain_fields() {
        let tree_hash = tree_snapshot_hash(b"tree-v11");
        let mut state = KeyScheduleState::new("group-k", tree_hash);
        state.ensure_epoch(1, "group-k", tree_hash, Some(b"commit-1"));

        // Build a v1 payload (root_secret only per node) and ensure v2 decoder accepts it.
        let mut v1 = Vec::new();
        encode_u8(&mut v1, KEY_SCHEDULE_STATE_VERSION_V1);
        encode_u64(&mut v1, state.current_epoch);
        v1.extend_from_slice(&state.init_secret);
        encode_u32(&mut v1, state.epoch_secret_nodes.len() as u32);
        for node in &state.epoch_secret_nodes {
            encode_u64(&mut v1, node.epoch);
            match node.parent_epoch {
                Some(parent) => {
                    encode_u8(&mut v1, 1);
                    encode_u64(&mut v1, parent);
                }
                None => encode_u8(&mut v1, 0),
            }
            v1.extend_from_slice(&node.root_secret);
        }

        let decoded = KeyScheduleState::decode(&v1).expect("decode v1 payload");
        assert_eq!(decoded.current_epoch, state.current_epoch);
        assert_eq!(
            decoded.root_secret_for_epoch(1),
            state.root_secret_for_epoch(1)
        );
        let chain = decoded.chain_secrets_for_epoch(1).expect("chain epoch 1");
        assert_ne!(chain.commit_secret, [0u8; 32]);
        assert_ne!(chain.epoch_secret, [0u8; 32]);
    }

    fn hex(bytes: &[u8; 32]) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }

    #[test]
    fn deterministic_vector_alpha_matches_expected() {
        let tree_hash = tree_snapshot_hash(b"vector-tree-alpha");
        let mut state = KeyScheduleState::new("vector-group-alpha", tree_hash);
        state.ensure_epoch(1, "vector-group-alpha", tree_hash, Some(b"vector-commit-1"));
        state.ensure_epoch(2, "vector-group-alpha", tree_hash, Some(b"vector-commit-2"));

        let d0 = state
            .derive_secrets_for_epoch("vector-group-alpha", 0)
            .expect("epoch 0 secrets");
        let d2 = state
            .derive_secrets_for_epoch("vector-group-alpha", 2)
            .expect("epoch 2 secrets");

        assert_eq!(
            hex(&state.init_secret),
            "e85bc51861c301f5bd2acd2092c0986555235b6895f312765b17766f7f9c2a1b"
        );
        assert_eq!(
            hex(&state.root_secret_for_epoch(0).expect("root0")),
            "f1f9e85e90d099083e5ce741615efae80b07e12f8d29f3cf673dca0aee438f7f"
        );
        assert_eq!(
            hex(&d0.handshake_secret),
            "9522945d421806c4e6ae7e5c54830c161cdd97f1368867f8ba84cfe56d47c5ba"
        );
        assert_eq!(
            hex(&d0.application_secret),
            "4fd7d517d054f868bb0899b49a7e131b5cc1ece75e9b80091468d56ae8408783"
        );
        assert_eq!(
            hex(&d0.exporter_secret),
            "abd01a6adcc9059b7fc72d506445a8c3d1458357a89f4b1ebcf59b8f60cab088"
        );
        assert_eq!(
            hex(&d0.confirmation_key),
            "543fadabcf5ed8c9aa352e3d7b52e5ab34965c1bbb58fdfd17bfa9aed4d48dda"
        );
        assert_eq!(
            hex(&d0.membership_key),
            "91ae0e1c85cebc977b3d1295934580648f4bfaa7b66ba71ca4f384839d985e04"
        );
        assert_eq!(
            hex(&d0.sender_data_key),
            "4ca630a2875f182a12a32c6f7184e7029315a0bbf5d487103b3e4722cf084982"
        );
        assert_eq!(
            hex(&state.root_secret_for_epoch(1).expect("root1")),
            "f7179da6831f4ba24ca5402650b78da96a29e97f7591fa2cfa73ec4b8d824e17"
        );
        assert_eq!(
            hex(&state.root_secret_for_epoch(2).expect("root2")),
            "527b0ee420c280382e239c13014495aa0d18ec1c78514eb0435e670abca73907"
        );
        assert_eq!(
            hex(&d2.handshake_secret),
            "03c9a9520c490e3c53bdf843add05c2d40c2ccfb21f5ba9a4c4791b3e23c1d9c"
        );
        assert_eq!(
            hex(&d2.application_secret),
            "7639cf87698f845cab1ca698b0d6980d4932018353dc64270e6ee3819779a262"
        );
        assert_eq!(
            hex(&d2.exporter_secret),
            "c6c10a5ae039687ae1e104d6a796db0ea1c0bc1c1dcd39481f0e6bc293a434ee"
        );
        assert_eq!(
            hex(&d2.confirmation_key),
            "ab2ecab454675943370799e853d0717d055f4aaf5aee3a512a85e8b68fa586f4"
        );
        assert_eq!(
            hex(&d2.membership_key),
            "0e764544e5e431cd567c39f2339cda72e0db2d821cee12d4523d27003c5484a2"
        );
        assert_eq!(
            hex(&d2.sender_data_key),
            "426ffd3c25eb869798bb75104ae11e51988a3740509438f6ee2831844ff9f329"
        );
    }

    #[test]
    fn deterministic_vector_beta_matches_expected() {
        let tree_hash = tree_snapshot_hash(b"vector-tree-beta");
        let state = KeyScheduleState::bootstrap_to_epoch("vector-group-beta", 3, tree_hash);
        let d3 = state
            .derive_secrets_for_epoch("vector-group-beta", 3)
            .expect("epoch 3 secrets");

        assert_eq!(
            hex(&state.init_secret),
            "ce7edeb7c83380b91d29a304ec5c8ed8ec8a7961dcaa07c93bbc12819d69d614"
        );
        assert_eq!(
            hex(&state.root_secret_for_epoch(3).expect("root3")),
            "6336e929e94630af689e464743e1700476e938cff538e1e898a11ff69bdb7512"
        );
        assert_eq!(
            hex(&d3.handshake_secret),
            "cc2a4e706046d8dc8270d2088c74bf2838cb85b2dd9064c5eaf19153f04c29d3"
        );
        assert_eq!(
            hex(&d3.application_secret),
            "0b0523de96b48fecc4e80a7e06b65ecfd5dafb9d37f7865e704a62e6c30253a6"
        );
        assert_eq!(
            hex(&d3.exporter_secret),
            "ebc7bf606ca4e64a73597cc3d724cb5311b0777cbd7bd6e13b1e1c64ead78dc5"
        );
        assert_eq!(
            hex(&d3.confirmation_key),
            "9625ba97a0f4d47c88746c4b87dfdc4c5fb53e8f6ae9e657911c62e6dc1bd9ce"
        );
        assert_eq!(
            hex(&d3.membership_key),
            "0c08b5ca7f793a75641a124ac583cdd77fcecd252c35125df8b4c81c6b00ad28"
        );
        assert_eq!(
            hex(&d3.sender_data_key),
            "2377b9b44c4c938e8c31c5320b0e0fe68d74601e6eec1b08b16a21f1254a9919"
        );
    }
}
