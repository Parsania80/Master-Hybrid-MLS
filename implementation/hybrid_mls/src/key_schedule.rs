use sha3::{Digest, Sha3_256};

const KEY_SCHEDULE_STATE_VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq)]
pub struct EpochSecretNode {
    pub epoch: u64,
    pub parent_epoch: Option<u64>,
    pub root_secret: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochDerivedSecrets {
    pub epoch: u64,
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
        let epoch0 = derive_epoch_root_secret(&init_secret, group_id, 0, &tree_hash, None);
        Self {
            current_epoch: 0,
            init_secret,
            epoch_secret_nodes: vec![EpochSecretNode {
                epoch: 0,
                parent_epoch: None,
                root_secret: epoch0,
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
        let root_secret = self.root_secret_for_epoch(epoch)?;
        Some(derive_epoch_secrets(&root_secret, group_id, epoch))
    }

    pub fn derive_current_epoch_secrets(&self, group_id: &str) -> Option<EpochDerivedSecrets> {
        self.derive_secrets_for_epoch(group_id, self.current_epoch)
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
            let previous_root = self
                .current_root_secret()
                .unwrap_or(self.init_secret);
            let next_epoch = self.current_epoch.saturating_add(1);
            let next_root = derive_epoch_root_secret(
                &previous_root,
                group_id,
                next_epoch,
                &tree_hash,
                commit_context,
            );

            self.epoch_secret_nodes.push(EpochSecretNode {
                epoch: next_epoch,
                parent_epoch: Some(self.current_epoch),
                root_secret: next_root,
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
            out.extend_from_slice(&node.root_secret);
        }

        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        if decoder.read_u8()? != KEY_SCHEDULE_STATE_VERSION {
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
            let root_secret = decoder.read_array_32()?;
            epoch_secret_nodes.push(EpochSecretNode {
                epoch,
                parent_epoch,
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
    root_secret: &[u8; 32],
    group_id: &str,
    epoch: u64,
) -> EpochDerivedSecrets {
    let mut epoch_bytes = [0u8; 8];
    epoch_bytes.copy_from_slice(&epoch.to_be_bytes());
    let context = group_id.as_bytes();

    let handshake_secret = labeled_hash(
        b"handshake secret",
        context,
        &[root_secret, &epoch_bytes],
    );
    let application_secret = labeled_hash(
        b"application secret",
        context,
        &[root_secret, &epoch_bytes],
    );
    let exporter_secret = labeled_hash(
        b"exporter secret",
        context,
        &[root_secret, &epoch_bytes],
    );

    EpochDerivedSecrets {
        epoch,
        handshake_secret,
        application_secret,
        exporter_secret,
    }
}

fn derive_epoch_root_secret(
    previous_root_secret: &[u8; 32],
    group_id: &str,
    epoch: u64,
    tree_hash: &[u8; 32],
    commit_context: Option<&[u8]>,
) -> [u8; 32] {
    let mut epoch_bytes = [0u8; 8];
    epoch_bytes.copy_from_slice(&epoch.to_be_bytes());
    labeled_hash(
        b"epoch root secret",
        group_id.as_bytes(),
        &[
            previous_root_secret,
            &epoch_bytes,
            tree_hash,
            commit_context.unwrap_or(&[]),
        ],
    )
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

    fn hex(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()
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
            "d4a2ba3b7e2101f02579eaf189b0d68619a49a3f801cb94ca8e31ffb27351fe6"
        );
        assert_eq!(
            hex(&d0.handshake_secret),
            "aa54c307e1be9ef80f84009fa472c92a786d27d3f37673f3be9aa6b5e9247e31"
        );
        assert_eq!(
            hex(&d0.application_secret),
            "d915900693c828c9536b6a8a3d3a173e5a776267764a64a2fb1fed643734b130"
        );
        assert_eq!(
            hex(&d0.exporter_secret),
            "62962cf8d0b08e4143ea12fc6d8845ed8e5b84b6c21def2817dbc7a734fe5a29"
        );
        assert_eq!(
            hex(&state.root_secret_for_epoch(1).expect("root1")),
            "159a68d413e5c6632763bf70bd7bbf8be10e5687a96c0d075a4254641a81cbd8"
        );
        assert_eq!(
            hex(&state.root_secret_for_epoch(2).expect("root2")),
            "59de63ac6d94f01dfb02463162950760f402447f5be9635e2583de4dd569db53"
        );
        assert_eq!(
            hex(&d2.handshake_secret),
            "13d65b91130b0f8479a642fc6ec8fd75715d1d4427d6b872a5551874cc744919"
        );
        assert_eq!(
            hex(&d2.application_secret),
            "dea337f36efa4265a7ccdfe6aa5dddf53a87bbef6f8c266a51d9ebbf8f71a356"
        );
        assert_eq!(
            hex(&d2.exporter_secret),
            "bce09f8ab414734dd27a81ada26cde1cfcef5ef61f45817b112fd51f220ed864"
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
            "03a5b4db55b4c622cf8325121353fb530f8d21f2591871ddc53c43480d42cdf9"
        );
        assert_eq!(
            hex(&d3.handshake_secret),
            "f619690601d29f4d1a0552dfdacf76558e37cf731f9258d63adc223a03c9e78e"
        );
        assert_eq!(
            hex(&d3.application_secret),
            "7a4e194c4d57acd6bb8baf585f9cc48af35365800c40401d0d800986e818c2f6"
        );
        assert_eq!(
            hex(&d3.exporter_secret),
            "1c8dac88e4e6cd89da33566e5ddafbc110ecceb030265dfb19e75aff48bc77ab"
        );
    }
}
