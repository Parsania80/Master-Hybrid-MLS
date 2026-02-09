use crate::tree::{Proposal, RatchetTree};
use std::fs;
use std::path::Path;
use thiserror::Error;

const CLIENT_STATE_VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq)]
pub struct ClientGroupState {
    pub group_id: String,
    pub ratchet_tree: RatchetTree,
    pub own_leaf_index: usize,
    pub epoch: u64,
    pub pending_proposals: Vec<Vec<u8>>,
}

#[derive(Debug, Error)]
pub enum ClientStateError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("corrupt client state")]
    CorruptState,
}

impl ClientGroupState {
    pub fn new(group_id: impl Into<String>, ratchet_tree: RatchetTree, own_leaf_index: usize) -> Self {
        Self {
            group_id: group_id.into(),
            ratchet_tree,
            own_leaf_index,
            epoch: 0,
            pending_proposals: Vec::new(),
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
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        if decoder.read_u8()? != CLIENT_STATE_VERSION {
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

        if decoder.remaining() != 0 {
            return None;
        }

        Some(Self {
            group_id,
            ratchet_tree,
            own_leaf_index,
            epoch,
            pending_proposals,
        })
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

    #[test]
    fn client_group_state_encode_decode_roundtrip() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(1), make_leaf(2)]);
        let mut state = ClientGroupState::new("group-1", tree, 0);
        state.epoch = 3;
        let proposal = Proposal::Add(make_key_package(3));
        state.queue_proposal(&proposal);

        let encoded = state.encode();
        let decoded = ClientGroupState::decode(&encoded).expect("decode state");
        assert_eq!(decoded, state);

        let decoded_props = decoded.decoded_pending_proposals().expect("decode proposals");
        assert_eq!(decoded_props.len(), 1);
        assert_eq!(decoded_props[0].encode(), proposal.encode());
    }

    #[test]
    fn client_group_state_save_load_file() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(10)]);
        let mut state = ClientGroupState::new("group-2", tree, 0);
        state.epoch = 1;

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
}
