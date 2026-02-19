use crate::crypto::{
    decrypt_path_secret, encrypt_path_secret, hybrid_kem_decapsulate, hybrid_kem_encapsulate,
    HybridCiphertext, HybridPrivateKey, HybridPublicKey, HybridSignPubKey, HybridSignature,
    KyberPub,
};
use ed25519_dalek::{Signature as EdSig, VerifyingKey as EdPublic};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65};
use ml_kem::Key;
use rand_core::{CryptoRng, Rng};
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;
use x25519_dalek::PublicKey as X25519Pub;

/// Represents a User in the tree.
#[derive(Clone, Debug, PartialEq)]
pub struct LeafNode {
    /// The Hybrid Key (X25519 + Kyber) used to encrypt to this user.
    pub public_key: HybridPublicKey,
    /// The User's Identity (Verifying Key)
    pub credential: HybridSignPubKey,
}

/// Represents a path/subgroup in the tree.
#[derive(Clone, Debug, PartialEq)]
pub struct ParentNode {
    pub public_key: HybridPublicKey,
    /// Hash of this parent node bound to its copath (RFC 9420).
    pub parent_hash: Vec<u8>,
    pub unmerged_leaves: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Node {
    Leaf(LeafNode),
    Parent(ParentNode),
    Blank,
}

/// Ratchet tree container using MLS-style, left-balanced, inorder indexing.
///
/// Indexing rules:
/// - Leaves are at even indices: leaf_index -> node_index = 2 * leaf_index
/// - Parents are at odd indices
/// - Total nodes = 2 * leaf_count - 1 (empty tree has 0 nodes)
#[derive(Clone, Debug, PartialEq)]
pub struct RatchetTree {
    pub nodes: Vec<Node>,
}

/// Data required to populate a parent node during an Add commit path update.
#[derive(Clone, Debug)]
pub struct ParentUpdate {
    pub public_key: HybridPublicKey,
    pub unmerged_leaves: Vec<u32>,
}

/// Proposals that can be included in a Commit.
#[derive(Clone, Debug)]
pub enum Proposal {
    Add(KeyPackage),
    Update {
        leaf_index: usize,
        key_package: KeyPackage,
    },
    Remove {
        leaf_index: usize,
    },
    PreSharedKey {
        psk_id: Vec<u8>,
    },
    ReInit {
        group_id: String,
        version: u16,
        cipher_suite: u16,
        extensions: Vec<u8>,
    },
    GroupContextExtensions {
        extensions: Vec<u8>,
    },
}

/// Commit object applying a batch of proposals plus a path update by the sender.
#[derive(Clone, Debug)]
pub struct Commit {
    pub sender: usize,
    pub proposals: Vec<Proposal>,
    pub path: Vec<ParentUpdate>,
}

/// Path update output: derived secrets and ciphertexts per level.
#[derive(Clone, Debug)]
pub struct PathUpdate {
    pub path_secrets: Vec<[u8; 32]>,
    pub ciphertexts: Vec<Vec<PathSecretCiphertext>>,
}

/// Ciphertext carrying a path secret to a specific node in the copath resolution.
#[derive(Clone, Debug)]
pub struct PathSecretCiphertext {
    pub kem: HybridCiphertext,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CommitValidationError {
    SenderOutOfBounds,
    DuplicateAddTarget,
    AddIdentityAlreadyMember,
    InvalidAddKeyPackage,
    DuplicateUpdate,
    DuplicateRemove,
    DuplicatePreSharedKey,
    DuplicateReInit,
    DuplicateGroupContextExtensions,
    EmptyPreSharedKeyId,
    EmptyReInitGroupId,
    MixedReInitProposalSet,
    ReInitAndGroupContextExtensionsConflict,
    UnsupportedReInitVersion { version: u16 },
    UnsupportedReInitCipherSuite { cipher_suite: u16 },
    UpdateAndRemoveConflict,
    UpdateOutOfBounds { leaf_index: usize },
    RemoveOutOfBounds { leaf_index: usize },
}

/// The "Business Card" a user publishes so others can add them.
/// Now cryptographically bound to a Hybrid Identity.
#[derive(Clone, Debug)]
pub struct KeyPackage {
    /// The Hybrid Identity (Ed25519 + Dilithium)
    pub identity: HybridSignPubKey,
    /// The Hybrid Encryption Key (X25519 + Kyber)
    pub init_key: HybridPublicKey,
    /// Signature over the init_key by the identity key
    pub signature: HybridSignature,
}

impl KeyPackage {
    /// Verify the KeyPackage signature binds the identity to the init_key.
    pub fn verify(&self) -> bool {
        self.signature
            .verify(&self.identity, &self.init_key.to_bytes())
    }

    /// Serialize the KeyPackage in a TLS-style encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_bytes(&mut out, &self.identity.to_bytes());
        encode_bytes(&mut out, &self.init_key.to_bytes());
        encode_bytes(&mut out, &self.signature.to_bytes());
        out
    }

    /// Decode a KeyPackage from a TLS-style encoding.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        let identity_bytes = decoder.read_bytes()?;
        let init_bytes = decoder.read_bytes()?;
        let sig_bytes = decoder.read_bytes()?;

        if decoder.remaining() != 0 {
            return None;
        }

        let identity = decode_hybrid_sign_pub_key(&identity_bytes)?;
        let init_key = decode_hybrid_public_key(&init_bytes)?;
        let signature = decode_hybrid_signature(&sig_bytes)?;

        Some(Self {
            identity,
            init_key,
            signature,
        })
    }
}

impl ParentUpdate {
    /// Serialize the ParentUpdate in a TLS-style encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_bytes(&mut out, &self.public_key.to_bytes());
        encode_u32_vec(&mut out, &self.unmerged_leaves);
        out
    }

    /// Decode a ParentUpdate from a TLS-style encoding.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        let public_key_bytes = decoder.read_bytes()?;
        let public_key = decode_hybrid_public_key(&public_key_bytes)?;
        let unmerged_leaves = decode_u32_vec(&mut decoder)?;

        if decoder.remaining() != 0 {
            return None;
        }

        Some(Self {
            public_key,
            unmerged_leaves,
        })
    }
}

impl Proposal {
    /// Serialize a proposal in a TLS-style encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Proposal::Add(key_package) => {
                encode_u8(&mut out, PROPOSAL_ADD);
                encode_bytes(&mut out, &key_package.encode());
            }
            Proposal::Update {
                leaf_index,
                key_package,
            } => {
                encode_u8(&mut out, PROPOSAL_UPDATE);
                encode_u32(&mut out, *leaf_index as u32);
                encode_bytes(&mut out, &key_package.encode());
            }
            Proposal::Remove { leaf_index } => {
                encode_u8(&mut out, PROPOSAL_REMOVE);
                encode_u32(&mut out, *leaf_index as u32);
            }
            Proposal::PreSharedKey { psk_id } => {
                encode_u8(&mut out, PROPOSAL_PSK);
                encode_bytes(&mut out, psk_id);
            }
            Proposal::ReInit {
                group_id,
                version,
                cipher_suite,
                extensions,
            } => {
                encode_u8(&mut out, PROPOSAL_REINIT);
                encode_bytes(&mut out, group_id.as_bytes());
                encode_u16(&mut out, *version);
                encode_u16(&mut out, *cipher_suite);
                encode_bytes(&mut out, extensions);
            }
            Proposal::GroupContextExtensions { extensions } => {
                encode_u8(&mut out, PROPOSAL_GROUP_CONTEXT_EXTENSIONS);
                encode_bytes(&mut out, extensions);
            }
        }
        out
    }

    /// Decode a proposal from a TLS-style encoding.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        let tag = decoder.read_u8()?;
        let proposal = match tag {
            PROPOSAL_ADD => {
                let kp_bytes = decoder.read_bytes()?;
                let kp = KeyPackage::decode(&kp_bytes)?;
                Proposal::Add(kp)
            }
            PROPOSAL_UPDATE => {
                let leaf_index = decoder.read_u32()? as usize;
                let kp_bytes = decoder.read_bytes()?;
                let kp = KeyPackage::decode(&kp_bytes)?;
                Proposal::Update {
                    leaf_index,
                    key_package: kp,
                }
            }
            PROPOSAL_REMOVE => {
                let leaf_index = decoder.read_u32()? as usize;
                Proposal::Remove { leaf_index }
            }
            PROPOSAL_PSK => {
                let psk_id = decoder.read_bytes()?;
                Proposal::PreSharedKey { psk_id }
            }
            PROPOSAL_REINIT => {
                let group_id = String::from_utf8(decoder.read_bytes()?).ok()?;
                let version = decoder.read_u16()?;
                let cipher_suite = decoder.read_u16()?;
                let extensions = decoder.read_bytes()?;
                Proposal::ReInit {
                    group_id,
                    version,
                    cipher_suite,
                    extensions,
                }
            }
            PROPOSAL_GROUP_CONTEXT_EXTENSIONS => {
                let extensions = decoder.read_bytes()?;
                Proposal::GroupContextExtensions { extensions }
            }
            _ => return None,
        };

        if decoder.remaining() != 0 {
            return None;
        }

        Some(proposal)
    }
}

impl Commit {
    /// Serialize the Commit in a TLS-style encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_u32(&mut out, self.sender as u32);

        encode_u32(&mut out, self.proposals.len() as u32);
        for proposal in &self.proposals {
            encode_bytes(&mut out, &proposal.encode());
        }

        encode_u32(&mut out, self.path.len() as u32);
        for update in &self.path {
            encode_bytes(&mut out, &update.encode());
        }

        out
    }

    /// Serialize the Commit with a path update payload.
    pub fn encode_with_path_update(&self, path_update: &PathUpdate) -> Vec<u8> {
        let mut out = self.encode();
        encode_bytes(&mut out, &path_update.encode());
        out
    }

    /// Decode a Commit from a TLS-style encoding.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        let sender = decoder.read_u32()? as usize;

        let proposal_count = decoder.read_u32()? as usize;
        let mut proposals = Vec::with_capacity(proposal_count);
        for _ in 0..proposal_count {
            let proposal_bytes = decoder.read_bytes()?;
            let proposal = Proposal::decode(&proposal_bytes)?;
            proposals.push(proposal);
        }

        let path_count = decoder.read_u32()? as usize;
        let mut path = Vec::with_capacity(path_count);
        for _ in 0..path_count {
            let update_bytes = decoder.read_bytes()?;
            let update = ParentUpdate::decode(&update_bytes)?;
            path.push(update);
        }

        if decoder.remaining() != 0 {
            return None;
        }

        Some(Self {
            sender,
            proposals,
            path,
        })
    }

    /// Decode a Commit and an optional PathUpdate payload.
    pub fn decode_with_path_update(bytes: &[u8]) -> Option<(Self, Option<PathUpdate>)> {
        let mut decoder = Decoder::new(bytes);
        let sender = decoder.read_u32()? as usize;

        let proposal_count = decoder.read_u32()? as usize;
        let mut proposals = Vec::with_capacity(proposal_count);
        for _ in 0..proposal_count {
            let proposal_bytes = decoder.read_bytes()?;
            let proposal = Proposal::decode(&proposal_bytes)?;
            proposals.push(proposal);
        }

        let path_count = decoder.read_u32()? as usize;
        let mut path = Vec::with_capacity(path_count);
        for _ in 0..path_count {
            let update_bytes = decoder.read_bytes()?;
            let update = ParentUpdate::decode(&update_bytes)?;
            path.push(update);
        }

        let commit = Commit {
            sender,
            proposals,
            path,
        };

        if decoder.remaining() == 0 {
            return Some((commit, None));
        }

        let path_update_bytes = decoder.read_bytes()?;
        if decoder.remaining() != 0 {
            return None;
        }

        let path_update = PathUpdate::decode(&path_update_bytes)?;
        Some((commit, Some(path_update)))
    }
}

impl PathSecretCiphertext {
    /// Serialize the PathSecretCiphertext in a TLS-style encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_bytes(&mut out, &self.kem.classic);
        encode_bytes(&mut out, self.kem.pq.as_ref());
        encode_bytes(&mut out, &self.payload);
        out
    }

    /// Decode a PathSecretCiphertext from a TLS-style encoding.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        let classic = decoder.read_bytes()?;
        if classic.len() != 32 {
            return None;
        }
        let mut classic_arr = [0u8; 32];
        classic_arr.copy_from_slice(&classic);

        let pq = decoder.read_bytes()?;
        let pq_ct: HybridCiphertext = HybridCiphertext {
            classic: classic_arr,
            pq: pq.as_slice().try_into().ok()?,
        };

        let payload = decoder.read_bytes()?;

        if decoder.remaining() != 0 {
            return None;
        }

        Some(Self {
            kem: pq_ct,
            payload,
        })
    }
}

impl PathUpdate {
    /// Serialize the PathUpdate in a TLS-style encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_u32(&mut out, self.ciphertexts.len() as u32);
        for level in &self.ciphertexts {
            encode_u32(&mut out, level.len() as u32);
            for ct in level {
                encode_bytes(&mut out, &ct.encode());
            }
        }
        out
    }

    /// Decode a PathUpdate from a TLS-style encoding.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        let levels = decoder.read_u32()? as usize;
        let mut ciphertexts = Vec::with_capacity(levels);

        for _ in 0..levels {
            let count = decoder.read_u32()? as usize;
            let mut level = Vec::with_capacity(count);
            for _ in 0..count {
                let ct_bytes = decoder.read_bytes()?;
                let ct = PathSecretCiphertext::decode(&ct_bytes)?;
                level.push(ct);
            }
            ciphertexts.push(level);
        }

        if decoder.remaining() != 0 {
            return None;
        }

        Some(Self {
            path_secrets: Vec::new(),
            ciphertexts,
        })
    }
}

impl RatchetTree {
    /// Create an empty ratchet tree with the given leaf capacity.
    pub fn new(leaf_count: usize) -> Self {
        let node_count = node_width(leaf_count);
        let nodes = vec![Node::Blank; node_count];
        Self { nodes }
    }

    /// Build a ratchet tree from a list of leaves; parents start as Blank.
    pub fn from_leaves(leaves: Vec<LeafNode>) -> Self {
        let leaf_count = leaves.len();
        let mut nodes = vec![Node::Blank; node_width(leaf_count)];
        for (leaf_index, leaf) in leaves.into_iter().enumerate() {
            let node_index = leaf_to_node_index(leaf_index);
            nodes[node_index] = Node::Leaf(leaf);
        }
        Self { nodes }
    }

    /// Serialize the full ratchet tree including blank nodes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_u32(&mut out, self.nodes.len() as u32);
        for node in &self.nodes {
            match node {
                Node::Leaf(leaf) => {
                    encode_u8(&mut out, NODE_TYPE_LEAF);
                    encode_leaf_node(leaf, &mut out);
                }
                Node::Parent(parent) => {
                    encode_u8(&mut out, NODE_TYPE_PARENT);
                    encode_bytes(&mut out, &parent.public_key.to_bytes());
                    encode_bytes(&mut out, &parent.parent_hash);
                    encode_u32_vec(&mut out, &parent.unmerged_leaves);
                }
                Node::Blank => {
                    encode_u8(&mut out, NODE_TYPE_BLANK);
                }
            }
        }
        out
    }

    /// Decode a full ratchet tree serialized with `encode`.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        let count = decoder.read_u32()? as usize;
        let mut nodes = Vec::with_capacity(count);

        for _ in 0..count {
            let tag = decoder.read_u8()?;
            match tag {
                NODE_TYPE_LEAF => {
                    let public_key_bytes = decoder.read_bytes()?;
                    let credential_bytes = decoder.read_bytes()?;
                    let public_key = decode_hybrid_public_key(&public_key_bytes)?;
                    let credential = decode_hybrid_sign_pub_key(&credential_bytes)?;
                    nodes.push(Node::Leaf(LeafNode {
                        public_key,
                        credential,
                    }));
                }
                NODE_TYPE_PARENT => {
                    let public_key_bytes = decoder.read_bytes()?;
                    let parent_hash = decoder.read_bytes()?;
                    let unmerged_leaves = decode_u32_vec(&mut decoder)?;
                    let public_key = decode_hybrid_public_key(&public_key_bytes)?;
                    nodes.push(Node::Parent(ParentNode {
                        public_key,
                        parent_hash,
                        unmerged_leaves,
                    }));
                }
                NODE_TYPE_BLANK => nodes.push(Node::Blank),
                _ => return None,
            }
        }

        if decoder.remaining() != 0 {
            return None;
        }

        Some(Self { nodes })
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn leaf_count(&self) -> usize {
        if self.nodes.is_empty() {
            0
        } else {
            (self.nodes.len() + 1) / 2
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn root_index(&self) -> Option<usize> {
        let leaf_count = self.leaf_count();
        if leaf_count == 0 {
            None
        } else {
            Some(root_index_for_range(0, leaf_count))
        }
    }

    pub fn is_leaf_index(node_index: usize) -> bool {
        node_index % 2 == 0
    }

    pub fn leaf_to_node_index(leaf_index: usize) -> usize {
        leaf_to_node_index(leaf_index)
    }

    pub fn node_to_leaf_index(node_index: usize) -> Option<usize> {
        if Self::is_leaf_index(node_index) {
            Some(node_index / 2)
        } else {
            None
        }
    }

    pub fn parent(&self, node_index: usize) -> Option<usize> {
        if node_index >= self.nodes.len() {
            return None;
        }
        let leaf_count = self.leaf_count();
        parent_index_for_node(0, leaf_count, node_index)
    }

    pub fn left_child(&self, node_index: usize) -> Option<usize> {
        if node_index >= self.nodes.len() {
            return None;
        }
        let leaf_count = self.leaf_count();
        let (start_leaf, count) = leaf_range_for_node(0, leaf_count, node_index)?;
        if count <= 1 {
            return None;
        }
        let left_count = left_subtree_size(count);
        Some(root_index_for_range(start_leaf, left_count))
    }

    pub fn right_child(&self, node_index: usize) -> Option<usize> {
        if node_index >= self.nodes.len() {
            return None;
        }
        let leaf_count = self.leaf_count();
        let (start_leaf, count) = leaf_range_for_node(0, leaf_count, node_index)?;
        if count <= 1 {
            return None;
        }
        let left_count = left_subtree_size(count);
        let right_start = start_leaf + left_count;
        let right_count = count - left_count;
        Some(root_index_for_range(right_start, right_count))
    }

    /// Add a member using a KeyPackage and a supplied parent path.
    /// The parent path length must match the direct path length.
    pub fn add_key_package(
        &mut self,
        key_package: &KeyPackage,
        parent_path: &[ParentUpdate],
    ) -> Option<usize> {
        if !key_package.verify() {
            return None;
        }
        let leaf_index = match self.first_blank_leaf_index() {
            Some(index) => index,
            None => {
                self.grow_by_one_leaf();
                self.leaf_count().saturating_sub(1)
            }
        };

        let leaf_node = LeafNode {
            public_key: key_package.init_key.clone(),
            credential: key_package.identity.clone(),
        };
        let leaf_node_index = leaf_to_node_index(leaf_index);
        if leaf_node_index >= self.nodes.len() {
            return None;
        }
        self.nodes[leaf_node_index] = Node::Leaf(leaf_node);

        let direct_path = self.direct_path(leaf_index)?;
        if direct_path.len() != parent_path.len() {
            return None;
        }

        for (parent_index, update) in direct_path.into_iter().zip(parent_path.iter()) {
            if parent_index >= self.nodes.len() {
                return None;
            }
            self.nodes[parent_index] = Node::Parent(ParentNode {
                public_key: update.public_key.clone(),
                parent_hash: Vec::new(),
                unmerged_leaves: update.unmerged_leaves.clone(),
            });
        }

        self.compute_parent_hashes_for_leaf(leaf_index)?;
        Some(leaf_index)
    }

    /// Apply a Commit: proposals are applied first, then the sender path update.
    pub fn apply_commit(&mut self, commit: &Commit) -> Option<()> {
        self.validate_commit(commit).ok()?;

        for proposal in &commit.proposals {
            match proposal {
                Proposal::Add(key_package) => {
                    self.insert_key_package(key_package)?;
                }
                Proposal::Update {
                    leaf_index,
                    key_package,
                } => {
                    self.update_leaf(*leaf_index, key_package)?;
                }
                Proposal::Remove { leaf_index } => {
                    self.remove_leaf(*leaf_index)?;
                }
                Proposal::PreSharedKey { .. } => {}
                Proposal::ReInit { .. } => {}
                Proposal::GroupContextExtensions { .. } => {}
            }
        }

        self.apply_path_update(commit.sender, &commit.path)?;
        Some(())
    }

    /// Apply a Commit and then consume a PathUpdate payload as a receiver.
    /// Returns derived secrets aligned to the sender's direct path.
    pub fn apply_commit_with_path_update(
        &mut self,
        commit: &Commit,
        path_update: &PathUpdate,
        receiver_leaf: usize,
        receiver_private: &HybridPrivateKey,
    ) -> Option<Vec<Option<[u8; 32]>>> {
        self.apply_commit(commit)?;
        self.process_path_update_for_leaf(
            commit.sender,
            receiver_leaf,
            receiver_private,
            path_update,
        )
    }

    /// Derive path secrets and encrypt them to each copath resolution.
    pub fn build_path_update<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        leaf_index: usize,
        leaf_secret: [u8; 32],
    ) -> Option<PathUpdate> {
        let path = self.direct_path_with_copath(leaf_index)?;
        if path.is_empty() {
            return Some(PathUpdate {
                path_secrets: Vec::new(),
                ciphertexts: Vec::new(),
            });
        }

        let mut secrets_rev = Vec::new();
        let mut current = leaf_secret;
        for (level, (parent_index, _)) in path.iter().rev().enumerate() {
            let next = derive_path_secret(&current, *parent_index, level as u32);
            secrets_rev.push(next);
            current = next;
        }
        secrets_rev.reverse();

        let mut ciphertexts = Vec::new();
        for ((parent_index, copath_index), path_secret) in path.iter().zip(secrets_rev.iter()) {
            let resolution = self.resolution(*copath_index)?;
            let mut level_ct = Vec::new();
            for node_index in resolution {
                let public_key = self.node_public_key(node_index)?;
                let ctx = path_secret_encryption_context(leaf_index, *parent_index, node_index);

                let (ct, shared) = hybrid_kem_encapsulate(rng, public_key, &ctx);
                let payload = encrypt_path_secret(&shared, &ctx, path_secret);
                level_ct.push(PathSecretCiphertext { kem: ct, payload });
            }
            ciphertexts.push(level_ct);
        }

        Some(PathUpdate {
            path_secrets: secrets_rev,
            ciphertexts,
        })
    }

    /// Process a received PathUpdate and derive path secrets for the sender's direct path.
    pub fn process_path_update_for_leaf(
        &self,
        sender: usize,
        receiver_leaf: usize,
        receiver_private: &HybridPrivateKey,
        update: &PathUpdate,
    ) -> Option<Vec<Option<[u8; 32]>>> {
        if sender >= self.leaf_count() || receiver_leaf >= self.leaf_count() {
            return None;
        }

        let path = self.direct_path_with_copath(sender)?;
        if path.len() != update.ciphertexts.len() {
            return None;
        }

        let receiver_node = leaf_to_node_index(receiver_leaf);
        let mut found_index: Option<usize> = None;
        let mut found_secret: Option<[u8; 32]> = None;

        for idx in (0..path.len()).rev() {
            let (parent_index, copath_index) = path[idx];
            let resolution = self.resolution(copath_index)?;
            if resolution.is_empty() {
                continue;
            }
            let pos = resolution.iter().position(|node| *node == receiver_node);
            if let Some(pos) = pos {
                let level_cts = update.ciphertexts.get(idx)?;
                if level_cts.len() != resolution.len() {
                    return None;
                }
                let ct = level_cts.get(pos)?;
                let ctx = path_secret_encryption_context(sender, parent_index, receiver_node);

                let shared = hybrid_kem_decapsulate(receiver_private, &ct.kem, &ctx);
                let secret = decrypt_path_secret(&shared, &ctx, &ct.payload)?;
                found_index = Some(idx);
                found_secret = Some(secret);
                break;
            }
        }

        let start_index = found_index?;
        let mut secrets = vec![None; path.len()];
        let mut current = found_secret?;
        secrets[start_index] = Some(current);

        if start_index > 0 {
            for k in (0..start_index).rev() {
                let (parent_index, _) = path[k];
                let level = (path.len() - 1 - k) as u32;
                let next = derive_path_secret(&current, parent_index, level);
                secrets[k] = Some(next);
                current = next;
            }
        }

        Some(secrets)
    }

    /// Validate proposal set for duplicates, bounds, and conflicts.
    pub fn validate_commit(&self, commit: &Commit) -> Result<(), CommitValidationError> {
        if commit.sender >= self.leaf_count() {
            return Err(CommitValidationError::SenderOutOfBounds);
        }

        let mut existing_member_identities = HashSet::new();
        for node in &self.nodes {
            if let Node::Leaf(leaf) = node {
                existing_member_identities.insert(leaf.credential.to_bytes());
            }
        }
        let mut add_identities = HashSet::new();
        let mut add_init_keys = HashSet::new();
        let mut updates = HashSet::new();
        let mut removes = HashSet::new();
        let mut psk_ids = HashSet::new();
        let mut reinit_count = 0usize;
        let mut group_context_extensions_count = 0usize;

        for proposal in &commit.proposals {
            match proposal {
                Proposal::Add(key_package) => {
                    if !key_package.verify() {
                        return Err(CommitValidationError::InvalidAddKeyPackage);
                    }

                    let identity = key_package.identity.to_bytes();
                    if existing_member_identities.contains(&identity) {
                        return Err(CommitValidationError::AddIdentityAlreadyMember);
                    }
                    if !add_identities.insert(identity) {
                        return Err(CommitValidationError::DuplicateAddTarget);
                    }

                    let init_key = key_package.init_key.to_bytes();
                    if !add_init_keys.insert(init_key) {
                        return Err(CommitValidationError::DuplicateAddTarget);
                    }
                }
                Proposal::Update { leaf_index, .. } => {
                    if *leaf_index >= self.leaf_count() {
                        return Err(CommitValidationError::UpdateOutOfBounds {
                            leaf_index: *leaf_index,
                        });
                    }
                    if !updates.insert(*leaf_index) {
                        return Err(CommitValidationError::DuplicateUpdate);
                    }
                }
                Proposal::Remove { leaf_index } => {
                    if *leaf_index >= self.leaf_count() {
                        return Err(CommitValidationError::RemoveOutOfBounds {
                            leaf_index: *leaf_index,
                        });
                    }
                    if !removes.insert(*leaf_index) {
                        return Err(CommitValidationError::DuplicateRemove);
                    }
                }
                Proposal::PreSharedKey { psk_id } => {
                    if psk_id.is_empty() {
                        return Err(CommitValidationError::EmptyPreSharedKeyId);
                    }
                    if !psk_ids.insert(psk_id.clone()) {
                        return Err(CommitValidationError::DuplicatePreSharedKey);
                    }
                }
                Proposal::ReInit {
                    group_id,
                    version,
                    cipher_suite,
                    ..
                } => {
                    reinit_count += 1;
                    if reinit_count > 1 {
                        return Err(CommitValidationError::DuplicateReInit);
                    }
                    if group_id.is_empty() {
                        return Err(CommitValidationError::EmptyReInitGroupId);
                    }
                    if *version != REINIT_SUPPORTED_MLS_VERSION {
                        return Err(CommitValidationError::UnsupportedReInitVersion {
                            version: *version,
                        });
                    }
                    if *cipher_suite != REINIT_SUPPORTED_CIPHER_SUITE {
                        return Err(CommitValidationError::UnsupportedReInitCipherSuite {
                            cipher_suite: *cipher_suite,
                        });
                    }
                }
                Proposal::GroupContextExtensions { .. } => {
                    group_context_extensions_count += 1;
                    if group_context_extensions_count > 1 {
                        return Err(CommitValidationError::DuplicateGroupContextExtensions);
                    }
                }
            }
        }

        if reinit_count > 0 && group_context_extensions_count > 0 {
            return Err(CommitValidationError::ReInitAndGroupContextExtensionsConflict);
        }
        if reinit_count > 0 && commit.proposals.len() > 1 {
            return Err(CommitValidationError::MixedReInitProposalSet);
        }

        for leaf_index in updates {
            if removes.contains(&leaf_index) {
                return Err(CommitValidationError::UpdateAndRemoveConflict);
            }
        }

        Ok(())
    }

    fn insert_key_package(&mut self, key_package: &KeyPackage) -> Option<usize> {
        if !key_package.verify() {
            return None;
        }
        let leaf_index = match self.first_blank_leaf_index() {
            Some(index) => index,
            None => {
                self.grow_by_one_leaf();
                self.leaf_count().saturating_sub(1)
            }
        };
        let leaf_node = LeafNode {
            public_key: key_package.init_key.clone(),
            credential: key_package.identity.clone(),
        };
        let leaf_node_index = leaf_to_node_index(leaf_index);
        if leaf_node_index >= self.nodes.len() {
            return None;
        }
        self.nodes[leaf_node_index] = Node::Leaf(leaf_node);
        Some(leaf_index)
    }

    fn update_leaf(&mut self, leaf_index: usize, key_package: &KeyPackage) -> Option<()> {
        if !key_package.verify() {
            return None;
        }
        let node_index = leaf_to_node_index(leaf_index);
        if node_index >= self.nodes.len() {
            return None;
        }
        self.nodes[node_index] = Node::Leaf(LeafNode {
            public_key: key_package.init_key.clone(),
            credential: key_package.identity.clone(),
        });
        Some(())
    }

    fn remove_leaf(&mut self, leaf_index: usize) -> Option<()> {
        let node_index = leaf_to_node_index(leaf_index);
        if node_index >= self.nodes.len() {
            return None;
        }
        self.nodes[node_index] = Node::Blank;
        Some(())
    }

    fn apply_path_update(&mut self, sender: usize, path: &[ParentUpdate]) -> Option<()> {
        if sender >= self.leaf_count() {
            return None;
        }
        let direct_path = self.direct_path(sender)?;
        if direct_path.len() != path.len() {
            return None;
        }
        for (parent_index, update) in direct_path.into_iter().zip(path.iter()) {
            if parent_index >= self.nodes.len() {
                return None;
            }
            self.nodes[parent_index] = Node::Parent(ParentNode {
                public_key: update.public_key.clone(),
                parent_hash: Vec::new(),
                unmerged_leaves: update.unmerged_leaves.clone(),
            });
        }
        self.compute_parent_hashes_for_leaf(sender)?;
        Some(())
    }

    fn node_public_key(&self, node_index: usize) -> Option<&HybridPublicKey> {
        if node_index >= self.nodes.len() {
            return None;
        }
        match &self.nodes[node_index] {
            Node::Leaf(leaf) => Some(&leaf.public_key),
            Node::Parent(parent) => Some(&parent.public_key),
            Node::Blank => None,
        }
    }

    /// Compute and store parent_hash values along the filtered direct path for a leaf.
    pub fn compute_parent_hashes_for_leaf(&mut self, leaf_index: usize) -> Option<()> {
        if leaf_index >= self.leaf_count() {
            return None;
        }

        let path = self.direct_path_with_copath(leaf_index)?;
        let mut next_parent_hash: Vec<u8> = Vec::new();

        for (parent_index, copath_index) in path {
            let (parent_key, unmerged_leaves) = match &self.nodes[parent_index] {
                Node::Parent(parent) => (parent.public_key.clone(), parent.unmerged_leaves.clone()),
                _ => continue,
            };

            let blanked = self.blanked_leaves_for_copath(&unmerged_leaves, copath_index)?;
            let sibling_hash = self.tree_hash_with_blank_set(copath_index, &blanked)?;

            let parent_hash =
                compute_parent_hash_bytes(&parent_key, &next_parent_hash, &sibling_hash);
            if let Node::Parent(parent) = &mut self.nodes[parent_index] {
                parent.parent_hash = parent_hash.clone();
            }
            next_parent_hash = parent_hash;
        }

        Some(())
    }

    /// Internal helper used by parent-hash/path-secret logic.
    /// Returns `(parent, copath)` pairs in root-to-leaf order.
    fn direct_path_with_copath(&self, leaf_index: usize) -> Option<Vec<(usize, usize)>> {
        let mut path = Vec::new();
        let mut current = self.root_index()?;

        loop {
            if RatchetTree::is_leaf_index(current) {
                break;
            }
            let left = self.left_child(current)?;
            let right = self.right_child(current)?;
            let in_left = self.leaf_in_subtree(leaf_index, left)?;
            let (next, copath) = if in_left {
                (left, right)
            } else {
                (right, left)
            };
            path.push((current, copath));
            current = next;
        }

        Some(path)
    }

    /// Direct path from the leaf's parent up to the root (leaf-to-root order).
    pub fn direct_path(&self, leaf_index: usize) -> Option<Vec<usize>> {
        let mut direct_path: Vec<usize> = self
            .direct_path_with_copath(leaf_index)?
            .into_iter()
            .map(|(parent, _)| parent)
            .collect();
        direct_path.reverse();
        Some(direct_path)
    }

    /// Copath nodes corresponding to the direct path (leaf-to-root order).
    pub fn copath(&self, leaf_index: usize) -> Option<Vec<usize>> {
        let mut copath: Vec<usize> = self
            .direct_path_with_copath(leaf_index)?
            .into_iter()
            .map(|(_, copath)| copath)
            .collect();
        copath.reverse();
        Some(copath)
    }

    /// Filtered direct path in leaf-to-root order:
    /// include only parents whose copath resolution is non-empty.
    pub fn filtered_direct_path(&self, leaf_index: usize) -> Option<Vec<usize>> {
        let path = self.direct_path_with_copath(leaf_index)?;
        let mut filtered = Vec::new();
        for (parent, copath) in path.into_iter().rev() {
            let resolution = self.resolution(copath)?;
            if !resolution.is_empty() {
                filtered.push(parent);
            }
        }
        Some(filtered)
    }

    /// Resolution of a node per MLS:
    /// - If the node is non-blank, resolution is the node itself.
    /// - If the node is blank leaf, resolution is empty.
    /// - If the node is blank parent, resolution is the union of child resolutions.
    pub fn resolution(&self, node_index: usize) -> Option<Vec<usize>> {
        if node_index >= self.nodes.len() {
            return None;
        }

        match &self.nodes[node_index] {
            Node::Leaf(_) | Node::Parent(_) => Some(vec![node_index]),
            Node::Blank => {
                if RatchetTree::is_leaf_index(node_index) {
                    return Some(Vec::new());
                }
                let left = self.left_child(node_index)?;
                let right = self.right_child(node_index)?;
                let mut res = self.resolution(left)?;
                res.extend(self.resolution(right)?);
                Some(res)
            }
        }
    }

    fn leaf_in_subtree(&self, leaf_index: usize, node_index: usize) -> Option<bool> {
        let (start, count) = self.leaf_range_for_node_index(node_index)?;
        let end = start + count;
        Some(leaf_index >= start && leaf_index < end)
    }

    fn leaf_range_for_node_index(&self, node_index: usize) -> Option<(usize, usize)> {
        let leaf_count = self.leaf_count();
        leaf_range_for_node(0, leaf_count, node_index)
    }

    fn blanked_leaves_for_copath(
        &self,
        unmerged_leaves: &[u32],
        copath_index: usize,
    ) -> Option<HashSet<usize>> {
        let (start, count) = self.leaf_range_for_node_index(copath_index)?;
        let end = start + count;
        let mut blanked = HashSet::new();
        for &leaf in unmerged_leaves {
            let leaf_index = leaf as usize;
            if leaf_index >= start && leaf_index < end {
                blanked.insert(leaf_index);
            }
        }
        Some(blanked)
    }

    fn tree_hash_with_blank_set(
        &self,
        node_index: usize,
        blanked_leaves: &HashSet<usize>,
    ) -> Option<[u8; 32]> {
        if node_index >= self.nodes.len() {
            return None;
        }

        if RatchetTree::is_leaf_index(node_index) {
            let leaf_index = node_index / 2;
            let mut input = Vec::new();
            input.push(NODE_TYPE_LEAF);
            encode_u32(&mut input, leaf_index as u32);

            match &self.nodes[node_index] {
                Node::Leaf(leaf) if !blanked_leaves.contains(&leaf_index) => {
                    input.push(1);
                    encode_leaf_node(leaf, &mut input);
                }
                _ => {
                    input.push(0);
                }
            }

            return Some(hash_bytes(&input));
        }

        let left = self.left_child(node_index)?;
        let right = self.right_child(node_index)?;
        let left_hash = self.tree_hash_with_blank_set(left, blanked_leaves)?;
        let right_hash = self.tree_hash_with_blank_set(right, blanked_leaves)?;

        let mut input = Vec::new();
        input.push(NODE_TYPE_PARENT);

        match &self.nodes[node_index] {
            Node::Parent(parent) => {
                input.push(1);
                encode_parent_node(parent, blanked_leaves, &mut input);
            }
            _ => {
                input.push(0);
            }
        }

        encode_bytes(&mut input, &left_hash);
        encode_bytes(&mut input, &right_hash);

        Some(hash_bytes(&input))
    }

    fn first_blank_leaf_index(&self) -> Option<usize> {
        for node_index in (0..self.nodes.len()).step_by(2) {
            if matches!(self.nodes[node_index], Node::Blank) {
                return Some(node_index / 2);
            }
        }
        None
    }

    fn grow_by_one_leaf(&mut self) {
        if self.nodes.is_empty() {
            self.nodes.push(Node::Blank);
        } else {
            self.nodes.push(Node::Blank);
            self.nodes.push(Node::Blank);
        }
    }
}

fn node_width(leaf_count: usize) -> usize {
    if leaf_count == 0 {
        0
    } else {
        2 * leaf_count - 1
    }
}

fn leaf_to_node_index(leaf_index: usize) -> usize {
    2 * leaf_index
}

fn left_subtree_size(leaf_count: usize) -> usize {
    debug_assert!(leaf_count > 1);
    let mut size = 1usize;
    let target = leaf_count - 1;
    while size << 1 <= target {
        size <<= 1;
    }
    size
}

fn root_index_for_range(start_leaf: usize, leaf_count: usize) -> usize {
    if leaf_count <= 1 {
        return leaf_to_node_index(start_leaf);
    }
    let left_count = left_subtree_size(leaf_count);
    leaf_to_node_index(start_leaf) + (2 * left_count - 1)
}

fn leaf_range_for_node(
    start_leaf: usize,
    leaf_count: usize,
    target_node: usize,
) -> Option<(usize, usize)> {
    if leaf_count == 0 {
        return None;
    }
    let min_index = leaf_to_node_index(start_leaf);
    let max_index = leaf_to_node_index(start_leaf + leaf_count - 1);
    if target_node < min_index || target_node > max_index {
        return None;
    }
    let root = root_index_for_range(start_leaf, leaf_count);
    if target_node == root {
        return Some((start_leaf, leaf_count));
    }
    if leaf_count <= 1 {
        return None;
    }
    let left_count = left_subtree_size(leaf_count);
    if target_node < root {
        leaf_range_for_node(start_leaf, left_count, target_node)
    } else {
        let right_start = start_leaf + left_count;
        let right_count = leaf_count - left_count;
        leaf_range_for_node(right_start, right_count, target_node)
    }
}

fn parent_index_for_node(
    start_leaf: usize,
    leaf_count: usize,
    target_node: usize,
) -> Option<usize> {
    if leaf_count == 0 {
        return None;
    }
    let min_index = leaf_to_node_index(start_leaf);
    let max_index = leaf_to_node_index(start_leaf + leaf_count - 1);
    if target_node < min_index || target_node > max_index {
        return None;
    }
    let root = root_index_for_range(start_leaf, leaf_count);
    if target_node == root || leaf_count <= 1 {
        return None;
    }
    let left_count = left_subtree_size(leaf_count);
    let left_root = root_index_for_range(start_leaf, left_count);
    if target_node < root {
        if target_node == left_root {
            return Some(root);
        }
        return parent_index_for_node(start_leaf, left_count, target_node);
    }
    let right_start = start_leaf + left_count;
    let right_count = leaf_count - left_count;
    let right_root = root_index_for_range(right_start, right_count);
    if target_node == right_root {
        return Some(root);
    }
    parent_index_for_node(right_start, right_count, target_node)
}

const NODE_TYPE_LEAF: u8 = 1;
const NODE_TYPE_PARENT: u8 = 2;
const NODE_TYPE_BLANK: u8 = 3;
const PROPOSAL_ADD: u8 = 1;
const PROPOSAL_UPDATE: u8 = 2;
const PROPOSAL_REMOVE: u8 = 3;
const PROPOSAL_PSK: u8 = 4;
const PROPOSAL_REINIT: u8 = 5;
const PROPOSAL_GROUP_CONTEXT_EXTENSIONS: u8 = 6;
const REINIT_SUPPORTED_MLS_VERSION: u16 = 1;
const REINIT_SUPPORTED_CIPHER_SUITE: u16 = 0x0001;

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn compute_parent_hash_bytes(
    public_key: &HybridPublicKey,
    parent_hash: &[u8],
    original_sibling_tree_hash: &[u8],
) -> Vec<u8> {
    let mut input = Vec::new();
    encode_bytes(&mut input, &public_key.to_bytes());
    encode_bytes(&mut input, parent_hash);
    encode_bytes(&mut input, original_sibling_tree_hash);
    hash_bytes(&input).to_vec()
}

fn derive_path_secret(parent_secret: &[u8; 32], parent_index: usize, level: u32) -> [u8; 32] {
    let context =
        mls_tree_labeled_context(b"path secret derivation", &[parent_index as u32, level]);
    mls_tree_labeled_hash(b"derive path secret", &context, &[parent_secret])
}

fn path_secret_encryption_context(
    sender_leaf: usize,
    parent_index: usize,
    recipient_node: usize,
) -> Vec<u8> {
    mls_tree_labeled_context(
        b"path secret encryption",
        &[
            sender_leaf as u32,
            parent_index as u32,
            recipient_node as u32,
        ],
    )
}

fn mls_tree_labeled_context(label: &[u8], fields: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_bytes(&mut out, b"MLS 1.0");
    encode_bytes(&mut out, label);
    encode_u32(&mut out, fields.len() as u32);
    for field in fields {
        encode_u32(&mut out, *field);
    }
    out
}

fn mls_tree_labeled_hash(label: &[u8], context: &[u8], secrets: &[&[u8]]) -> [u8; 32] {
    let mut input = Vec::new();
    encode_bytes(&mut input, b"MLS 1.0");
    encode_bytes(&mut input, label);
    encode_bytes(&mut input, context);
    for secret in secrets {
        encode_bytes(&mut input, secret);
    }
    hash_bytes(&input)
}

fn encode_leaf_node(leaf: &LeafNode, out: &mut Vec<u8>) {
    encode_bytes(out, &leaf.public_key.to_bytes());
    encode_bytes(out, &leaf.credential.to_bytes());
}

fn encode_parent_node(parent: &ParentNode, blanked_leaves: &HashSet<usize>, out: &mut Vec<u8>) {
    encode_bytes(out, &parent.public_key.to_bytes());
    encode_bytes(out, &parent.parent_hash);

    let filtered_unmerged: Vec<u32> = parent
        .unmerged_leaves
        .iter()
        .copied()
        .filter(|leaf| !blanked_leaves.contains(&(*leaf as usize)))
        .collect();
    encode_u32_vec(out, &filtered_unmerged);
}

fn encode_u32_vec(out: &mut Vec<u8>, values: &[u32]) {
    encode_u32(out, values.len() as u32);
    for value in values {
        encode_u32(out, *value);
    }
}

fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    encode_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

fn encode_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn encode_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn encode_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn decode_u32_vec(decoder: &mut Decoder<'_>) -> Option<Vec<u32>> {
    let len = decoder.read_u32()? as usize;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(decoder.read_u32()?);
    }
    Some(out)
}

fn decode_hybrid_public_key(bytes: &[u8]) -> Option<HybridPublicKey> {
    if bytes.len() < 32 {
        return None;
    }
    let mut classic = [0u8; 32];
    classic.copy_from_slice(&bytes[..32]);
    let classic_pub = X25519Pub::from(classic);

    let pq_bytes = &bytes[32..];
    let pq_key: Key<KyberPub> = pq_bytes.try_into().ok()?;
    let pq_pub = KyberPub::new(&pq_key).ok()?;

    Some(HybridPublicKey {
        classic: classic_pub,
        pq: pq_pub,
    })
}

fn decode_hybrid_sign_pub_key(bytes: &[u8]) -> Option<HybridSignPubKey> {
    if bytes.len() < 32 {
        return None;
    }
    let mut classic = [0u8; 32];
    classic.copy_from_slice(&bytes[..32]);
    let classic_pub = EdPublic::from_bytes(&classic).ok()?;

    let pq_bytes = &bytes[32..];
    let pq_enc: EncodedVerifyingKey<MlDsa65> = pq_bytes.try_into().ok()?;
    let pq_pub = ml_dsa::VerifyingKey::<MlDsa65>::decode(&pq_enc);

    Some(HybridSignPubKey {
        classic: classic_pub,
        pq: pq_pub,
    })
}

fn decode_hybrid_signature(bytes: &[u8]) -> Option<HybridSignature> {
    if bytes.len() < 64 {
        return None;
    }
    let mut classic = [0u8; 64];
    classic.copy_from_slice(&bytes[..64]);
    let classic_sig = EdSig::from_bytes(&classic);

    let pq_bytes = &bytes[64..];
    let pq_enc: EncodedSignature<MlDsa65> = pq_bytes.try_into().ok()?;
    let pq_sig = ml_dsa::Signature::<MlDsa65>::decode(&pq_enc)?;

    Some(HybridSignature {
        classic: classic_sig,
        pq: pq_sig,
    })
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

    fn read_u32(&mut self) -> Option<u32> {
        if self.remaining() < 4 {
            return None;
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 4]);
        self.pos += 4;
        Some(u32::from_be_bytes(buf))
    }

    fn read_u16(&mut self) -> Option<u16> {
        if self.remaining() < 2 {
            return None;
        }
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 2]);
        self.pos += 2;
        Some(u16::from_be_bytes(buf))
    }

    fn read_u8(&mut self) -> Option<u8> {
        if self.remaining() < 1 {
            return None;
        }
        let value = self.data[self.pos];
        self.pos += 1;
        Some(value)
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
    use crate::crypto::{HybridSignPrivKey, KyberPriv};
    use ed25519_dalek::{SigningKey as EdSecret, VerifyingKey as EdPublic};
    use ml_dsa::{KeyGen, MlDsa65};
    use ml_kem::Seed;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use rand_core::{Infallible, TryCryptoRng, TryRng};
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

    #[derive(Debug)]
    struct TestRng(u64);

    impl TestRng {
        fn next_u64_internal(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    impl TryRng for TestRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.next_u64_internal() as u32)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(self.next_u64_internal())
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            let mut offset = 0;
            while offset < dst.len() {
                let chunk = self.next_u64_internal().to_le_bytes();
                let remaining = dst.len() - offset;
                let take = remaining.min(chunk.len());
                dst[offset..offset + take].copy_from_slice(&chunk[..take]);
                offset += take;
            }
            Ok(())
        }
    }

    impl TryCryptoRng for TestRng {}

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

    fn hybrid_private_key(seed: u8) -> HybridPrivateKey {
        let kem_seed = Seed::from([seed; 64]);
        let kyber_priv = KyberPriv::from_seed(kem_seed);
        let classic_priv = X25519Priv::from([seed; 32]);
        HybridPrivateKey {
            classic: classic_priv,
            pq: kyber_priv,
        }
    }

    #[test]
    fn add_key_package_rejects_invalid_signature() {
        let mut tree = RatchetTree::new(0);
        let (identity, priv_key) = hybrid_signing_keys(8);
        let init_key = hybrid_public_key(9);
        let bad_signature = priv_key.sign(b"wrong-message");
        let kp = KeyPackage {
            identity,
            init_key,
            signature: bad_signature,
        };

        assert!(tree.add_key_package(&kp, &[]).is_none());
    }

    fn make_leaf(seed: u8) -> LeafNode {
        let (identity, _priv_key) = hybrid_signing_keys(seed);
        let public_key = hybrid_public_key(seed);
        LeafNode {
            public_key,
            credential: identity,
        }
    }

    fn parent_updates_for(tree: &RatchetTree, sender: usize, seed: u8) -> Vec<ParentUpdate> {
        let direct_path = tree.direct_path(sender).expect("direct path");
        direct_path
            .iter()
            .map(|_| ParentUpdate {
                public_key: hybrid_public_key(seed),
                unmerged_leaves: Vec::new(),
            })
            .collect()
    }

    #[test]
    fn add_key_package_inserts_into_empty_tree() {
        let mut tree = RatchetTree::new(0);
        let kp = make_key_package(1);

        let leaf_index = tree.add_key_package(&kp, &[]).expect("add failed");
        assert_eq!(leaf_index, 0);
        assert_eq!(tree.leaf_count(), 1);

        let node_index = RatchetTree::leaf_to_node_index(leaf_index);
        match &tree.nodes[node_index] {
            Node::Leaf(leaf) => assert_eq!(leaf.public_key, kp.init_key),
            other => panic!("expected leaf node, got {other:?}"),
        }
    }

    #[test]
    fn add_key_package_reuses_blank_leaf_and_updates_parent() {
        let leaf0 = make_leaf(2);
        let leaf1 = make_leaf(3);
        let mut tree = RatchetTree::from_leaves(vec![leaf0, leaf1]);

        let blank_index = RatchetTree::leaf_to_node_index(1);
        tree.nodes[blank_index] = Node::Blank;

        let kp = make_key_package(4);
        let direct_path = tree.direct_path(1).expect("direct path");
        let parent_path: Vec<ParentUpdate> = direct_path
            .iter()
            .map(|_| ParentUpdate {
                public_key: hybrid_public_key(9),
                unmerged_leaves: Vec::new(),
            })
            .collect();

        let leaf_index = tree.add_key_package(&kp, &parent_path).expect("add failed");
        assert_eq!(leaf_index, 1);

        let leaf_node_index = RatchetTree::leaf_to_node_index(leaf_index);
        match &tree.nodes[leaf_node_index] {
            Node::Leaf(leaf) => assert_eq!(leaf.public_key, kp.init_key),
            other => panic!("expected leaf node, got {other:?}"),
        }

        let root_index = tree.root_index().expect("root");
        match &tree.nodes[root_index] {
            Node::Parent(parent) => assert_eq!(parent.public_key, parent_path[0].public_key),
            other => panic!("expected parent node, got {other:?}"),
        }
    }

    #[test]
    fn add_key_package_grows_tree_when_full() {
        let leaf0 = make_leaf(5);
        let mut tree = RatchetTree::from_leaves(vec![leaf0]);
        assert_eq!(tree.node_count(), 1);

        let kp = make_key_package(6);
        let parent_path = [ParentUpdate {
            public_key: hybrid_public_key(7),
            unmerged_leaves: Vec::new(),
        }];

        let leaf_index = tree.add_key_package(&kp, &parent_path).expect("add failed");
        assert_eq!(leaf_index, 1);
        assert_eq!(tree.node_count(), 3);
    }

    #[test]
    fn apply_commit_adds_member_and_updates_path() {
        let sender_leaf = make_leaf(10);
        let mut tree = RatchetTree::from_leaves(vec![sender_leaf]);

        let add_kp = make_key_package(11);
        let mut tree_after = tree.clone();
        tree_after
            .insert_key_package(&add_kp)
            .expect("insert into temp tree");
        let path = parent_updates_for(&tree_after, 0, 12);
        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::Add(add_kp.clone())],
            path,
        };

        tree.apply_commit(&commit).expect("commit failed");

        assert_eq!(tree.leaf_count(), 2);
        let added_index = RatchetTree::leaf_to_node_index(1);
        match &tree.nodes[added_index] {
            Node::Leaf(leaf) => assert_eq!(leaf.public_key, add_kp.init_key),
            other => panic!("expected leaf node, got {other:?}"),
        }

        let root = tree.root_index().expect("root");
        match &tree.nodes[root] {
            Node::Parent(parent) => assert_eq!(parent.public_key, hybrid_public_key(12)),
            other => panic!("expected parent node, got {other:?}"),
        }
    }

    #[test]
    fn apply_commit_adds_multiple_members_in_single_commit() {
        let sender_leaf = make_leaf(13);
        let mut tree = RatchetTree::from_leaves(vec![sender_leaf]);

        let add_kp_b = make_key_package(14);
        let add_kp_c = make_key_package(15);

        let mut tree_after = tree.clone();
        tree_after
            .insert_key_package(&add_kp_b)
            .expect("insert first add into temp tree");
        tree_after
            .insert_key_package(&add_kp_c)
            .expect("insert second add into temp tree");

        let path = parent_updates_for(&tree_after, 0, 16);
        let commit = Commit {
            sender: 0,
            proposals: vec![
                Proposal::Add(add_kp_b.clone()),
                Proposal::Add(add_kp_c.clone()),
            ],
            path,
        };

        tree.apply_commit(&commit)
            .expect("multi-add commit should apply");
        assert_eq!(tree.leaf_count(), 3);

        let leaf1 = RatchetTree::leaf_to_node_index(1);
        let leaf2 = RatchetTree::leaf_to_node_index(2);
        match &tree.nodes[leaf1] {
            Node::Leaf(leaf) => assert_eq!(leaf.public_key, add_kp_b.init_key),
            other => panic!("expected leaf node for added member B, got {other:?}"),
        }
        match &tree.nodes[leaf2] {
            Node::Leaf(leaf) => assert_eq!(leaf.public_key, add_kp_c.init_key),
            other => panic!("expected leaf node for added member C, got {other:?}"),
        }
    }

    #[test]
    fn apply_commit_updates_member_and_path() {
        let leaf0 = make_leaf(20);
        let leaf1 = make_leaf(21);
        let mut tree = RatchetTree::from_leaves(vec![leaf0, leaf1]);

        let update_kp = make_key_package(22);
        let path = parent_updates_for(&tree, 0, 23);
        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::Update {
                leaf_index: 1,
                key_package: update_kp.clone(),
            }],
            path,
        };

        tree.apply_commit(&commit).expect("commit failed");

        let leaf_index = RatchetTree::leaf_to_node_index(1);
        match &tree.nodes[leaf_index] {
            Node::Leaf(leaf) => assert_eq!(leaf.public_key, update_kp.init_key),
            other => panic!("expected leaf node, got {other:?}"),
        }

        let root = tree.root_index().expect("root");
        match &tree.nodes[root] {
            Node::Parent(parent) => assert_eq!(parent.public_key, hybrid_public_key(23)),
            other => panic!("expected parent node, got {other:?}"),
        }
    }

    #[test]
    fn apply_commit_removes_member_and_updates_path() {
        let leaf0 = make_leaf(30);
        let leaf1 = make_leaf(31);
        let mut tree = RatchetTree::from_leaves(vec![leaf0, leaf1]);

        let path = parent_updates_for(&tree, 0, 32);
        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::Remove { leaf_index: 1 }],
            path,
        };

        tree.apply_commit(&commit).expect("commit failed");

        let leaf_index = RatchetTree::leaf_to_node_index(1);
        match &tree.nodes[leaf_index] {
            Node::Blank => {}
            other => panic!("expected blank node, got {other:?}"),
        }

        let root = tree.root_index().expect("root");
        match &tree.nodes[root] {
            Node::Parent(parent) => assert_eq!(parent.public_key, hybrid_public_key(32)),
            other => panic!("expected parent node, got {other:?}"),
        }
    }

    #[test]
    fn apply_commit_with_path_update_success() {
        let sender_leaf = make_leaf(40);
        let mut tree = RatchetTree::from_leaves(vec![sender_leaf]);

        let (bob_kp, bob_priv) = {
            let kp = make_key_package(41);
            let kem_seed = Seed::from([41u8; 64]);
            let kyber_priv = KyberPriv::from_seed(kem_seed);
            let classic_priv = X25519Priv::from([41u8; 32]);
            let priv_key = HybridPrivateKey {
                classic: classic_priv,
                pq: kyber_priv,
            };
            (kp, priv_key)
        };

        let mut tree_after = tree.clone();
        tree_after
            .insert_key_package(&bob_kp)
            .expect("insert into temp tree");

        let parent_path = parent_updates_for(&tree_after, 0, 42);
        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::Add(bob_kp.clone())],
            path: parent_path,
        };

        let mut rng = TestRng(0x5a5a5a5a5a5a5a5a);
        let path_update = tree_after
            .build_path_update(&mut rng, 0, [7u8; 32])
            .expect("path update");

        let derived = tree
            .apply_commit_with_path_update(&commit, &path_update, 1, &bob_priv)
            .expect("apply with path update");

        assert_eq!(derived.len(), path_update.ciphertexts.len());
        assert!(derived.iter().any(|v| v.is_some()));
    }

    #[test]
    fn apply_commit_with_path_update_wrong_leaf() {
        let sender_leaf = make_leaf(50);
        let mut tree = RatchetTree::from_leaves(vec![sender_leaf]);

        let (bob_kp, bob_priv) = {
            let kp = make_key_package(51);
            let kem_seed = Seed::from([51u8; 64]);
            let kyber_priv = KyberPriv::from_seed(kem_seed);
            let classic_priv = X25519Priv::from([51u8; 32]);
            let priv_key = HybridPrivateKey {
                classic: classic_priv,
                pq: kyber_priv,
            };
            (kp, priv_key)
        };

        let mut tree_after = tree.clone();
        tree_after
            .insert_key_package(&bob_kp)
            .expect("insert into temp tree");

        let parent_path = parent_updates_for(&tree_after, 0, 52);
        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::Add(bob_kp.clone())],
            path: parent_path,
        };

        let mut rng = TestRng(0x1111111111111111);
        let path_update = tree_after
            .build_path_update(&mut rng, 0, [9u8; 32])
            .expect("path update");

        // Wrong receiver leaf index should fail.
        let result = tree.apply_commit_with_path_update(&commit, &path_update, 2, &bob_priv);
        assert!(result.is_none());
    }

    #[test]
    fn apply_commit_with_tampered_path_payload_fails() {
        let sender_leaf = make_leaf(53);
        let mut tree = RatchetTree::from_leaves(vec![sender_leaf]);

        let (bob_kp, bob_priv) = {
            let kp = make_key_package(54);
            let kem_seed = Seed::from([54u8; 64]);
            let kyber_priv = KyberPriv::from_seed(kem_seed);
            let classic_priv = X25519Priv::from([54u8; 32]);
            let priv_key = HybridPrivateKey {
                classic: classic_priv,
                pq: kyber_priv,
            };
            (kp, priv_key)
        };

        let mut tree_after = tree.clone();
        tree_after
            .insert_key_package(&bob_kp)
            .expect("insert into temp tree");

        let parent_path = parent_updates_for(&tree_after, 0, 55);
        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::Add(bob_kp.clone())],
            path: parent_path,
        };

        let mut rng = TestRng(0x3333333333333333);
        let mut path_update = tree_after
            .build_path_update(&mut rng, 0, [0xAAu8; 32])
            .expect("path update");

        path_update.ciphertexts[0][0].payload[0] ^= 0x80;

        let result = tree.apply_commit_with_path_update(&commit, &path_update, 1, &bob_priv);
        assert!(result.is_none());
    }

    #[test]
    fn apply_commit_with_tampered_kem_ciphertext_fails() {
        let sender_leaf = make_leaf(56);
        let mut tree = RatchetTree::from_leaves(vec![sender_leaf]);

        let (bob_kp, bob_priv) = {
            let kp = make_key_package(57);
            let kem_seed = Seed::from([57u8; 64]);
            let kyber_priv = KyberPriv::from_seed(kem_seed);
            let classic_priv = X25519Priv::from([57u8; 32]);
            let priv_key = HybridPrivateKey {
                classic: classic_priv,
                pq: kyber_priv,
            };
            (kp, priv_key)
        };

        let mut tree_after = tree.clone();
        tree_after
            .insert_key_package(&bob_kp)
            .expect("insert into temp tree");

        let parent_path = parent_updates_for(&tree_after, 0, 58);
        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::Add(bob_kp.clone())],
            path: parent_path,
        };

        let mut rng = TestRng(0x4444444444444444);
        let mut path_update = tree_after
            .build_path_update(&mut rng, 0, [0xBBu8; 32])
            .expect("path update");

        path_update.ciphertexts[0][0].kem.classic[0] ^= 0x40;

        let result = tree.apply_commit_with_path_update(&commit, &path_update, 1, &bob_priv);
        assert!(result.is_none());
    }

    #[test]
    fn apply_commit_with_mismatched_resolution_ciphertext_count_fails() {
        let sender_leaf = make_leaf(59);
        let mut tree = RatchetTree::from_leaves(vec![sender_leaf]);

        let (bob_kp, bob_priv) = {
            let kp = make_key_package(60);
            let kem_seed = Seed::from([60u8; 64]);
            let kyber_priv = KyberPriv::from_seed(kem_seed);
            let classic_priv = X25519Priv::from([60u8; 32]);
            let priv_key = HybridPrivateKey {
                classic: classic_priv,
                pq: kyber_priv,
            };
            (kp, priv_key)
        };

        let mut tree_after = tree.clone();
        tree_after
            .insert_key_package(&bob_kp)
            .expect("insert into temp tree");

        let parent_path = parent_updates_for(&tree_after, 0, 61);
        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::Add(bob_kp.clone())],
            path: parent_path,
        };

        let mut rng = TestRng(0x5555555555555555);
        let mut path_update = tree_after
            .build_path_update(&mut rng, 0, [0xCCu8; 32])
            .expect("path update");

        let _ = path_update.ciphertexts[0].pop();
        let result = tree.apply_commit_with_path_update(&commit, &path_update, 1, &bob_priv);
        assert!(result.is_none());
    }

    #[test]
    fn forward_secrecy_old_receiver_key_cannot_decrypt_after_update() {
        let alice_leaf = make_leaf(90);
        let bob_leaf = make_leaf(91);
        let mut sender_state = RatchetTree::from_leaves(vec![alice_leaf, bob_leaf]);
        let mut alice_receiver_state = sender_state.clone();

        let alice_priv = hybrid_private_key(90);
        let bob_priv_epoch0 = hybrid_private_key(91);
        let bob_kp_epoch1 = make_key_package(92);
        let alice_kp_epoch2 = make_key_package(93);

        let mut tree_after_props_epoch1 = sender_state.clone();
        tree_after_props_epoch1
            .update_leaf(1, &bob_kp_epoch1)
            .expect("update leaf for epoch1");
        let path_epoch1 = parent_updates_for(&tree_after_props_epoch1, 1, 94);
        let commit_epoch1 = Commit {
            sender: 1,
            proposals: vec![Proposal::Update {
                leaf_index: 1,
                key_package: bob_kp_epoch1.clone(),
            }],
            path: path_epoch1,
        };
        let mut rng_epoch1 = TestRng(0x1010_1010_1010_1010);
        let path_update_epoch1 = tree_after_props_epoch1
            .build_path_update(&mut rng_epoch1, 1, [0x11u8; 32])
            .expect("path update epoch1");

        sender_state
            .apply_commit(&commit_epoch1)
            .expect("apply sender commit epoch1");
        let derived_epoch1 = alice_receiver_state
            .apply_commit_with_path_update(&commit_epoch1, &path_update_epoch1, 0, &alice_priv)
            .expect("alice apply epoch1");
        assert!(derived_epoch1.iter().any(|v| v.is_some()));
        assert_eq!(sender_state, alice_receiver_state);

        let mut tree_after_props_epoch2 = sender_state.clone();
        tree_after_props_epoch2
            .update_leaf(0, &alice_kp_epoch2)
            .expect("update leaf for epoch2");
        let path_epoch2 = parent_updates_for(&tree_after_props_epoch2, 0, 95);
        let commit_epoch2 = Commit {
            sender: 0,
            proposals: vec![Proposal::Update {
                leaf_index: 0,
                key_package: alice_kp_epoch2,
            }],
            path: path_epoch2,
        };
        let mut rng_epoch2 = TestRng(0x2020_2020_2020_2020);
        let path_update_epoch2 = tree_after_props_epoch2
            .build_path_update(&mut rng_epoch2, 0, [0x22u8; 32])
            .expect("path update epoch2");

        let mut bob_receiver_with_new_key = alice_receiver_state.clone();
        let mut bob_receiver_with_old_key = alice_receiver_state.clone();
        let mut sender_after_epoch2 = sender_state.clone();
        sender_after_epoch2
            .apply_commit(&commit_epoch2)
            .expect("apply sender commit epoch2");

        let bob_priv_epoch1 = hybrid_private_key(92);
        let derived_with_new_key = bob_receiver_with_new_key
            .apply_commit_with_path_update(&commit_epoch2, &path_update_epoch2, 1, &bob_priv_epoch1)
            .expect("bob apply epoch2 with new key");
        assert!(derived_with_new_key.iter().any(|v| v.is_some()));
        assert_eq!(sender_after_epoch2, bob_receiver_with_new_key);

        let old_key_result = bob_receiver_with_old_key.apply_commit_with_path_update(
            &commit_epoch2,
            &path_update_epoch2,
            1,
            &bob_priv_epoch0,
        );
        assert!(old_key_result.is_none());
    }

    #[test]
    fn forward_secrecy_removed_member_cannot_decrypt_future_path_updates() {
        let alice_leaf = make_leaf(96);
        let bob_leaf = make_leaf(97);
        let carol_leaf = make_leaf(98);
        let mut sender_state = RatchetTree::from_leaves(vec![alice_leaf, bob_leaf, carol_leaf]);

        let bob_priv = hybrid_private_key(97);
        let carol_priv = hybrid_private_key(98);

        let mut tree_after_remove = sender_state.clone();
        tree_after_remove
            .remove_leaf(2)
            .expect("remove leaf in temp tree");
        let path_remove = parent_updates_for(&tree_after_remove, 0, 99);
        let remove_commit = Commit {
            sender: 0,
            proposals: vec![Proposal::Remove { leaf_index: 2 }],
            path: path_remove,
        };
        let mut rng_remove = TestRng(0x3030_3030_3030_3030);
        let path_update_remove = tree_after_remove
            .build_path_update(&mut rng_remove, 0, [0x33u8; 32])
            .expect("path update remove commit");

        sender_state
            .apply_commit(&remove_commit)
            .expect("sender apply remove commit");
        let mut bob_after_remove =
            RatchetTree::from_leaves(vec![make_leaf(96), make_leaf(97), make_leaf(98)]);
        let bob_derived = bob_after_remove
            .apply_commit_with_path_update(&remove_commit, &path_update_remove, 1, &bob_priv)
            .expect("bob apply remove commit");
        assert!(bob_derived.iter().any(|v| v.is_some()));
        assert_eq!(sender_state, bob_after_remove);

        let mut tree_after_bob_update = sender_state.clone();
        let bob_kp_epoch2 = make_key_package(100);
        tree_after_bob_update
            .update_leaf(1, &bob_kp_epoch2)
            .expect("update bob leaf in temp tree");
        let path_epoch2 = parent_updates_for(&tree_after_bob_update, 1, 101);
        let bob_update_commit = Commit {
            sender: 1,
            proposals: vec![Proposal::Update {
                leaf_index: 1,
                key_package: bob_kp_epoch2,
            }],
            path: path_epoch2,
        };
        let mut rng_epoch2 = TestRng(0x4040_4040_4040_4040);
        let path_update_epoch2 = tree_after_bob_update
            .build_path_update(&mut rng_epoch2, 1, [0x44u8; 32])
            .expect("path update epoch2");

        let mut alice_after_remove = sender_state.clone();
        let mut removed_carol_state = sender_state.clone();
        let alice_priv = hybrid_private_key(96);
        let alice_derived = alice_after_remove
            .apply_commit_with_path_update(&bob_update_commit, &path_update_epoch2, 0, &alice_priv)
            .expect("alice apply bob update");
        assert!(alice_derived.iter().any(|v| v.is_some()));

        let removed_result = removed_carol_state.apply_commit_with_path_update(
            &bob_update_commit,
            &path_update_epoch2,
            2,
            &carol_priv,
        );
        assert!(removed_result.is_none());
    }

    #[test]
    fn path_secret_derivation_is_context_bound() {
        let parent_secret = [0x55u8; 32];
        let a = derive_path_secret(&parent_secret, 3, 1);
        let b = derive_path_secret(&parent_secret, 4, 1);
        let c = derive_path_secret(&parent_secret, 3, 2);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn path_secret_encryption_context_is_field_bound() {
        let c1 = path_secret_encryption_context(0, 1, 2);
        let c2 = path_secret_encryption_context(0, 1, 3);
        let c3 = path_secret_encryption_context(1, 1, 2);
        assert_ne!(c1, c2);
        assert_ne!(c1, c3);
    }

    #[test]
    fn validate_commit_allows_multiple_distinct_adds() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(60)]);
        let commit = Commit {
            sender: 0,
            proposals: vec![
                Proposal::Add(make_key_package(61)),
                Proposal::Add(make_key_package(62)),
            ],
            path: Vec::new(),
        };

        assert!(tree.validate_commit(&commit).is_ok());
    }

    #[test]
    fn validate_commit_rejects_duplicate_add_target() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(63)]);
        let add_kp = make_key_package(64);
        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::Add(add_kp.clone()), Proposal::Add(add_kp)],
            path: Vec::new(),
        };

        let result = tree.validate_commit(&commit);
        assert_eq!(result, Err(CommitValidationError::DuplicateAddTarget));
    }

    #[test]
    fn validate_commit_rejects_add_identity_already_member() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(65)]);
        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::Add(make_key_package(65))],
            path: Vec::new(),
        };

        let result = tree.validate_commit(&commit);
        assert_eq!(result, Err(CommitValidationError::AddIdentityAlreadyMember));
    }

    #[test]
    fn validate_commit_rejects_invalid_add_key_package() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(66)]);
        let mut bad_add = make_key_package(67);
        bad_add.signature = make_key_package(68).signature;
        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::Add(bad_add)],
            path: Vec::new(),
        };

        let result = tree.validate_commit(&commit);
        assert_eq!(result, Err(CommitValidationError::InvalidAddKeyPackage));
    }

    #[test]
    fn proposal_encode_decode_roundtrip_pre_shared_key() {
        let proposal = Proposal::PreSharedKey {
            psk_id: b"psk-ref-01".to_vec(),
        };
        let encoded = proposal.encode();
        let decoded = Proposal::decode(&encoded).expect("decode pre-shared-key proposal");
        match decoded {
            Proposal::PreSharedKey { psk_id } => assert_eq!(psk_id, b"psk-ref-01"),
            other => panic!("expected PreSharedKey proposal, got {other:?}"),
        }
    }

    #[test]
    fn validate_commit_rejects_empty_pre_shared_key_id() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(62)]);
        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::PreSharedKey { psk_id: Vec::new() }],
            path: Vec::new(),
        };

        let result = tree.validate_commit(&commit);
        assert_eq!(result, Err(CommitValidationError::EmptyPreSharedKeyId));
    }

    #[test]
    fn validate_commit_rejects_duplicate_pre_shared_key_ids() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(63)]);
        let commit = Commit {
            sender: 0,
            proposals: vec![
                Proposal::PreSharedKey {
                    psk_id: b"shared-psk".to_vec(),
                },
                Proposal::PreSharedKey {
                    psk_id: b"shared-psk".to_vec(),
                },
            ],
            path: Vec::new(),
        };

        let result = tree.validate_commit(&commit);
        assert_eq!(result, Err(CommitValidationError::DuplicatePreSharedKey));
    }

    #[test]
    fn apply_commit_with_pre_shared_key_only_keeps_tree_shape() {
        let mut tree = RatchetTree::from_leaves(vec![make_leaf(64)]);
        let before = tree.clone();
        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::PreSharedKey {
                psk_id: b"psk-for-next-epoch".to_vec(),
            }],
            path: Vec::new(),
        };

        tree.apply_commit(&commit)
            .expect("apply pre-shared-key commit");
        assert_eq!(tree, before);
    }

    #[test]
    fn proposal_encode_decode_roundtrip_reinit() {
        let proposal = Proposal::ReInit {
            group_id: "group-v2".to_string(),
            version: 1,
            cipher_suite: 0x0001,
            extensions: vec![1, 2, 3, 4],
        };
        let encoded = proposal.encode();
        let decoded = Proposal::decode(&encoded).expect("decode reinit proposal");
        match decoded {
            Proposal::ReInit {
                group_id,
                version,
                cipher_suite,
                extensions,
            } => {
                assert_eq!(group_id, "group-v2");
                assert_eq!(version, 1);
                assert_eq!(cipher_suite, 0x0001);
                assert_eq!(extensions, vec![1, 2, 3, 4]);
            }
            other => panic!("expected ReInit proposal, got {other:?}"),
        }
    }

    #[test]
    fn validate_commit_rejects_duplicate_reinit() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(65)]);
        let commit = Commit {
            sender: 0,
            proposals: vec![
                Proposal::ReInit {
                    group_id: "group-v2-a".to_string(),
                    version: 1,
                    cipher_suite: 0x0001,
                    extensions: Vec::new(),
                },
                Proposal::ReInit {
                    group_id: "group-v2-b".to_string(),
                    version: 1,
                    cipher_suite: 0x0001,
                    extensions: Vec::new(),
                },
            ],
            path: Vec::new(),
        };

        let result = tree.validate_commit(&commit);
        assert_eq!(result, Err(CommitValidationError::DuplicateReInit));
    }

    #[test]
    fn validate_commit_rejects_mixed_reinit_proposal_set() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(66)]);
        let commit = Commit {
            sender: 0,
            proposals: vec![
                Proposal::ReInit {
                    group_id: "group-v2".to_string(),
                    version: 1,
                    cipher_suite: 0x0001,
                    extensions: Vec::new(),
                },
                Proposal::PreSharedKey {
                    psk_id: b"psk-mixed".to_vec(),
                },
            ],
            path: Vec::new(),
        };

        let result = tree.validate_commit(&commit);
        assert_eq!(result, Err(CommitValidationError::MixedReInitProposalSet));
    }

    #[test]
    fn validate_commit_rejects_reinit_with_empty_group_id() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(67)]);
        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::ReInit {
                group_id: String::new(),
                version: 1,
                cipher_suite: 0x0001,
                extensions: Vec::new(),
            }],
            path: Vec::new(),
        };

        let result = tree.validate_commit(&commit);
        assert_eq!(result, Err(CommitValidationError::EmptyReInitGroupId));
    }

    #[test]
    fn validate_commit_rejects_reinit_with_unsupported_version() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(68)]);
        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::ReInit {
                group_id: "group-v2".to_string(),
                version: 2,
                cipher_suite: 0x0001,
                extensions: Vec::new(),
            }],
            path: Vec::new(),
        };

        let result = tree.validate_commit(&commit);
        assert_eq!(
            result,
            Err(CommitValidationError::UnsupportedReInitVersion { version: 2 })
        );
    }

    #[test]
    fn validate_commit_rejects_reinit_with_unsupported_cipher_suite() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(69)]);
        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::ReInit {
                group_id: "group-v2".to_string(),
                version: 1,
                cipher_suite: 0x9999,
                extensions: Vec::new(),
            }],
            path: Vec::new(),
        };

        let result = tree.validate_commit(&commit);
        assert_eq!(
            result,
            Err(CommitValidationError::UnsupportedReInitCipherSuite {
                cipher_suite: 0x9999,
            })
        );
    }

    #[test]
    fn apply_commit_with_reinit_only_keeps_tree_shape() {
        let mut tree = RatchetTree::from_leaves(vec![make_leaf(70)]);
        let before = tree.clone();
        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::ReInit {
                group_id: "group-v2".to_string(),
                version: 1,
                cipher_suite: 0x0001,
                extensions: Vec::new(),
            }],
            path: Vec::new(),
        };

        tree.apply_commit(&commit).expect("apply reinit commit");
        assert_eq!(tree, before);
    }

    #[test]
    fn proposal_encode_decode_roundtrip_group_context_extensions() {
        let proposal = Proposal::GroupContextExtensions {
            extensions: vec![0xA1, 0xB2, 0xC3],
        };
        let encoded = proposal.encode();
        let decoded = Proposal::decode(&encoded).expect("decode group-context-extensions");
        match decoded {
            Proposal::GroupContextExtensions { extensions } => {
                assert_eq!(extensions, vec![0xA1, 0xB2, 0xC3]);
            }
            other => panic!("expected GroupContextExtensions proposal, got {other:?}"),
        }
    }

    #[test]
    fn validate_commit_rejects_duplicate_group_context_extensions() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(75)]);
        let commit = Commit {
            sender: 0,
            proposals: vec![
                Proposal::GroupContextExtensions {
                    extensions: vec![0x01],
                },
                Proposal::GroupContextExtensions {
                    extensions: vec![0x02],
                },
            ],
            path: Vec::new(),
        };

        let result = tree.validate_commit(&commit);
        assert_eq!(
            result,
            Err(CommitValidationError::DuplicateGroupContextExtensions)
        );
    }

    #[test]
    fn validate_commit_rejects_reinit_and_group_context_extensions_conflict() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(76)]);
        let commit = Commit {
            sender: 0,
            proposals: vec![
                Proposal::ReInit {
                    group_id: "group-v2".to_string(),
                    version: 1,
                    cipher_suite: 0x0001,
                    extensions: Vec::new(),
                },
                Proposal::GroupContextExtensions {
                    extensions: vec![0x01, 0x02],
                },
            ],
            path: Vec::new(),
        };

        let result = tree.validate_commit(&commit);
        assert_eq!(
            result,
            Err(CommitValidationError::ReInitAndGroupContextExtensionsConflict)
        );
    }

    #[test]
    fn apply_commit_with_group_context_extensions_only_keeps_tree_shape() {
        let mut tree = RatchetTree::from_leaves(vec![make_leaf(77)]);
        let before = tree.clone();
        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::GroupContextExtensions {
                extensions: vec![0x10, 0x20],
            }],
            path: Vec::new(),
        };

        tree.apply_commit(&commit)
            .expect("apply group-context-extensions commit");
        assert_eq!(tree, before);
    }

    #[test]
    fn commit_encode_decode_roundtrip_without_path_update() {
        let leaf0 = make_leaf(71);
        let leaf1 = make_leaf(72);
        let mut tree = RatchetTree::from_leaves(vec![leaf0, leaf1]);

        let update_kp = make_key_package(73);
        let parent_path = parent_updates_for(&tree, 0, 74);
        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::Update {
                leaf_index: 1,
                key_package: update_kp,
            }],
            path: parent_path,
        };

        let encoded = commit.encode();
        let decoded = Commit::decode(&encoded).expect("decode");
        assert_eq!(decoded.encode(), encoded);
        assert!(tree.apply_commit(&decoded).is_some());
    }

    #[test]
    fn commit_encode_decode_roundtrip_with_path_update() {
        let sender_leaf = make_leaf(70);
        let tree = RatchetTree::from_leaves(vec![sender_leaf]);

        let add_kp = make_key_package(71);
        let mut tree_after = tree.clone();
        tree_after
            .insert_key_package(&add_kp)
            .expect("insert into temp tree");
        let parent_path = parent_updates_for(&tree_after, 0, 72);

        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::Add(add_kp.clone())],
            path: parent_path,
        };

        let mut rng = TestRng(0x2222222222222222);
        let path_update = tree_after
            .build_path_update(&mut rng, 0, [3u8; 32])
            .expect("path update");

        let encoded = commit.encode_with_path_update(&path_update);
        let (decoded_commit, decoded_path_update) =
            Commit::decode_with_path_update(&encoded).expect("decode with path update");
        let decoded_path_update = decoded_path_update.expect("missing path update");

        assert_eq!(decoded_commit.encode(), commit.encode());
        assert_eq!(decoded_path_update.encode(), path_update.encode());
    }

    #[test]
    fn commit_decode_rejects_truncated_bytes() {
        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::Remove { leaf_index: 0 }],
            path: Vec::new(),
        };
        let encoded = commit.encode();
        assert!(Commit::decode(&encoded).is_some());

        let mut truncated = encoded;
        let _ = truncated.pop();
        assert!(Commit::decode(&truncated).is_none());
    }

    #[test]
    fn commit_decode_with_path_update_rejects_malformed_bytes() {
        let commit = Commit {
            sender: 0,
            proposals: vec![Proposal::Remove { leaf_index: 0 }],
            path: Vec::new(),
        };
        let path_update = PathUpdate {
            path_secrets: Vec::new(),
            ciphertexts: Vec::new(),
        };

        let encoded = commit.encode_with_path_update(&path_update);
        assert!(Commit::decode_with_path_update(&encoded).is_some());

        let mut truncated = encoded.clone();
        let _ = truncated.pop();
        assert!(Commit::decode_with_path_update(&truncated).is_none());

        let mut trailing = encoded;
        trailing.push(0xEE);
        assert!(Commit::decode_with_path_update(&trailing).is_none());
    }

    #[test]
    fn path_update_decode_rejects_malformed_bytes() {
        let update = PathUpdate {
            path_secrets: Vec::new(),
            ciphertexts: Vec::new(),
        };
        let encoded = update.encode();
        assert!(PathUpdate::decode(&encoded).is_some());

        let mut truncated = encoded.clone();
        let _ = truncated.pop();
        assert!(PathUpdate::decode(&truncated).is_none());

        let mut trailing = encoded;
        trailing.push(0xEF);
        assert!(PathUpdate::decode(&trailing).is_none());
    }

    #[test]
    fn path_secret_ciphertext_decode_rejects_wrong_classic_length() {
        let mut encoded = Vec::new();
        encode_bytes(&mut encoded, &[0u8; 31]);
        encode_bytes(&mut encoded, &[1u8; 1]);
        encode_bytes(&mut encoded, &[2u8; 1]);
        assert!(PathSecretCiphertext::decode(&encoded).is_none());
    }

    #[test]
    fn path_secret_ciphertext_decode_rejects_wrong_pq_length() {
        let mut encoded = Vec::new();
        encode_bytes(&mut encoded, &[0u8; 32]);
        encode_bytes(&mut encoded, &[1u8; 1]);
        encode_bytes(&mut encoded, &[2u8; 1]);
        assert!(PathSecretCiphertext::decode(&encoded).is_none());
    }

    #[test]
    fn path_update_decode_rejects_corrupted_level_counts() {
        let mut missing_ct_entry = Vec::new();
        encode_u32(&mut missing_ct_entry, 1); // levels
        encode_u32(&mut missing_ct_entry, 1); // level[0] count, but no entries follow
        assert!(PathUpdate::decode(&missing_ct_entry).is_none());

        let mut missing_second_level = Vec::new();
        encode_u32(&mut missing_second_level, 2); // levels
        encode_u32(&mut missing_second_level, 0); // level[0] count
                                                  // level[1] count is missing
        assert!(PathUpdate::decode(&missing_second_level).is_none());
    }

    #[test]
    fn direct_path_and_copath_are_leaf_to_root_ordered() {
        let tree = RatchetTree::from_leaves(vec![
            make_leaf(90),
            make_leaf(91),
            make_leaf(92),
            make_leaf(93),
        ]);

        let direct = tree.direct_path(0).expect("direct path");
        let copath = tree.copath(0).expect("copath");

        assert_eq!(direct, vec![1, 3], "expected leaf->root direct path");
        assert_eq!(copath, vec![2, 5], "expected leaf->root copath");
    }

    #[test]
    fn filtered_direct_path_preserves_leaf_to_root_order() {
        let mut tree = RatchetTree::from_leaves(vec![
            make_leaf(100),
            make_leaf(101),
            make_leaf(102),
            make_leaf(103),
        ]);

        let direct = tree.direct_path(0).expect("direct path");
        let filtered = tree
            .filtered_direct_path(0)
            .expect("filtered direct path");
        assert_eq!(filtered, direct);

        tree.nodes[RatchetTree::leaf_to_node_index(1)] = Node::Blank;
        tree.nodes[RatchetTree::leaf_to_node_index(2)] = Node::Blank;
        tree.nodes[RatchetTree::leaf_to_node_index(3)] = Node::Blank;
        let filtered_after_blank = tree
            .filtered_direct_path(0)
            .expect("filtered direct path after blanking");
        assert_eq!(filtered_after_blank, Vec::<usize>::new());
    }

    #[test]
    fn ratchet_tree_encode_decode_roundtrip() {
        let leaf0 = make_leaf(80);
        let leaf1 = make_leaf(81);
        let mut tree = RatchetTree::from_leaves(vec![leaf0, leaf1]);

        let root = tree.root_index().expect("root");
        tree.nodes[root] = Node::Parent(ParentNode {
            public_key: hybrid_public_key(82),
            parent_hash: vec![1, 2, 3, 4],
            unmerged_leaves: vec![0, 1],
        });

        let encoded = tree.encode();
        let decoded = RatchetTree::decode(&encoded).expect("decode tree");
        assert_eq!(decoded, tree);
    }
}
