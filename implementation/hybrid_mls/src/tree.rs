use crate::crypto::{HybridPublicKey, HybridSignPubKey, HybridSignature};
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;

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

            let parent_hash = compute_parent_hash_bytes(&parent_key, &next_parent_hash, &sibling_hash);
            if let Node::Parent(parent) = &mut self.nodes[parent_index] {
                parent.parent_hash = parent_hash.clone();
            }
            next_parent_hash = parent_hash;
        }

        Some(())
    }

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
            let (next, copath) = if in_left { (left, right) } else { (right, left) };
            path.push((current, copath));
            current = next;
        }

        Some(path)
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

fn encode_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}
