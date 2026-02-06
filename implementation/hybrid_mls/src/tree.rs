use crate::crypto::{HybridPublicKey, HybridSignPubKey, HybridSignature};

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
    pub unmerged_leaves: Vec<u32>, 
}

#[derive(Clone, Debug, PartialEq)]
pub enum Node {
    Leaf(LeafNode),
    Parent(ParentNode),
    Blank,
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
