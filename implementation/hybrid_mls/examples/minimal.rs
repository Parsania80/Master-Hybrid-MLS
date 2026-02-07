use hybrid_mls::crypto::{
    HybridPrivateKey, HybridPublicKey, HybridSignPrivKey, HybridSignPubKey,
};
use hybrid_mls::tree::{Commit, KeyPackage, LeafNode, ParentUpdate, Proposal, RatchetTree};
use ml_dsa::{KeyGen, MlDsa65};
use ml_kem::Seed;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use rand_core::{Infallible, TryCryptoRng, TryRng};
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret as X25519Priv};

#[derive(Debug)]
struct ExampleRng(u64);

impl ExampleRng {
    fn next_u64_internal(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

impl TryRng for ExampleRng {
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

impl TryCryptoRng for ExampleRng {}

fn make_hybrid_kem_keypair(rng: &mut StdRng) -> (HybridPublicKey, HybridPrivateKey) {
    let mut classic_bytes = [0u8; 32];
    rng.fill_bytes(&mut classic_bytes);
    let classic_priv = X25519Priv::from(classic_bytes);
    let classic_pub = X25519Pub::from(&classic_priv);

    let mut seed_bytes = [0u8; 64];
    rng.fill_bytes(&mut seed_bytes);
    let kyber_priv = hybrid_mls::crypto::KyberPriv::from_seed(Seed::from(seed_bytes));
    let kyber_pub = kyber_priv.encapsulation_key().clone();

    (
        HybridPublicKey {
            classic: classic_pub,
            pq: kyber_pub,
        },
        HybridPrivateKey {
            classic: classic_priv,
            pq: kyber_priv,
        },
    )
}

fn make_hybrid_sign_keypair(rng: &mut StdRng) -> (HybridSignPubKey, HybridSignPrivKey) {
    let mut classic_bytes = [0u8; 32];
    rng.fill_bytes(&mut classic_bytes);
    let classic_priv = ed25519_dalek::SigningKey::from_bytes(&classic_bytes);
    let classic_pub = ed25519_dalek::VerifyingKey::from(&classic_priv);

    let kp = MlDsa65::key_gen(rng);
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

fn make_key_package(rng: &mut StdRng) -> (KeyPackage, HybridPrivateKey) {
    let (init_pub, init_priv) = make_hybrid_kem_keypair(rng);
    let (identity_pub, identity_priv) = make_hybrid_sign_keypair(rng);
    let signature = identity_priv.sign(&init_pub.to_bytes());

    (
        KeyPackage {
            identity: identity_pub,
            init_key: init_pub,
            signature,
        },
        init_priv,
    )
}

fn main() {
    let mut rng = StdRng::seed_from_u64(42);
    let mut kem_rng = ExampleRng(0x5a5a5a5a5a5a5a5a);

    let (alice_kp, _alice_priv) = make_key_package(&mut rng);
    let (bob_kp, bob_priv) = make_key_package(&mut rng);

    let alice_leaf = LeafNode {
        public_key: alice_kp.init_key.clone(),
        credential: alice_kp.identity.clone(),
    };

    let mut tree = RatchetTree::from_leaves(vec![alice_leaf]);

    // Build a post-Add view to compute direct path length.
    let bob_leaf = LeafNode {
        public_key: bob_kp.init_key.clone(),
        credential: bob_kp.identity.clone(),
    };
    let tree_after = RatchetTree::from_leaves(vec![
        LeafNode {
            public_key: alice_kp.init_key.clone(),
            credential: alice_kp.identity.clone(),
        },
        bob_leaf,
    ]);

    let parent_path: Vec<ParentUpdate> = tree_after
        .direct_path(0)
        .expect("direct path")
        .iter()
        .map(|_| ParentUpdate {
            public_key: make_hybrid_kem_keypair(&mut rng).0,
            unmerged_leaves: Vec::new(),
        })
        .collect();

    let commit = Commit {
        sender: 0,
        proposals: vec![Proposal::Add(bob_kp.clone())],
        path: parent_path,
    };

    tree.apply_commit(&commit).expect("commit failed");

    // Build a path update and have Bob process it.
    let leaf_secret = [7u8; 32];
    let path_update = tree_after
        .build_path_update(&mut kem_rng, 0, leaf_secret)
        .expect("path update");

    let derived = tree_after
        .process_path_update_for_leaf(0, 1, &bob_priv, &path_update)
        .expect("process path update");

    println!("Bob derived secrets (root to leaf parent): {derived:?}");
}
