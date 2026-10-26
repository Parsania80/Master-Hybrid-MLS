use ed25519_dalek::{SigningKey as EdSecret, VerifyingKey as EdPublic};
use hybrid_mls::client_state::ClientGroupState;
use hybrid_mls::crypto::{
    HybridPrivateKey, HybridPublicKey, HybridSignPrivKey, HybridSignPubKey, KyberPriv,
};
use hybrid_mls::envelope::{CommitEnvelope, PathUpdateEnvelope};
use hybrid_mls::tree::{Commit, KeyPackage, LeafNode, Node, ParentUpdate, Proposal, RatchetTree};
use ml_dsa::{KeyGen, MlDsa65};
use ml_kem::Seed;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand_core::{Infallible, TryCryptoRng, TryRng};
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret as X25519Priv};

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
        let mut offset = 0usize;
        while offset < dst.len() {
            let chunk = self.next_u64_internal().to_le_bytes();
            let take = (dst.len() - offset).min(chunk.len());
            dst[offset..offset + take].copy_from_slice(&chunk[..take]);
            offset += take;
        }
        Ok(())
    }
}

impl TryCryptoRng for TestRng {}

#[derive(Clone)]
struct MemberMaterial {
    key_package: KeyPackage,
    private_key: HybridPrivateKey,
}

fn hybrid_signing_keys(seed: u8) -> (HybridSignPubKey, HybridSignPrivKey) {
    let classic_priv = EdSecret::from_bytes(&[seed; 32]);
    let classic_pub = EdPublic::from(&classic_priv);

    let mut rng = StdRng::seed_from_u64(seed as u64);
    let kp = MlDsa65::key_gen(&mut rng);

    (
        HybridSignPubKey {
            classic: classic_pub,
            pq: kp.verifying_key().clone(),
        },
        HybridSignPrivKey {
            classic: classic_priv,
            pq: kp.signing_key().clone(),
        },
    )
}

fn member_material(seed: u8) -> MemberMaterial {
    let classic_priv = X25519Priv::from([seed; 32]);
    let classic_pub = X25519Pub::from(&classic_priv);

    let kem_seed = Seed::from([seed; 64]);
    let kyber_priv = KyberPriv::from_seed(kem_seed);
    let kyber_pub = kyber_priv.encapsulation_key().clone();

    let init_key = HybridPublicKey {
        classic: classic_pub,
        pq: kyber_pub,
    };

    let (identity, signer) = hybrid_signing_keys(seed);
    let signature = signer.sign(&init_key.to_bytes());
    let key_package = KeyPackage {
        identity,
        init_key,
        signature,
    };

    MemberMaterial {
        key_package,
        private_key: HybridPrivateKey {
            classic: classic_priv,
            pq: kyber_priv,
        },
    }
}

fn leaf_from_key_package(kp: &KeyPackage) -> LeafNode {
    LeafNode {
        public_key: kp.init_key.clone(),
        credential: kp.identity.clone(),
    }
}

fn test_parent_public(seed: u8) -> HybridPublicKey {
    let classic_priv = X25519Priv::from([seed; 32]);
    let classic_pub = X25519Pub::from(&classic_priv);
    let kyber_priv = KyberPriv::from_seed(Seed::from([seed; 64]));
    HybridPublicKey {
        classic: classic_pub,
        pq: kyber_priv.encapsulation_key().clone(),
    }
}

#[test]
fn apply_real_commit_and_path_update_across_two_client_states() {
    let alice_initial = member_material(11);
    let bob_initial = member_material(22);
    let alice_update = member_material(33);

    let initial_tree = RatchetTree::from_leaves(vec![
        leaf_from_key_package(&alice_initial.key_package),
        leaf_from_key_package(&bob_initial.key_package),
    ]);

    let mut alice_state = ClientGroupState::new("group-integration", initial_tree.clone(), 0);
    let mut bob_state = ClientGroupState::new("group-integration", initial_tree.clone(), 1);

    let proposal = Proposal::Update {
        leaf_index: 0,
        key_package: alice_update.key_package.clone(),
    };
    alice_state.queue_proposal(&proposal);
    let proposals = alice_state
        .decoded_pending_proposals()
        .expect("decode pending proposals");
    assert_eq!(proposals.len(), 1);

    let mut tree_after_proposals = alice_state.ratchet_tree.clone();
    let alice_node = RatchetTree::leaf_to_node_index(0);
    tree_after_proposals.nodes[alice_node] =
        Node::Leaf(leaf_from_key_package(&alice_update.key_package));

    let direct_path = tree_after_proposals
        .direct_path(0)
        .expect("sender direct path");
    let path: Vec<ParentUpdate> = direct_path
        .iter()
        .map(|_| ParentUpdate {
            public_key: test_parent_public(44),
            unmerged_leaves: Vec::new(),
        })
        .collect();

    let mut rng = TestRng(0xABCDEF1122334455);
    let path_update = tree_after_proposals
        .build_path_update(&mut rng, 0, [0x5Au8; 32])
        .expect("build path update");

    let commit = Commit {
        sender: 0,
        proposals: proposals.clone(),
        path,
    };

    let commit_envelope = CommitEnvelope {
        group_id: alice_state.group_id.clone(),
        epoch: alice_state.epoch,
        sender_leaf: 0,
        commit: commit.clone(),
    };
    let path_envelope = PathUpdateEnvelope {
        group_id: alice_state.group_id.clone(),
        epoch: alice_state.epoch,
        sender_leaf: 0,
        path_update: path_update.clone(),
    };

    let commit_wire = commit_envelope.encode();
    let path_wire = path_envelope.encode();
    let decoded_commit = CommitEnvelope::decode(&commit_wire).expect("decode commit envelope");
    let decoded_path = PathUpdateEnvelope::decode(&path_wire).expect("decode path envelope");

    alice_state
        .ratchet_tree
        .apply_commit(&decoded_commit.commit)
        .expect("sender apply commit");
    alice_state.clear_pending_proposals();
    alice_state.epoch += 1;

    let derived = bob_state
        .ratchet_tree
        .apply_commit_with_path_update(
            &decoded_commit.commit,
            &decoded_path.path_update,
            bob_state.own_leaf_index,
            &bob_initial.private_key,
        )
        .expect("receiver apply commit + path update");
    bob_state.clear_pending_proposals();
    bob_state.epoch += 1;

    assert_eq!(alice_state.epoch, 1);
    assert_eq!(bob_state.epoch, 1);
    assert_eq!(alice_state.ratchet_tree, bob_state.ratchet_tree);
    assert_eq!(derived.len(), decoded_path.path_update.ciphertexts.len());
    assert!(derived.iter().any(|v| v.is_some()));

    let updated_leaf = RatchetTree::leaf_to_node_index(0);
    match &bob_state.ratchet_tree.nodes[updated_leaf] {
        Node::Leaf(leaf) => assert_eq!(leaf.public_key, alice_update.key_package.init_key),
        other => panic!("expected updated sender leaf, got {other:?}"),
    }
}
