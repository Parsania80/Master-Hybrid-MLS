use std::collections::BTreeMap;

use hybrid_mls::client_state::ClientGroupState;
use hybrid_mls::crypto::{HybridPublicKey, HybridSignPubKey, KyberPriv};
use hybrid_mls::envelope::CommitEnvelope;
use hybrid_mls::tree::{Commit, LeafNode, RatchetTree};
use ml_dsa::{KeyGen, MlDsa65};
use ml_kem::Seed;
use rand::rngs::StdRng;
use rand::SeedableRng;
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret as X25519Priv};

#[derive(Clone)]
struct StreamEntry {
    id: i64,
    kind: &'static str,
    bytes: Vec<u8>,
}

struct StreamResult {
    applied: usize,
    skipped: usize,
    stopped_on_gap: bool,
}

fn make_leaf(seed: u8) -> LeafNode {
    let classic_priv = X25519Priv::from([seed; 32]);
    let classic_pub = X25519Pub::from(&classic_priv);
    let kyber_priv = KyberPriv::from_seed(Seed::from([seed; 64]));

    let classic_signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let mut rng = StdRng::seed_from_u64(seed as u64);
    let dsa = MlDsa65::key_gen(&mut rng);

    LeafNode {
        public_key: HybridPublicKey {
            classic: classic_pub,
            pq: kyber_priv.encapsulation_key().clone(),
        },
        credential: HybridSignPubKey {
            classic: classic_signing.verifying_key(),
            pq: dsa.verifying_key().clone(),
        },
    }
}

fn commit_bytes(group_id: &str, epoch: u64, sender_leaf: usize) -> Vec<u8> {
    let envelope = CommitEnvelope {
        group_id: group_id.to_string(),
        epoch,
        sender_leaf,
        commit: Commit {
            sender: sender_leaf,
            proposals: Vec::new(),
            path: Vec::new(),
        },
    };
    envelope.encode()
}

fn process_stream(state: &mut ClientGroupState, entries: &[StreamEntry]) -> StreamResult {
    let mut by_id = BTreeMap::<i64, &StreamEntry>::new();
    for entry in entries {
        by_id.entry(entry.id).or_insert(entry);
    }

    let ids: Vec<i64> = by_id.keys().copied().collect();
    let mut applied = 0usize;
    let mut skipped = 0usize;
    let mut stopped_on_gap = false;

    for id in ids {
        if state.has_applied_commit_id(id) {
            skipped += 1;
            continue;
        }

        let entry = by_id.get(&id).expect("entry by id");
        if entry.kind != "commit" {
            skipped += 1;
            continue;
        }

        let Some(commit_env) = CommitEnvelope::decode(&entry.bytes) else {
            skipped += 1;
            continue;
        };

        if commit_env.group_id != state.group_id {
            skipped += 1;
            continue;
        }
        if commit_env.epoch > state.epoch {
            stopped_on_gap = true;
            break;
        }
        if commit_env.epoch < state.epoch || commit_env.sender_leaf != commit_env.commit.sender {
            skipped += 1;
            continue;
        }

        state
            .ratchet_tree
            .apply_commit(&commit_env.commit)
            .expect("apply commit");
        state.clear_pending_proposals();
        state.advance_epoch_with_context(None);
        state.mark_applied_commit_id(id);
        applied += 1;
    }

    StreamResult {
        applied,
        skipped,
        stopped_on_gap,
    }
}

#[test]
fn replay_out_of_order_and_noisy_streams_are_handled() {
    let group_id = "stream-group";
    let tree = RatchetTree::from_leaves(vec![make_leaf(9)]);
    let mut state = ClientGroupState::new(group_id, tree, 0);

    // Unsorted stream with noise + duplicate IDs.
    let entries = vec![
        StreamEntry {
            id: 40,
            kind: "commit",
            bytes: commit_bytes(group_id, 1, 0),
        },
        StreamEntry {
            id: 10,
            kind: "application",
            bytes: b"noise".to_vec(),
        },
        StreamEntry {
            id: 30,
            kind: "commit",
            bytes: commit_bytes(group_id, 0, 0),
        },
        StreamEntry {
            id: 30,
            kind: "commit",
            bytes: commit_bytes(group_id, 0, 0),
        },
        StreamEntry {
            id: 50,
            kind: "commit",
            bytes: vec![0xAA, 0xBB, 0xCC],
        },
    ];

    let first = process_stream(&mut state, &entries);
    assert_eq!(first.applied, 2);
    assert!(first.skipped >= 2);
    assert!(!first.stopped_on_gap);
    assert_eq!(state.epoch, 2);
    assert_eq!(state.last_applied_commit_id, Some(40));

    let path = std::env::temp_dir().join(format!(
        "hybrid-mls-sync-replay-{}.bin",
        rand::random::<u64>()
    ));
    state.save_to_file(&path).expect("save state");
    let mut reloaded = ClientGroupState::load_from_file(&path).expect("load state");
    let second = process_stream(&mut reloaded, &entries);
    assert_eq!(second.applied, 0);
    assert!(second.skipped >= 3);
    assert_eq!(reloaded.epoch, 2);

    let _ = std::fs::remove_file(path);
}

#[test]
fn stream_stops_on_future_epoch_gap() {
    let group_id = "stream-gap";
    let tree = RatchetTree::from_leaves(vec![make_leaf(4)]);
    let mut state = ClientGroupState::new(group_id, tree, 0);

    // Sorted by ID becomes: 10(epoch0) -> 20(epoch2 gap) -> 30(epoch1)
    // Processing should stop at ID 20 and never apply ID 30 in this pass.
    let entries = vec![
        StreamEntry {
            id: 30,
            kind: "commit",
            bytes: commit_bytes(group_id, 1, 0),
        },
        StreamEntry {
            id: 20,
            kind: "commit",
            bytes: commit_bytes(group_id, 2, 0),
        },
        StreamEntry {
            id: 10,
            kind: "commit",
            bytes: commit_bytes(group_id, 0, 0),
        },
    ];

    let result = process_stream(&mut state, &entries);
    assert_eq!(result.applied, 1);
    assert!(result.stopped_on_gap);
    assert_eq!(state.epoch, 1);
    assert_eq!(state.last_applied_commit_id, Some(10));
}
