use sha3::{Digest, Sha3_256};

pub use crate::stage_keys::derive_confirmation_key;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranscriptState {
    confirmed_transcript_hash: [u8; 32],
    interim_transcript_hash: [u8; 32],
}

const TRANSCRIPT_STATE_VERSION: u8 = 1;

impl TranscriptState {
    pub fn new(group_id: &str, tree_hash: [u8; 32]) -> Self {
        let confirmed_transcript_hash = transcript_hash(
            b"MLS-TRANSCRIPT-INIT-CONFIRMED",
            &[group_id.as_bytes(), &tree_hash],
        );
        let interim_transcript_hash = transcript_hash(
            b"MLS-TRANSCRIPT-INIT-INTERIM",
            &[&confirmed_transcript_hash],
        );
        Self {
            confirmed_transcript_hash,
            interim_transcript_hash,
        }
    }

    pub fn bootstrap_legacy(
        group_id: &str,
        tree_hash: [u8; 32],
        epoch: u64,
        pending_proposals: &[Vec<u8>],
    ) -> Self {
        let mut state = Self::new(group_id, tree_hash);
        for i in 0..epoch {
            let marker = i.to_be_bytes();
            let _ = state.apply_commit(&marker, None);
        }
        for proposal in pending_proposals {
            state.record_proposal(proposal);
        }
        state
    }

    pub fn confirmed_transcript_hash(&self) -> [u8; 32] {
        self.confirmed_transcript_hash
    }

    pub fn interim_transcript_hash(&self) -> [u8; 32] {
        self.interim_transcript_hash
    }

    pub fn record_proposal(&mut self, proposal_bytes: &[u8]) {
        let proposal_hash = transcript_hash(b"MLS-TRANSCRIPT-PROPOSAL", &[proposal_bytes]);
        self.interim_transcript_hash = transcript_hash(
            b"MLS-TRANSCRIPT-INTERIM-PROPOSAL",
            &[&self.interim_transcript_hash, &proposal_hash],
        );
    }

    pub fn predict_confirmed_after_commit(&self, commit_context: &[u8]) -> [u8; 32] {
        let commit_hash = transcript_hash(b"MLS-TRANSCRIPT-COMMIT", &[commit_context]);
        transcript_hash(
            b"MLS-CONFIRMED-TRANSCRIPT",
            &[&self.interim_transcript_hash, &commit_hash],
        )
    }

    pub fn apply_commit(
        &mut self,
        commit_context: &[u8],
        confirmation_tag: Option<&[u8; 32]>,
    ) -> [u8; 32] {
        let confirmed = self.predict_confirmed_after_commit(commit_context);
        let zero_tag = [0u8; 32];
        let tag = confirmation_tag.unwrap_or(&zero_tag);
        self.interim_transcript_hash =
            transcript_hash(b"MLS-INTERIM-TRANSCRIPT", &[&confirmed, tag]);
        self.confirmed_transcript_hash = confirmed;
        confirmed
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(TRANSCRIPT_STATE_VERSION);
        out.extend_from_slice(&self.confirmed_transcript_hash);
        out.extend_from_slice(&self.interim_transcript_hash);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 1 + 32 + 32 {
            return None;
        }
        if bytes[0] != TRANSCRIPT_STATE_VERSION {
            return None;
        }
        let mut confirmed_transcript_hash = [0u8; 32];
        confirmed_transcript_hash.copy_from_slice(&bytes[1..33]);
        let mut interim_transcript_hash = [0u8; 32];
        interim_transcript_hash.copy_from_slice(&bytes[33..65]);
        Some(Self {
            confirmed_transcript_hash,
            interim_transcript_hash,
        })
    }
}

pub fn derive_confirmation_tag(
    confirmation_key: &[u8; 32],
    confirmed_transcript_hash: &[u8; 32],
) -> [u8; 32] {
    transcript_hash(
        b"MLS-CONFIRMATION-TAG",
        &[confirmation_key, confirmed_transcript_hash],
    )
}

pub fn verify_confirmation_tag(
    expected_confirmation_key: &[u8; 32],
    confirmed_transcript_hash: &[u8; 32],
    received_confirmation_tag: &[u8; 32],
) -> bool {
    derive_confirmation_tag(expected_confirmation_key, confirmed_transcript_hash)
        == *received_confirmation_tag
}

fn transcript_hash(label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(label);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn transcript_state_roundtrip() {
        let mut state = TranscriptState::new("g", [1u8; 32]);
        state.record_proposal(b"proposal-1");
        let _ = state.apply_commit(b"commit-1", None);

        let encoded = state.encode();
        let decoded = TranscriptState::decode(&encoded).expect("decode transcript state");
        assert_eq!(decoded, state);
    }

    #[test]
    fn transcript_pipeline_proposal_then_commit_changes_hashes() {
        let mut state = TranscriptState::new("group", [2u8; 32]);
        let init_confirmed = state.confirmed_transcript_hash();
        let init_interim = state.interim_transcript_hash();

        state.record_proposal(b"proposal-a");
        let after_proposal_interim = state.interim_transcript_hash();
        assert_ne!(after_proposal_interim, init_interim);
        assert_eq!(state.confirmed_transcript_hash(), init_confirmed);

        let predicted = state.predict_confirmed_after_commit(b"commit-a");
        let applied = state.apply_commit(b"commit-a", Some(&[0xAB; 32]));
        assert_eq!(predicted, applied);
        assert_eq!(state.confirmed_transcript_hash(), predicted);
        assert_ne!(state.interim_transcript_hash(), after_proposal_interim);
    }

    #[test]
    fn transcript_deterministic_vector_matches_expected() {
        let mut state = TranscriptState::new("vector-group", [0x11; 32]);
        state.record_proposal(b"proposal-v1");
        let confirmed = state.apply_commit(b"commit-v1", Some(&[0x22; 32]));
        let interim = state.interim_transcript_hash();

        assert_eq!(
            hex(&confirmed),
            "2d421ec3f98e6a36855ed78d1064b9ed341bd783ef69e4f56bff1e6efba3c203"
        );
        assert_eq!(
            hex(&interim),
            "55a7aa78850a604bf82375f8efec0d40070f23672cdd9c6137337a8b09bd8e5b"
        );
    }

    #[test]
    fn confirmation_tag_derive_and_verify() {
        let epoch_secret = [0x33u8; 32];
        let confirmation_key = derive_confirmation_key(&epoch_secret);
        let confirmed = [0x44u8; 32];
        let tag = derive_confirmation_tag(&confirmation_key, &confirmed);
        assert!(verify_confirmation_tag(&confirmation_key, &confirmed, &tag));

        let mut tampered = tag;
        tampered[0] ^= 0x80;
        assert!(!verify_confirmation_tag(
            &confirmation_key,
            &confirmed,
            &tampered
        ));
    }
}
