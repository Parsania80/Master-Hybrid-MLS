use crate::tree::{Commit, PathUpdate, Proposal};

#[derive(Clone, Debug)]
pub struct ProposalEnvelope {
    pub group_id: String,
    pub epoch: u64,
    pub sender_leaf: usize,
    pub proposal: Proposal,
}

#[derive(Clone, Debug)]
pub struct CommitEnvelope {
    pub group_id: String,
    pub epoch: u64,
    pub sender_leaf: usize,
    pub commit: Commit,
}

#[derive(Clone, Debug)]
pub struct PathUpdateEnvelope {
    pub group_id: String,
    pub epoch: u64,
    pub sender_leaf: usize,
    pub path_update: PathUpdate,
}

impl ProposalEnvelope {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_bytes(&mut out, self.group_id.as_bytes());
        encode_u64(&mut out, self.epoch);
        encode_u32(&mut out, self.sender_leaf as u32);
        encode_bytes(&mut out, &self.proposal.encode());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        let group_id = String::from_utf8(decoder.read_bytes()?).ok()?;
        let epoch = decoder.read_u64()?;
        let sender_leaf = decoder.read_u32()? as usize;
        let proposal_bytes = decoder.read_bytes()?;
        let proposal = Proposal::decode(&proposal_bytes)?;
        if decoder.remaining() != 0 {
            return None;
        }
        Some(Self {
            group_id,
            epoch,
            sender_leaf,
            proposal,
        })
    }
}

impl CommitEnvelope {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_bytes(&mut out, self.group_id.as_bytes());
        encode_u64(&mut out, self.epoch);
        encode_u32(&mut out, self.sender_leaf as u32);
        encode_bytes(&mut out, &self.commit.encode());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        let group_id = String::from_utf8(decoder.read_bytes()?).ok()?;
        let epoch = decoder.read_u64()?;
        let sender_leaf = decoder.read_u32()? as usize;
        let commit_bytes = decoder.read_bytes()?;
        let commit = Commit::decode(&commit_bytes)?;
        if decoder.remaining() != 0 {
            return None;
        }
        Some(Self {
            group_id,
            epoch,
            sender_leaf,
            commit,
        })
    }
}

impl PathUpdateEnvelope {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_bytes(&mut out, self.group_id.as_bytes());
        encode_u64(&mut out, self.epoch);
        encode_u32(&mut out, self.sender_leaf as u32);
        encode_bytes(&mut out, &self.path_update.encode());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        let group_id = String::from_utf8(decoder.read_bytes()?).ok()?;
        let epoch = decoder.read_u64()?;
        let sender_leaf = decoder.read_u32()? as usize;
        let path_update_bytes = decoder.read_bytes()?;
        let path_update = PathUpdate::decode(&path_update_bytes)?;
        if decoder.remaining() != 0 {
            return None;
        }
        Some(Self {
            group_id,
            epoch,
            sender_leaf,
            path_update,
        })
    }
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
    use sha3::{Digest, Sha3_256};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn sha3_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(bytes);
        hex(&hasher.finalize())
    }

    #[test]
    fn proposal_envelope_roundtrip() {
        let envelope = ProposalEnvelope {
            group_id: "group-1".to_string(),
            epoch: 2,
            sender_leaf: 0,
            proposal: Proposal::Remove { leaf_index: 3 },
        };
        let encoded = envelope.encode();
        let decoded = ProposalEnvelope::decode(&encoded).expect("decode proposal envelope");
        assert_eq!(decoded.group_id, envelope.group_id);
        assert_eq!(decoded.epoch, envelope.epoch);
        assert_eq!(decoded.sender_leaf, envelope.sender_leaf);
        assert_eq!(decoded.proposal.encode(), envelope.proposal.encode());
    }

    #[test]
    fn commit_envelope_roundtrip() {
        let commit = Commit {
            sender: 1,
            proposals: vec![Proposal::Remove { leaf_index: 2 }],
            path: Vec::new(),
        };
        let envelope = CommitEnvelope {
            group_id: "group-2".to_string(),
            epoch: 5,
            sender_leaf: 1,
            commit,
        };
        let encoded = envelope.encode();
        let decoded = CommitEnvelope::decode(&encoded).expect("decode commit envelope");
        assert_eq!(decoded.group_id, envelope.group_id);
        assert_eq!(decoded.epoch, envelope.epoch);
        assert_eq!(decoded.sender_leaf, envelope.sender_leaf);
        assert_eq!(decoded.commit.encode(), envelope.commit.encode());
    }

    #[test]
    fn path_update_envelope_roundtrip() {
        let path_update = PathUpdate {
            path_secrets: Vec::new(),
            ciphertexts: Vec::new(),
        };
        let envelope = PathUpdateEnvelope {
            group_id: "group-3".to_string(),
            epoch: 9,
            sender_leaf: 2,
            path_update,
        };
        let encoded = envelope.encode();
        let decoded = PathUpdateEnvelope::decode(&encoded).expect("decode path envelope");
        assert_eq!(decoded.encode(), encoded);
    }

    #[test]
    fn reject_trailing_bytes() {
        let envelope = ProposalEnvelope {
            group_id: "g".to_string(),
            epoch: 1,
            sender_leaf: 0,
            proposal: Proposal::Remove { leaf_index: 0 },
        };
        let mut encoded = envelope.encode();
        encoded.push(0xFF);
        assert!(ProposalEnvelope::decode(&encoded).is_none());
    }

    #[test]
    fn commit_envelope_rejects_truncated_and_trailing_bytes() {
        let envelope = CommitEnvelope {
            group_id: "group-c".to_string(),
            epoch: 3,
            sender_leaf: 1,
            commit: Commit {
                sender: 1,
                proposals: vec![Proposal::Remove { leaf_index: 0 }],
                path: Vec::new(),
            },
        };
        let encoded = envelope.encode();
        assert!(CommitEnvelope::decode(&encoded).is_some());

        let mut truncated = encoded.clone();
        let _ = truncated.pop();
        assert!(CommitEnvelope::decode(&truncated).is_none());

        let mut trailing = encoded;
        trailing.push(0xAA);
        assert!(CommitEnvelope::decode(&trailing).is_none());
    }

    #[test]
    fn path_update_envelope_rejects_truncated_and_trailing_bytes() {
        let envelope = PathUpdateEnvelope {
            group_id: "group-p".to_string(),
            epoch: 4,
            sender_leaf: 2,
            path_update: PathUpdate {
                path_secrets: Vec::new(),
                ciphertexts: Vec::new(),
            },
        };
        let encoded = envelope.encode();
        assert!(PathUpdateEnvelope::decode(&encoded).is_some());

        let mut truncated = encoded.clone();
        let _ = truncated.pop();
        assert!(PathUpdateEnvelope::decode(&truncated).is_none());

        let mut trailing = encoded;
        trailing.push(0xBB);
        assert!(PathUpdateEnvelope::decode(&trailing).is_none());
    }

    #[test]
    fn proposal_envelope_binary_fixture_vector_matches_expected() {
        let fixture = include_bytes!("../tests/vectors/proposal_envelope_vector.bin");
        assert_eq!(
            sha3_hex(fixture),
            "489c55a31798801afc9bcf782afe2ac19e97b99862ed6a984850d6f95d2b14ba"
        );

        let decoded = ProposalEnvelope::decode(fixture).expect("decode proposal fixture");
        assert_eq!(decoded.group_id, "vector-env");
        assert_eq!(decoded.epoch, 11);
        assert_eq!(decoded.sender_leaf, 4);
        assert_eq!(
            decoded.proposal.encode(),
            Proposal::Remove { leaf_index: 7 }.encode()
        );
        assert_eq!(decoded.encode(), fixture.to_vec());
    }

    #[test]
    fn commit_envelope_binary_fixture_vector_matches_expected() {
        let fixture = include_bytes!("../tests/vectors/commit_envelope_vector.bin");
        assert_eq!(
            sha3_hex(fixture),
            "4ea6ae8a8072ebce91712f638d120c17f38affe3a3e4d6669ad8babdcef78ca3"
        );

        let decoded = CommitEnvelope::decode(fixture).expect("decode commit fixture");
        assert_eq!(decoded.group_id, "vector-env");
        assert_eq!(decoded.epoch, 11);
        assert_eq!(decoded.sender_leaf, 4);
        let expected_commit = Commit {
            sender: 4,
            proposals: vec![Proposal::Remove { leaf_index: 7 }],
            path: Vec::new(),
        };
        assert_eq!(decoded.commit.encode(), expected_commit.encode());
        assert_eq!(decoded.encode(), fixture.to_vec());
    }

    #[test]
    fn path_update_envelope_binary_fixture_vector_matches_expected() {
        let fixture = include_bytes!("../tests/vectors/path_update_envelope_vector.bin");
        assert_eq!(
            sha3_hex(fixture),
            "0ea12d707c1eddb11fc195bb4ca52544f5ad373e1ad8103378e55d392cb45bb5"
        );

        let decoded = PathUpdateEnvelope::decode(fixture).expect("decode path fixture");
        assert_eq!(decoded.group_id, "vector-env");
        assert_eq!(decoded.epoch, 11);
        assert_eq!(decoded.sender_leaf, 4);
        assert!(decoded.path_update.ciphertexts.is_empty());
        assert!(decoded.path_update.path_secrets.is_empty());
        assert_eq!(decoded.encode(), fixture.to_vec());
    }

    #[test]
    fn malformed_envelope_fixtures_are_rejected() {
        let proposal_cases: [(&str, &[u8]); 2] = [
            (
                "proposal_truncated",
                include_bytes!("../tests/vectors/malformed/proposal_envelope_vector_truncated.bin"),
            ),
            (
                "proposal_trailing",
                include_bytes!("../tests/vectors/malformed/proposal_envelope_vector_trailing.bin"),
            ),
        ];
        for (name, bytes) in proposal_cases {
            assert!(
                ProposalEnvelope::decode(bytes).is_none(),
                "malformed proposal fixture should fail: {name}"
            );
        }

        let commit_cases: [(&str, &[u8]); 2] = [
            (
                "commit_truncated",
                include_bytes!("../tests/vectors/malformed/commit_envelope_vector_truncated.bin"),
            ),
            (
                "commit_trailing",
                include_bytes!("../tests/vectors/malformed/commit_envelope_vector_trailing.bin"),
            ),
        ];
        for (name, bytes) in commit_cases {
            assert!(
                CommitEnvelope::decode(bytes).is_none(),
                "malformed commit fixture should fail: {name}"
            );
        }

        let path_cases: [(&str, &[u8]); 2] = [
            (
                "path_truncated",
                include_bytes!(
                    "../tests/vectors/malformed/path_update_envelope_vector_truncated.bin"
                ),
            ),
            (
                "path_trailing",
                include_bytes!("../tests/vectors/malformed/path_update_envelope_vector_trailing.bin"),
            ),
        ];
        for (name, bytes) in path_cases {
            assert!(
                PathUpdateEnvelope::decode(bytes).is_none(),
                "malformed path fixture should fail: {name}"
            );
        }
    }
}
