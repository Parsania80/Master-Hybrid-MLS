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
}
