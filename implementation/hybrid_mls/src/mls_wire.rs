use crate::envelope::{CommitEnvelope, PathUpdateEnvelope, ProposalEnvelope};
use crate::tree::{Commit, PathUpdate, Proposal};

/// RFC 9420 MLS protocol version (MLS 1.0).
pub const MLS_PROTOCOL_VERSION: u16 = 0x0001;

/// Wire formats for `MLSMessage`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireFormat {
    PublicMessage = 1,
    PrivateMessage = 2,
}

impl WireFormat {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::PublicMessage),
            2 => Some(Self::PrivateMessage),
            _ => None,
        }
    }
}

/// Content types modeled for the current prototype.
///
/// `PathUpdate` is a project extension to bridge existing split-message transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentType {
    Proposal = 1,
    Commit = 2,
    Application = 3,
    PathUpdate = 0x80,
}

impl ContentType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Proposal),
            2 => Some(Self::Commit),
            3 => Some(Self::Application),
            0x80 => Some(Self::PathUpdate),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicMessage {
    pub group_id: String,
    pub epoch: u64,
    pub sender_leaf: u32,
    pub content_type: ContentType,
    pub authenticated_data: Vec<u8>,
    pub content: Vec<u8>,
    pub membership_tag: Option<Vec<u8>>,
    pub confirmation_tag: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateMessage {
    pub group_id: String,
    pub epoch: u64,
    pub content_type: ContentType,
    pub authenticated_data: Vec<u8>,
    pub encrypted_sender_data: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MlsMessageBody {
    Public(PublicMessage),
    Private(PrivateMessage),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsMessage {
    pub version: u16,
    pub body: MlsMessageBody,
}

impl MlsMessage {
    pub fn from_public(message: PublicMessage) -> Self {
        Self {
            version: MLS_PROTOCOL_VERSION,
            body: MlsMessageBody::Public(message),
        }
    }

    pub fn from_private(message: PrivateMessage) -> Self {
        Self {
            version: MLS_PROTOCOL_VERSION,
            body: MlsMessageBody::Private(message),
        }
    }

    pub fn wire_format(&self) -> WireFormat {
        match self.body {
            MlsMessageBody::Public(_) => WireFormat::PublicMessage,
            MlsMessageBody::Private(_) => WireFormat::PrivateMessage,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_u16(&mut out, self.version);
        encode_u8(&mut out, self.wire_format() as u8);
        match &self.body {
            MlsMessageBody::Public(public) => encode_bytes(&mut out, &public.encode()),
            MlsMessageBody::Private(private) => encode_bytes(&mut out, &private.encode()),
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.read_u16()?;
        if version != MLS_PROTOCOL_VERSION {
            return None;
        }
        let wire = WireFormat::from_u8(decoder.read_u8()?)?;
        let body_bytes = decoder.read_bytes()?;
        if decoder.remaining() != 0 {
            return None;
        }

        let body = match wire {
            WireFormat::PublicMessage => MlsMessageBody::Public(PublicMessage::decode(&body_bytes)?),
            WireFormat::PrivateMessage => {
                MlsMessageBody::Private(PrivateMessage::decode(&body_bytes)?)
            }
        };
        Some(Self { version, body })
    }
}

impl PublicMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_bytes(&mut out, self.group_id.as_bytes());
        encode_u64(&mut out, self.epoch);
        encode_u32(&mut out, self.sender_leaf);
        encode_u8(&mut out, self.content_type as u8);
        encode_bytes(&mut out, &self.authenticated_data);
        encode_bytes(&mut out, &self.content);
        match &self.membership_tag {
            Some(tag) => {
                encode_u8(&mut out, 1);
                encode_bytes(&mut out, tag);
            }
            None => encode_u8(&mut out, 0),
        }
        match &self.confirmation_tag {
            Some(tag) => {
                encode_u8(&mut out, 1);
                out.extend_from_slice(tag);
            }
            None => encode_u8(&mut out, 0),
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        let group_id = String::from_utf8(decoder.read_bytes()?).ok()?;
        let epoch = decoder.read_u64()?;
        let sender_leaf = decoder.read_u32()?;
        let content_type = ContentType::from_u8(decoder.read_u8()?)?;
        let authenticated_data = decoder.read_bytes()?;
        let content = decoder.read_bytes()?;
        let membership_tag = match decoder.read_u8()? {
            0 => None,
            1 => {
                let tag = decoder.read_bytes()?;
                if tag.is_empty() {
                    return None;
                }
                Some(tag)
            }
            _ => return None,
        };
        let confirmation_tag = match decoder.read_u8()? {
            0 => None,
            1 => Some(decoder.read_fixed_32()?),
            _ => return None,
        };
        if decoder.remaining() != 0 {
            return None;
        }

        Some(Self {
            group_id,
            epoch,
            sender_leaf,
            content_type,
            authenticated_data,
            content,
            membership_tag,
            confirmation_tag,
        })
    }

    pub fn from_proposal_envelope(envelope: &ProposalEnvelope) -> Self {
        Self {
            group_id: envelope.group_id.clone(),
            epoch: envelope.epoch,
            sender_leaf: envelope.sender_leaf as u32,
            content_type: ContentType::Proposal,
            authenticated_data: Vec::new(),
            content: envelope.proposal.encode(),
            membership_tag: None,
            confirmation_tag: None,
        }
    }

    pub fn to_proposal_envelope(&self) -> Option<ProposalEnvelope> {
        if self.content_type != ContentType::Proposal {
            return None;
        }
        Some(ProposalEnvelope {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            sender_leaf: self.sender_leaf as usize,
            proposal: Proposal::decode(&self.content)?,
        })
    }

    pub fn from_commit_envelope(envelope: &CommitEnvelope) -> Self {
        Self {
            group_id: envelope.group_id.clone(),
            epoch: envelope.epoch,
            sender_leaf: envelope.sender_leaf as u32,
            content_type: ContentType::Commit,
            authenticated_data: Vec::new(),
            content: envelope.commit.encode(),
            membership_tag: None,
            confirmation_tag: None,
        }
    }

    pub fn to_commit_envelope(&self) -> Option<CommitEnvelope> {
        if self.content_type != ContentType::Commit {
            return None;
        }
        Some(CommitEnvelope {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            sender_leaf: self.sender_leaf as usize,
            commit: Commit::decode(&self.content)?,
        })
    }

    pub fn from_path_update_envelope(envelope: &PathUpdateEnvelope) -> Self {
        Self {
            group_id: envelope.group_id.clone(),
            epoch: envelope.epoch,
            sender_leaf: envelope.sender_leaf as u32,
            content_type: ContentType::PathUpdate,
            authenticated_data: Vec::new(),
            content: envelope.path_update.encode(),
            membership_tag: None,
            confirmation_tag: None,
        }
    }

    pub fn to_path_update_envelope(&self) -> Option<PathUpdateEnvelope> {
        if self.content_type != ContentType::PathUpdate {
            return None;
        }
        Some(PathUpdateEnvelope {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            sender_leaf: self.sender_leaf as usize,
            path_update: PathUpdate::decode(&self.content)?,
        })
    }
}

impl PrivateMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_bytes(&mut out, self.group_id.as_bytes());
        encode_u64(&mut out, self.epoch);
        encode_u8(&mut out, self.content_type as u8);
        encode_bytes(&mut out, &self.authenticated_data);
        encode_bytes(&mut out, &self.encrypted_sender_data);
        encode_bytes(&mut out, &self.ciphertext);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        let group_id = String::from_utf8(decoder.read_bytes()?).ok()?;
        let epoch = decoder.read_u64()?;
        let content_type = ContentType::from_u8(decoder.read_u8()?)?;
        let authenticated_data = decoder.read_bytes()?;
        let encrypted_sender_data = decoder.read_bytes()?;
        let ciphertext = decoder.read_bytes()?;
        if encrypted_sender_data.is_empty() || ciphertext.is_empty() {
            return None;
        }
        if decoder.remaining() != 0 {
            return None;
        }
        Some(Self {
            group_id,
            epoch,
            content_type,
            authenticated_data,
            encrypted_sender_data,
            ciphertext,
        })
    }
}

fn encode_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn encode_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
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

    fn read_u16(&mut self) -> Option<u16> {
        if self.remaining() < 2 {
            return None;
        }
        let mut out = [0u8; 2];
        out.copy_from_slice(&self.data[self.pos..self.pos + 2]);
        self.pos += 2;
        Some(u16::from_be_bytes(out))
    }

    fn read_u32(&mut self) -> Option<u32> {
        if self.remaining() < 4 {
            return None;
        }
        let mut out = [0u8; 4];
        out.copy_from_slice(&self.data[self.pos..self.pos + 4]);
        self.pos += 4;
        Some(u32::from_be_bytes(out))
    }

    fn read_u64(&mut self) -> Option<u64> {
        if self.remaining() < 8 {
            return None;
        }
        let mut out = [0u8; 8];
        out.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        Some(u64::from_be_bytes(out))
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

    fn read_fixed_32(&mut self) -> Option<[u8; 32]> {
        if self.remaining() < 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.data[self.pos..self.pos + 32]);
        self.pos += 32;
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::{Commit, PathUpdate, Proposal};

    #[test]
    fn public_message_proposal_roundtrip() {
        let proposal_envelope = ProposalEnvelope {
            group_id: "group-wire".to_string(),
            epoch: 7,
            sender_leaf: 1,
            proposal: Proposal::Remove { leaf_index: 2 },
        };
        let public = PublicMessage::from_proposal_envelope(&proposal_envelope);
        let encoded = public.encode();
        let decoded = PublicMessage::decode(&encoded).expect("decode public message");
        assert_eq!(decoded, public);

        let recovered = decoded
            .to_proposal_envelope()
            .expect("recover proposal envelope");
        assert_eq!(recovered.encode(), proposal_envelope.encode());
    }

    #[test]
    fn public_message_commit_and_path_extension_roundtrip() {
        let commit_envelope = CommitEnvelope {
            group_id: "group-wire".to_string(),
            epoch: 9,
            sender_leaf: 0,
            commit: Commit {
                sender: 0,
                proposals: vec![Proposal::Remove { leaf_index: 1 }],
                path: Vec::new(),
            },
        };
        let commit_public = PublicMessage::from_commit_envelope(&commit_envelope);
        let commit_recovered = PublicMessage::decode(&commit_public.encode())
            .expect("decode commit message")
            .to_commit_envelope()
            .expect("recover commit envelope");
        assert_eq!(commit_recovered.encode(), commit_envelope.encode());

        let path_envelope = PathUpdateEnvelope {
            group_id: "group-wire".to_string(),
            epoch: 9,
            sender_leaf: 0,
            path_update: PathUpdate {
                path_secrets: vec![[1u8; 32]],
                ciphertexts: Vec::new(),
            },
        };
        let path_public = PublicMessage::from_path_update_envelope(&path_envelope);
        let path_recovered = PublicMessage::decode(&path_public.encode())
            .expect("decode path_update message")
            .to_path_update_envelope()
            .expect("recover path_update envelope");
        assert_eq!(path_recovered.encode(), path_envelope.encode());
    }

    #[test]
    fn private_message_roundtrip_and_reject_empty_ciphertext() {
        let message = PrivateMessage {
            group_id: "group-private".to_string(),
            epoch: 4,
            content_type: ContentType::Application,
            authenticated_data: b"ad".to_vec(),
            encrypted_sender_data: vec![0xA1, 0xB2],
            ciphertext: vec![0x11, 0x22, 0x33],
        };
        let encoded = message.encode();
        let decoded = PrivateMessage::decode(&encoded).expect("decode private message");
        assert_eq!(decoded, message);

        let mut malformed = message.clone();
        malformed.ciphertext.clear();
        assert!(PrivateMessage::decode(&malformed.encode()).is_none());
    }

    #[test]
    fn mls_message_public_private_roundtrip() {
        let public = MlsMessage::from_public(PublicMessage {
            group_id: "g".to_string(),
            epoch: 1,
            sender_leaf: 0,
            content_type: ContentType::Proposal,
            authenticated_data: vec![1, 2],
            content: Proposal::Remove { leaf_index: 0 }.encode(),
            membership_tag: None,
            confirmation_tag: None,
        });
        let public_decoded =
            MlsMessage::decode(&public.encode()).expect("decode mls public message");
        assert_eq!(public_decoded, public);

        let private = MlsMessage::from_private(PrivateMessage {
            group_id: "g".to_string(),
            epoch: 1,
            content_type: ContentType::Application,
            authenticated_data: vec![7],
            encrypted_sender_data: vec![8, 9],
            ciphertext: vec![10, 11],
        });
        let private_decoded =
            MlsMessage::decode(&private.encode()).expect("decode mls private message");
        assert_eq!(private_decoded, private);
    }

    #[test]
    fn mls_message_rejects_bad_version_and_bad_wire_format() {
        let public = MlsMessage::from_public(PublicMessage {
            group_id: "g".to_string(),
            epoch: 1,
            sender_leaf: 0,
            content_type: ContentType::Proposal,
            authenticated_data: Vec::new(),
            content: Proposal::Remove { leaf_index: 0 }.encode(),
            membership_tag: None,
            confirmation_tag: None,
        });
        let mut bytes = public.encode();
        bytes[1] = 0x02;
        assert!(MlsMessage::decode(&bytes).is_none());

        let mut bytes = public.encode();
        bytes[2] = 0x7F;
        assert!(MlsMessage::decode(&bytes).is_none());
    }

    #[test]
    fn public_message_rejects_unknown_content_type_and_trailing_bytes() {
        let public = PublicMessage {
            group_id: "g".to_string(),
            epoch: 1,
            sender_leaf: 0,
            content_type: ContentType::Proposal,
            authenticated_data: Vec::new(),
            content: Proposal::Remove { leaf_index: 0 }.encode(),
            membership_tag: None,
            confirmation_tag: None,
        };
        let mut encoded = public.encode();
        // group_id length (4) + "g" (1) + epoch (8) + sender (4) = 17, next byte is content_type
        encoded[17] = 0xFE;
        assert!(PublicMessage::decode(&encoded).is_none());

        let mut trailing = public.encode();
        trailing.push(0xAA);
        assert!(PublicMessage::decode(&trailing).is_none());
    }
}
