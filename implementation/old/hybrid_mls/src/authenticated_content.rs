use sha3::{Digest, Sha3_256};

use crate::crypto::{HybridSignPrivKey, HybridSignPubKey, HybridSignature};
use crate::envelope::{CommitEnvelope, PathUpdateEnvelope, ProposalEnvelope};
use crate::mls_wire::{MlsMessage, PublicMessage, WireFormat, MLS_PROTOCOL_VERSION};
pub use crate::stage_keys::derive_membership_key;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedContentTbs {
    pub wire_format: WireFormat,
    pub public_message: PublicMessage,
}

#[derive(Clone, Debug)]
pub struct AuthenticatedContent {
    pub tbs: AuthenticatedContentTbs,
    pub signature: HybridSignature,
}

impl AuthenticatedContentTbs {
    pub fn encode(&self) -> Vec<u8> {
        self.encode_with_membership_tag(self.public_message.membership_tag.as_deref())
    }

    pub fn encode_for_signature(&self) -> Vec<u8> {
        self.encode_with_membership_tag(None)
    }

    fn encode_with_membership_tag(&self, membership_tag: Option<&[u8]>) -> Vec<u8> {
        let mut public_message = self.public_message.clone();
        public_message.membership_tag = membership_tag.map(|tag| tag.to_vec());

        let mut out = Vec::new();
        encode_u16(&mut out, MLS_PROTOCOL_VERSION);
        encode_u8(&mut out, self.wire_format as u8);
        encode_bytes(&mut out, &public_message.encode());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.read_u16()?;
        if version != MLS_PROTOCOL_VERSION {
            return None;
        }
        let wire_format = WireFormat::from_u8(decoder.read_u8()?)?;
        if wire_format != WireFormat::PublicMessage {
            return None;
        }
        let public_message = PublicMessage::decode(&decoder.read_bytes()?)?;
        if decoder.remaining() != 0 {
            return None;
        }
        Some(Self {
            wire_format,
            public_message,
        })
    }

    pub fn to_proposal_envelope(&self) -> Option<ProposalEnvelope> {
        self.public_message.to_proposal_envelope()
    }

    pub fn to_commit_envelope(&self) -> Option<CommitEnvelope> {
        self.public_message.to_commit_envelope()
    }

    pub fn to_path_update_envelope(&self) -> Option<PathUpdateEnvelope> {
        self.public_message.to_path_update_envelope()
    }
}

impl AuthenticatedContent {
    pub fn sign(tbs: AuthenticatedContentTbs, signer: &HybridSignPrivKey) -> Self {
        let signature = signer.sign(&authenticated_content_signing_input(&tbs));
        Self { tbs, signature }
    }

    pub fn sign_with_membership_tag(
        mut tbs: AuthenticatedContentTbs,
        signer: &HybridSignPrivKey,
        membership_key: &[u8; 32],
    ) -> Self {
        tbs.public_message.membership_tag = None;
        let signature = signer.sign(&authenticated_content_signing_input(&tbs));
        let tag = derive_membership_tag(membership_key, &tbs, &signature);
        tbs.public_message.membership_tag = Some(tag.to_vec());
        Self { tbs, signature }
    }

    pub fn verify(&self, pub_key: &HybridSignPubKey) -> bool {
        self.signature
            .verify(pub_key, &authenticated_content_signing_input(&self.tbs))
    }

    pub fn verify_with_membership_tag(
        &self,
        pub_key: &HybridSignPubKey,
        membership_key: &[u8; 32],
    ) -> bool {
        if !self.verify(pub_key) {
            return false;
        }
        let Some(tag_bytes) = self.tbs.public_message.membership_tag.as_ref() else {
            return false;
        };
        if tag_bytes.len() != 32 {
            return false;
        }
        let mut received = [0u8; 32];
        received.copy_from_slice(tag_bytes);
        let expected = derive_membership_tag(membership_key, &self.tbs, &self.signature);
        expected == received
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_bytes(&mut out, &self.tbs.encode());
        encode_bytes(&mut out, &self.signature.to_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        let tbs = AuthenticatedContentTbs::decode(&decoder.read_bytes()?)?;
        let signature = HybridSignature::from_bytes(&decoder.read_bytes()?)?;
        if decoder.remaining() != 0 {
            return None;
        }
        Some(Self { tbs, signature })
    }

    pub fn to_mls_message(&self) -> MlsMessage {
        MlsMessage::from_public(self.tbs.public_message.clone())
    }
}

pub fn tbs_from_proposal_envelope(envelope: &ProposalEnvelope) -> AuthenticatedContentTbs {
    AuthenticatedContentTbs {
        wire_format: WireFormat::PublicMessage,
        public_message: PublicMessage::from_proposal_envelope(envelope),
    }
}

pub fn tbs_from_commit_envelope(envelope: &CommitEnvelope) -> AuthenticatedContentTbs {
    AuthenticatedContentTbs {
        wire_format: WireFormat::PublicMessage,
        public_message: PublicMessage::from_commit_envelope(envelope),
    }
}

pub fn tbs_from_path_update_envelope(envelope: &PathUpdateEnvelope) -> AuthenticatedContentTbs {
    AuthenticatedContentTbs {
        wire_format: WireFormat::PublicMessage,
        public_message: PublicMessage::from_path_update_envelope(envelope),
    }
}

pub fn proposal_authenticated_content_hash(group_id: &str, proposal_bytes: &[u8]) -> [u8; 32] {
    if let Some(envelope) = ProposalEnvelope::decode(proposal_bytes) {
        if envelope.group_id == group_id {
            return hash_authenticated_content_tbs(&tbs_from_proposal_envelope(&envelope));
        }
    }
    hash_payload_fallback(proposal_bytes)
}

pub fn commit_authenticated_content_hash(group_id: &str, commit_bytes: &[u8]) -> [u8; 32] {
    if let Some(envelope) = CommitEnvelope::decode(commit_bytes) {
        if envelope.group_id == group_id {
            return hash_authenticated_content_tbs(&tbs_from_commit_envelope(&envelope));
        }
    }
    hash_payload_fallback(commit_bytes)
}

pub fn path_update_authenticated_content_hash(group_id: &str, path_bytes: &[u8]) -> [u8; 32] {
    if let Some(envelope) = PathUpdateEnvelope::decode(path_bytes) {
        if envelope.group_id == group_id {
            return hash_authenticated_content_tbs(&tbs_from_path_update_envelope(&envelope));
        }
    }
    hash_payload_fallback(path_bytes)
}

pub fn hash_payload_fallback(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"DS-PAYLOAD");
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hash_authenticated_content_tbs(tbs: &AuthenticatedContentTbs) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"DS-AUTHENTICATED-CONTENT");
    hasher.update(tbs.encode_for_signature());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn authenticated_content_signing_input(tbs: &AuthenticatedContentTbs) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"MLS 1.0 AuthenticatedContent|");
    out.extend_from_slice(&tbs.encode_for_signature());
    out
}

pub fn derive_membership_tag(
    membership_key: &[u8; 32],
    tbs: &AuthenticatedContentTbs,
    signature: &HybridSignature,
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"MLS-MEMBERSHIP-TAG");
    hasher.update(membership_key);
    hasher.update(tbs.encode_for_signature());
    hasher.update(signature.to_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
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
    use ed25519_dalek::{SecretKey as EdSecretKey, SigningKey as EdSigningKey};
    use ml_dsa::{KeyGen, MlDsa65};
    use rand::rngs::{OsRng, StdRng};
    use rand::SeedableRng;
    use sha3::{Digest, Sha3_256};

    use crate::crypto::HybridSignPubKey;
    use crate::tree::Proposal;

    fn test_signing_keys() -> (HybridSignPrivKey, HybridSignPubKey) {
        let mut rng = OsRng;
        let secret: EdSecretKey = [7u8; 32];
        let classic_sign = EdSigningKey::from_bytes(&secret);
        let classic_pub = classic_sign.verifying_key();
        let kp = MlDsa65::key_gen(&mut rng);
        let pq_priv = kp.signing_key().clone();
        let pq_pub = kp.verifying_key().clone();

        (
            HybridSignPrivKey {
                classic: classic_sign,
                pq: pq_priv,
            },
            HybridSignPubKey {
                classic: classic_pub,
                pq: pq_pub,
            },
        )
    }

    fn deterministic_signing_keys() -> (HybridSignPrivKey, HybridSignPubKey) {
        let secret: EdSecretKey = [0x11u8; 32];
        let classic_sign = EdSigningKey::from_bytes(&secret);
        let classic_pub = classic_sign.verifying_key();
        let mut rng = StdRng::seed_from_u64(0xA11CE55);
        let kp = MlDsa65::key_gen(&mut rng);
        let pq_priv = kp.signing_key().clone();
        let pq_pub = kp.verifying_key().clone();

        (
            HybridSignPrivKey {
                classic: classic_sign,
                pq: pq_priv,
            },
            HybridSignPubKey {
                classic: classic_pub,
                pq: pq_pub,
            },
        )
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn from_hex(hex_str: &str) -> Vec<u8> {
        assert!(
            hex_str.len().is_multiple_of(2),
            "hex fixture must have even length"
        );
        let mut out = Vec::with_capacity(hex_str.len() / 2);
        let bytes = hex_str.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            let hi = (bytes[i] as char).to_digit(16).expect("hex hi");
            let lo = (bytes[i + 1] as char).to_digit(16).expect("hex lo");
            out.push(((hi << 4) | lo) as u8);
            i += 2;
        }
        out
    }

    fn sha3_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(bytes);
        hex(&hasher.finalize())
    }

    #[test]
    fn authenticated_content_sign_verify_roundtrip() {
        let proposal = ProposalEnvelope {
            group_id: "group-ac".to_string(),
            epoch: 4,
            sender_leaf: 1,
            proposal: Proposal::Remove { leaf_index: 2 },
        };
        let tbs = tbs_from_proposal_envelope(&proposal);
        let (signing, verify_key) = test_signing_keys();
        let content = AuthenticatedContent::sign(tbs.clone(), &signing);
        assert!(content.verify(&verify_key));

        let encoded = content.encode();
        let decoded = AuthenticatedContent::decode(&encoded).expect("decode authenticated content");
        assert!(decoded.verify(&verify_key));
        let recovered = decoded
            .tbs
            .to_proposal_envelope()
            .expect("recover proposal envelope");
        assert_eq!(recovered.encode(), proposal.encode());
        assert_eq!(
            decoded.to_mls_message().wire_format(),
            WireFormat::PublicMessage
        );
    }

    #[test]
    fn authenticated_content_membership_tag_roundtrip() {
        let commit = CommitEnvelope {
            group_id: "group-membership".to_string(),
            epoch: 2,
            sender_leaf: 0,
            commit: crate::tree::Commit {
                sender: 0,
                proposals: vec![Proposal::Remove { leaf_index: 1 }],
                path: Vec::new(),
            },
        };
        let tbs = tbs_from_commit_envelope(&commit);
        let (signing, verify_key) = test_signing_keys();
        let membership_key = derive_membership_key(&[0x44u8; 32]);
        let content =
            AuthenticatedContent::sign_with_membership_tag(tbs, &signing, &membership_key);

        assert!(content.verify(&verify_key));
        assert!(content.verify_with_membership_tag(&verify_key, &membership_key));
    }

    #[test]
    fn authenticated_content_membership_tag_rejects_tamper() {
        let proposal = ProposalEnvelope {
            group_id: "group-membership".to_string(),
            epoch: 3,
            sender_leaf: 1,
            proposal: Proposal::Remove { leaf_index: 2 },
        };
        let tbs = tbs_from_proposal_envelope(&proposal);
        let (signing, verify_key) = test_signing_keys();
        let membership_key = derive_membership_key(&[0x66u8; 32]);
        let mut content =
            AuthenticatedContent::sign_with_membership_tag(tbs, &signing, &membership_key);

        assert!(content.verify_with_membership_tag(&verify_key, &membership_key));
        content
            .tbs
            .public_message
            .membership_tag
            .as_mut()
            .expect("membership tag exists")[0] ^= 0x80;
        assert!(!content.verify_with_membership_tag(&verify_key, &membership_key));
    }

    #[test]
    fn authenticated_content_rejects_tamper_and_trailing() {
        let commit = CommitEnvelope {
            group_id: "group-ac".to_string(),
            epoch: 5,
            sender_leaf: 0,
            commit: crate::tree::Commit {
                sender: 0,
                proposals: vec![Proposal::Remove { leaf_index: 1 }],
                path: Vec::new(),
            },
        };
        let (signing, verify_key) = test_signing_keys();
        let mut encoded =
            AuthenticatedContent::sign(tbs_from_commit_envelope(&commit), &signing).encode();

        assert!(AuthenticatedContent::decode(&encoded)
            .expect("decode")
            .verify(&verify_key));

        let idx = encoded.len() - 1;
        encoded[idx] ^= 0x40;
        match AuthenticatedContent::decode(&encoded) {
            Some(tampered) => assert!(!tampered.verify(&verify_key)),
            None => {}
        }

        let mut trailing =
            AuthenticatedContent::sign(tbs_from_commit_envelope(&commit), &signing).encode();
        trailing.push(0xAA);
        assert!(AuthenticatedContent::decode(&trailing).is_none());
    }

    #[test]
    fn auth_content_hash_prefers_tbs_and_falls_back_for_malformed() {
        let proposal = ProposalEnvelope {
            group_id: "group-ac".to_string(),
            epoch: 1,
            sender_leaf: 0,
            proposal: Proposal::Remove { leaf_index: 1 },
        };
        let encoded = proposal.encode();
        let tbs_hash = proposal_authenticated_content_hash("group-ac", &encoded);
        let fallback_hash = hash_payload_fallback(&encoded);
        assert_ne!(tbs_hash, fallback_hash);

        let malformed = vec![0x00, 0x01, 0x02];
        let malformed_hash = proposal_authenticated_content_hash("group-ac", &malformed);
        assert_eq!(malformed_hash, hash_payload_fallback(&malformed));
    }

    #[test]
    fn authenticated_content_framing_vector_matches_expected() {
        let proposal = ProposalEnvelope {
            group_id: "vector-ac".to_string(),
            epoch: 9,
            sender_leaf: 2,
            proposal: Proposal::Remove { leaf_index: 3 },
        };
        let tbs = tbs_from_proposal_envelope(&proposal);
        let framing_hex = hex(&tbs.encode_for_signature());
        let signing_input_hash = sha3_hex(&authenticated_content_signing_input(&tbs));
        assert_eq!(
            framing_hex,
            "0001010000002900000009766563746f722d616300000000000000090000000201000000000000000503000000030000"
        );
        assert_eq!(
            signing_input_hash,
            "9721b5538bd587d9c3935a0e68a454f1ccf5b8cc3e66c195a2bb843eca33d887"
        );
    }

    #[test]
    fn authenticated_content_signature_bytes_vector_matches_expected() {
        let proposal = ProposalEnvelope {
            group_id: "vector-ac".to_string(),
            epoch: 9,
            sender_leaf: 2,
            proposal: Proposal::Remove { leaf_index: 3 },
        };
        let tbs = tbs_from_proposal_envelope(&proposal);
        let (signing, verify_key) = deterministic_signing_keys();
        let content = AuthenticatedContent::sign(tbs.clone(), &signing);
        assert!(content.verify(&verify_key));

        let signature_bytes = content.signature.to_bytes();
        let encoded = content.encode();
        assert_eq!(signature_bytes.len(), 3373);
        assert_eq!(
            sha3_hex(&signature_bytes),
            "cbee9c412d55b28dc00acb86b92e5fc1ac3ec77a4001b1d07b2164c25c48a899"
        );
        assert_eq!(
            sha3_hex(&encoded),
            "e629784ae5455d8dd42eb723735b993be5dbfcd66983ee487aff36ba2c84a776"
        );

        let membership_key = derive_membership_key(&[0x55u8; 32]);
        let tagged = AuthenticatedContent::sign_with_membership_tag(tbs, &signing, &membership_key);
        assert!(tagged.verify_with_membership_tag(&verify_key, &membership_key));
        let membership_tag = tagged
            .tbs
            .public_message
            .membership_tag
            .as_ref()
            .expect("membership tag");
        assert_eq!(membership_tag.len(), 32);
        assert_eq!(
            hex(membership_tag),
            "55f35274c6aea4f27a291f7d3550b035b091e6bdc3ba46015ddd136737e1a1e1"
        );
    }

    #[test]
    fn authenticated_content_decode_fixture_untagged_full_bytes() {
        let fixture = include_bytes!("../tests/vectors/authenticated_content_untagged.bin");
        let decoded = AuthenticatedContent::decode(fixture).expect("decode fixture");
        let (_, verify_key) = deterministic_signing_keys();
        assert!(decoded.verify(&verify_key));
        assert_eq!(
            sha3_hex(fixture),
            "e629784ae5455d8dd42eb723735b993be5dbfcd66983ee487aff36ba2c84a776"
        );

        let proposal = decoded
            .tbs
            .to_proposal_envelope()
            .expect("fixture proposal envelope");
        assert_eq!(proposal.group_id, "vector-ac");
        assert_eq!(proposal.epoch, 9);
        assert_eq!(proposal.sender_leaf, 2);
        assert_eq!(
            proposal.proposal.encode(),
            Proposal::Remove { leaf_index: 3 }.encode()
        );
        assert!(decoded.tbs.public_message.membership_tag.is_none());
        assert!(decoded.tbs.public_message.confirmation_tag.is_none());
        assert_eq!(decoded.encode(), fixture.to_vec());
    }

    #[test]
    fn authenticated_content_decode_fixture_tagged_full_bytes() {
        let fixture = include_bytes!("../tests/vectors/authenticated_content_tagged.bin");
        let decoded = AuthenticatedContent::decode(fixture).expect("decode fixture");
        let (_, verify_key) = deterministic_signing_keys();
        let membership_key = derive_membership_key(&[0x55u8; 32]);
        assert!(decoded.verify_with_membership_tag(&verify_key, &membership_key));
        assert_eq!(
            sha3_hex(fixture),
            "6ba5e461c44a670ef4827e45a4aed29f2dc66c911ab99735c6e11174d800422d"
        );

        let proposal = decoded
            .tbs
            .to_proposal_envelope()
            .expect("fixture proposal envelope");
        assert_eq!(proposal.group_id, "vector-ac");
        assert_eq!(proposal.epoch, 9);
        assert_eq!(proposal.sender_leaf, 2);
        assert_eq!(
            proposal.proposal.encode(),
            Proposal::Remove { leaf_index: 3 }.encode()
        );
        assert_eq!(
            decoded
                .tbs
                .public_message
                .membership_tag
                .as_deref()
                .expect("membership tag present"),
            &from_hex("55f35274c6aea4f27a291f7d3550b035b091e6bdc3ba46015ddd136737e1a1e1")
        );
        assert!(decoded.tbs.public_message.confirmation_tag.is_none());
        assert_eq!(decoded.encode(), fixture.to_vec());
    }
}
