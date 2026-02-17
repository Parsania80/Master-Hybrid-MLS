use crate::client_state::ClientGroupState;
use crate::crypto::{decrypt_hpke_payload, encrypt_hpke_payload};
use crate::mls_wire::{ContentType, MlsMessage, MlsMessageBody, PrivateMessage};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptedApplicationMessage {
    pub sender_leaf: u32,
    pub generation: u32,
    pub authenticated_data: Vec<u8>,
    pub plaintext: Vec<u8>,
}

pub fn protect_application_message(
    state: &ClientGroupState,
    sender_leaf: u32,
    plaintext: &[u8],
    authenticated_data: &[u8],
) -> Option<PrivateMessage> {
    if sender_leaf as usize >= state.ratchet_tree.leaf_count() {
        return None;
    }
    let derived = state
        .key_schedule
        .derive_secrets_for_epoch(&state.group_id, state.epoch)?;

    let sender_data = encode_sender_data(sender_leaf, 0);
    let sender_data_aad = sender_data_aad(
        &state.group_id,
        state.epoch,
        ContentType::Application,
        authenticated_data,
    );
    let encrypted_sender_data =
        encrypt_hpke_payload(&derived.sender_data_key, &sender_data_aad, &sender_data);

    let ciphertext_aad = ciphertext_aad(
        &state.group_id,
        state.epoch,
        ContentType::Application,
        authenticated_data,
        &encrypted_sender_data,
    );
    let ciphertext = encrypt_hpke_payload(&derived.application_secret, &ciphertext_aad, plaintext);

    Some(PrivateMessage {
        group_id: state.group_id.clone(),
        epoch: state.epoch,
        content_type: ContentType::Application,
        authenticated_data: authenticated_data.to_vec(),
        encrypted_sender_data,
        ciphertext,
    })
}

pub fn protect_application_message_bytes(
    state: &ClientGroupState,
    sender_leaf: u32,
    plaintext: &[u8],
    authenticated_data: &[u8],
) -> Option<Vec<u8>> {
    let private = protect_application_message(state, sender_leaf, plaintext, authenticated_data)?;
    Some(MlsMessage::from_private(private).encode())
}

pub fn unprotect_application_message(
    state: &ClientGroupState,
    private: &PrivateMessage,
) -> Option<DecryptedApplicationMessage> {
    if private.group_id != state.group_id
        || private.epoch != state.epoch
        || private.content_type != ContentType::Application
    {
        return None;
    }
    let derived = state
        .key_schedule
        .derive_secrets_for_epoch(&state.group_id, state.epoch)?;

    let sender_data_aad = sender_data_aad(
        &private.group_id,
        private.epoch,
        private.content_type,
        &private.authenticated_data,
    );
    let sender_data_bytes = decrypt_hpke_payload(
        &derived.sender_data_key,
        &sender_data_aad,
        &private.encrypted_sender_data,
    )?;
    let (sender_leaf, generation) = decode_sender_data(&sender_data_bytes)?;

    let ciphertext_aad = ciphertext_aad(
        &private.group_id,
        private.epoch,
        private.content_type,
        &private.authenticated_data,
        &private.encrypted_sender_data,
    );
    let plaintext = decrypt_hpke_payload(
        &derived.application_secret,
        &ciphertext_aad,
        &private.ciphertext,
    )?;

    Some(DecryptedApplicationMessage {
        sender_leaf,
        generation,
        authenticated_data: private.authenticated_data.clone(),
        plaintext,
    })
}

pub fn unprotect_application_message_bytes(
    state: &ClientGroupState,
    bytes: &[u8],
) -> Option<DecryptedApplicationMessage> {
    let message = MlsMessage::decode(bytes)?;
    let private = match message.body {
        MlsMessageBody::Private(private) => private,
        MlsMessageBody::Public(_) => return None,
    };
    unprotect_application_message(state, &private)
}

fn encode_sender_data(sender_leaf: u32, generation: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.extend_from_slice(&sender_leaf.to_be_bytes());
    out.extend_from_slice(&generation.to_be_bytes());
    out
}

fn decode_sender_data(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.len() != 8 {
        return None;
    }
    let mut sender_leaf = [0u8; 4];
    sender_leaf.copy_from_slice(&bytes[..4]);
    let mut generation = [0u8; 4];
    generation.copy_from_slice(&bytes[4..]);
    Some((
        u32::from_be_bytes(sender_leaf),
        u32::from_be_bytes(generation),
    ))
}

fn sender_data_aad(
    group_id: &str,
    epoch: u64,
    content_type: ContentType,
    authenticated_data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"MLS-PRIVATE-SENDER-DATA-AAD|");
    out.extend_from_slice(group_id.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(&epoch.to_be_bytes());
    out.push(content_type as u8);
    out.extend_from_slice(authenticated_data);
    out
}

fn ciphertext_aad(
    group_id: &str,
    epoch: u64,
    content_type: ContentType,
    authenticated_data: &[u8],
    encrypted_sender_data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"MLS-PRIVATE-CIPHERTEXT-AAD|");
    out.extend_from_slice(group_id.as_bytes());
    out.extend_from_slice(b"|");
    out.extend_from_slice(&epoch.to_be_bytes());
    out.push(content_type as u8);
    out.extend_from_slice(authenticated_data);
    out.extend_from_slice(encrypted_sender_data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{HybridPublicKey, HybridSignPrivKey, HybridSignPubKey, KyberPriv};
    use crate::tree::{LeafNode, RatchetTree};
    use ed25519_dalek::{SigningKey as EdSecret, VerifyingKey as EdPublic};
    use ml_dsa::{KeyGen, MlDsa65};
    use ml_kem::Seed;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use x25519_dalek::{PublicKey as X25519Pub, StaticSecret as X25519Priv};

    fn hybrid_public_key(seed: u8) -> HybridPublicKey {
        let classic_priv = X25519Priv::from([seed; 32]);
        let classic_pub = X25519Pub::from(&classic_priv);

        let kem_seed = Seed::from([seed; 64]);
        let kyber_priv = KyberPriv::from_seed(kem_seed);
        let kyber_pub = kyber_priv.encapsulation_key().clone();

        HybridPublicKey {
            classic: classic_pub,
            pq: kyber_pub,
        }
    }

    fn hybrid_signing_keys(seed: u8) -> (HybridSignPubKey, HybridSignPrivKey) {
        let classic_priv = EdSecret::from_bytes(&[seed; 32]);
        let classic_pub = EdPublic::from(&classic_priv);

        let mut rng = StdRng::seed_from_u64(seed as u64);
        let kp = MlDsa65::key_gen(&mut rng);

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

    fn make_leaf(seed: u8) -> LeafNode {
        let (identity, _) = hybrid_signing_keys(seed);
        LeafNode {
            public_key: hybrid_public_key(seed),
            credential: identity,
        }
    }

    #[test]
    fn app_private_message_roundtrip() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(11)]);
        let state = ClientGroupState::new("group-app", tree, 0);
        let plaintext = b"hello application";
        let aad = b"meta-aad";

        let encoded = protect_application_message_bytes(&state, 0, plaintext, aad)
            .expect("protect app message");
        let opened =
            unprotect_application_message_bytes(&state, &encoded).expect("unprotect app message");
        assert_eq!(opened.sender_leaf, 0);
        assert_eq!(opened.generation, 0);
        assert_eq!(opened.authenticated_data, aad);
        assert_eq!(opened.plaintext, plaintext);
    }

    #[test]
    fn app_private_message_rejects_wrong_epoch() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(12)]);
        let state = ClientGroupState::new("group-app", tree.clone(), 0);
        let mut advanced = ClientGroupState::new("group-app", tree, 0);
        advanced.advance_epoch_with_context(Some(b"commit-app-1"));

        let encoded = protect_application_message_bytes(&state, 0, b"hello", b"aad")
            .expect("protect app message");
        assert!(unprotect_application_message_bytes(&advanced, &encoded).is_none());
    }

    #[test]
    fn app_private_message_rejects_tamper() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(13)]);
        let state = ClientGroupState::new("group-app", tree, 0);
        let mut encoded = protect_application_message_bytes(&state, 0, b"hello", b"aad")
            .expect("protect app message");

        let mls = MlsMessage::decode(&encoded).expect("decode mls message");
        let mut private = match mls.body {
            MlsMessageBody::Private(pm) => pm,
            MlsMessageBody::Public(_) => panic!("expected private message"),
        };
        private.ciphertext[0] ^= 0x80;
        encoded = MlsMessage::from_private(private).encode();

        assert!(unprotect_application_message_bytes(&state, &encoded).is_none());
    }

    #[test]
    fn protect_rejects_sender_out_of_bounds() {
        let tree = RatchetTree::from_leaves(vec![make_leaf(14)]);
        let state = ClientGroupState::new("group-app", tree, 0);
        assert!(protect_application_message_bytes(&state, 1, b"hello", b"aad").is_none());
    }
}
