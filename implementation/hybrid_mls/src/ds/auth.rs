use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::VerifyingKey as EdPublic;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65};

use crate::crypto::{HybridSignPubKey, HybridSignature};

pub fn decode_hybrid_sign_pub_key_bytes(classic: &[u8], pq: &[u8]) -> Option<HybridSignPubKey> {
    if classic.len() != 32 {
        return None;
    }
    let mut classic_bytes = [0u8; 32];
    classic_bytes.copy_from_slice(classic);
    let classic_pub = EdPublic::from_bytes(&classic_bytes).ok()?;

    let pq_enc: EncodedVerifyingKey<MlDsa65> = pq.try_into().ok()?;
    let pq_pub = ml_dsa::VerifyingKey::<MlDsa65>::decode(&pq_enc);

    Some(HybridSignPubKey {
        classic: classic_pub,
        pq: pq_pub,
    })
}

pub fn decode_hybrid_signature_b64(b64: &str) -> Option<HybridSignature> {
    let bytes = STANDARD.decode(b64).ok()?;
    decode_hybrid_signature(&bytes)
}

pub fn decode_hybrid_signature(bytes: &[u8]) -> Option<HybridSignature> {
    if bytes.len() < 64 {
        return None;
    }
    let mut classic = [0u8; 64];
    classic.copy_from_slice(&bytes[..64]);
    let classic_sig = ed25519_dalek::Signature::from_bytes(&classic);

    let pq_bytes = &bytes[64..];
    let pq_enc: EncodedSignature<MlDsa65> = pq_bytes.try_into().ok()?;
    let pq_sig = ml_dsa::Signature::<MlDsa65>::decode(&pq_enc)?;

    Some(HybridSignature {
        classic: classic_sig,
        pq: pq_sig,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{SecretKey, SigningKey as EdSigningKey};
    use ml_dsa::{KeyGen, MlDsa65};
    use rand::{rngs::OsRng, RngCore};

    use crate::crypto::{HybridSignPrivKey, HybridSignPubKey};

    #[test]
    fn decode_and_verify_hybrid_signature_roundtrip() {
        let mut rng = OsRng;
        let mut secret: SecretKey = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let classic_sk = EdSigningKey::from_bytes(&secret);
        let classic_pk = classic_sk.verifying_key();

        let kp = MlDsa65::key_gen(&mut rng);
        let pq_sk = kp.signing_key().clone();
        let pq_pk = kp.verifying_key().clone();

        let priv_key = HybridSignPrivKey {
            classic: classic_sk,
            pq: pq_sk,
        };
        let pub_key = HybridSignPubKey {
            classic: classic_pk,
            pq: pq_pk,
        };

        let message = b"hybrid-signature-test";
        let sig = priv_key.sign(message);
        let sig_b64 = STANDARD.encode(sig.to_bytes());

        let decoded_pub =
            decode_hybrid_sign_pub_key_bytes(pub_key.classic.as_bytes(), &pub_key.pq.encode())
                .expect("decode pub key");
        let decoded_sig = decode_hybrid_signature_b64(&sig_b64).expect("decode signature");

        assert!(decoded_sig.verify(&decoded_pub, message));
    }
}
