use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{
    Signature as EdSig, Signer, SigningKey as EdSecret, Verifier, VerifyingKey as EdPublic,
};
use ml_dsa::{EncodedSignature, MlDsa65}; // Dilithium3 (NIST Level 3)
use ml_kem::{
    Ciphertext, Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, KeyExport, MlKem768,
};
use rand_core::{CryptoRng, Rng};
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey as X25519Pub, StaticSecret as X25519Priv};
use zeroize::{Zeroize, ZeroizeOnDrop};

// --- HYBRID KEM (Encryption) ---
pub type KyberPub = EncapsulationKey<MlKem768>;
pub type KyberPriv = DecapsulationKey<MlKem768>;
pub type KyberCiphertext = Ciphertext<MlKem768>;

#[derive(Clone, Debug, PartialEq)]
pub struct HybridPublicKey {
    pub classic: X25519Pub,
    pub pq: KyberPub,
}

impl HybridPublicKey {
    /// Serialize the hybrid public key (X25519 || ML-KEM-768).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.classic.as_bytes());
        out.extend_from_slice(self.pq.to_bytes().as_ref());
        out
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridPrivateKey {
    pub classic: X25519Priv,
    #[zeroize(skip)]
    pub pq: KyberPriv,
}

#[derive(Clone, Debug)]
pub struct HybridCiphertext {
    pub classic: [u8; 32],
    pub pq: KyberCiphertext,
}

/// Hybrid KEM encapsulation (X25519 + ML-KEM-768).
pub fn hybrid_kem_encapsulate<R: Rng + CryptoRng>(
    rng: &mut R,
    public_key: &HybridPublicKey,
    context: &[u8],
) -> (HybridCiphertext, [u8; 32]) {
    let mut eph_bytes = [0u8; 32];
    rng.fill_bytes(&mut eph_bytes);
    let eph_secret = X25519Priv::from(eph_bytes);
    let eph_public = X25519Pub::from(&eph_secret);
    let classic_shared = eph_secret.diffie_hellman(&public_key.classic);

    let (pq_ct, pq_shared) = public_key.pq.encapsulate_with_rng(rng);

    let shared = hybrid_kdf(classic_shared.as_bytes(), pq_shared.as_ref(), context);
    let ct = HybridCiphertext {
        classic: eph_public.to_bytes(),
        pq: pq_ct,
    };

    (ct, shared)
}

/// Hybrid KEM decapsulation (X25519 + ML-KEM-768).
pub fn hybrid_kem_decapsulate(
    private_key: &HybridPrivateKey,
    ciphertext: &HybridCiphertext,
    context: &[u8],
) -> [u8; 32] {
    let their_public = X25519Pub::from(ciphertext.classic);
    let classic_shared = private_key.classic.diffie_hellman(&their_public);
    let pq_shared = private_key.pq.decapsulate(&ciphertext.pq);

    hybrid_kdf(classic_shared.as_bytes(), pq_shared.as_ref(), context)
}

/// Encrypt a 32-byte path secret with HPKE-style context binding.
pub fn encrypt_path_secret(shared_secret: &[u8], aad: &[u8], path_secret: &[u8; 32]) -> Vec<u8> {
    encrypt_hpke_payload(shared_secret, aad, path_secret)
}

/// Decrypt a 32-byte path secret with HPKE-style context binding.
pub fn decrypt_path_secret(
    shared_secret: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<[u8; 32]> {
    let plaintext = decrypt_hpke_payload(shared_secret, aad, ciphertext)?;
    if plaintext.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&plaintext);
    Some(out)
}

/// Encrypt an arbitrary payload with the same HPKE-style key/nonce derivation.
pub fn encrypt_hpke_payload(shared_secret: &[u8], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let (key_bytes, nonce_bytes) = derive_aead_key_nonce(shared_secret, aad);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("hpke payload encryption failed")
}

/// Decrypt an arbitrary payload with the same HPKE-style key/nonce derivation.
pub fn decrypt_hpke_payload(
    shared_secret: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    let (key_bytes, nonce_bytes) = derive_aead_key_nonce(shared_secret, aad);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
}

fn hybrid_kdf(classic: &[u8], pq: &[u8], context: &[u8]) -> [u8; 32] {
    mls_labeled_hash(b"hybrid kem shared secret", context, &[classic, pq])
}

fn derive_aead_key_nonce(shared_secret: &[u8], context: &[u8]) -> ([u8; 32], [u8; 12]) {
    let key = mls_labeled_hash(b"hpke key", context, &[shared_secret]);
    let nonce_digest = mls_labeled_hash(b"hpke nonce", context, &[shared_secret]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_digest[..12]);

    (key, nonce)
}

fn mls_labeled_hash(label: &[u8], context: &[u8], ikm_parts: &[&[u8]]) -> [u8; 32] {
    let mut input = Vec::new();
    encode_u32_prefixed(&mut input, b"MLS 1.0");
    encode_u32_prefixed(&mut input, label);
    encode_u32_prefixed(&mut input, context);
    for part in ikm_parts {
        encode_u32_prefixed(&mut input, part);
    }

    let mut hasher = Sha3_256::new();
    hasher.update(&input);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn encode_u32_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

// --- HYBRID SIGNATURES (Authentication) ---

pub type DilithiumPublic = ml_dsa::VerifyingKey<MlDsa65>;
pub type DilithiumSecret = ml_dsa::SigningKey<MlDsa65>;
pub type DilithiumSig = ml_dsa::Signature<MlDsa65>;

#[derive(Clone, Debug, PartialEq)]
pub struct HybridSignPubKey {
    pub classic: EdPublic,
    pub pq: DilithiumPublic,
}

#[derive(Clone)]
pub struct HybridSignPrivKey {
    pub classic: EdSecret,
    pub pq: DilithiumSecret,
}

impl HybridSignPrivKey {
    /// Sign a message with both algorithms (Ed25519 + Dilithium)
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        let classic_sig = self.classic.sign(message);
        // try_sign ensures we handle potential RNG failures
        let pq_sig = self.pq.try_sign(message).expect("Dilithium signing failed");

        HybridSignature {
            classic: classic_sig,
            pq: pq_sig,
        }
    }
}

#[derive(Clone, Debug)]
pub struct HybridSignature {
    pub classic: EdSig,
    pub pq: DilithiumSig,
}

impl HybridSignature {
    /// Verify both signatures. Returns true ONLY if both are valid.
    pub fn verify(&self, pub_key: &HybridSignPubKey, message: &[u8]) -> bool {
        let classic_ok = pub_key.classic.verify(message, &self.classic).is_ok();
        let pq_ok = pub_key.pq.verify(message, &self.pq).is_ok();

        classic_ok && pq_ok
    }

    /// Serialize the hybrid signature (Ed25519 || ML-DSA).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.classic.to_bytes());
        out.extend_from_slice(&self.pq.encode());
        out
    }

    /// Decode the hybrid signature (Ed25519 || ML-DSA).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 64 {
            return None;
        }
        let mut classic = [0u8; 64];
        classic.copy_from_slice(&bytes[..64]);
        let classic_sig = EdSig::from_bytes(&classic);

        let pq_bytes = &bytes[64..];
        let pq_enc: EncodedSignature<MlDsa65> = pq_bytes.try_into().ok()?;
        let pq_sig = ml_dsa::Signature::<MlDsa65>::decode(&pq_enc)?;

        Some(Self {
            classic: classic_sig,
            pq: pq_sig,
        })
    }
}

impl HybridSignPubKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // Ed25519 (classic)
        out.extend_from_slice(self.classic.as_bytes());

        // Dilithium / ML-DSA (pq)
        out.extend_from_slice(&self.pq.encode());

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::Seed;
    use rand_core::{Infallible, TryCryptoRng, TryRng};

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

    impl TryCryptoRng for TestRng {}

    #[test]
    fn path_secret_encryption_roundtrip() {
        let mut rng = TestRng(0x5a5a5a5a5a5a5a5a);

        let classic_priv = X25519Priv::from([7u8; 32]);
        let classic_pub = X25519Pub::from(&classic_priv);

        let kem_seed = Seed::from([9u8; 64]);
        let kyber_priv = KyberPriv::from_seed(kem_seed);
        let kyber_pub = kyber_priv.encapsulation_key().clone();

        let public_key = HybridPublicKey {
            classic: classic_pub,
            pq: kyber_pub,
        };
        let private_key = HybridPrivateKey {
            classic: classic_priv,
            pq: kyber_priv,
        };

        let context = b"path-update";
        let path_secret = [0xABu8; 32];

        let (ct, shared_enc) = hybrid_kem_encapsulate(&mut rng, &public_key, context);
        let payload = encrypt_path_secret(&shared_enc, context, &path_secret);

        let shared_dec = hybrid_kem_decapsulate(&private_key, &ct, context);
        let decrypted =
            decrypt_path_secret(&shared_dec, context, &payload).expect("decrypt failed");

        assert_eq!(shared_enc, shared_dec);
        assert_eq!(decrypted, path_secret);
    }

    #[test]
    fn path_secret_context_mismatch_is_rejected() {
        let mut rng = TestRng(0xabababababababab);

        let classic_priv = X25519Priv::from([3u8; 32]);
        let classic_pub = X25519Pub::from(&classic_priv);
        let kyber_priv = KyberPriv::from_seed(Seed::from([4u8; 64]));
        let kyber_pub = kyber_priv.encapsulation_key().clone();

        let public_key = HybridPublicKey {
            classic: classic_pub,
            pq: kyber_pub,
        };
        let private_key = HybridPrivateKey {
            classic: classic_priv,
            pq: kyber_priv,
        };

        let path_secret = [0x33u8; 32];
        let ctx_ok = b"path-update-ok";
        let ctx_bad = b"path-update-bad";

        let (ct, shared_enc) = hybrid_kem_encapsulate(&mut rng, &public_key, ctx_ok);
        let payload = encrypt_path_secret(&shared_enc, ctx_ok, &path_secret);

        let shared_bad = hybrid_kem_decapsulate(&private_key, &ct, ctx_bad);
        assert_ne!(shared_enc, shared_bad);
        assert!(decrypt_path_secret(&shared_bad, ctx_bad, &payload).is_none());
    }

    #[test]
    fn hpke_payload_roundtrip_and_tamper_rejection() {
        let mut rng = TestRng(0x1234567812345678);

        let classic_priv = X25519Priv::from([5u8; 32]);
        let classic_pub = X25519Pub::from(&classic_priv);
        let kyber_priv = KyberPriv::from_seed(Seed::from([6u8; 64]));
        let kyber_pub = kyber_priv.encapsulation_key().clone();

        let public_key = HybridPublicKey {
            classic: classic_pub,
            pq: kyber_pub,
        };
        let private_key = HybridPrivateKey {
            classic: classic_priv,
            pq: kyber_priv,
        };

        let context = b"welcome-group-secrets";
        let plaintext = b"group-secrets-payload".to_vec();

        let (ct, shared_enc) = hybrid_kem_encapsulate(&mut rng, &public_key, context);
        let ciphertext = encrypt_hpke_payload(&shared_enc, context, &plaintext);
        let shared_dec = hybrid_kem_decapsulate(&private_key, &ct, context);
        let decrypted =
            decrypt_hpke_payload(&shared_dec, context, &ciphertext).expect("decrypt payload");
        assert_eq!(decrypted, plaintext);

        let mut tampered = ciphertext;
        tampered[0] ^= 0x01;
        assert!(decrypt_hpke_payload(&shared_dec, context, &tampered).is_none());
    }
}
