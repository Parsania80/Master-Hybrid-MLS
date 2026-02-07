use x25519_dalek::{PublicKey as X25519Pub, StaticSecret as X25519Priv};
use ml_kem::{
    MlKem768,
    EncapsulationKey,
    DecapsulationKey,
    Ciphertext,
    Decapsulate,
    Encapsulate,
    KeyExport,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand_core::{CryptoRng, Rng};
use sha3::{Digest, Sha3_256};
use ed25519_dalek::{
    SigningKey as EdSecret,
    VerifyingKey as EdPublic,
    Signature as EdSig,
    Signer,
    Verifier,
};
use ml_dsa::{MlDsa65}; // Dilithium3 (NIST Level 3)
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
pub fn encrypt_path_secret(
    shared_secret: &[u8],
    aad: &[u8],
    path_secret: &[u8; 32],
) -> Vec<u8> {
    let (key_bytes, nonce_bytes) = derive_aead_key_nonce(shared_secret, aad);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: path_secret,
                aad,
            },
        )
        .expect("path secret encryption failed")
}

/// Decrypt a 32-byte path secret with HPKE-style context binding.
pub fn decrypt_path_secret(
    shared_secret: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<[u8; 32]> {
    let (key_bytes, nonce_bytes) = derive_aead_key_nonce(shared_secret, aad);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()?;
    if plaintext.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&plaintext);
    Some(out)
}

fn hybrid_kdf(classic: &[u8], pq: &[u8], context: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"MLS-HYBRID-KEM");
    hasher.update(classic);
    hasher.update(pq);
    hasher.update(context);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn derive_aead_key_nonce(shared_secret: &[u8], context: &[u8]) -> ([u8; 32], [u8; 12]) {
    let mut key_hasher = Sha3_256::new();
    key_hasher.update(b"MLS-HPKE-KEY");
    key_hasher.update(shared_secret);
    key_hasher.update(context);
    let key_digest = key_hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_digest);

    let mut nonce_hasher = Sha3_256::new();
    nonce_hasher.update(b"MLS-HPKE-NONCE");
    nonce_hasher.update(shared_secret);
    nonce_hasher.update(context);
    let nonce_digest = nonce_hasher.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_digest[..12]);

    (key, nonce)
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
        let decrypted = decrypt_path_secret(&shared_dec, context, &payload)
            .expect("decrypt failed");

        assert_eq!(shared_enc, shared_dec);
        assert_eq!(decrypted, path_secret);
    }
}
