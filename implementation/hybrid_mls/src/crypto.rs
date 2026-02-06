use x25519_dalek::{PublicKey as X25519Pub, StaticSecret as X25519Priv};
use ml_kem::{MlKem768, EncapsulationKey, DecapsulationKey, Ciphertext};
use ed25519_dalek::{SigningKey as EdSecret, VerifyingKey as EdPublic, Signature as EdSig, Signer, Verifier};
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

// --- HYBRID SIGNATURES (Authentication) ---
// We use MlDsa65 (Dilithium3) to match security level of MlKem768 (Kyber768)

pub type DilithiumPublic = ml_dsa::VerifyingKey<MlDsa65>;
pub type DilithiumSecret = ml_dsa::SigningKey<MlDsa65>;
pub type DilithiumSig = ml_dsa::Signature<MlDsa65>;

#[derive(Clone, Debug, PartialEq)]
pub struct HybridSignPubKey {
    pub classic: EdPublic,
    pub pq: DilithiumPublic,
}

impl HybridSignPubKey {
    /// Serializes the hybrid identity for network transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.classic.as_bytes());
        // FIX: Use as_ref() because ml_dsa keys don't have as_bytes()
        out.extend_from_slice(self.pq.as_ref()); 
        out
    }
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
        // We use the Verifier trait imported from ed25519_dalek which is compatible
        let classic_ok = pub_key.classic.verify(message, &self.classic).is_ok();
        let pq_ok = pub_key.pq.verify(message, &self.pq).is_ok();
        
        classic_ok && pq_ok
    }
}
