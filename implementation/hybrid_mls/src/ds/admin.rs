use ed25519_dalek::SigningKey as EdSigningKey;
use ml_dsa::{KeyGen, MlDsa65};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sha3::{Digest, Sha3_256};

pub const ADMIN_USERNAME: &str = "admin";
pub const ADMIN_PASSWORD: &str = "admin@123";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminKeyMaterial {
    pub classic_secret: [u8; 32],
    pub classic_public: Vec<u8>,
    pub pq_secret: Vec<u8>,
    pub pq_public: Vec<u8>,
}

pub fn derive_admin_key_material() -> AdminKeyMaterial {
    let mut rng = StdRng::from_seed(seed_from_label(b"HYBRID-MLS-ADMIN-IDENTITY-V1"));
    let mut classic_secret = [0u8; 32];
    rng.fill_bytes(&mut classic_secret);
    let classic_sign = EdSigningKey::from_bytes(&classic_secret);
    let classic_public = classic_sign.verifying_key().as_bytes().to_vec();

    let keypair = MlDsa65::key_gen(&mut rng);
    let pq_signing = keypair.signing_key().clone();
    let pq_verifying = keypair.verifying_key().clone();

    AdminKeyMaterial {
        classic_secret,
        classic_public,
        pq_secret: encoded_to_vec(pq_signing.encode()),
        pq_public: encoded_to_vec(pq_verifying.encode()),
    }
}

pub fn admin_password_salt() -> [u8; 16] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"HYBRID-MLS-ADMIN-SALT-V1");
    let digest = hasher.finalize();
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&digest[..16]);
    salt
}

fn seed_from_label(label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(label);
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest[..32]);
    seed
}

fn encoded_to_vec<T: AsRef<[u8]>>(value: T) -> Vec<u8> {
    value.as_ref().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_key_material_is_deterministic() {
        let one = derive_admin_key_material();
        let two = derive_admin_key_material();
        assert_eq!(one, two);
        assert_eq!(one.classic_public.len(), 32);
        assert!(!one.pq_public.is_empty());
        assert!(!one.pq_secret.is_empty());
    }

    #[test]
    fn admin_salt_is_deterministic() {
        assert_eq!(admin_password_salt(), admin_password_salt());
    }
}
