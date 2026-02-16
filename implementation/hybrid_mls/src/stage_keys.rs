use sha3::{Digest, Sha3_256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochStageKeys {
    pub confirmation_key: [u8; 32],
    pub membership_key: [u8; 32],
    pub sender_data_key: [u8; 32],
}

pub fn derive_epoch_stage_keys(epoch_secret: &[u8; 32]) -> EpochStageKeys {
    EpochStageKeys {
        confirmation_key: derive_confirmation_key(epoch_secret),
        membership_key: derive_membership_key(epoch_secret),
        sender_data_key: derive_sender_data_key(epoch_secret),
    }
}

pub fn derive_confirmation_key(epoch_secret: &[u8; 32]) -> [u8; 32] {
    derive_stage_key(b"MLS-CONFIRMATION-KEY", epoch_secret)
}

pub fn derive_membership_key(epoch_secret: &[u8; 32]) -> [u8; 32] {
    derive_stage_key(b"MLS-MEMBERSHIP-KEY", epoch_secret)
}

pub fn derive_sender_data_key(epoch_secret: &[u8; 32]) -> [u8; 32] {
    derive_stage_key(b"MLS-SENDER-DATA-KEY", epoch_secret)
}

fn derive_stage_key(label: &[u8], epoch_secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(label);
    hasher.update((epoch_secret.len() as u64).to_be_bytes());
    hasher.update(epoch_secret);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8; 32]) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }

    #[test]
    fn stage_keys_are_domain_separated() {
        let epoch_secret = [0x44u8; 32];
        let keys = derive_epoch_stage_keys(&epoch_secret);
        assert_ne!(keys.confirmation_key, keys.membership_key);
        assert_ne!(keys.confirmation_key, keys.sender_data_key);
        assert_ne!(keys.membership_key, keys.sender_data_key);
    }

    #[test]
    fn deterministic_stage_key_vector_matches_expected() {
        let epoch_secret = [0x5au8; 32];
        let keys = derive_epoch_stage_keys(&epoch_secret);
        assert_eq!(
            hex(&keys.confirmation_key),
            "c2c2453740392d8d5e3d7b4c381deb09525243d9cef93929ef9d6755eb8a46c9"
        );
        assert_eq!(
            hex(&keys.membership_key),
            "240401c01dd3556121d9a886c81a8fe5a9453fa981096cd09c07ecb00501be66"
        );
        assert_eq!(
            hex(&keys.sender_data_key),
            "f5efdb29736bc74d78cc1a0a1265356c61dcd8d9f56038eb3f1aa4e2d1f65750"
        );
    }
}
