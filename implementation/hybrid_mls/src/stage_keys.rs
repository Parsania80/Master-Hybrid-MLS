use sha3::{Digest, Sha3_256};

const LABEL_CONFIRMATION_KEY: &[u8] = b"confirm";
const LABEL_MEMBERSHIP_KEY: &[u8] = b"membership";
const LABEL_SENDER_DATA_KEY: &[u8] = b"sender_data";
const STAGE_KEY_CONTEXT: &[u8] = b"stage_keys";
const LEGACY_STAGE_KEY_CONTEXT_HASH: [u8; 32] = [0u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochStageKeys {
    pub confirmation_key: [u8; 32],
    pub membership_key: [u8; 32],
    pub sender_data_key: [u8; 32],
}

pub fn derive_epoch_stage_keys(epoch_secret: &[u8; 32]) -> EpochStageKeys {
    derive_epoch_stage_keys_with_context(epoch_secret, &LEGACY_STAGE_KEY_CONTEXT_HASH)
}

pub fn derive_epoch_stage_keys_with_context(
    epoch_secret: &[u8; 32],
    context_hash: &[u8; 32],
) -> EpochStageKeys {
    EpochStageKeys {
        confirmation_key: derive_confirmation_key_with_context(epoch_secret, context_hash),
        membership_key: derive_membership_key_with_context(epoch_secret, context_hash),
        sender_data_key: derive_sender_data_key_with_context(epoch_secret, context_hash),
    }
}

pub fn derive_confirmation_key(epoch_secret: &[u8; 32]) -> [u8; 32] {
    derive_confirmation_key_with_context(epoch_secret, &LEGACY_STAGE_KEY_CONTEXT_HASH)
}

pub fn derive_membership_key(epoch_secret: &[u8; 32]) -> [u8; 32] {
    derive_membership_key_with_context(epoch_secret, &LEGACY_STAGE_KEY_CONTEXT_HASH)
}

pub fn derive_sender_data_key(epoch_secret: &[u8; 32]) -> [u8; 32] {
    derive_sender_data_key_with_context(epoch_secret, &LEGACY_STAGE_KEY_CONTEXT_HASH)
}

pub fn derive_confirmation_key_with_context(
    epoch_secret: &[u8; 32],
    context_hash: &[u8; 32],
) -> [u8; 32] {
    derive_stage_key(LABEL_CONFIRMATION_KEY, epoch_secret, context_hash)
}

pub fn derive_membership_key_with_context(
    epoch_secret: &[u8; 32],
    context_hash: &[u8; 32],
) -> [u8; 32] {
    derive_stage_key(LABEL_MEMBERSHIP_KEY, epoch_secret, context_hash)
}

pub fn derive_sender_data_key_with_context(
    epoch_secret: &[u8; 32],
    context_hash: &[u8; 32],
) -> [u8; 32] {
    derive_stage_key(LABEL_SENDER_DATA_KEY, epoch_secret, context_hash)
}

fn derive_stage_key(label: &[u8], epoch_secret: &[u8; 32], context_hash: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::new();
    encode_u32_prefixed(&mut input, b"MLS 1.0");
    encode_u32_prefixed(&mut input, label);
    encode_u32_prefixed(&mut input, STAGE_KEY_CONTEXT);
    encode_u32_prefixed(&mut input, context_hash);
    encode_u32_prefixed(&mut input, epoch_secret);

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
            "7e1fe2c22eb95dfd68ce5cc6a76e8cad28d77fdc7f33f56e72c9f7ccd8ee4a65"
        );
        assert_eq!(
            hex(&keys.membership_key),
            "32ba4b7d9acc6061d2aaba98dd706104ac19e220ef0bb68402637ec18afa2ab1"
        );
        assert_eq!(
            hex(&keys.sender_data_key),
            "6b602c459dcc3ce6c32606374cb05bfa8d8e0f56491a3e97aadaed90cfb4d76c"
        );
    }
}
