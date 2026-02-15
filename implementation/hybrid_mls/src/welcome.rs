/// RFC 9420-style Welcome message model (hybrid-oriented wire skeleton).
///
/// This module defines strict encode/decode helpers for:
/// - `Welcome`
/// - `EncryptedGroupSecrets`
/// - `GroupSecrets`
/// - `GroupInfo`
///
/// Cryptographic encryption/signing operations are intentionally out of scope here.
/// Task 2 wires hybrid HPKE-style encryption over these payloads.

const WELCOME_VERSION: u8 = 1;
const GROUP_SECRETS_VERSION: u8 = 1;
const GROUP_INFO_VERSION: u8 = 1;

use rand_core::{CryptoRng, Rng};

use crate::crypto::{
    decrypt_hpke_payload, encrypt_hpke_payload, hybrid_kem_decapsulate, hybrid_kem_encapsulate,
    HybridCiphertext, HybridPrivateKey, HybridPublicKey, KyberCiphertext,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Welcome {
    pub cipher_suite: u16,
    pub secrets: Vec<EncryptedGroupSecrets>,
    pub encrypted_group_info: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedGroupSecrets {
    /// Hash reference to the joiner's KeyPackage (placeholder for key_package_ref).
    pub key_package_ref_hash: [u8; 32],
    /// Classic KEM component (for hybrid encapsulation output).
    pub kem_classic_ephemeral: [u8; 32],
    /// PQ KEM component (for hybrid encapsulation output).
    pub kem_pq_ciphertext: Vec<u8>,
    /// Encrypted `GroupSecrets` payload.
    pub encrypted_group_secrets: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupSecrets {
    pub joiner_secret: [u8; 32],
    pub path_secret: Option<[u8; 32]>,
    /// Opaque PreSharedKey identifiers (future extension point).
    pub psk_ids: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupInfo {
    pub group_id: String,
    pub epoch: u64,
    pub tree_hash: [u8; 32],
    pub confirmed_transcript_hash: [u8; 32],
    pub signer_leaf: u32,
    pub extensions: Vec<u8>,
    pub confirmation_tag: [u8; 32],
    pub signature: Vec<u8>,
}

impl Welcome {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_u8(&mut out, WELCOME_VERSION);
        encode_u16(&mut out, self.cipher_suite);
        encode_u32(&mut out, self.secrets.len() as u32);
        for item in &self.secrets {
            encode_bytes(&mut out, &item.encode());
        }
        encode_bytes(&mut out, &self.encrypted_group_info);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        if decoder.read_u8()? != WELCOME_VERSION {
            return None;
        }

        let cipher_suite = decoder.read_u16()?;
        let count = decoder.read_u32()? as usize;
        let mut secrets = Vec::with_capacity(count);
        for _ in 0..count {
            let enc = decoder.read_bytes()?;
            secrets.push(EncryptedGroupSecrets::decode(&enc)?);
        }
        let encrypted_group_info = decoder.read_bytes()?;

        if decoder.remaining() != 0 {
            return None;
        }

        Some(Self {
            cipher_suite,
            secrets,
            encrypted_group_info,
        })
    }
}

impl EncryptedGroupSecrets {
    /// Hybrid HPKE-style encryption for an encoded `GroupSecrets` payload.
    pub fn encrypt_for_recipient<R: Rng + CryptoRng>(
        rng: &mut R,
        group_id: &str,
        epoch: u64,
        key_package_ref_hash: [u8; 32],
        recipient_public: &HybridPublicKey,
        group_secrets: &GroupSecrets,
    ) -> Self {
        let context = welcome_group_secrets_context(group_id, epoch, &key_package_ref_hash);
        let plaintext = group_secrets.encode();
        let (kem, shared_secret) = hybrid_kem_encapsulate(rng, recipient_public, &context);
        let kem_pq_bytes: &[u8] = kem.pq.as_ref();
        let encrypted_group_secrets = encrypt_hpke_payload(&shared_secret, &context, &plaintext);

        Self {
            key_package_ref_hash,
            kem_classic_ephemeral: kem.classic,
            kem_pq_ciphertext: kem_pq_bytes.to_vec(),
            encrypted_group_secrets,
        }
    }

    /// Decapsulate and decrypt into `GroupSecrets`.
    pub fn decrypt_group_secrets(
        &self,
        group_id: &str,
        epoch: u64,
        recipient_private: &HybridPrivateKey,
    ) -> Option<GroupSecrets> {
        let context = welcome_group_secrets_context(group_id, epoch, &self.key_package_ref_hash);
        let kem_pq: KyberCiphertext = self.kem_pq_ciphertext.as_slice().try_into().ok()?;
        let kem = HybridCiphertext {
            classic: self.kem_classic_ephemeral,
            pq: kem_pq,
        };
        let shared_secret = hybrid_kem_decapsulate(recipient_private, &kem, &context);
        let plaintext =
            decrypt_hpke_payload(&shared_secret, &context, &self.encrypted_group_secrets)?;
        GroupSecrets::decode(&plaintext)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.key_package_ref_hash);
        out.extend_from_slice(&self.kem_classic_ephemeral);
        encode_bytes(&mut out, &self.kem_pq_ciphertext);
        encode_bytes(&mut out, &self.encrypted_group_secrets);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        let key_package_ref_hash = decoder.read_fixed_32()?;
        let kem_classic_ephemeral = decoder.read_fixed_32()?;
        let kem_pq_ciphertext = decoder.read_bytes()?;
        let encrypted_group_secrets = decoder.read_bytes()?;

        if kem_pq_ciphertext.is_empty() || encrypted_group_secrets.is_empty() {
            return None;
        }
        let _: KyberCiphertext = kem_pq_ciphertext.as_slice().try_into().ok()?;
        if decoder.remaining() != 0 {
            return None;
        }

        Some(Self {
            key_package_ref_hash,
            kem_classic_ephemeral,
            kem_pq_ciphertext,
            encrypted_group_secrets,
        })
    }
}

impl GroupSecrets {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_u8(&mut out, GROUP_SECRETS_VERSION);
        out.extend_from_slice(&self.joiner_secret);
        match self.path_secret {
            Some(path) => {
                encode_u8(&mut out, 1);
                out.extend_from_slice(&path);
            }
            None => encode_u8(&mut out, 0),
        }
        encode_u32(&mut out, self.psk_ids.len() as u32);
        for id in &self.psk_ids {
            encode_bytes(&mut out, id);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        if decoder.read_u8()? != GROUP_SECRETS_VERSION {
            return None;
        }

        let joiner_secret = decoder.read_fixed_32()?;
        let path_secret = match decoder.read_u8()? {
            0 => None,
            1 => Some(decoder.read_fixed_32()?),
            _ => return None,
        };

        let psk_count = decoder.read_u32()? as usize;
        let mut psk_ids = Vec::with_capacity(psk_count);
        for _ in 0..psk_count {
            psk_ids.push(decoder.read_bytes()?);
        }

        if decoder.remaining() != 0 {
            return None;
        }

        Some(Self {
            joiner_secret,
            path_secret,
            psk_ids,
        })
    }
}

impl GroupInfo {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_u8(&mut out, GROUP_INFO_VERSION);
        encode_bytes(&mut out, self.group_id.as_bytes());
        encode_u64(&mut out, self.epoch);
        out.extend_from_slice(&self.tree_hash);
        out.extend_from_slice(&self.confirmed_transcript_hash);
        encode_u32(&mut out, self.signer_leaf);
        encode_bytes(&mut out, &self.extensions);
        out.extend_from_slice(&self.confirmation_tag);
        encode_bytes(&mut out, &self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut decoder = Decoder::new(bytes);
        if decoder.read_u8()? != GROUP_INFO_VERSION {
            return None;
        }

        let group_id = String::from_utf8(decoder.read_bytes()?).ok()?;
        let epoch = decoder.read_u64()?;
        let tree_hash = decoder.read_fixed_32()?;
        let confirmed_transcript_hash = decoder.read_fixed_32()?;
        let signer_leaf = decoder.read_u32()?;
        let extensions = decoder.read_bytes()?;
        let confirmation_tag = decoder.read_fixed_32()?;
        let signature = decoder.read_bytes()?;

        if signature.is_empty() {
            return None;
        }
        if decoder.remaining() != 0 {
            return None;
        }

        Some(Self {
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
            signer_leaf,
            extensions,
            confirmation_tag,
            signature,
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

fn welcome_group_secrets_context(
    group_id: &str,
    epoch: u64,
    key_package_ref_hash: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::new();
    encode_bytes(&mut out, b"welcome-group-secrets");
    encode_bytes(&mut out, group_id.as_bytes());
    encode_u64(&mut out, epoch);
    out.extend_from_slice(key_package_ref_hash);
    out
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
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 2]);
        self.pos += 2;
        Some(u16::from_be_bytes(buf))
    }

    fn read_u32(&mut self) -> Option<u32> {
        if self.remaining() < 4 {
            return None;
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 4]);
        self.pos += 4;
        Some(u32::from_be_bytes(buf))
    }

    fn read_u64(&mut self) -> Option<u64> {
        if self.remaining() < 8 {
            return None;
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        Some(u64::from_be_bytes(buf))
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
    use std::convert::Infallible;

    use ml_kem::Seed;
    use rand_core::{TryCryptoRng, TryRng};
    use sha3::{Digest, Sha3_256};
    use x25519_dalek::{PublicKey as X25519Pub, StaticSecret as X25519Priv};

    use crate::crypto::{HybridPrivateKey, HybridPublicKey, KyberPriv};

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
            let mut offset = 0usize;
            while offset < dst.len() {
                let chunk = self.next_u64_internal().to_le_bytes();
                let take = (dst.len() - offset).min(chunk.len());
                dst[offset..offset + take].copy_from_slice(&chunk[..take]);
                offset += take;
            }
            Ok(())
        }
    }

    impl TryCryptoRng for TestRng {}

    fn hash(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }

    fn recipient_keys(seed: u8) -> (HybridPublicKey, HybridPrivateKey) {
        let classic_priv = X25519Priv::from([seed; 32]);
        let classic_pub = X25519Pub::from(&classic_priv);
        let pq_priv = KyberPriv::from_seed(Seed::from([seed.wrapping_add(1); 64]));
        let pq_pub = pq_priv.encapsulation_key().clone();

        (
            HybridPublicKey {
                classic: classic_pub,
                pq: pq_pub,
            },
            HybridPrivateKey {
                classic: classic_priv,
                pq: pq_priv,
            },
        )
    }

    #[test]
    fn group_secrets_roundtrip_with_path_secret() {
        let gs = GroupSecrets {
            joiner_secret: hash(1),
            path_secret: Some(hash(2)),
            psk_ids: vec![b"psk-alpha".to_vec(), b"psk-beta".to_vec()],
        };
        let encoded = gs.encode();
        let decoded = GroupSecrets::decode(&encoded).expect("decode group secrets");
        assert_eq!(decoded, gs);
    }

    #[test]
    fn group_secrets_roundtrip_without_path_secret() {
        let gs = GroupSecrets {
            joiner_secret: hash(3),
            path_secret: None,
            psk_ids: Vec::new(),
        };
        let encoded = gs.encode();
        let decoded = GroupSecrets::decode(&encoded).expect("decode group secrets");
        assert_eq!(decoded, gs);
    }

    #[test]
    fn group_info_roundtrip() {
        let info = GroupInfo {
            group_id: "group-alpha".to_string(),
            epoch: 7,
            tree_hash: hash(9),
            confirmed_transcript_hash: hash(10),
            signer_leaf: 1,
            extensions: vec![0x01, 0x02, 0x03],
            confirmation_tag: hash(11),
            signature: vec![0xAA; 64],
        };
        let encoded = info.encode();
        let decoded = GroupInfo::decode(&encoded).expect("decode group info");
        assert_eq!(decoded, info);
    }

    #[test]
    fn welcome_roundtrip() {
        let (recipient_pub_a, _) = recipient_keys(20);
        let (recipient_pub_b, _) = recipient_keys(21);
        let mut rng = TestRng(0x1111_2222_3333_4444);
        let welcome = Welcome {
            cipher_suite: 0x0001,
            secrets: vec![
                EncryptedGroupSecrets::encrypt_for_recipient(
                    &mut rng,
                    "group-r",
                    5,
                    hash(20),
                    &recipient_pub_a,
                    &GroupSecrets {
                        joiner_secret: hash(1),
                        path_secret: Some(hash(2)),
                        psk_ids: vec![b"a".to_vec()],
                    },
                ),
                EncryptedGroupSecrets::encrypt_for_recipient(
                    &mut rng,
                    "group-r",
                    5,
                    hash(30),
                    &recipient_pub_b,
                    &GroupSecrets {
                        joiner_secret: hash(3),
                        path_secret: None,
                        psk_ids: vec![b"b".to_vec(), b"c".to_vec()],
                    },
                ),
            ],
            encrypted_group_info: vec![0xF0, 0xF1, 0xF2],
        };
        let encoded = welcome.encode();
        let decoded = Welcome::decode(&encoded).expect("decode welcome");
        assert_eq!(decoded, welcome);
    }

    #[test]
    fn reject_welcome_truncated_and_trailing() {
        let (recipient_pub, _) = recipient_keys(5);
        let mut rng = TestRng(0x0102_0304_0506_0708);
        let welcome = Welcome {
            cipher_suite: 0x0001,
            secrets: vec![EncryptedGroupSecrets::encrypt_for_recipient(
                &mut rng,
                "group-z",
                1,
                hash(1),
                &recipient_pub,
                &GroupSecrets {
                    joiner_secret: hash(2),
                    path_secret: None,
                    psk_ids: Vec::new(),
                },
            )],
            encrypted_group_info: vec![3],
        };
        let encoded = welcome.encode();
        assert!(Welcome::decode(&encoded).is_some());

        let mut truncated = encoded.clone();
        let _ = truncated.pop();
        assert!(Welcome::decode(&truncated).is_none());

        let mut trailing = encoded;
        trailing.push(0xFF);
        assert!(Welcome::decode(&trailing).is_none());
    }

    #[test]
    fn reject_encrypted_group_secrets_with_empty_ciphertexts() {
        let egs = EncryptedGroupSecrets {
            key_package_ref_hash: hash(1),
            kem_classic_ephemeral: hash(2),
            kem_pq_ciphertext: Vec::new(),
            encrypted_group_secrets: vec![1],
        };
        assert!(EncryptedGroupSecrets::decode(&egs.encode()).is_none());
    }

    #[test]
    fn reject_group_info_without_signature() {
        let info = GroupInfo {
            group_id: "g".to_string(),
            epoch: 1,
            tree_hash: hash(1),
            confirmed_transcript_hash: hash(2),
            signer_leaf: 0,
            extensions: Vec::new(),
            confirmation_tag: hash(3),
            signature: Vec::new(),
        };
        assert!(GroupInfo::decode(&info.encode()).is_none());
    }

    #[test]
    fn encrypted_group_secrets_hybrid_roundtrip() {
        let (recipient_pub, recipient_priv) = recipient_keys(42);
        let mut rng = TestRng(0xdead_beef_dead_beef);
        let group_id = "group-hybrid";
        let epoch = 9;
        let key_package_ref_hash = hash(55);
        let secrets = GroupSecrets {
            joiner_secret: hash(1),
            path_secret: Some(hash(2)),
            psk_ids: vec![b"psk-1".to_vec(), b"psk-2".to_vec()],
        };

        let encrypted = EncryptedGroupSecrets::encrypt_for_recipient(
            &mut rng,
            group_id,
            epoch,
            key_package_ref_hash,
            &recipient_pub,
            &secrets,
        );

        let decrypted = encrypted
            .decrypt_group_secrets(group_id, epoch, &recipient_priv)
            .expect("decrypt group secrets");
        assert_eq!(decrypted, secrets);
    }

    #[test]
    fn encrypted_group_secrets_wrong_recipient_is_rejected() {
        let (recipient_pub, _) = recipient_keys(7);
        let (_, wrong_priv) = recipient_keys(8);
        let mut rng = TestRng(0xabcdef0123456789);
        let secrets = GroupSecrets {
            joiner_secret: hash(9),
            path_secret: None,
            psk_ids: Vec::new(),
        };
        let encrypted = EncryptedGroupSecrets::encrypt_for_recipient(
            &mut rng,
            "g",
            1,
            hash(3),
            &recipient_pub,
            &secrets,
        );

        assert!(encrypted
            .decrypt_group_secrets("g", 1, &wrong_priv)
            .is_none());
    }

    #[test]
    fn encrypted_group_secrets_tamper_rejected() {
        let (recipient_pub, recipient_priv) = recipient_keys(11);
        let mut rng = TestRng(0x1122_3344_5566_7788);
        let encrypted = EncryptedGroupSecrets::encrypt_for_recipient(
            &mut rng,
            "group-x",
            3,
            hash(77),
            &recipient_pub,
            &GroupSecrets {
                joiner_secret: hash(1),
                path_secret: Some(hash(2)),
                psk_ids: Vec::new(),
            },
        );

        let mut tampered = encrypted.clone();
        tampered.encrypted_group_secrets[0] ^= 0x40;
        assert!(tampered
            .decrypt_group_secrets("group-x", 3, &recipient_priv)
            .is_none());
    }

    #[test]
    fn deterministic_vector_group_secrets_encoding_matches_expected() {
        let gs = GroupSecrets {
            joiner_secret: hash(0x11),
            path_secret: Some(hash(0x22)),
            psk_ids: vec![b"psk-a".to_vec(), b"psk-b".to_vec()],
        };
        let encoded = gs.encode();
        assert_eq!(
            hex(&encoded),
            "011111111111111111111111111111111111111111111111111111111111111111012222222222222222222222222222222222222222222222222222222222222222000000020000000570736b2d610000000570736b2d62"
        );
    }

    #[test]
    fn deterministic_vector_welcome_encoding_matches_expected() {
        let (recipient_pub, _) = recipient_keys(0x33);
        let mut rng = TestRng(0x1234_5678_9abc_def0);
        let welcome = Welcome {
            cipher_suite: 0x0001,
            secrets: vec![EncryptedGroupSecrets::encrypt_for_recipient(
                &mut rng,
                "vector-welcome",
                9,
                hash(0x01),
                &recipient_pub,
                &GroupSecrets {
                    joiner_secret: hash(0x44),
                    path_secret: Some(hash(0x55)),
                    psk_ids: vec![b"psk-vector".to_vec()],
                },
            )],
            encrypted_group_info: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        let encoded = welcome.encode();
        let digest = Sha3_256::digest(&encoded);
        assert_eq!(
            hex(&digest),
            "7877bb75900750a5ef48155bf5acf506a1d4016d797769f7085cad2b7d35803e"
        );
        let decoded = Welcome::decode(&encoded).expect("decode deterministic welcome vector");
        assert_eq!(decoded, welcome);
    }
}
