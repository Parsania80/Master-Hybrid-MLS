use std::fmt::Debug;

use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    storage::{StorageProvider as StorageProviderTrait, CURRENT_VERSION},
    types::{Ciphersuite, HpkeCiphertext, HpkeKeyPair},
};
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};

#[cfg(feature = "experimental-hybrid")]
use crate::experimental_hybrid::{
    ExperimentalMkyberNodePrivateKey, ExperimentalMkyberNodePublicKey, ExperimentalNodeKeyError,
};
use crate::{
    ciphersuite::{hpke, HpkePrivateKey, HpkePublicKey, Secret},
    error::LibraryError,
    storage::{OpenMlsProvider, StorageProvider},
};
#[cfg(feature = "experimental-hybrid")]
use mkyber::{EducationalMkyber512Reference, MkyberDomain, MkyberKeyPair};

/// [`EncryptionKey`] contains an HPKE public key that allows the encryption of
/// path secrets in MLS commits.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
    PartialEq,
    Eq,
    Hash,
)]
pub struct EncryptionKey {
    key: HpkePublicKey,
    /// Optional non-standard mKyber public material for this TreeKEM node.
    ///
    /// The field exists only in the experimental fork wire format. A future
    /// UpdatePath integration must require `Some` for every resolution node.
    #[cfg(feature = "experimental-hybrid")]
    experimental_mkyber_key: Option<ExperimentalMkyberNodePublicKey>,
}

impl EncryptionKey {
    /// Return the internal [`HpkePublicKey`].
    pub(crate) fn key(&self) -> &HpkePublicKey {
        &self.key
    }

    /// Return the internal [`HpkePublicKey`] as slice.
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.key.as_slice()
    }

    /// Attaches feature-gated public mKyber material to this TreeKEM node.
    #[cfg(feature = "experimental-hybrid")]
    pub fn with_experimental_mkyber_key(
        mut self,
        mkyber_key: ExperimentalMkyberNodePublicKey,
    ) -> Self {
        self.experimental_mkyber_key = Some(mkyber_key);
        self
    }

    /// Returns the feature-gated public mKyber material for this TreeKEM node.
    #[cfg(feature = "experimental-hybrid")]
    pub fn experimental_mkyber_key(&self) -> Option<&ExperimentalMkyberNodePublicKey> {
        self.experimental_mkyber_key.as_ref()
    }

    /// Encrypt to this HPKE public key.
    pub(crate) fn encrypt(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        context: &[u8],
        plaintext: &[u8],
    ) -> Result<HpkeCiphertext, LibraryError> {
        hpke::encrypt_with_label(
            self.as_slice(),
            "UpdatePathNode",
            context,
            plaintext,
            ciphersuite,
            crypto,
        )
        .map_err(|_| LibraryError::custom("Encryption failed. A serialization issue really"))
    }
}

impl From<Vec<u8>> for EncryptionKey {
    fn from(key: Vec<u8>) -> Self {
        Self {
            key: key.into(),
            #[cfg(feature = "experimental-hybrid")]
            experimental_mkyber_key: None,
        }
    }
}

#[derive(
    Clone, Serialize, Deserialize, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq, Eq))]
pub struct EncryptionPrivateKey {
    key: HpkePrivateKey,
    #[cfg(feature = "experimental-hybrid")]
    experimental_mkyber_key: Option<ExperimentalMkyberNodePrivateKey>,
}

impl Debug for EncryptionPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ds = f.debug_struct("EncryptionPrivateKey");

        #[cfg(feature = "crypto-debug")]
        ds.field("key", &self.key);
        #[cfg(not(feature = "crypto-debug"))]
        ds.field("key", &"***");

        #[cfg(feature = "experimental-hybrid")]
        ds.field("experimental_mkyber_key", &self.experimental_mkyber_key);

        ds.finish()
    }
}

impl From<Vec<u8>> for EncryptionPrivateKey {
    fn from(key: Vec<u8>) -> Self {
        Self {
            key: key.into(),
            #[cfg(feature = "experimental-hybrid")]
            experimental_mkyber_key: None,
        }
    }
}

impl From<HpkePrivateKey> for EncryptionPrivateKey {
    fn from(key: HpkePrivateKey) -> Self {
        Self {
            key,
            #[cfg(feature = "experimental-hybrid")]
            experimental_mkyber_key: None,
        }
    }
}

impl EncryptionPrivateKey {
    /// Decrypt a given `HpkeCiphertext` using this [`EncryptionPrivateKey`] and
    /// `group_context`.
    ///
    /// Returns the decrypted [`Secret`]. Returns an error if the decryption was
    /// unsuccessful.
    pub(crate) fn decrypt(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        ciphertext: &HpkeCiphertext,
        group_context: &[u8],
    ) -> Result<Secret, hpke::Error> {
        // ValSem203: Path secrets must decrypt correctly
        hpke::decrypt_with_label(
            &self.key,
            "UpdatePathNode",
            group_context,
            ciphertext,
            ciphersuite,
            crypto,
        )
        .map(|secret_bytes| Secret::from_slice(&secret_bytes))
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl EncryptionPrivateKey {
    pub(crate) fn key(&self) -> &HpkePrivateKey {
        &self.key
    }
}

impl From<HpkePublicKey> for EncryptionKey {
    fn from(key: HpkePublicKey) -> Self {
        Self {
            key,
            #[cfg(feature = "experimental-hybrid")]
            experimental_mkyber_key: None,
        }
    }
}

#[derive(
    Debug, Clone, Serialize, Deserialize, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq, Eq))]
pub(crate) struct EncryptionKeyPair {
    public_key: EncryptionKey,
    private_key: EncryptionPrivateKey,
}

impl EncryptionKeyPair {
    /// Write the [`EncryptionKeyPair`] to the store of the `provider`.
    ///
    /// This must only be used for encryption key pairs that are generated for
    /// update leaf nodes. All other encryption key pairs are stored as part
    /// of the key package or the epoch encryption key pairs.
    pub(crate) fn write<Storage: StorageProvider>(
        &self,
        store: &Storage,
    ) -> Result<(), Storage::Error> {
        store.write_encryption_key_pair(self.public_key(), self)
    }

    /// Read the [`EncryptionKeyPair`] from the key store of the `provider`. This
    /// function is meant to read standalone keypairs, not ones that are
    /// already in use with an MLS group.
    ///
    /// This must only be used for encryption key pairs that are generated for
    /// update leaf nodes. All other encryption key pairs are stored as part
    /// of the key package or the epoch encryption key pairs.
    ///
    /// Returns `None` if the keypair cannot be read from the store.
    pub(crate) fn read(
        provider: &impl OpenMlsProvider,
        encryption_key: &EncryptionKey,
    ) -> Option<EncryptionKeyPair> {
        provider
            .storage()
            .encryption_key_pair(encryption_key)
            .ok()
            .flatten()
    }

    /// Delete the [`EncryptionKeyPair`] from the store of the `provider`.
    ///
    /// This must only be used for encryption key pairs that are generated for
    /// update leaf nodes. All other encryption key pairs are stored as part
    /// of the key package or the epoch encryption key pairs.
    pub(crate) fn delete<Storage: StorageProviderTrait<CURRENT_VERSION>>(
        &self,
        store: &Storage,
    ) -> Result<(), Storage::Error> {
        store.delete_encryption_key_pair(self.public_key())
    }

    pub(crate) fn public_key(&self) -> &EncryptionKey {
        &self.public_key
    }

    pub(crate) fn private_key(&self) -> &EncryptionPrivateKey {
        &self.private_key
    }

    /// Generates a classical and mKyber key pair for a fresh experimental leaf.
    #[cfg(feature = "experimental-hybrid")]
    pub(crate) fn random_with_experimental_mkyber(
        rand: &impl OpenMlsRand,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        domain: MkyberDomain,
    ) -> Result<Self, LibraryError> {
        let mkyber_keypair = EducationalMkyber512Reference
            .keygen_with_os_rng(domain)
            .map_err(|_| LibraryError::custom("experimental mKyber key generation failed"))?;
        Self::random(rand, crypto, ciphersuite)?.with_experimental_mkyber_keypair(mkyber_keypair)
    }

    /// Adds matching experimental mKyber material to an existing classical pair.
    #[cfg(feature = "experimental-hybrid")]
    pub(crate) fn with_experimental_mkyber_keypair(
        mut self,
        mkyber_keypair: MkyberKeyPair,
    ) -> Result<Self, LibraryError> {
        let (public_key, private_key) = mkyber_keypair.into_parts();
        let public_key = ExperimentalMkyberNodePublicKey::from_mkyber_key(&public_key);
        let private_key = ExperimentalMkyberNodePrivateKey::from_mkyber_key(private_key)
            .map_err(|_| LibraryError::custom("experimental mKyber private key is invalid"))?;
        self.public_key.experimental_mkyber_key = Some(public_key);
        self.private_key.experimental_mkyber_key = Some(private_key);
        Ok(self)
    }

    /// Returns the local mKyber private key only for a future hybrid receiver.
    #[cfg(feature = "experimental-hybrid")]
    pub(crate) fn experimental_mkyber_private_key(
        &self,
    ) -> Result<Option<mkyber::MkyberDecapsulationKey>, ExperimentalNodeKeyError> {
        self.private_key
            .experimental_mkyber_key
            .as_ref()
            .map(ExperimentalMkyberNodePrivateKey::to_mkyber_key)
            .transpose()
    }

    pub(crate) fn random(
        rand: &impl OpenMlsRand,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<Self, LibraryError> {
        let ikm =
            Secret::random(ciphersuite, rand).map_err(LibraryError::unexpected_crypto_error)?;
        Ok(crypto
            .derive_hpke_keypair(ciphersuite.hpke_config(), ikm.as_slice())
            .map_err(LibraryError::unexpected_crypto_error)?
            .into())
    }
}

#[cfg(feature = "test-utils")]
pub mod test_utils {
    use super::*;

    pub fn read_keys_from_key_store(
        provider: &impl OpenMlsProvider,
        encryption_key: &EncryptionKey,
    ) -> HpkeKeyPair {
        let keys = EncryptionKeyPair::read(provider, encryption_key).unwrap();

        HpkeKeyPair {
            private: keys.private_key.key,
            public: keys.public_key.key.as_slice().to_vec(),
        }
    }

    pub fn write_keys_from_key_store(provider: &impl OpenMlsProvider, encryption_key: HpkeKeyPair) {
        let keypair = EncryptionKeyPair::from(encryption_key);

        keypair.write(provider.storage()).unwrap();
    }
}

#[cfg(test)]
impl EncryptionKeyPair {
    /// Build a key pair from raw bytes for testing.
    pub(crate) fn from_raw(public_key: Vec<u8>, private_key: Vec<u8>) -> Self {
        Self {
            public_key: EncryptionKey {
                key: public_key.into(),
                #[cfg(feature = "experimental-hybrid")]
                experimental_mkyber_key: None,
            },
            private_key: EncryptionPrivateKey {
                key: private_key.into(),
                #[cfg(feature = "experimental-hybrid")]
                experimental_mkyber_key: None,
            },
        }
    }
}

impl From<(HpkePublicKey, HpkePrivateKey)> for EncryptionKeyPair {
    fn from((public_key, private_key): (HpkePublicKey, HpkePrivateKey)) -> Self {
        Self {
            public_key: public_key.into(),
            private_key: private_key.into(),
        }
    }
}

impl From<HpkeKeyPair> for EncryptionKeyPair {
    fn from(hpke_keypair: HpkeKeyPair) -> Self {
        let public_bytes: VLBytes = hpke_keypair.public.into();
        let private_bytes = hpke_keypair.private;
        Self {
            public_key: public_bytes.into(),
            private_key: private_bytes.into(),
        }
    }
}

impl From<(EncryptionKey, EncryptionPrivateKey)> for EncryptionKeyPair {
    fn from((public_key, private_key): (EncryptionKey, EncryptionPrivateKey)) -> Self {
        Self {
            public_key,
            private_key,
        }
    }
}
