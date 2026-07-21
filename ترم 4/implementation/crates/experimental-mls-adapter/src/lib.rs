#![forbid(unsafe_code)]

//! Isolated activation boundary for the local experimental OpenMLS fork.
//!
//! This crate deliberately links the separately named fork without exposing
//! it through the unchanged baseline adapter. It contains no hybrid UpdatePath
//! or adaptive-transition behavior yet; those changes must be implemented and
//! tested inside the fork before an experimental client is exposed.

/// Exact upstream OpenMLS revision used by the local fork.
pub const OPENMLS_HYBRID_UPSTREAM_REVISION: &str = "47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6";

/// Confirms that the opt-in fork package is linked into this isolated boundary.
pub fn fork_ciphersuite_type_name() -> &'static str {
    std::any::type_name::<openmls_hybrid::prelude::Ciphersuite>()
}

#[cfg(test)]
mod tests {
    use hybrid_path_secret::{
        HybridPathCiphertext, HybridRecipientCiphertext, PathNodeIndex, RecipientNodeIndex,
    };
    use mkyber::{MkyberCommonCiphertext, MkyberDomain, MkyberRecipientCiphertext};
    use openmls_hybrid::{
        experimental_hybrid::{
            mkyber_recipient_capabilities, required_mkyber_recipient_capabilities,
            supports_mkyber_recipient_capabilities, ExperimentalHybridDeliveryError,
            ExperimentalHybridPathDelivery, ExperimentalMkyberError, MkyberRecipientKeyMaterial,
            MKYBER_RECIPIENT_KEY_MATERIAL_BYTES, MKYBER_RECIPIENT_KEY_MATERIAL_VERSION,
        },
        prelude::{Extension, Extensions, KeyPackage, UnknownExtension},
    };

    use super::{fork_ciphersuite_type_name, OPENMLS_HYBRID_UPSTREAM_REVISION};

    #[test]
    fn links_the_expected_named_fork() {
        assert!(fork_ciphersuite_type_name().contains("Ciphersuite"));
        assert_eq!(OPENMLS_HYBRID_UPSTREAM_REVISION.len(), 40);
    }

    #[test]
    fn mkyber_recipient_material_is_canonical_and_capability_gated() {
        let material = MkyberRecipientKeyMaterial::from_parts([0x42; 32], [0x24; 768])
            .expect("fixed-size public material must parse");
        let extensions = material
            .key_package_extensions()
            .expect("private-use key package extension must be valid");

        assert_eq!(
            MkyberRecipientKeyMaterial::from_key_package_extensions(&extensions)
                .expect("canonical extension must round-trip"),
            material
        );
        assert!(supports_mkyber_recipient_capabilities(
            &mkyber_recipient_capabilities()
        ));
        assert!(!supports_mkyber_recipient_capabilities(
            &openmls_hybrid::prelude::Capabilities::default()
        ));
    }

    #[test]
    fn mkyber_recipient_material_rejects_wrong_version_and_length() {
        let mut wrong_version = vec![0_u8; MKYBER_RECIPIENT_KEY_MATERIAL_BYTES];
        wrong_version[..2]
            .copy_from_slice(&(MKYBER_RECIPIENT_KEY_MATERIAL_VERSION + 1).to_be_bytes());
        let extensions = Extensions::<KeyPackage>::single(Extension::Unknown(
            required_mkyber_recipient_capabilities()[1].into(),
            UnknownExtension(wrong_version),
        ))
        .expect("private-use key package extension must be valid");

        assert_eq!(
            MkyberRecipientKeyMaterial::from_key_package_extensions(&extensions),
            Err(ExperimentalMkyberError::UnsupportedVersion(
                MKYBER_RECIPIENT_KEY_MATERIAL_VERSION + 1
            ))
        );
        assert_eq!(
            MkyberRecipientKeyMaterial::from_extension_value(&[0_u8; 3]),
            Err(ExperimentalMkyberError::InvalidEncodingLength {
                expected: MKYBER_RECIPIENT_KEY_MATERIAL_BYTES,
                actual: 3,
            })
        );
    }

    #[test]
    fn hybrid_delivery_accepts_only_exact_canonical_bytes_for_its_path_node() {
        let ciphertext = HybridPathCiphertext::new(
            PathNodeIndex::new(3),
            MkyberDomain::new([0x42; 32]),
            MkyberCommonCiphertext::from_bytes(&[0x11; 704]).expect("fixed-size common component"),
            vec![HybridRecipientCiphertext::new(
                RecipientNodeIndex::new(7),
                [0x22; 32],
                MkyberRecipientCiphertext::from_bytes(&[0x33; 48])
                    .expect("fixed-size recipient component"),
                [0x44; 48],
            )],
        )
        .expect("canonical fixture");
        let canonical_bytes = ciphertext
            .commit_authenticated_bytes()
            .expect("canonical serialization");

        let delivery =
            ExperimentalHybridPathDelivery::from_canonical_bytes(3, canonical_bytes.clone())
                .expect("matching canonical delivery");
        assert_eq!(delivery.path_node_index(), 3);
        assert_eq!(delivery.canonical_bytes(), canonical_bytes);
        assert_eq!(
            ExperimentalHybridPathDelivery::from_canonical_bytes(4, canonical_bytes),
            Err(ExperimentalHybridDeliveryError::PathNodeMismatch {
                expected: 4,
                actual: 3,
            })
        );
    }
}
