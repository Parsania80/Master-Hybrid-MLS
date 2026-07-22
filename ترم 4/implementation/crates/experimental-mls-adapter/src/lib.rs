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
    use arity_state::{ArityPolicySnapshot, ArityState, TransitionEvaluationState};
    use hybrid_path_secret::{
        open_hybrid_path_level_with_provider, seal_hybrid_path_level_with_provider,
        ClassicalHpkeKeyPair, HybridPathCiphertext, HybridPathLevelContext,
        HybridPathRecipientPrivate, HybridPathRecipientPublic, HybridPathSecret,
        HybridRecipientCiphertext, PathNodeIndex, RecipientNodeIndex, TreeArity,
        MLS_PATH_SECRET_BYTES,
    };
    use mkyber::{
        EducationalMkyber512Reference, MkyberCommonCiphertext, MkyberDomain,
        MkyberRecipientCiphertext, MultiRecipientKem, RecipientId, RecipientPublicKey,
        RecipientSet,
    };
    use openmls_hybrid::{
        experimental_hybrid::{
            mkyber_recipient_capabilities, required_mkyber_recipient_capabilities,
            supports_mkyber_recipient_capabilities, ExperimentalHybridDeliveryError,
            ExperimentalHybridPathDelivery, ExperimentalMkyberError,
            ExperimentalMkyberNodeKeyStore, ExperimentalMkyberNodePublicKey,
            ExperimentalNodeKeyError, ExperimentalResolutionNodeId, ForkClassicalHpkeProvider,
            MkyberRecipientKeyMaterial, MKYBER_RECIPIENT_KEY_MATERIAL_BYTES,
            MKYBER_RECIPIENT_KEY_MATERIAL_VERSION,
        },
        prelude::{
            ApplyUpdatePathError, BasicCredential, Capabilities, Ciphersuite, CredentialWithKey,
            Extension, Extensions, GroupContext, KeyPackage, LeafNodeParameters, MlsGroup,
            MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageBodyOut,
            MlsMessageIn, OpenMlsProvider, ProcessMessageError, ProcessedMessageContent,
            StageCommitError, StagedCommit, StagedWelcome, UnknownExtension,
        },
        treesync::{EncryptionKey, ParentNode},
    };
    use openmls_hybrid_basic_credential::SignatureKeyPair;
    use openmls_hybrid_rust_crypto::OpenMlsRustCrypto;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};
    use transition_policy::{
        DeltaThreshold, PolicyWindowConfig, TransitionByteComponent, TransitionByteRange,
        TransitionPreflightMeasurement, TransitionStartConfig,
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

    #[test]
    fn fork_classical_provider_executes_hybrid_delivery_without_upstream_provider_types() {
        let backend = EducationalMkyber512Reference;
        let domain = MkyberDomain::new([0x52; 32]);
        let mut randomness = ChaCha20Rng::from_seed([0x53; 32]);
        let (mkyber_public, mkyber_private) = backend
            .keygen(domain, &mut randomness)
            .expect("deterministic test mKyber key generation")
            .into_parts();
        let (classical_public, classical_private) = ClassicalHpkeKeyPair::generate_with_os_rng()
            .expect("classical key generation")
            .into_parts();
        let context = HybridPathLevelContext::new(
            b"fork-provider-test".to_vec(),
            9,
            1,
            TreeArity::Binary,
            PathNodeIndex::new(4),
            domain,
            [0x54; 32],
        );
        let path_secret = HybridPathSecret::from_bytes(&[0x55; MLS_PATH_SECRET_BYTES])
            .expect("fixed-size path secret");
        let recipient_public = HybridPathRecipientPublic::new(
            RecipientNodeIndex::new(6),
            mkyber_public,
            classical_public,
        );
        let recipient_private = HybridPathRecipientPrivate::new(
            RecipientNodeIndex::new(6),
            mkyber_private,
            classical_private,
        );
        let provider = ForkClassicalHpkeProvider::default();

        let ciphertext = seal_hybrid_path_level_with_provider(
            &provider,
            &backend,
            &mut randomness,
            &context,
            &path_secret,
            &[recipient_public],
        )
        .expect("fork provider must seal");
        let opened = open_hybrid_path_level_with_provider(
            &provider,
            &backend,
            &context,
            &ciphertext,
            &recipient_private,
        )
        .expect("fork provider must open");

        assert_eq!(opened.as_bytes(), path_secret.as_bytes());
    }

    #[test]
    fn node_key_store_separates_leaf_and_parent_lifecycle() {
        let domain = MkyberDomain::new([0x61; 32]);
        let leaf = ExperimentalResolutionNodeId::new(0);
        let parent = ExperimentalResolutionNodeId::new(1);
        let mut store = ExperimentalMkyberNodeKeyStore::default();
        let leaf_public = store
            .generate_for_node(leaf, domain)
            .expect("leaf key generation");
        let parent_public = store
            .generate_for_node(parent, domain)
            .expect("parent key generation");
        let parent_recipient = RecipientId::new(parent.as_u32());
        let recipient_set = RecipientSet::new(
            domain,
            vec![RecipientPublicKey {
                recipient: parent_recipient,
                key: parent_public
                    .to_mkyber_key()
                    .expect("typed parent public key"),
            }],
        )
        .expect("single parent recipient");
        let backend = EducationalMkyber512Reference;
        let encapsulation = backend
            .encapsulate_with_os_rng(&recipient_set)
            .expect("parent public key must encapsulate");
        let recovered = backend
            .decapsulate(
                &store
                    .private_key_for(parent)
                    .expect("matching parent private key"),
                &encapsulation.ciphertext,
                parent_recipient,
            )
            .expect("matching parent private key must decapsulate");
        let leaf_canonical = leaf_public.canonical_bytes().expect("canonical leaf key");

        assert_eq!(store.retained_key_count(), 2);
        assert_eq!(recovered.as_bytes(), encapsulation.shared_secret.as_bytes());
        assert_eq!(leaf_canonical.len(), 800);
        assert_eq!(
            leaf_public,
            ExperimentalMkyberNodePublicKey::from_canonical_bytes(&leaf_canonical)
                .expect("exact leaf public key"),
        );
        assert_eq!(
            ExperimentalMkyberNodePublicKey::from_canonical_bytes(&leaf_canonical[..799]),
            Err(ExperimentalNodeKeyError::InvalidPublicEncoding)
        );
        assert_eq!(
            store.generate_for_node(parent, domain),
            Err(ExperimentalNodeKeyError::DuplicatePrivateKey(1))
        );
        assert_ne!(
            leaf_public
                .to_mkyber_key()
                .expect("typed leaf key")
                .as_bytes(),
            parent_public
                .to_mkyber_key()
                .expect("typed parent key")
                .as_bytes(),
        );
        assert_eq!(
            store
                .private_key_for(parent)
                .expect("parent private key")
                .domain(),
            domain
        );
        assert!(store.retire_node(parent));
        assert_eq!(store.retained_key_count(), 1);
        assert!(matches!(
            store.private_key_for(parent),
            Err(ExperimentalNodeKeyError::MissingPrivateKey(1))
        ));
    }

    #[test]
    fn node_public_key_is_bound_to_experimental_tree_key_state() {
        let domain = MkyberDomain::new([0x71; 32]);
        let mut store = ExperimentalMkyberNodeKeyStore::default();
        let node_key = store
            .generate_for_node(ExperimentalResolutionNodeId::new(5), domain)
            .expect("node key generation");
        let plain_key = EncryptionKey::from(vec![0x72; 32]);
        let bound_key = plain_key
            .clone()
            .with_experimental_mkyber_key(node_key.clone());
        let encoded_key = bound_key
            .tls_serialize_detached()
            .expect("experimental tree key serialization");
        let decoded_key = EncryptionKey::tls_deserialize_exact(&encoded_key)
            .expect("experimental tree key deserialization");
        let parent = ParentNode::from(bound_key.clone());
        let encoded_parent = parent
            .tls_serialize_detached()
            .expect("experimental parent serialization");
        let decoded_parent = ParentNode::tls_deserialize_exact(&encoded_parent)
            .expect("experimental parent deserialization");

        assert_ne!(
            plain_key
                .tls_serialize_detached()
                .expect("plain tree key serialization"),
            encoded_key
        );
        assert_eq!(
            decoded_key
                .experimental_mkyber_key()
                .expect("decoded key material"),
            &node_key
        );
        assert_eq!(decoded_parent, parent);
    }

    #[test]
    fn experimental_key_package_binds_signed_leaf_and_extension_to_one_mkyber_pair() {
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .expect("supported signature key generation");
        let credential_with_key = CredentialWithKey {
            credential: BasicCredential::new(b"experimental-key-package".to_vec()).into(),
            signature_key: signer.public().into(),
        };
        let domain = MkyberDomain::new([0x81; 32]);
        let bundle = KeyPackage::builder()
            .build_with_experimental_mkyber(
                ciphersuite,
                &provider,
                &signer,
                credential_with_key,
                domain,
            )
            .expect("experimental KeyPackage build");
        let signed_material = MkyberRecipientKeyMaterial::from_key_package(bundle.key_package())
            .expect("signed KeyPackage material");
        let leaf_material = bundle
            .key_package()
            .leaf_node()
            .encryption_key()
            .experimental_mkyber_key()
            .expect("bound leaf material");

        assert_eq!(signed_material.domain(), domain);
        assert_eq!(
            signed_material.public_key().as_bytes(),
            leaf_material
                .to_mkyber_key()
                .expect("bound leaf mKyber public key")
                .as_bytes(),
        );
        assert!(supports_mkyber_recipient_capabilities(
            bundle.key_package().leaf_node().capabilities()
        ));
        let recipient = RecipientId::new(12);
        let recipient_set = RecipientSet::new(
            domain,
            vec![RecipientPublicKey {
                recipient,
                key: signed_material.public_key().clone(),
            }],
        )
        .expect("single recipient set");
        let backend = EducationalMkyber512Reference;
        let encapsulation = backend
            .encapsulate_with_os_rng(&recipient_set)
            .expect("signed public key encapsulation");
        let recovered = backend
            .decapsulate(
                &bundle
                    .experimental_mkyber_private_key()
                    .expect("private bundle key reconstruction")
                    .expect("matched private bundle key"),
                &encapsulation.ciphertext,
                recipient,
            )
            .expect("matched private bundle key decapsulation");
        assert_eq!(recovered.as_bytes(), encapsulation.shared_secret.as_bytes());
    }

    fn experimental_binary_pair() -> (
        OpenMlsRustCrypto,
        SignatureKeyPair,
        MlsGroup,
        OpenMlsRustCrypto,
        SignatureKeyPair,
        MlsGroup,
    ) {
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let domain = MkyberDomain::new([0x91; 32]);
        let alice_provider = OpenMlsRustCrypto::default();
        let bob_provider = OpenMlsRustCrypto::default();
        let alice_signer =
            SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("Alice signer");
        let bob_signer =
            SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("Bob signer");
        let alice_credential = CredentialWithKey {
            credential: BasicCredential::new(b"experimental-alice".to_vec()).into(),
            signature_key: alice_signer.public().into(),
        };
        let bob_credential = CredentialWithKey {
            credential: BasicCredential::new(b"experimental-bob".to_vec()).into(),
            signature_key: bob_signer.public().into(),
        };
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(ciphersuite)
            .use_ratchet_tree_extension(true)
            .with_group_context_extensions(normal_binary_arity_extensions())
            .build();
        let mut alice = MlsGroup::new_with_group_id_experimental_mkyber(
            &alice_provider,
            &alice_signer,
            &config,
            openmls_hybrid::prelude::GroupId::from_slice(b"experimental-round-trip"),
            alice_credential,
            domain,
        )
        .expect("experimental group creation");
        let bob_bundle = KeyPackage::builder()
            .build_with_experimental_mkyber(
                ciphersuite,
                &bob_provider,
                &bob_signer,
                bob_credential,
                domain,
            )
            .expect("Bob experimental KeyPackage");
        let (_add_commit, welcome, _) = alice
            .add_members(
                &alice_provider,
                &alice_signer,
                core::slice::from_ref(bob_bundle.key_package()),
            )
            .expect("experimental add");
        alice
            .merge_pending_commit_experimental_atomic(&alice_provider)
            .expect("Alice merges add");
        let welcome = match MlsMessageIn::tls_deserialize_exact(
            welcome
                .tls_serialize_detached()
                .expect("welcome serialization"),
        )
        .expect("welcome parsing")
        .extract()
        {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => panic!("expected Welcome"),
        };
        let bob = StagedWelcome::new_from_welcome(
            &bob_provider,
            &MlsGroupJoinConfig::builder()
                .use_ratchet_tree_extension(true)
                .build(),
            welcome,
            None,
        )
        .expect("Bob staged Welcome")
        .into_group(&bob_provider)
        .expect("Bob joins");
        (
            alice_provider,
            alice_signer,
            alice,
            bob_provider,
            bob_signer,
            bob,
        )
    }

    fn normal_binary_arity_extensions() -> Extensions<GroupContext> {
        let window = PolicyWindowConfig::new(20, 2, 1).expect("valid policy window");
        let preflight = TransitionPreflightMeasurement::from_serialized_outer_message(
            &[0_u8; 100],
            &[TransitionByteRange::new(
                TransitionByteComponent::BaseCommit,
                0,
                100,
            )],
        )
        .expect("valid transition preflight");
        let resolved = DeltaThreshold::PercentOfTransitionMicro(25_000_000)
            .resolve_for_preflight(preflight)
            .expect("resolved test threshold");
        let start = TransitionStartConfig::new(2, 4, 128, 1, resolved.resolved_bytes())
            .expect("valid transition controls");
        let policy = ArityPolicySnapshot::from_policy_inputs(window, start, resolved)
            .expect("self-consistent policy snapshot");
        let state = ArityState::normal(2, 4, 0, policy, TransitionEvaluationState::new(0, 0, 0))
            .expect("valid normal binary state");
        Extensions::single(Extension::Unknown(
            state.extension_type(),
            UnknownExtension(
                state
                    .extension_value_bytes()
                    .expect("canonical ArityState encoding"),
            ),
        ))
        .expect("unique ArityState extension")
    }

    fn hybrid_self_update_wire(
        bob: &mut MlsGroup,
        bob_provider: &OpenMlsRustCrypto,
        bob_signer: &SignatureKeyPair,
        leaf_node_parameters: LeafNodeParameters,
    ) -> Vec<u8> {
        let update = bob
            .self_update(bob_provider, bob_signer, leaf_node_parameters)
            .expect("Bob stages hybrid self-update");
        let (update_commit, _, _) = update.into_contents();
        update_commit
            .tls_serialize_detached()
            .expect("update serialization")
    }

    fn staged_commit_from_wire(
        group: &mut MlsGroup,
        provider: &OpenMlsRustCrypto,
        wire: &[u8],
    ) -> StagedCommit {
        let protocol_message = MlsMessageIn::tls_deserialize_exact(wire)
            .expect("Commit parsing")
            .try_into_protocol_message()
            .expect("protocol message");
        let processed = group
            .process_message(provider, protocol_message)
            .expect("hybrid Commit processing");
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            panic!("expected staged Commit");
        };
        *staged
    }

    #[test]
    fn experimental_binary_self_update_round_trips_through_tree_sync() {
        let (alice_provider, alice_signer, mut alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair();
        let update_wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::default(),
        );
        let protocol_message = MlsMessageIn::tls_deserialize_exact(&update_wire)
            .expect("update parsing")
            .try_into_protocol_message()
            .expect("protocol message");
        let staged = alice
            .process_message(&alice_provider, protocol_message)
            .expect("Alice processes hybrid self-update");
        let ProcessedMessageContent::StagedCommitMessage(staged) = staged.into_content() else {
            panic!("expected staged Commit");
        };
        alice
            .merge_staged_commit_experimental_atomic(&alice_provider, *staged)
            .expect("Alice merges hybrid self-update");
        bob.merge_pending_commit_experimental_atomic(&bob_provider)
            .expect("Bob merges self-update");

        assert_eq!(alice.epoch(), bob.epoch());
        assert_eq!(alice.export_ratchet_tree(), bob.export_ratchet_tree());
        let alice_context = match alice
            .export_group_info(alice_provider.crypto(), &alice_signer, false)
            .expect("Alice GroupInfo")
            .body()
        {
            MlsMessageBodyOut::GroupInfo(group_info) => group_info
                .group_context()
                .tls_serialize_detached()
                .expect("Alice GroupContext serialization"),
            _ => panic!("expected Alice GroupInfo"),
        };
        let bob_context = match bob
            .export_group_info(bob_provider.crypto(), &bob_signer, false)
            .expect("Bob GroupInfo")
            .body()
        {
            MlsMessageBodyOut::GroupInfo(group_info) => group_info
                .group_context()
                .tls_serialize_detached()
                .expect("Bob GroupContext serialization"),
            _ => panic!("expected Bob GroupInfo"),
        };
        assert_eq!(alice_context, bob_context);
    }

    #[test]
    fn experimental_atomic_binary_commit_converges_three_members_and_reloads() {
        let (alice_provider, alice_signer, mut alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair();
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let domain = MkyberDomain::new([0x91; 32]);
        let charlie_provider = OpenMlsRustCrypto::default();
        let charlie_signer =
            SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("Charlie signer");
        let charlie_credential = CredentialWithKey {
            credential: BasicCredential::new(b"experimental-charlie".to_vec()).into(),
            signature_key: charlie_signer.public().into(),
        };
        let charlie_bundle = KeyPackage::builder()
            .build_with_experimental_mkyber(
                ciphersuite,
                &charlie_provider,
                &charlie_signer,
                charlie_credential,
                domain,
            )
            .expect("Charlie experimental KeyPackage");
        let (add_commit, welcome, _) = alice
            .add_members(
                &alice_provider,
                &alice_signer,
                core::slice::from_ref(charlie_bundle.key_package()),
            )
            .expect("Alice adds Charlie");
        let add_wire = add_commit
            .tls_serialize_detached()
            .expect("add Commit serialization");
        let bob_staged = staged_commit_from_wire(&mut bob, &bob_provider, &add_wire);
        alice
            .merge_pending_commit_experimental_atomic(&alice_provider)
            .expect("Alice atomically merges Charlie add");
        bob.merge_staged_commit_experimental_atomic(&bob_provider, bob_staged)
            .expect("Bob atomically merges Charlie add");

        let welcome = match MlsMessageIn::tls_deserialize_exact(
            welcome
                .tls_serialize_detached()
                .expect("Charlie Welcome serialization"),
        )
        .expect("Charlie Welcome parsing")
        .extract()
        {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => panic!("expected Charlie Welcome"),
        };
        let mut charlie = StagedWelcome::new_from_welcome(
            &charlie_provider,
            &MlsGroupJoinConfig::builder()
                .use_ratchet_tree_extension(true)
                .build(),
            welcome,
            None,
        )
        .expect("Charlie staged Welcome")
        .into_group(&charlie_provider)
        .expect("Charlie joins");

        let update_wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::default(),
        );
        let alice_staged = staged_commit_from_wire(&mut alice, &alice_provider, &update_wire);
        let charlie_staged = staged_commit_from_wire(&mut charlie, &charlie_provider, &update_wire);
        alice
            .merge_staged_commit_experimental_atomic(&alice_provider, alice_staged)
            .expect("Alice atomically merges Bob update");
        charlie
            .merge_staged_commit_experimental_atomic(&charlie_provider, charlie_staged)
            .expect("Charlie atomically merges Bob update");
        bob.merge_pending_commit_experimental_atomic(&bob_provider)
            .expect("Bob atomically merges own update");

        assert_eq!(alice.epoch(), bob.epoch());
        assert_eq!(bob.epoch(), charlie.epoch());
        assert_eq!(alice.export_ratchet_tree(), bob.export_ratchet_tree());
        assert_eq!(bob.export_ratchet_tree(), charlie.export_ratchet_tree());
        assert_eq!(alice.extensions(), bob.extensions());
        assert_eq!(bob.extensions(), charlie.extensions());

        for (provider, group) in [
            (&alice_provider, &alice),
            (&bob_provider, &bob),
            (&charlie_provider, &charlie),
        ] {
            let reloaded = MlsGroup::load(provider.storage(), group.group_id())
                .expect("group reload storage access")
                .expect("stored group");
            assert_eq!(reloaded.epoch(), group.epoch());
            assert_eq!(reloaded.export_ratchet_tree(), group.export_ratchet_tree());
            assert_eq!(reloaded.extensions(), group.extensions());
        }
    }

    #[test]
    fn experimental_atomic_receiver_merge_rolls_back_every_storage_mutation() {
        let (control_provider, _alice_signer, mut control, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair();
        let control_wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::default(),
        );
        let control_staged =
            staged_commit_from_wire(&mut control, &control_provider, &control_wire);
        control_provider.storage().set_transaction_failure_at(None);
        control
            .merge_staged_commit_experimental_atomic(&control_provider, control_staged)
            .expect("control receiver merge");
        let mutation_count = control_provider.storage().last_transaction_mutation_count();
        assert!(mutation_count > 0);

        for failure_at in 0..mutation_count {
            let (alice_provider, _alice_signer, mut alice, bob_provider, bob_signer, mut bob) =
                experimental_binary_pair();
            let update_wire = hybrid_self_update_wire(
                &mut bob,
                &bob_provider,
                &bob_signer,
                LeafNodeParameters::default(),
            );
            let staged = staged_commit_from_wire(&mut alice, &alice_provider, &update_wire);
            let before_epoch = alice.epoch();
            let before_tree = alice.export_ratchet_tree();
            let before_extensions = alice.extensions().clone();
            let before_storage = alice_provider.storage().values.read().unwrap().clone();
            alice_provider
                .storage()
                .set_transaction_failure_at(Some(failure_at));

            assert!(alice
                .merge_staged_commit_experimental_atomic(&alice_provider, staged)
                .is_err());
            assert_eq!(alice.epoch(), before_epoch);
            assert_eq!(alice.export_ratchet_tree(), before_tree);
            assert_eq!(alice.extensions(), &before_extensions);
            assert_eq!(
                *alice_provider.storage().values.read().unwrap(),
                before_storage
            );
            let reloaded = MlsGroup::load(alice_provider.storage(), alice.group_id())
                .expect("failed transaction remains loadable")
                .expect("stored pre-merge group");
            assert_eq!(reloaded.epoch(), before_epoch);
            assert_eq!(reloaded.export_ratchet_tree(), before_tree);
            assert_eq!(reloaded.extensions(), &before_extensions);
        }
    }

    #[test]
    fn experimental_atomic_pending_merge_rolls_back_every_storage_mutation() {
        let (_alice_provider, _alice_signer, _alice, control_provider, control_signer, mut control) =
            experimental_binary_pair();
        let _control_wire = hybrid_self_update_wire(
            &mut control,
            &control_provider,
            &control_signer,
            LeafNodeParameters::default(),
        );
        control_provider.storage().set_transaction_failure_at(None);
        control
            .merge_pending_commit_experimental_atomic(&control_provider)
            .expect("control pending merge");
        let mutation_count = control_provider.storage().last_transaction_mutation_count();
        assert!(mutation_count > 0);

        for failure_at in 0..mutation_count {
            let (_alice_provider, _alice_signer, _alice, bob_provider, bob_signer, mut bob) =
                experimental_binary_pair();
            let _update_wire = hybrid_self_update_wire(
                &mut bob,
                &bob_provider,
                &bob_signer,
                LeafNodeParameters::default(),
            );
            let before_epoch = bob.epoch();
            let before_tree = bob.export_ratchet_tree();
            let before_extensions = bob.extensions().clone();
            let before_storage = bob_provider.storage().values.read().unwrap().clone();
            assert!(bob.pending_commit().is_some());
            bob_provider
                .storage()
                .set_transaction_failure_at(Some(failure_at));

            assert!(bob
                .merge_pending_commit_experimental_atomic(&bob_provider)
                .is_err());
            assert_eq!(bob.epoch(), before_epoch);
            assert_eq!(bob.export_ratchet_tree(), before_tree);
            assert_eq!(bob.extensions(), &before_extensions);
            assert!(bob.pending_commit().is_some());
            assert_eq!(
                *bob_provider.storage().values.read().unwrap(),
                before_storage
            );
            let reloaded = MlsGroup::load(bob_provider.storage(), bob.group_id())
                .expect("failed pending transaction remains loadable")
                .expect("stored pending group");
            assert_eq!(reloaded.epoch(), before_epoch);
            assert_eq!(reloaded.export_ratchet_tree(), before_tree);
            assert_eq!(reloaded.extensions(), &before_extensions);
            assert!(reloaded.pending_commit().is_some());
        }
    }

    #[test]
    fn experimental_binary_commit_rejects_tampered_wire_without_mutation() {
        let (alice_provider, _alice_signer, mut alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair();
        let mut update_wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::default(),
        );
        let before_epoch = alice.epoch();
        let before_tree = alice.export_ratchet_tree();
        let last_byte = update_wire.last_mut().expect("non-empty Commit wire");
        *last_byte ^= 0x01;
        let protocol_message = MlsMessageIn::tls_deserialize_exact(&update_wire)
            .expect("tampered fixed-length wire remains parseable")
            .try_into_protocol_message()
            .expect("tampered Commit remains a protocol message");

        assert!(alice
            .process_message(&alice_provider, protocol_message)
            .is_err());
        assert_eq!(alice.epoch(), before_epoch);
        assert_eq!(alice.export_ratchet_tree(), before_tree);
    }

    #[test]
    fn experimental_binary_commit_rejects_malformed_wire_without_mutation() {
        let (_alice_provider, _alice_signer, alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair();
        let mut update_wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::default(),
        );
        let before_epoch = alice.epoch();
        let before_tree = alice.export_ratchet_tree();
        update_wire.pop().expect("non-empty Commit wire");

        assert!(MlsMessageIn::tls_deserialize_exact(&update_wire).is_err());
        assert_eq!(alice.epoch(), before_epoch);
        assert_eq!(alice.export_ratchet_tree(), before_tree);
    }

    #[test]
    fn experimental_binary_commit_rejects_non_member_receiver_without_mutation() {
        let (_alice_provider, _alice_signer, _alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair();
        let update_wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::default(),
        );
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let mallory_provider = OpenMlsRustCrypto::default();
        let mallory_signer =
            SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("Mallory signer");
        let mallory_credential = CredentialWithKey {
            credential: BasicCredential::new(b"experimental-mallory".to_vec()).into(),
            signature_key: mallory_signer.public().into(),
        };
        let mut mallory = MlsGroup::new_with_group_id_experimental_mkyber(
            &mallory_provider,
            &mallory_signer,
            &MlsGroupCreateConfig::builder()
                .ciphersuite(ciphersuite)
                .use_ratchet_tree_extension(true)
                .with_group_context_extensions(normal_binary_arity_extensions())
                .build(),
            openmls_hybrid::prelude::GroupId::from_slice(b"non-member-receiver"),
            mallory_credential,
            MkyberDomain::new([0x91; 32]),
        )
        .expect("Mallory experimental group creation");
        let before_epoch = mallory.epoch();
        let before_tree = mallory.export_ratchet_tree();
        let protocol_message = MlsMessageIn::tls_deserialize_exact(&update_wire)
            .expect("non-member Commit parsing")
            .try_into_protocol_message()
            .expect("non-member protocol message");

        assert!(mallory
            .process_message(&mallory_provider, protocol_message)
            .is_err());
        assert_eq!(mallory.epoch(), before_epoch);
        assert_eq!(mallory.export_ratchet_tree(), before_tree);
    }

    #[test]
    fn experimental_binary_commit_replay_is_rejected_without_mutation() {
        let (alice_provider, _alice_signer, mut alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair();
        let update_wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::default(),
        );
        let protocol_message = MlsMessageIn::tls_deserialize_exact(&update_wire)
            .expect("update parsing")
            .try_into_protocol_message()
            .expect("protocol message");
        let staged = alice
            .process_message(&alice_provider, protocol_message)
            .expect("Alice processes hybrid self-update");
        let ProcessedMessageContent::StagedCommitMessage(staged) = staged.into_content() else {
            panic!("expected staged Commit");
        };
        alice
            .merge_staged_commit_experimental_atomic(&alice_provider, *staged)
            .expect("Alice merges hybrid self-update");
        bob.merge_pending_commit_experimental_atomic(&bob_provider)
            .expect("Bob merges self-update");
        let before_epoch = alice.epoch();
        let before_tree = alice.export_ratchet_tree();
        let replay = MlsMessageIn::tls_deserialize_exact(&update_wire)
            .expect("replay parsing")
            .try_into_protocol_message()
            .expect("replay protocol message");

        assert!(alice.process_message(&alice_provider, replay).is_err());
        assert_eq!(alice.epoch(), before_epoch);
        assert_eq!(alice.export_ratchet_tree(), before_tree);
    }

    #[test]
    fn experimental_binary_commit_rejects_missing_sender_capabilities_without_mutation() {
        let (alice_provider, _alice_signer, mut alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair();
        let update_wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::builder()
                .with_capabilities(Capabilities::new(
                    None,
                    None,
                    Some(&[required_mkyber_recipient_capabilities()[0]]),
                    None,
                    None,
                ))
                .build(),
        );
        let before_epoch = alice.epoch();
        let before_tree = alice.export_ratchet_tree();
        let protocol_message = MlsMessageIn::tls_deserialize_exact(&update_wire)
            .expect("capability-rejection Commit parsing")
            .try_into_protocol_message()
            .expect("capability-rejection protocol message");

        assert!(matches!(
            alice
                .process_message(&alice_provider, protocol_message)
                .expect_err("missing experimental capabilities must be rejected"),
            ProcessMessageError::InvalidCommit(StageCommitError::UpdatePathError(
                ApplyUpdatePathError::MissingExperimentalCapability
            ))
        ));
        assert_eq!(alice.epoch(), before_epoch);
        assert_eq!(alice.export_ratchet_tree(), before_tree);
    }

    #[test]
    fn experimental_mkyber_epoch_keypairs_replace_only_when_self_update_merges() {
        let (_alice_provider, _alice_signer, _alice, bob_provider, bob_signer, mut bob) =
            experimental_binary_pair();
        let old_epoch = bob.epoch();
        let old_leaf_key = bob
            .own_leaf_node()
            .expect("Bob own leaf")
            .encryption_key()
            .clone();
        let old_mkyber_keypair_count = bob
            .experimental_mkyber_epoch_keypair_count(&bob_provider, old_epoch)
            .expect("old epoch mKyber key-pair status");
        assert!(old_mkyber_keypair_count > 0);

        let _update_wire = hybrid_self_update_wire(
            &mut bob,
            &bob_provider,
            &bob_signer,
            LeafNodeParameters::default(),
        );
        assert_eq!(bob.epoch(), old_epoch);
        assert_eq!(
            bob.experimental_mkyber_epoch_keypair_count(&bob_provider, old_epoch)
                .expect("pending self-update retains old epoch key pairs"),
            old_mkyber_keypair_count
        );

        bob.merge_pending_commit_experimental_atomic(&bob_provider)
            .expect("Bob merges self-update");
        let new_epoch = bob.epoch();
        let new_leaf_key = bob
            .own_leaf_node()
            .expect("Bob updated own leaf")
            .encryption_key();

        assert_ne!(new_epoch, old_epoch);
        assert_ne!(new_leaf_key, &old_leaf_key);
        assert_eq!(
            bob.experimental_mkyber_epoch_keypair_count(&bob_provider, old_epoch)
                .expect("retired epoch key-pair status"),
            0
        );
        assert!(
            bob.experimental_mkyber_epoch_keypair_count(&bob_provider, new_epoch)
                .expect("new epoch mKyber key-pair status")
                > 0
        );
    }
}
