use hybrid_mls::authenticated_content::derive_membership_key;
use hybrid_mls::key_schedule::KeyScheduleState;
use hybrid_mls::mls_wire::{ContentType, MlsMessage, PrivateMessage, PublicMessage, MLS_PROTOCOL_VERSION};
use hybrid_mls::transcript::{derive_confirmation_key, derive_confirmation_tag, verify_confirmation_tag, TranscriptState};
use hybrid_mls::tree::Proposal;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

fn hex32(bytes: &[u8; 32]) -> String {
    hex(bytes)
}

#[test]
fn wire_decode_negative_matrix_rejects_malformed_frames() {
    let valid_public = PublicMessage {
        group_id: "matrix-group".to_string(),
        epoch: 7,
        sender_leaf: 1,
        content_type: ContentType::Proposal,
        authenticated_data: b"aad".to_vec(),
        content: Proposal::Remove { leaf_index: 2 }.encode(),
        membership_tag: Some(vec![0xAA; 8]),
        confirmation_tag: None,
    };
    let valid_public_mls = MlsMessage::from_public(valid_public.clone()).encode();

    let valid_private = PrivateMessage {
        group_id: "matrix-group".to_string(),
        epoch: 7,
        content_type: ContentType::Application,
        authenticated_data: b"aad".to_vec(),
        encrypted_sender_data: vec![1, 2, 3],
        ciphertext: vec![4, 5, 6],
    };
    let valid_private_mls = MlsMessage::from_private(valid_private.clone()).encode();

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        (
            "bad_version",
            {
                let mut b = valid_public_mls.clone();
                b[0] = 0x00;
                b[1] = 0x02;
                b
            },
        ),
        (
            "bad_wire_format",
            {
                let mut b = valid_private_mls.clone();
                b[2] = 0xFF;
                b
            },
        ),
        ("truncated", valid_public_mls[..valid_public_mls.len() - 1].to_vec()),
    ];

    for (name, bytes) in cases {
        assert!(MlsMessage::decode(&bytes).is_none(), "case should fail: {name}");
    }

    let mut with_trailing = valid_public_mls.clone();
    with_trailing.push(0x00);
    assert!(MlsMessage::decode(&with_trailing).is_none());

    let mut private_empty_cipher = valid_private;
    private_empty_cipher.ciphertext.clear();
    assert!(PrivateMessage::decode(&private_empty_cipher.encode()).is_none());

    let mut public_empty_membership = valid_public;
    public_empty_membership.membership_tag = Some(Vec::new());
    assert!(PublicMessage::decode(&public_empty_membership.encode()).is_none());
}

#[test]
fn proposal_encoding_vectors_match_expected() {
    let cases: Vec<(&str, Proposal, &str)> = vec![
        (
            "remove",
            Proposal::Remove { leaf_index: 5 },
            "0300000005",
        ),
        (
            "pre_shared_key",
            Proposal::PreSharedKey {
                psk_id: b"psk-01".to_vec(),
            },
            "040000000670736b2d3031",
        ),
        (
            "reinit",
            Proposal::ReInit {
                group_id: "g2".to_string(),
                version: 1,
                cipher_suite: 1,
                extensions: vec![1, 2, 3],
            },
            "050000000267320001000100000003010203",
        ),
        (
            "group_context_extensions",
            Proposal::GroupContextExtensions {
                extensions: vec![9, 8, 7],
            },
            "0600000003090807",
        ),
    ];

    for (name, proposal, expected_hex) in cases {
        let encoded = proposal.encode();
        assert_eq!(hex(&encoded), expected_hex, "vector mismatch for {name}");
        let decoded = Proposal::decode(&encoded).expect("decode vector proposal");
        assert_eq!(
            decoded.encode(),
            encoded,
            "roundtrip mismatch for {name}"
        );
    }
}

#[test]
fn transcript_confirmation_membership_vectors_and_negative_matrix() {
    let mut transcript = TranscriptState::new("matrix-group", [0x2a; 32]);
    transcript.record_proposal(b"proposal-a");
    transcript.record_proposal(b"proposal-b");
    let confirmed = transcript.predict_confirmed_after_commit(b"commit-a");

    let epoch_secret = [0x7b; 32];
    let confirmation_key = derive_confirmation_key(&epoch_secret);
    let membership_key = derive_membership_key(&epoch_secret);
    let confirmation_tag = derive_confirmation_tag(&confirmation_key, &confirmed);

    assert_eq!(
        hex32(&confirmed),
        "0a0ff0a632155be6fdfa758f047f333274607df3ffa6d31183724379a9cbb127"
    );
    assert_eq!(
        hex32(&confirmation_key),
        "e16f49569606a3315f70355cdd3194d78be2f3b44d9379f24c51fb723332dddd"
    );
    assert_eq!(
        hex32(&membership_key),
        "8484dc09923a9f4129d00ae6f66a9ed431e654777bfda29dad77fc1a23508ec6"
    );
    assert_eq!(
        hex32(&confirmation_tag),
        "3f033a50cc15a60d624c88bd9feb2137753c4554ad54b92cb864c5e987619f51"
    );

    let mut tampered_tag = confirmation_tag;
    tampered_tag[0] ^= 0x80;
    assert!(!verify_confirmation_tag(
        &confirmation_key,
        &confirmed,
        &tampered_tag
    ));
    assert!(!verify_confirmation_tag(
        &membership_key,
        &confirmed,
        &confirmation_tag
    ));
}

#[test]
fn key_schedule_transition_matrix_vectors_and_decode_guards() {
    let tree_hash = [0x55; 32];
    let mut schedule = KeyScheduleState::new("matrix-group", tree_hash);
    schedule.ensure_epoch(1, "matrix-group", tree_hash, Some(b"commit-1"));
    schedule.ensure_epoch(2, "matrix-group", tree_hash, Some(b"commit-2"));

    assert!(schedule.is_well_formed());
    assert!(schedule.is_epoch_aligned(2));
    assert_eq!(schedule.current_epoch, 2);

    let epoch_2_chain = schedule
        .chain_secrets_for_epoch(2)
        .expect("chain secrets for epoch 2");
    let epoch_2_derived = schedule
        .derive_secrets_for_epoch("matrix-group", 2)
        .expect("derived secrets for epoch 2");

    assert_eq!(
        hex32(&epoch_2_chain.commit_secret),
        "306dbeaf113be1a4661da01cfb1e3241dfccbe59d9ff40a7d0d1e2ab624b71f0"
    );
    assert_eq!(
        hex32(&epoch_2_chain.joiner_secret),
        "a48a90198cf1defd1521b0f5f4dfb82e4bab0dce925b65af94057de54485c0e5"
    );
    assert_eq!(
        hex32(&epoch_2_chain.welcome_secret),
        "d397f5e3e62adcc7b47a341e5d10ff677c35c9734d6952fa438258604e47ef13"
    );
    assert_eq!(
        hex32(&epoch_2_chain.epoch_secret),
        "372bc793e41a1b197288617d508650bfc50d6e420773079cf9c87a8bd4636b3d"
    );
    assert_eq!(
        hex32(&epoch_2_chain.root_secret),
        "5e11f3a8ff1a7b41b07d703a6365d1b5f46645344f63cd1fd79a5108f62f8ee1"
    );
    assert_eq!(
        hex32(&epoch_2_derived.handshake_secret),
        "ec33952918aa3937949a16e47aded5a2ffa8d179ca51e1f0efebb0ee3052892a"
    );
    assert_eq!(
        hex32(&epoch_2_derived.application_secret),
        "b8e8212776bf2ee44871d5cf0d168f3c2495b05cec384846de75186eb0279599"
    );
    assert_eq!(
        hex32(&epoch_2_derived.exporter_secret),
        "ec0a80503d44763493c11c8aff43bcc839d0798ed66ba6e9bc69a03129cdac89"
    );

    let encoded = schedule.encode();
    let mut tampered_epoch = encoded.clone();
    let fake_epoch = 99u64.to_be_bytes();
    tampered_epoch[1..9].copy_from_slice(&fake_epoch);
    assert!(
        KeyScheduleState::decode(&tampered_epoch).is_none(),
        "decode should reject mismatched current_epoch"
    );

    assert!(
        KeyScheduleState::decode(&encoded[..encoded.len() - 1]).is_none(),
        "decode should reject truncated payload"
    );
    assert_eq!(
        KeyScheduleState::decode(&encoded).expect("decode baseline"),
        schedule
    );
}

#[test]
fn mls_protocol_version_vector_is_stable() {
    assert_eq!(MLS_PROTOCOL_VERSION, 0x0001);
}
