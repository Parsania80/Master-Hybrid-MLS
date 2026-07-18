#![forbid(unsafe_code)]

use mls_adapter::{BaselineClient, InboundEvent};

#[test]
fn authenticated_public_state_converges_after_each_valid_commit() {
    let (mut alice, mut bob, mut charlie) = three_member_group();
    assert_converged(&[&alice, &bob, &charlie], 2, 3);

    let update = charlie.self_update().expect("Charlie must stage an update");
    deliver_commit(&mut alice, &update.commit);
    deliver_commit(&mut bob, &update.commit);
    charlie
        .merge_pending_commit()
        .expect("Charlie must merge its update");
    assert_converged(&[&alice, &bob, &charlie], 3, 3);

    let remove_bob = alice
        .remove_members_by_identity(&[b"bob".to_vec()])
        .expect("Alice must stage Bob's removal");
    deliver_commit(&mut charlie, &remove_bob.commit);
    alice
        .merge_pending_commit()
        .expect("Alice must merge Bob's removal");
    assert_converged(&[&alice, &charlie], 4, 2);
}

#[test]
fn application_messages_decrypt_for_every_valid_recipient() {
    let (mut alice, mut bob, mut charlie) = three_member_group();

    let bob_message = bob
        .create_application_message(b"message from Bob")
        .expect("Bob must encrypt an application message");
    assert_application(&mut alice, &bob_message, b"message from Bob");
    assert_application(&mut charlie, &bob_message, b"message from Bob");

    let charlie_message = charlie
        .create_application_message(b"message from Charlie")
        .expect("Charlie must encrypt an application message");
    assert_application(&mut alice, &charlie_message, b"message from Charlie");
    assert_application(&mut bob, &charlie_message, b"message from Charlie");
}

fn three_member_group() -> (BaselineClient, BaselineClient, BaselineClient) {
    let mut alice = BaselineClient::new(b"alice").expect("Alice identity must be valid");
    let mut bob = BaselineClient::new(b"bob").expect("Bob identity must be valid");
    let mut charlie = BaselineClient::new(b"charlie").expect("Charlie identity must be valid");
    alice
        .create_group(b"baseline-regression")
        .expect("group creation must succeed");

    let bob_key_package = bob.key_package().expect("Bob key package must be created");
    let add_bob = alice
        .add_members(core::slice::from_ref(bob_key_package.key_package()))
        .expect("Alice must stage Bob's add commit");
    alice
        .merge_pending_commit()
        .expect("Alice must merge Bob's add commit");
    bob.join_from_welcome(add_bob.welcome.as_deref().expect("add has welcome"))
        .expect("Bob must join from welcome");

    let charlie_key_package = charlie
        .key_package()
        .expect("Charlie key package must be created");
    let add_charlie = bob
        .add_members(core::slice::from_ref(charlie_key_package.key_package()))
        .expect("Bob must stage Charlie's add commit");
    deliver_commit(&mut alice, &add_charlie.commit);
    bob.merge_pending_commit()
        .expect("Bob must merge Charlie's add commit");
    charlie
        .join_from_welcome(add_charlie.welcome.as_deref().expect("add has welcome"))
        .expect("Charlie must join from welcome");

    (alice, bob, charlie)
}

fn deliver_commit(recipient: &mut BaselineClient, commit: &[u8]) {
    assert_eq!(
        recipient
            .process_message(commit)
            .expect("valid recipient must process commit"),
        InboundEvent::CommitMerged
    );
}

fn assert_application(recipient: &mut BaselineClient, message: &[u8], expected: &[u8]) {
    assert_eq!(
        recipient
            .process_message(message)
            .expect("valid recipient must decrypt application message"),
        InboundEvent::ApplicationMessage(expected.to_vec())
    );
}

fn assert_converged(clients: &[&BaselineClient], epoch: u64, member_count: usize) {
    let first = clients[0]
        .state()
        .expect("first member state must be available");
    assert_eq!(first.epoch, epoch);
    assert_eq!(first.member_count, member_count);
    assert!(!first.group_context.is_empty());
    assert!(!first.tree_hash.is_empty());
    for client in &clients[1..] {
        assert_eq!(
            client.state().expect("member state must be available"),
            first
        );
    }
}
