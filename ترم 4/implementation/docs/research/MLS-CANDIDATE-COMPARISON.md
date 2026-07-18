# Rust MLS Candidate Comparison

## Scope and Status

This document completes Part 1, Task 2 of the thesis roadmap. It compares the maintained Rust MLS candidates at their public API and source-module boundaries to identify the least invasive locations for:

- preserving an unchanged normal binary MLS baseline;
- carrying authenticated experimental transition metadata;
- serializing experimental `HybridPathCiphertext` values inside each TreeKEM UpdatePath level; and
- measuring exact wire size and cryptographic work.

This is research evidence, not an architecture decision record. It does not approve a dependency, a ciphersuite, an extension code point, an mKyber implementation, or an experimental wire format.

## Audited Snapshots

| Candidate | Audited package version | Source snapshot | License | Public project position |
|---|---:|---|---|---|
| [OpenMLS](https://github.com/openmls/openmls) | `openmls` 0.8.1 | `65396d8ed3121506d1b9c7d0e6ec9fce1bed486d` on 2026-07-16 | MIT | Maintained RFC 9420 Rust implementation with supported binary-tree ciphersuites. |
| [`mls-rs`](https://github.com/awslabs/mls-rs) | `mls-rs` 0.55.2 | `42131c9959efb1d3928428259bc89853027f730d` on 2026-06-17 | Apache-2.0 OR MIT | Maintained RFC 9420 Rust implementation with configurable storage, crypto providers, custom proposals, and extensions. |

The package versions were read from the cloned workspaces through `cargo metadata --no-deps`; neither library was built, modified, nor added to this thesis workspace.

## Source-Level Findings

### OpenMLS

- The public `MlsGroup::commit_builder()` API provides Add, Remove, GroupContextExtensions, proposal-store, self-update, and group-info controls in `openmls/src/group/mls_group/commit_builder.rs`.
- `MlsGroup::process_message()` and `MlsGroup::merge_pending_commit()` are public receive/apply seams in `openmls/src/group/mls_group/processing.rs`.
- `UpdatePathNode` owns the classical public key and `Vec<HpkeCiphertext>`, but its fields are `pub(super)`. `UpdatePath::new`, node accessors, TreeSync path generation, path encryption, and path application are crate-private in `openmls/src/treesync/treekem.rs`, `node/parent_node.rs`, and `diff.rs`.
- `PlainUpdatePathNode::encrypt()` is the narrow send-side seam: it receives the path secret, recipient public keys, ciphersuite, and group context before producing the ciphertext vector.
- `TreeSyncDiff::apply_received_update_path()` and TreeKEM path decryption are the corresponding receive-side seams.
- TLS codec derives own the wire encoding. Complete commit bytes can be measured from the returned `MlsMessageOut` with `tls_serialize_detached()`.

### mls-rs

- The public `Group::commit_builder()` supports Add, Remove, custom proposals, authenticated data, and `set_group_context_ext()` in `mls-rs/src/group/commit.rs`.
- `UpdatePathNode` and `UpdatePath` are public and derive `MlsSize`, `MlsEncode`, and `MlsDecode` in `mls-rs/src/tree_kem/update_path.rs`; the node directly contains `public_key` and `Vec<HpkeCiphertext>`.
- Despite the public wire structures, the actual TreeKEM update-path validation, generation, and application remain crate-private across `tree_kem`, `group/message_processor.rs`, and `group/mod.rs`. `Group::commit_internal()` is also `pub(super)`.
- Complete outgoing commit bytes are available through `MlsMessage::to_bytes()`.
- The project supports custom extensions and custom proposals, but those hooks do not expose a supported way to substitute TreeKEM’s per-recipient HPKE ciphertext processing.

## Seam Comparison

| Concern | OpenMLS seam | mls-rs seam | Thesis consequence |
|---|---|---|---|
| Unchanged baseline | Upstream `MlsGroup` public API and its normal UpdatePath implementation | Upstream `Group` public API and its normal UpdatePath implementation | Either can supply the standard baseline with no experimental code enabled. |
| Commit construction | Public typed `CommitBuilder` | Public typed asynchronous `CommitBuilder` | Both support valid multi-committer Add, Remove, Update, and commit workflows. |
| Transition metadata | Public GroupContextExtensions proposal API | Public `set_group_context_ext()` API | Use a negotiated experimental group-context extension for canonical `ArityState`, leaf-map hash, and TreeCover version. |
| Hybrid UpdatePath wire | `UpdatePathNode` field and codec changes within `treesync` | `UpdatePathNode` codec changes within `tree_kem` | A fork is mandatory in both cases because the thesis ciphertext must be in UpdatePath, not beside it. |
| Hybrid send path | `PlainUpdatePathNode::encrypt()` | Internal TreeKEM path creation | Replace or branch only the experimental encryption path. |
| Hybrid receive path | TreeSync UpdatePath decryption/application | Internal message processor and TreeKEM application | Decode, authenticate, decapsulate, derive, decrypt, and reject atomically before committing state. |
| Full commit size | `MlsMessageOut::tls_serialize_detached()` | `MlsMessage::to_bytes()` | Measure real serialized bytes at the outer message boundary. |
| Component sizes | TLS codec serialization of forked wire types plus counters around the experimental path function | `MlsEncode`/`MlsSize` of forked wire types plus counters around internal TreeKEM functions | Record actual component bytes; never use simulated constants when serialization is available. |
| Cryptographic counts and timings | Instrument the experimental path function and, if needed, an OpenMLS crypto-provider wrapper | Instrument the experimental TreeKEM path and, if needed, a cipher-suite-provider wrapper | Count individual classical and mKyber operations without logging secret material. |

## Required Boundary

The least invasive safe structure is two independently testable dependency paths:

1. `openmls` remains a version-pinned upstream dependency for `BaselineBinaryMls`.
2. A renamed, version-pinned `openmls-hybrid` fork supplies only `BinaryMlsWithMkyber` and `AdaptiveBinaryToQuaternaryMls`.
3. The fork changes only the experimental UpdatePath node/wire codec, send-side path encryption, receive-side path decryption/application, and narrowly scoped measurement hooks. Its public group lifecycle stays as close as possible to upstream.
4. `mls-adapter` selects baseline or experimental implementation behind a project-owned trait. Tests run the baseline directly against upstream and never through a global `[patch.crates-io]` replacement.

This boundary is a preliminary recommendation, not an adopted ADR. It favors OpenMLS because the source separates public `MlsGroup` lifecycle code from `treesync` UpdatePath mechanics more clearly. `mls-rs` makes the wire structs public, but the construction and application paths still cross internal async group and TreeKEM code, so it does not eliminate the fork or reduce the experimental security boundary.

## Extension and Authentication Policy

`ArityState` belongs in a negotiated experimental GroupContext extension because its values must converge for all members and bind to group state. It must encode or commit to at least current/candidate arity, transition state, tree version, threshold configuration identifier, deterministic leaf-mapping hash, and TreeCover version.

That extension is not a substitute for `HybridPathCiphertext`. The thesis explicitly requires each mKyber common component and recipient component to travel in the corresponding UpdatePath level. A detached sidecar message would create a different protocol, weaken the intended commit/update-path binding, and violate the stated requirement. The forked wire data remains authenticated by the experimental Commit framing, making that mode non-interoperable with RFC 9420 implementations.

## Instrumentation Policy

- Measure `total_commit_bytes` by serializing the outgoing commit once at the adapter boundary.
- Measure UpdatePath and component bytes from the same canonical codec that sends the message.
- Start timing immediately around experimental classical encapsulation, mKyber encapsulation/decapsulation, hybrid KDF, and AEAD operations; store only counts and durations.
- Capture topology and recipient-resolution data in the forked TreeKEM seam, where the actual recipient public-key set is known.
- Never log shared secrets, path secrets, private keys, AEAD keys, raw randomness, or serializations containing them.

## Items Deliberately Deferred

- Pinning the upstream OpenMLS release and fork revision in the thesis workspace.
- Choosing an experimental extension code point and canonical `ArityState` encoding.
- Auditing mKyber implementations and choosing a backend.
- Implementing the hybrid KDF, AEAD construction, path wire format, or adaptive quaternary tree.
- A build/test compatibility spike against the selected release and fork.

Those decisions belong to Tasks 3 and 4. The preliminary recommendation must be revisited if the mKyber audit or the compatibility spike reveals a blocking constraint.
