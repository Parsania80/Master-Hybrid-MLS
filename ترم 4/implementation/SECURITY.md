# Security and Research Boundary

## Status and Scope

This repository is a thesis research prototype. It contains an upstream-only baseline MLS adapter, the thesis-local `mkyber512-thesis-v1` educational reference backend, and an isolated experimental hybrid path-level delivery boundary. That boundary performs canonical KDF expansion and AES-GCM wrapping, but it is not injected into an experimental OpenMLS fork, does not generate experiment results, does not provide an author-compatible profile, and has no official vector corpus. This document defines the security claims that future work must not exceed.

`BaselineBinaryMls` is intended to exercise unmodified OpenMLS 0.8.1 with RFC 9420 ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`. It can only be described as an RFC 9420 baseline after the upstream dependency is pinned, the baseline code is implemented without a fork, and the required regression tests pass. It is not a security certification of this repository or OpenMLS.

`BinaryMlsWithMkyber` and `AdaptiveBinaryToQuaternaryMls` are non-standard experimental protocols. They are not production cryptography, are not RFC 9420 interoperable, have no end-to-end formal security proof, and must never be presented as audited or standards-compliant.

The governing design decisions are [ADR 0001](docs/adr/0001-openmls-baseline-and-experimental-fork.md) through [ADR 0005](docs/adr/0005-arity-state-extension-authentication.md). The mKyber evidence and limitations are recorded in the [implementation audit](docs/research/MKYBER-IMPLEMENTATION-AUDIT.md).

## Claim Matrix

| Property | Baseline mode | Experimental modes | Evidence required before reporting |
|---|---|---|---|
| RFC 9420 wire interoperability | Intended only when using unmodified upstream OpenMLS | No; forked UpdatePath and private-use extension are incompatible with stock implementations | Upstream baseline interoperability/regression tests |
| Standard MLS key schedule | Intended to remain upstream behavior | Unchanged for MLS itself; experimental path-secret delivery is additional | Differential baseline tests and fork-diff review |
| Post-quantum protection | No | Research hypothesis using mKyber512 | Correctness tests, independent review, and explicit limitation statement; no production claim |
| Hybrid combiner security | No new claim | No formal composition claim | A new, applicable proof and review would be required |
| Adaptive-corruption security | No new claim | Not claimed for mKyber | A proof for the exact construction would be required |
| Side-channel resistance | No repository-specific claim | Not claimed | A platform-specific audit and testing programme would be required |
| Availability / denial-of-service resistance | No repository-specific claim | Not claimed | Resource limits, fuzzing, and operational testing would be required |

## Non-standard Protocol Changes

The following changes are experimental and are enabled only outside the unchanged baseline path.

| Change | Intended behavior | Security consequence and mandatory control |
|---|---|---|
| Forked UpdatePath | Replace standard per-recipient path-secret delivery with a versioned `HybridPathCiphertext` | Stock MLS implementations cannot parse or process it. Decode, validate, derive, AEAD-open, and merge state atomically; any failure rejects the commit. |
| mKyber512 multi-recipient KEM | One common `u` and one recipient `v_i` component per recipient, behind `MultiRecipientKem` | mKyber is neither FIPS ML-KEM nor standardized MLS. The backend is reference-only and replaceable. |
| Public mKyber domain | All keys in a recipient set share a public matrix/domain | The domain must be typed, serialized by identifier, authenticated, and rejected on mismatch. It is not secret seed material. |
| Hybrid path-secret wrapper | Combine `ss_classical`, `ss_pq`, and canonical context through HKDF-SHA256; encrypt the path secret with AES-128-GCM | This is not an RFC 9420 or X-Wing construction. Key/nonce labels, canonical context, and AEAD associated data are mandatory. |
| Hybrid UpdatePath encoding | Serialize the mKyber common component once per path level and canonical recipient records | Reject malformed lengths, duplicate or unordered recipient indexes, unknown versions, and wrong node bindings before secret use. |
| `adaptive_hybrid_tree_state` extension | Carry authenticated `ArityState` in private-use extension `0xF001` | All experimental members must support it. It is authenticated state, not confidential data, and it must not carry ciphertexts. |
| Binary-to-quaternary transition | Use a quaternary tree for new secrets while the old binary tree is delivery-only `TreeCover` | Exactly one active root may derive an epoch secret. State disagreement is a commit-processing failure. |
| Measurement hooks and deterministic tests | Record byte/cost observations and use seeded deterministic test inputs | Metrics and fixtures must not expose private keys, shared secrets, path secrets, AEAD keys, raw entropy, or a seed that reconstructs private state. |

## Threat Model

The design must defend against an active network adversary that can observe, delay, reorder, drop, replay, duplicate, inject, and modify MLS protocol messages. It must also reject malformed hybrid fields and prevent honest members from silently applying different adaptive-tree state for the same commit.

The following protections are required for experimental messages:

- Verify normal MLS authentication, membership, epoch, transcript, and commit-processing requirements before accepting a hybrid state transition.
- Validate extension capability, wire version, mKyber domain identifier, component lengths, recipient ordering, node indexes, group ID, epoch, tree version, arity, mapping hash, TreeCover hash, and GroupContext hash.
- Bind the canonical `HybridKdfContext` to the hybrid KDF and AES-GCM associated data, then reject any AEAD-open, decapsulation, or context-validation failure before merging group state.
- Treat a hybrid commit as all-or-nothing: no partially decrypted path secret, partially applied tree, or partially updated `ArityState` may persist after failure.
- Use operating-system cryptographic randomness for secret keys and encapsulation outside deterministic test mode; erase temporary secrets where the implementation and selected crates permit.

The following are out of scope for the first thesis prototype and must not be implied by reports:

- endpoint compromise, malicious operating systems, backup compromise, memory disclosure, physical attacks, or side-channel resistance;
- a compromised or biased random-number generator;
- denial of service, resource exhaustion, traffic analysis, metadata hiding, or delivery-service availability;
- identity-system, credential-validation, deployment, and user-interface security beyond the selected upstream MLS behavior;
- a formal proof for the hybrid KDF, the adaptive-tree transition, or their composition with MLS;
- adaptive-corruption security for mKyber long-lived keys; and
- interoperability, certification, or production suitability of the fork or reference mKyber backend.

## Hybrid KDF and X-Wing Limitation

ADR 0003 fixes the experimental input to:

```text
IKM = ss_classical || ss_pq || TLSEncode(HybridKdfContext)
```

The serialized classical encapsulation, mKyber common `u`, and recipient `v_i` are transmitted and authenticated, but their bytes and hashes are excluded from `IKM` and the HKDF `info` input. This is a thesis requirement, not a generic hybrid-KEM recommendation.

Tasks 20 and 21 implement the typed canonical context and level-delivery boundary: version `1`, fixed label, ciphersuite `0x0001`, group ID, epoch, tree version, arity, both node indexes, mKyber domain, and authenticated GroupContext hash. For every recipient, Task 21 uses the approved HPKE provider to derive a fixed 32-byte exporter output bound to the canonical context, combines it with the recipient's mKyber shared secret, expands the ADR 0003 AES-GCM material, and opens/seals one path secret. The public KDF builder has no ciphertext parameter. These controls reduce ambiguity, but are not a forked MLS commit, an independent authentication mechanism, or a proof of security.

Task 22 adds value-free regression instrumentation at that boundary. It reads actual canonical ciphertext lengths from a `HybridPathCiphertext` and reports the serialized classical encapsulation, mKyber common, mKyber recipient, and encrypted-path-secret lengths separately, while its `*_bytes_in_kdf()` accessors are all zero. The focused test changes the common component and then the recipient component: each change alters the commit-authenticated TLS bytes, while the instrumented `IKM` remains byte-for-byte equal when the two shared secrets and canonical context are held fixed. This is implementation-level regression evidence only; it neither proves the composition secure nor weakens the unresolved SEC-03/SEC-04 limitations.

Task 23 exercises the isolated receive path with public failure categories only. Modifying the classical encapsulation, common mKyber component, recipient mKyber component, or AES-GCM path-secret ciphertext must return an error before a path secret is returned. Both intended recipients open their own records; a node with distinct private material but no recipient record is rejected. Replaying the same payload under a different group ID, epoch, tree version, or path-node index also returns an error. These tests do not establish complete MLS commit atomicity, fork correctness, denial-of-service resistance, or a cryptographic proof.

It is incorrect to claim automatic coverage by X-Wing's C2PRI result. X-Wing analyzes a different construction based on X25519, ML-KEM-768, and SHA3-256. The relevant hybrid-KEM guidance states that omitting a component KEM encapsulation key and ciphertext from a combiner KDF requires a C2PRI property. This project uses mKyber512, not ML-KEM-768, and has no cited C2PRI proof for mKyber or a proof for this MLS-specific composition. The X-Wing proof therefore does not transfer automatically. See the [X-Wing paper](https://eprint.iacr.org/2024/039.pdf) and the [CFRG hybrid-KEM draft](https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-04.html).

If a future thesis revision changes the KDF input, cipher suite, mKyber construction, or hybrid proof claim, it must first replace ADR 0003 and this section, then rerun the complete security and regression test set. No change is allowed merely to make a security claim look stronger.

## mKyber-specific Limits

mKyber512 is a research construction with parameter values distinct from standard ML-KEM. The paper's mKyber construction has a standard non-adaptive multi-user IND-CCA security statement; the paper presents amKyber as the construction with an adaptive-corruption proof. No known attack is needed to justify this limitation: the missing proof itself is sufficient reason not to make the stronger claim, especially for potentially long-lived MLS keys. See the [mKyber paper](https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/how-multi-recipient-kems.pdf).

The available mKyber paper overview is not sufficient to implement an author-compatible byte-level backend by inference: it explicitly simplifies its Kyber description, including hash/PRF and representation details. The generic mPKE FO source describes `G1`, `G2`, and `H` as random oracles rather than fixing concrete byte-level instantiations, while the Kyber Round-3 specification covers ordinary Kyber rather than mKyber's shortened message and recipient encoding. Until an author-approved profile or a compatible licensed implementation and test material are supplied, author-compatible mKyber512 interoperability is blocked; the project must not treat ordinary Kyber code as mKyber512.

The operator has authorized a paper-based educational reference implementation for the thesis. It must implement every stated paper parameter and algorithm step, while labelling any necessary concrete mapping as thesis-local. It is not recommended for business or production use and must not claim interoperability, audit status, or a formal security proof.

The future native Rust backend must never:

- substitute ML-KEM, Kyber, amKyber, or an incompatible multi-recipient variant while still calling results mKyber512;
- adapt the author-released legacy Kyber-mKEM artifact as mKyber512; its 1,280/257-byte K=2 ciphertext layout is incompatible with the target 704/48-byte layout;
- call project-generated deterministic fixtures official known-answer tests; or
- report an mKyber benchmark without stating the exact backend revision, parameter set, and whether the measurement is real serialized output.

## Interoperability and Upgrade Limits

Baseline and experimental groups are separate protocol populations. A baseline group must not negotiate extension `0xF001`, emit hybrid UpdatePath data, or accept a hybrid commit. An experimental group must require all members to support the private-use extension and the exact hybrid wire version before admission.

RFC 9420 confirms GroupContext extensions through the MLS key schedule, but a GroupContextExtensions proposal replaces the full extension list rather than merging it. Future code must preserve every required existing extension during an `ArityState` update and must reject an update that loses required capabilities. See [RFC 9420, Section 12.1.7](https://www.rfc-editor.org/rfc/rfc9420.html#section-12.1.7).

The private-use extension code can collide with another private deployment. The fork and its messages are thesis-local and must not be sent to an unrelated MLS deployment. A future interoperable protocol would require an independently specified wire format, capability negotiation, registry action where applicable, and security review.

## Secret Handling and Reporting Rules

Never place the following in source control, logs, test snapshots, CSV, JSON, Markdown reports, charts, error messages, or panic text:

- mKyber secret keys, MLS private keys, classical or PQ shared secrets, path secrets, AEAD keys, nonces derived from secret state, raw entropy, or internal PRK/IKM values;
- deterministic seeds capable of reconstructing private key material; or
- full ciphertext-plus-secret transcripts that enable retrospective decryption.

Public experiment configuration may include a non-secret reproducibility identifier only when it cannot reconstruct a private key. Tests may use deterministic private test material only in isolated fixtures that are clearly non-production and never reused for a live group. Error types should expose only category and public field metadata.

The educational reference backend exposes dedicated operating-system RNG entry points for normal key generation and encapsulation. Its deterministic RNG exists only inside its test module. Long-lived private keys and shared secrets use `ZeroizeOnDrop`; temporary entropy, seeds, decoded messages, noise polynomials, and packed secret-key bytes use scoped zeroization guards. This is best-effort memory hygiene only: it does not establish side-channel resistance, compiler-level memory-erasure guarantees, or security of hash/XOF implementation internals.

## Unresolved Thesis Assumptions and Closure Criteria

| ID | Unresolved assumption | Risk if false | Required closure before a stronger claim |
|---|---|---|---|
| SEC-01 | An exact, license-compatible mKyber512 specification or implementation can be obtained without copying unlicensed code | Incorrect reference backend, wrong encoding, or false mKyber512 claim | Authoritatively approved byte-level specification or independently auditable compatible implementation, plus versioned implementation notes and cross-implementation test material if it becomes available |
| SEC-02 | mKyber's non-adaptive multi-user security is acceptable for the thesis's MLS key lifetime | Overstated adaptive-corruption resilience | Threat-model justification or a switch to a separately reviewed adaptive construction, with new ADRs |
| SEC-03 | HKDF composition of classical and mKyber secrets is secure for this exact wire and MLS context | Hybrid secrecy or integrity claim is unsupported | Applicable formal analysis and cryptographic review; until then retain research-only wording |
| SEC-04 | Excluding ciphertext bytes from the KDF is safe for this construction | X-Wing/C2PRI claim could be wrongly inferred | A proof that covers mKyber and the exact transcript, or a redesigned combiner |
| SEC-05 | Forked UpdatePath generation and application preserve MLS invariants | Divergent trees, epoch/key mismatch, or loss of baseline behavior | Differential baseline tests, malformed-message tests, fuzzing, and a narrow fork-diff review |
| SEC-06 | Adaptive binary-to-quaternary transition has one active root and convergent `TreeCover` state | Split-brain epoch secrets or replayable transition state | Model/property tests, 128-member convergence tests, and transition replay/tamper tests |
| SEC-07 | The Rust reference mKyber implementation is correct and has acceptable implementation security | Cryptographic failure or side-channel leakage | Independent code review, test coverage, constant-time assessment, and no production claim regardless |
| SEC-08 | Deterministic experiment mode cannot leak or reconstruct live private state | Reproducibility data compromises confidentiality | Explicit entropy separation, fixture review, and redaction tests |
| SEC-09 | Resource bounds are adequate for malformed or large recipient sets | Denial of service or memory exhaustion | Input limits, allocation review, fuzzing, and load testing |
| SEC-10 | Measurements accurately distinguish real serialized costs from estimates | Invalid thesis conclusions | Codec-bound instrumentation, provenance fields, and reproducibility review |

## Minimum Security Gates Before Experiments

No experimental benchmark may be described as a successful security evaluation until all of the following are true:

1. The Cargo workspace, approved dependencies, and OpenMLS pins are recorded and reproducible.
2. Baseline RFC 9420 behavior passes independently from the experimental fork.
3. Hybrid codec, KDF, tamper, replay, recipient/non-recipient, and context-mismatch tests pass.
4. Adaptive transition convergence and single-active-root invariants pass under multi-committer workloads.
5. Output redaction tests verify that reports contain no prohibited secret material.
6. The report labels every result as experimental, identifies unresolved assumptions SEC-01 through SEC-10, and distinguishes measurements from security proofs.
