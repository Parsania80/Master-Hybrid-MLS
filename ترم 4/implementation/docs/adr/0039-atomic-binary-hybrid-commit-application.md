# ADR 0039: Atomic Binary Hybrid Commit Application

**Status:** Accepted on 2026-07-22  
**Decision scope:** Feature-gated binary hybrid Commit merge and storage publication

## Context

The inherited OpenMLS merge path mutates the live `MlsGroup` while issuing
independent storage writes for group state, TreeSync, GroupContext, transcript
and confirmation data, epoch/message secrets, epoch keypairs, proposal queues,
resumption PSKs, own leaf records, and pending state. A storage error after an
earlier write can therefore expose a partially advanced epoch. The generic
`StorageProvider` contract has no transaction or rollback primitive.

The hybrid path also requires private mKyber material to move with its complete
classical `EncryptionKeyPair`. Applying public TreeSync state without the
matching new epoch keypair set would make the accepted Commit unusable after a
restart.

## Decision

1. Add a separate `TransactionalStorageProvider` capability to the fork-local
   traits crate. It creates an isolated storage snapshot and atomically
   publishes that snapshot. Existing `StorageProvider` implementations do not
   receive an implicit or false atomicity guarantee.
2. Implement that capability for the fork's `MemoryStorage` by cloning its
   complete key/value map and replacing the live map under one write lock only
   after every staged operation succeeds. Other storage backends must provide
   equivalent semantics before they can use the experimental atomic API.
3. Refactor the internal merge implementation to accept a storage object
   directly. The ordinary public merge methods keep their inherited behavior;
   the isolated baseline and non-experimental API are unchanged.
4. Add explicit experimental atomic methods for receiver-side `StagedCommit`
   and sender-side pending Commit application. Each method loads a candidate
   group from the transaction snapshot, preserves ephemeral AAD, performs the
   complete merge against the snapshot, commits storage, and replaces the live
   in-memory group only after publication succeeds.
5. Require the authenticated GroupContext to contain the canonical `0xF001`
   `ArityState` before and after the merge. Task 58 accepts only lifecycle
   `Normal`, active arity 2, candidate arity 4, and tree version 0. Missing,
   malformed, transitioning, or quaternary state fails before publication;
   Task 60 owns transition semantics.
6. Ensure an experimental creator leaf advertises both `0xF001` and `0xF002`.
   Once normal `ArityState` is actually present in GroupContext, omitting the
   matching leaf capability is correctly rejected by OpenMLS extension
   validation.

## Failure Semantics

- A validation error, staged write/delete error, or failed atomic publication
  leaves the live `MlsGroup` and original storage snapshot unchanged.
- A successful publication installs TreeSync/public group state, epoch and
  message secrets, complete matched epoch keypairs, proposal/resumption state,
  own leaf cleanup, and pending-state cleanup together.
- The in-memory backend provides process-local atomic visibility. It does not
  claim durable crash recovery; a future filesystem/database backend must
  implement its own transactional durability and tests.
- Message decryption ratchet advancement performed before a caller obtains a
  `StagedCommit` remains outside this merge transaction. The experimental
  workload must retain the inspected-staged-Commit API boundary.

## Verification Criteria

- A real three-member group adds and joins an experimental member, applies a
  later hybrid self-update at all members, converges on epoch/tree/extensions,
  and reloads the same state from each provider.
- Receiver-side and sender-side control merges report the number of staged
  storage mutations.
- Fault injection fails each zero-based mutation in both paths. Every failure
  preserves epoch, ratchet tree, authenticated extensions, pending state where
  applicable, the exact storage map, and reload consistency.
- Locked/offline formatting, strict Clippy, adapter tests, and unchanged
  upstream baseline regressions pass.

## Remaining Work

This decision completes Task 58 for the in-memory experimental provider. It
does not expose a repeatable binary workload, produce numeric experimental
metrics, implement an adaptive transition, or make a durability claim for the
unused SQL storage backends. Those outcomes remain Tasks 59 and later.
