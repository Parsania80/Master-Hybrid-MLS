# ADR 0036: Experimental Node Private Storage Design

**Status:** Accepted on 2026-07-22
**Decision scope:** Persisting matching mKyber private material after ADR 0035 public TreeSync binding

## Context

ADR 0035 now attaches optional experimental mKyber public material to the
fork's `EncryptionKey`. Since that type is carried by `LeafNode`, `ParentNode`,
the ratchet tree, and UpdatePath nodes, a bound public key survives the existing
TLS public-state serialization.

OpenMLS already persists a complete `EncryptionKeyPair` for standalone leaf
updates and for each member's epoch keypairs. The storage provider keys those
records by the complete public `EncryptionKey` and serializes the complete pair
as one entity. A separate node-index database would be wrong: tree indices can
move or disappear, while the matching public key is the stable lookup value
used by the current private-key lifecycle.

## Decision

1. Extend feature-gated `EncryptionPrivateKey` with optional, redacted mKyber
   private material and extend `EncryptionKeyPair` only as the matched public
   and private envelope. A pair must contain either both experimental public
   and private fields or neither; hybrid processing will reject `None`.
2. Represent the private mKyber value as its domain plus exact backend private
   bytes. It must have manual serialization validation, redacted debug output,
   and zeroization on retirement/drop. It must not expose raw bytes through a
   public API.
3. Reuse existing `write_encryption_key_pair`, epoch-keypair write/read/delete,
   and KeyPackage bundle persistence. No `StorageProvider` method or external
   database is added. The full `EncryptionKeyPair` becomes the one persistent
   unit for its classical and mKyber material.
4. Replace the temporary `ExperimentalMkyberNodeKeyStore` only when a pair is
   created and staged together with its public leaf/parent node. The node-ID
   store remains a test/assembly boundary, not durable state.
5. Do not generate mKyber material from an implicit default domain. A future
   experimental group constructor must supply the authenticated experimental
   domain and create matching leaf KeyPackage extension and `EncryptionKey`
   material in the same operation.
6. Do not claim storage-backend atomicity. Gate 57.6 must stage TreeSync,
   private pairs, and authenticated ArityState before observable group mutation
   and must test failure non-mutation.

## Consequences

- Existing private-key storage locations remain the single source of truth.
- The public-key serialization change is usable for testable TreeSync state,
  but it does not make an ordinary fork tree a valid hybrid tree: `None` is
  still permitted until experimental validation and pair generation arrive.
- ADR 0037 implements KeyPackage creation and parent-path derivation. Pair
  replacement, deletion, and staged-commit persistence remain the next coupled
  implementation scope.
- No hybrid UpdatePath ciphertext, Commit acceptance, adaptive transition, or
  Task 57 experimental metric is available through this decision.

## Verification Criteria

- A pair containing experimental material serializes, reloads, and decapsulates
  only with its matched public key.
- Existing pair write/read/delete and epoch-keypair lifecycle tests prove the
  mKyber private field follows the same replacement and retirement path.
- A generated experimental KeyPackage has matching `0xF002` and leaf
  `EncryptionKey` public values.
- Parent-path generation creates matching public/private pairs for each parent
  resolution node, with no fallback leaf key.
- Failed staged application leaves both public TreeSync state and private
  storage unchanged.
