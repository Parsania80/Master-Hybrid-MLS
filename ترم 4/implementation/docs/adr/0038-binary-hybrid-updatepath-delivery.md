# ADR 0038: Binary Hybrid UpdatePath Delivery

**Status:** Accepted on 2026-07-22  
**Decision scope:** Feature-gated binary TreeKEM sender/receiver delivery

## Decision

When an experimental parent `EncryptionKey` carries bound mKyber material,
the fork replaces that node's ordinary per-recipient HPKE path-secret vector
with one canonical hybrid delivery value. The sender builds records from the
exact indexed co-path resolution, uses the matched classical and mKyber public
keys, and binds the delivery to the authenticated serialized GroupContext,
binary arity, tree version zero, parent tree-array index, recipient tree-array
index, and mKyber domain.

The receiver rejects a hybrid node with a missing mKyber public key or a
non-empty classical vector, rejects an mKyber parent node without hybrid
delivery, validates exact canonical delivery bytes and parent index, rebuilds
the same context, and opens only the record for its matching resolution-node
private pair. It then passes the recovered ordinary MLS `PathSecret` to the
existing parent derivation and complete-key comparison logic.

Nodes without experimental mKyber material retain the ordinary RFC 9420
delivery path inside the fork. The hybrid code supports only the fixed
MLS-128/X25519 experimental profile and fails closed for another ciphersuite.

## Limits

This is an internal feature-gated fork wire change, not RFC 9420
interoperability. It does not yet provide experimental-member admission across
all group builders, authenticated nonzero ArityState/tree-version handling,
atomic storage replacement/removal, or rejection coverage for recipients,
non-recipients, tampering, replay, malformed wire data, and capabilities.

The adapter now proves one real two-member accepted-Commit round-trip: Alice
creates an experimental group, adds Bob from a signed experimental KeyPackage,
Bob joins through a Welcome, and Bob's serialized hybrid self-update is
processed and merged by Alice before both members merge to matching epoch,
ratchet-tree, and GroupContext state. Atomic storage replacement/removal and
failure non-mutation remain Gate 57.6 work.
