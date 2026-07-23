# ADR 0035: Node-Scoped mKyber Key Material Lifecycle

**Status:** Accepted on 2026-07-22
**Decision scope:** Experimental binary TreeKEM leaf and parent mKyber key material before TreeSync integration

## Context

ADR 0032 authenticates a recipient's mKyber public key through its signed
KeyPackage. That is sufficient only for a leaf. A TreeKEM UpdatePath may
encrypt to any resolution node, including a parent node that has no KeyPackage.
Using an arbitrary descendant leaf key for such a parent would make the
recipient set and local decapsulation state disagree.

Before experimental UpdatePath delivery can replace the standard path-secret
vector, the fork therefore needs one matching mKyber public/private pair per
binary TreeKEM resolution node. Public material must have a deterministic,
strict encoding suitable for authenticated future tree state. Private material
must remain local, must not be debug-printed, and must be retired with its
matching tree node.

## Decision

1. Introduce `ExperimentalResolutionNodeId`, a public wrapper around the
   TreeKEM tree-array node index. It identifies both leaves and parents without
   treating a parent as a KeyPackage-bearing member.
2. Represent a node's public material as
   `ExperimentalMkyberNodePublicKey`. Its exact version-1 encoding is
   `domain[32] || encapsulation_key[768]` (800 bytes). Parsing accepts exactly
   that length and reconstructs only a domain-bound typed mKyber public key.
3. Introduce `ExperimentalMkyberNodeKeyStore` as the initial local private
   lifecycle boundary. Generating a node pair returns only the public value;
   the matching decapsulation key is retained by node ID, redacted from debug
   output, zeroized when retired or dropped, and cannot silently overwrite a
   live record.
4. Keep the public and private layers separate. The public value is now an
   optional field in feature-gated `EncryptionKey`, so it is carried by the
   existing `LeafNode`, `ParentNode`, ratchet-tree, and UpdatePath public
   serialization. A future experimental validator must require `Some` for
   every resolution node before hybrid delivery is enabled.
5. Do not yet alter the private `EncryptionKeyPair`, KeyPackage bundle,
   storage-provider lifecycle, `UpdatePath` delivery, or Commit application.
   Those changes must be made together so no accepted experimental tree can
   contain a public node key without matching staged private material.

## Consequences

- Parent resolution nodes now have a correct, independent mKyber key-pair
  representation instead of an unsafe leaf-key shortcut.
- The new fixed 800-byte public encoding is not the signed KeyPackage
  extension encoding from ADR 0032: it has no extension version field because
  it is a node-state value governed by this ADR's version-1 shape.
- The isolated store is not persistent storage and cannot by itself make an
  experimental MLS Commit valid. Gate 57.4 remains incomplete until matching
  private material is bound to fork node generation, storage, replacement, and
  removal.
- No hybrid UpdatePath, atomic state application, adaptive transition, or
  numeric Task 57 experimental result becomes available through this ADR.

## Verification Criteria

- Leaf and parent IDs can each generate independent node pairs.
- A canonical public node key round-trips exactly; malformed-length input is
  rejected.
- A ciphertext addressed to the serialized parent public key decapsulates only
  through its matching locally retained parent private key.
- Retiring a parent record removes its private material while retaining the
  unrelated leaf record.
- Formatting, strict lint, fork-adapter tests, unchanged baseline regression,
  and diff checks pass on the locked offline graph.
