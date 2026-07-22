# ADR 0037: Deterministic mKyber Parent-Key Derivation

**Status:** Accepted on 2026-07-22  
**Decision scope:** Matched experimental mKyber material for KeyPackage leaves and binary TreeKEM parents

## Context

A new leaf can safely receive fresh operating-system-random mKyber material:
its public key is carried in the signed KeyPackage extension and its matching
private key is persisted in the KeyPackage bundle. A parent node is different.
Every recipient that decrypts a binary TreeKEM UpdatePath must derive identical
parent private state from the same MLS `PathSecret`. Generating a parent mKyber
pair with operating-system randomness would leave only the committer with the
private key and break TreeSync convergence.

## Decision

1. `EncryptionKeyPair` carries optional matched public and private
   domain-bound mKyber material. The private value has an exact fixed-size
   representation, strict deserialization, redacted debug output, and
   zeroization on drop.
2. `KeyPackageBuilder::build_with_experimental_mkyber` creates an OS-random
   leaf pair, binds its exact public key to the signed `0xF002` extension, and
   ensures the leaf advertises both `0xF001` and `0xF002`. Caller-supplied
   capabilities are retained; a duplicate `0xF002` extension fails.
3. Each parent pair derives deterministically from its ordinary MLS
   `PathSecret` using MLS `ExpandWithLabel` with label
   `"mKyber TreeKEM node"`, context `domain[32] || parent_node_index_u32_be`,
   and a 32-byte output. That output seeds the educational mKyber backend's
   local ChaCha20 DRBG key generation. The MLS secret schedule itself is not
   changed.
4. Receiver derivation uses the authenticated incoming UpdatePath leaf's bound
   domain and compares the complete `EncryptionKey`, including optional mKyber
   public material, before accepting a derived parent path.
5. The deterministic seed is secret protocol state. It is never a public
   experiment seed, report field, artifact, or caller-provided random value.

## Consequences

- The signed KeyPackage public key, stored leaf private key, sender parent
  public key, and receiver-derived parent private key have an explicit matched
  construction.
- The ordinary non-experimental fork path stays unchanged when no mKyber domain
  is present.
- This does not yet replace the HPKE UpdatePath payload, stage hybrid private
  material atomically, or make an experimental Commit executable. Gate 57.5
  and Gate 57.6 remain required before measurements may become numeric.

## Verification Criteria

- A generated experimental KeyPackage's `0xF002` public key equals its leaf
  `EncryptionKey` mKyber public key and decapsulates with its persisted bundle
  private key.
- Sender and receiver binary parent derivation agree for each affected parent
  path index and reject an `EncryptionKey` mismatch.
- Existing baseline behavior, format, strict lint, and locked-offline adapter
  tests remain passing.
