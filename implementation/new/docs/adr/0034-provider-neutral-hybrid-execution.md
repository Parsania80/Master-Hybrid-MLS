# ADR 0034: Provider-Neutral Hybrid Path Execution

**Status:** Accepted on 2026-07-22
**Decision scope:** Executing the existing hybrid sender/receiver construction with fork-local OpenMLS traits

## Context

The canonical hybrid wire, KDF, mKyber, and AEAD construction already exists in
`hybrid-path-secret`, but its classical HPKE steps previously created the
crates.io `OpenMlsRustCrypto` provider directly. That made the complete sender
and receiver engine unusable from `openmls-hybrid`, whose trait and provider
packages have distinct identities.

The hybrid construction needs only fixed-size classical public/private key
wrappers, an HPKE encapsulation, and a 32-byte exporter output. It does not
need an upstream OpenMLS type in its public execution boundary.

## Decision

1. Add `ClassicalHpkeProvider` to `hybrid-path-secret`. Its inputs and outputs
   are fixed-size byte wrappers and redacted secret wrappers only. It does not
   expose an OpenMLS trait, provider, ciphertext type, or private path secret.
2. Preserve `seal_hybrid_path_level` and `open_hybrid_path_level` for existing
   callers using `UpstreamClassicalHpkeProvider`. Add parallel explicit-provider
   entry points for fork use.
3. Implement `ForkClassicalHpkeProvider` inside `openmls-hybrid` with the
   fork's local `OpenMlsRustCrypto`, local traits, and the fixed MLS 128/X25519
   HPKE configuration. It produces exactly the same 32-byte exporter boundary.
4. Verify the fork-local provider end-to-end: one mKyber recipient receives and
   opens a full hybrid path-level ciphertext using the fork provider, while the
   existing upstream hybrid suite remains unchanged.
5. Do not insert this engine into TreeSync yet. A TreeKEM copath resolution can
   be a parent node, while ADR 0032 currently provides mKyber public material
   only through leaf KeyPackages. A future node-key design must bind matching
   public/secret mKyber material to every resolution node before encryption or
   decryption can be correct.

## Consequences

- The type-universe boundary is removed for the hybrid execution primitive,
  without merging or patching the unchanged baseline OpenMLS package.
- Existing callers retain their default behavior; only explicit fork calls use
  the local provider implementation.
- The next safe work is node-scoped mKyber key material and lifecycle storage,
  followed by an atomic experimental UpdatePath sender/receiver replacement.
- This does not authenticate a live Commit, mutate TreeSync, validate live
  GroupContext state, or make Task 57 experimental measurements available.

## Verification Criteria

- The existing hybrid suite passes with its preserved default provider.
- An isolated adapter test seals and opens a hybrid level through the fork
  provider with no upstream OpenMLS provider passed into the fork.
- Strict Clippy, formatting, unchanged baseline regression, and diff checks
  pass on the locked offline graph.
