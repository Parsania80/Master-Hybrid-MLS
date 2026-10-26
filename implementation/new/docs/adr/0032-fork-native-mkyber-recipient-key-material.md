# ADR 0032: Fork-Native mKyber Recipient Capability and Key Material

**Status:** Accepted on 2026-07-22
**Decision scope:** Experimental KeyPackage capability advertisement and public mKyber recipient key material

## Context

ADR 0031 requires a fork-native seam before replacing `UpdatePath` delivery. A
future sender must obtain each experimental recipient's public mKyber
encapsulation key from authenticated MLS input, rather than an unbound side
table or a local configuration file. RFC 9420 KeyPackages carry signed
extensions, and OpenMLS validates that a KeyPackage extension is advertised by
the LeafNode capabilities. This is the appropriate public bootstrap location;
it neither transports ciphertexts nor replaces a path-secret delivery node.

ADR 0005 already reserves private-use extension `0xF001` for the authenticated
adaptive `ArityState`. It requires every experimental member to advertise
support for that extension before admission. A distinct private-use extension
is needed for public mKyber recipient material so a parser cannot confuse tree
state with a recipient key.

## Decision

1. Reserve `0xF002` exclusively in this thesis fork as the
   `mkyber_recipient_key_package` extension. It is a KeyPackage extension,
   never a GroupContext extension, and is not a standards or interoperability
   claim.
2. Version-1 extension values are exactly 802 bytes:
   `uint16_be(version = 1) || domain[32] || mkyber512_encapsulation_key[768]`.
   The fork rejects a missing value, any other length, unsupported versions,
   and malformed typed public key material. It accepts no trailing bytes or
   alternative encodings.
3. An experimental mKyber recipient must advertise both `0xF001` and `0xF002`
   in LeafNode capabilities. The fork provides a default capability constructor
   and verifies those capabilities before exposing recipient material from a
   KeyPackage.
4. The implementation is feature-gated in `openmls-hybrid::experimental_hybrid`
   and uses the existing thesis-local `mkyber` crate only for its public
   `MkyberDomain`/`MkyberEncapsulationKey` types. It holds no mKyber secret,
   no shared secret, and no randomness.
5. This step does not change `UpdatePathNode`, GroupContext extension
   validation, sender/receiver cryptography, tree mutation, or Task 57
   availability. A future atomic fork path must consume this authenticated
   KeyPackage material only after the normal KeyPackage signature and MLS
   validation succeed.

## Consequences

- Experimental member admission now has a canonical, signed source for one
  recipient's public mKyber key and an explicit capability gate.
- Baseline `openmls` and `mls-adapter` stay unchanged. A baseline KeyPackage
  never gains this private-use extension through the fork dependency.
- `0xF001` remains the only location for adaptive public state; `0xF002` never
  carries `ArityState`, hybrid ciphertexts, path secrets, or private keys.
- Future UpdatePath work must reject members lacking either capability and
  must retain the fixed extension bytes within the already authenticated
  KeyPackage/Commit lifecycle, not copy them into a sidecar.

## Verification Criteria

- A known public domain/key pair round-trips through the strict extension
  encoding.
- Wrong version and non-exact-length extension values are rejected.
- Default capabilities do not satisfy the experimental gate, while the fork's
  experimental capability constructor advertises both private-use types.
- The isolated adapter tests, strict Clippy, and unchanged baseline regression
  remain green with the locked offline graph.
