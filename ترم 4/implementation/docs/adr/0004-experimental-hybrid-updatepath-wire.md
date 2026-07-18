# ADR 0004: Use a Versioned Hybrid UpdatePath Encoding Inside Experimental Commits

**Status:** Accepted on 2026-07-18
**Decision scope:** Experimental wire encoding and serialization

## Context

The thesis requires a classical encapsulation, one mKyber common component, one mKyber recipient component per recipient, a hybrid-encrypted path secret, and node binding within the corresponding UpdatePath level. The candidate comparison established that an extension or detached sidecar cannot meet that requirement.

RFC 9420 uses TLS Presentation Language-style encodings for MLS data, while HPKE itself requires the application to specify an unambiguous encoding of its encapsulation and ciphertext values. See [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420) and [RFC 9180, Section 10](https://www.rfc-editor.org/rfc/rfc9180.html#section-10).

## Decision

1. The experimental OpenMLS fork defines a version-1 `HybridPathCiphertext` value in the UpdatePath node, encoded with its TLS codec and never accepted by baseline mode.
2. The value is a set, not a copy-per-recipient blob: it carries once the wire version, path-node index, mKyber domain ID, and mKyber common `u`; it then carries a canonical vector of recipient records.
3. Each recipient record carries the recipient-node index, the classical HPKE KEM encapsulation output, its mKyber recipient component `v_i`, and the AES-128-GCM encrypted path secret. No shared secret, private key, raw randomness, or experiment seed is serialized.
4. Recipient records are strictly increasing by recipient-node index. Decoders reject duplicate, missing, out-of-range, non-canonical, oversized, or wrong-version fields before any secret derivation. The codec checks the mKyber backend's exact common and recipient component lengths.
5. The experimental commit's MLS authenticated content covers the complete encoded UpdatePath. The hybrid AEAD independently authenticates the canonical context. Both checks must succeed before state changes are merged.
6. Outer-message byte measurements use the same codec that transmits the commit. Reports separately record common-component bytes once per path node, recipient-component bytes per record, and complete serialized commit bytes.

## Consequences

- The common `u` is sent once per UpdatePath level, preserving the multi-recipient measurement objective.
- The wire is intentionally non-interoperable with stock RFC 9420 implementations and must be capability-gated by ADR 0005.
- Canonical ordering and early rejection make recipient selection and byte accounting deterministic.

## Rejected Alternatives

| Alternative | Reason rejected |
|---|---|
| Repeat common `u` in every recipient record | It destroys the intended shared-component cost measurement. |
| Put the hybrid ciphertext in an application message or sidecar | It fails to bind the delivery to the UpdatePath level required by the thesis. |
| Use ad-hoc JSON/CBOR encoding | It would not share MLS's canonical serialization and measurement boundary. |
| Serialize an mKyber shared secret or seed | It violates the security boundary and would make reports/fixtures hazardous. |

## Verification Criteria

- Round-trip, malformed-input, ordering, duplicate-index, and component-size tests exercise the exact codec.
- A serialized outer commit contains one common `u` per hybrid path level and exactly one `v_i` per intended recipient record.
- Baseline decoding rejects experimental hybrid nodes, and experimental decoding rejects baseline-incompatible hybrid versions.
