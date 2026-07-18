# ADR 0003: Pin the Level-I MLS Ciphersuite and Define the Hybrid KDF

**Status:** Accepted on 2026-07-18
**Decision scope:** Classical ciphersuite, hybrid KDF, and experimental AEAD

## Context

The mKyber512 paper targets NIST security level I. RFC 9420 defines `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` as its mandatory-to-implement ciphersuite, and OpenMLS 0.8.1 supports it. The selected suite uses DHKEM(X25519, HKDF-SHA256), SHA-256, and AES-128-GCM; see [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420) and the [OpenMLS supported-suite list](https://docs.rs/openmls/0.8.1/openmls/ciphersuite/enum.Ciphersuite.html).

The thesis requires `ss_classical || ss_pq || domain_separation_context` as the hybrid KDF input, while requiring PQ ciphertext bytes to be transmitted and authenticated but excluded from that input.

## Decision

1. Support only ciphersuite `0x0001`, `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, in the first research implementation. The baseline MLS key schedule remains OpenMLS's normal ciphersuite behavior.
2. The experimental hybrid path-secret wrapper uses HKDF-SHA256 and AES-128-GCM. It does not alter the RFC 9420 MLS key schedule; it only protects the experimental per-recipient path-secret delivery.
3. Encode a versioned `HybridKdfContext` canonically with the same TLS codec used for the experimental wire format. It contains: protocol version, ASCII label `Adaptive-Hybrid-TreeKEM-PathSecret-v1`, ciphersuite ID, group ID, epoch, tree version, current arity, path-node index, recipient-node index, mKyber domain ID, and the 32-byte authenticated GroupContext hash.
4. After both recipient-specific secrets are obtained, form exactly `IKM = ss_classical || ss_pq || TLSEncode(HybridKdfContext)`. Both shared-secret lengths must be fixed by their selected algorithms and validated before concatenation.
5. Set `PRK = HKDF-Extract(zeros(32), IKM)`. Derive a 16-byte AEAD key and a 12-byte nonce with independent ASCII suffixes `.../aead-key` and `.../aead-nonce`, each followed by the same canonical context in the HKDF-Expand `info` input. Encrypt the MLS path secret with AES-128-GCM.
6. Use `TLSEncode(HybridKdfContext || wire_version)` as AES-GCM associated data. Never use ciphertext bytes, raw secret values, or a reproducible experiment seed as context fields.
7. The mKyber common `u`, recipient `v_i`, and classical encapsulation bytes are wire data and AEAD/commit authenticated, but their raw bytes and hashes are excluded from `IKM` and HKDF `info`; only the already-listed stable identifiers in the canonical context are used.

HKDF Extract and Expand are used as specified in [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html). The classical encapsulation/decapsulation behavior follows HPKE's explicit KEM shared-secret model, not a new HPKE algorithm; see [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html).

## Consequences

- All first-phase measurements use one classical security level and one hash/AEAD family, making baseline and experimental results comparable.
- The hybrid wrapper has unambiguous inputs, distinct key/nonce derivations, replay binding to MLS and tree state, and no dependence on the serialized ciphertext bytes.
- This construction is experimental. Neither the KDF composition nor the ciphertext exclusion inherits an X-Wing proof or RFC 9420 interoperability claim.

## Rejected Alternatives

| Alternative | Reason rejected |
|---|---|
| Offer several MLS ciphersuites initially | It multiplies experimental variables before the baseline and hybrid path are validated. |
| Use ordinary ML-KEM for `ss_pq` | It violates the thesis construction and ADR 0002. |
| Put PQ ciphertext bytes into the KDF | It contradicts the thesis requirement. |
| Reuse one derived output for both key and nonce | Independent labeled outputs make purpose separation explicit. |

## Verification Criteria

- Unit tests reconstruct `IKM` from fixed fixtures and demonstrate that changing any required context field changes the derived key.
- Tests demonstrate that changing the common or recipient PQ ciphertext fails authentication/decapsulation while an instrumentation hook confirms those raw ciphertext bytes never enter `IKM`.
- Nonce uniqueness is asserted across all successful encryptions by the context's epoch, tree-version, path-node, and recipient bindings.
