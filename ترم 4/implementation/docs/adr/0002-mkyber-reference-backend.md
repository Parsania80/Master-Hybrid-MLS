# ADR 0002: Implement mKyber512 as a Replaceable Reference-Only Backend

**Status:** Accepted on 2026-07-18
**Decision scope:** mKyber implementation, provenance, parameters, and test vectors

## Context

The [mKyber audit](../research/MKYBER-IMPLEMENTATION-AUDIT.md) found no maintained compatible Rust backend. The relevant public C/AVX2 repository is explicitly work in progress, has different `K=2` sizes, and has no explicit license for its repository-specific changes. Standard ML-KEM is neither a parameter-compatible implementation nor an acceptable substitute.

The target is the paper's mKyber512: `q=3329`, `n=256`, `k=2`, `eta1=3`, `eta2=2`, `du=11`, `dv=3`, a 16-byte message, a 768-byte encapsulation key, a 704-byte common `u`, and a 48-byte recipient `v_i`. These values and the shared public matrix requirement come from the [mKyber paper](https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/how-multi-recipient-kems.pdf).

## Decision

1. Create `crates/mkyber` as a project-owned, specification-driven Rust reference backend behind a replaceable `MultiRecipientKem` trait. It is not production cryptography.
2. Do not copy, translate, vendor, or derive fixtures from the unlicensed repository-specific changes in `cryptojedi/kyber-mkem`. The paper is the specification source; provenance for every new implementation file must be recorded.
3. Model the matrix/domain input as a typed, public `MkyberDomain`. Key generation, encapsulation, and decapsulation reject mixed domains. This public domain is distinct from both the public experiment seed and secret randomness.
4. Expose common and recipient components separately and assert the exact target serialized sizes (704 and 48 bytes) at the codec boundary.
5. Generate project-owned deterministic regression vectors with a versioned generator, but label them regression vectors, never official or external KATs. An independent compatible implementation or published KAT corpus is required before adding a cross-implementation claim.
6. Document mKyber's non-adaptive multi-user security scope. Do not claim amKyber's adaptive-corruption proof or silently replace the thesis construction with amKyber.

## Consequences

- The backend can be replaced if a maintained, compatible, correctly licensed implementation becomes available.
- This project bears the implementation and review burden; no claim of audit, standardization, production suitability, or formal protocol proof is permitted.
- The shared domain becomes explicit authenticated protocol state rather than hidden global configuration.

## Rejected Alternatives

| Alternative | Reason rejected |
|---|---|
| Use RustCrypto `ml-kem` | It implements standard ML-KEM, not multi-recipient mKyber512. |
| Adapt `cryptojedi/kyber-mkem` | Its parameters are incompatible, it is WIP C/AVX2 code, and its modification license is not established. |
| Substitute amKyber | It is a different, larger construction and does not satisfy the thesis request for mKyber512. |
| Treat deterministic self-generated outputs as KATs | No external compatible vector corpus was found. |

## Verification Criteria

- Tests cover recipient agreement, non-recipient behavior, domain mismatch, malformed inputs, common/per-recipient tampering, and deterministic reproducibility.
- The test suite asserts mKyber512's exact component sizes and never reports ML-KEM or incompatible-C measurements as mKyber measurements.
- Public reports state the reference-only and non-adaptive-security limitations.
