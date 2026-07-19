# ADR 0002: Implement mKyber512 as a Replaceable Reference-Only Backend

**Status:** Accepted; `mkyber512-thesis-v1` implemented on 2026-07-18
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

### Educational reference profile `mkyber512-thesis-v1`

The paper fixes the high-level construction and Table 1 parameters but deliberately simplifies several byte-level operations. The operator has authorized an educational thesis reference implementation, so the following project-local profile makes every such mapping explicit. It is **not** an author-approved mKyber512 wire profile and it creates no interoperability, security, audit, side-channel, or production-use claim.

1. Work in `Z_3329[x]/(x^256 + 1)` with `k=2`, `eta1=3`, `eta2=2`, `du=11`, `dv=3`, 16-byte messages, a 768-byte `b`, a 704-byte `u`, and a 48-byte `v_i`. The reference arithmetic uses canonical coefficient representation and schoolbook negacyclic multiplication; it does not claim a paper-specified NTT representation.
2. `MkyberDomain` is the public 32-byte `seedA`. Matrix expansion is SHAKE128 over a profile tag, `seedA`, row index, and column index, followed by Kyber-style 12-bit rejection sampling below `q`.
3. `H`, `G1`, `G2`, and `KDF` use SHA3-256 with distinct ASCII profile tags. `G2` also binds the domain and the recipient's 768-byte `b`. `PRF1` and `PRF2` use SHAKE256 with distinct tags, a 32-byte seed, and a one-byte nonce; centered-binomial sampling uses the stated `eta` values.
4. A message is encoded in coefficients 0 through 127 as zero or `(q+1)/2`; coefficients 128 through 255 are zero. Recipient serialization compresses and packs exactly those first 128 coefficients in ascending coefficient order at three bits each. Full `b` serialization packs canonical coefficients in ascending vector/coefficient order at 12 bits each; `u` packs both vector polynomials in the same order at 11 bits each.
5. Key generation samples `s,e` with `eta1`, computes `b=A*s+e`, and stores packed `s`, packed `b`, and a 32-byte fallback value `z`. Encapsulation derives a 16-byte message from randomness, produces one `u` from `r,e'`, and produces every `v_i` from recipient-specific `e''_i`. Decapsulation recomputes both components and uses their constant-time equality result only to select the normal or fallback output.
6. To preserve the paper's required single shared key for every valid recipient, normal output is `SHA3-256(tag || K' || domain || u)`. Invalid decapsulation returns `SHA3-256(fallback-tag || z || domain || u || v_i)`. This resolves the paper's simplified `KDF(K',ct)` notation as a thesis-local mapping; it must never be described as an author-standardized KDF input.
7. Normal reference key generation and encapsulation instantiate `rand::rngs::OsRng` through dedicated entry points. Deterministic entropy is private to the unit-test module. Long-lived decapsulation keys and shared secrets use `ZeroizeOnDrop`; temporary entropy, seeds, decoded messages, noise polynomials, and packed secret-key bytes use `Zeroizing` guards. This is best-effort hygiene, not a compiler-erasure, side-channel-resistance, or implementation-security claim.
8. Regression tests may pin a digest over deterministic **public** keys and ciphertext components. That project-owned digest is not an author vector, a known-answer test, or interoperability evidence; no deterministic seed, private key, or shared secret may be stored in a fixture or assertion.

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
