# mKyber Implementation, Parameter, License, and Test-Vector Audit

**Status:** Completed for Part 1, Task 3 on 2026-07-18. This document records a source-level and public-package audit, not a cryptographic audit or a production-security assessment.

## Conclusion

No maintained, compatible, and auditable Rust implementation of the thesis's mKyber512 construction was identified. The only directly relevant public implementation found is a C/AVX2 work-in-progress repository whose `K=2` parameters and ciphertext layout differ materially from the paper's mKyber512 parameters. The repository archive has no embedded license file, although its authors' associated paper describes the legacy artifact as public domain (CC0).

Therefore, no third-party mKyber backend is approved for this project. Ordinary ML-KEM/Kyber, including RustCrypto's `ml-kem`, is not an mKyber substitute. A later ADR must authorize either a newly written, clearly reference-only Rust implementation from the published specification or an adapter only after a compatible implementation, its provenance, and its license have been independently established.

### Backend implementation gate

Task 14 cannot safely turn the available paper overview into a cryptographic backend. Its Figure 2 expressly simplifies Kyber: it omits or merges hash/PRF calls and omits bit-representation and NTT/coefficient-representation transitions. Those choices determine key and ciphertext bytes, rejection behavior, and the Fujisaki-Okamoto re-encryption check; the published mKyber512 sizes alone do not define them. The paper remains the authoritative source for the high-level construction and Table 1 parameters, but it is not a complete implementable byte-level specification. See the paper's [simplifications statement and construction](https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/how-multi-recipient-kems.pdf) (Section 3.1).

The additional primary-source search on 2026-07-18 located mKEM research and ordinary Kyber reference code, but no complete licensed mKyber512 implementation specification, compatible implementation, or mKyber512 KAT corpus. Consequently, this project must not invent those unspecified details or label a toy construction as mKyber512. Task 14 requires one of these inputs before code can be added:

1. an authoritatively approved, versioned mKyber512 specification that fixes XOF/hash/PRF domains, noise sampling, rejection sampling, NTT and compression/packing, secret-key layout, Fujisaki-Okamoto fallback, and byte encoding; or
2. an independently auditable, license-compatible mKyber512 implementation with matching test material and permission to adapt it.

#### Source-chain result

The cited source chain does not provide the missing profile. The generic mPKE Fujisaki-Okamoto transform used by the later research treats `G1`, `G2`, and `H` as random oracles and defines only their abstract inputs and outputs; it does not select concrete hash/XOF functions, output widths, or byte-domain encodings. The mKyber overview uses those same names while changing the message length and ciphertext layout. The CRYSTALS-Kyber Round-3 materials provide exact ordinary-Kyber primitives, serialization, and vectors, but do not define mKyber's 128-bit message hash, the `G1`/`G2` mappings, or its 128-coefficient recipient encoding. Consequently, combining these documents would create a thesis-local derived profile, not an authoritative mKyber512 specification. See the [mPKE FO transform](https://eprint.iacr.org/2022/1046.pdf) (Figure 6), the [mKyber construction and parameters](https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/how-multi-recipient-kems.pdf) (Section 3), and the [Kyber Round-3 resources](https://pq-crystals.org/kyber/resources.shtml).

#### Author-hosted artifact check

On 2026-07-18, the author-hosted `kyber-mkem.tar.bz2` archive cited by the [mPKE paper](https://eprint.iacr.org/2022/1046.pdf) remained available. That paper explicitly says that its Kyber-mKEM implementation is placed in the public domain (CC0); the served archive itself contains no root license file. Its `KYBER_K=2` parameter header fixes a 32-byte CPA message, an 800-byte public key, a 1,280-byte common component, and a 257-byte recipient component. Its vector program emits deterministic test output but contains no expected mKyber512 fixture corpus. This is author-approved evidence for a legacy Kyber-mKEM artifact only. It neither specifies nor validates the paper mKyber512 profile, whose corresponding values are 16, 768, 704, and 48 bytes. Do not adapt it as mKyber512.

An additional public-release sweep on 2026-07-18 queried GitHub repositories for `mkyber`, `mkyber512`, `kyber-mkem`, and `multi-recipient kyber`, and queried crates.io for `mkyber`. The only relevant repository result was the incompatible `cryptojedi/kyber-mkem`; no `mkyber`/`mkyber512` Rust package, released byte-level profile, or compatible vector corpus was found. This is a time-bounded public-discovery result. Obtaining an author-approved compatible artifact now requires an author response or a new author-controlled release.

## Audited Target: Paper mKyber512

The thesis target is the paper's mKyber512 construction, not FIPS 203 ML-KEM-512 and not an arbitrary multi-recipient Kyber variant. The paper defines a multi-recipient ciphertext as one common component `u` and one recipient-specific component `v_i` per recipient. A recipient decapsulates only `(u, v_i)`.

| Parameter | mKyber512 target | Significance |
|---|---:|---|
| `q` | 3329 | Modulus |
| `n` | 256 | Ring degree |
| `k` | 2 | Module rank |
| `eta1`, `eta2` | 3, 2 | Noise parameters |
| `du`, `dv` | 11, 3 | Compression widths |
| Message length | 16 bytes | 128-bit message, not Kyber512's 32-byte message |
| Encapsulation key | 768 bytes | Paper target |
| Common `u` | 704 bytes | Serialized once per recipient set |
| Recipient `v_i` | 48 bytes | Serialized once per recipient |

These figures are taken from Table 1 and the accompanying efficiency discussion in the [mKyber paper](https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/how-multi-recipient-kems.pdf). The paper also requires the public matrix `A` to be shared by all key pairs in one mKyber parameter domain; this must be represented and validated explicitly by the future Rust API rather than treated as secret key-generation entropy.

### Security boundary

The paper describes mKyber as providing its standard multi-user IND-CCA security notion, while stating that it has no proof with a non-exponential loss for adaptive corruptions. It presents the larger amKyber construction for the adaptive-corruption setting. This distinction matters for long-lived MLS keys and must be stated in the threat model and implementation labels; the thesis request remains mKyber512, so this audit does not silently replace it with amKyber. See the paper's [security discussion](https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/how-multi-recipient-kems.pdf) (pp. 1–3, 6–8).

## Implementation Inventory

### `cryptojedi/kyber-mkem`

| Field | Audit result |
|---|---|
| Repository | [`cryptojedi/kyber-mkem`](https://github.com/cryptojedi/kyber-mkem) |
| Snapshot examined | Commit `531bbe284bdde1e621fa470648519741db03f9ba` (2022-10-05) |
| Language | C reference implementation plus AVX2 assembly/C |
| Maintenance/release signal | The repository calls itself “Heavily Work in Progress (don't use!)”; no Rust package or release was identified. |
| Multi-recipient API | Separate common-C1 and per-recipient-C2 encapsulation functions, with a decapsulation input comprising both components. |
| Common-domain input | Key generation takes the same public seed for all key-pair computations, matching the general shared-matrix requirement but requiring an explicit domain identifier in any future integration. |
| Reuse decision | Rejected: technically incompatible, not Rust, and explicitly WIP. The associated author paper describes the legacy artifact as CC0, but that does not make it mKyber512-compatible. |

The implementation is a useful historical comparison, not the paper's mKyber512 backend. Its [`ref/params.h`](https://github.com/cryptojedi/kyber-mkem/blob/531bbe284bdde1e621fa470648519741db03f9ba/ref/params.h) gives, at `KYBER_K=2`, a 32-byte message, a 1,280-byte common C1, and a 257-byte per-recipient C2. Those values do not match mKyber512's 16-byte message, 704-byte `u`, or 48-byte `v_i`; measurements or vectors from this code must never be presented as mKyber512 results.

#### License determination

The repository and author-hosted archive have no root `LICENSE`, `COPYING`, or `NOTICE` file. However, the author paper for the archive explicitly states that the Kyber-mKEM implementation is placed in the public domain (CC0). That is evidence of author intent for this legacy artifact, while the archive itself should still be pinned and independently reviewed before any future source reuse. It remains prohibited here because its construction and byte layout are incompatible with mKyber512, not because ordinary Kyber code may be relabelled as mKyber512.

### RustCrypto `ml-kem`

RustCrypto's [`ml-kem`](https://docs.rs/ml-kem/latest/ml_kem/) is a maintained Rust implementation of standard ML-KEM parameter sets. It has no multi-recipient `(u, v_i)` API and no mKyber512 parameter set, so it cannot be used as the thesis mKyber backend or as a source of mKyber size claims. Its documentation additionally says it has not been independently audited. It may be discussed as a standard-ML-KEM comparison point only; it is not approved as a fallback.

### Package and repository search result

On 2026-07-18, an exact `mkyber` crates.io package search returned no crate results. Public GitHub repository searches for `mKyber`, multi-recipient Kyber, and mKEM Kyber produced the C repository above as the only directly relevant implementation located in this audit. This is a time-bounded discovery result, not proof that no other implementation exists.

## Test-Vector Audit

The C repository contains `test_mkyber.c`, `testvectors.c`, and shell scripts for its reference and AVX2 directories. Static inspection found:

- `test_mkyber.c` exercises recipient agreement, invalid secret-key handling, and bit flips in the common and recipient-specific ciphertext components.
- `testvectors.c` deterministically generates vectors using an in-source deterministic generator; it is configured for multiple recipients and iterations.
- No committed expected-vector fixtures or external published mKyber512 KAT corpus was found in the audited snapshot. The scripts generate output; comparison of reference and AVX2 output is a differential check rather than an independently published known-answer test.
- The vectors belong to the repository's incompatible construction. They cannot validate a paper-mKyber512 Rust implementation, and they must not be relabelled as mKyber512 KATs.

The future `crates/mkyber` test strategy must instead create a reviewable project-owned corpus from an exact written specification and version it with its generator. Required cases are deterministic key generation within one public matrix domain, recipient-set agreement, non-recipient rejection/failure behavior, malformed lengths, common-component tampering, per-recipient-component tampering, wrong-recipient component, domain mismatch, serialization round trips, and exact 704/48-byte component assertions. Until an independently compatible implementation or official KAT corpus exists, such fixtures are regression vectors, not external known-answer vectors.

## Required Interface and Serialization Consequences

The planned `MultiRecipientKem` abstraction needs a typed public domain parameter in addition to normal public/secret keys. At minimum it must prevent accidental mixing of keys created under different shared-matrix domains and expose the two ciphertext components separately:

```text
keygen(domain, rng) -> (public_key, secret_key)
encapsulate_set(domain, recipient_public_keys, rng) -> (common_u, recipient_v_i..., shared_secret)
decapsulate(domain, secret_key, common_u, recipient_v_i) -> shared_secret
```

The authenticated hybrid wire format must carry a canonical domain identifier and bind it to the group/tree context. It must serialize the mKyber common and recipient-specific components independently and record their actual encoded lengths. The component bytes remain transmitted and authenticated but remain outside the hybrid KDF input, in line with the thesis boundary.

## Next Decision Inputs

Task 4 must record all of the following in ADRs:

1. mKyber512 is a reference-only research backend, never a production claim.
2. The implementation is specification-driven; the unlicensed C modifications are not copied or translated.
3. The exact security claim is mKyber's non-adaptive multi-user setting, with adaptive-corruption limitations prominently documented.
4. The shared public matrix/domain is a validated public protocol parameter, distinct from a reproducible experiment seed and secret randomness.
5. Project-owned deterministic regression vectors are not called official KATs and must assert the paper's sizes exactly.
