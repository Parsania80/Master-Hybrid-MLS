# ADR 0044: Canonical Topology-Route Cost Accounting

**Status:** Accepted on 2026-07-23  
**Decision scope:** Task 82 exact `C_leaf`, `C_new`, `C_old`, and `C_ideal` bytes

## Context

Task 81 selected exact disjoint cover nodes but deliberately assigned no byte
cost. The earlier Task 65 replay used fixed recipient chunk widths rather than
authenticated `T_new` and eligible `T_old` topology, so its values cannot be
reused.

The emitted post-transition Commit contains one or more signed canonical
hybrid deliveries plus invariant outer MLS framing. Each counterfactual must
carry the same recipient-set payload through the exact cover chosen for that
alternative, and the outer framing must not be multiplied by the number of
cover nodes.

## Decision

1. The fork exposes only the exact canonical byte length of each signed hybrid
   delivery alongside its already public path and recipient indexes. It does
   not expose or retain ciphertext bytes, keys, path secrets, or randomness.
2. For each authenticated path-level recipient set, every exact cover node
   becomes one `HybridPathCiphertext`. Its recipient records are exactly the
   active-quaternary leaf identities covered by that node. Across a route,
   every target recipient must occur exactly once.
3. All four alternatives use one public 32-byte logical-payload binding for the
   path-level set. Concrete fixed-width public component values are passed
   through `HybridPathCiphertext::commit_authenticated_bytes`; no byte formula
   substitutes for the production TLS serializer.
4. The reconstructed one-delivery route for the authenticated recipient set
   must have the same serialized length as the signed accepted delivery.
   Mismatch makes the measurement unavailable.
5. Route-only bytes are summed over every authenticated path-level set.
   Common outer bytes are calculated once per accepted Commit:

   ```text
   C_outer = emitted_outer_commit_bytes - signed_route_payload_bytes
   C_x = C_outer + sum_path_sets(canonical_route_x_bytes)
   ```

   Checked subtraction and addition are mandatory.
6. The signed route length and emitted Commit length are observed. Alternative
   route bytes are exact canonical-codec counterfactuals. Each aggregate
   therefore has mixed provenance:
   `observed_outer_commit_remainder_plus_authenticated_topology_exact_cover_canonical_codec`.
7. These exact costs establish serialized size, not a valid alternative MLS
   Commit, encrypted-plaintext equality, network traffic, interoperability, or
   a security proof. The public logical-payload binding declares the
   same-payload comparison; ciphertext bytes cannot prove plaintext equality.
8. Task 82 does not calculate `h_newcost`, `h_oldcost`, `t`, a formula
   retirement decision, or TreeCover retirement. Those remain unavailable
   until Task 83.

## Seed-42 Result

The accepted 64-member post-transition Commit contains one 9,060-byte signed
hybrid delivery for 63 recipients. Its emitted outer length is 16,133 bytes, so
the invariant outer remainder is 7,073 bytes.

| Alternative | Exact cover nodes | Route-only bytes | Outer bytes counted once | Exact total bytes |
|---|---:|---:|---:|---:|
| `C_leaf` | 63 | 55,188 | 7,073 | 62,261 |
| `C_new` | 9 | 15,012 | 7,073 | 22,085 |
| `C_old` | 6 | 12,780 | 7,073 | 19,853 |
| `C_ideal` | 9 | 15,012 | 7,073 | 22,085 |

`C_new == C_ideal` because the current quaternary topology is fully occupied.
`C_old < C_ideal` because the eligible binary TreeCover selects six cover nodes
while the quaternary alternatives select nine. Task 83 must preserve the exact
formula behavior when this produces an above-one raw old-cost ratio.

## Verification

- Unit tests exercise multi-node same-recipient routes and the complete
  seed-42 63/9/6/9 cover shape through the canonical codec.
- The real run verifies the reconstructed observed route length equals the
  signed 9,060-byte delivery.
- CSV event rows retain signed-route, per-set route-only, common-outer, and
  aggregate bytes with separate provenance.
- Cost arithmetic uses checked conversions, sums, and subtraction.
- Report output retains no ciphertext or secret material.
