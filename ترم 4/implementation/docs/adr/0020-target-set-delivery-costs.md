# ADR 0020: Target-Set Delivery Cost Measurements

**Status:** Accepted on 2026-07-20
**Decision scope:** Task 46 exact serializer-driven `C_leaf`, `C_new`, `C_old`, and `C_ideal` records

## Context

ADR 0006 defines four costs for every relevant recipient target set `S` during a binary-to-quaternary transition. The prior metrics crate could count an individual canonical hybrid payload, but it could not prove which target set a collection of payloads covered, distinguish independent leaf delivery from shared delivery, or retain an unavailable TreeCover route without fabricating a numeric value. Those omissions would make later maturity arithmetic unsafe.

## Decision

1. The `metrics` crate defines a canonical `RecipientTargetSet`: strictly ascending, duplicate-free public recipient-node indexes. Empty sets are valid records and are excluded by the later maturity aggregator.
2. `RecipientTargetSetCostMeasurement::measure` accepts one public logical-payload binding and four route inputs for the same target set: `Leaf`, `New`, `Old`, and `Ideal`. The binding is a caller-supplied public identifier; it must not contain secret material, and this crate cannot prove equality of encrypted plaintexts from ciphertext bytes.
3. Every available route supplies actual `HybridPathCiphertext` values. The measurement calls their canonical `commit_authenticated_bytes` serializer, sums the byte lengths with checked arithmetic, then retains only count/provenance metadata—not ciphertext bytes.
4. Every available route must cover every recipient in `S` exactly once. Empty collections, partial coverage, and duplicate recipients are rejected. `Leaf` additionally requires one singleton-recipient ciphertext per member of `S`.
5. Each measured cost records the route kind, delivery-target count, recipient count, and `ShadowExactCodec` provenance. It is exact at the hybrid TLS component boundary but remains a counterfactual estimate rather than an emitted MLS Commit.
6. Empty target sets must use `EmptyTargetSet`; old TreeCover or other unavailable routes retain a typed reason such as `NoEligibleOldTreeCoverRoute` or `RouteNotMaterialized`. No unavailable value becomes zero or another favorable byte count.

## Consequences

- Task 47 receives raw, target-scoped inputs with sufficient provenance to reject undefined maturity rather than inferring a value from missing data.
- The API has no routing algorithm: a future fork or evaluator must materialize the appropriate new-tree, TreeCover, and mature-tree ciphertext collections before measuring them.
- This code does not prove an encrypted plaintext equality, route authentication, MLS Commit validity, network cost, live TreeCover behavior, or any security/interoperability property.

## Verification

- Unit tests derive all four values from actual canonical hybrid TLS serialization, verify exact set coverage and independent leaf delivery, and reject non-canonical target sets, duplicate coverage, and non-independent leaf routes.
- Unit tests preserve an unavailable old TreeCover route and an explicit empty target set without numeric fallbacks.
- Locked-offline formatting, focused tests, and strict Clippy must pass.
