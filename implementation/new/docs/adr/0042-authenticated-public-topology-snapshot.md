# ADR 0042: Authenticated Public Topology Snapshot

**Status:** Accepted on 2026-07-23  
**Decision scope:** Task 80 `T_new`, `T_old`, and recipient-set extraction

## Context

The fork previously exposed only aggregate hybrid-delivery counts. Exact
path-level recipient node indexes remained inside the signed UpdatePath, while
the adapter separately retained an unauthenticated shadow-tree object. Correct
transition-cost measurement requires both facts to be tied to the same accepted
Commit and authenticated GroupContext state.

## Decision

1. Before optional PrivateMessage encryption, the fork extracts only each
   signed hybrid delivery's public path-node index and ordered public recipient
   node indexes. It discards ciphertext and key bytes.
2. Extraction is observational. It records what was signed and does not replace
   receiver validation; malformed signed test Commits must still reach and fail
   at the authenticated receiver boundary.
3. The adapter publishes a topology snapshot only after every valid member
   accepts the Commit and converges on the same epoch and public MLS ratchet
   tree.
4. The adapter reconstructs the active quaternary tree and frozen binary
   TreeCover from current public members, then requires their mapping and
   TreeCover hashes to match the accepted GroupContext `ArityState`.
5. For the accepted post-transition Commit, every extracted recipient set must
   use the active-quaternary namespace, exclude the committer, be non-empty and
   disjoint, and collectively equal all other active quaternary leaf ordinals.
6. The public snapshot retains group ID, converged epoch, committer identity and
   quaternary leaf ordinal, validated active/old trees, and ciphertext-free
   recipient sets. It retains no private keys, path secrets, ciphertexts,
   public-key encodings, or entropy.

## Observed Task 80 Result

The resource-bounded seed-42 64-member run produced one authenticated recipient
set for Commit sequence 4 at epoch 5:

- active `T_new`: tree version 1, arity 4, height 3, leaf capacity 64, and 64
  occupied leaves;
- eligible `T_old`: TreeCover version 1, 64 eligible frozen members, and 127
  populated routing nodes;
- committer: workload member 10, quaternary leaf ordinal 2;
- signed delivery: active-quaternary path node 0 with exactly leaf ordinals
  `0..63` except `2`.

The current experimental Commit therefore emits one root-level quaternary
delivery to all other leaves. Task 81 must derive alternative valid covers from
the authenticated topology; it must not reinterpret this one emitted recipient
set as fixed arity-sized chunks.

## Consequences

- Task 80 provides sufficient authenticated public input for cover selection.
- `C_*`, `h_*`, and retirement remain unavailable until Tasks 81–83.
- The clear event CSV and Markdown expose the exact topology and recipient set
  with `accepted_signed_commit_plus_authenticated_group_context` provenance.
