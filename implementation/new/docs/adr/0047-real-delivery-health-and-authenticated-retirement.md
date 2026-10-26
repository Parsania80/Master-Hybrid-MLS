# ADR 0047: Real Delivery Health and Authenticated TreeCover Retirement

**Status:** Accepted  
**Decision scope:** Task 86 fork observation and report boundary

Task 85 persists the authenticated frozen transition mapping and retained
old/new node availability, but the report still used a standalone simulator.
The fork also needed a commit-level retirement boundary that could not be
confused with a formula result or a caller-supplied state change.

## Decision

1. The adapter runs a bounded seeded fork workload: two real normal binary
   self-updates, one authenticated transition Commit, then real post-transition
   Update/Remove Commits. The report consumes accepted Commit bytes and the
   ciphertext-free Task 85 snapshot.
2. `transition-tree` computes endpoint counts from that snapshot. `C_new` and
   `C_old` remain independent; `C_real` follows the fork's new-tree → retained
   old-tree → leaf priority. Health fractions use exact reduced integers and
   strict `h_new > 0.70 || h_old < 0.50` triggers.
3. Retirement evidence is a canonical fixed-width `0xF003` GroupContext
   extension. It binds tree version, transition/observation epochs, impactful
   Commit count, all endpoint counts, both reduced fractions, and trigger bits.
   Receivers reject malformed, mismatched, non-successor, or non-triggering
   evidence before mutating state.
4. The retirement Commit changes the authenticated state to normal 4/4,
   activates the new quaternary authority, and atomically clears the retained
   transition node/keypair envelope. Reports expose only evidence and redacted
   erasure counts; no key, ciphertext, or secret is serialized.
5. Mode 4 of `test.sh` fixes the 2→4 topology and bounds the initial group to
   64–128 members so the real workload remains an operator-friendly report.
   Schema 5 marks the provenance as a real fork observation with authenticated
   atomic retirement, while retaining the thesis-local/non-interoperable
   warning.

## Consequences

The interactive report no longer emits `UnsupportedSimulationOnly` for this
workload and no longer describes retirement as unsupported. Retirement delivery
uses the authenticated transitioning context for the compact path before
publishing normal 4/4 state; member-local erased-private counts therefore remain
redacted and are not required to match across members. It still does not claim
production security, distributed/network atomicity, RFC interoperability, or a
general secret-erasure proof. Windows acceptance is available through the
official GNU/MinGW toolchain on `E:` when MSVC is absent; Linux remains the
operator comparison run.
