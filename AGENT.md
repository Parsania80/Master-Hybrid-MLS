# AGENT.md - Hybrid PQ-MLS Protocol Design

**Project:** Hybrid Post-Quantum Messaging Layer Security (TreeKEM)
**Standard:** RFC 9420 (MLS)
**Core Crypto:** X25519 (Classic) + ML-KEM-768 (Kyber/Post-Quantum)
**Last Updated:** Session covering Parts 1–6

---

## 1. Project Overview & The "Hybrid" Thesis
**Goal:** Design a Group Key Exchange (GKE) protocol that provides immediate security (Classical) and long-term protection against Quantum computers (PQ), using a single integrated TreeKEM structure.

### The Core Academic Argument (The "Professor Defense")
**Critique:** "Why not run two separate trees (one X25519, one Kyber) and XOR the keys at the end?"
**The Answer (Justification for Integrated Hybrid Tree):**
1.  **Atomicity & State Consistency (Primary):**
    *   In a Dual-Tree system, network packet loss could update the Classic tree but fail to update the PQ tree, leading to a "Split-Brain" state where keys are desynchronized.
    *   In the **Integrated Hybrid Tree**, a `Commit` is atomic. Either the whole state transitions to the new Epoch (securely in both domains), or it fails entirely.
2.  **Forward Secrecy Alignment:**
    *   Post-Compromise Security (PCS) requires "healing" the path. An integrated `Update` ensures that *fresh entropy* is injected into both the Classic and PQ layers simultaneously.
3.  **Efficiency (Metadata & Control):**
    *   Dual trees double the control message overhead (ordering, proposals, framing). An integrated tree maintains $O(\log N)$ complexity for control logic, even if the payload size increases.

---

## 2. Learning Roadmap & Status

### **Part 1: The Static Structure [COMPLETED]**
*   **Concept:** Left-Balanced Binary Tree mapped to a flat array.
*   **Hybrid Node:** Every `LeafNode` and `ParentNode` contains a `HybridPublicKey` (Struct `{X25519, Kyber}`).
*   **Operations:**
    *   **Growth:** Array expansion (requires new Root).
    *   **Blanking:** Logical removal (setting nodes to `null`).
    *   **Truncation:** Physical array shrinking (only possible from the right edge).

### **Part 2: Group Creation (KeyPackages) [SKIPPED / CONCEPT ONLY]**
*   **Status:** Skipped to focus on Engine logic.
*   **Concept:** A `KeyPackage` is an "Offline Resume" containing initial Hybrid Keys and Credentials, published to a server so others can add you asynchronously.

### **Part 3: The Engine (Proposals & Commits) [COMPLETED]**
*   **Concept:** Separation of Intent (`Proposal`) vs. Execution (`Commit`).
*   **Governance:** First-Come-First-Served (FCFS). The Delivery Service orders commits; the first valid one wins, others must retry (Update-and-Rebase).
*   **Batching:** Multiple proposals (Add Alice, Remove Bob) are applied in one single atomic `Commit`.

### **Part 4: Dynamic Tree Operations (Path Math) [COMPLETED]**
*   **Concept:** The `UpdatePath` operation.
*   **Mechanism:**
    1.  User generates a new Leaf Secret.
    2.  User hashes up the tree to generate new secrets for the direct path.
    3.  User **Encrypts** (KEM) the new node secrets to the "siblings" (Resolution Path) at every level.
*   **Hybrid Logic:** This requires **Double Encapsulation** (one ciphertext for Classic, one for PQ) at every step of the path.

### **Part 5: Security Properties (FS & PCS) [COMPLETED]**
*   **Forward Secrecy (FS):** Achieved by **deleting** old private keys immediately after the Epoch transition.
*   **Post-Compromise Security (PCS):** Achieved by the `Update` operation, which injects fresh random entropy that an attacker (who stole old keys) cannot guess.
*   **The "OR" Guarantee:** System is secure if $\text{Security}(Classic) \lor \text{Security}(PQ)$ holds.

### **Part 6: Key Schedule & Management [COMPLETED]**
*   **Concept:** Deriving working keys from the Tree Root.
*   **Mechanism:** `Hybrid_Root_Secret` $\to$ `Commit_Secret` $\to$ `Epoch_Secret`.
*   **Outputs:**
    *   `Handshake_Key`: For internal MLS messages.
    *   `Application_Key`: For actual user chat/data (ratcheted per sender).

---

## 3. Technical Specifications

### A. Data Structures
```rust
struct HybridPublicKey {
classic: X25519_PublicKey,
pq: ML_KEM_768_PublicKey
}

struct HybridCiphertext {
iv: [u8; 16],
ct_classic: Vec<u8>, // X25519 Output
ct_pq: Vec<u8>       // Kyber Output
}

### B. The Hybrid Commit Logic
1.  **Input:** A list of Proposals (e.g., "Add Member").
2.  **Processing:**
*   The Committer applies the changes to the Tree View.
*   The Committer generates a new keypair for their own Leaf.
*   **Path Computation:** The Committer calculates the new values for every node in their direct path to the root.
3.  **Encryption (The Hybrid Step):**
For each node in the path, the secret is encrypted for the "Copather" (Sibling):
*   $C_{cl} \leftarrow \text{Encap}(Pub_{cl}, Secret)$
*   $C_{pq} \leftarrow \text{Encap}(Pub_{pq}, Secret)$
*   `Commit_Message` includes $C_{cl} || C_{pq}$.
4.  **Receiver Logic:** A receiver MUST successfully decapsulate **both** (or validly process the combiners) to derive the node secret.

### C. Security & Key Schedule
*   **The Combiner (X-Wing Style):**
When deriving the `Epoch_Secret`, we mix the Classic and PQ shared secrets:
$$Secret = \text{KDF}( \text{Hash}( S_{classic} || S_{pq} || \dots ) )$$
*   **Application Keys:**
Traffic keys are derived via `HKDF-Expand` from the `Epoch_Secret`. This ensures that if the Hybrid Tree is secure, the chat messages inherit that security (Quantum Resistance).

---

## 4. Next Steps & Action Items

**Current Status:** Theoretical Architecture Complete (Parts 1-6).

**Phase 2: Implementation & Simulation**
1.  **Code the Structures:** Define the `LeafNode` and `ParentNode` classes in Python/Rust.
2.  **Code the Math:** Implement the "UpdatePath" logic (generating a path and encrypting it).
3.  **Trace a Scenario:** Create a text-based simulation:
*   *Step 1:* Create Group (A, B, C).
*   *Step 2:* B commits an Update (Hybrid Path Gen).
*   *Step 3:* Verify A and C can process the commit and derive the same `Epoch_Secret`.

**Phase 3: Thesis Writing**
*   Draft the "Threat Model" section based on Part 5 notes.
*   Draft the "Performance Analysis" comparing payload sizes (Standard vs. Hybrid).
