# AGENT.md - Hybrid PQ-MLS Protocol Design

## 1. Project Identity & Goal
**Project:** Design and implementation of a Hybrid Post-Quantum Messaging Layer Security (MLS) Protocol.
**Core Standard:** IETF RFC 9420 (MLS) / TreeKEM.
**Objective:** Create a Group Key Exchange (GKE) that is secure against both Classic (current) and Quantum (future) adversaries by combining X25519 (ECC) and Kyber (ML-KEM).

## 2. The Core Challenge (The "Professor's Critique")
**Critique:** "If we run two separate trees—one Classic (X25519) and one Post-Quantum (Kyber)—and simply combine the final epoch key, why is your proposed 'Integrated Hybrid Tree' scheme better?"

**Defense Strategy (Why the Integrated Scheme is Superior):**
Based on the analysis of *Proposal.pdf* and MLS mechanics, here is the technical justification:

1.  **Atomicity & State Synchronization (The Strongest Argument):**
    *   *Dual-Tree Failure Mode:* If you run two separate trees, they are two separate distributed states. In a network with packet loss or latency, a user might receive the update for the Classic Tree but miss the update for the PQ Tree. This puts the group in an undefined/desynchronized state (Split-brain).
    *   *Integrated Solution:* By using a Hybrid Node structure, an "Update" or "Commit" message is atomic. Either the whole state transitions to the next Epoch (securely updated in both domains), or it fails entirely. This guarantees consistency.

2.  **Protocol Overhead & Complexity:**
    *   *Dual-Tree Overhead:* Running two trees requires duplicating all control messages (Proposals, Commits, Welcome messages). It doubles the metadata overhead and the complexity of the "Delivery Service" ordering.
    *   *Integrated Solution:* Uses the standard MLS framing. The payload increases (due to Kyber keys), but the *number* of messages and the logic for ordering them remains $O(log N)$.

3.  **Forward Secrecy (FS) & Post-Compromise Security (PCS) Alignment:**
    *   *Dual-Tree Issue:* PCS relies on "healing" the path from a leaf to the root. In a dual-tree, an attacker might compromise User A. If User A updates *only* the Classic tree (due to a bug or network error), the PQ tree remains compromised. The session security becomes fragmented.
    *   *Integrated Solution:* A single `Update` operation forces a refresh of entropy for both the Classic and PQ secrets simultaneously along the direct path.

4.  **Bandwidth Efficiency via mKEM (Ref: Page 8):**
    *   The proposal mentions utilizing **mKEM (Multi-recipient KEM)**.
    *   In an integrated tree, when a node sends a commit, it can use mKEM optimizations to encrypt the new path secret to the copath siblings efficiently.
    *   In a Dual-Tree, optimizing the PQ tree while keeping the Classic tree synchronized creates massive implementation friction.

## 3. Technical Specifications (From Proposal)

### 3.1. Cryptographic Primitives
*   **Classic Component:** X25519 (Elliptic Curve Diffie-Hellman).
*   **Post-Quantum Component:** ML-KEM-768 (Kyber) - NIST Standard.
*   **Combiner Method:** X-Wing Design (Ref: Page 7).
    *   *Concept:* `Output_Key = KDF( SHA3( ECDH_Secret || PQ_Shared_Secret || CT || PubKeys ) )`
    *   *Property:* Security holds if *at least one* mechanism remains unbroken.

### 3.2. System Model (Page 4)
*   **Structure:** Binary Tree (Left-Balanced).
*   **Node Composition:** Each node in the tree contains a "Hybrid Key Pair" (Classic Key + PQ Key).
*   **Path Update:** When updating a path, the user generates fresh entropy, splits it, encapsulates for the parent node using *both* schemes, and combines the result.

### 3.3. Threat Model (Page 5)
*   **Adversary:** Active (can read/modify/inject network packets).
*   **Compromise:** Can corrupt a member's state temporarily.
*   **Requirement:** Protocol must provide Forward Secrecy (protect past messages) and Post-Compromise Security (heal future messages after attacker loses access).

## 4. Implementation Roadmap
1.  **Phase 1: The Combiner (X-Wing Logic)**
    *   Implement a function that takes an X25519 keypair and a Kyber keypair and outputs a single combined shared secret.
2.  **Phase 2: The Hybrid Node**
    *   Define a data structure for a Tree Node that holds `[Classic_Pub, PQ_Pub]`.
3.  **Phase 3: The Tree Logic (The Simulator)**
    *   Implement the `Join`, `Update`, and `Process_Commit` functions using the Hybrid Node.
4.  **Phase 4: Benchmarking**
    *   Compare "Integrated Hybrid" vs. "Dual Tree" (simulated) regarding message size and processing time to prove the hypothesis.

## 5. Current Action Items
*   [ ] Define the exact KDF structure for combining X25519 and Kyber at a specific tree node.
*   [ ] Draft the mathematical notation for the "Update" operation in the integrated tree.
*   [ ] Create a comparison table (Theoretical) for the Professor defense.


# AGENT.md - Project: Hybrid PQ-TreeKEM (MLS)

## 1. Project Overview & Objectives
**Goal:** Design and implement a Hybrid Group Key Exchange protocol based on MLS (RFC 9420) that combines Classical (X25519) and Post-Quantum (Kyber/ML-KEM) cryptography.
**Primary Reference:** RFC 9420 (Messaging Layer Security).
**Key Challenge:** Justify the "Hybrid" approach (Atomicity, Efficiency) over running two parallel trees.
**Academic Focus:** Security proofs (PCS/FS), Performance analysis (Overhead), and Compatibility.

## 2. The Learning Roadmap (RFC 9420 Breakdown)
*Status: In Progress*

### **Part 1: The Static Structure (The "Board") [COMPLETED]**
*   **Concepts:** Ratchet Tree, Left-Balanced Binary Tree, LeafNode vs. ParentNode.
*   **Hybrid Adaptation:** Nodes must store a `HybridPublicKey` (Struct containing `{X25519_Pub, Kyber_Pub}`).
*   **Key Mechanic:** "Blanking" (Setting nodes to null) vs. "Truncation" (Physical resizing).

### **Part 2: Group Creation & The KeyPackage [NEXT UP]**
*   **Focus:** How a group starts. The "Pre-login" phase.
*   **Key Concepts:** `KeyPackage`, `GroupContext`, `Welcome` Message.
*   **Addresses User Q:** #1 (Creation), #2 (Joining).

### **Part 3: The Engine - Proposals vs. Commits**
*   **Focus:** The rules of the protocol.
*   **Key Concepts:** Proposal types (Add, Remove, Update) and the Commit message.
*   **Addresses User Q:** #2 (Add permissions), #3 (Remove mechanics).

### **Part 4: Dynamic Tree Operations (Path Updates)**
*   **Focus:** The mathematical operations on the tree.
*   **Key Concepts:** `UpdatePath`, Tree Resolution, Encryption to Parent Nodes.
*   **Addresses User Q:** #4 (Dynamic updates), #5 (Key upgrades).

### **Part 5: Security Properties (PCS & FS)**
*   **Focus:** Cryptographic guarantees.
*   **Key Concepts:** Epochs, Forward Secrecy (FS), Post-Compromise Security (PCS/Healing).
*   **Addresses User Q:** #6 (Why rotate keys?).

### **Part 6: Key Schedule & Management**
*   **Focus:** Deriving the actual working keys.
*   **Key Concepts:** Key Schedule, Application Keys, Membership Keys.
*   **Addresses User Q:** #7 (Key Management).

## 3. Technical Specifications & Decisions

### A. Tree Structure Modifications (From Part 1)
To support the Hybrid scheme, the standard MLS data structures must be wrapped or modified:
1.  **Hybrid Public Key:**
```rust
struct HybridPublicKey {
classic: X25519_PublicKey,
pq: Kyber_PublicKey
}



---

### Summary of Tonight's Session(1404-11-12) (Part 1) 

Tonight we established the **Static Structure** of the protocol:
1.  **The Array Mapping:** The tree is not a pointer-based web, but a flat array where children of Node $X$ are at specific indices.
2.  **The Cost of Growth:** Adding a member expands the array by 2 slots (New Leaf + New Root).
3.  **The Cost of Removal:** Removing a member creates "Holes" (Blanks). It does not shift the array (unless the member was at the very end).
4.  **Healing:** We clarified that "Healing" means refilling those empty holes with new, secure keys.

### Next Step: Tomorrow Night
We will pick up with **Part 2: Group Creation & The KeyPackage**.

**Topic Preview:**
You cannot add a user to a tree if they are offline.
*   **The KeyPackage:** A user "publishes" their resume (Keys + ID) to a server *before* the group exists.
*   **The Welcome:** How the creator picks up that resume and invites them in.

Have a good night. I am ready for Part 2 whenever you return.
