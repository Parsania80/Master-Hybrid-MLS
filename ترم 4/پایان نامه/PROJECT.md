# Hybrid TreeKEM Thesis Project

## Project Scope

This project is the master thesis work of محمدرضا پارسانیا in Cybersecurity at University of Isfahan, supervised by Dr. Hamid Molla.

Persian title:
پروتکل تبادل کلید گروهی ترکیبی بر پایه TreeKEM

English title:
Hybrid Group Key Exchange Protocol Based on TreeKEM

The thesis studies and designs a hybrid group key exchange protocol for secure group messaging. The core idea is to adapt the TreeKEM key-management structure used in MLS so that a single tree can contain both classical and post-quantum key material. Each relevant tree node should combine a classical key exchange component, such as X25519, with a post-quantum KEM component, such as Kyber / ML-KEM, so that the group key remains secure unless both components are broken.

## Mandatory Writing Rules

- Main thesis font: IRNazanin.
- Main thesis font size: 13.
- Mathematical expressions in explanations and notes must use `$ ... $` for inline math and `$$ ... $$` for block math.
- Cryptographic algorithms and protocol flows should be written first in language-agnostic pseudocode unless implementation code is explicitly requested.
- The project files `PROJECT.md` and `SESSION-LOG.md` are the continuity files for future work.

## Core Research Problem

Current classical public-key cryptography is threatened by quantum algorithms such as Shor's algorithm. Post-quantum cryptography addresses this threat, but many post-quantum schemes have larger keys/ciphertexts and are still newer than mature classical primitives. A hybrid approach combines classical and post-quantum mechanisms to reduce transition risk.

The research gap is that hybrid key exchange has been studied mainly for two-party protocols, while secure group messaging needs scalable, dynamic, asynchronous group key management. TreeKEM, the cryptographic core of MLS, gives efficient group key updates, but the standard design is based on classical assumptions. This thesis therefore targets a hybrid TreeKEM-style group key exchange protocol that preserves MLS-style scalability while adding post-quantum resilience.

## Research Objectives

- Design a tree-based hybrid group key exchange protocol using both classical and post-quantum primitives.
- Define how each tree node stores, updates, and combines classical and post-quantum key material.
- Preserve the main TreeKEM/MLS workflow for group creation, add, update, and remove operations.
- Provide a formal or semi-formal security model for the proposed protocol.
- Argue that security remains intact if only one of the classical or post-quantum components is broken.
- Evaluate computational cost, message size, memory cost, and scalability for groups of different sizes.
- Compare the proposed design with classical TreeKEM, prior group key agreement protocols, hybrid two-party KEM designs, and multi-recipient KEM approaches.

## Research Questions

- How can hybrid TreeKEM security be formalized in a group messaging setting?
- What is the performance cost of adding post-quantum key material to TreeKEM?
- Can the design remain compatible with MLS message structure and deployment assumptions?
- What KEM combiner design is most suitable for deriving each node secret from classical and post-quantum shared secrets?
- Which operations suffer the most overhead: group creation, add, update, remove, or epoch transition?

## System And Threat Model

The system is a dynamic group messaging setting. Members are represented as leaves of a binary key tree. Internal nodes hold key material used to derive the root secret and ultimately the group epoch secrets. Members know the private key material along their direct path and use update-path messages to move the group to a new epoch.

The adversary may eavesdrop, modify, replay, or delay network messages. The adversary may temporarily compromise a member and obtain some private state, but is not assumed to maintain permanent control over all members. The protocol should preserve forward secrecy and post-compromise security through update operations. The hybrid security target is that compromise of only the classical component or only the post-quantum component should not reveal the final combined group secret.

## Key Sources

- Proposal.docx: official research proposal and problem statement.
- Thesis.docx / Thesis.pdf: current thesis draft.
- فصل 3.docx: related works draft material.
- RFC 9420: The Messaging Layer Security protocol.
- TreeKEM / MLS literature.
- X-Wing and hybrid KEM combiner literature.
- Multi-recipient KEM literature, especially mKEM, mKyber, and amKyber.
- Local folder `related_works/` for chapter 3 papers.

## Chapter Roadmap

### Chapter 1: مقدمه

Purpose: introduce the quantum threat, post-quantum migration problem, MLS, TreeKEM, and the need for hybrid group key exchange.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Explain quantum threat to RSA/ECC and long-term confidentiality | Drafted | Use Shor's algorithm as motivation. |
| 2 | Introduce post-quantum cryptography and migration uncertainty | Drafted | Mention key/ciphertext size and maturity risks. |
| 3 | Introduce MLS and TreeKEM for secure group messaging | Drafted | Connect to scalable group key updates. |
| 4 | State research gap and thesis contribution | Needs revision | Make the gap sharper: hybrid two-party exists, hybrid tree/group protocol is missing. |

### Chapter 2: مبانی نظری و مفاهیم پایه

Purpose: build the technical foundation needed for the proposal.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Explain secure group messaging and group key agreement | Drafted | Include dynamic groups and epoch changes. |
| 2 | Explain MLS entities and architecture | Drafted | Clients, delivery service, key package directory, group state. |
| 3 | Explain TreeKEM structure and update path | Drafted | Show leaf-to-root path update and logarithmic cost. |
| 4 | Explain forward secrecy and post-compromise security | Drafted | These are central evaluation criteria. |
| 5 | Explain PQC and NIST algorithms | Drafted | Kyber / ML-KEM should be tied to KEM usage. |
| 6 | Explain hybrid KEM and KEM combiners | Drafted | Prepare for the proposed protocol in chapter 4. |

### Chapter 3: پیشینه پژوهش و کارهای مرتبط

Purpose: review related works and older works, then identify the research gap for Hybrid TreeKEM.

| # | Topic | Status | Notes |
|---|-------|--------|-------|
| 1 | Sender Keys and practical group messaging security | In progress | Use local paper in `related_works/3-1-1/`. |
| 2 | CLIQUES and early group key agreement | In progress | Explain how group DH evolved toward tree approaches. |
| 3 | Burmester-Desmedt conference key distribution | In progress | Compare constant-round design with dynamic membership limits. |
| 4 | Secure group communications using key graphs | In progress | Useful historical basis for key trees. |
| 5 | Tree-based group key agreement | In progress | Bridge older tree approaches to TreeKEM. |
| 6 | Hybrid two-party KEM designs for TLS, X-Wing, HAKEM, MIKA | Todo | Show that hybrid work is mature in two-party settings. |
| 7 | KEM combiners | Todo | Explain parallel/cascade/KDF-based combiners. |
| 8 | Multi-recipient KEM, mKyber, amKyber | Todo | Important for bandwidth reduction in group settings. |
| 9 | Gap analysis table | Todo | Compare classical security, PQ security, group support, dynamic membership, MLS compatibility, overhead. |

Chapter 3 conclusion must clearly say: older group key agreement gives scalability ideas; modern MLS/TreeKEM gives dynamic secure group messaging; hybrid KEM work gives dual classical/PQ security; multi-recipient KEM gives bandwidth ideas; but there is still no complete hybrid TreeKEM design where one MLS-style tree carries both classical and post-quantum key pairs.

### Chapter 4: پروتکل پیشنهادی

Purpose: define the proposed Hybrid TreeKEM protocol.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Define notation and cryptographic primitives | Todo | X25519, Kyber/ML-KEM, HPKE/KEM, KDF, hash, signatures. |
| 2 | Define hybrid node structure | Todo | Each node stores classical public key, PQ public key, and derived hybrid secret. |
| 3 | Define hybrid leaf/key package structure | Todo | Must remain close to MLS key package concepts. |
| 4 | Define setup/group creation | Todo | Initial tree construction and root secret derivation. |
| 5 | Define add operation | Todo | How a new member receives both classical and PQ path information. |
| 6 | Define update operation | Todo | Most important operation for PCS. |
| 7 | Define remove operation | Todo | Must prevent removed members from learning future secrets. |
| 8 | Define hybrid KEM combiner | Todo | KDF over classical shared secret, PQ shared secret, public context, node/epoch labels. |
| 9 | Define MLS compatibility points | Todo | Identify which MLS fields change and which remain unchanged. |
| 10 | Provide protocol pseudocode | Todo | Use language-agnostic pseudocode, not programming-language code. |
| 11 | Security argument | Todo | Show security if at least one component remains secure. |

Key design principle: a single tree should contain both post-quantum and classical key pairs, instead of running two independent trees.

### Chapter 5: ارزیابی طرح پیشنهادی

Purpose: evaluate security and performance of the proposed design.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Define evaluation metrics | Todo | Runtime, bandwidth, ciphertext size, public key size, memory, update cost. |
| 2 | Define comparison baselines | Todo | Classical TreeKEM, naive hybrid TreeKEM, mKEM-based approaches if relevant. |
| 3 | Analyze complexity | Todo | Compare asymptotic and concrete costs. |
| 4 | Implement or simulate prototype | Todo | Measure group sizes such as 8, 32, 128, 512, 1024. |
| 5 | Evaluate security properties | Todo | Forward secrecy, PCS, hybrid security, replay/update-path integrity assumptions. |
| 6 | Evaluate MLS compatibility | Todo | Note deployment cost and message changes. |
| 7 | Present tables and charts | Todo | Keep comparison readable and tied to research questions. |

Expected evaluation claim: the proposed design increases bandwidth and computation compared with classical TreeKEM, but provides hybrid classical/PQ security and should keep TreeKEM-style logarithmic update behavior.

### Chapter 6: نتیجه گیری و پیشنهادها

Purpose: summarize findings, contributions, limitations, and future work.

| # | Task | Status | Notes |
|---|------|--------|-------|
| 1 | Summarize research problem and proposed solution | Todo | Keep it aligned with chapter 1 claims. |
| 2 | Summarize security and performance results | Todo | Use chapter 5 evidence, not broad claims. |
| 3 | State limitations | Todo | PQ key sizes, implementation complexity, formal proof limits. |
| 4 | Suggest future work | Todo | Multi-recipient optimization, formal verification, real MLS implementation, alternative PQ KEMs. |

## Working Method

1. Keep `PROJECT.md` as the single source of truth for roadmap and chapter progress.
2. Keep `SESSION-LOG.md` updated after every work session.
3. Work one topic at a time.
4. For chapter 3, read one related work, extract contribution/limits, then place it in the comparison table.
5. For chapter 4, design the protocol before implementing or evaluating.
6. For chapter 5, evaluate only claims that are actually supported by analysis or measurement.

## Current Focus

Current topic: Chapter 3 related works.

Next topic: finish the structured related-work summaries for the local papers in `related_works/`, then build the comparison table that motivates Chapter 4.
