@title Adaptive Arity and TreeCover Migration in Hybrid TreeKEM
@authors Mohammadreza Parsania and Hamid Mala
@affiliation Faculty of Computer Engineering, University of Isfahan, Isfahan, Iran

@abstract
Hybrid key establishment increases the communication cost of tree-based group messaging, while changing the tree arity introduces a separate cost of rebuilding shared state. This paper investigates a migration policy for hybrid TreeKEM that increases arity from two to four and, conceptually, from four to eight. Each valid node carries classical and post-quantum key material. During migration, the new tree becomes the sole source of the group commit secret, while an authenticated cover of eligible old-tree nodes temporarily delivers new path secrets. Subsequent commits populate the new tree, and normalized delivery costs guide retirement of the old cover. An analytical model accounts for public-key and encapsulation payload separately from other protocol fields. Under its healthy-tree approximation, increasing arity from two to four at 129 members reduces the modeled payload from 12,672 to 6,976 bytes, a 44.9% reduction. A leaf-only initial transition at 1,024 members instead requires eleven additional healthy commits to recover its modeled excess cost. Security is examined through conditional arguments rather than a formal proof. Retained old keys can prolong group-wide exposure after compromise, so a communication-cost threshold does not establish cryptographic recovery. The contribution is a migration design and explicit accounting of its efficiency and security tradeoffs.

@keywords TreeKEM; Messaging Layer Security; hybrid key establishment; multi-recipient KEM; adaptive tree arity; TreeCover

# Introduction

Messaging Layer Security (MLS) establishes shared cryptographic state for dynamic groups through authenticated membership changes and tree-based key updates [1]. A commit can refresh a path toward the root and distribute the necessary path secrets to other members. When usable internal keys exist, several members can receive a secret through one subtree key. Blank or invalidated nodes require a finer recipient resolution and can increase communication. Hybrid classical and post-quantum key establishment makes the cost of these public keys and encapsulations particularly relevant.

Multi-recipient key encapsulation mechanisms (mKEMs) reduce repeated ciphertext material when the same secret is sent to several recipients. Their application to TreeKEM, including trees of degree greater than two, is established prior work [2]. Tree shape and degree have also been studied as optimization parameters for MLS [3]. These results motivate a different operational question: how can a group change its tree arity without immediately rebuilding every shared internal key, and how should it decide when the retained old structure is no longer useful?

We investigate the adaptive design developed in the first author's master's thesis [4]. A transition introduces a new tree whose internal state is initially sparse. Eligible nodes of the old tree form a temporary TreeCover for delivering path secrets belonging to the new tree. Only the new root supplies the commit secret. As commits populate the new tree, delivery becomes less dependent on the old cover. A retirement policy compares the new and old structures against leaf-only and idealized delivery costs.

The contribution is the combination of an explicit migration lifecycle, temporary old-tree delivery, and a cost-based retirement rule. It is not a new KEM, the first use of hybrid cryptography in MLS, or the first proposal for higher-arity TreeKEM. We present the thesis construction as the authoritative design and derive its communication tradeoffs under explicit assumptions. The numerical examples are direct evaluations of the analytical formulas. The scope is protocol design, cost analysis, and conditional security reasoning.

Three distinctions organize the analysis. First, a healthy-tree byte formula accounts for selected cryptographic components rather than every protocol field. Second, lower costs for a mature tree do not imply that a migration has repaid its setup cost. Third, a reduction in delivery endpoints does not demonstrate post-compromise recovery. A complete computational security proof remains an open obligation.

# Background and related work

## Tree state and hybrid delivery

An MLS ratchet tree associates members with leaves and distributes private state according to subtree membership. Path derivation and recipient encryption have different roles: path secrets determine future node keys and the commit secret, whereas encryption delivers selected path secrets to members. This separation is retained in the proposed design. The hybrid output is an encryption input for path-secret transport; it is not itself the group epoch secret. The term hybrid in Hybrid Public Key Encryption denotes a KEM–KDF–AEAD composition [5]; it does not by itself mean a classical/post-quantum combiner. Integration must ultimately use the authenticated group context and the full MLS key schedule [1].

The IETF work on ML-KEM and hybrid MLS cipher suites provides a separate route to post-quantum deployment. Revision 06, dated 21 July 2026, specifies cipher-suite choices and remains an Internet-Draft [6]. The Amortized PQ MLS Combiner instead couples two MLS sessions and imports exported post-quantum material into the traditional session [7]. Revision 02 is an expired draft, dated 20 October 2025. Neither draft is an RFC. Our migration retains two structural versions temporarily, but does not run distinct classical and post-quantum MLS sessions.

## Multi recipient encryption and tree degree

Alwen et al. explicitly analyze mKyber for TreeKEM and for an m-ary variant [2, Section 4]. Sharing a large common ciphertext component makes additional recipients comparatively inexpensive. Consequently, a reduction in path depth may compensate for the greater number of siblings at each level. Their treatment already establishes the architectural motivation for higher arity. Our remaining question concerns migration between arities and management of the old keys during that process.

Chevalier et al. study tree evolution and degree selection for MLS [3]. Their reported preference for ternary trees under some post-quantum parameter sets reinforces that the useful degree depends on the cost model. The thesis restricts its candidate degrees to two, four, and eight; this restriction does not establish global optimality. Table 1 positions the present work relative to the closest approaches. A broader comparison should use the same topology assumptions and cost model across several candidate degrees.

@table Closest related approaches and the scope of the present contribution
Work | Main mechanism | Relationship to this study
MLS [1] | Standard ratchet-tree state and key schedule | Baseline architecture; this extension is not RFC interoperable
Alwen et al. [2] | mKyber and m-ary TreeKEM | Establishes multi-recipient and higher-arity motivation
Chevalier et al. [3] | Tree evolution and degree optimization | Tree degree is a pre-existing optimization variable
MLS drafts [6, 7] | Hybrid suites or two-session amortization | Different hybridization and update mechanisms
Present study | Lazy arity migration with an old-tree cover | Analyzes migration cost and retained-key exposure

## Security results that do not transfer automatically

KEM combiners require explicit assumptions and constructions to preserve security when one component fails [8]. X-Wing provides a concrete example using X25519, ML-KEM-768, and SHA3-256, with proofs tied to that construction [9]. Its proof cannot justify replacing ML-KEM-768 with an mKEM or changing the key derivation inputs. Likewise, the machine-checked symbolic TreeKEM analysis of Wallez et al. concerns a precise specification of MLS [10]; it does not automatically cover new arities, retained TreeCover keys, or a custom hybrid wrapper.

The distinction between mKyber and amKyber also matters. The mKyber source discusses a non-adaptive multi-user security treatment and a limitation of known reductions under adaptive corruptions; amKyber addresses the stronger setting with different costs [2]. This is a proof limitation, not evidence of a practical adaptive attack. Nevertheless, long-lived retained node keys make it inappropriate to assume that an adaptive group-security theorem follows from the smaller mKyber parameters. FIPS 203 standardizes ML-KEM, not this mKyber profile [11].

# Model and cryptographic specification

## Participants and state

Let n be the number of active members, e the epoch, and d the current arity. The candidate arities are 2, 4, and 8. A public node has a location and, when valid, a classical public key and a post-quantum public key. A member retains the private keys needed along its authorized path. A blank node has no usable shared node key. A node may also become ineligible because its secret was available to a removed member, even if a public key remains stored.

During migration the state comprises an old tree, a new tree, a fixed mapping between member identities and new leaves, a tree version, and authenticated transition metadata. The old tree is a delivery structure only. The new root is the unique authority for deriving the commit secret. At most one arity transition is active. This logical separation is needed to prevent receivers from treating a retained old root as an alternative source of epoch state.

The adversary may observe, delay, reorder, replay, or modify delivery traffic and may obtain member state through compromise. Confidentiality cannot be expected against an authorized member that currently knows the group secret. Statements about recovery concern a former compromise after the adversary has ceased obtaining fresh state, with authentication credentials and recipient selection satisfying the stated assumptions. No availability guarantee is asserted against a delivery service that suppresses messages.

## Node derivation and encapsulation

For node v, ps_v denotes a path secret and ns_v a node secret. Context ctx_(v,e) identifies the relevant group, epoch, tree version, arity, and node. The thesis uses separate labels for node derivation and upward path derivation:

@eq ns_{v} = KDFExpand(ps_{v}, "node" || ctx_{v,e})
@eq ps_{parent(v)} = KDFExpand(ps_{v}, "path" || ctx_{v,e})

The node secret feeds separately labeled classical-key and pq-key derivations. Their outputs seed the corresponding key-generation procedures. Domain separation is essential because the two key families and the upward path must not reuse a derivation purpose. Equations (1) and (2) express the thesis's design interface; they do not supply the missing byte-level choice of every KDF and encoding.

For a recipient node v, classical encapsulation yields a shared secret ss_v^C and ciphertext ct_v^C. The post-quantum component yields ss_v^PQ and recipient ciphertext material. In the multi-recipient case, a path level uses a shared mKyber component u_j and recipient components w_(j,v). The latter notation avoids confusing the recipient node v with the original mKyber ciphertext symbol v_i. Every key in an encapsulation set must belong to the same public mKyber parameter domain.

The authoritative thesis combiner, with the source's ambiguous symbol ct_xe replaced by its explicitly defined meaning, is

@eq hs_{v} = KDF(ss_{v}^{C} || ss_{v}^{PQ} || ct_{v}^{C} || Encode(pk_{v}^{C}) || label_{v})

Here label_v binds the string “HybridTreeKEM-Node” to the group identifier, epoch, tree version, arity, and recipient-node index. Encode(pk_v^C) denotes the canonical classical recipient public key. It is not a post-quantum ciphertext. The omission of raw post-quantum ciphertext from (3) is part of the thesis design, not a security result. The ciphertext still has to be transmitted, associated with the intended recipient, and authenticated as protocol data.

@eq (k_{v}, nonce_{v}) = KDFExpand(hs_{v}, "path-encryption" || ctx_{v,e})
@eq c_{v}^{path} = AEAD.Seal(k_{v}, nonce_{v}, aad_{v}, ps_{target})

The associated data binds delivery to the intended group and transition state. A receiver decapsulates both components, reconstructs (3) and (4), and authenticates (5). A failure rejects the delivery. The recovered path secret is propagated upward to the new root and then to the commit secret. That secret enters the MLS key-schedule interface; the abbreviated schedule equations in the thesis are not a substitute for the full labeled RFC derivations.

The thesis does not fully fix canonical encodings, KDF instantiation, output partitioning, associated-data serialization, or nonce management for every repeated delivery. Equations (1)–(5) therefore describe a proposed construction rather than an interoperable cryptographic specification. Fresh encapsulations and unique, authenticated delivery context are necessary obligations; their adequacy needs a construction-specific analysis. These unresolved choices limit the security conclusions that can be drawn from the design.

# Adaptive migration and TreeCover

## Starting and executing a transition

The thesis proposes increasing arity only after the group remains sufficiently large and an estimated saving exceeds a margin. Its illustrative settings require at least 128 members for five epochs for a 2-to-4 transition, and at least 2,048 members for ten epochs for a 4-to-8 transition. These settings are policy choices, not empirically optimized constants. Let q_e be a forecast number of future commits, B_d and B_dprime their modeled steady costs, B_tr the charged transition cost, and Δ a safety margin. The proposed economic condition is

@eq q_{e}(B_{d} - B_{dprime}) - B_{tr} > Delta

The cost convention must specify whether B_tr means total transition cost or only excess over staying in the old tree. Mixing the conventions changes the trigger. The group-size condition alone is insufficient: a group that soon shrinks or stops updating may never recover the setup cost. The forecast horizon and the safety margin require workload-specific justification before this rule can be treated as an operational recommendation.

On accepting a transition commit, members agree on the target arity, tree version, leaf mapping, and transition state. The new internal nodes begin blank; the initiating commit materializes its direct path. For every recipient subset needing a particular new-tree path secret, delivery first uses eligible new-tree nodes, then eligible old-tree cover nodes, and finally individual current leaves. The choice operates over subsets, not as a global minimum between two scalar cost totals.

@algorithm Starting and advancing a migration
> 1. Check the authenticated current state, policy conditions, and absence of another active transition.
> 2. Fix the target arity and identity-to-leaf mapping; bind them to the next accepted group state.
> 3. Initialize the new tree and derive fresh secrets on the committer's new direct path.
> 4. Partition each intended recipient set using eligible new nodes, eligible old cover nodes, then current leaves.
> 5. Encapsulate per nonempty level and encrypt each required path secret under the thesis hybrid construction.
> 6. Authenticate and process the commit; reject inconsistent versions, mappings, recipients, or derivations.
> 7. Continue deriving group state from the new root and reevaluate cover costs after accepted changes.

Algorithm 1 summarizes the thesis lifecycle at the design level. The precise cryptographic encodings remain to be specified. Figure 1 illustrates the distinct functions of the two tree versions: an old subtree key can deliver a new root path secret without becoming a second root authority.

@figure migration.png|Old tree delivery during lazy migration. For eight members, the new four-ary structure has a populated left path and a blank right internal node. An eligible old node covering members 5–8 can deliver the new root path secret. The old root does not derive the new epoch state.

## Eligibility and membership changes

Let S be the authorized recipient set for one delivery, and M(v) the set of current leaves associated with a selected node. A cover C must satisfy

@eq M(v) ⊆ S,   ⋃_{v∈C} M(v) = S,   M(v) ∩ M(w) = ∅  for v ≠ w

Equation (7) is a set-cover condition, not a complete security predicate. Each selected node must also have a usable authenticated key, and the recipients represented by it must possess the corresponding private state. Most importantly, a removed member that previously knew that key must not retain access to newly delivered secrets through it. Eligibility therefore depends on historical knowledge of the key, not merely the present labels below its node.

A removal invalidates affected path keys in both retained structures before selecting recipients for the next secret. Invalidated old nodes must be decomposed into safe descendants or replaced by current leaf delivery. New members conceptually join only the new tree and receive their initial state through a Welcome mechanism; they cannot be assumed to know old internal keys. This join behavior is a design requirement. A complete treatment must define how the authenticated mapping changes and how a new member obtains consistent state without receiving obsolete secrets.

Removing leaves can make an apparently mature tree less useful for the next committer. Updating one branch also does not populate every other branch. Migration progress should be assessed using the recipient sets actually under consideration, with an explicit aggregation convention if a group-wide statistic is desired. Node counts alone do not determine delivery cost.

## Cost normalized retirement

For the same target set, let C_leaf count leaf-only delivery endpoints, C_ideal count endpoints in the chosen fully populated reference, and C_new and C_old count delivery using the new and old structures separately. When C_leaf is strictly larger than C_ideal, define

@eq H_{new} = \frac{C_{leaf} - C_{new}}{C_{leaf} - C_{ideal}},   H_{old} = \frac{C_{leaf} - C_{old}}{C_{leaf} - C_{ideal}}

The thesis retirement policy is

@eq retire ⇐ (H_{new} ≥ theta_{new}) ∨ (H_{old} < theta_{old})

For 2-to-4 migration it proposes theta_new = 0.70 and theta_old = 0.50; for 4-to-8 migration the new-tree threshold becomes 0.80. The disjunction permits retirement either because the new tree is sufficiently useful or because the old cover has become comparatively unhelpful. It does not require both conditions.

These ratios are cost measures, despite the thesis's “health” terminology. Their range is not automatically [0,1]: for example, an old cover cheaper than the selected ideal new-tree reference produces H_old greater than one. Equal leaf and ideal costs make the denominator zero. A complete policy must define what happens for zero denominators and out-of-range values. Equation (8) defines unmodified ratios on the stated domain, and Equation (9) preserves the thesis's inequality.

Retirement must be an authenticated state change accepted consistently by remaining members, followed by removal of the retained old-key envelope. Cost authorization alone cannot perform this change. Nor does local erasure delete copies obtained by an adversary. The informal update windows in the thesis are planning heuristics and do not establish a fixed number of commits for either retirement or security recovery.

# Conditional security analysis

## Confidentiality and authentication obligations

The intended hybrid property is that path-secret confidentiality survives failure of one key-establishment component. Establishing that property for (3) requires a precise adversarial game and a reduction for the actual KDF, encapsulation mechanisms, encodings, and validity checks. A suitable robust combiner, correct authenticated encryption, authenticated public keys, and independent component randomness are assumptions for the argument here. They are not consequences of concatenation alone [8, 9]. The thesis provides no construction-specific computational proof.

The transition adds an authentication obligation beyond encapsulation. Members must agree on the active arity, root authority, tree version, frozen mapping, and applicable old keys. Otherwise, even an honestly encrypted path secret could be interpreted in different trees. A receiver should accept state changes only after validating the commit and its bound transition context. A precise proof would have to connect these checks to a group-state agreement invariant across adds, removals, updates, and retirement. The existing symbolic proof for standard TreeKEM cannot simply be reused [10].

The hybrid encapsulation design does not itself specify a post-quantum replacement for classical signatures. A post-quantum confidentiality aspiration therefore must not be described as full protection against an active quantum adversary capable of forging the retained classical signatures. In particular, the design must distinguish a passive adversary recording traffic for later decryption from an attacker that can already impersonate members. Credential compromise and credential recovery also require their own model.

## Forward secrecy and retained state

Forward secrecy requires protection of earlier traffic after later state compromise. One-way path derivation and erasure of obsolete state support this goal only under an appropriate key-evolution argument. TreeCover deliberately extends the lifetime of some old private keys. A later compromise of a retained key may expose recorded migration ciphertexts addressed to that key. Whether those recovered path secrets expose a particular earlier epoch additionally depends on the key-schedule state available to the adversary. Retention therefore changes the relevant exposure window and cannot be dismissed as a harmless storage optimization.

A complete protocol needs explicit key lifetimes and a record of which key generations were available to which members. It must invalidate removed-member knowledge, erase superseded state when no longer needed, and reject reuse of a retired version. Removing retained state does not establish that no earlier copies exist. The available evidence does not provide a general secure-erasure theorem.

## Post compromise recovery can be group wide

Consider an attacker that copied a member's state, including an old cover private key and the relevant preceding epoch state. If a later commit still encrypts a useful new-tree path secret to that old key, the attacker can recover it and derive upward to the new root. With the necessary previous key-schedule inputs, the attacker can continue deriving group epoch state. The disclosure is not confined to the leaves below that old node: the recovered root contribution affects the group's common secret.

Consequently, recovery requires that the attacker lose access to every delivery route capable of revealing the fresh contribution, under the relevant compromise scenario. An honest update is insufficient if the same contribution remains accessible through an attacker-known cover key. Continued compromise or an authorized malicious recipient prevents the desired recovery regardless of arity. This is a conditional argument about secret dependencies.

Neither H_new nor H_old measures adversarial knowledge. A high H_new can coexist with one unsafe retained route, and a low H_old says little about the confidentiality of the routes still used. A security-driven retirement policy would need additional freshness and knowledge conditions. Without assumptions about update scheduling, honest entropy injection, and elimination of compromised routes, no finite bound on post-compromise recovery follows from the proposed cost thresholds.

# Communication and resource analysis

## Accounting by component

Let h be the number of published nonleaf path-node key pairs, L the number of nonempty encapsulation levels, q_j the number of delivery endpoints at level j, and R their total. For the analytical parameter setting, take 32-byte classical public keys and encapsulations. The mKyber parameters are a 768-byte public key, a 704-byte common ciphertext, and a 48-byte per-recipient component [2, Table 1]. The resulting key-and-KEM payload is

@eq R = ∑_{j=1}^{L} q_{j},   B_{core} = 800h + 704L + 80R

The 800h term publishes both public keys; 704L charges one common component at each used level; and 80R charges a classical encapsulation and a post-quantum recipient component. These coefficients specify the lengths of the selected cryptographic components. Fragmented recipient resolutions increase R without necessarily changing h.

Equation (10) excludes the encrypted path-secret payload, its authentication tag, signatures, proposals, leaf objects, vector lengths, and other framing. If each recipient receives one 32-byte path secret with a 16-byte authentication tag, the accounted cryptographic payload becomes B_core + 48R before the remaining framing. This conditional extension illustrates how payload assumptions affect the accounting; the remaining protocol fields would require further terms.

For a fully populated balanced reference, approximate h by the rounded height h_d(n), take L = h, and take R = (d − 1)h:

@eq h_{d}(n) = ⌈log_{d}(n)⌉,   B_{healthy}(d,n) = [1504 + 80(d - 1)]h_{d}(n)

The resulting per-level coefficients are 1,584, 1,744, and 2,064 bytes for degrees two, four, and eight. A partially filled tree need not have d − 1 occupied siblings at every level. Equation (11) is therefore an idealized reference approximation, not the exact cost for every population or tree shape. In particular, its ceiling-induced jumps arise from rounding the reference height.

@table Recalculated healthy reference payload in bytes under Equation 11
Members | Binary | Four ary | Eight ary
128 | 11,088 | 6,976 | 6,192
129 | 12,672 | 6,976 | 6,192
512 | 14,256 | 8,720 | 6,192
1,024 | 15,840 | 8,720 | 8,256
1,025 | 17,424 | 10,464 | 8,256
2,048 | 17,424 | 10,464 | 8,256
4,096 | 19,008 | 10,464 | 8,256

Table 2 evaluates Equation (11) directly for the listed group sizes. At n = 129 the binary-to-four-ary reduction is 5,696/12,672 = 44.95%. At n = 1,025 the four-to-eight-ary reduction is 2,208/10,464 = 21.10%. These are reductions in the modeled components only. The latter mathematical opportunity also occurs below the thesis's proposed 2,048-member transition threshold, illustrating the difference between a cost curve and an operational policy.

## Initial cost and amortization

If no usable internal cover exists, a transition may deliver to n − 1 leaves. A simplified first-commit model for target arity d′ is

@eq B_{first} ≈ 1504h_{dprime}(n) + 80(n - 1)

Assume for this calculation that every subsequent commit immediately achieves the healthy target-tree cost. Let B_old and B_new be the reference costs of remaining in the old tree and operating in the new tree. When B_old > B_new, the additional number of healthy commits needed after the first transition commit is

@eq Q = ⌈max(0, \frac{B_{first} - B_{old}}{B_{old} - B_{new}})⌉

Equation (13) compares the transition with an old-tree commit in the same first position. It consequently charges only the excess B_first − B_old. Table 3 evaluates Equations (11)–(13) for illustrative group sizes, using the displayed model inputs. When the denominator is nonpositive, this steady-cost model gives no positive amortization benefit.

@table Illustrative break even under immediate healthy follow up commits
Transition | Members | B_old | B_first | B_new | Q
2 to 4 | 129 | 12,672 | 16,256 | 6,976 | 1
2 to 4 | 1,024 | 15,840 | 89,360 | 8,720 | 11
4 to 8 | 1,025 | 10,464 | 87,936 | 8,256 | 36
4 to 8 | 2,048 | 10,464 | 169,776 | 8,256 | 73
4 to 8 | 4,096 | 10,464 | 333,616 | 8,256 | 147

The assumptions pull in different directions. Leaf-only delivery can overstate the first cost when TreeCover is useful, whereas immediate maturity understates later costs when the new tree remains sparse. The table is therefore a scenario calculation, not a guaranteed upper or lower bound for complete migration. A complete analytical comparison must instead sum the costs for the same sequence of group changes, including the transition, subsequent delivery, retirement, and any additional setup or Welcome traffic.

## Occupancy and asymptotic limits

The thesis also considers a simplified occupancy argument. For a fixed subtree of s members in a static group of n, after t independent uniformly chosen member updates, the probability of at least one update in that subtree and its associated one-node-versus-leaves cost are

@eq p_{s}(t) = 1 - (1 - s/n)^{t},   E[c_{s}(t)] = 1 + (s - 1)(1 - s/n)^{t}

This model assumes that an update in the subtree makes its relevant aggregate key usable and that no later removal invalidates it. Summing the second expression requires an explicit set of disjoint relevant subtrees. It does not justify using the same distribution after conditioning on “effective” updates, nor does it predict costs for arbitrary churn. The formula therefore supplies intuition for gradual population only under the stated sampling and key-validity assumptions.

For fixed arity, storing the public tree takes O(n) space and a member's path private state takes O(log n) space. Retaining old and new structures preserves these asymptotic orders while increasing constants. Complete-tree information in a Welcome can remain linear in n. Similarly, a commit's upload size and a delivery service's total broadcast volume are different: transmitting a full B-byte object to n receivers can cost approximately nB bytes.

# Discussion and limitations

The design shifts part of an arity change from an immediate rebuild into subsequent ordinary commits. TreeCover provides a concrete way to make that shift: old internal keys can reduce leaf-level delivery while the new tree acquires usable internal state. The same retained keys prolong dependencies on historical secrets. Communication efficiency and compromise recovery must therefore be treated as separate objectives, even when both motivate refreshing tree state.

The analytical savings show where the chosen parameter dimensions can make a higher arity attractive. They do not determine the best arity or threshold. A broader analytical treatment should include ternary and other degrees, exact occupied topology, heterogeneous update frequencies, repeated removals, and cumulative costs over both growing and shrinking groups. Fixed-degree, immediate-rebuild, and TreeCover policies should be compared for the same mathematical sequence of group changes, with setup, Welcome, and retirement costs included.

The most urgent protocol work is to finalize the thesis combiner, its encodings, and the state-transition rules. A security model must track historical node-key knowledge during migration, distinguish passive post-quantum confidentiality from active authentication, and define the conditions for recovery. A formal treatment should include authenticated tree-version agreement, removal eligibility, and atomic retirement at each receiver. The present conditional analysis identifies these obligations without claiming that they have been discharged.

The analytical scope also has limits. The healthy reference replaces exact occupied topology by a rounded-height approximation, while the break-even examples assume immediate healthy operation after transition. A tighter analysis would bound the cumulative delivery cost while the new tree remains sparse and would specify how changes in membership affect those bounds. Such a result is not supplied by the present examples.

# Conclusion

Adaptive arity in hybrid TreeKEM is useful only if the costs and security consequences of changing the tree are included. The thesis design makes the new root authoritative immediately and uses an old-tree TreeCover to deliver new path secrets during gradual population. Its reference model exhibits lower mature-tree key-and-KEM payload at selected larger arities, while the transition examples show that repaying initial cost can require many later commits. These analytical examples do not prove the construction secure or establish that one migration policy has lower cumulative cost for every sequence of group changes. TreeCover is therefore best understood as a migration mechanism whose efficiency policy must be complemented by explicit key-freshness, authentication, and recovery conditions.

# Research provenance and availability

This article derives from Mohammadreza Parsania's Persian master's thesis, Hybrid Group Key Exchange based on TreeKEM, University of Isfahan, 2026 [4]. All numerical examples in this article are calculated from the equations and parameter lengths stated in the text.

OpenAI Codex assisted with Persian-to-English synthesis, manuscript organization, literature checking, consistency analysis, and document preparation. This assistance also contributed to the explicit qualification of security and analytical claims. Scientific assessment and responsibility for the final text remain with the authors.

# References

@ref 1|Richard Barnes, Benjamin Beurdouche, Raphael Robert, Jon Millican, Emad Omara, and Katriel Cohn-Gordon. The Messaging Layer Security (MLS) Protocol. RFC 9420, July 2023.|https://doi.org/10.17487/RFC9420
@ref 2|Joël Alwen, Matthew Campagna, Dominik Hartmann, Shuichi Katsumata, Eike Kiltz, Jake Massimo, Marta Mularczyk, Guillermo Pascual-Perez, Thomas Prest, and Peter Schwabe. How Multi-Recipient KEMs can help the Deployment of Post-Quantum Cryptography. Paper presented at the Fifth NIST PQC Standardization Conference, 2024, 15 pages.|https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/how-multi-recipient-kems.pdf
@ref 3|Céline Chevalier, Guirec Lebrun, Ange Martinelli, and Jérôme Plût. The Art of Bonsai: How Well-Shaped Trees Improve the Communication Cost of MLS. Cryptology ePrint Archive, Paper 2024/746, 2024; revised 11 April 2025.|https://eprint.iacr.org/2024/746
@ref 4|Mohammadreza Parsania. Hybrid Group Key Exchange based on TreeKEM. Master's thesis, University of Isfahan, 2026. In Persian, with an English title and abstract.|
@ref 5|Richard Barnes, Karthikeyan Bhargavan, Benjamin Lipp, and Christopher A. Wood. Hybrid Public Key Encryption. RFC 9180, February 2022.|https://doi.org/10.17487/RFC9180
@ref 6|Rohan Mahy and Richard L. Barnes. ML-KEM and Hybrid Cipher Suites for Messaging Layer Security. Internet-Draft draft-ietf-mls-pq-ciphersuites-06, 21 July 2026. Work in progress.|https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/06/
@ref 7|Xisen Tian, Britta Hale, Marta Mularczyk, and Joël Alwen. Amortized PQ MLS Combiner. Internet-Draft draft-ietf-mls-combiner-02, 20 October 2025. Expired 23 April 2026; work in progress.|https://datatracker.ietf.org/doc/html/draft-ietf-mls-combiner-02
@ref 8|Federico Giacon, Felix Heuer, and Bertram Poettering. KEM Combiners. In Public-Key Cryptography – PKC 2018, Part I, Lecture Notes in Computer Science 10769, pp. 190–218. Springer, 2018.|https://doi.org/10.1007/978-3-319-76578-5_7
@ref 9|Manuel Barbosa, Deirdre Connolly, João Diogo Duarte, Aaron Kaiser, Peter Schwabe, Karolin Varner, and Bas Westerbaan. X-Wing: The Hybrid KEM You've Been Looking For. IACR Communications in Cryptology 1(1), 2024, 22 pages.|https://doi.org/10.62056/a3qj89n4e
@ref 10|Théophile Wallez, Jonathan Protzenko, and Karthikeyan Bhargavan. TreeKEM: A Modular Machine-Checked Symbolic Security Analysis of Group Key Agreement in Messaging Layer Security. Cryptology ePrint Archive, Paper 2025/410, 2025. Author version of the IEEE Symposium on Security and Privacy paper.|https://eprint.iacr.org/2025/410
@ref 11|National Institute of Standards and Technology. Module-Lattice-Based Key-Encapsulation Mechanism Standard. FIPS 203, 13 August 2024.|https://doi.org/10.6028/NIST.FIPS.203
