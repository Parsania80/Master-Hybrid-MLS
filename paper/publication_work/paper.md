@title Adaptive Arity and Tree Migration in Hybrid TreeKEM
@authors Mohammadreza Parsania and Hamid Mala
@affiliation Faculty of Computer Engineering, University of Isfahan, Isfahan, Iran

@abstract
Hybrid key establishment combines classical and post-quantum cryptography to reduce reliance on either component alone during the transition to quantum-resistant communication. Messaging Layer Security (MLS) is a protocol that establishes shared keys for end-to-end encrypted group communication. Its TreeKEM mechanism updates these keys as group membership changes. Combining classical and post-quantum cryptography increases the amount of data transmitted during these key updates. We propose a migration mechanism that changes the number of children per internal node from two to four and considers a later change to eight. During a transition, members use suitable keys from the old tree to encrypt the secret values needed to establish keys in the new tree. Subsequent updates establish additional internal keys, and a communication-cost criterion determines when to discard the old tree. For a balanced tree with all required internal keys available, our analysis estimates that changing from two to four children at 129 members reduces the public-key and encapsulation data per update by 44.9%, from 12,672 to 6,976 bytes. These figures exclude other message fields. In the 1,024-member example, the first update in the new four-ary tree encrypts separately for each of the other 1,023 members and costs more than a binary-tree update. Eleven subsequent updates offset this extra cost, assuming each immediately achieves the lower cost of a fully populated four-ary tree. The security evaluation explains why retaining old keys can delay recovery after compromise and states the assumptions behind the security argument.

@keywords TreeKEM; Messaging Layer Security; hybrid key establishment; multi-recipient KEM; adaptive tree arity; tree migration

# Introduction

Group key exchange allows the members of a messaging group to establish the shared secrets needed to protect their communication. When members join or leave, the group must update these secrets so that new members cannot read earlier messages and removed members cannot read later ones. Efficient updates matter when groups are large or their membership changes frequently [1].

Messaging Layer Security (MLS) provides asynchronous key establishment for dynamic groups [1]. Its TreeKEM mechanism represents members as leaves of a binary tree. Each nonblank node contains a public encryption key. A shared internal private key allows several members of a subtree to decrypt the same update.

In MLS, an epoch is a group state in which a fixed set of authenticated members share an epoch secret used to derive keys for protecting their messages [1]. A member called the committer sends an authenticated control message, called a Commit, to start the next epoch. It applies proposed changes, such as adding or removing a member or updating a key [1]. When it includes an update path, the Commit carries fresh public keys and encrypted path secrets. These secrets are derived from fresh randomness chosen by the committer and determine updated node keys and a fresh contribution to the next epoch's secrets. This supports post-compromise security (PCS), meaning recovery after earlier key exposure, provided the attacker can no longer access the affected member's current state and cannot recover the fresh secrets [1].

A key encapsulation mechanism (KEM) lets a sender use a recipient's public key to generate a shared secret and a ciphertext; the recipient recovers that secret using its private key [11]. A multi-recipient KEM (mKEM) establishes the same secret with several recipients while sharing part of the ciphertext [2]. This can reduce the communication needed to encrypt a path secret for several subtrees. An IETF draft proposes MLS cipher suites that combine classical and post-quantum key establishment [6]. Here, hybrid TreeKEM refers to a TreeKEM construction in which each usable node carries both classical and post-quantum key material. Publishing both public keys and transmitting both encapsulation components increases the communication cost of a key update.

Alwen et al. study mKyber, a post-quantum mKEM, in TreeKEM and in a variant with more than two children per internal node [2]. A larger number of children reduces tree depth, so an update publishes fewer node public keys and fewer common ciphertext components. It also increases the number of sibling subtrees that must receive a secret at each level. Because mKyber shares a large ciphertext component, the reduction in depth can outweigh the cost of these additional recipients. Keeping a binary tree can therefore require more communication for the parameter sets considered here. Chevalier et al. also show that the best tree degree depends on the cryptographic parameter set. In their analysis, binary trees are preferable with classical algorithms, while ternary trees are generally more efficient with post-quantum algorithms. By improving how the tree grows and selecting a suitable degree, they reduce TreeKEM communication by 5-10% for the parameter sets studied [3].

These results motivate changing the tree degree as the group grows. The transition itself, however, has a cost. The new internal nodes initially lack shared keys, and rebuilding every internal key immediately can require many separate encryptions. The problem addressed in this paper is how to change the tree degree while distributing the required secrets during this initial period, and how to decide when the old tree can be discarded.

We retain the old tree temporarily while establishing a new tree. Only the new tree determines the fresh contribution used to derive the group's next keys. If a required internal key in the new tree is unavailable, the sender encrypts the path secret using suitable nodes of the old tree, or separately for individual current members. A retained node may be used only if its key is authenticated, its intended recipients possess the private key, and removed members cannot use it to obtain the new secret. Later Commit messages establish more internal keys in the new tree.

## Our Contribution

We propose a migration mechanism for hybrid TreeKEM that combines an increase in tree degree with gradual establishment of internal keys. It specifies how members agree on the new tree, use keys from the old tree to distribute new path secrets, and eventually discard the old tree. The retirement rule measures each tree's savings relative to encrypting separately for individual members, normalized against a fully populated target tree. The old tree is discarded when the new tree provides sufficient savings or when the old tree provides too little saving, according to stated thresholds.

We evaluate the communication costs of transmitting public keys and KEM ciphertexts, including the initial transition cost and the number of subsequent updates needed to offset it under explicit assumptions. The examples show a 44.9% reduction in these components for a four-ary tree at 129 members, while the 1,024-member transition example requires eleven further updates to offset its initial extra cost if each immediately achieves the cost of a fully populated four-ary tree. Our security analysis examines recipient selection and retention of old keys. If the committer uses a public key from the old tree to encrypt a fresh path secret, an attacker who copied the matching private key can recover that secret. The retirement thresholds measure communication savings, so meeting them gives no assurance that the attacker has lost access to fresh path secrets. A complete computational proof for the migration protocol remains future work.

## Paper Organisation

Section 2 reviews TreeKEM, hybrid key establishment, and related work. Section 3 defines the group state and explains how members derive path secrets and node keys and how the committer encrypts path secrets for recipients. Section 4 presents the migration mechanism and the rule for discarding the old tree. Section 5 analyzes its security conditions. Section 6 evaluates communication and storage costs. Section 7 discusses limitations and future work, and Section 8 concludes the paper.

# Background and related work

We first review how TreeKEM distributes path secrets in MLS and how related proposals combine classical and post-quantum key establishment. We then discuss how multi-recipient encryption and tree degree affect communication costs and which security guarantees for KEMs and their combiners inform our analysis.

## Tree state and hybrid delivery

An MLS ratchet tree associates members with leaves and distributes private state according to subtree membership. Members use path secrets to derive updated node keys and the commit secret. The committer encrypts the required path secrets using the public keys of suitable tree nodes and includes the ciphertexts in the Commit message. Recipients use the corresponding private keys to recover the secrets and derive the updated keys [1]. This separation is retained in the proposed scheme. The hybrid output is an encryption input for path-secret transport; it is not itself the group epoch secret. The term hybrid in Hybrid Public Key Encryption denotes a KEM–KDF–AEAD composition [5]; it does not by itself mean a classical/post-quantum combiner. Integration must ultimately use the authenticated group context and the full MLS key schedule [1].

One IETF draft proposes MLS cipher suites that combine classical and post-quantum key establishment within a single MLS session [6]. A separate draft, the Amortized PQ MLS Combiner, uses a secret exported from a post-quantum MLS session as a pre-shared key in a classical MLS session [7]. During an arity change, our scheme temporarily keeps the old and new ratchet trees in the same MLS session.

## Multi recipient encryption and tree degree

Alwen et al. explicitly analyze mKyber for TreeKEM and for an m-ary variant [2]. Sharing a large common ciphertext component makes additional recipients comparatively inexpensive. Consequently, a reduction in path depth may compensate for the greater number of siblings at each level. Their treatment already establishes the architectural motivation for higher arity. Our remaining question concerns migration between arities and management of the old keys during that process.

Chevalier et al. study tree evolution and degree selection for MLS [3]. Their reported preference for ternary trees under some post-quantum parameter sets reinforces that the useful degree depends on the cost model. We restrict the candidate degrees to two, four, and eight; this restriction does not establish global optimality. Table 1 positions the present work relative to the closest approaches. A broader comparison should use the same topology assumptions and cost model across several candidate degrees.

@table Closest related approaches and the scope of the present contribution
Work | Main mechanism | Relationship to this study
MLS [1] | Standard ratchet-tree state and key schedule | Baseline architecture; this extension is not RFC interoperable
Alwen et al. [2] | mKyber and m-ary TreeKEM | Establishes multi-recipient and higher-arity motivation
Chevalier et al. [3] | Tree evolution and degree optimization | Tree degree is a pre-existing optimization variable
MLS drafts [6, 7] | Hybrid suites or two-session amortization | Combine algorithms within a cipher suite [6] or link two MLS sessions [7]
This work | Gradual migration using keys from the old tree | Analyzes migration cost and retained-key exposure

## Established KEM security and protocol scope

KEM combiners have established security guarantees under precise component assumptions [8]. Barbosa et al. analyze the combiner used by X-Wing under two sets of assumptions [9]. One analysis relies on the underlying KEM’s security against chosen-ciphertext attacks (IND-CCA) and assumes the hash function behaves as a pseudorandom function. The other relies on the strong Diffie–Hellman assumption, ciphertext second-preimage resistance (C2PRI) of the KEM, and a hash function modeled as a random oracle. These results guide the analysis of other KEMs that satisfy the same assumptions. Similarly, the symbolic TreeKEM proof establishes guarantees for its specified MLS protocol [10]. FIPS 203 standardizes the single-recipient KEM ML-KEM [11]. The multi-recipient scheme used in our cost analysis is mKyber, which Alwen et al. specify and analyze separately [2].

mKyber enjoys standard non-adaptive multi-user IND-CCA security [2]. For ciphertext binding, Alwen et al. show that their Fujisaki–Okamoto (FO) construction is collision resistant if the hash function used to derive the shared key is collision resistant [12]. For a fixed recipient, mKyber includes (u,v_i) in the final KDF input whether the re-encryption check passes or fails (Algorithm 9 in Alwen et al. [2]). With unambiguous encoding, two distinct recipient ciphertexts that yield the same shared key therefore give a KDF collision. Thus, per-recipient C2PRI follows under the assumption that the final KDF is collision resistant.

Alwen et al. also describe amKyber, a variant of mKyber with a stronger security guarantee. In its security model, an attacker can choose which recipients’ private keys to obtain as the attack proceeds. This is known as adaptive corruption [2].

# Model and cryptographic specification

## Participants and state

Let n be the number of active members, e the epoch number, and d the arity of the current ratchet tree. We consider arities 2, 4, and 8. A node is identified by its position in its ratchet tree. The public copy of the tree records the classical and post-quantum public keys of each nonblank node. A member’s direct path starts at the parent of its leaf and ends at the root. The member stores the private keys for its leaf and for the nodes on that path whose keys it has received or derived [1]. A blank node has no usable shared node key. A node may also become ineligible because its secret was available to a removed member.

In this model, the epoch state includes the group context, the ratchet tree, and the secrets used to derive the keys for the current epoch. During migration, members also keep the old tree, a fixed mapping from member identities to leaves in the new tree, and authenticated information identifying the transition and tree version. The committer can use an eligible public key from the old tree to encrypt a path secret for the new tree. A recipient uses the matching private key to recover that secret and derives path secrets up to the root of the new tree. Members derive the commit secret from the path secret at the new root. At most one arity transition is active.

The adversary may observe, delay, reorder, replay, or modify delivery traffic. Compromising a member may reveal the private data stored by that member, including its tree private keys and any secrets it holds for the current epoch. Confidentiality cannot be expected against an authorized member that currently knows the group secret. The recovery analysis assumes that the adversary has stopped obtaining new private data from the member and that the stated conditions on authentication and recipient selection hold. No availability guarantee is asserted against a delivery service that suppresses messages.

## Secret derivation and key encapsulation

For node v, ps_v denotes a path secret and ns_v a node secret. Context ctx_(v,e) identifies the relevant group, epoch number, tree version, arity, and node identity. The node secret is computed as follows:

@eq ns_{v} = KDFExpand(ps_{v}, "node" || ctx_{v,e})

Given ps_v, the parent’s path secret is computed as follows:

@eq ps_{parent(v)} = KDFExpand(ps_{v}, "path" || ctx_{v,e})

The committer derives two seeds from the node secret. It uses one label for the seed of the classical key pair and another label for the seed of the post-quantum key pair. It passes each seed to the corresponding key generation algorithm. These labels distinguish the two seed derivations from each other and from the derivation of the parent’s path secret. Equations (1) and (2) describe how to derive the node secret and the parent’s path secret. The choice of KDF and the byte encodings remain to be specified.

For a recipient node v, classical encapsulation yields a shared secret ss_v^C and ciphertext ct_v^C. The post-quantum component yields ss_v^PQ and recipient ciphertext material. In the multi-recipient case, a path level uses a shared mKyber component u_j and recipient components w_(j,v). The latter notation avoids confusing the recipient node v with the original mKyber ciphertext symbol v_i. Every key in an encapsulation set must belong to the same public mKyber parameter domain.

The hybrid shared secret for recipient node v is

@eq hs_{v} = KDF(ss_{v}^{C} || ss_{v}^{PQ} || ct_{v}^{C} || Encode(pk_{v}^{C}) || label_{v})

Here label_v binds the string “HybridTreeKEM-Node” to the group identifier, epoch, tree version, arity, and recipient-node index. Encode(pk_v^C) denotes the canonical classical recipient public key. It is not a post-quantum ciphertext. Equation (3) omits the post-quantum ciphertext as a direct input to the combiner. Theorem 1 of the X-Wing paper uses C2PRI of the underlying KEM in its proof based on the strong Diffie–Hellman assumption [9]. Theorem 5 of Alwen et al. establishes ciphertext collision resistance for their FO construction, which rejects invalid ciphertexts and returns a hash of the recovered message for valid ones [12]. The mKyber decapsulation in [2] returns a fallback key for invalid ciphertexts and includes the ciphertext when deriving the output key. Using the conditional C2PRI result from Section 2.3 in the X-Wing proof approach for Equation (3) still requires justifying the other assumptions of the combiner theorem. The delivery context must still bind the intended recipient and be authenticated as protocol data.

@eq (k_{v}, nonce_{v}) = KDFExpand(hs_{v}, "path-encryption" || ctx_{v,e})
@eq c_{v}^{path} = AEAD.Seal(k_{v}, nonce_{v}, aad_{v}, ps_{target})

The associated data binds delivery to the intended group and transition state. A receiver decapsulates both components, reconstructs (3) and (4), and authenticates (5). A failure rejects the delivery. The recovered path secret is propagated upward to the new root and then to the commit secret. That secret enters the MLS key-schedule interface; the abbreviated schedule equations used here are not a substitute for the full labeled RFC derivations.

The present specification does not fully fix canonical encodings, KDF instantiation, output partitioning, associated-data serialization, or nonce management for every repeated delivery. Equations (1)–(5) therefore describe a proposed construction rather than an interoperable cryptographic specification. Fresh encapsulations and unique, authenticated delivery context are necessary obligations; their adequacy needs a construction-specific analysis. These unresolved choices limit the security conclusions that can be drawn from the design.

# Adaptive tree migration

## Starting and executing a transition

We propose increasing arity only after the group remains sufficiently large and an estimated saving exceeds a margin. Its illustrative settings require at least 128 members for five epochs for a 2-to-4 transition, and at least 2,048 members for ten epochs for a 4-to-8 transition. These settings are policy choices, not empirically optimized constants. Let q_e be a forecast number of future commits, B_d and B_dprime their modeled steady costs, B_tr the charged transition cost, and Δ a safety margin. The proposed economic condition is

@eq q_{e}(B_{d} - B_{dprime}) - B_{tr} > Delta

The cost convention must specify whether B_tr means total transition cost or only excess over staying in the old tree. Mixing the conventions changes the trigger. The group-size condition alone is insufficient: a group that soon shrinks or stops updating may never recover the setup cost. The forecast horizon and the safety margin require workload-specific justification before this rule can be treated as an operational recommendation.

On accepting a transition commit, members agree on the target arity, tree version, leaf mapping, and transition state. The new internal nodes begin blank; the initiating commit materializes its direct path. For every recipient subset needing a particular new-tree path secret, delivery first uses eligible new-tree nodes, then suitable nodes of the old tree, and finally individual current leaves. The choice operates over subsets, not as a global minimum between two scalar cost totals.

@algorithm Starting and advancing a migration
> 1. Check the authenticated current state, policy conditions, and absence of another active transition.
> 2. Fix the target arity and identity-to-leaf mapping; bind them to the next accepted group state.
> 3. Initialize the new tree and derive fresh secrets on the committer's new direct path.
> 4. Partition each intended recipient set using eligible new nodes, suitable nodes of the old tree, then current leaves.
> 5. Encapsulate per nonempty level and encrypt each required path secret under the hybrid construction.
> 6. Authenticate and process the commit; reject inconsistent versions, mappings, recipients, or derivations.
> 7. Continue deriving commit secrets from the new tree and reevaluate delivery costs after accepted changes.

Algorithm 1 summarizes the migration lifecycle at the design level. The precise cryptographic encodings remain to be specified. Figure 1 shows how the committer can use an old tree key to encrypt a path secret for the new root. Members use that path secret to derive the commit secret.

@figure migration.png|Old tree delivery during lazy migration. For eight members, the new four-ary structure has a populated left path and a blank right internal node. An eligible old node covering members 5–8 can deliver the new root path secret. Members derive the commit secret from the path secret at the new root.

## Eligibility and membership changes

Let S be the authorized recipient set for one delivery, and M(v) the set of current leaves associated with a selected node. A cover C must satisfy

@eq M(v) ⊆ S,   ⋃_{v∈C} M(v) = S,   M(v) ∩ M(w) = ∅  for v ≠ w

Equation (7) is a set-cover condition, not a complete security predicate. Each selected node must also have a usable authenticated key, and the recipients represented by it must possess the corresponding private state. Most importantly, a removed member that previously knew that key must not retain access to newly delivered secrets through it. Eligibility therefore depends on historical knowledge of the key, not merely the present labels below its node.

A removal invalidates affected path keys in both retained structures before selecting recipients for the next secret. Invalidated old nodes must be decomposed into safe descendants or replaced by current leaf delivery. New members conceptually join only the new tree and receive their initial state through a Welcome mechanism; they cannot be assumed to know old internal keys. This join behavior is a design requirement. A complete treatment must define how the authenticated mapping changes and how a new member obtains consistent state without receiving obsolete secrets.

Removing leaves can make an apparently mature tree less useful for the next committer. Updating one branch also does not populate every other branch. Migration progress should be assessed using the recipient sets actually under consideration, with an explicit aggregation convention if a group-wide statistic is desired. Node counts alone do not determine delivery cost.

## Cost normalized retirement

For the same target set, let C_leaf count leaf-only delivery endpoints, C_ideal count endpoints in the chosen fully populated reference, and C_new and C_old count delivery using the new and old structures separately. When C_leaf is strictly larger than C_ideal, define

@eq H_{new} = \frac{C_{leaf} - C_{new}}{C_{leaf} - C_{ideal}},   H_{old} = \frac{C_{leaf} - C_{old}}{C_{leaf} - C_{ideal}}

The retirement rule is

@eq retire ⇐ (H_{new} ≥ theta_{new}) ∨ (H_{old} < theta_{old})

For 2-to-4 migration it proposes theta_new = 0.70 and theta_old = 0.50; for 4-to-8 migration the new-tree threshold becomes 0.80. The disjunction permits retirement either because the new tree is sufficiently useful or because the old tree provides too little communication saving. It does not require both conditions.

These ratios measure communication savings. Their range is not automatically [0,1]: for example, delivery through the old tree at a lower cost than the selected ideal new-tree reference produces H_old greater than one. Equal leaf and ideal costs make the denominator zero. A complete policy must define what happens for zero denominators and out-of-range values. Equation (8) defines unmodified ratios on the stated domain, and Equation (9) specifies the retirement condition.

Retirement must be an authenticated state change accepted consistently by remaining members, followed by removal of the retained old-key envelope. Cost authorization alone cannot perform this change. Nor does local erasure delete copies obtained by an adversary. The illustrative update windows are planning heuristics and do not establish a fixed number of commits for either retirement or security recovery.

# Conditional security analysis

## Confidentiality and authentication obligations

The intended hybrid property is that path-secret confidentiality survives failure of one key-establishment component. Published KEM and combiner theorems provide the relevant primitive guarantees, including the FO ciphertext-resistance result discussed in Section 2.3 [8, 9, 12]. As discussed after Equation (3), a proof following this approach must establish the required ciphertext property for the chosen mKyber decapsulation and check the combiner’s assumptions for the KDF, encapsulations, and encodings. Correct authenticated encryption, authenticated public keys, and independent component randomness are additional obligations. A complete computational proof for the composed migration protocol remains to be supplied.

The transition adds an authentication obligation beyond encapsulation. Members must agree on which tree supplies the commit secret, its arity and version, the fixed leaf mapping, and the old keys eligible for encryption. Otherwise, even an honestly encrypted path secret could be interpreted in different trees. A receiver should accept state changes only after validating the commit and its bound transition context. A precise proof would have to connect these checks to a group-state agreement invariant across adds, removals, updates, and retirement. The existing symbolic proof for standard TreeKEM cannot simply be reused [10].

The hybrid encapsulation design does not itself specify a post-quantum replacement for classical signatures. A post-quantum confidentiality aspiration therefore must not be described as full protection against an active quantum adversary capable of forging the retained classical signatures. In particular, the design must distinguish a passive adversary recording traffic for later decryption from an attacker that can already impersonate members. Credential compromise and credential recovery also require their own model.

## Forward secrecy and retained state

Forward secrecy requires protection of earlier traffic after later state compromise. One-way path derivation and erasure of obsolete state support this goal only under an appropriate key-evolution argument. Retaining the old tree deliberately extends the lifetime of some old private keys. A later compromise of a retained key may expose recorded migration ciphertexts addressed to that key. Whether those recovered path secrets expose a particular earlier epoch additionally depends on the key-schedule state available to the adversary. Retention therefore changes the relevant exposure window and cannot be dismissed as a harmless storage optimization.

A complete protocol needs explicit key lifetimes and a record of which key generations were available to which members. It must invalidate removed-member knowledge, erase superseded state when no longer needed, and reject reuse of a retired version. Removing retained state does not establish that no earlier copies exist. The available evidence does not provide a general secure-erasure theorem.

## Post compromise recovery can be group wide

Consider an attacker who copied a private key from the old tree and the secrets needed from the preceding epoch. If a later commit still encrypts a useful new-tree path secret to that old key, the attacker can recover it and derive upward to the new root. With the necessary previous key-schedule inputs, the attacker can continue deriving the group’s secrets for subsequent epochs. The disclosure is not confined to the leaves below that old node: the recovered root contribution affects the group's common secret.

Consequently, recovery requires that the attacker lose access to every delivery route capable of revealing the fresh contribution, under the relevant compromise scenario. An honest update is insufficient if the same contribution remains accessible through a key from the old tree already known to the attacker. Continued compromise or an authorized malicious recipient prevents the desired recovery regardless of arity. This is a conditional argument about secret dependencies.

Neither H_new nor H_old measures adversarial knowledge. A high H_new can coexist with one unsafe retained route, and a low H_old says little about the confidentiality of the routes still used. A security-driven retirement policy would need additional freshness and knowledge conditions. Without assumptions about update scheduling, honest entropy injection, and elimination of compromised routes, no finite bound on post-compromise recovery follows from the proposed cost thresholds.

# Communication and resource analysis

## Accounting by component

Let h be the number of published nonleaf path-node key pairs, L the number of nonempty encapsulation levels, q_j the number of delivery endpoints at level j, and R their total. For the analytical parameter setting, take 32-byte classical public keys and encapsulations. The mKyber parameters are a 768-byte public key, a 704-byte common ciphertext, and a 48-byte per-recipient component [2]. The resulting key-and-KEM payload is

@eq R = ∑_{j=1}^{L} q_{j},   B_{core} = 800h + 704L + 80R

The 800h term publishes both public keys; 704L charges one common component at each used level; and 80R charges a classical encapsulation and a post-quantum recipient component. These coefficients specify the lengths of the selected cryptographic components. Fragmented recipient resolutions increase R without necessarily changing h.

Equation (10) excludes the encrypted path-secret payload, its authentication tag, signatures, proposals, leaf objects, vector lengths, and other framing. If each recipient receives one 32-byte path secret with a 16-byte authentication tag, the accounted cryptographic payload becomes B_core + 48R before the remaining framing. This conditional extension illustrates how payload assumptions affect the accounting; the remaining protocol fields would require further terms.

For a fully populated balanced reference, approximate h by the rounded height h_d(n), take L = h, and take R = (d − 1)h:

@eq h_{d}(n) = ⌈log_{d}(n)⌉,   B_{healthy}(d,n) = [1504 + 80(d - 1)]h_{d}(n)

The resulting per-level coefficients are 1,584, 1,744, and 2,064 bytes for degrees two, four, and eight. A partially filled tree need not have d − 1 occupied siblings at every level. Equation (11) is therefore an idealized reference approximation, not the exact cost for every population or tree shape. In particular, its ceiling-induced jumps arise from rounding the reference height.

@table Public key and encapsulation bytes for the fully populated reference in Equation 11
Members | Binary | Four ary | Eight ary
128 | 11,088 | 6,976 | 6,192
129 | 12,672 | 6,976 | 6,192
512 | 14,256 | 8,720 | 6,192
1,024 | 15,840 | 8,720 | 8,256
1,025 | 17,424 | 10,464 | 8,256
2,048 | 17,424 | 10,464 | 8,256
4,096 | 19,008 | 10,464 | 8,256

Table 2 evaluates Equation (11) directly for the listed group sizes. At n = 129 the binary-to-four-ary reduction is 5,696/12,672 = 44.95%. At n = 1,025 the four-to-eight-ary reduction is 2,208/10,464 = 21.10%. These are reductions in the modeled components only. The latter mathematical opportunity also occurs below the proposed 2,048-member transition threshold, illustrating the difference between a cost curve and an operational policy.

## Initial cost and amortization

If no usable internal node key exists, a transition may deliver to n − 1 leaves. A simplified first-commit model for target arity d′ is

@eq B_{first} ≈ 1504h_{dprime}(n) + 80(n - 1)

Assume for this calculation that every subsequent commit immediately achieves the cost of the fully populated target tree. Let B_old and B_new be the reference costs of remaining in the old tree and operating in the new tree. When B_old > B_new, the additional number of commits at that cost needed after the first transition commit is

@eq Q = ⌈max(0, \frac{B_{first} - B_{old}}{B_{old} - B_{new}})⌉

Equation (13) compares the transition with an old-tree commit in the same first position. It consequently charges only the excess B_first − B_old. Table 3 evaluates Equations (11)–(13) for illustrative group sizes, using the displayed model inputs. When the denominator is nonpositive, this steady-cost model gives no positive amortization benefit.

@table Illustrative break even with subsequent updates at the fully populated tree cost
Transition | Members | B_old | B_first | B_new | Q
2 to 4 | 129 | 12,672 | 16,256 | 6,976 | 1
2 to 4 | 1,024 | 15,840 | 89,360 | 8,720 | 11
4 to 8 | 1,025 | 10,464 | 87,936 | 8,256 | 36
4 to 8 | 2,048 | 10,464 | 169,776 | 8,256 | 73
4 to 8 | 4,096 | 10,464 | 333,616 | 8,256 | 147

The assumptions pull in different directions. Leaf-only delivery can overstate the first cost when keys from the old tree can be used, whereas immediate maturity understates later costs when the new tree remains sparse. The table is therefore a scenario calculation, not a guaranteed upper or lower bound for complete migration. A complete analytical comparison must instead sum the costs for the same sequence of group changes, including the transition, subsequent delivery, retirement, and any additional setup or Welcome traffic.

## Occupancy and asymptotic limits

We also consider a simplified occupancy argument. For a fixed subtree of s members in a static group of n, after t independent uniformly chosen member updates, the probability of at least one update in that subtree and its associated one-node-versus-leaves cost are

@eq p_{s}(t) = 1 - (1 - s/n)^{t},   E[c_{s}(t)] = 1 + (s - 1)(1 - s/n)^{t}

This model assumes that an update in the subtree makes its relevant aggregate key usable and that no later removal invalidates it. Summing the second expression requires an explicit set of disjoint relevant subtrees. It does not justify using the same distribution after conditioning on “effective” updates, nor does it predict costs for arbitrary churn. The formula therefore supplies intuition for gradual population only under the stated sampling and key-validity assumptions.

For fixed arity, storing the public tree takes O(n) space and a member's path private state takes O(log n) space. Retaining old and new structures preserves these asymptotic orders while increasing constants. Complete-tree information in a Welcome can remain linear in n. Similarly, a commit's upload size and a delivery service's total broadcast volume are different: transmitting a full B-byte object to n receivers can cost approximately nB bytes.

# Discussion and limitations

The design shifts part of an arity change from an immediate rebuild into subsequent ordinary commits. Retaining the old tree provides a way to make that shift: old internal keys can reduce leaf-level delivery while the new tree acquires usable internal state. The same retained keys prolong dependencies on historical secrets. Communication efficiency and compromise recovery must therefore be treated as separate objectives, even when both motivate refreshing tree state.

The analytical savings show where the chosen parameter dimensions can make a higher arity attractive. They do not determine the best arity or threshold. A broader analytical treatment should include ternary and other degrees, exact occupied topology, heterogeneous update frequencies, repeated removals, and cumulative costs over both growing and shrinking groups. Fixed-degree policies, immediate rebuilding, and policies that temporarily retain the old tree should be compared for the same mathematical sequence of group changes, with setup, Welcome, and retirement costs included.

The most urgent protocol work is to finalize the hybrid combiner, its encodings, and the state-transition rules. A security model must track historical node-key knowledge during migration, distinguish passive post-quantum confidentiality from active authentication, and define the conditions for recovery. A formal treatment should include authenticated tree-version agreement, removal eligibility, and atomic retirement at each receiver. The present conditional analysis identifies these obligations without claiming that they have been discharged.

The analytical scope also has limits. The fully populated reference replaces exact occupied topology by a rounded-height approximation, while the break-even examples assume that the new tree immediately operates at the fully populated reference cost. A tighter analysis would bound the cumulative delivery cost while the new tree remains sparse and would specify how changes in membership affect those bounds. Such a result is not supplied by the present examples.

# Conclusion

Adaptive arity in hybrid TreeKEM is useful only if the costs and security consequences of changing the tree are included. The proposed mechanism uses the new root to determine the group's fresh secret contribution and temporarily retains keys from the old tree to encrypt new path secrets while internal keys are established. Its reference model exhibits lower mature-tree key-and-KEM payload at selected larger arities, while the transition examples show that repaying initial cost can require many later commits. These analytical examples do not prove the construction secure or establish that one migration policy has lower cumulative cost for every sequence of group changes. Its communication savings must therefore be evaluated together with key freshness, authentication, and the conditions for recovery.

# Research provenance and availability

This article derives from Mohammadreza Parsania's Persian master's thesis, Hybrid Group Key Exchange based on TreeKEM, University of Isfahan, 2026 [4]. All numerical examples in this article are calculated from the equations and parameter lengths stated in the text.

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

@ref 12|Joël Alwen, Dominik Hartmann, Eike Kiltz, Marta Mularczyk, and Peter Schwabe. Post-Quantum Multi-Recipient Public Key Encryption. In Proceedings of the 2023 ACM SIGSAC Conference on Computer and Communications Security, pp. 1108–1122. ACM, 2023.|https://doi.org/10.1145/3576915.3623185
