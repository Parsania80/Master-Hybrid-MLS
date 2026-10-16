@title Research Audit for Adaptive Hybrid TreeKEM
@subtitle Scientific evidence and submission decisions
@date Prepared 14 October 2026; security revision 16 October 2026

This audit accompanies the English article Adaptive Arity and TreeCover Migration in Hybrid TreeKEM. The defensible contribution is a policy for gradually changing tree arity while temporarily using old-tree nodes to deliver secrets belonging to the new tree. The contribution is architectural and analytical. A formal proof of the custom hybrid construction, an adaptive-corruption theorem, and a fully reproducible evaluation are not established by the supplied materials.

The manuscript is suitable for author and supervisor scientific review. It is not yet a submission-ready security specification. The most consequential outstanding decisions concern the exact cryptographic profile, historical key knowledge during TreeCover retention, completeness of the evaluation, and the final publication venue. The user directed that the thesis be authoritative, that Hamid Mala be included as second author, and that no implementation information appear in the paper. This audit retains implementation findings for internal review only.

# Source coverage and provenance

## Thesis inspection

The supplied Thesis.docx was inspected across its front matter, Persian and English abstracts, six chapters, equations, all 17 tables, bibliography, footnotes, and embedded figures. The extracted body contains 1,338 nonempty top-level blocks and 2,275 paragraphs including table content. It contains 1,106 Office Math objects, including inline mathematics; this is not a count of distinct displayed equations. Nineteen embedded image assets include university/front-matter graphics and raster/SVG variants of the two delivery plots. All raster assets were visually inspected, and the two SVG variants were checked against their plotted values and labels.

The current source was preserved. Its SHA-256 is f916f0572b73a7275db1b4441d897bcf5ddf917673b041d08baecf344f4f1146. Source locations below use chapter, equation, or table identifiers where available. “Block” refers to the zero-based direct child position in word/document.xml, preserved in publication_work/thesis_blocks.json. These identifiers are extraction locators, not Word page numbers. No source page number is inferred from an older PDF.

The English title is Hybrid Group Key Exchange based on TreeKEM. The thesis identifies Mohammadreza Parsania, the Faculty of Computer Engineering, University of Isfahan, and supervisor Dr. Hamid Mala. The supplied examination table identifies the supervisor's institution as University of Isfahan. The current manuscript lists Mohammadreza Parsania and Dr Hamid Mala in that order. The professor's honorific was added in the user's Word file and preserved during this revision. A corresponding author, email addresses, ORCIDs, individual contributions, and funding or competing-interest declarations have not been supplied.

Some thesis closing sections contain instructional drafting language, and the cover/front matter contains inconsistent month labels. These are not scientific evidence. The paper uses the verified thesis year 2026, removes university ceremonial material, and does not reproduce incomplete front-matter fields.

## Supporting implementation inspection

At the user's authorization, the sibling implementation workspace was inspected read-only. The repository HEAD reported b0d60cd4e9e261adbc014caf13540cb9aea83d41. This identifies the inspected repository state, not a proven clean snapshot or the revision that produced the thesis tables. No build, benchmark, or test suite was run in this conversion. Historical test counts in project notes were not represented as newly verified results.

Relevant evidence includes README.md, SECURITY.md, docs/THESIS-MEASUREMENT-MAP.md, docs/FINAL-EXPERIMENT-MANIFEST.md, docs/research/MKYBER-IMPLEMENTATION-AUDIT.md, ADRs 0003, 0022, and 0047, the hybrid-path-secret and experimental-mls-adapter source, and archive/SESSION-LOG-2026-07.md. The output and report directories contain no original result files beyond their placeholders. The user confirmed that no raw CSV/JSON results are available. The later instruction excludes all implementation-derived material from the paper, including numerical results reproduced in the thesis.

The final paper excludes all implementation descriptions, observations, operation-cost tables, and discussion of execution or testing. Both thesis Tables 5–6 and 5–7 are excluded, including derivative threshold calculations and mentions in the abstract, introduction, membership discussion, limitations, conclusion, and provenance statement. Only protocol design, mathematical analysis, conditional security reasoning, and formula-derived numerical examples remain. Implementation findings are confined to this separate audit.

# Research extraction and evidence map

The research question is: how can a hybrid TreeKEM group increase arity while avoiding a complete immediate rebuild of internal key state, and how should it decide when an old-tree delivery cover can be retired? The significance is that expensive shared per-level material can make shallower trees attractive, while sparse new trees and retained historical secrets create transition costs that steady-state comparisons omit.

The proposed answer is to make the new root authoritative from the transition, retain eligible old nodes only for delivery, populate the new tree through subsequent commits, and retire the old cover using normalized endpoint costs. The core novelty should be claimed at this combination and lifecycle level. Higher-arity TreeKEM, mKEM batching, hybrid KEMs, and post-quantum MLS are prior work.

@table Major claims and their evidence status
Claim | Evidence location | Assessment used in the paper
One logical hybrid node carries two key families | Chapter 4 node derivations, blocks 610–644 | Thesis design, not two independent crypto trees
Hybrid output transports a path secret | Equations 4–19 to 4–26, blocks 651–670 | Preserved; distinguished from epoch secret
Only the new root drives new group state | Chapter 4 transition description | Architectural invariant, not a proven theorem
Old nodes cover recipients during migration | Chapter 4 TreeCover construction | Preserved with key-history eligibility obligations
Arity candidates are 2, 4, and 8 | Chapters 4 and 5 | Design space restriction; no optimality claim
Group size and future costs trigger migration | Chapter 4 policy parameters | Heuristics; forecast and cost convention unresolved
Cost ratios authorize retirement | Chapter 4 retirement rule | Disjunction preserved; not a security metric
Lower healthy reference costs at higher arity | Chapter 5 formulas and table | Independently recalculated analytical values
Transition cost can delay break even | Chapter 5 transition examples | Recalculated scenario, not a measured guarantee
Reported five-event delivery sequence | Thesis Table 5–7, block 1375 | Excluded from paper: implementation-derived observations
Binary/quaternary size comparison | Thesis Table 5–6, block 1358 | Excluded from paper: implementation-derived comparison and semantic mismatch
Forward secrecy and recovery | Chapter 5 informal analysis | Conditional discussion; unconditional wording removed
Adaptive-corruption security | No reduction for the proposed construction | Not established; mKyber/amKyber distinction retained
Production and RFC compatibility | No such evidence in thesis | Not claimed

# Novelty assessment and closest work

Alwen et al., How Multi-Recipient KEMs can help the Deployment of Post-Quantum Cryptography, explicitly discuss m-ary TreeKEM in Section 4, including a four-ary example. Their Table 1 supplies the 768-byte public key, 704-byte common ciphertext, and 48-byte recipient ciphertext parameters. Their MLS treatment already explains why shared encapsulation material changes the depth/fanout tradeoff. The thesis cannot claim these mechanisms as its inventions. The supplied 15-page paper was extracted and its construction, parameter, security, and MLS sections inspected.

Chevalier, Lebrun, Martinelli, and Plût's The Art of Bonsai analyzes MLS tree evolution and degree choice. The official ePrint record identifies publication at IEEE EuroS&P 2025 and reports that useful degree depends on the encryption parameters. It is essential related work absent from the thesis bibliography. Its full PDF could not be retrieved because the source returned access errors; the manuscript confines its account to the official abstract and metadata. Detailed dominance or novelty claims against its algorithms remain unresolved. The reference cites the verified ePrint record instead of guessing publisher pagination or a DOI that could not be confirmed through the publisher.

The two IETF draft families address different questions. The hybrid-cipher-suite draft concerns cipher-suite choices. The Amortized PQ MLS Combiner couples two MLS sessions to change the frequency of costly post-quantum updates. They are relevant alternatives, but neither the presence of hybridization nor amortized post-quantum cost alone distinguishes this thesis. Their dated draft status is recorded explicitly; neither is presented as a standard.

X-Wing establishes concrete hybrid KEM results for its own selected components. KEM Combiners supplies general motivation for construction-specific robust combination. The symbolic TreeKEM work establishes proof results for a precise MLS specification. None supplies a proof for this custom combiner plus arity transition plus retained cover. The paper uses these works to delimit what must be proved, not to imply inherited security.

The recommended contribution claim is: “We investigate an adaptive-arity migration design for hybrid TreeKEM that uses an authenticated old-tree cover to deliver new-tree path secrets during gradual population, and analyze the resulting communication and retained-key tradeoffs.” This claim is supported by the supplied design. A claim of being the first such construction would need a broader full-text literature review and is deliberately not made.

# Mathematical and protocol corrections

## Combiner authority and notation

The user explicitly selected the thesis as the final specification. Equation 4–19 includes ss_v^C, ss_v^PQ, ct_v^C, ct_xe, and label_v. The surrounding Persian text defines ct_xe as a canonical public value corresponding to the classical recipient public key in the X25519 setting, not a post-quantum ciphertext. The manuscript replaces that misleading symbol with Encode(pk_v^C), an editorial clarification expressly contemplated by the thesis itself. It retains the classical ciphertext and public key in the KDF input.

The exact KDF, canonical concatenation, key/nonce output partition, complete associated-data encoding, and treatment of repeated delivery are not fully fixed. The manuscript therefore does not claim an interoperable byte-level specification. The supervisor should approve a complete profile before a security theorem or conformance claim is attempted. Adopting X-Wing wholesale or silently substituting standard ML-KEM would change the thesis and was not done.

The prototype instead builds ss_classical || ss_pq || TLSEncode(HybridKdfContext). ADR 0003 and hybrid-path-secret/src/lib.rs, function build_hybrid_kdf_input, explicitly exclude raw ciphertext bytes from this input. The classical secret is a context-bound HPKE exporter value. Its HKDF-SHA256/AES-128-GCM wrapper is materially different from the authoritative thesis equation. No results of that code can establish conformance to Equation 4–19 merely because the byte sizes look similar.

## Local equations and key schedule

The thesis contains small worked-example inconsistencies: a repeated classical public-key symbol where the surrounding node definition calls for a post-quantum public key; an example deriving ns_A from ps_L; and an opposite-subtree delivery example naming ps_A where the narrative requires a root-level path secret. The paper avoids copying these inconsistent examples, states the generic labeled derivation, and uses a newly drawn migration diagram. These changes are semantic clarifications supported by the surrounding text, not additional experiments.

The abbreviated joiner/member/epoch schedule in the thesis does not reproduce every RFC 9420 operation and label. The paper refers to the full RFC key-schedule interface rather than presenting the simplified equations as normative MLS. This is especially important because changing tree structure does not remove the need to authenticate the correct group context and feed the right commit secret into that interface.

## Cover validity and retirement

Set coverage, disjointness, and current membership are necessary but insufficient for secure delivery. A removed member may still know the private key of an old node whose current labels appear harmless. The paper makes historical key knowledge an explicit eligibility obligation. A full algorithm must define key generations, possession, invalidation, and allowed reuse in both structures; the thesis does not provide a formal inductive invariant proving them correct.

The thesis retirement comparison is H_new ≥ theta_new OR H_old < theta_old. The implementation uses strict H_new > theta_new and strict H_old < theta_old, with exact clamped fractions and explicit undefined-case rejection. The paper preserves the thesis's operator. The reported final value 40/57 exceeds 0.70, so both variants agree on that example. A threshold equality case would differ and must be settled before a conformance test is meaningful.

The ratios are not automatically between zero and one. A smaller old-tree cost than the chosen ideal new-tree reference yields H_old > 1, and equal leaf/ideal costs produce a zero denominator. The paper states those conditions instead of silently adding clamping. The policy needs an explicit target-set aggregation convention and handling of exceptional values. Its decision is an economic authorization, not a proof of secret freshness or a completed authenticated retirement operation.

## Security claim repairs

The thesis's suggestion that an old compromised cover route delays recovery only in a local subtree is too strong. A recovered path secret can propagate to the new root. If the attacker also possesses the required prior key-schedule state, exposure can affect the group epoch secret. The paper explains this conditional group-wide consequence and does not claim a finite recovery bound without a schedule that eliminates all attacker-known delivery routes.

Forward secrecy is also conditional on key lifetimes and erasure. Retaining an old private key makes recorded migration ciphertexts addressed to it potentially decryptable after later compromise. The exact affected epochs depend on other key-schedule secrets. Deleting local retained keys cannot delete copies already recorded by an attacker. The paper neither asserts a practical attack on a deployed product nor repeats an unconditional preservation claim.

The supplied six-page proof note, mkyber_ciphertext_resistance_proof.pdf, dated 15 October 2026, was read in full. It correctly directs attention to the established FO collision-resistance theorem. The author PDF of Alwen et al., Post-Quantum Multi-Recipient Public Key Encryption, was checked at Definition 8, Theorems 4–5, and Appendix B.3. The manuscript now explicitly recognizes standard mKyber IND-CCA security and the FO recipient-local ciphertext-resistance result. X-Wing's general QSF framework is described as applicable when its C2PRI and Diffie–Hellman hypotheses hold. Adaptive-corruption confidentiality is identified as a separate security question.

The supplied note is supplementary AI-assisted technical analysis, not a peer-reviewed publication; the paper cites the verified primary research instead. Its explicit-rejection argument uses deterministic reconstruction, full canonical recipient-ciphertext comparison, and an accepted output derived through a collision-resistant hash. Its implicit-rejection extensions have additional stated hash or oracle assumptions. No theorem for every algorithm bearing the mKyber name is inferred. The same-recipient property does not authenticate unused components of a full multi-recipient vector. These distinctions concern mathematical algorithms and do not add implementation material to the paper.

# Numerical audit

## Recomputed analytical values

The key-and-KEM model is B_core = 800h + 704L + 80R, with R the sum of recipient endpoints over nonempty levels. The healthy approximation uses rounded height h = ceil(log_d n), L = h, and R = (d − 1)h. The coefficients are therefore 1,584, 1,744, and 2,064 bytes per level for d = 2, 4, and 8. Every row in manuscript Table 2 is recomputed from these definitions; none is described as measured wire traffic.

The model excludes per-recipient encrypted path secrets and authentication tags. A 32-byte path secret plus a 16-byte tag would add 48R bytes before other framing, under the stated one-wrapper-per-recipient assumption. The paper explicitly separates this accounting example from the authoritative but incomplete cryptographic profile. Actual occupied sibling counts can differ from the full-capacity approximation, especially at n just above a power boundary.

The five break-even examples were independently recalculated. Their first-cost formula is 1,504 times target height plus 80(n − 1). The excess cost over one old-tree commit is divided by the future healthy per-commit saving and rounded upward. The values 1, 11, 36, 73, and 147 are additional commits after the transition commit. They assume immediate healthy operation afterward. Cover use can reduce the first cost, while sparse later state can increase follow-up costs; the examples are neither a universal upper bound nor a lower bound.

The occupancy expression 1 − (1 − s/n)^t assumes independent uniform updates in a fixed group. Conditioning t on effective updates changes the sampling distribution. Removals and nonuniform update rates violate the simple model. The paper retains the formula with these conditions but does not reproduce numerical maturity forecasts without the exact subtree decomposition and sampling definition.

## Thesis Table 5–6 retained only in this audit

@table Original binary and quaternary reported comparison with corrected units
Event and committer | Active n | Quaternary bytes | Binary bytes | Q minus B
Add 21 | 129 | 9,034 | 15,976 | −6,942
Add 61 | 130 | 9,034 | 16,856 | −7,822
Remove 122 | 129 | 9,042 | 15,334 | −6,292
Add 44 | 130 | 9,034 | 16,856 | −7,822
Remove 35 | 129 | 9,041 | 15,597 | −6,556
Remove 64 | 128 | 9,041 | 15,597 | −6,556
Remove 88 | 127 | 8,909 | 13,883 | −4,974
Update 97 | 127 | 8,902 | 13,216 | −4,314

Table 2 above preserves the thesis values. Source inspection identifies these as serialized Commit byte counts despite the thesis's computational-complexity heading. The supporting functions measure_real_binary_probe_operation_bytes and measure_real_quaternary_probe_bytes show that Add rows are not matched operations: the binary side performs Add, while the quaternary side performs Update on the post-add population because the frozen quaternary mapping rejects Add/remapping. This prevents an Add-efficiency claim. The user requested no implementation information in the paper, so the entire table is excluded there rather than published without its essential explanation.

The five Remove/Update rows give a descriptive relative reduction of approximately 32.6–42.0%, but use prepared probe states and exclude warmup. They are not cumulative live-migration traffic. The eight-row overall range would misleadingly mix these with substituted Add operations. No statistical significance, average population performance, latency, or cryptographic-security conclusion follows.

## Thesis Table 5–7 excluded from the paper

Thesis Table 5–7 contains implementation-derived operation observations and is excluded from the paper in full. Its five rows, usable-node counts, endpoint costs, exact ratios, and derived examples are not manuscript evidence. The following checks belong only to this audit of the source. The final ratios are 40/57 = 0.701754… and 77/114 = 0.675439…. The new-tree threshold is crossed while the old-tree threshold is not. The OR rule therefore authorizes retirement for that observation. An authorization does not itself establish distributed acceptance, deletion of all copies, or post-compromise recovery.

The displayed fractions allow algebraic reconstruction of reference costs: (C_leaf,C_ideal) = (126,10), (125,10), (125,10), (125,10), and (124,10). These pairs reproduce both ratios in each row. They are inferred from the table, not separately recorded fields. Those reconstructions have also been removed from the paper. C_real is not min(C_new,C_old); mixed delivery uses a priority over subsets. Nonmonotonic health is expected when committers and memberships change.

## Provenance mismatch and missing evidence

The thesis environment table gives Rust 1.93.1, an Intel i5-11400F, Ubuntu 26.04 LTS, a kernel identifier, and an ambiguous memory number without units. Archived July 2026 notes matching the eight probe values describe Windows GNU/MinGW runs. No raw artifact permits these to be tied to a unique environment. The paper consequently reports neither environment nor runtime claims.

The earlier FINAL-EXPERIMENT-MANIFEST concerns a different seed-62, three-operation workload and states retirement was unsupported at that historical boundary. Later ADRs and archived runs describe supported authenticated retirement. The manifest's hashes and totals cannot be repurposed as provenance for the seed-42 Table 5–6/5–7 observations. Neither the source trace nor the manifest is used as evidence in the paper.

# Reference verification report

## Sources retained in the manuscript

The initial bibliography verification date is 14 October 2026; reference 12 and the ciphertext-resistance claims were verified on 16 October 2026. Every manuscript reference is cited in the text, and every numbered text citation has a bibliography entry. References use full author lists in verified order. No DOI is invented for a conference presentation, thesis, Internet-Draft, or cited ePrint version. Preprint references are labeled as such even when their records identify later conference publication.

@table Verification record for the final bibliography
Paper ref | Verified metadata and claim boundary | Primary verification location
1 | Six authors, title, July 2023, RFC 9420; MLS interface | rfc-editor.org/rfc/rfc9420.html; DOI 10.17487/RFC9420
2 | Ten authors, order, title; 15-page 2024 NIST conference paper; parameters and m-ary TreeKEM | Supplied PDF and official NIST conference PDF
3 | Four authors, title, report 2024/746, revision date; degree/evolution topic | eprint.iacr.org/2024/746; full PDF inaccessible
4 | Author, thesis title, institution, year | Supplied thesis front matter and examination table
5 | Four authors, title, February 2022, RFC 9180, DOI | rfc-editor.org/rfc/rfc9180.html
6 | Mahy and Barnes; revision 06; 21 July 2026; draft status | datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/06/
7 | Tian, Hale, Mularczyk, Alwen; revision 02; 20 October 2025; expired | datatracker.ietf.org/doc/html/draft-ietf-mls-combiner-02
8 | Three authors, PKC 2018 I, LNCS 10769, pp. 190–218, DOI | Royal Holloway author research portal; ePrint 2018/024
9 | Seven authors, CiC 1(1), 2024, 22 pages, DOI | DOI resolves to cic.iacr.org/p/1/1/21; supplied PDF
10 | Three authors, title, ePrint 2025/410, 2025; symbolic model | ePrint record, author site twal.org/research, supplied PDF
11 | NIST corporate author, title, FIPS 203, 13 August 2024, DOI | csrc.nist.gov/pubs/fips/203/final
12 | Five authors; CCS 2023, pp. 1108–1122; FO collision resistance and mKEM combiner theorem | ACM DOI 10.1145/3576915.3623185; author PDF cryptojedi.org/papers/mkem-20220812.pdf, Definition 8, Theorems 4–5, Appendix B.3

RFC 9420's thesis bibliography author list was incorrect. The final entry uses Richard Barnes, Benjamin Beurdouche, Raphael Robert, Jon Millican, Emad Omara, and Katriel Cohn-Gordon. The NIST mKEM paper had only two authors in the thesis entry; all ten appear in the final reference. KEM Combiners had malformed author formatting, now corrected. X-Wing's 2024 volume and issue were confirmed through its DOI; its 22-page extent was checked in the supplied PDF. The TreeKEM reference cites the verified ePrint rather than adding unconfirmed proceedings pages.

The two MLS drafts are dated snapshots as of the verification date. The hybrid-suite revision is work in progress, and the amortized-combiner revision is expired. These are not normative standards. The FIPS reference is the final 2024 standard, not the 2023 initial public draft cited in the older X-Wing PDF.

## Disposition of all thesis bibliography entries

The table below is a disposition audit, not a declaration that every excluded reference has been verified. Unused historical background was removed to keep the article focused. Suspect entries were excluded rather than silently repaired without primary confirmation. The closest retained works and new additions received the verification described above.

@table Thesis bibliography disposition in its original order
Entry | Short source identifier | Disposition
1 | NIST PQC project 2016 | Omitted; replaced by final FIPS 203 for the needed claim
2 | How Multi-Recipient KEMs 2024 | Retained; all ten authors restored
3 | Continuous Group Key Agreement with Active Security | Omitted; supplied metadata not verified
4 | Post-Quantum Multi-Recipient Public Key Encryption | Retained as paper reference 12; five authors, CCS metadata, and FO collision-resistance theorem verified
5 | Security Analysis and Improvements for IETF MLS | Omitted; supplied author metadata requires checking
6 | Multi-Recipient KEMs and Their Applications | Omitted; exact supplied entry not verified
7 | Keep the Dirt | Omitted; malformed/truncated author attribution not verified
8 | X-Wing | Retained; DOI, authors, year, venue, extent checked
9 | RFC 9420 | Retained; author list corrected
10 | Post-Quantum TLS 2020 | Omitted; supplied entry not verified
11 | Burmester–Desmedt conference key distribution | Omitted historical background
12 | On Ends-to-Ends Encryption | Omitted; supplied author field incomplete
13 | External-Operations TreeKEM 2026 | Omitted; supplied year/venue/pages not verified
14 | Hybrid PQ KEM for TLS 1.2 | Omitted; malformed author metadata and revision unspecified
15 | Grover database search | Omitted textbook motivation
16 | Concrete Treatment of Efficient CGKA | Omitted; thesis two-author list is incomplete
17 | NTRU | Omitted unrelated primitive background
18 | On the Security of Hybrid Key Exchange | Omitted; exact supplied reference not verified
19 | Scalable Ciphertext Compression Techniques | Omitted; supplied author list requires verification
20 | Tree-Based Group Key Agreement | Omitted; historical source has multiple authors
21 | Hybrid KEMs and Authenticated Key Exchange | Omitted from focused treatment; not independently verified here
22 | KEM Combiners | Retained; author order and bibliographic formatting corrected
23 | MIKA | Omitted; supplied conference designation requires checking
24 | Shor algorithms | Omitted textbook motivation
25 | DH Key Distribution Extended to Group Communication | Omitted historical background
26 | CLIQUES | Omitted historical background
27 | TreeKEM symbolic analysis | Retained as verified author ePrint
28 | TreeSync | Omitted; primary author site lists four authors, not two
29 | Secure Group Communications Using Key Graphs | Omitted; supplied author list is incomplete

New manuscript references are Bonsai, the two IETF MLS drafts, final FIPS 203, and RFC 9180. Their purpose is respectively to narrow novelty, identify alternative hybridization approaches, distinguish standardized ML-KEM from mKyber, and disambiguate the meaning of HPKE. No bibliography inflation or unsupported security citation is needed.

# Manuscript organization and abstract review

The title names the mechanism and setting without promising proven post-quantum security. The abstract states the transition problem, describes the single new-root authority and temporary old cover, gives one analytical saving and one contrasting amortization example, and identifies the security limitation. It has no citations. Its strongest result is the transparent communication tradeoff, not a claimed benchmark or a theorem.

The manuscript progresses from introduction and related work to model and cryptographic specification, migration, conditional security, mathematical communication analysis, discussion, and conclusion. This order makes the mechanism understandable before assessing its security and cost. There is no empirical-results section. The provenance and AI-assistance statements precede the bibliography.

The paper omits elementary quantum-algorithm tutorials, university front matter, long historical surveys, inconsistent worked examples, and all implementation material. It retains the authoritative combiner and formula-derived cost examples, and adds qualifications required to prevent unsupported conclusions. The original numerical endpoint trace and every implementation-derived result are excluded. It uses a single original diagram of old-tree delivery to a new root; no third-party figure is reproduced.

# Publication options and compliance

No venue has been selected. The manuscript uses a journal-neutral A4 layout with editable styles, tables, equations, and numerical references. It is not labeled compliant with IEEE, Springer, Elsevier, or any other publisher template. The two options below are conditional scope recommendations, not acceptance predictions.

International Journal of Information Security is a plausible option after the protocol and security model are strengthened. Its official scope includes theoretical, applied, and implementation work in information security. Its current instructions call for a 150–250-word abstract and 4–6 keywords. The journal-specific text-format section requests Springer's two-column LaTeX package, despite a general paragraph mentioning editable DOCX sources. The present Word file therefore does not satisfy a claim of template compliance. A future conversion or editorial clarification would be required. Official scope: https://link.springer.com/journal/10207/aims-and-scope. Instructions: https://link.springer.com/journal/10207/submission-guidelines.

Cryptography is a second scope match for a carefully delimited protocol-design and analysis article. Its official aims include quantum-safe cryptography, key management, protocols, and security evaluation, and identify regular research papers and short communications. This does not remove the need for a complete specification and defensible evidence. Its current detailed author-instructions page could not be retrieved during this check, so article length, template details, fees, and thesis/AI disclosure requirements remain unverified. Official scope: https://www.mdpi.com/journal/cryptography/about. Instructions to recheck: https://www.mdpi.com/journal/cryptography/instructions.

The Springer instructions require appropriate documentation of substantive LLM use and distinguish it from simple copy editing. This conversion included synthesis and technical consistency analysis, so it is not described as copy editing alone. The paper truthfully records Codex assistance and does not assert that author review has already happened. The final disclosure must be reviewed against the selected venue's then-current policy. Neither AI assistance nor thesis defense establishes scientific correctness.

The current journal-specific treatment of this defended thesis as prior publication has not been conclusively established. Disclose the thesis and any repository publication in the cover letter; obtain its permanent bibliographic URL if one exists. Do not apply the IJIS requirement for extending conference papers to a thesis without clarification. Rights in reused thesis figures should also be considered, although this manuscript redraws its sole schematic and uses no external artwork.

# Decisions for the authors and supervisor

## Scientific decisions before submission

1. Approve a complete byte-level profile for the thesis combiner: classical encapsulation interpretation, exact KDF, encodings, labels, output lengths, associated data, nonce management, and rejection behavior. The user's choice of the thesis resolves authority but does not fill unspecified parameters.

2. Define a formal state invariant for TreeCover key history, including removal, rejoining, new-member mapping, retained-node eligibility, and retirement. Determine what evidence all receivers authenticate before discarding old state.

3. Specify the adversarial and recovery model. Decide whether the target is passive post-quantum confidentiality, active classical security, adaptive compromise, or some combination, and prove only the selected properties under stated assumptions.

4. Resolve whether retirement remains purely cost-driven or additionally requires a freshness condition. Define zero-denominator behavior, out-of-range ratios, target-set aggregation, and the equality case of the new-tree threshold.

5. Provide a cumulative evaluation with exact topology and identical schedules for competing policies. Include transition and retirement bytes. Test candidate arities beyond 2/4/8, or explicitly defend the restriction. Keep analytical values and observations separate.

6. Obtain the full Bonsai paper and compare its algorithms directly with the final migration specification. The present account uses verified abstract-level scope and cannot rule out closer overlap in the full work.

## Authorship and publication decisions

The named authors should confirm spelling and order, their final affiliations, the corresponding author and email, ORCIDs if desired, and individual contributions. The user authorized Hamid Mala's inclusion; this is not evidence of the professor's completed review or consent to a particular submission. No email or approval was invented.

Select one venue and verify its latest article-type, template, length, reference, data, thesis-disclosure, and AI-use rules. Supply truthful funding, competing-interest, acknowledgment, and contribution statements; the current manuscript intentionally does not invent negative declarations. Confirm that the work is not under simultaneous review elsewhere before submission. No submission or external communication has been performed.

# Skeptical review outcome

The central problem is precise and the paper now acknowledges the closest known higher-arity and mKEM approaches. The design is coherent at the architectural level, while its cryptographic profile remains incomplete. The security section is appropriately conditional and highlights a material recovery issue. The analytical arithmetic is reproducible from the stated formulas. The endpoint trace is excluded from the manuscript and provides no evidence for its claims. The abstract and conclusion are limited to those findings.

The manuscript's main risk is scientific completeness, not English or Word formatting. A reviewer could reasonably request a formal model, a complete implementation-independent specification, a stronger novelty comparison, and reproducible cumulative evaluation before acceptance. The delivered paper makes those limits visible rather than concealing them behind broad claims of quantum resistance, efficiency, or preservation of post-compromise security.
