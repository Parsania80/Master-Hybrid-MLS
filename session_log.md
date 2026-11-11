# Session log and Codex onboarding

Last updated: 2026-11-11, Asia/Tehran.

## Start here in a new chat

Suggested opening prompt:

> Read `session_log.md` at the repository root, then inspect the current Git status and the paper files it identifies. Summarize the current manuscript, the professor's feedback, completed changes, and unresolved research questions before starting my next request. Preserve the agreed wording and limit edits to the scope I request. Distinguish professor feedback from my preferences and earlier assistant assessments.

This is a handoff record of the available conversations and checked repository artifacts, covering the original chat **Clarify hybrid meaning in abstract** and the continuation in this chat. It is not a claim to recover every conversation ever held about the thesis. The original chat was reread through the chat tool; its retrieved history had no further pages. All 31 comments in the preserved professor review have a dedicated entry below. Later feedback and decisions are recorded separately so their authorship is clear.

Current work: an English research article derived from Mohammadreza Parsania's Persian master's thesis, supervised/coauthored by Hamid Mala, University of Isfahan. The current focus is the English article, not the Persian thesis abstract.

## Current snapshot

- Repository: `D:/Github/Master-Hybrid-MLS`.
- Manuscript title: **Adaptive Arity and Tree Migration in Hybrid TreeKEM**.
- Authors: **Mohammadreza Parsania and Hamid Mala**. The professor requested removal of the honorific `Dr` from the author line.
- Latest existing commit when this log was started: `0a406e1` — `docs: clarify MLS epoch definition using RFC 9420`.
- The November 5 round is in commit ca494c1. The November 9 round and Ver3 are in commit cb05abb. Commit 4cdfe7d records the November 11 Ver4 text revisions. The variable typography follow-up is uncommitted.
- The current Word, Markdown and clean PDF reflect Ver4. The clean PDF and Ver4 each have 12 pages. The abstract has 241 words.
- Ver1 through Ver3 are frozen review copies. The current review PDF is ParsaniaPaper-Ver4.pdf. It has 296 yellow annotations across pages 4–10 and 13 links. The clean PDF has 13 links.
- No manuscript change remains pending from the specific editing requests in these chats. Scientific strengthening discussed later remains proposed work, not completed results or an instruction to implement experiments automatically.

## Files and source hierarchy

Paths below are relative to the repository root unless explicitly absolute.

| Path | Purpose and handling |
| --- | --- |
| `paper/paper.docx` | Current editable manuscript; preserve formatting, equations, tables, fields, and references. |
| `paper/paper.pdf` | Current clean PDF corresponding to Word. |
| `paper/ParsaniaPaper-Ver1.pdf` | FROZEN prior-round comparison, restored byte-for-byte to commit 0a406e1 after the user corrected the output version. Do not modify for new feedback. This is distinct from the untouched professor review in reviews/. |
| `paper/ParsaniaPaper-Ver2.pdf` | Frozen second-round review copy. Use it as the text baseline for Ver3. |
| `paper/ParsaniaPaper-Ver3.pdf` | Frozen November 9 review copy and text baseline for Ver4. |
| `paper/ParsaniaPaper-Ver4.pdf` | Current professor-facing review copy. Yellow highlights mark November 11 changes relative to Ver3. |
| `paper/reviews/ParsaniaPaper-Ver1.pdf` | Preserved original professor-annotated review. Read this to see original annotations and their highlighted anchors. Do not overwrite it with revised output. |
| `paper/publication_work/paper.md` | Synchronized manuscript text/source with custom directives such as `@title`, `@eq`, `@table`, and `@ref`. Keep it aligned with Word. |
| `paper/publication_work/build_documents.py` | Existing DOCX/figure builder. Its main entry point builds BOTH paper and research audit and regenerates the figure. Do not run it blindly for a sentence edit. |
| `paper/publication_work/render_word.ps1` | Existing Word export helper; also processes both paper and audit. Inspect before reuse. |
| `paper/publication_work/review_revision_2026-10-26/comment_resolution.json` | Structured source for the 31 original professor comments and the initial recorded resolutions. |
| `paper/publication_work/review_revision_2026-10-26/comment_resolution.md` | Readable original resolution record. Some descriptions were superseded later; see this log. |
| `paper/publication_work/review_revision_2026-10-26/revision_checks.json` | Initial broad revision checks, including 14 preserved equations and 3 tables. Historical snapshot, not current PDF metadata. |
| `paper/publication_work/review_revision_2026-10-26/latest_changes.json` | The five later changes made on October 26. Does not include the later October 30 epoch correction. |
| `paper/publication_work/review_revision_2026-10-26/highlight_checks.json` | Historical highlight-generation checks; do not assume its count is current. |
| `paper/publication_work/security_revision_2026-10-16/` | Earlier security-source records and backups; inspect these before revisiting the mKEM/combiner analysis. |
| `paper/publication_work/abstract_revision_2026-10-16/` | Original abstract-definition revision backup and checks. |
| `paper/publication_work/qa/` | Earlier generated QA artifacts. May be stale; current top-level paper outputs take precedence. |
| `paper/research_audit.docx` and `paper/publication_work/research_audit.md` | Separate earlier audit material; not a substitute for checking the current article. |
| `implementation/old/` | Older implementation. |
| `implementation/new/` | Newer implementation moved out of the former `ترم 4` tree. Its existence does not establish experimental results for the paper. |
| `پایان نامه/` | Persian thesis and supporting material preserved after cleanup. |
| `Proposal/` | Preserved proposal folder; root-level proposal Word/PDF files also remain. |
| `AGENT.md`, `STUDY-AGENT.md`, `STUDY-PLAN.md` | Earlier project/study notes. They contain simplified/older security claims; treat them as historical context and verify against the current manuscript and primary sources. |

There is also an older implementation-specific archive log at `implementation/new/archive/SESSION-LOG-2026-07.md`. This new root-level log is the handoff for the article revision conversations; it does not replace that archive.

## User preferences and editing constraints

1. Use simple, precise, coherent academic English. Explain unfamiliar terms before using them. Avoid invented terminology, compressed phrases, and vague claims.
2. Follow the professor's concrete feedback. Attribute it accurately; user questions and assistant concerns are not additional professor comments.
3. When the user says to change only a section or definition, make that exact change and verify the rest of the manuscript text remains identical.
4. Update the current Word, clean PDF, `paper/ParsaniaPaper-Ver2.pdf`, and matching Markdown source together when manuscript edits require them. Keep `paper/ParsaniaPaper-Ver1.pdf` frozen. Highlight only changes since that prior review version in Ver2.
5. In the comparison PDF, retain yellow highlights but **do not add comment text, deletion notes, popups, or explanations such as “Added or revised wording compared with the professor-reviewed version.”** Internal resolution logs are fine.
6. Preserve the untouched professor review in `paper/reviews`.
7. Explain the scope before expanding local edits into terminology changes elsewhere. The user specifically questioned why later pages were highlighted when the professor commented only on the first two pages.
8. The user has not requested removal of those earlier later-page edits or highlights. They remain; do not silently revert them or reinterpret their presence as professor approval.
9. Keep scientific claims conditional where evidence is conditional. Do not convert component-cost calculations into measured total-bandwidth claims, or primitive security results into a proof of the whole migration protocol.
10. Commit when asked, using a descriptive message. Prior commit requests were completed; they are not standing authorization to commit every later change or push remotely.
11. Maintain this log when new feedback, decisions, completed work, or limitations materially change the handoff. Clearly label historical/superseded entries.
12. New November 5 instruction: show every manuscript change directly in chat with the exact before and after wording. Do not rely on PDF highlights as the only explanation.
13. In manuscript citations, give reference numbers only (for example `[1]` or `[9, 12]`). Omit section, subsection, table, theorem, and similar locators from the cited source. Internal source-verification notes may retain precise locators.

## Chronology of completed work

### October 16: clarify hybrid in the English abstract

The professor said:

> در شروع ابسترکت اول یه جمله در مورد مفهوم هایبرید بودن و اهمبتش بگین. چون هایبرید به تنهایی معنی ترکیب طرحهای کوانتومی و پساکوانتومی یا ترکیبهای دیگر رو هم میده.

The user clarified that this concerns the **English article Abstract**. An opening sentence was added defining hybrid key establishment as combining classical and post-quantum mechanisms to reduce reliance on either alone. Word, Markdown, and PDF were synchronized. The historical abstract had 224 words, and that historical PDF had 11 pages. Those counts are not the current manuscript counts.

An earlier security-revision record, already present in the repository, records examination of a supplied six-page proof, Definition 8, Theorems 4 and 5, Appendix B.3, X-Wing Definition 7/Section 6, and the NIST mKEM overview Sections 2.3/3.1. Its primary-source link is `https://cryptojedi.org/papers/mkem-20220812.pdf`. It records that implementation material was not added to the paper. This record is background evidence of previous checking; no complete protocol proof was established by it.

### October 26: inspect the professor's first review

The professor's original `ParsaniaPaper-Ver1.pdf` was initially read from Downloads. The assistant found 31 comments: 29 on original page 1 and 2 on original page 2, in Persian and English, and confirmed they could be read and associated with highlighted passages. The preserved repository copy is now in `paper/reviews/`.

The professor's general message was:

> سلام. کامنتهای زیادی روی بخش abstract و introduction گذاشته ام. مطالب خیلی پراکنده و غیردقیق هستند. باید ساده و دقیق و منسجم بیان شوند. کامنتهای روی فایل رو به دقت بخونین و اعمال کنید.

Meaning: the abstract/introduction were scattered and imprecise and needed simple, precise, coherent presentation. Every original annotation is recorded later in this file.

### October 26: repository cleanup before article editing

At the user's request:

- Removed dated folders `1404-11-12`, `1404-11-14`, `1404-11-16`.
- Organized implementations as `implementation/old` and `implementation/new`.
- Moved material out of `ترم 4` to the root and removed the old wrapper folder.
- Moved article material into root-level `paper/`; preserved the professor review in `paper/reviews/`.
- Preserved `Proposal` and thesis supporting files.
- Removed 27 `Thesis-before-*.docx` backups and the requested obsolete Pseudocode/Questions/template/MLS documents/Flashcards/notes/old session-log material. The user explicitly clarified: **keep thesis supporting files; remove only Thesis-before backups**, rather than deleting all thesis support material.
- Earlier completion reported 946 retained files verified by checksum and about 396 MB removed. These are historical operation results, not newly recounted inventories.
- A Windows lock on the old directory was attributed in that session to helper processes using the removed thesis directory as their working directory; helpers were released and paths adjusted.
- Cleanup commit: `48174fc` — `chore: reorganize repository and remove obsolete thesis backups`.

The user's current explicit request authorizes recreating this root-level `session_log.md`, superseding the earlier removal of obsolete log material.

### October 26: apply the 31 review comments

Rewrote the abstract and introduction, introduced definitions, added **Our Contribution** and **Paper Organisation**, replaced unclear coined wording, and updated related terminology elsewhere for consistency. The revision preserved all 14 equations, 3 numerical tables, and reference entries, according to its recorded checks. The then-new abstract had 215 words and the PDF had 12 pages.

The title temporarily became **Adaptive Arity and Gradual Tree Migration in Hybrid TreeKEM**; this was superseded by the user's subsequent instruction to remove “Gradual.”

The initial comparison copy included yellow highlights plus explanations/deletion notes. The user explicitly rejected the comments. The assistant removed comment text and deletion notes and retained highlights only. The initial historical comparison count was 126 highlights; later edits changed the count.

### October 26: the original chat stalled and this chat continued it

The user showed a screenshot with “Thinking” and “You stopped after 0s.” The assistant inspected **Clarify hybrid meaning in abstract**, found interrupted attempts followed by an in-progress turn with no recorded response/error, and later saw it idle with the attempts interrupted. The precise cause was **not diagnosed**. Do not state that chat age, context length, a removed working directory, or any particular connection failure was proven to be the cause.

The assistant read all available turns of that chat and continued here. Original chat ID: `01a145da-642f-7251-af10-44c4bed5bd7b`. Its recorded working directory was the obsolete `D:/Github/Master-Hybrid-MLS/ترم 4/پایان نامه`; current work belongs at the root repository and `paper/` paths above.

### October 26: five additional requested corrections

These came from the user's next editing request. Only the title removal was explicitly attributed there to the professor; do not attribute every item to him automatically.

1. **Title:** remove “Gradual,” leaving **Adaptive Arity and Tree Migration in Hybrid TreeKEM**.
2. **Reduction wording:** replace ambiguous “..., or 44.9%” with **“... by 44.9%, from 12,672 to 6,976 bytes.”**
3. **Eleven updates:** explain the transition cost and later savings in language the author can understand. The abstract now states that for 1,024 members the first four-ary update encrypts separately for the other 1,023 members and costs more than a binary-tree update; eleven subsequent updates offset that excess **assuming each immediately achieves the fully populated four-ary cost**. The matching contribution sentence was clarified too.
4. **Repetition:** remove the introduction paragraph beginning **“Long-term confidentiality also requires attention to quantum attacks on classical public-key mechanisms.”** The user judged the abstract definition sufficient. This supersedes the part of original comment 13's resolution that described a separate quantum/hybrid paragraph.
5. **MLS explanation and references:** verify `[1, Sections 7.5 and 12.4]`, introduce Commit/committer/epoch, explain fresh path randomness and its connection to PCS, and retain necessary qualifications.

RFC 9420 Sections 7.5 and 12.4 were checked and are valid references. Sections 3, 7.4–7.6, and 16.6 were used for more precise explanations. Fresh randomness supports recovery only under suitable conditions, including that the attacker cannot continue obtaining relevant current state or recover the fresh secret through a compromised delivery route.

The abstract became 233 words after these changes. Word/PDF output remained 12 pages. The clean and highlighted PDFs were checked to have identical text. The professor's original remained unchanged. Commit: `1861c1e` — `docs: revise manuscript after professor review`.

### October 27: separate repository cleanup visible in Git

Commit `d8e7f8f` — `feat: delete unnecessary files` — removed root-level `questions.docx`, `~$estions.docx`, and `~WRL0104.tmp`. This is verified repository history; this log does not attribute its execution to an action in this continuation chat.

### October 30: professor approved Commit wording but rejected epoch wording

The user sent the professor a screenshot of the explanatory paragraph. The professor replied:

> تعریف commit خوب شده. اما تعریف epoch خوب نیست

Meaning: the Commit definition has improved, but the epoch definition is not good.

The old definition was:

> An epoch is a numbered stage of the group's shared cryptographic state, with its own membership and message-protection keys.

The assistant checked RFC 9420 Sections 2, 3, 12, and 9.1. Key findings: an epoch denotes a group state; a new epoch need not change the member set; message keys can evolve within an epoch. The user approved replacing **only the epoch definition**. The existing Commit sentence was left as approved by the professor.

Current agreed sentence, including its citation:

> In MLS, an epoch is a group state in which a fixed set of authenticated members share an epoch secret used to derive keys for protecting their messages [1, Sections 2 and 3].

The following sentence remains:

> A member called the committer sends an authenticated control message, called a Commit, to start the next epoch.

Verification: exactly one sentence in one paragraph changed; only `word/document.xml` changed inside the DOCX package; Markdown had one changed line; clean PDF pages 2–12 rendered pixel-identically to the preceding version. Both PDFs remained 12 pages. Later-page highlight rectangles were preserved. Current comparison count: 187 highlights, no comment text. Commit: `0a406e1` — `docs: clarify MLS epoch definition using RFC 9420`.

### October 30: the user questioned highlights on uncommented pages

The user asked why other pages were highlighted when the professor had not commented on them. The assistant explained that the earlier revision had propagated consistency edits through the body (for example replacing “TreeCover,” “healthy” labels, and thesis-centric wording) and highlighted all differences against the original review, not only passages anchored to professor comments. The assistant acknowledged that this broader scope should have been explicit.

No rollback or removal of later-page highlights was requested or performed. For the epoch-only change, all other manuscript text and later-page highlights were preserved. Future agents should not equate a highlight with a professor comment and should not broaden narrowly requested edits without explaining the scope.

### October 30: “four-ary” versus “four arity”

This was the user's terminology question, not a professor correction. The explanation was:

- **a four-ary tree** is the conventional adjective form;
- **a tree with arity four** is also grammatical;
- **four arity tree** is not standard wording;
- **a tree with up to four children per node** is a plainer explanatory alternative.

No terminology change was requested or applied.

### October 30: candid discussion of publication value

The user expressed worry about whether the research deserved a paper, while the professor encouraged publication. The assistant reread the current manuscript and inspected the closest cited work. Its assessment was: a worthwhile research direction with a plausible contribution, but the draft does not yet demonstrate the migration contribution convincingly enough. This is the assistant's developmental assessment, **not professor feedback, a peer-review decision, or an acceptance prediction**.

Potential contribution: changing tree arity without paying all rebuilding costs immediately, with explicit accounting for temporary use of old keys and its security tradeoffs. Higher-arity TreeKEM, mKEM savings, and tree-degree optimization already exist in prior work. Originality of this particular migration design has not been established by an exhaustive literature review.

## Scientific boundaries and unfinished research work

These are important context for future writing. They are not permission to rewrite the paper or invent experiments.

1. **The 44.9% figure is a model result.** It compares selected public-key/encapsulation components of idealized mature trees at 129 members. It is not a measured reduction in complete protocol traffic and does not by itself evaluate the migration mechanism.
2. **The eleven-update result is conditional.** Initial extra cost: `89,360 - 15,840 = 73,520` bytes. Assumed later saving: `15,840 - 8,720 = 7,120` bytes per update. Ten updates save 71,200 bytes; eleven save 78,320 bytes. This explains the ceiling result but assumes immediate mature-tree follow-up costs. It does not measure actual sparse-tree migration.
3. **No complete composed-protocol proof has been supplied.** KEM/combiner security and standard TreeKEM proofs do not automatically prove the proposed migration construction secure.
4. **Retained old keys matter to group-wide recovery.** A copied old key may continue revealing a new path secret, allowing derivation upward to the new root contribution when the attacker also has relevant preceding state. A cost threshold does not establish cryptographic recovery.
5. **Specification details remain open.** Canonical encodings, exact KDF choices, nonce handling, authenticated transition state, joins/removals, recipient eligibility, and retirement need precise treatment matched to the intended security model. Classical authentication must not be described as full protection against active quantum attackers without a corresponding signature treatment.
6. **mKyber is not simply standardized ML-KEM under another name.** The manuscript's analytical sizes use the cited mKyber parameter set (768-byte public key, 704-byte common component, 48-byte recipient component), plus 32-byte classical keys/encapsulations. Check the actual primitive/profile and theorems when revising claims. The distinction between standard and adaptive-corruption multi-user security must be retained.
7. **The thresholds are illustrative.** Degree/window examples and retirement thresholds have not been empirically optimized. Do not present them as proven optimal settings.
8. **Existence of implementation folders is not experimental evidence.** No new implementation validation, benchmark, simulation, or end-to-end migration study was performed in this chat.
9. **Suggested next scientific work:** evaluate cumulative communication across a full migration with sparse nodes, updates, joins/removals, and retirement. Compare identical operation sequences under fixed binary, immediate rebuilding, and the proposed mechanism; consider other degrees where relevant. A rigorous analytical treatment is also possible. Report both favorable and unfavorable regimes and match security claims to explicit rules/assumptions.
10. **Publication status:** no target venue, submission, formal peer-review outcome, or publication acceptance is recorded. Better prose alone does not close the methodological gaps.

## Sources previously consulted and citation status

- RFC 9420: <https://www.rfc-editor.org/rfc/rfc9420.html>. In-paper reference `[1]`.
  - Section 2: formal terminology, including epoch.
  - Section 3: group/epoch overview and shared epoch secrets.
  - Sections 7.4–7.6: new path randomness, secret derivation/distribution, UpdatePath.
  - Section 12, especially 12.4: epoch transitions and Commit messages.
  - Section 9.1: per-sender message-key evolution within an epoch.
  - Section 16.6: FS/PCS conditions and member updates.
- Alwen et al., *How Multi-Recipient KEMs can help the Deployment of Post-Quantum Cryptography*: <https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/how-multi-recipient-kems.pdf>. Section 4 includes higher-arity TreeKEM; this is important prior work, not a new contribution of this manuscript.
- Chevalier et al., *The Art of Bonsai: How Well-Shaped Trees Improve the Communication Cost of MLS*: <https://eprint.iacr.org/2024/746>. Examines tree evolution and degree optimization. Do not directly compare its percentage gains with ours without aligning parameters, baselines, and counted fields.
- Earlier mKEM proof source recorded in the repository: <https://cryptojedi.org/papers/mkem-20220812.pdf>.

These links record sources checked during earlier tasks. They do not mean that all 12 bibliography entries have received a fresh metadata audit on November 5. Recheck current draft versions and venue rules when needed; do not assume the IETF draft-version statements in the paper remain current indefinitely.

## Document production and technical lessons

- Use the bundled workspace dependency loader before document work. Previously resolved Python: `C:/Users/parsa/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe`; Node: `C:/Users/parsa/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe`. Resolve again if unavailable.
- Follow the document/PDF skills and visually inspect rendered output. Packaged `render_docx.py` was attempted but LibreOffice/`soffice.exe` was unavailable. Installed Microsoft Word COM export followed by `pypdfium2` rendering worked.
- Earlier sandboxed attempts could not see D:, sometimes defaulted to C: despite a working-directory argument, or failed Word COM with `E_ACCESSDENIED`. The former restricted profile needed escalation; the profile on November 5 is unrestricted with approvals disabled. Do not copy old escalation arguments blindly. Use an explicit repository path and stop if changing directory fails.
- Some failed renderer attempts also reported temporary-directory cleanup permissions. Those failures were not manuscript errors and were worked around with Word export.
- Prefer a minimal OOXML replacement for an approved one-sentence edit. Validate that equations/tables/references and other package parts remain unchanged. Do not rebuild the audit and figures accidentally.
- The Word DOCX and exported PDFs must have matching text. The highlighted copy should add yellow only and no explanatory annotations. During previous checks the highlighted renders preserved the clean render's red/green channels exactly and only reduced blue where yellow was applied.
- Full-document word-diff highlighting can introduce fragmented marks when wrapping changes. For the epoch-only update the assistant mapped existing highlighted text and preserved later-page annotations rather than treating reflow as new content.
- Git initially treated the ASCII-generated `migration_figure.pdf` as text and reported trailing whitespace/CRLF conversion. PDF cross-reference formatting must not be “cleaned up” as ordinary text. Preserve generated binary artifacts byte-for-byte in staging and verify with raw Git object hashes when needed.
- An attempted `core.autocrlf=false` staging of the entire paper also staged CRLF text without normal normalization and caused large whitespace reports. Text was renormalized separately. Some original quoted review text contains CR characters/trailing spaces; these are historical quotation issues, not scientific failures. Do not churn the manuscript just to silence inappropriate checks on PDF bytes.
- Keep internal review records separate from professor-facing comparison annotations. Historical records can legitimately describe earlier intermediate output (e.g. deletion notes, 126/199 highlights); current output supersedes those snapshots.

Task-local backups/scripts from this continuation, if still present:

`C:/Users/parsa/.codex/visualizations/2026/10/26/01a17952-bf2d-7ac0-a361-16b434269801/`

- `revise_latest.py`, `verify_and_highlight.py`, `latest-paper-revision/`: October 26 five-change preparation and checks.
- `epoch_only.py`, `epoch-revision-2026-10-30/`: October 30 minimal epoch replacement, backups, rendered pages, and `checks.json`.

Do not rerun these scripts without reading them: they refer to fixed dates, baseline files, and snapshot counts, and some assert that backups do not already exist. They are not generic current-state rebuild commands.

## Git milestones

| Commit | Date (Asia/Tehran) | Meaning |
| --- | --- | --- |
| `e4a1c0b` | 2026-10-26 | `feat: add paper info` — earlier paper material in repository history. |
| `48174fc` | 2026-10-26 | `chore: reorganize repository and remove obsolete thesis backups`. |
| `1861c1e` | 2026-10-26 | `docs: revise manuscript after professor review` — broad review revision plus the five subsequent corrections and comparison files. |
| `d8e7f8f` | 2026-10-27 | `feat: delete unnecessary files` — three root-level obsolete/temp files. |
| `0a406e1` | 2026-10-30 | `docs: clarify MLS epoch definition using RFC 9420` — one sentence plus regenerated outputs. |

## Research Agent Skills installation on November 5

Requested repository: <https://github.com/KalarisLabs/research-agent-skills>.

The collection index and five specialist skills were already present and were verified by their local `SKILL.md` files. The collection index recommends selecting relevant specialists rather than installing the entire collection unless explicitly requested. For this paper, the following are available globally under `C:/Users/parsa/.codex/skills/`:

| Skill | Status in this task | Intended use |
| --- | --- | --- |
| `research-agent-skills` | Already installed, verified | Collection index and choosing a relevant specialist. |
| `scientific-writing` | Already installed, verified | Evidence-grounded manuscript drafting/revision. |
| `citation-verification` | Already installed, verified | Bibliographic existence/metadata checking; not a substitute for checking whether a source supports a claim. |
| `literature-review` | Already installed, verified | Structured literature synthesis and gap analysis. |
| `peer-review` | Already installed, verified | Claim/evidence and manuscript assessment. |
| `rebuttal-and-response-to-reviewers` | Already installed, verified | Tracking and answering review feedback. |
| `abstract-and-title` | Newly installed | Titles, abstracts, keywords, and contribution wording. |
| `unslop-academic-writing` | Newly installed | Specific, clear academic prose and a local prose linter. |
| `reproducibility-statement` | Newly installed | Accurate code/data availability, reproducibility, and disclosure statements when required. |

The three new skills were installed with the official local Skill Installer helper from the pinned upstream revision `fa023d6d166562a8de118f59bb73647c0e444b8c`, using paths `skills/abstract-and-title`, `skills/unslop-academic-writing`, and `skills/reproducibility-statement`. Existing skills were not overwritten or claimed to be freshly updated. All nine `SKILL.md` files were verified locally after installation. The full collection was not installed, and no paid service/account was configured. New skills are available from the next turn; invoke them by name or describe the writing task normally. Their presence does not verify scientific correctness or prove publication readiness.

## All 31 original professor comments

The appendix below preserves every original comment from `comment_resolution.json`, with whitespace normalized for readable Markdown. Wording/typos in the comments are otherwise retained. The resolutions are the recorded October 26 actions; explicit later superseding notes are added where needed. “Applied” records an edit, not later professor approval or a guarantee that every issue is scientifically settled.

### Original comment 1 (original PDF page 1)

> حذف

Recorded resolution: Removed the honorific Dr from the author line in the clean manuscript and synchronized source.

Recorded status: **applied**.

### Original comment 2 (original PDF page 1)

> حذف

Recorded resolution: Replaced the coined title with Adaptive Arity and Gradual Tree Migration in Hybrid TreeKEM.

Recorded status: **applied**.

Later context: Superseded title: the professor later asked to remove Gradual. The current title is Adaptive Arity and Tree Migration in Hybrid TreeKEM.

### Original comment 3 (original PDF page 1)

> ابتدا یک جمله بیاورید که منظور از طرحهای هایبرید و مزایای آنها را بیان کند و سپس این جمله را بیاورید.

Recorded resolution: Abstract opens by defining classical/post-quantum hybridization and its motivation.

Recorded status: **applied**.

### Original comment 4 (original PDF page 1)

> قبل از این یک جمله بیاورید و TreeKEM را معرقی کنید.

Recorded resolution: Abstract introduces TreeKEM and its role in MLS before describing the mechanism.

Recorded status: **applied**.

### Original comment 5 (original PDF page 1)

> خواننده نمیداند که چیست. بیان را تغییر دهید.

Recorded resolution: Replaced commit secret in the abstract with a plain description; introduction explains the fresh contribution to the group secret.

Recorded status: **applied**.

### Original comment 6 (original PDF page 1)

> خواننده نمیداند که چیست.

Recorded resolution: Replaced path secrets in the abstract with secret values needed to establish new keys; introduction defines path secret.

Recorded status: **applied**.

### Original comment 7 (original PDF page 1)

> يعنی چه؟ قبلا توضیحی داده نشده!

Recorded resolution: Replaced healthy-tree approximation with a balanced tree whose required internal keys are available.

Recorded status: **applied**.

### Original comment 8 (original PDF page 1)

> ؟؟؟؟؟

Recorded resolution: Replaced modeled payload with public-key and encapsulation data per update and stated exclusions.

Recorded status: **applied**.

### Original comment 9 (original PDF page 1)

> ؟؟؟؟

Recorded resolution: Replaced unexplained modeled cost wording with an explicitly conditional transition example.

Recorded status: **applied**.

### Original comment 10 (original PDF page 1)

> evaluation

Recorded resolution: Abstract now uses security evaluation and describes communication analysis directly.

Recorded status: **applied**.

### Original comment 11 (original PDF page 1)

> جنس این کامیت چیست؟ از جنس يک پیام است؟ چه کسی تولید و ارسال میکند؟ خود MLS چگونه از آن یاد میکند؟

Recorded resolution: Introduction identifies a Commit as an MLS message created and broadcast by a member acting as committer, initiating an epoch; cites RFC 9420 Sections 7.5 and 12.4.

Recorded status: **applied**.

Later context: Later expanded and checked against RFC 9420. The professor subsequently approved the Commit explanation, but rejected the first epoch definition; the approved replacement is recorded above.

### Original comment 12 (original PDF page 1)

> کدام کلیدهای عمومی؟؟؟؟ در جملات قبل حرفی از کلید عمومی نبود که الان در این جمله به آنها ارجاع میدهید!

Recorded resolution: Introduction explains the public encryption keys at tree nodes before discussing transmission cost.

Recorded status: **applied**.

### Original comment 13 (original PDF page 1)

> به نظرم مقدمه نباید مستقیما با MLS شروع شود. بلکه باید با اهمیت تبادل کلید گروهی شروع شود بعد هم با مفاهیم امنیت پساکوانتومی و هیبریدی ادامه یابد و بعد به MLS پرداخته شود.

Recorded resolution: Introduction starts with group key exchange, then quantum and hybrid security, then MLS.

Recorded status: **applied**.

Later context: Later user instruction superseded the separate quantum/hybrid paragraph: it was removed as repetitive. Keep the broader-to-specific introduction flow without restoring that paragraph automatically.

### Original comment 14 (original PDF page 1)

> يعنی چی 
> makes the cost relevant؟؟؟

Recorded resolution: Replaced makes the cost relevant with an explicit explanation that two key/ciphertext components increase update communication.

Recorded status: **applied**.

### Original comment 15 (original PDF page 1)

> in a

Recorded resolution: Rewrote the prior-work sentence with Alwen et al. as subject, removing the ungrammatical phrase.

Recorded status: **applied**.

### Original comment 16 (original PDF page 1)

> حذف

Recorded resolution: Deleted the first-author thesis phrase and its citation from the introduction; retained source provenance in its own section.

Recorded status: **applied**.

### Original comment 17 (original PDF page 1)

> یه جوری نوشتین که انگار یک اصطلاح کاملا یونیورسال است. این اصطلاح خودنان است؟ اگر بله اصلا جالب نیست. از نام معمولی استفاده کنید.

Recorded resolution: Removed TreeCover from manuscript, metadata, headings, and keywords; uses ordinary descriptions of retaining the old tree.

Recorded status: **applied**.

Later context: These terminology changes propagated to later sections and caused highlights on pages without professor comments. The user questioned that scope; later narrow edits must not repeat it silently.

### Original comment 18 (original PDF page 1)

> يعنی چه گره هایی؟؟؟؟ نامفهوم و غیر دقیق است.

Recorded resolution: Introduction states key authentication, private-key availability, and exclusion of removed members for a retained node.

Recorded status: **applied**.

### Original comment 19 (original PDF page 1)

> اینجا هنوز مسئله برای خواننده روشن نیست. باید توضیح دهید که اگر درخت همچنان باینری بماند چه عیبی حادث میشود.

Recorded resolution: Explains why a binary tree can transmit more public keys and common ciphertext components than a shallower tree.

Recorded status: **applied**.

### Original comment 20 (original PDF page 1)

> اول بگویید که KEM چیست و بعد بروید سراغ mKEM.

Recorded resolution: Defines KEM before introducing multi-recipient KEM.

Recorded status: **applied**.

### Original comment 21 (original PDF page 1)

> برای خواننده بگویید که چرا و با چه هدفی این طرحها به سراغ تغییر درخت رفته اند.

Recorded resolution: Explains the depth-versus-recipient tradeoff that motivates changing the tree degree.

Recorded status: **applied**.

### Original comment 22 (original PDF page 1)

> کاور دیگه چيه؟ اگر منظورتون درخت قدیمیه خب نویسین old tree.

Recorded resolution: Uses old tree in the introduction; reserves the mathematical set-cover term for its formal definition in Section 4.2.

Recorded status: **applied**.

### Original comment 23 (original PDF page 1)

> قشنگ مسئله رو باز کنید و ساده بنویسید که معیار مورد نظر برای بازنشسته کردن (کنار گذاشتن) درخت قدیمی چیه؟

Recorded resolution: Our Contribution explains both threshold alternatives for discarding the old tree and the normalization baseline.

Recorded status: **applied**.

Later context: The threshold alternatives are explained in the manuscript, but they remain illustrative efficiency rules and are not cryptographic recovery conditions.

### Original comment 24 (original PDF page 1)

> بیان من در آوردی است (old-tree را به عنوان صفت بکار برده اید). بعد delivery به چه چیزی برمیگردد؟ چه چیزی باید deliver شود؟ ساده و دقیق بنویسید نه تلگرافی و مبهم. introduction باید مسئله را روشن و دقیق بیان کند. بعد هم نوآوریها و نتایج حاصل را بدون ذکر جزئیات بیان کند.

Recorded resolution: Describes who encrypts and distributes which new path secrets using keys from the old tree in complete sentences.

Recorded status: **applied**.

### Original comment 25 (original PDF page 1)

> نباید بگویید نوآوری شما چه چیزهایی نیست. بلکه بگویید چه چیزی هست.

Recorded resolution: States positive contributions and deletes the list of what is not claimed as novel.

Recorded status: **applied**.

### Original comment 26 (original PDF page 1)

> تز؟؟؟؟
> 
> دقیق بگویید چیزی که در این مقاله ارایه میشود چیست؟ یک طرح است یا یک چارچوب یا یک مکانیزم یا یک الگوریتم یا یک سیاست؟ چیست؟

Recorded resolution: Identifies the contribution consistently as a migration mechanism and removes authoritative thesis framing.

Recorded status: **applied**.

Later context: Use migration mechanism consistently, while retaining the distinction between a design proposal and a fully specified/proven cryptographic protocol.

### Original comment 27 (original PDF page 1)

> این بیان غیر مرسوم است

Recorded resolution: Replaces the scope sentence with concrete design, evaluation, and security contributions.

Recorded status: **applied**.

### Original comment 28 (original PDF page 1)

> اصطلاح غیر مرسوم. بیان را ساده و دقیق کنید.

Recorded resolution: Replaces the healthy-tree byte formula label with plain descriptions of the counted components and reference tree.

Recorded status: **applied**.

### Original comment 29 (original PDF page 1)

> این پاراگراف را تخت یک زیربخش با عنوان Our Contribution  بازنویسی کنید

Recorded resolution: Adds an automatically numbered Our Contribution subsection with the mechanism and findings.

Recorded status: **applied**.

### Original comment 30 (original PDF page 2)

> يک زیربخش با عنوان Paper Organisation بیاورید و در آن بگویید بخشهای بعدی شامل چه هستند.

Recorded resolution: Adds an automatically numbered Paper Organisation subsection describing Sections 2 through 8.

Recorded status: **applied**.

### Original comment 31 (original PDF page 2)

> This work

Recorded resolution: Changes the Table 1 row label from Present study to This work.

Recorded status: **applied**.

## Final handoff verification on November 5

- All 31 original comment IDs are included exactly once, along with the initial hybrid-definition request, general review message, later title correction, and later epoch feedback.
- The five user editing requests, highlight-only preference, scope concern, four-ary question, and publication-value discussion are recorded with attribution.
- The original review and current manuscript outputs were inspected; the manuscript was not edited by this logging/skill-installation task.
- This log is deliberately a narrative handoff, not a fresh citation audit, security proof, benchmark report, or a full transcript export.
- Current target venue and next scientific experiment remain undecided. Ask for the user's next task after onboarding rather than assuming a new research program is authorized.

File fingerprints before the November 5 abstract correction (historical snapshot):

- `paper/paper.docx` — SHA-256 `565cd87c6920262f52867c2d56cc98e527e22ce2d01e6da4613e29a0bd3b7077`.
- `paper/paper.pdf` — SHA-256 `2ba16bd50598dd392a3bc604a4d184a28c0254036193078d2871e37465fca3ea`.
- `paper/ParsaniaPaper-Ver1.pdf` — SHA-256 `a77ccd92fa0afdab0b8327ba6695f62f88ba6c666e4693fae7ef350f928f7fd5`.
- `paper/reviews/ParsaniaPaper-Ver1.pdf` — SHA-256 `dbd809a48dec8c5b58ae5d56e22b826d689ede53a149768fdd1154ced22b426e`.


## November 5 follow-up feedback round, message 1

The user requested use of the installed KalarisLabs research skills and explicitly asked to see every manuscript change in chat as exact before/after text.

Professor message, as supplied by the user:

> هنوز کار داره: مثلا در ابسترکت من تا الان چنین عبارتی در هیج مقاله ای تدیده ام: size of key updates  در ابسترکت، MLS آنچنان شناخته شده نیست و باید معرفی بشه.

Interpretation: replace the unclear expression “size of key updates” and introduce what MLS does inside the abstract, rather than assuming readers already know it. The professor's observation about having not seen the wording is a terminology criticism, not evidence that the English phrase has never appeared anywhere.

Applied change 1, introducing MLS before TreeKEM:

Before:

> TreeKEM is the tree-based group key establishment mechanism used by Messaging Layer Security (MLS) to refresh shared keys as group membership changes.

After:

> Messaging Layer Security (MLS) is a protocol that establishes shared keys for end-to-end encrypted group communication. Its TreeKEM mechanism updates these keys as group membership changes.

Applied change 2, naming the communication quantity:

Before:

> Combining both types of cryptography increases the size of key updates.

After:

> Combining classical and post-quantum cryptography increases the amount of data transmitted during these key updates.

The MLS description was checked against RFC 9420 Section 3 on November 5 by the assistant; this is not recorded as a human citation audit. No new citation was inserted into the abstract. The scientific-writing, abstract-and-title, and unslop-academic-writing skills were used. The local prose linter reported no findings for the revised abstract; that editorial result does not validate scientific claims. The independently counted abstract length changed from 233 to 241 whitespace-separated words; no venue word limit has yet been specified.

Scope and verification: only the abstract paragraph changed, with exactly the two substitutions above. The title, introductory definitions (including the approved epoch/Commit text), remaining abstract text, numerical claims, equations, tables, and reference entries were preserved. Only word/document.xml changed inside the DOCX package. Microsoft Word export remained 12 pages. The changed first page was visually inspected; pages 2–12 rendered identically to the previous version. Existing later-page highlight annotations were preserved, no comments were added, and the comparison PDF contains the same text as the clean PDF. Current comparison count: 197 yellow highlights and 13 links. Word, both PDFs, and Markdown source were synchronized. No commit was made.

Task-local backups, script, and checks are in:

`C:/Users/parsa/.codex/visualizations/2026/10/26/01a17952-bf2d-7ac0-a361-16b434269801/abstract-feedback-2026-11-05/`

The preparation script is `abstract_feedback.py` in the parent workspace. Its original generic helper assertion/message mentions sentence replacement; the actual scoped change was two original sentences replaced with three, as shown above. Re-read any dated helper before reuse.

Updated manuscript fingerprints after this correction:

- `paper/paper.docx` — SHA-256 `8e628221ac76036f02eb458273767cbf83b8406224429e7cde10f64e0176772e`.
- `paper/paper.pdf` — SHA-256 `8de3421d7be9b4bf72c133ce51dfe2e83b7bcf708eacb31e572f2804d6f100df`.
- `paper/ParsaniaPaper-Ver1.pdf` — SHA-256 `4e3ffcb1d9128a689995edf61229b1514f6c01102a9bec35bfa62367196fdea3`.
- `paper/publication_work/paper.md` — SHA-256 `0b236a89db2d76e8bf9b973181540cac6d3c5b51e569271c44ccceee42fe2190`.


## November 5 comparison version correction

The user corrected the review workflow immediately after the first new feedback message:

> do not touch ParsaniaPaper-Ver1.pdf and revert your last changes. changes should be in ParsaniaPaper-Ver2.pdf cause i want to send it to my professor i dont want him to read those all again

Applied interpretation: restore the edits to the old comparison file, retain the requested abstract corrections in the current manuscript, and present those corrections in a new second-round PDF. The user wants the professor to see only new changes in this round; this does not request reverting the approved abstract wording in Word/the clean PDF.

- Restored `paper/ParsaniaPaper-Ver1.pdf` from the pre-edit backup and verified that its raw Git object hash matches `HEAD:paper/ParsaniaPaper-Ver1.pdf` at commit `0a406e1`. It is no longer modified in the working tree.
- Created `paper/ParsaniaPaper-Ver2.pdf` from the current clean manuscript with exactly the new MLS introduction/TreeKEM explanation and communication-cost wording highlighted. It has 4 yellow highlight annotations, all on page 1, and none of the old-round highlights on other pages.
- Ver2 has 12 pages, the same text as `paper/paper.pdf`, 13 links, and no comment text or popup notes. Its first page was visually inspected; pages 2–12 render exactly like the clean PDF.
- Current Word, clean PDF, and Markdown retain the two abstract substitutions already shown in chat. No additional manuscript text change was made in this packaging correction.
- Future revisions in this feedback round must update **Ver2**, accumulate new-round changes relative to the frozen Ver1 text, and continue showing each textual before/after in chat. Do not overwrite Ver1 or copy its old highlights into Ver2.
- The earlier paragraph in this log describing the initial November 5 update of Ver1 is historical and is superseded by this correction.
- No commit was requested or made.

Verification fingerprints:

- Frozen Ver1 SHA-256: `a77ccd92fa0afdab0b8327ba6695f62f88ba6c666e4693fae7ef350f928f7fd5`.
- Current Ver2 SHA-256: `fc96137c489b0dbfc16b0b83a7a6f8dd58dd25ab1cce591f5a79edb3a1cddabb`.


## November 5 follow-up feedback round, message 2

Professor feedback supplied by the user:

> در مرجع دهی ها فقط شماره مرجع رو دکر کنید. شماره زیربخشهای مرجع را حذف کنید.

Meaning: in citations, give only the reference number and remove source subsection numbers. Applied consistently to source section, theorem, and table locators so the bracketed citations contain only reference numbers.

Every replacement (one occurrence each):

| Before | After |
| --- | --- |
| `[1, Sections 2 and 3]` | `[1]` |
| `[1, Sections 3 and 12.4]` | `[1]` |
| `[1, Sections 7.4-7.6 and 16.6]` | `[1]` |
| `[2, Section 4]` | `[2]` |
| `[9, Section 6]` | `[9]` |
| `[2, Sections 2.3 and 3.1]` | `[2]` |
| `[12, Theorem 5]` | `[12]` |
| `[2, Table 1]` | `[2]` |

This is an editorial citation-style change, not a change to which sources support the claims. References to this paper's own sections, equations, tables, and theorem discussion were preserved. Bibliographic entries and numbering, all equations and numerical tables, the approved epoch/Commit definitions apart from their citation format, and the previous abstract corrections were preserved. Precise RFC/source locators remain in internal historical/source-verification records; they are no longer printed inside manuscript citations. The October 30 epoch sentence recorded earlier with `[1, Sections 2 and 3]` is therefore now printed with `[1]`.

Exactly eight citation replacements were verified in Word and the matching Markdown source. Exported PDFs contain the same manuscript text and have 12 pages. Visually affected pages 1, 3, 4, and 8 were inspected; the other pages rendered identically to the preceding version. Ver2 retains this round's abstract highlights and marks the simplified citations; it has 23 highlight annotations and 13 links, with no comment text. The changes on later pages in Ver2 now correspond to the professor's new citation-format request. Ver1's SHA-256 was checked and is unchanged. Word, clean PDF, Ver2, and Markdown were saved together. No commit was made.

Task-local script: `reference_numbers_only.py` under this chat's visualization workspace. Backups/rendered pages/checks: `reference-style-2026-11-05/` in the same workspace. These are dated helpers, not generic rebuilding scripts.

Latest file fingerprints:

- `paper/paper.docx` — SHA-256 `c2462780040ca00ad7c22c071e324f514c95c5d49d51d6d3c732d58fd5725119`.
- `paper/paper.pdf` — SHA-256 `17e84643ed5d692f9d38162202d2e4e16a41836c2cd188b2853b9dd5d74a6e8e`.
- `paper/ParsaniaPaper-Ver2.pdf` — SHA-256 `c3662eb27fe0545b1d7c55c426cbc90f7c261d558342fc27aa74ea1e57682026`.
- `paper/publication_work/paper.md` — SHA-256 `4425ca35e9b882c54710ba1c369fcf12389b7c3fdea81f0e6cfac41e9eb593fa`.


## November 5 follow-up feedback round, message 3

Professor feedback supplied by the user:

> در صفحه ۱ به هایبرید treekem اشاره میکنید اما مرجعی نمیدهید. آیا در مرجعی جز مرجع اصلی treekem ذکر شده؟

Meaning: hybrid TreeKEM is mentioned on page 1 without a reference; is it discussed in a source other than the original TreeKEM reference?

Source investigation used the installed citation-verification skill and primary sources. The existing reference [6], Rohan Mahy and Richard L. Barnes, ML-KEM and Hybrid Cipher Suites for Messaging Layer Security, draft-ietf-mls-pq-ciphersuites-06 (21 July 2026), explicitly proposes MLS cipher suites combining ML-KEM with X25519/P-256/P-384. Title, authors, version, date, and relevant content were checked on the official IETF sources by the assistant. The draft supports the classical/post-quantum hybrid MLS approach. It does not by itself specify or prove this paper's exact mKyber migration construction. It remains an Internet-Draft/work in progress, not an RFC.

Verified pinned source: https://www.ietf.org/archive/id/draft-ietf-mls-pq-ciphersuites-06.html

The latest Datatracker page also showed revision 07, dated 1 November 2026. The current manuscript's explicit archived revision-06 citation and matching background description were retained to keep this correction scoped; do not call revision 06 the latest version. A future update to [6] should change the bibliography and associated background wording together after checking the selected version.

Reference [2] was checked for its actual support: it discusses post-quantum mKEMs and higher-arity TreeKEM. Its uses of the word hybrid do not establish this paper's combined classical/post-quantum node construction. Reference [10]'s checked abstract concerns a symbolic proof of standard TreeKEM; its title or use of HPKE must not be mistaken for evidence of the specific hybrid PQ construction. Hybrid in HPKE and a proof's hybrid argument have different meanings from classical/post-quantum hybrid key establishment. The bounded search did not establish a peer-reviewed canonical protocol with the exact name and construction used here; no exhaustive novelty claim is made.

Applied replacement (one occurrence in the introduction):

Before:

> In hybrid TreeKEM, each usable node carries both classical and post-quantum key material.

After:

> An IETF draft proposes MLS cipher suites that combine classical and post-quantum key establishment [6]. Here, hybrid TreeKEM refers to a TreeKEM construction in which each usable node carries both classical and post-quantum key material.

This separates the cited prior hybrid MLS direction from this paper's explicit definition, instead of attaching an unsupported citation to the entire construction. The citation is [6] only, with no source subsection locator. No bibliography entries or reference numbering were changed.

The remaining manuscript text, abstract, equations, tables, earlier citation-format changes, and existing review-round highlights were preserved. Word, Markdown, the clean PDF and Ver2 were synchronized. The PDFs contain identical text and remain 12 pages. Visually affected pages 1–4 were inspected; all other clean pages render identically to the preceding version. Ver2 contains 27 highlights and 13 links with no comment text. Frozen Ver1's checksum remains unchanged. The new content flows from the bottom of page 1 onto page 2. No commit was requested or made.

Task-local preparation script: `hybrid_treekem_citation.py` in this chat's visualization workspace; backups/rendered pages/checks: `hybrid-treekem-citation-2026-11-05/`.

Latest file fingerprints:

- `paper/paper.docx` — SHA-256 `a129c6380b2834dffe9ed18cb630ee3a7367836ee4f9c4887911c653ae88312f`.
- `paper/paper.pdf` — SHA-256 `2caa5f8d02040c2906b3ffed271ac8065c9ebd6258cb6391e2ca7b28c11050d7`.
- `paper/ParsaniaPaper-Ver2.pdf` — SHA-256 `11cc5e7c65bc47bc56ea741b2ed768dc536b6cb8963b022b9964adc4ef2b09c6`.
- `paper/publication_work/paper.md` — SHA-256 `30783134e3a7e2b9b5c920b334c1b50ed273a91e5f59303477446d6b7d2d1525`.


## November 5 follow-up feedback round, message 4

Professor feedback supplied by the user:

> آخرین جمله از پاراگراف اول در ص ۲ کاملا رهاست. منطقا به قبل از خود نچسبیده و بعد از ان هم که پاراگراف تمام میشود. لااقل نتایج کلی بدست امده از مرجع ۳ رو هم دکر کنید.

Meaning: the final sentence of the first paragraph on original page 2 is disconnected from the preceding argument; at least summarize the general results of reference [3]. In the current pagination, the relevant passage is the first complete Alwen/Chevalier paragraph after the continuation of the preceding page's hybrid-definition paragraph. The target was identified by its closing citation to [3], not by blindly assuming the first text block on the reflowed page.

Source checked: Chevalier, Lebrun, Martinelli, and Plut, The Art of Bonsai: How Well-Shaped Trees Improve the Communication Cost of MLS, https://eprint.iacr.org/2024/746 (revision shown: 11 April 2025). The accessible primary-source abstract explicitly reports the classical binary/post-quantum ternary preference and 5-10% communication improvements. Direct PDF retrieval returned HTTP 403, so the assistant relied on that accessible original abstract for these general findings, not on an asserted full-text reading. No new bibliography item was needed.

Applied replacement (one closing sentence expanded into three connected result sentences):

Before:

> Chevalier et al. also examine tree shape and degree as ways to reduce MLS communication [3].

After:

> Chevalier et al. also show that the best tree degree depends on the cryptographic parameter set. In their analysis, binary trees are preferable with classical algorithms, while ternary trees are generally more efficient with post-quantum algorithms. By improving how the tree grows and selecting a suitable degree, they reduce TreeKEM communication by 5-10% for the parameter sets studied [3].

The revision connects [3] to the preceding depth-versus-recipient-cost discussion by explaining the dependence on cryptographic parameters, then states the classical/post-quantum degree result and the reported communication reduction. The 5-10% is expressly attributed to that study's parameter sets. It is not asserted to share the baseline of this manuscript's 44.9% component-cost example, and it does not establish that our chosen degrees are globally optimal.

No other manuscript text, bibliography entries, equations, or table data changed. The earlier corrections and review-round highlights were preserved. Word, clean PDF, Ver2, and Markdown source were synchronized; PDFs remain 12 pages and have identical text. Reflow affected pages 2-9, which were visually inspected; other clean pages render identically to the preceding version. Ver2 now has 32 highlights and 13 links with no comments/popups. Ver1's frozen hash was checked and remains unchanged. No commit was requested or made.

Task-local preparation script: `reference3_results.py` in this chat's visualization workspace; backups/rendered pages/checks: `reference3-results-2026-11-05/`.

Latest file fingerprints:

- `paper/paper.docx` — SHA-256 `bb83f172863a5929d53a2d6dd43dd9054edaa62b9b703d0ce4850f678e0025ec`.
- `paper/paper.pdf` — SHA-256 `8b7302917de62f5ab437a08aa659631357f57db98c0d76b4e961744245386de9`.
- `paper/ParsaniaPaper-Ver2.pdf` — SHA-256 `b07e2de44c7d8ccf89acd417a0bf1573c1d7abe4a9e3e02b496a7ee00578b959`.
- `paper/publication_work/paper.md` — SHA-256 `65cf017c0850fd34a65683237a9551fba107508a2fb252beb789cc5a2f7a1385`.


## November 5 follow-up feedback round, message 5

Professor feedback supplied by the user:

> جمله ی We evaluate the public-key and encapsulation communication costs درست نیست. زیرا public-key و encapsulation که با و به هم وصل شده اند همجنس نیستند.

Meaning: the coordinated terms public-key and encapsulation are not parallel. A public key is a cryptographic object, whereas encapsulation is an operation. The sentence should identify the transmitted objects whose communication costs are being evaluated. The user's message also ended with the token svg; no separate request to draw an image was inferred from it.

Applied replacement (only the opening clause of the quoted sentence):

Before:

> We evaluate the public-key and encapsulation communication costs

After:

> We evaluate the communication costs of transmitting public keys and KEM ciphertexts

The remainder of the sentence, starting with “, including the initial transition cost”, is unchanged. Both coordinated objects are now transmitted data: public keys and KEM ciphertexts. KEM ciphertexts matches the model's counted shared and recipient encapsulation components; it does not broaden the model to include every encrypted path-secret payload, signature, or framing field. The interpretation was checked against the manuscript's existing accounting definitions; no new external claim, reference, experiment, or numerical result was added.

Exactly one clause in the Our Contribution paragraph changed. All other manuscript text, references, equations, and table data were preserved. Word, clean PDF, Ver2, and Markdown were synchronized; both PDFs remain 12 pages and contain identical text. Only page 2's clean rendering changed; it was visually inspected and all other pages rendered identically to the preceding version. Ver2 preserves earlier changes from this review round and now contains 33 highlights and 13 links with no comment text. Ver1's frozen checksum remains unchanged. No commit was requested or made.

Task-local preparation script: `parallel_cost_wording.py` in this chat's visualization workspace; backups/rendered pages/checks: `parallel-cost-wording-2026-11-05/`.

Latest file fingerprints:

- `paper/paper.docx` — SHA-256 `2cdbb29eb4728c0718104207c16d78d2b8c240b1f452629b1d976089b7777bce`.
- `paper/paper.pdf` — SHA-256 `3e5d466c0e63966d973c7c99743c5ebabab4efc0d03745c9377d037982250348`.
- `paper/ParsaniaPaper-Ver2.pdf` — SHA-256 `eeedbc6ee3e012d4e902c7ea5bf634478753a496cb9b7549a47a8b195891313f`.
- `paper/publication_work/paper.md` — SHA-256 `11da12e780a7842138024908e9aadbe250bff8fd471c85aacbbc595f09896f81`.


## November 5 follow-up feedback round, message 6

Professor feedback supplied by the user:

> encryption delivers selected path secrets to members.
> جملاتی مثل جمله بالا معنی نمیده

Interpretation: the sentence compresses the encryption and recovery steps into vague delivery wording. Explain the actors, the public/private keys, and the message carrying the ciphertexts. This is a local clarification, not a new protocol or security claim.

Exact before:

> Path derivation and recipient encryption have different roles: path secrets determine future node keys and the commit secret, whereas encryption delivers selected path secrets to members.

Exact after:

> Members use path secrets to derive updated node keys and the commit secret. The committer encrypts the required path secrets using the public keys of suitable tree nodes and includes the ciphertexts in the Commit message. Recipients use the corresponding private keys to recover the secrets and derive the updated keys [1].

Evidence: checked the primary RFC 9420 text at https://www.rfc-editor.org/rfc/rfc9420.html#section-7.5 . Sections 7.4–7.6 describe path-secret derivation, encryption to public keys of resolution nodes, and recipient decryption/derivation; Section 12.4 connects the update path to the Commit and commit secret. These locators are internal evidence notes only; the manuscript adds the reference-number citation [1]. The assistant inspected the relevant RFC text; this was not a new whole-bibliography audit.

Only the quoted span in the Background paragraph under Tree state and hybrid delivery changed. The surrounding text, equations, tables, and bibliography were preserved. Word, clean PDF, Markdown, and the current Ver2 review PDF were synchronized. Both PDFs remain 12 pages. Ver2 has 37 yellow highlight annotations and 13 links, with no comment text; previous review-round highlights were preserved. Its extracted text exactly matches the clean PDF. Rendered pages 3–9, affected by reflow, were visually inspected; the other pages were pixel-identical to the previous clean rendering. Highlighting changes only the yellow background, not the rendered text. Frozen Ver1 was verified unchanged. No commit was requested or made.

Reproducibility artifacts outside the repository: `C:/Users/parsa/.codex/visualizations/2026/10/26/01a17952-bf2d-7ac0-a361-16b434269801/path_secret_explanation.py` and its stage directory `path-secret-explanation-2026-11-05/`, containing before copies, revised outputs, page renders, and `checks.json`.

Latest SHA-256 fingerprints after message 6:

- `paper/paper.docx`: `c150d3f96cf5c89a6b799a3032d73bfce36967f7c7162c64842892e48bb9dbc7`.
- `paper/paper.pdf`: `4144721742173a408cc67d4fbfecde3042483ab49c1be8765c501d4ad92435ed`.
- `paper/ParsaniaPaper-Ver2.pdf`: `390c5ecf5a31dd680bddcbe6de6978e453b5763a06f7fd36eb3271dc15cef6f0`.
- `paper/publication_work/paper.md`: `e6af6665cc7e8899d00a33d00e528d290b066de05e2cd238c38479434813c73d`.


## November 5 follow-up feedback round, message 7

Professor feedback supplied by the user:

> همینطور عبارتی مثل recipient encryption. منظورتون چی بوده؟

The user requested a simple explanation first, then a correction. Intended meaning: the committer encrypts a path secret for the intended recipients using the appropriate tree-node public keys; recipients recover it with the matching private keys they hold. The old phrase was ambiguous about who performs encryption. It was descriptive shorthand, not a separately defined operation.

This exact phrase in the Background sentence was already removed by the immediately preceding message-6 replacement. No further manuscript edit was needed. The current explanation is:

> Members use path secrets to derive updated node keys and the commit secret. The committer encrypts the required path secrets using the public keys of suitable tree nodes and includes the ciphertexts in the Commit message. Recipients use the corresponding private keys to recover the secrets and derive the updated keys [1].

Rechecked the current Word, Markdown, clean PDF, and Ver2 text. The only remaining substring “recipient encryption” occurs within the different heading “Multi recipient encryption and tree degree”; it does not reuse the rejected standalone expression. That heading refers to the established multi-recipient topic and was not changed in this narrowly scoped response. Reopened primary RFC 9420 Section 7.5 for the encryption/decryption explanation. No source, numeric claim, bibliography, layout, or highlight was changed. Word/PDF/Markdown hashes remain those recorded after message 6. Ver1 remains untouched. Only this session-log entry was added; no commit was requested or made.

Suggested Persian response for the professor (draft, not sent):

> منظورم رمزکردن راز مسیر توسط فرستنده برای اعضای دریافت‌کننده بود؛ فرستنده از کلید عمومی گره مناسب استفاده می‌کند و اعضایی که کلید خصوصی متناظر را دارند، راز مسیر را بازیابی می‌کنند. عبارت recipient encryption مبهم بود، بنابراین آن را حذف کردم و مراحل رمزگذاری و بازیابی راز را به‌صورت صریح توضیح دادم.


## November 5: commit the completed review round

The user approved the simpler Persian explanation and requested a commit with a proper message. The final suggested reply was:

> منظورم این بود که فرستنده راز مسیر را با کلید عمومی گره مربوطه رمز می‌کند و گیرنده‌ها با کلید خصوصی آن را به دست می‌آورند. این عبارت واضح نبود، برای همین حذفش کردم و به جایش همین مراحل را توضیح دادم.

Commit scope: current Word, clean PDF, synchronized Markdown, new highlighted Ver2 review PDF, and this onboarding log. The manuscript revisions address professor feedback on the abstract, reference-number-only citations, hybrid TreeKEM attribution, the summary of Chevalier et al., parallel communication-cost terminology, and explicit path-secret encryption/recovery. The preserved Ver1 baseline is excluded and unchanged. The earlier recorded document/text/layout checks remain applicable; a final Git whitespace check passed. No push was requested.

## November 9: green comments on Ver2

The professor's review copy is C:/Users/parsa/Downloads/2ParsaniaPaper-Ver2-commented.pdf. Its page text matches the committed Ver2 PDF. Fifteen green annotations on pages 2–4 are mapped below. The 37 yellow annotations in the input describe the earlier revision round.

Used the Kalaris Labs scientific-writing and rebuttal-and-response-to-reviewers skills to tie each comment to a concrete change. Grouped neighboring notes when they concern the same sentence or paragraph. The two annotations whose comment is a dash fall at the hyphens in “re-encryption” and “explicit-rejection.” Interpreted them as punctuation notes and revised both phrases into explicit actions.

Evidence checked locally or from primary sources:
- The retained-key example restates the manuscript's Section 5.3 scenario. The communication thresholds say nothing about whether the attacker still holds the matching private key.
- Reference [6], https://www.ietf.org/archive/id/draft-ietf-mls-pq-ciphersuites-06.html , describes hybrid cipher suites. Reference [7], https://datatracker.ietf.org/doc/html/draft-ietf-mls-combiner-02#section-4 , describes using a secret exported from the PQ session as a pre-shared key in the classical session. The cited draft versions remain in the bibliography.
- Reference [9], https://cic.iacr.org/p/1/1/21/pdf , Section 6 and Definition 7, supports the two sets of assumptions and the C2PRI terminology.
- Reference [11], https://csrc.nist.gov/pubs/fips/203/final , identifies the standardized ML-KEM. Reference [2], https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/how-multi-recipient-kems.pdf , gives the mKyber cost parameters and defines amKyber and adaptive corruption in Sections 2 and 3.2.
- Reference [12], https://cryptojedi.org/papers/mkem-20220812.pdf , Figure 6, Theorem 5 and Appendix B.3, supports the FO ciphertext rejection check and the conditional collision resistance argument. The explanation is about the construction proved in [12] and describes the ciphertext that a particular recipient processes.

### Revision 1

Original wording

> It shows why a cost threshold alone cannot establish recovery after compromise; a

Green comments

- Ver2 page 2, annotation 159. “قبل و بعد از آن هر کدام یک جمله کاملا مستقل است. پس این باید نقطه باشد.”
- Ver2 page 2, annotation 161. “خب الان خواننده منتظر است که به او دلیل این "چرا" را بگویید. اما نمیگویید.”

Revised wording

> If the committer uses a public key from the old tree to encrypt a fresh path secret, an attacker who copied the matching private key can recover that secret. The retirement thresholds measure communication savings, so meeting them gives no assurance that the attacker has lost access to fresh path secrets. A

Changed the semicolon to a sentence boundary and gave the concrete case of a copied old private key revealing a fresh path secret. The sentence beginning “A complete computational proof” still records the proof limitation.

### Revision 2

Original wording

> proposed design.

Green comments

- Ver2 page 3, annotation 168. “scheme”

Revised wording

> proposed scheme.

Used the professor’s preferred term “scheme” in the marked sentence.

### Revision 3

Original wording

> The IETF work on ML-KEM and hybrid MLS cipher suites provides a separate route to post-quantum deployment. Revision 06, dated 21 July 2026, specifies cipher-suite choices and remains an Internet-Draft [6]. The Amortized PQ MLS Combiner instead couples two MLS sessions and imports exported post-quantum material into the traditional session [7]. Revision 02 is an expired draft, dated 20 October 2025. Neither draft is an RFC. Our migration retains two structural versions temporarily, but does not run distinct classical and post-quantum MLS sessions.

Green comments

- Ver2 page 3, annotation 170. “يعنی کدام نشست؟ نشست کلاسیک؟ خب بگویید کلاسیک”
- Ver2 page 3, annotation 172. “چه گفتنی دارد؟! بخصوص که قبلتر در مورد نسخه 6 صحبت شده و الان به نسخه 2 برمیگردید!”
- Ver2 page 3, annotation 174. “دو نسخه ساختاری یعنی چه؟ يعنی نسخه 2 و نسخه 6؟ منطقی نیست. نامفهوم است.”

Revised wording

> One IETF draft proposes MLS cipher suites that combine classical and post-quantum key establishment within a single MLS session [6]. A separate draft, the Amortized PQ MLS Combiner, uses a secret exported from a post-quantum MLS session as a pre-shared key in a classical MLS session [7]. During an arity change, our scheme temporarily keeps the old and new ratchet trees in the same MLS session.

Identified the two documents as separate drafts, described the transfer to the classical MLS session, and specified that our migration temporarily keeps the old and new ratchet trees in a single session. Removed the draft revision dates and numbers from this paragraph.

### Revision 4

Original wording

> Different hybridization and update mechanisms

Green comments

- Ver2 page 3, annotation 176. “يعنی چه؟ خب معلومه مکانیزم بروزرسانی و مکنیزم ترکیب دو چیز متفاوت هستند!”

Revised wording

> Combine algorithms within a cipher suite [6] or link two MLS sessions [7]

Identified the mechanism of each draft in the marked Table 1 cell.

### Revision 5

Original wording

> The QSF framework underlying X-Wing gives complementary confidentiality reductions: one relies on KEM IND-CCA security; the other on KEM ciphertext second-preimage resistance (C2PRI) together with the stated Diffie–Hellman assumption [9]. It provides a framework for analyzing other KEM components when those hypotheses hold.

Green comments

- Ver2 page 3, annotation 178. “يعنی چه؟”

Revised wording

> Barbosa et al. analyze the combiner used by X-Wing under two sets of assumptions [9]. One analysis relies on the underlying KEM’s security against chosen-ciphertext attacks (IND-CCA) and assumes the hash function behaves as a pseudorandom function. The other relies on the strong Diffie–Hellman assumption, ciphertext second-preimage resistance (C2PRI) of the KEM, and a hash function modeled as a random oracle. These results guide the analysis of other KEMs that satisfy the same assumptions.

Replaced “complementary confidentiality reductions” with a description of the two security analyses and their assumptions.

### Revision 6

Original wording

> FIPS 203 specifies ML-KEM [11]; mKyber has its own construction and security analysis [2].

Green comments

- Ver2 page 4, annotation 183. “بازهم ارتباط منطقی بین جمله قبل از ; و بعد از آن را نمیفهمم.”

Revised wording

> FIPS 203 standardizes the single-recipient KEM ML-KEM [11]. The multi-recipient scheme used in our cost analysis is mKyber, which Alwen et al. specify and analyze separately [2].

Separated the clauses into two sentences that identify standardized ML-KEM and the distinct multi-recipient scheme used for the cost estimates.

### Revision 7

Original wording

> For ciphertext binding, Alwen et al. prove that their explicit-rejection Fujisaki–Okamoto (FO) mKEM is collision resistant whenever its output hash is collision resistant [12]. In the corresponding accepted-key profile, deterministic re-encryption fixes the recipient ciphertext for each recovered message. A different accepted ciphertext matching an honest target key must therefore yield a different message with the same output hash. This gives recipient-local C2PRI even with the recipient secret key exposed, under the corresponding classical or quantum hash assumption. The property concerns the complete canonical recipient ciphertext; it does not assert that a recipient detects changes to other recipients’ ciphertext components.

Green comments

- Ver2 page 4, annotation 185. “-”
- Ver2 page 4, annotation 187. “-”
- Ver2 page 4, annotation 189. “نامفهوم”
- Ver2 page 4, annotation 191. “ثقیل است. ساده تر بنویسید.”

Revised wording

> For ciphertext binding, Alwen et al. show that their Fujisaki–Okamoto (FO) construction is collision resistant if the hash function used to derive the shared key is collision resistant [12]. During decapsulation, the recipient decrypts the ciphertext and uses the recovered message and the recipient’s public key to recreate the expected ciphertext. If the two ciphertexts differ, the recipient rejects the received ciphertext. For a fixed recipient key, each recovered message yields one ciphertext that passes this check. Two different ciphertexts that pass the check and yield the same shared key must therefore come from two different messages with the same hash. This gives C2PRI for that recipient even if the attacker knows the recipient’s private key, under the corresponding classical or quantum hash assumption. The guarantee covers the shared ciphertext component and the component addressed to that recipient.

Explained the rejection check, the reason a matching shared key would imply a hash collision, and which ciphertext components the guarantee covers. The revised wording resolves the two dash notes.

### Revision 8

Original wording

> Adaptive-corruption confidentiality is a separate property. The distinction between mKyber and amKyber concerns that stronger multi-user model and the available reduction bounds [2]; it does not negate mKyber’s standard IND-CCA guarantee or the FO ciphertext-resistance result.

Green comments

- Ver2 page 4, annotation 193. “هنوز نگفته اید که چیست.”

Revised wording

> Alwen et al. also describe amKyber, a variant of mKyber with a stronger security guarantee. In its security model, an attacker can choose which recipients’ private keys to obtain as the attack proceeds. This is known as adaptive corruption [2].

Defined amKyber on first use and explained what an adaptive corruption allows the attacker to do.

### Revision 9

Original wording

> Primitive security results provide the basis for this protocol analysis; they do not alone establish group recovery with retained historical keys.

Green comments

- Ver2 page 4, annotation 195. “يعنی چه؟”

Revised wording

> These results describe the security of the cryptographic components. To establish recovery for the group, we also need to check whether later Commit messages still encrypt fresh path secrets using public keys whose matching private keys the attacker already holds.

Explained the additional protocol-level recovery check in terms of later Commits and private keys the attacker already holds.

Exported the revised DOCX via Microsoft Word and visually inspected the four affected pages. Ver3 has 12 pages, 36 new yellow annotations on pages 2–4, and 13 links. Reflow affects page 5. Extracted text matches the clean PDF and the planned changes. Equations, bibliography, and all other table cells were verified against Ver2. The downloaded PDF, frozen Ver1 and Ver2, and original annotated review matched their pre-edit hashes.

Files delivered and SHA-256 fingerprints

- paper/paper.docx  c12c689cab2deab1074fbeee54fdeb32a00aa9878c50ffd23d333d2179dc347b
- paper/publication_work/paper.md  f55a665e4491b3ed624f0cd6ba6d3d65c572817b8e0e10899c7d71abedd02eb5
- paper/paper.pdf  0e0da3203d0621e20de014be25d4692496e5965f39e81c2802cecec344062b6e
- paper/ParsaniaPaper-Ver3.pdf  64ae7c8f7a58dc85fdaef1e528ce85eaf673330f2d2810f4af22fd0da44ae0a4

Professor’s input SHA-256  6cd4e4a398677b188adbc4145ed42f2b18dd17bed94effef84ad61f5f4f101ad

## November 11: green comments on Ver3

The professor's input is C:/Users/parsa/Downloads/ParsaniaPaper-Ver3-commented.pdf. Its text matches the committed Ver3. There are 23 green marks on Ver3 pages 4–5. Used the installed Kalaris Labs scientific-writing and reviewer response skills. The green comments and corresponding old and new wording are recorded below.

The professor asked for the meaning of the claim and for the specific theorem. The substantive issue is that the explicit rejection construction in Theorem 5 of Alwen et al. [12] returns a hash of the recovered message for a valid ciphertext and signals rejection for an invalid one. The mKyber decapsulation in [2] includes the ciphertext in its output key derivation and returns a fallback key when its ciphertext check fails. Theorem 1 of the X-Wing paper [9] uses C2PRI in the proof under the strong Diffie–Hellman assumption and the random oracle model. To use that proof approach for Equation (3), the chosen mKyber decapsulation and the combiner assumptions need a separate justification. This is a proof obligation. The draft presents the explanation next to Equation (3), the amKyber paragraph ends after defining adaptive corruption, and the group recovery issue remains developed in Section 5.3.

Primary sources checked by the assistant:

- RFC 9420 Sections 4.1.2 and 4.2 describe the direct path and the public and private views of the ratchet tree. https://www.rfc-editor.org/rfc/rfc9420.html#section-4.1.2
- Alwen et al. [2], Figure 4, Algorithm 13 gives both output branches of mKyber decapsulation. https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/how-multi-recipient-kems.pdf
- Barbosa et al. [9], Definition 7 and Theorem 1, gives the C2PRI condition and the proof based on strong Diffie–Hellman. https://cic.iacr.org/p/1/1/21/pdf
- Alwen et al. [12], Theorem 5 and Appendix B.3, proves the collision resistance bound for their FO construction. https://cryptojedi.org/papers/mkem-20220812.pdf

### Theorem and paragraph logic

- Ver3 p. 4, annotation 245, “to match the selected rejection and output rules”. Professor’s comment “منظورتون چی بوده؟ لطفا جواب بدین نه اینکه ذوباره بدین هوش مصنوعی و ازش بخواین rephrase کنه.”
- Ver3 p. 4, annotation 247, “to the applicable theorem”. Professor’s comment “کدام قضیه؟”
- Ver3 p. 4, annotation 249, “These results”. Professor’s comment “از کدام نتایج حرف میزنید؟ در جملات قبلی نتیجه و دستاوردی ذکر نشده که الان بخواهید در مورد آن توضیح دهید. اصلا کل این جمله ربط منطقی با این پاراگراف ندارد.”

### Equation font

- Ver3 p. 4, annotation 251, “n”. Professor’s comment “$n$ متغیرهای داخل متن همه با فونت فرمول تایپ شوند.”
- Ver3 p. 4, annotation 253, “e”. Green mark with no accompanying text.
- Ver3 p. 4, annotation 255, “d”. Green mark with no accompanying text.
- Ver3 p. 4, annotation 273, “v”. Green mark with no accompanying text.
- Ver3 p. 4, annotation 275, “ps_v”. Green mark with no accompanying text.
- Ver3 p. 4, annotation 277, “ns_v”. Green mark with no accompanying text.
- Ver3 p. 4, annotation 279, “ctx_(v,e)”. Green mark with no accompanying text.
- Ver3 p. 4, annotation 281, “Equation (1)”. Professor’s comment “تمام فرمولها باید با فونت فرمول نوشته شوند.”

### Tree and keys

- Ver3 p. 4, annotation 257, “public node”. Professor’s comment “مگر گره های درخت هم عمومی و خصوصی هستند؟!”
- Ver3 p. 4, annotation 259, “location”. Professor’s comment “منظورتون آدرس در درخت d-ary است؟ یه حرفی از درخت بزنید.”
- Ver3 p. 4, annotation 261, “authorized path”. Professor’s comment “باید تعریف شود منظور از authorized path چیست؟”

### Epoch and tree roles

- Ver3 p. 4, annotation 263, “The new root is the unique authority for deriving the commit secret”. Professor’s comment “يعنی یک موجودیت از جنس مرجع در ریشه قرار میگیرد؟”
- Ver3 p. 4, annotation 265, “a delivery structure”. Professor’s comment “يعنی چه؟”
- Ver3 p. 4, annotation 267, “epoch state”. Professor’s comment “تعریف نشده! state کلی تعریف شد اما epoch state تعریف نشده.”
- Ver3 p. 4, annotation 269, “This logical separation”. Professor’s comment “از کدام جداسازی منطقی حرف میزنید؟”

### Private data

- Ver3 p. 4, annotation 271, “member state”. Professor’s comment “این هم یک state جدید! state epoch state member state ????????”

### Key generation

- Ver3 p. 5, annotation 284, “derivations”. Professor’s comment “چی کی کجا؟ تا الان در چند مقاله دیده اید که مثلا اینطوری بنویسند: classical key derivation”
- Ver3 p. 5, annotation 286, “hyphen in key-generation”. Professor’s comment “خط تیره نمیخواهد. فاصله میخواهد”
- Ver3 p. 5, annotation 288, “hyphen in classical-key”. Professor’s comment “فاصله”
- Ver3 p. 5, annotation 290, “pq-key”. Professor’s comment “اینطوری ننویسید”

### Exact text changes

Original

> For this article, the remaining task is to match the selected rejection and output rules and the hybrid derivation in Equation (3) to the applicable theorem, then analyze recipient eligibility and state evolution during migration. These results describe the security of the cryptographic components. To establish recovery for the group, we also need to check whether later Commit messages still encrypt fresh path secrets using public keys whose matching private keys the attacker already holds.

Deleted from the amKyber paragraph. See the explanation after Equation (3).

Original

> Let n be the number of active members, e the epoch, and d the current arity. The candidate arities are 2, 4, and 8. A public node has a location and, when valid, a classical public key and a post-quantum public key. A member retains the private keys needed along its authorized path.

Revised

> Let n be the number of active members, e the epoch number, and d the arity of the current ratchet tree. We consider arities 2, 4, and 8. A node is identified by its position in its ratchet tree. The public copy of the tree records the classical and post-quantum public keys of each nonblank node. A member’s direct path starts at the parent of its leaf and ends at the root. The member stores the private keys for its leaf and for the nodes on that path whose keys it has received or derived [1].

Original

> During migration the state comprises an old tree, a new tree, a fixed mapping between member identities and new leaves, a tree version, and authenticated transition metadata. The old tree is a delivery structure only. The new root is the unique authority for deriving the commit secret. At most one arity transition is active. This logical separation is needed to prevent receivers from treating a retained old root as an alternative source of epoch state.

Revised

> In this model, the epoch state includes the group context, the ratchet tree, and the secrets used to derive the keys for the current epoch. During migration, members also keep the old tree, a fixed mapping from member identities to leaves in the new tree, and authenticated information identifying the transition and tree version. The committer can use an eligible public key from the old tree to encrypt a path secret for the new tree. A recipient uses the matching private key to recover that secret and derives path secrets up to the root of the new tree. Members derive the commit secret from the path secret at the new root. At most one arity transition is active.

Original

> The adversary may observe, delay, reorder, replay, or modify delivery traffic and may obtain member state through compromise.

Revised

> The adversary may observe, delay, reorder, replay, or modify delivery traffic. Compromising a member may reveal the private data stored by that member, including its tree private keys and any secrets it holds for the current epoch.

Original

> Statements about recovery concern a former compromise after the adversary has ceased obtaining fresh state, with authentication credentials and recipient selection satisfying the stated assumptions.

Revised

> The recovery analysis assumes that the adversary has stopped obtaining new private data from the member and that the stated conditions on authentication and recipient selection hold.

Original

> The node secret feeds separately labeled classical-key and pq-key derivations. Their outputs seed the corresponding key-generation procedures. Domain separation is essential because the two key families and the upward path must not reuse a derivation purpose. Equations (1) and (2) express the proposed design interface; they do not supply the missing byte-level choice of every KDF and encoding.

Revised

> The committer derives two seeds from the node secret. It uses one label for the seed of the classical key pair and another label for the seed of the post-quantum key pair. It passes each seed to the corresponding key generation algorithm. These labels distinguish the two seed derivations from each other and from the derivation of the parent’s path secret. Equations (1) and (2) describe how to derive the node secret and the parent’s path secret. The choice of KDF and the byte encodings remain to be specified.

Original

> Recipient-local C2PRI is the relevant ciphertext-binding property when a hybrid derivation omits a separate copy of the post-quantum ciphertext [9, 12]. Applying that argument to (3) requires matching the selected FO rejection and output rules and the remaining combiner assumptions.

Revised

> Equation (3) omits the post-quantum ciphertext as a direct input to the combiner. Theorem 1 of the X-Wing paper uses C2PRI of the underlying KEM in its proof based on the strong Diffie–Hellman assumption [9]. Theorem 5 of Alwen et al. establishes ciphertext collision resistance for their FO construction, which rejects invalid ciphertexts and returns a hash of the recovered message for valid ones [12]. The mKyber decapsulation in [2] returns a fallback key for invalid ciphertexts and includes the ciphertext when deriving the output key. To use the X-Wing proof approach for Equation (3), we would need to establish C2PRI for the exact mKyber decapsulation used and justify the assumptions of the combiner theorem.

Original

> Continue deriving group state from the new root and reevaluate delivery costs after accepted changes.

Revised

> Continue deriving commit secrets from the new tree and reevaluate delivery costs after accepted changes.

Original

> Figure 1 illustrates the distinct functions of the two tree versions: an old subtree key can deliver a new root path secret without becoming a second root authority.

Revised

> Figure 1 shows how the committer can use an old tree key to encrypt a path secret for the new root. Members use that path secret to derive the commit secret.

Original

> The old root does not derive the new epoch state.

Revised

> Members derive the commit secret from the path secret at the new root.

Original

> Applying them to (3) requires a precise adversarial game and a correspondence between its KDF, encapsulation mechanisms, encodings, and validity checks and those of the selected theorem.

Revised

> As discussed after Equation (3), a proof following this approach must establish the required ciphertext property for the chosen mKyber decapsulation and check the combiner’s assumptions for the KDF, encapsulations, and encodings.

Original

> Members must agree on the active arity, root authority, tree version, frozen mapping, and applicable old keys.

Revised

> Members must agree on which tree supplies the commit secret, its arity and version, the fixed leaf mapping, and the old keys eligible for encryption.

Original

> Consider an attacker that copied a member's state, including a private key from the old tree and the relevant preceding epoch state.

Revised

> Consider an attacker who copied a private key from the old tree and the secrets needed from the preceding epoch.

Original

> the attacker can continue deriving group epoch state.

Revised

> the attacker can continue deriving the group’s secrets for subsequent epochs.

### Equation typography and PDF verification

Converted 80 variable or formula occurrences in the body and Table 3 headings to native Cambria Math objects. The 14 displayed equations already used native Word equations in Cambria Math. Their content and formatting were verified at the XML level. The Word text matches the planned edits. The Markdown source records the same prose and formula notation. Kept the Table 2 discussion together after Word reflow split a numerical expression across pages.

Ver4 has 12 pages and 168 yellow highlight rectangles on pages 4–11. Some rectangles cover different lines or subscript levels of the same edit. The deleted passage has no replacement highlight at the deletion site. The later highlights correspond to equation typography and the associated consistency edits. Reviewed the reflowed pages, verified the clean and annotated PDFs have identical text, and confirmed there are 13 links. Verified the prior review PDFs and the professor's input against their original hashes.

Files delivered and SHA-256 fingerprints

- paper/paper.docx  68932ea2285862e6eb71e6dd83d5bd7d95c9db29f78c7e03823951641df02462
- paper/publication_work/paper.md  05142278e20e1bcf14e06b3dd5241560f44406b570211cea8235611bde50c0fc
- paper/paper.pdf  f11fe30468de5c5873a05b88068384218b84b7c5e8b5ff0be875aa8e54861e16
- paper/ParsaniaPaper-Ver4.pdf  c9cae19b2bbb186cb688d3fbc04b23783dce0a7045a632ae7b269dbcf66035d5

## November 11: conditional C2PRI result in Ver4

At the user's request, replaced the C2PRI argument in Section 2.3 with the argument from both output branches of mKyber decapsulation. Algorithm 9 of Alwen et al. [2], lines 16 and 18, includes the recipient ciphertext in the KDF input for either outcome. The revised argument assumes unambiguous encoding and collision resistance of the final KDF. The separate description of Alwen et al.'s FO result [12] remains in Section 2.3. Checked the cited algorithm at https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/how-multi-recipient-kems.pdf .

Exact revised spans:

> For a fixed recipient, mKyber includes (u,v_i) in the final KDF input whether the re-encryption check passes or fails (Algorithm 9 in Alwen et al. [2]). With unambiguous encoding, two distinct recipient ciphertexts that yield the same shared key therefore give a KDF collision. Thus, per-recipient C2PRI follows under the assumption that the final KDF is collision resistant.

> Using the conditional C2PRI result from Section 2.3 in the X-Wing proof approach for Equation (3) still requires justifying the other assumptions of the combiner theorem.

The second span follows Equation (3). It references the conditional result and preserves the obligation to justify the other combiner assumptions. Verified exactly two manuscript text replacements. Both PDFs have 12 pages. The review copy keeps the Ver4 highlights with positions updated for reflow.

Current SHA-256 fingerprints

- paper/paper.docx  bfd7369f5878505de1af7b4163d95fe90f2fbf8c31b82174a2a0cf9a4ef58ec3
- paper/publication_work/paper.md  25b7fe80cc4bc7d85d284db6d25c7680ae34723b9b811edcdf935ae46c188cbf
- paper/paper.pdf  387e363391ffec0f6f1aee9e2014b1ffa755cde4229cc5902400a20016c6ca60
- paper/ParsaniaPaper-Ver4.pdf  8c96a7624a0191e91a388e091d12f3bc75e8ab36ef09d77d0437f3d3904d003a

## November 11: mathematical variable typography

The user noticed that symbols such as n and v still looked like ordinary letters. Inspection showed native Word equations in Cambria Math with upright math styling. Applied math italics to variables and variable indices in the inline notation and displayed equations. Operators, function names and descriptive labels retain their upright styling. The source notation and manuscript prose are unchanged. See the NIST typesetting convention at https://www.nist.gov/pml/special-publication-811/nist-guide-si-chapter-10-more-printing-and-using-symbols-and-numbers .

Checked all 95 Word math objects against the previous symbols and verified the rendered 12-page review PDF. The highlights include the revised variable styling.

Current SHA-256 fingerprints

- paper/paper.docx  70715fc7289271e715da3cf7ca1c3ef7babeb2b6fe4e5e44b8a11a0380c08778
- paper/paper.pdf  a809ff878157bacdb34a0490436fff9b20db4d5ee3a8012803ec5ef8075c7261
- paper/ParsaniaPaper-Ver4.pdf  cc65f715cf5fe08d1ebc9cc0dea953d09d4416714569c2ee91df0c7c9e629ea1
