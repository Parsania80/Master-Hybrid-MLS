from pathlib import Path
from shutil import copy2
from copy import deepcopy
import re
import json
import hashlib
import sys
from docx import Document
from docx.text.paragraph import Paragraph
import pypdfium2 as pdfium
from pypdf import PdfReader

work = Path(__file__).resolve().parent
root = work.parent
revision = work / 'security_revision_2026-10-16'
revision.mkdir(exist_ok=True)
for filename in ['paper.docx', 'research_audit.docx', 'formatting_report.txt']:
    target = revision / ('before_' + filename)
    assert not target.exists(), target
    copy2(root / filename, target)
for filename in ['paper.md', 'research_audit.md']:
    copy2(work / filename, revision / ('before_' + filename))

proof = Path(r'C:\Users\parsa\Downloads\mkyber_ciphertext_resistance_proof.pdf')
reader = PdfReader(proof)
(revision / 'supplied_proof_text.txt').write_text('\n\n'.join(f'PAGE {i+1}\n{p.extract_text()}' for i, p in enumerate(reader.pages)), encoding='utf-8')
pdf = pdfium.PdfDocument(str(proof))
for i, page in enumerate(pdf):
    page.render(scale=1.7).to_pil().save(revision / f'proof-page-{i+1}.png')

title_old = 'Security results that do not transfer automatically'
title_new = 'Established KEM security and protocol scope'
section_paragraphs = [
    'KEM combiners have established security guarantees under precise component assumptions [8]. The QSF framework underlying X-Wing proves hybrid confidentiality using ciphertext second-preimage resistance (C2PRI) of the KEM and the stated Diffie–Hellman assumption [9, Section 6]. It provides a framework for analyzing other KEM components when those hypotheses hold. Similarly, the symbolic TreeKEM proof establishes guarantees for its specified MLS protocol [10]. FIPS 203 specifies ML-KEM [11]; mKyber has its own construction and security analysis [2].',
    'mKyber enjoys standard non-adaptive multi-user IND-CCA security [2, Sections 2.3 and 3.1]. For ciphertext binding, Alwen et al. prove that their explicit-rejection Fujisaki–Okamoto (FO) mKEM is collision resistant whenever its output hash is collision resistant [12, Theorem 5]. In the corresponding accepted-key profile, deterministic re-encryption fixes the recipient ciphertext for each recovered message. A different accepted ciphertext matching an honest target key must therefore yield a different message with the same output hash. This gives recipient-local C2PRI even with the recipient secret key exposed, under the corresponding classical or quantum hash assumption. The property concerns the complete canonical recipient ciphertext; it does not assert that a recipient detects changes to other recipients’ ciphertext components.',
    'Adaptive-corruption confidentiality is a separate property. The distinction between mKyber and amKyber concerns that stronger multi-user model and the available reduction bounds [2]; it does not negate mKyber’s standard IND-CCA guarantee or the FO ciphertext-resistance result. For this article, the remaining task is to match the selected rejection and output rules and the hybrid derivation in Equation (3) to the applicable theorem, then analyze recipient eligibility and state evolution during migration. Primitive security results provide the basis for this protocol analysis; they do not alone establish group recovery with retained historical keys.'
]
ref12_text = 'Joël Alwen, Dominik Hartmann, Eike Kiltz, Marta Mularczyk, and Peter Schwabe. Post-Quantum Multi-Recipient Public Key Encryption. In Proceedings of the 2023 ACM SIGSAC Conference on Computer and Communications Security, pp. 1108–1122. ACM, 2023.'
ref12_url = 'https://doi.org/10.1145/3576915.3623185'

path = work / 'paper.md'
paper = path.read_text(encoding='utf-8')
start = paper.index('## ' + title_old)
end = paper.index('\n# Model and cryptographic specification', start)
paper = paper[:start] + '## ' + title_new + '\n\n' + '\n\n'.join(section_paragraphs) + '\n' + paper[end:]
paper = paper.replace('@authors Mohammadreza Parsania and Hamid Mala', '@authors Mohammadreza Parsania and Dr Hamid Mala')
old_binding = 'The omission of raw post-quantum ciphertext from (3) is part of the thesis design, not a security result. The ciphertext still has to be transmitted, associated with the intended recipient, and authenticated as protocol data.'
new_binding = 'Recipient-local C2PRI is the relevant ciphertext-binding property when a hybrid derivation omits a separate copy of the post-quantum ciphertext [9, 12]. Applying that argument to (3) requires matching the selected FO rejection and output rules and the remaining combiner assumptions. The delivery context must still bind the intended recipient and be authenticated as protocol data.'
assert old_binding in paper
paper = paper.replace(old_binding, new_binding)
old_security = 'The intended hybrid property is that path-secret confidentiality survives failure of one key-establishment component. Establishing that property for (3) requires a precise adversarial game and a reduction for the actual KDF, encapsulation mechanisms, encodings, and validity checks. A suitable robust combiner, correct authenticated encryption, authenticated public keys, and independent component randomness are assumptions for the argument here. They are not consequences of concatenation alone [8, 9]. The thesis provides no construction-specific computational proof.'
new_security = 'The intended hybrid property is that path-secret confidentiality survives failure of one key-establishment component. Published KEM and combiner theorems provide the relevant primitive guarantees, including the FO ciphertext-resistance result discussed in Section 2.3 [8, 9, 12]. Applying them to (3) requires a precise adversarial game and a correspondence between its KDF, encapsulation mechanisms, encodings, and validity checks and those of the selected theorem. Correct authenticated encryption, authenticated public keys, and independent component randomness are additional obligations. A complete computational proof for the composed migration protocol remains to be supplied.'
assert old_security in paper
paper = paper.replace(old_security, new_security)
paper += '\n@ref 12|' + ref12_text + '|' + ref12_url + '\n'
path.write_text(paper, encoding='utf-8')

# Make local OOXML paragraph edits to preserve the user's current document,
# including their addition of the honorific Dr in the author line.
doc = Document(root / 'paper.docx')
baseline_untouched = [p.text for p in doc.paragraphs]
head = next(p for p in doc.paragraphs if p.text == title_old)
head.text = title_new
p1 = head._p.getnext()
p2 = p1.getnext()
assert Paragraph(p1, head._parent).text.startswith('KEM combiners require')
assert Paragraph(p2, head._parent).text.startswith('The distinction between mKyber')
Paragraph(p1, head._parent).text = section_paragraphs[0]
Paragraph(p2, head._parent).text = section_paragraphs[1]
new_p = deepcopy(p2)
p2.addnext(new_p)
Paragraph(new_p, head._parent).text = section_paragraphs[2]
for p in doc.paragraphs:
    if old_binding in p.text:
        original = p.text
        p.clear()
        sys.path.insert(0, str(work))
        from build_documents import prose
        prose(p, original.replace(old_binding, new_binding))
    elif p.text == old_security:
        p.text = new_security
from build_documents import hyperlink
p = doc.add_paragraph(style='Reference')
p.add_run('[12] ' + ref12_text + ' ')
hyperlink(p, ref12_url)
assert 'Mohammadreza Parsania and Dr Hamid Mala' in [p.text for p in doc.paragraphs]
assert not any(title_old == p.text or old_security == p.text for p in doc.paragraphs)
assert len(doc.tables) == 3
doc.save(root / 'paper.docx')

path = work / 'research_audit.md'
audit = path.read_text(encoding='utf-8').replace('@date Prepared 14 October 2026', '@date Prepared 14 October 2026; security revision 16 October 2026')
audit = audit.replace('The manuscript lists Mohammadreza Parsania and Hamid Mala in that order, without an academic honorific, as requested.', "The current manuscript lists Mohammadreza Parsania and Dr Hamid Mala in that order. The professor's honorific was added in the user's Word file and preserved during this revision.")
audit = audit.replace('4 | Post-Quantum Multi-Recipient Public Key Encryption | Omitted from final paper; thesis author list truncated', '4 | Post-Quantum Multi-Recipient Public Key Encryption | Retained as paper reference 12; five authors, CCS metadata, and FO collision-resistance theorem verified')
audit = audit.replace('11 | NIST corporate author, title, FIPS 203, 13 August 2024, DOI | csrc.nist.gov/pubs/fips/203/final', '11 | NIST corporate author, title, FIPS 203, 13 August 2024, DOI | csrc.nist.gov/pubs/fips/203/final\n12 | Five authors; CCS 2023, pp. 1108–1122; FO collision resistance and mKEM combiner theorem | ACM DOI 10.1145/3576915.3623185; author PDF cryptojedi.org/papers/mkem-20220812.pdf, Definition 8, Theorems 4–5, Appendix B.3')
old = "The mKyber source distinguishes its non-adaptive multi-user treatment from amKyber's adaptive-corruption setting. This is a limitation of known proof techniques, not a demonstrated break. The thesis-specific combiner requires its own argument. Classical authentication remains conceptually distinct from post-quantum confidentiality; replacing a KEM does not make classical signatures quantum resistant."
new = "The supplied six-page proof note, mkyber_ciphertext_resistance_proof.pdf, dated 15 October 2026, was read in full. It correctly directs attention to the established FO collision-resistance theorem. The author PDF of Alwen et al., Post-Quantum Multi-Recipient Public Key Encryption, was checked at Definition 8, Theorems 4–5, and Appendix B.3. The manuscript now explicitly recognizes standard mKyber IND-CCA security and the FO recipient-local ciphertext-resistance result. X-Wing's general QSF framework is described as applicable when its C2PRI and Diffie–Hellman hypotheses hold. Adaptive-corruption confidentiality is identified as a separate security question."
assert old in audit
audit = audit.replace(old, new + '\n\nThe supplied note is supplementary AI-assisted technical analysis, not a peer-reviewed publication; the paper cites the verified primary research instead. Its explicit-rejection argument uses deterministic reconstruction, full canonical recipient-ciphertext comparison, and an accepted output derived through a collision-resistant hash. Its implicit-rejection extensions have additional stated hash or oracle assumptions. No theorem for every algorithm bearing the mKyber name is inferred. The same-recipient property does not authenticate unused components of a full multi-recipient vector. These distinctions concern mathematical algorithms and do not add implementation material to the paper.')
audit = audit.replace('Verification date is 14 October 2026.', 'The initial bibliography verification date is 14 October 2026; reference 12 and the ciphertext-resistance claims were verified on 16 October 2026.')
path.write_text(audit, encoding='utf-8')

from build_documents import build
build('research_audit')

path = work / 'validate_documents.py'
validator = path.read_text(encoding='utf-8').replace('set(range(1,12))', 'set(range(1,13))').replace("'citation_ids':list(range(1,12))", "'citation_ids':list(range(1,13))")
validator = validator.replace("assert 'Hamid Mala' in text", "assert 'Hamid Mala' in text\n            assert 'Established KEM security and protocol scope' in text\n            assert 'Theorem 5' in text and 'recipient-local C2PRI' in text\n            assert 'mKyber enjoys standard non-adaptive multi-user IND-CCA security' in text")
path.write_text(validator, encoding='utf-8')
(revision / 'revision_record.json').write_text(json.dumps({
    'date': '2026-10-16', 'supplied_proof_pages': len(reader.pages),
    'proof_sha256': hashlib.sha256(proof.read_bytes()).hexdigest(),
    'primary_source': 'https://cryptojedi.org/papers/mkem-20220812.pdf',
    'checked': ['Definition 8', 'Theorem 4', 'Theorem 5', 'Appendix B.3', 'X-Wing Definition 7 and Section 6', 'NIST overview Sections 2.3 and 3.1'],
    'user_honorific_preserved': True, 'implementation_content_added_to_paper': False
}, indent=2), encoding='utf-8')
print('Security section and two directly related paragraphs revised; user author-line edit preserved.')
print('Added verified primary reference 12; audit and citation checks updated.')
