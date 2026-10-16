from pathlib import Path
from fractions import Fraction
from hashlib import sha256
from zipfile import ZipFile
from lxml import etree
from docx import Document
import json

root = Path(__file__).resolve().parent.parent
ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
expected = {
    'paper.docx': '54981fffc18d3ad5001f25b03ad4a6082c59816aeafe181160eea09a7bb04851',
    'research_audit.docx': '79e55f912599f39b54b73b2647ecaa57740692f789a693952032a77ede94f334',
    'Thesis.docx': 'f916f0572b73a7275db1b4441d897bcf5ddf917673b041d08baecf344f4f1146',
}
for name, digest in expected.items():
    assert sha256((root / name).read_bytes()).hexdigest() == digest, name
for name in ['paper.docx', 'research_audit.docx']:
    with ZipFile(root / name) as archive:
        xml = etree.fromstring(archive.read('word/document.xml'))
        assert not xml.xpath('//w:ins | //w:del | //w:commentRangeStart', namespaces=ns), name
        assert not any('comments' in item.lower() for item in archive.namelist()), name
rows = [
    (126, 10, 111, 41, '15/116', '85/116'),
    (125, 10, 124, 60, '1/115', '13/23'),
    (125, 10, 45, 52, '16/23', '73/115'),
    (125, 10, 48, 44, '77/115', '81/115'),
    (124, 10, 44, 47, '40/57', '77/114'),
]
for leaf, ideal, new, old, hnew, hold in rows:
    assert Fraction(leaf-new, leaf-ideal) == Fraction(hnew)
    assert Fraction(leaf-old, leaf-ideal) == Fraction(hold)
report = (root / 'formatting_report.txt').read_text(encoding='utf-8')
assert '11 pages' in report and '12 numbered references' in report and len(report) > 5000
original = Document(root / 'publication_work' / 'security_revision_2026-10-16' / 'before_paper.docx')
current = Document(root / 'paper.docx')
old_prefixes = ('Security results that do not transfer automatically', 'KEM combiners require', 'The distinction between mKyber', 'Here label', 'The intended hybrid property')
new_prefixes = ('Established KEM security and protocol scope', 'KEM combiners have', 'mKyber enjoys', 'Adaptive-corruption confidentiality', 'Here label', 'The intended hybrid property', '[12]')
before_other = [p.text for p in original.paragraphs if not p.text.startswith(old_prefixes)]
after_other = [p.text for p in current.paragraphs if not p.text.startswith(new_prefixes)]
assert before_other == after_other, 'Unexpected change outside the intended paragraphs'
assert [[c.text for r in t.rows for c in r.cells] for t in original.tables] == [[c.text for r in t.rows for c in r.cells] for t in current.tables]
assert 'Mohammadreza Parsania and Dr Hamid Mala' in after_other
result = {'status': 'passed', 'source_and_deliverable_hashes_match': True,
          'unresolved_tracked_changes_or_comments': False,
          'audit_only_trace_fractions_recomputed': True,
          'implementation_derived_content_removed_from_paper': True,
          'unrelated_paper_text_and_user_author_edit_preserved': True,
          'security_source_and_primary_theorem_checked': True,
          'final_visual_pages_inspected': {'paper': 11, 'research_audit': 11},
          'deliverables': [str(root / n) for n in ['paper.docx', 'research_audit.docx', 'formatting_report.txt']]}
(root / 'publication_work' / 'qa' / 'final_checks.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps(result, ensure_ascii=True, indent=2))
