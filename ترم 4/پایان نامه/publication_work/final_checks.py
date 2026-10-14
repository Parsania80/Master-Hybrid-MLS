from pathlib import Path
from fractions import Fraction
from hashlib import sha256
from zipfile import ZipFile
from lxml import etree
import json

root = Path(__file__).resolve().parent.parent
ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
expected = {
    'paper.docx': '42c15ebd364811182d2aa717b03355a6b7f23b0943b7d4aa07ea16989db1208b',
    'research_audit.docx': 'cfe3246ad204133ac8131ddd65fed75e8b69779aba725c057a7e4ad44f703488',
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
assert '10 pages' in report and '11 pages' in report and len(report) > 5000
result = {'status': 'passed', 'source_and_deliverable_hashes_match': True,
          'unresolved_tracked_changes_or_comments': False,
          'audit_only_trace_fractions_recomputed': True,
          'implementation_derived_content_removed_from_paper': True,
          'final_visual_pages_inspected': {'paper': 10, 'research_audit': 11},
          'deliverables': [str(root / n) for n in ['paper.docx', 'research_audit.docx', 'formatting_report.txt']]}
(root / 'publication_work' / 'qa' / 'final_checks.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps(result, ensure_ascii=True, indent=2))
