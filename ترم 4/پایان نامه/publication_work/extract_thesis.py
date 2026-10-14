from pathlib import Path
from zipfile import ZipFile
from lxml import etree as E
import json, hashlib

BASE=Path(__file__).resolve().parent.parent
OUT=BASE/'publication_work'
OUT.mkdir(exist_ok=True)
NS={'w':'http://schemas.openxmlformats.org/wordprocessingml/2006/main','m':'http://schemas.openxmlformats.org/officeDocument/2006/math','a':'http://schemas.openxmlformats.org/drawingml/2006/main','r':'http://schemas.openxmlformats.org/officeDocument/2006/relationships'}
def tag(e): return E.QName(e).localname
def txt(e):
    n=tag(e)
    if n in ('t','delText'): return e.text or ''
    if n=='tab': return ' | '
    if n=='br': return '\n'
    if n=='instrText': return ''
    if n in ('sSub','sSup','sSubSup'):
        parts={tag(c):txt(c) for c in e if tag(c)!='sSubPr'}
        return parts.get('e','')+('_{'+parts['sub']+'}' if 'sub' in parts else '')+('^{'+parts['sup']+'}' if 'sup' in parts else '')
    if n=='f':
        return '('+txt(e.find('m:num',NS))+')/('+txt(e.find('m:den',NS))+')'
    if n=='rad': return 'sqrt('+txt(e.find('m:e',NS))+')'
    if n=='footnoteReference': return '[fn:'+e.get('{'+NS['w']+'}id','')+']'
    if n=='drawing': return '[IMAGE:'+','.join(e.xpath('.//a:blip/@r:embed',namespaces=NS))+']'
    return ''.join(txt(c) for c in e)
with ZipFile(BASE/'Thesis.docx') as z:
    root=E.fromstring(z.read('word/document.xml'))
    rels=E.fromstring(z.read('word/_rels/document.xml.rels'))
    images={r.get('Id'):r.get('Target') for r in rels if 'image' in r.get('Type','')}
    blocks=[]
    for i,e in enumerate(root.find('w:body',NS)):
        text=txt(e)
        if not text.strip(): continue
        st=e.find('w:pPr/w:pStyle',NS)
        style=st.get('{'+NS['w']+'}val') if st is not None else ''
        if tag(e)=='tbl':
            text='\n'.join(' || '.join(txt(c) for c in r.findall('w:tc',NS)) for r in e.findall('w:tr',NS))
        blocks.append({'id':i,'type':tag(e),'style':style,'text':text})
    (OUT/'thesis_blocks.json').write_text(json.dumps(blocks,ensure_ascii=False,indent=2),encoding='utf-8')
    (OUT/'thesis_full.txt').write_text('\n\n'.join(f"[{b['id']:04d} {b['type']} {b['style']}] {b['text']}" for b in blocks),encoding='utf-8')
    headings=[b for b in blocks if any(x in b['style'].lower() for x in ('heading','title'))]
    (OUT/'thesis_headings.json').write_text(json.dumps(headings,ensure_ascii=False,indent=2),encoding='utf-8')
    for n in ['word/footnotes.xml','word/endnotes.xml','word/comments.xml']:
        if n in z.namelist():
            rr=E.fromstring(z.read(n))
            (OUT/(Path(n).stem+'.txt')).write_text('\n\n'.join(txt(e) for e in rr),encoding='utf-8')
    (OUT/'source_images').mkdir(exist_ok=True)
    for rid,target in images.items():
        p='word/'+target
        if p in z.namelist(): (OUT/'source_images'/Path(target).name).write_bytes(z.read(p))
    meta={'sha256':hashlib.sha256((BASE/'Thesis.docx').read_bytes()).hexdigest(),'blocks':len(blocks),'paragraphs':len(root.xpath('.//w:p',namespaces=NS)),'tables':len(root.xpath('.//w:tbl',namespaces=NS)),'equations':len(root.xpath('.//m:oMath',namespaces=NS)),'images':images,'headings':headings}
    (OUT/'source_manifest.json').write_text(json.dumps(meta,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in meta.items() if k not in ('images','headings')},ensure_ascii=False))
    for b in headings: print(f"{b['id']}: {b['style']}: {b['text']}")
