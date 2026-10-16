from pathlib import Path
from zipfile import ZipFile
from lxml import etree as E
from docx import Document
import pypdfium2 as pdfium
import pdfplumber
import json,re,hashlib,math
O=Path(__file__).resolve().parent;B=O.parent
N={'w':'http://schemas.openxmlformats.org/wordprocessingml/2006/main','m':'http://schemas.openxmlformats.org/officeDocument/2006/math','a':'http://schemas.openxmlformats.org/drawingml/2006/main'}
meta=[]
for stem in ['paper','research_audit']:
    p=B/(stem+'.docx');doc=Document(p)
    with ZipFile(p) as z:
        assert z.testzip() is None
        for name in z.namelist():
            if name.endswith('.xml') or name.endswith('.rels'):E.fromstring(z.read(name))
        root=E.fromstring(z.read('word/document.xml'))
        text=' '.join(root.xpath('//w:t/text() | //m:t/text()',namespaces=N))
        assert not re.search('[\u0600-\u06ff]',text)
        assert not root.xpath('//w:bidi[not(@w:val="0") and not(@w:val="false")]',namespaces=N)
        eq=len(root.xpath('//m:oMath',namespaces=N));imgs=len(root.xpath('//w:drawing',namespaces=N))
        if stem=='paper':
            assert eq==14 and len(doc.tables)==3 and imgs==1
            assert not re.search(r'\b(?:implementation|implemented|prototype|Rust|OpenMLS|MinGW|benchmark\w*|CSV|JSON|trace|observations?|experiment\w*|runtime|hardware)\b|5[–-]7|C_real|40/57|77/114|0\.701754',text,re.I)
            assert 'Hamid Mala' in text
            assert 'Established KEM security and protocol scope' in text
            assert 'Theorem 5' in text and 'recipient-local C2PRI' in text
            assert 'mKyber enjoys standard non-adaptive multi-user IND-CCA security' in text
            before=text.split('References')[0].replace('[0,1]','')
            cited=set()
            for x in re.findall(r'\[([0-9, ]+)\]',before):cited.update(int(y.strip()) for y in x.split(','))
            assert cited==set(range(1,13)),cited
        sec=doc.sections[0]
        data={'file':stem,'valid_xml':True,'size_bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'paragraphs':len(doc.paragraphs),'tables':len(doc.tables),'omml_equations':eq,'drawings':imgs,'words_xml_regex':len(re.findall(r'\b\S+\b',text)), 'a4_mm':[round(sec.page_width.mm,1),round(sec.page_height.mm,1)],'margins_mm':[sec.top_margin.mm,sec.bottom_margin.mm,sec.left_margin.mm,sec.right_margin.mm]}
    pdf=O/'qa'/(stem+'.pdf');d=pdfium.PdfDocument(str(pdf));out=O/'qa'/stem;out.mkdir(exist_ok=True)
    for i,page in enumerate(d):page.render(scale=1.6).to_pil().save(out/f'page-{i+1}.png')
    with pdfplumber.open(pdf) as pp:
        texts=[pg.extract_text() or '' for pg in pp.pages]
        (out/'rendered_text.txt').write_text('\n\n'.join(f'PAGE {i+1}\n'+t for i,t in enumerate(texts)),encoding='utf8')
        data['pdf_pages']=len(pp.pages)
        data['page_words']=[len(t.split()) for t in texts]
        data['blank_pages']=[i+1 for i,t in enumerate(texts) if len(t.split())<5]
        # All body text must lie inside page boundaries; footer intentionally below body margin.
        bad=[]
        for i,pg in enumerate(pp.pages):
            for ch in pg.chars:
                if ch['x0']<0 or ch['x1']>pg.width+1 or ch['top']<0 or ch['bottom']>pg.height+1:bad.append(i+1)
        data['out_of_page_text']=sorted(set(bad))
    meta.append(data)
sourcehash=hashlib.sha256((B/'Thesis.docx').read_bytes()).hexdigest()
assert sourcehash=='f916f0572b73a7275db1b4441d897bcf5ddf917673b041d08baecf344f4f1146'
# Exact integer heights avoid floating-point boundary mistakes.
def h(d,n):
    x=1;k=0
    while x<n:x*=d;k+=1
    return k
def healthy(d,n):return (1504+80*(d-1))*h(d,n)
analytical=[[n,*[healthy(d,n) for d in (2,4,8)]] for n in [128,129,512,1024,1025,2048,4096]]
assert analytical==[[128,11088,6976,6192],[129,12672,6976,6192],[512,14256,8720,6192],[1024,15840,8720,8256],[1025,17424,10464,8256],[2048,17424,10464,8256],[4096,19008,10464,8256]]
q=[]
for a,b,n in [(2,4,129),(2,4,1024),(4,8,1025),(4,8,2048),(4,8,4096)]:
    first=1504*h(b,n)+80*(n-1);old=healthy(a,n);new=healthy(b,n);q.append(math.ceil(max(0,(first-old)/(old-new))))
assert q==[1,11,36,73,147]
abstract=(O/'paper.md').read_text(encoding='utf8').split('@abstract\n')[1].split('@keywords')[0].strip()
assert 180<=len(abstract.split())<=250
result={'documents':meta,'source_unchanged':True,'abstract_words':len(abstract.split()),'analytical_rows':analytical,'break_even':q,'citation_ids':list(range(1,13))}
(O/'qa'/'validation.json').write_text(json.dumps(result,indent=2),encoding='utf8')
print(json.dumps(result,indent=2))
