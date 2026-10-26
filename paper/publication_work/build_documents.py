from pathlib import Path
from docx import Document
from docx.shared import Inches, Pt, Mm, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK, WD_TAB_ALIGNMENT
from docx.enum.style import WD_STYLE_TYPE
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from lxml import etree
from reportlab.pdfgen import canvas
import pypdfium2 as pdfium
import re,json,math,hashlib

O=Path(__file__).resolve().parent
B=O.parent
def el(tag,**attrs):
    e=OxmlElement(tag)
    for k,v in attrs.items():e.set(qn(k),str(v))
    return e

def diagram():
    p=O/'migration_figure.pdf'
    c=canvas.Canvas(str(p),pagesize=(660,250))
    c.setTitle('Gradual tree migration schematic')
    def text(x,y,t,size=10):
        c.setFillColorRGB(0,0,0);c.setFont('Helvetica',size);c.drawCentredString(x,y,t)
    def edge(a,b,dashed=False):
        c.setStrokeColorRGB(.25,.25,.25);c.setLineWidth(.8)
        c.setDash(3,2) if dashed else c.setDash()
        c.line(*a,*b);c.setDash()
    def node(x,y,t,blank=False):
        c.setFillColorRGB(1,1,1) if blank else c.setFillColorRGB(.88,.91,.93)
        c.setStrokeColorRGB(.12,.12,.12);c.circle(x,y,12,stroke=1,fill=1)
        text(x,y-3,t,9)
    text(150,231,'Retained binary tree',12)
    text(510,231,'New four-ary tree',12)
    # Old tree has four levels; explicit leaf sets.
    root=(150,202);parents=[(80,163),(220,163)]
    bottoms=[(45,122),(115,122),(185,122),(255,122)]
    for pnt in parents:edge(root,pnt)
    for i,pnt in enumerate(bottoms):edge(parents[i//2],pnt)
    for i in range(8):
        x=26+i*35;edge(bottoms[i//2],(x,77));node(x,77,str(i+1))
    node(*root,'old');node(*parents[0],'L');node(*parents[1],'R')
    for i,pnt in enumerate(bottoms):node(*pnt,str(2*i+1)+'-'+str(2*i+2))
    nr=(510,202);np=[(440,140),(580,140)]
    for pnt in np:edge(nr,pnt)
    for i in range(8):
        x=390+i*35;edge(np[i//4],(x,77));node(x,77,str(i+1))
    node(*nr,'new');node(*np[0],'A');node(*np[1],'',True)
    c.setStrokeColorRGB(.15,.15,.15);c.setDash(4,3)
    c.line(232,170,470,190);c.setDash()
    c.line(470,190,463,184);c.line(470,190,462,194)
    text(353,207,'R delivers the new root path secret',9)
    text(150,40,'R covers members 5-8',10)
    text(510,40,'Blank node: use a suitable old node',10)
    text(510,20,'Only the new root drives group state',10)
    c.save()
    d=pdfium.PdfDocument(str(p));im=d[0].render(scale=3.2).to_pil();im.save(O/'migration.png')

def mathrun(t,normal=False):
    r=el('m:r');rp=el('m:rPr');rp.append(el('m:sty',**{'m:val':'p'}))
    if normal:rp.append(el('m:nor'))
    r.append(rp)
    wr=el('w:rPr');wr.append(el('w:rFonts',**{'w:ascii':'Cambria Math','w:hAnsi':'Cambria Math'}));r.append(wr)
    tx=el('m:t');tx.set(qn('xml:space'),'preserve');tx.text=t;r.append(tx);return r

def mathparse(s):
    s=s.replace('dprime','d′').replace('Delta','Δ').replace('theta','θ')
    def group(i):
        if i<len(s) and s[i]=='{':
            start=i+1;depth=1;i+=1
            while i<len(s) and depth:
                if s[i]=='{':depth+=1
                elif s[i]=='}':depth-=1
                i+=1
            return s[start:i-1],i
        return s[i:i+1],i+1
    out=[];i=0
    while i<len(s):
        if s[i]=='"':
            end=s.find('"',i+1)
            if end!=-1:out.append(mathrun(s[i:end+1],True));i=end+1;continue
        if s.startswith('\\frac',i):
            n,i=group(i+5);d,i=group(i)
            f=el('m:f');num=el('m:num');den=el('m:den');num.extend(mathparse(n));den.extend(mathparse(d));f.extend([num,den]);out.append(f);continue
        if s[i] in '_^' and out:
            typ=s[i];g,i=group(i+1);base=out.pop()
            # Preserve a shared base for consecutive subscript and superscript.
            if typ=='^' and base.tag==qn('m:sSub'):
                e=base.find(qn('m:e'));sub=base.find(qn('m:sub'))
                obj=el('m:sSubSup');obj.append(e);obj.append(sub);sup=el('m:sup');sup.extend(mathparse(g));obj.append(sup)
            else:
                obj=el('m:sSub' if typ=='_' else 'm:sSup');e=el('m:e');e.append(base);obj.append(e)
                ex=el('m:sub' if typ=='_' else 'm:sup');ex.extend(mathparse(g));obj.append(ex)
            out.append(obj);continue
        # Keep words together but individual operators independent for scripts.
        m=re.match(r'[A-Za-zθΔ]+|[0-9]+',s[i:])
        t=m.group() if m else s[i];out.append(mathrun(t));i+=len(t)
    return out

def field(p,instr,cache):
    r=p.add_run();r._r.append(el('w:fldChar',**{'w:fldCharType':'begin'}))
    r=p.add_run();t=el('w:instrText');t.set(qn('xml:space'),'preserve');t.text=' '+instr+' ';r._r.append(t)
    p.add_run()._r.append(el('w:fldChar',**{'w:fldCharType':'separate'}));p.add_run(str(cache))
    p.add_run()._r.append(el('w:fldChar',**{'w:fldCharType':'end'}))

def hyperlink(p,url,label=None):
    h=el('w:hyperlink',**{'r:id':p.part.relate_to(url,RT.HYPERLINK,is_external=True)})
    r=el('w:r');pr=el('w:rPr');pr.append(el('w:color',**{'w:val':'000000'}));r.append(pr)
    t=el('w:t');t.text=label or url;r.append(t);h.append(r);p._p.append(h)

inline=re.compile(r'\b(?:ps|ns|ss|hs|pk|ct|ctx|label|nonce|aad|theta|B|C|H|q|w|u|v|h)_(?:\([^\)]+\)|[A-Za-z0-9]+)(?:\^[A-Za-z]+)?')
def prose(p,t):
    last=0
    for m in inline.finditer(t):
        p.add_run(t[last:m.start()]);x=m.group();base,sub=x.split('_',1);sup=None
        if '^' in sub:sub,sup=sub.split('^')
        p.add_run('θ' if base=='theta' else base)
        r=p.add_run(sub.replace('dprime','d′').strip('()'));r.font.subscript=True
        if sup:r=p.add_run(sup);r.font.superscript=True
        last=m.end()
    p.add_run(t[last:])

def setup(doc,is_audit):
    sec=doc.sections[0];sec.page_width=Mm(210);sec.page_height=Mm(297)
    sec.top_margin=Mm(21);sec.bottom_margin=Mm(21);sec.left_margin=Mm(22);sec.right_margin=Mm(22)
    sec.header_distance=Mm(10);sec.footer_distance=Mm(10)
    styles=doc.styles
    for st in styles:
        for border in st.element.xpath('.//w:pBdr'):border.getparent().remove(border)
    for name in ['Normal','Title','Subtitle','Heading 1','Heading 2','Heading 3','Caption']:
        st=styles[name];st.font.name='Times New Roman';st.font.color.rgb=RGBColor(0,0,0)
        st.element.get_or_add_rPr().append(el('w:lang',**{'w:val':'en-US'}))
        st.element.get_or_add_rPr().append(el('w:rFonts',**{'w:ascii':'Times New Roman','w:hAnsi':'Times New Roman','w:cs':'Times New Roman'}))
    normal=styles['Normal'];normal.font.size=Pt(11);normal.paragraph_format.line_spacing=1.12;normal.paragraph_format.space_after=Pt(6)
    normal.paragraph_format.widow_control=True
    for name,size,bef,aft in [('Title',19,0,12),('Heading 1',13,13,6),('Heading 2',11.5,10,4),('Heading 3',11,8,4)]:
        st=styles[name];st.font.size=Pt(size);st.font.bold=name!='Title';st.paragraph_format.space_before=Pt(bef);st.paragraph_format.space_after=Pt(aft);st.paragraph_format.keep_with_next=True
    styles['Subtitle'].font.size=Pt(12);styles['Subtitle'].font.italic=False
    for name,size in [('Abstract Text',10.5),('Table Text',9.5),('Reference',10),('Equation',11),('Algorithm',10),('Note',9.5)]:
        st=styles.add_style(name,WD_STYLE_TYPE.PARAGRAPH);st.base_style=normal;st.font.size=Pt(size)
        st.paragraph_format.line_spacing=1.05;st.paragraph_format.space_after=Pt(4)
    styles['Reference'].paragraph_format.left_indent=Mm(7);styles['Reference'].paragraph_format.first_line_indent=Mm(-7)
    styles['Reference'].paragraph_format.keep_together=True
    styles['Reference'].paragraph_format.line_spacing=1.0
    styles['Reference'].paragraph_format.space_after=Pt(2)
    styles['Equation'].paragraph_format.space_before=Pt(5);styles['Equation'].paragraph_format.space_after=Pt(7)
    styles['Algorithm'].paragraph_format.left_indent=Mm(4)
    styles['Caption'].font.size=Pt(10);styles['Caption'].font.italic=False;styles['Caption'].font.bold=False;styles['Caption'].paragraph_format.space_before=Pt(8);styles['Caption'].paragraph_format.space_after=Pt(5);styles['Caption'].paragraph_format.keep_with_next=True
    # Real automatic section numbering, separate instance in each document.
    numroot=doc.part.numbering_part.element
    ab=el('w:abstractNum',**{'w:abstractNumId':'42'})
    ab.append(el('w:multiLevelType',**{'w:val':'multilevel'}))
    for lvl in range(3):
        lev=el('w:lvl',**{'w:ilvl':str(lvl)})
        for t,v in [('start','1'),('numFmt','decimal'),('lvlText','.'.join('%'+str(j+1) for j in range(lvl+1))),('lvlJc','left')]:lev.append(el('w:'+t,**{'w:val':v}))
        lev.append(el('w:suff',**{'w:val':'space'}));ab.append(lev)
    numroot.append(ab);num=el('w:num',**{'w:numId':'42'});num.append(el('w:abstractNumId',**{'w:val':'42'}));numroot.append(num)
    footer=sec.footer.paragraphs[0];footer.alignment=WD_ALIGN_PARAGRAPH.CENTER;footer.style='Note';field(footer,'PAGE',1)
    settings=doc.settings.element;settings.append(el('w:updateFields',**{'w:val':'true'}))
    doc.core_properties.author='Mohammadreza Parsania; Hamid Mala' if not is_audit else 'Research audit'
    doc.core_properties.subject='Adaptive arity and gradual tree migration in hybrid TreeKEM'
    doc.core_properties.keywords='TreeKEM; MLS; hybrid cryptography; tree migration'

def caption(doc,kind,num,title):
    p=doc.add_paragraph(style='Caption');p.add_run(kind+' ');field(p,'SEQ '+kind+' \\* ARABIC',num);p.add_run('. '+title);return p

def table(doc,lines):
    rows=[[x.strip() for x in line.split('|')] for line in lines];n=len(rows[0]);t=doc.add_table(rows=0,cols=n);t.alignment=WD_TABLE_ALIGNMENT.CENTER;t.autofit=False
    if n==3: proportions=[.24,.34,.42]
    elif n==4:proportions=[.28,.24,.24,.24]
    elif n==5:proportions=[.28,.14,.2,.2,.18]
    elif n==6:proportions=[.21,.14,.17,.18,.17,.13]
    elif n==7:proportions=[.27,.17,.11,.11,.11,.115,.115]
    else:proportions=[1/n]*n
    for col,pct in zip(t.columns,proportions):col.width=Mm(166*pct)
    borders=el('w:tblBorders')
    for pos in ['top','left','bottom','right','insideH','insideV']:borders.append(el('w:'+pos,**{'w:val':'single','w:sz':'4','w:color':'D9D9D9'}))
    t._tbl.tblPr.append(borders)
    mar=el('w:tblCellMar')
    for pos in ['top','bottom','left','right']:mar.append(el('w:'+pos,**{'w:w':'75','w:type':'dxa'}))
    t._tbl.tblPr.append(mar)
    for idx,vals in enumerate(rows):
        row=t.add_row();row._tr.get_or_add_trPr().append(el('w:cantSplit'))
        if idx==0:row._tr.get_or_add_trPr().append(el('w:tblHeader'))
        for j,(cell,txt,pct) in enumerate(zip(row.cells,vals,proportions)):
            cell.width=Mm(166*pct);cell.vertical_alignment=WD_CELL_VERTICAL_ALIGNMENT.CENTER
            p=cell.paragraphs[0];p.style='Table Text';prose(p,txt)
            p.paragraph_format.space_after=Pt(1);p.paragraph_format.space_before=Pt(1)
            if len(rows)<=10 and idx<len(rows)-1:p.paragraph_format.keep_with_next=True
            if idx==0:
                cell._tc.get_or_add_tcPr().append(el('w:shd',**{'w:fill':'E7EBEE'}))
                for r in p.runs:r.bold=True
            if n>=4 and j>0:p.alignment=WD_ALIGN_PARAGRAPH.CENTER
    return t

def build(name):
    doc=Document();setup(doc,name=='research_audit');lines=(O/(name+'.md')).read_text(encoding='utf8').splitlines()
    i=0;eqnum=tnum=fnum=anum=0;abstract=False;hcounter=0
    while i<len(lines):
        line=lines[i].strip();i+=1
        if not line:continue
        if line.startswith('@title '):
            t=line[7:];doc.add_paragraph(t,'Title');doc.core_properties.title=t
        elif line.startswith('@authors '):doc.add_paragraph(line[9:],'Subtitle')
        elif line.startswith('@affiliation '):doc.add_paragraph(line[13:],'Note')
        elif line.startswith('@subtitle '):doc.add_paragraph(line[10:],'Subtitle')
        elif line.startswith('@date '):doc.add_paragraph(line[6:],'Note')
        elif line=='@abstract':
            p=doc.add_paragraph('Abstract','Heading 2');abstract=True
        elif line.startswith('@keywords '):
            p=doc.add_paragraph(style='Note');p.add_run('Keywords: ').bold=True;p.add_run(line[10:]);abstract=False
        elif line.startswith('#'):
            level=len(line)-len(line.lstrip('#'));title=line[level:].strip();p=doc.add_paragraph(title,'Heading '+str(level))
            if title not in ['References','Research provenance and availability']:
                np=el('w:numPr');np.append(el('w:ilvl',**{'w:val':str(level-1)}));np.append(el('w:numId',**{'w:val':'42'}));p._p.get_or_add_pPr().append(np)
        elif line.startswith('@eq '):
            eqnum+=1;p=doc.add_paragraph(style='Equation');p.paragraph_format.keep_together=True
            p.paragraph_format.tab_stops.add_tab_stop(Mm(159),WD_TAB_ALIGNMENT.RIGHT)
            eq=el('m:oMath');eq.extend(mathparse(line[4:]));p._p.append(eq);p.add_run('\t(');field(p,'SEQ Equation \\* ARABIC',eqnum);p.add_run(')')
        elif line.startswith('@table '):
            tnum+=1;caption(doc,'Table',tnum,line[7:]);data=[]
            while i<len(lines) and '|' in lines[i] and lines[i].strip():data.append(lines[i]);i+=1
            table(doc,data)
        elif line.startswith('@algorithm '):
            anum+=1;caption(doc,'Algorithm',anum,line[11:])
        elif line.startswith('> '):
            p=doc.add_paragraph(style='Algorithm');prose(p,line[2:]);p.paragraph_format.keep_with_next=i<len(lines) and lines[i].startswith('> ')
        elif line.startswith('@figure '):
            fname,title=line[8:].split('|',1);p=doc.add_paragraph();p.alignment=WD_ALIGN_PARAGRAPH.CENTER;p.paragraph_format.keep_with_next=True
            r=p.add_run();inlinepic=r.add_picture(str(O/fname),width=Mm(166));inlinepic._inline.docPr.set('descr',title)
            fnum+=1;cap=caption(doc,'Figure',fnum,title);cap.paragraph_format.keep_with_next=False
        elif line.startswith('@note '):p=doc.add_paragraph(line[6:],'Note')
        elif line.startswith('@ref '):
            num,txt,url=line[5:].split('|',2);p=doc.add_paragraph(style='Reference');p.add_run('['+num+'] '+txt)
            if url:p.add_run(' ');hyperlink(p,url)
        else:
            p=doc.add_paragraph(style='Abstract Text' if abstract else 'Normal');prose(p,line)
            p.alignment=WD_ALIGN_PARAGRAPH.JUSTIFY
    for p in doc.paragraphs:
        p._p.get_or_add_pPr().append(el('w:bidi',**{'w:val':'0'}))
    doc.save(B/(name+'.docx'))
    print(name, 'paragraphs',len(doc.paragraphs),'tables',tnum,'equations',eqnum,'figures',fnum)
    return doc

if __name__=='__main__':
    diagram()
    for name in ['paper','research_audit']:build(name)
