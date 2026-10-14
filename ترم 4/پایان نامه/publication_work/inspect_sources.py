from pathlib import Path
import json, hashlib
from PIL import Image, ImageOps, ImageDraw
import pdfplumber
B=Path(__file__).resolve().parent.parent
O=B/'publication_work'
for src in (B/'related_works').rglob('*.pdf'):
    if src.parent.name not in ['3-3','3-4','3-5']: continue
    d=pdfplumber.open(src)
    out=O/(src.parent.name+'_primary.txt')
    out.write_text('\n'.join(f'\nPAGE {i+1}\n'+(p.extract_text() or '') for i,p in enumerate(d.pages)),encoding='utf8')
    print(src.name, len(d.pages), 'pages')
imgs=[]
for src in sorted((O/'source_images').iterdir(),key=lambda p:int(''.join(x for x in p.stem if x.isdigit()))):
    if src.suffix=='.svg': continue
    im=Image.open(src).convert('RGB')
    imgs.append((src.name,im))
for start in range(0,len(imgs),4):
    canvas=Image.new('RGB',(1600,1800),'white'); draw=ImageDraw.Draw(canvas)
    for j,(name,im) in enumerate(imgs[start:start+4]):
        x=(j%2)*800;y=(j//2)*900
        draw.text((x+20,y+10),name,fill='black')
        im.thumbnail((770,850))
        canvas.paste(im,(x+15,y+40))
    canvas.save(O/f'source_sheet_{start//4+1}.png')
print('Contact sheets created')
