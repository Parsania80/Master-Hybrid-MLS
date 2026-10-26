import json, sys
from pathlib import Path
b=json.loads((Path(__file__).parent/'thesis_blocks.json').read_text(encoding='utf-8'))
lo,hi=map(int,sys.argv[1:3])
for x in b:
    if lo<=x['id']<hi and x['style']!='TOC1' and x['type']!='sdt':
        print('[%04d %s] %s\n'%(x['id'],x['style'],x['text']))
