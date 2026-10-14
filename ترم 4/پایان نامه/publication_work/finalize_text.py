from pathlib import Path
import re
O=Path(__file__).resolve().parent
p=O/'paper.md';s=p.read_text(encoding='utf8')
s=s.replace('target arity dprime','target arity d′').replace('and Delta a safety margin','and Δ a safety margin')
s=s.replace('Requires a narrower novelty claim about migration','Tree degree is a pre-existing optimization variable')
s=s.replace('The manuscript requires scientific review by both named authors before submission; no completed author approval or independent cryptographic validation is implied.','Scientific assessment and responsibility for the final text remain with the authors.')
mapping={1:1,2:2,3:3,4:4,11:5,5:6,6:7,7:8,8:9,9:10,10:11}
def ren(m):return '['+', '.join(str(mapping[int(x.strip())]) for x in m.group(1).split(','))+']'
body,refs=s.split('# References\n')
body=re.sub(r'\[([1-9][0-9]*(?:, *[1-9][0-9]*)*)\]',ren,body)
rr=[]
for line in refs.splitlines():
    if line.startswith('@ref '):
        n,rest=line[5:].split('|',1);rr.append((mapping[int(n)],rest))
s=body+'# References\n\n'+'\n'.join('@ref '+str(n)+'|'+rest for n,rest in sorted(rr))+'\n'
p.write_text(s,encoding='utf8')
p=O/'research_audit.md';s=p.read_text(encoding='utf8');a=s.index('Paper ref |');b=s.index('\n\n',a)
lines=s[a:b].splitlines();rows=[]
for line in lines[1:]:
    n,rest=line.split('|',1);rows.append((mapping[int(n.strip())],rest))
s=s[:a]+lines[0]+'\n'+'\n'.join(str(n)+' |'+rest for n,rest in sorted(rows))+s[b:]
p.write_text(s,encoding='utf8')
print('Citation ordering and notation finalized')
