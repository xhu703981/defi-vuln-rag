import json,sys,report
ids=open('/tmp/abl_ids.txt').read().split()
cs={c['id']:c for c in map(json.loads,open('cases.jsonl')) if c['id'] in ids}
for i in ids:
    r=report.explain(cs[i])
    print('##',i,'| refs:',[p['similar'] for p in r['picks']])
    for x in r['claims']: print('  ',x['function'],x['conf'],'|',x.get('class','')[:40],'|',x['path'][:230])
