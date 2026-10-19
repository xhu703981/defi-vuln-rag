# Exp G: strong LLM reads full victim source directly (same victim as SEL=jev) vs report.py pipeline. Generator sees source + addr/chain only.
import json, re, sys, time, os, glob, hashlib
from concurrent.futures import ThreadPoolExecutor
import fetch_source as fs, judge
from llm import gen_model, CACHE
M = os.environ.get('DIRECT_MODEL', 'google/gemini-2.5-pro')
IDS = ['20210817_XSURGE', '20210804_WaultFinace', '20211130_MonoX Finance', '20230227_LaunchZone', '20231106_KR']
def src(c):
    ch = next(ch for ch, a, _ in fs.addrs(c) if a == c['vaddr']); r = fs.get(ch, c['vaddr'])
    s = '\n'.join(v for k, v in fs.files(r['SourceCode']).items() if not re.search(r'@openzeppelin|/interfaces?/|/lib/', k, re.I))
    return ch, r['ContractName'], s
def direct(c):
    ch, name, s = src(c)
    p = (f'You are an expert smart-contract auditor. Contract {name} at {c["vaddr"]} on chain id {ch}. Full verified source below. '
         'Find the functions most likely exploitable by an unprivileged attacker to steal or take control of others\' assets. Reply ONLY JSON: '
         '[{"function": "<exact function name>", "class": "<mechanism class>", "path": "<entry, what is manipulated, what is extracted>"}] '
         'with 1-3 items, most likely first.\n\n' + s)
    t = time.time(); out = gen_model(M, p); dt = time.time() - t
    k = f'{CACHE}/{hashlib.sha1((M + p).encode()).hexdigest()}.json'; u = json.load(open(k)).get('usage') or {}
    try: picks = json.loads(re.search(r'\[[\s\S]*\]', out)[0])
    except Exception: picks = []
    return {'picks': [{'name': x.get('function', ''), 'why': x.get('class', ''), 'path': x.get('path', '')} for x in picks][:3], 'sec': dt, 'usage': u, 'chars': len(s)}
if __name__ == '__main__':
    F = {c['id']: c for c in map(json.loads, open('f_dev_label_jev.jsonl'))}
    P = {c['id']: c for c in map(json.loads, open(sys.argv[1]))}  # pipeline report.py outputs
    rows = []
    for i in IDS:
        c = F[i]; d = direct(c); pc = P[i]
        pl = list(dict.fromkeys([x['function'] for x in pc['claims']] + [p['name'] for p in pc['picks']]))
        J = lambda names: [judge.judge({**c, 'picks': [{'name': n, 'why': ''} for n in names[:k]]})['func_hit'] for k in (1, 3)]
        rows.append({'id': i, 'direct': d, 'direct_hit': J([p['name'] for p in d['picks']]), 'pipe': pl[:3], 'pipe_hit': J(pl),
                     'pipe_finding': pc['finding'] if isinstance(pc['finding'], str) else pc['finding']['function']})
        print(json.dumps(rows[-1], ensure_ascii=False)[:2500], flush=True)
    json.dump(rows, open('exp_direct_out.json', 'w'), ensure_ascii=False, indent=1)
