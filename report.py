# Auditor report for one contract: Jev checklist ranking (fetch_source.index) -> DeepSeek proposes attack paths for the top-3 (call chain +
# similar EARLIER incidents, temporal split) -> Jev skeptic scores each claim -> finding or 'no finding'.
import re, json, os, sys, numpy as np
from concurrent.futures import ThreadPoolExecutor
import fetch_source as fs, rag
from llm import gen, gen_model, jev
calls = lambda C, n: [m for m in C if m != n and re.search(rf'\b{m}\s*\(', C[n])]
def up(C, n, d=3):  # callers up to an external entry
    return {} if not d else {k: v for m in C if n in calls(C, m) for k, v in [(m, re.sub(r'\s+', ' ', C[m])[:600]), *up(C, m, d - 1).items()]}
def similar(c, f, k=2):  # earlier incidents by best function match (raw + normalized embeddings)
    A = np.array([j for j, d in enumerate(rag.cases) if d['date'] < c['date'] and d['id'] != c['id']])
    s = sum(rag.E[n] @ rag.emb([x])[0] for n, x in (('raw', f), ('norm', rag.norm(f))))
    best = np.full(len(rag.cases), -1e9); np.maximum.at(best, rag.own, s)
    return [rag.cases[j] for j in A[np.argsort(-best[A])][:k]]
SKEPTIC = {'blocked': 'Is this attack path blocked by a check visible in the provided code (e.g. state keyed by msg.sender/user, allowance or signature check, invariant/K check, slippage or min-amount parameter, access modifier, reentrancy lock)?',
           'needs': 'Does this path require a privileged role, an owner/admin misconfiguration, a compromised key, the victim\'s own prior approval/signature for this exact action, or behaviour of code that is NOT shown?',
           'gain': 'Can an unprivileged external attacker, using only the shown code, take funds or value belonging to others (or the protocol) via this path?'}
def refs(c, n, f):  # NREF=k: top-8 by same embedding match, Jev drops clearly irrelevant ones (p<REF_TAU), keep up to k
    H = similar(c, f, k=8); ok = []
    for h in H:
        a = jev({'function_under_audit': f[:3000], 'past_incident_root_cause': h['root_cause'][:400]},
                {'useful': {'type': 'noul', 'instructions': 'Could this past incident root cause plausibly be relevant (same bug class or risky pattern) to the function under audit?'}})
        if a.get('useful', {}).get('noul', 0) >= REF_TAU: ok.append(h)
    return ok[:NREF]
def explain(c):  # -> picks + similar cases + claims [{function, path, class, conf}] + finding ('no finding' if max conf < TAU)
    c = {**c}; fs.index(c); C = fs.victim(c); ctx = []
    for p in c['picks']:
        n = p['name']; p['similar'] = [h['id'] for h in (refs(c, n, C[n]) if NREF else similar(c, C[n]))]
        ctx.append(f"### {n} (checklist: {p['why']})\n{C[n][:3000]}\nCallers: {', '.join(up(C, n)) or 'external entry'}\nCallees:\n" +
                   '\n'.join(C[m][:1500] for m in calls(C, n))[:5000] + ('' if NO_RAG else '\nSimilar earlier incidents: ' + ' || '.join(d['root_cause'][:300] for d in rag.cases if d['id'] in p['similar'])))
    _lead = ('You are a smart-contract auditor. Below are the 3 most suspicious functions of one contract, with call chains and checklist signals. '
             if NO_RAG else
             'You are a smart-contract auditor. Below are the 3 most suspicious functions of one contract, with call chains, checklist signals and '
             'root causes of similar past incidents (these may NOT apply). ')
    out = (lambda q: gen_model(GENM, q) if GENM else gen(q))(_lead + 'Propose at most one concrete attack path per function, only if it is plausible '
              'from THIS code. Reply ONLY JSON: [{"function": "<name>", "path": "<entry, what is manipulated, what is extracted>", "class": "<vulnerability class>"}] '
              '(empty list if none). Do not invent code that is not shown.\n\n' + '\n\n'.join(ctx))
    try: claims = [x for x in json.loads(re.search(r'\[[\s\S]*\]', out)[0]) if x.get('function') in C]
    except Exception: claims = []
    for x in claims:  # Jev skeptic on each claim, with the full function + callees
        n = x['function']; a = jev({'function': C[n][:4000], 'callees': {m: C[m][:2000] for m in calls(C, n)}, 'callers': list(up(C, n)) or 'external entry',
                                    'claimed_attack': x['path'], 'claimed_class': x.get('class', '')}, {k: {'type': 'noul', 'instructions': q} for k, q in SKEPTIC.items()})
        P = {k: a.get(k, {}).get('noul', 0) for k in SKEPTIC}; x['conf'] = round(P['gain'] * (1 - P['blocked']) * (1 - P['needs']), 3); x['p'] = P
    claims.sort(key=lambda x: -x['conf']); c['claims'] = claims
    c['finding'] = claims[0] if claims and claims[0]['conf'] >= TAU else 'no finding'
    return c
NO_RAG = os.environ.get('NO_RAG') == '1'
NREF = int(os.environ.get('NREF', 0))  # 0 = old behaviour (2 refs, no Jev filter)
REF_TAU = float(os.environ.get('REF_TAU', .3))
GENM = os.environ.get('GEN_MODEL')  # e.g. google/gemini-2.5-pro; unset = DeepSeek via gen()  # ablation: drop similar-earlier-incident root_cause context from the DeepSeek generation stage
TAU = float(os.environ.get('TAU', .15))
LEVEL = lambda x: 'medium' if x >= TAU else 'low'  # skeptic conf is low on almost everything; >= TAU only on ~10% of safe contracts
def md(c):  # auditor-facing markdown
    o = [f"# Audit triage: {c['id']}", '', '## Where to look (checklist ranking)']
    o += [f"{k}. `{p['name']}`: {p['why']}; similar earlier incidents: {', '.join(p.get('similar', [])) or '-'}" for k, p in enumerate(c['picks'], 1)]
    o += ['', '## Candidate attack paths (DeepSeek hypotheses, Jev skeptic confidence)']
    o += [f"- [{LEVEL(x['conf'])} {x['conf']:.2f}] `{x['function']}` ({x.get('class', '')}): {x['path']}" for x in c['claims']] or ['- none proposed']
    f = c['finding']; o += ['', '## Verdict', f"Finding ({LEVEL(f['conf'])}): `{f['function']}`: {f['path']}" if isinstance(f, dict) else 'No finding above threshold; review the ranked functions manually.']
    return '\n'.join(o)
def target(arg, chain='1'):  # address on a chain, or a local .sol file (cached under a pseudo-address) -> case dict
    if arg.endswith('.sol'):
        src = open(arg).read(); a = '0x' + __import__('hashlib').sha1(src.encode()).hexdigest()[:40]
        json.dump({'result': [{'SourceCode': src, 'ContractName': (re.findall(r'\bcontract\s+(\w+)', src) or ['main'])[-1], 'Proxy': '0', 'Implementation': ''}]}, open(f'data/1_{a}.json', 'w'))
        arg, chain = a, '1'
    host = {v: k for k, v in fs.CHAIN.items()}[int(chain)]
    return {'id': arg, 'date': '99999999', 'poc': f'// victim https://{host}/address/{arg}', 'root_cause': '', 'category': ''}
if __name__ == '__main__':  # report.py <0xaddr> [chainid] | <file.sol>  -> markdown;  report.py ids.txt|targets.jsonl out.jsonl -> eval
    if len(sys.argv) < 3 or sys.argv[2].isdigit(): print(md(explain(target(*sys.argv[1:3])))); sys.exit()
    ids = open(sys.argv[1]).read().split('\n')  # ids from cases.jsonl, or a .jsonl of external targets {id,date,poc:'// victim <explorer>/address/0x..'}
    cs = [json.loads(l) for l in ids if l] if sys.argv[1].endswith('.jsonl') else [c for c in map(json.loads, open('cases.jsonl')) if c['id'] in ids]
    for c in cs: c.setdefault('poc', c.get('code', ''))
    with open(sys.argv[2], 'w') as w:
        for r in ThreadPoolExecutor(8).map(explain, cs): w.write(json.dumps(r) + '\n')
