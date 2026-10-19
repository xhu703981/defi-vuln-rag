# Vectorless RAG for attack paradigms. Build a compact, generator-safe catalogue (one structural
# paradigm sketch per historical case), then let Jev pick which cases share a transferable paradigm
# with the current victim surface. No embeddings. cases.jsonl is READ-ONLY (never written).
# Safety: paradigm sketches are writeup/KeyInfo-level abstractions, fine to show as REFERENCES for
# OTHER cases; retrieve_refs always excludes the query case itself, so a target never leaks its own PoC.
import json, os, re, sys
from llm import gen_model, jev

CASES = 'cases.jsonl'
IDX_DIR = 'data/index'
CAT = f'{IDX_DIR}/catalogue.jsonl'
GEN = os.environ.get('INDEX_MODEL', 'deepseek/deepseek-v3.2')  # cheap paraphraser
BATCH = int(os.environ.get('INDEX_BATCH', 15))                 # cases per paraphrase LLM call
JEV_BATCH = int(os.environ.get('JEV_BATCH', 40))               # candidates per Jev decision call

def _chain(d):
    t = (d.get('loss', '') + ' ' + d.get('root_cause', '') + ' ' + d.get('summary', '')).lower()
    for name, pats in [('ethereum', ['on ethereum', ' weth', 'uniswap v4', 'uniswap v3', 'uniswap v2 on eth']),
                       ('bsc', ['bsc', 'bnb', 'wbnb', 'pancake', 'busd']),
                       ('arbitrum', ['arbitrum', ' arb ']), ('polygon', ['polygon', 'matic']),
                       ('base', [' on base', 'base chain']), ('optimism', ['optimism'])]:
        if any(p in t for p in pats):
            return name
    return 'unknown'

def _load():
    return [json.loads(l) for l in open(CASES)]

PARA_PROMPT = '''You abstract smart-contract exploit root-causes into SHORT, TRANSFERABLE attack-paradigm sketches for an auditor's reference index. For each case below, output the generalizable MECHANISM (what class of bug + how it is abused), NOT the specific addresses, token names, or step-by-step PoC. Keep it reusable across contracts.

Return ONLY a JSON array, one object per input id, in order:
[{"id":"<id>","paradigm":"<<=28 words: the reusable attack pattern, e.g. 'spot-price oracle read inside a settlement path, moved by a flash-loaned swap, then an ungated settle/accept pays out at the manipulated price'>","tags":["<2-5 short mechanism keywords>"]}]

Cases:
'''

def _paraphrase_batch(batch):
    p = PARA_PROMPT + '\n'.join(
        f'- id={c["id"]} category={c.get("category","")}\n  root_cause: {(c.get("root_cause") or "")[:500]}'
        for c in batch)
    try:
        txt = gen_model(GEN, p, temp=0)
        arr = json.loads(re.search(r'\[[\s\S]*\]', txt).group(0))
        by = {o.get('id'): o for o in arr if isinstance(o, dict)}
    except Exception:
        by = {}
    out = []
    for c in batch:
        o = by.get(c['id']) or {}
        para = (o.get('paradigm') or '').strip() or (c.get('root_cause') or '')[:160]
        tags = o.get('tags') if isinstance(o.get('tags'), list) else []
        out.append({'id': c['id'], 'paradigm': para[:300], 'tags': [str(t)[:24] for t in tags][:5]})
    return out

def build_catalogue(force=False):
    os.makedirs(IDX_DIR, exist_ok=True)
    cases = _load()
    done = {}
    if os.path.exists(CAT) and not force:
        done = {json.loads(l)['id']: json.loads(l) for l in open(CAT)}
    todo = [c for c in cases if c['id'] not in done]
    for i in range(0, len(todo), BATCH):
        for e in _paraphrase_batch(todo[i:i + BATCH]):
            done[e['id']] = e
        print(f'paraphrased {min(i+BATCH,len(todo))}/{len(todo)} new', file=sys.stderr, flush=True)
    rows = []
    for c in cases:
        e = done[c['id']]
        rows.append({'id': c['id'], 'date': c.get('date', ''), 'chain': _chain(c),
                     'category': c.get('category', ''), 'loss_short': (c.get('loss') or '')[:80],
                     'paradigm': e['paradigm'], 'tags': e.get('tags', [])})
    with open(CAT, 'w') as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')
    return rows

def load_catalogue():
    return [json.loads(l) for l in open(CAT)]

def _victim_surface(ctx, src=''):
    # compact, generator-safe description of the current victim: dense live CONTEXT + source fn signatures
    fns = re.findall(r'function\s+\w+\s*\([^)]*\)[^{;]*', src or '')[:40]
    s = 'VICTIM ON-CHAIN CONTEXT:\n' + (ctx or '')[:2600]
    if fns:
        s += '\n\nVICTIM FUNCTION SIGNATURES:\n' + '\n'.join(f[:160] for f in fns)
    return s[:4000]

def retrieve_refs(ctx, src='', query_id=None, k=5, chain=None):
    '''Jev picks which historical paradigms are transferable to this victim. Returns top-k
    [{id, category, paradigm, score, why}], excluding query_id.'''
    cat = load_catalogue()
    cands = [c for c in cat if c['id'] != query_id]
    if chain:
        same = [c for c in cands if c['chain'] == chain]
        cands = same or cands  # keep all if filtering leaves nothing
    state = {'victim': _victim_surface(ctx, src)}
    scored = []
    for i in range(0, len(cands), JEV_BATCH):
        chunk = cands[i:i + JEV_BATCH]
        Q = {f'q{j}': {'type': 'noul', 'instructions':
             f'Reference attack paradigm (category={c["category"]}, tags={c.get("tags")}): "{c["paradigm"]}". '
             'Could an UNPRIVILEGED attacker plausibly reuse THIS attack paradigm against the victim in state.victim? '
             'Answer high only if the victim\'s functions, pools, roles, and asset flows actually expose this class of bug.'}
             for j, c in enumerate(chunk)}
        ans = jev(state, Q)
        for j, c in enumerate(chunk):
            p = (ans.get(f'q{j}') or {}).get('noul', 0)
            scored.append((p, c))
    scored.sort(key=lambda x: -x[0])
    out = []
    for p, c in scored[:k]:
        out.append({'id': c['id'], 'category': c['category'], 'paradigm': c['paradigm'],
                    'score': round(p, 3),
                    'why': f'shares {c["category"]} paradigm [{",".join(c.get("tags",[]))}] (Jev p={round(p,3)})'})
    return out

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'build'
    if cmd == 'build':
        rows = build_catalogue(force='--force' in sys.argv)
        print(f'catalogue: {len(rows)} entries -> {CAT}')
    elif cmd == 'show':
        for r in load_catalogue()[:int(sys.argv[2]) if len(sys.argv) > 2 else 3]:
            print(json.dumps(r, ensure_ascii=False, indent=1))
    elif cmd == 'retrieve':  # retrieve <case_id> : smoke using that case's stored CONTEXT
        cid = sys.argv[2]
        slug = re.sub(r'\W+', '_', cid)
        ctx = open(f'data/loop/{slug}/CONTEXT.txt').read()
        for r in retrieve_refs(ctx, query_id=cid, k=6):
            print(json.dumps(r, ensure_ascii=False))
