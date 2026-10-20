# Vectorless RAG for attack paradigms. Build a compact, generator-safe catalogue (one structural
# paradigm sketch per historical case + closed subclass), then let Jev pick which cases share a
# transferable paradigm with the current victim surface. No embeddings. cases.jsonl is READ-ONLY.
# Safety: paradigm sketches are writeup/KeyInfo-level abstractions, fine to show as REFERENCES for
# OTHER cases; retrieve_refs always excludes the query case itself, so a target never leaks its own PoC.
import json, os, re, sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from llm import gen_model, jev
from taxonomy import TAXONOMY, criteria_for, subclasses_for

CASES = 'cases.jsonl'
IDX_DIR = 'data/index'
CAT = f'{IDX_DIR}/catalogue.jsonl'
SUM_SIDE = f'{IDX_DIR}/summaries_generated.jsonl'
GEN = os.environ.get('INDEX_MODEL', 'deepseek/deepseek-v3.2')  # cheap paraphraser
BATCH = int(os.environ.get('INDEX_BATCH', 12))                 # cases per paraphrase LLM call
JEV_BATCH = int(os.environ.get('JEV_BATCH', 40))               # candidates per Jev retrieve call
CLASS_BATCH = int(os.environ.get('CLASS_BATCH', 20))           # cases per Jev classify call

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

def _load_sidecar():
    out = {}
    if os.path.exists(SUM_SIDE):
        for l in open(SUM_SIDE):
            l = l.strip()
            if not l: continue
            o = json.loads(l)
            if (o.get('summary') or '').strip():
                out[o['id']] = o['summary'].strip()
    return out

def case_signal(c, sidecar, existing_para=''):
    '''Fallback: cases.jsonl summary -> generated sidecar -> root_cause -> existing paradigm.'''
    s = (c.get('summary') or '').strip()
    if s: return s, 'cases_summary'
    s = (sidecar.get(c['id']) or '').strip()
    if s: return s, 'generated'
    s = (c.get('root_cause') or '').strip()
    if s: return s, 'root_cause'
    s = (existing_para or '').strip()
    if s: return s, 'paradigm'
    return '', 'empty'

# ---- subclass classification (Jev choice over closed list) ----

def _classify_one(c, sidecar):
    '''Classify a single case via Jev choice. Per-case cache key (stable across batching).'''
    cat = c.get('category') or ''
    crit = criteria_for(cat)
    if not crit:
        return 'unknown'
    sig, src = case_signal(c, sidecar)
    sig_short = sig[:1800]
    rc = (c.get('root_cause') or '')[:240]
    instructions = (
        f'Top category is FIXED as "{cat}" (do not change it). '
        f'Pick the SINGLE best matching SUB-CLASS for this historical exploit\'s MECHANISM. '
        f'Prefer the most specific matching subclass. Disambiguation rules for reentrancy:\n'
        f'- If root_cause/signal says read-only / view reentrancy / stale view mid-update -> read_only.\n'
        f'- If ERC777 / ERC667 / tokensReceived / token hook -> token_hook_callback.\n'
        f'- If reentrancy crosses into a DIFFERENT contract sharing accounting -> cross_contract.\n'
        f'- If flashloan funds the reentrancy capital/callback -> flashloan_reentrancy '
        f'(unless the distinctive mechanism is clearly a different subclass above).\n'
        f'- If a function WITH nonReentrant/lock pays out, and a DIFFERENT unguarded state-changing '
        f'entrypoint (buy/mint/purchase/receive/deposit) can be re-entered against un-burned supply '
        f'or un-updated reserves -> cross_entrypoint_unlocked_sibling (NOT classic_single_fn_cei).\n'
        f'- Same-function CEI violation re-entered into itself -> classic_single_fn_cei.\n'
        f'- Reentrancy plus reward/share/stake over-claim -> reentrancy_reward_logic.\n'
        f'\ncase_id={c["id"]}\nroot_cause={rc}\nsignal_source={src}\nsignal:\n{sig_short}'
    )
    Q = {'subclass': {'type': 'choice', 'instructions': instructions, 'criteria': crit}}
    # state keyed by case id + signal hash so cache is stable & per-case
    state = {'task': 'classify_exploit_subclass_v2', 'case_id': c['id'], 'category': cat}
    try:
        ans = jev(state, Q)
        a = ans.get('subclass') or {}
        choice = a.get('choice') if a.get('type') == 'choice' else None
        if choice in crit:
            return choice
    except Exception as e:
        print(f'classify jev err {c["id"]}: {type(e).__name__}: {e}'[:200], file=sys.stderr, flush=True)
    return _heuristic_subclass(c, sidecar, cat)

def _classify_batch(batch, sidecar):
    '''Classify each case (parallel-friendly loop; each call is independently cached).'''
    out = {}
    for c in batch:
        out[c['id']] = _classify_one(c, sidecar)
    return out

def _heuristic_subclass(c, sidecar, cat):
    '''Deterministic fallback if Jev answer missing/invalid. Keyword match within category.'''
    sig, _ = case_signal(c, sidecar)
    t = ((c.get('root_cause') or '') + ' ' + sig[:800]).lower()
    prefs = {
        'reentrancy': [
            ('cross_entrypoint_unlocked_sibling', ['cross-entrypoint', 'cross entrypoint', 'sibling', 'unlocked', 'buy during sell', 'purchase during', 're-enter buy', 'reenter buy', 'different function', 'another entrypoint']),
            ('read_only', ['read-only', 'read only', 'view reentran']),
            ('token_hook_callback', ['erc777', 'erc667', 'erc721', 'token hook', 'tokensreceived', 'onreceived']),
            ('flashloan_reentrancy', ['flashloan', 'flash loan']),
            ('cross_contract', ['cross contract', 'cross-contract']),
            ('reentrancy_reward_logic', ['reward', 'share manip']),
            ('classic_single_fn_cei', ['reentrancy', 'reentrant', 'cei']),
        ],
        'price_manipulation': [
            ('vault_share_inflation', ['erc4626', 'share inflation', 'donation', 'first deposit', 'inflation attack']),
            ('twap_manipulation', ['twap']),
            ('stale_faulty_oracle', ['stale', 'faulty oracle', 'wrong oracle', 'oracle decimal']),
            ('governance_oracle_swap', ['governance', 'oracle swap', 'setoracle']),
            ('same_block_self_trade_latch', ['same block', 'self-trade', 'self trade', 'latch']),
            ('internal_virtual_amm_formula', ['virtual amm', 'internal amm', 'custom price', 'bonding curve']),
            ('direct_reserve_no_flashloan', ['skim', 'sync', 'direct transfer', 'no flash']),
            ('amm_spot_flashloan', ['flashloan', 'flash loan', 'spot', 'getreserves', 'price']),
        ],
        'access_control': [
            ('unprotected_initialization', ['initialize', 'uninit', 're-init']),
            ('arbitrary_external_call', ['arbitrary call', 'delegatecall', 'call{', 'user-supplied']),
            ('fake_pool_callback_drains_allowance', ['fake pool', 'callback', 'allowance']),
            ('proof_settlement_mismatch', ['proof', 'rollup', 'settlement mismatch']),
            ('caller_context_bypass', ['tx.origin', 'context', 'msg.sender bypass']),
            ('permissionless_state_feeds_downstream', ['permissionless state', 'feeds downstream']),
            ('missing_permission_check', ['access control', 'onlyowner', 'missing', 'permission']),
        ],
        'precision': [
            ('donation_inflated_rate_rounding', ['donation', 'inflat']),
            ('fixedpoint_share_rounding', ['fixed-point', 'fixedpoint', 'share round']),
            ('integer_division_truncation', ['truncat', 'division', 'rounding', 'precision']),
        ],
    }
    for sid, kws in prefs.get(cat, []):
        if any(k in t for k in kws):
            return sid
    # default: first key in taxonomy for that category
    subs = list(subclasses_for(cat).keys())
    return subs[0] if subs else 'unknown'

def classify_all(cases, sidecar, force=False, cache_path=None):
    cache_path = cache_path or f'{IDX_DIR}/subclasses.jsonl'
    done = {}
    if os.path.exists(cache_path) and not force:
        for l in open(cache_path):
            l = l.strip()
            if not l: continue
            o = json.loads(l)
            if o.get('subclass'):
                done[o['id']] = o['subclass']
    todo = [c for c in cases if c['id'] not in done]
    print(f'classify: {len(done)} cached, {len(todo)} todo', file=sys.stderr, flush=True)
    workers = int(os.environ.get('CLASS_WORKERS', '8'))
    with open(cache_path, 'a') as f, ThreadPoolExecutor(workers) as ex:
        futs = {ex.submit(_classify_one, c, sidecar): c for c in todo}
        n = 0
        for fut in as_completed(futs):
            c = futs[fut]
            try:
                sid = fut.result()
            except Exception as e:
                print(f'classify fail {c["id"]}: {e}'[:160], file=sys.stderr, flush=True)
                sid = _heuristic_subclass(c, sidecar, c.get('category') or '')
            done[c['id']] = sid
            f.write(json.dumps({'id': c['id'], 'category': c.get('category'), 'subclass': sid}) + '\n')
            f.flush()
            n += 1
            if n % 10 == 0 or n == len(todo):
                print(f'classified {n}/{len(todo)}', file=sys.stderr, flush=True)
    return done

# ---- paradigm paraphrase (cheap model, richer signal) ----

PARA_PROMPT = '''You abstract smart-contract exploit mechanisms into SHORT, TRANSFERABLE attack-paradigm sketches for an auditor's reference index. For each case below, output the generalizable MECHANISM (what class of bug + how it is abused), NOT specific addresses, token names, or step-by-step PoCs. Keep it reusable across contracts.

The subclass label is authoritative — your paradigm sentence MUST express that subclass's mechanism (e.g. for cross_entrypoint_unlocked_sibling: re-entering a DIFFERENT unlocked state-changing entrypoint against stale supply/reserves while a guarded sibling is mid-payout).

Return ONLY a JSON array, one object per input id, in order:
[{"id":"<id>","paradigm":"<<=32 words: reusable attack pattern>","tags":["<2-5 short mechanism keywords>"]}]

Cases:
'''

def _paraphrase_batch(batch, subclasses, sidecar):
    lines = []
    for c in batch:
        sid = subclasses.get(c['id'], '')
        cat = c.get('category') or ''
        defn = subclasses_for(cat).get(sid, '')
        sig, src = case_signal(c, sidecar)
        lines.append(
            f'- id={c["id"]} category={cat} subclass={sid}\n'
            f'  subclass_def: {defn}\n'
            f'  root_cause: {(c.get("root_cause") or "")[:240]}\n'
            f'  signal({src}): {sig[:900]}'
        )
    p = PARA_PROMPT + '\n'.join(lines)
    try:
        txt = gen_model(GEN, p, temp=0)
        arr = json.loads(re.search(r'\[[\s\S]*\]', txt).group(0))
        by = {o.get('id'): o for o in arr if isinstance(o, dict)}
    except Exception as e:
        print(f'paraphrase err: {type(e).__name__}: {e}'[:160], file=sys.stderr, flush=True)
        by = {}
    out = []
    for c in batch:
        o = by.get(c['id']) or {}
        para = (o.get('paradigm') or '').strip()
        if not para:
            sid = subclasses.get(c['id'], '')
            cat = c.get('category') or ''
            para = subclasses_for(cat).get(sid) or (c.get('root_cause') or '')[:160]
        tags = o.get('tags') if isinstance(o.get('tags'), list) else []
        # always include subclass as a tag for retrieve scoring readability
        sid = subclasses.get(c['id'], '')
        if sid and sid not in tags:
            tags = [sid] + list(tags)
        out.append({'id': c['id'], 'paradigm': para[:320], 'tags': [str(t)[:40] for t in tags][:6]})
    return out

def build_catalogue(force=False):
    os.makedirs(IDX_DIR, exist_ok=True)
    cases = _load()
    sidecar = _load_sidecar()
    # 1) classify subclasses (Jev), resume-friendly
    subclasses = classify_all(cases, sidecar, force=force)
    # 2) paraphrase paradigms with rich signal
    done = {}
    para_cache = f'{IDX_DIR}/paradigms_v2.jsonl'
    if os.path.exists(para_cache) and not force:
        for l in open(para_cache):
            l = l.strip()
            if not l: continue
            o = json.loads(l)
            if o.get('paradigm'):
                done[o['id']] = o
    todo = [c for c in cases if c['id'] not in done]
    print(f'paraphrase: {len(done)} cached, {len(todo)} todo', file=sys.stderr, flush=True)
    with open(para_cache, 'a') as f:
        for i in range(0, len(todo), BATCH):
            batch = todo[i:i + BATCH]
            for e in _paraphrase_batch(batch, subclasses, sidecar):
                done[e['id']] = e
                f.write(json.dumps(e, ensure_ascii=False) + '\n')
            f.flush()
            print(f'paraphrased {min(i+BATCH,len(todo))}/{len(todo)}', file=sys.stderr, flush=True)
    # 3) write catalogue
    rows = []
    for c in cases:
        e = done[c['id']]
        sid = subclasses.get(c['id'], '')
        rows.append({
            'id': c['id'],
            'date': c.get('date', ''),
            'chain': _chain(c),
            'category': c.get('category', ''),          # UNCHANGED from cases.jsonl
            'subclass': sid,
            'loss_short': (c.get('loss') or '')[:80],
            'paradigm': e['paradigm'],
            'tags': e.get('tags', []),
        })
    with open(CAT, 'w') as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')
    return rows

def load_catalogue():
    return [json.loads(l) for l in open(CAT)]

def _victim_surface(ctx, src=''):
    fns = re.findall(r'function\s+\w+\s*\([^)]*\)[^{;]*', src or '')[:40]
    s = 'VICTIM ON-CHAIN CONTEXT:\n' + (ctx or '')[:2200]
    if fns:
        s += '\n\nVICTIM FUNCTION SIGNATURES:\n' + '\n'.join(f[:160] for f in fns)
    # Include a compact slice of provided source so modifiers (nonReentrant) and sibling
    # entrypoints (receive/purchase/buy) are visible to the scorer.
    if src:
        s += '\n\nVICTIM SOURCE EXCERPT:\n' + (src or '')[:1400]
    return s[:4200]


def _src_excerpt_for_ctx(ctx):
    """Best-effort: pull sell/receive/purchase/buy bodies from cached verified SourceCode
    when CONTEXT names a VICTIM address. Never touches PoC/DeFiHackLabs."""
    m = re.search(r'VICTIM\s+(0x[0-9a-fA-F]{40})', ctx or '')
    if not m:
        return ''
    addr = m.group(1).lower()
    path = None
    for f in os.listdir('data'):
        if re.match(r'^\d+_' + re.escape(addr) + r'\.json$', f):
            path = f'data/{f}'; break
    if not path:
        return ''
    try:
        d = json.load(open(path))
        r = d.get('result', d)
        if isinstance(r, list):
            r = r[0]
        full = (r.get('SourceCode') or '') if isinstance(r, dict) else ''
        if full.startswith('{{'):
            inner = json.loads(full[1:-1])
            sources = inner.get('sources', inner)
            full = '\n'.join((v.get('content') if isinstance(v, dict) else str(v)) for v in sources.values())
    except Exception:
        return ''
    parts = []
    for pat in [r'receive\s*\(\s*\)\s*[^{;]*\{(?:[^{}]|\{[^{}]*\})*\}',
                r'function\s+(sell|buy|purchase\w*|mint\w*)\s*\([^)]*\)[^{;]*\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}']:
        for mm in re.finditer(pat, full):
            parts.append(mm.group(0)[:1500])
            if len(parts) >= 4:
                break
    return '\n\n'.join(parts)[:4000]

def retrieve_refs(ctx, src='', query_id=None, k=5, chain=None):
    '''Jev picks which historical paradigms are transferable to this victim. Returns top-k
    [{id, category, subclass, paradigm, score, why}], excluding query_id.'''
    cat = load_catalogue()
    cands = [c for c in cat if c['id'] != query_id]
    if chain:
        same = [c for c in cands if c['chain'] == chain]
        cands = same or cands
    state = {'victim': _victim_surface(ctx, src)}
    scored = []
    for i in range(0, len(cands), JEV_BATCH):
        chunk = cands[i:i + JEV_BATCH]
        def _instr(c):
            return (
                f'Reference attack paradigm (category={c["category"]}, subclass={c.get("subclass","")}, tags={c.get("tags")}): "{c["paradigm"]}". '
                'Could an UNPRIVILEGED attacker plausibly reuse THIS SPECIFIC attack paradigm as a PRIMARY exploit path '
                'against the victim in state.victim? '
                "Score HIGH only when the victim's concrete functions/modifiers/asset flows match this mechanism. "
                'Score LOW for generic "public function exists" / missing-permission matches unless the victim exposes an '
                'admin/privileged/init/arbitrary-call path that should have been gated. '
                'Mere presence of a public sell/transfer/swap is NOT enough for missing_permission_check. '
                'For cross_entrypoint_unlocked_sibling: HIGH if victim has a guarded/nonReentrant payout AND a different '
                'unguarded state-changing entrypoint (buy/mint/purchase/receive) usable mid-payout against stale supply/reserves. '
                'For classic_single_fn_cei: HIGH if same function is re-entered after external call before its own state update. '
                'For amm_spot_flashloan: HIGH if settlement/mint reads manipulable spot reserves.'
            )
        Q = {f'q{j}': {'type': 'noul', 'instructions': _instr(c)} for j, c in enumerate(chunk)}
        ans = jev(state, Q)
        for j, c in enumerate(chunk):
            p = (ans.get(f'q{j}') or {}).get('noul', 0)
            scored.append((p, c))
    scored.sort(key=lambda x: -x[0])
    # Diversify: at most 2 per subclass in the returned top-k so generic classes cannot flood the list.
    out, seen_sub, per_sub = [], {}, 2
    for p, c in scored:
        sub = c.get('subclass') or c.get('category') or ''
        if seen_sub.get(sub, 0) >= per_sub:
            continue
        seen_sub[sub] = seen_sub.get(sub, 0) + 1
        out.append({
            'id': c['id'],
            'category': c['category'],
            'subclass': c.get('subclass', ''),
            'paradigm': c['paradigm'],
            'score': round(p, 3),
            'why': (f'shares {c["category"]}/{c.get("subclass","")} paradigm '
                    f'[{",".join(c.get("tags",[]))}] (Jev p={round(p,3)})'),
        })
        if len(out) >= k:
            break
    return out

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'build'
    if cmd == 'build':
        rows = build_catalogue(force='--force' in sys.argv)
        print(f'catalogue: {len(rows)} entries -> {CAT}')
        # print subclass counts
        from collections import Counter
        cc = Counter((r['category'], r['subclass']) for r in rows)
        for (cat, sid), n in sorted(cc.items()):
            print(f'  {cat}/{sid}: {n}')
    elif cmd == 'show':
        for r in load_catalogue()[:int(sys.argv[2]) if len(sys.argv) > 2 else 3]:
            print(json.dumps(r, ensure_ascii=False, indent=1))
    elif cmd == 'retrieve':
        cid = sys.argv[2]
        slug = re.sub(r'\W+', '_', cid)
        ctx = open(f'data/loop/{slug}/CONTEXT.txt').read()
        src = _src_excerpt_for_ctx(ctx)
        for r in retrieve_refs(ctx, src=src, query_id=cid, k=6):
            print(json.dumps(r, ensure_ascii=False))
    elif cmd == 'signal':  # debug: show signal source for an id
        sidecar = _load_sidecar()
        cases = {c['id']: c for c in _load()}
        c = cases[sys.argv[2]]
        sig, src = case_signal(c, sidecar)
        print(json.dumps({'id': c['id'], 'category': c.get('category'), 'src': src, 'signal_head': sig[:500]}, ensure_ascii=False, indent=1))
