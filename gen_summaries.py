# Generate structured audit summaries for cases missing a `summary`, into a SIDECAR file.
# HARD CONSTRAINTS: cases.jsonl is READ-ONLY (never written). Only VERIFIED Etherscan source
# (via fetch_source.victim, same as pipeline) + the existing root_cause label are fed to the LLM.
# PoC/attack-tx/DeFiHackLabs details are NEVER fed to the generator. Secrets never printed.
import json, os, re, sys, hashlib
import fetch_source as fs
from llm import gen_model
from concurrent.futures import ThreadPoolExecutor

CASES = 'cases.jsonl'
SIDE = 'data/index/summaries_generated.jsonl'
MODEL = os.environ.get('SUM_MODEL', 'deepseek/deepseek-v3.2')
os.makedirs('data/index', exist_ok=True)

CHECKLIST = """1. Valuation/payout/mint uses spot price, pool reserves or balanceOf without TWAP/bounds?
2. External call or callback (ETH send, token/NFT/ERC777 hooks, flashloan, unlock) before state update / no reentrancy guard; OR callback entry points not validating msg.sender?
3. Inputs manipulable within one tx via flashloan (prices, balances, totalSupply, rewards)?
4. Missing access control on fund-moving functions, setters, init/initialize, mint/burn or arbitrary-call functions?
5. Direct token transfer to a pair + skim/sync, or token transfer logic that deducts/burns from the pair's balance?
6. Shares/exchange rate computed from balanceOf or totalAssets?
7. Permissionless public/external op-like functions with no caller restriction?
8. User-supplied target address or calldata / unchecked return values?
9. Inconsistent checks across similar/sibling functions (one path validates, another does not; a lock on one entrypoint not covering a sibling state-changing entrypoint)?
10. Accounting inconsistency (state updated in one place but not another; order of pay-vs-update)?
11. Rounding direction, integer truncation/unsafe casting, divide-by-zero or empty-state edge cases?
12. Fee-on-transfer / rebasing / reflection token assumptions; missing slippage/deadline on swaps?
13. Permissions relaxed after expiry/timeout/state change?
14. Other: signature replay, re-initializable proxy?"""

PROMPT = """You are a smart-contract auditor. Below is the VERIFIED on-chain source (selected functions) of a contract, plus a one-line root_cause label for a known issue class. Write a GENERIC structured audit/mechanism summary of THIS contract, in the exact shape used by our index.

Output format (plain text, no markdown headers):
- First, 1-2 prose paragraphs describing what the contract does: the fund flow (deposits/withdrawals, where ETH/tokens go), the price/valuation sources it uses, its access-control model, and its state machine/lifecycle.
- Then answer the following numbered checklist. For each item answer with `Yes:`/`NO`/`NA` followed by a brief, concrete evidence note referencing the actual function/variable names in the source. Keep each answer to 1-3 sentences. Be mechanism-specific and honest.

Checklist:
{checklist}

Rules: Describe only what the provided source shows. Do NOT invent an attack narrative, transaction, or step-by-step exploit. Do NOT reference any address, attacker, or incident. The root_cause label is a hint for which mechanism class to scrutinize, not something to restate as an attack. Keep the whole summary under ~550 words.

root_cause hint: {root_cause}

VERIFIED SOURCE:
{source}
"""

def build_source(C):
    # join verified-source functions, cap for cost
    parts = []
    total = 0
    for n, body in C.items():
        b = body[:3000]
        if total + len(b) > 16000:
            break
        parts.append(b)
        total += len(b)
    return '\n\n'.join(parts)

# Map free-text chain hints in PoC comments -> foundry fork name used by fetch_source.FORK
_CHAIN_HINT = [
    (r'(?i)\b(bnb chain|binance|bsc)\b', 'bsc'),
    (r'(?i)\bpolygon\b', 'polygon'),
    (r'(?i)\barbitrum\b', 'arbitrum'),
    (r'(?i)\bbase\b', 'base'),
    (r'(?i)\boptimism\b', 'optimism'),
    (r'(?i)\bfantom\b', 'fantom'),
    (r'(?i)\bavalanche\b', 'avalanche'),
    (r'(?i)\bgnosis\b', 'gnosis'),
    (r'(?i)\bmantle\b', 'mantle'),
    (r'(?i)\b(ethereum|mainnet)\b', 'mainnet'),
]

def _normalize_poc(poc):
    """Rewrite createSelectFork(\"https://...\") to a named fork so fetch_source.addrs can resolve chain.
    Infer the chain from free-text comments (Polygon / BNB Chain / ...). Leave named forks alone."""
    m = re.search(r'createSelectFork\(\s*"([^"]+)"', poc)
    if m and m.group(1).startswith('http'):
        chain = None
        for pat, name in _CHAIN_HINT:
            if re.search(pat, poc[:1500]):
                chain = name; break
        if chain:
            poc = poc[:m.start(1)] + chain + poc[m.end(1):]
    elif not m:
        # no fork at all: inject a named one from comments so addrs() has a chain
        chain = None
        for pat, name in _CHAIN_HINT:
            if re.search(pat, poc[:1500]):
                chain = name; break
        if chain:
            poc = f'// injected fork hint\nfunction __fake() public {{ vm.createSelectFork("{chain}"); }}\n' + poc
    return poc

def resolve_C(c):
    poc = _normalize_poc(c.get('poc') or c.get('code', ''))
    c = dict(c); c['poc'] = poc
    try:
        C = fs.victim(c)
    except Exception as e:
        return {}, f'ERR victim: {str(e)[:80]}'
    return C, (c.get('vaddr') or '')

def gen_one(c):
    cid = c['id']
    C, vaddr = resolve_C(c)
    if not C:
        return {'id': cid, 'status': 'no_source', 'vaddr': vaddr}
    src = build_source(C)
    prompt = PROMPT.format(checklist=CHECKLIST, root_cause=(c.get('root_cause') or '')[:600], source=src)
    try:
        txt = gen_model(MODEL, prompt, temp=0)
    except Exception as e:
        return {'id': cid, 'status': 'gen_err', 'err': str(e)[:100]}
    # fetch usage from cache file
    key = f"data/llm/{hashlib.sha1((MODEL+prompt).encode()).hexdigest()}.json"
    usage = {}
    try:
        usage = json.load(open(key)).get('usage') or {}
    except Exception:
        pass
    return {'id': cid, 'status': 'ok', 'summary': txt.strip(), 'model': MODEL,
            'vaddr': c.get('vaddr'), 'nfuncs': len(C), 'usage': usage}

def load_done():
    done = {}
    if os.path.exists(SIDE):
        for l in open(SIDE):
            l = l.strip()
            if not l: continue
            o = json.loads(l); done[o['id']] = o
    return done

def main():
    from concurrent.futures import as_completed
    rows = [json.loads(l) for l in open(CASES)]
    miss = [c for c in rows if not (c.get('summary') or '').strip()]
    # unique by id (cases.jsonl can have duplicate ids)
    seen_ids = set(); uniq = []
    for c in miss:
        if c['id'] in seen_ids: continue
        seen_ids.add(c['id']); uniq.append(c)
    miss = uniq
    limit = os.environ.get('LIMIT')
    only = os.environ.get('ONLY')
    done = load_done()
    if only:
        ids = set(only.split(','))
        todo = [c for c in miss if c['id'] in ids and c['id'] not in done]
    else:
        todo = [c for c in miss if c['id'] not in done]
    if limit:
        todo = todo[:int(limit)]
    workers = int(os.environ.get('WORKERS', '4'))
    print(f'missing={len(miss)} already_done={len(done)} todo_this_run={len(todo)} workers={workers}', file=sys.stderr, flush=True)
    ok = nosrc = errs = 0
    pt = ct = 0
    cost = 0.0
    nosrc_ids = []; err_list = []
    with ThreadPoolExecutor(workers) as ex, open(SIDE, 'a') as f:
        futs = {ex.submit(gen_one, c): c['id'] for c in todo}
        for i, fut in enumerate(as_completed(futs), 1):
            try:
                r = fut.result()
            except Exception as e:
                r = {'id': futs[fut], 'status': 'gen_err', 'err': str(e)[:100]}
            if r['status'] == 'ok':
                f.write(json.dumps({'id': r['id'], 'summary': r['summary'], 'model': r['model'],
                                    'vaddr': r.get('vaddr'), 'nfuncs': r.get('nfuncs')}, ensure_ascii=False) + '\n')
                f.flush(); ok += 1
                u = r.get('usage') or {}
                pt += u.get('prompt_tokens', 0) or 0
                ct += u.get('completion_tokens', 0) or 0
                cost += u.get('cost', 0) or 0
            elif r['status'] == 'no_source':
                nosrc += 1; nosrc_ids.append(r['id'])
            else:
                errs += 1; err_list.append(r)
            if i % 5 == 0 or i == len(todo):
                print(f'progress {i}/{len(todo)} ok={ok} no_source={nosrc} err={errs}', file=sys.stderr, flush=True)
    print(f'RESULT ok={ok} no_source={nosrc} err={errs} prompt_tok={pt} completion_tok={ct} usd_cost={cost:.5f}', file=sys.stderr, flush=True)
    if nosrc_ids:
        print('NO_SOURCE ids:', ','.join(nosrc_ids), file=sys.stderr, flush=True)
    if err_list:
        print('ERR:', json.dumps(err_list)[:600], file=sys.stderr, flush=True)

if __name__ == '__main__':
    main()
