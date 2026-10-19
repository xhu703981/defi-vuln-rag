# Victim address from PoC comments -> Etherscan V2 verified source (cached in data/) -> code field.
import re, json, os, time, threading, urllib.request
from rag_utils import funcs, strip
from llm import jev
from concurrent.futures import ThreadPoolExecutor
CHAIN = {'etherscan.io': 1, 'bscscan.com': 56, 'arbiscan.io': 42161, 'basescan.org': 8453, 'polygonscan.com': 137,
         'optimistic.etherscan.io': 10, 'gnosisscan.io': 100, 'snowtrace.io': 43114, 'ftmscan.com': 250,
         'blastscan.io': 81457, 'lineascan.build': 59144, 'scrollscan.com': 534352, 'sonicscan.org': 146}
LOCK = threading.Lock()
FORK = {'mainnet': 1, 'bsc': 56, 'arbitrum': 42161, 'base': 8453, 'polygon': 137, 'optimism': 10, 'fantom': 250,
        'avalanche': 43114, 'gnosis': 100, 'linea': 59144, 'mantle': 5000, 'blast': 81457, 'sonic': 146}
def get(chain, addr):
    p = f'data/{chain}_{addr.lower()}.json'
    if not os.path.exists(p):
        with LOCK: time.sleep(0.22)  # spacing only (~4.5 req/s), request runs outside the lock
        u = f'https://api.etherscan.io/v2/api?chainid={chain}&module=contract&action=getsourcecode&address={addr}&apikey={os.environ["ETHERSCAN_API_KEY"]}'
        j = json.load(urllib.request.urlopen(u, timeout=30))
        if 'rate limit' in str(j.get('result', '')).lower(): time.sleep(1); return get(chain, addr)
        json.dump(j, open(p, 'w'))
    r = json.load(open(p))['result']
    r = r[0] if isinstance(r, list) and r and r[0].get('SourceCode') else None
    imp = (r or {}).get('Implementation', '')
    if r and r.get('Proxy') == '1' and re.match(r'0x[0-9a-fA-F]{40}$', imp) and imp.lower() != addr.lower():
        return get(chain, imp) or r  # proxy -> implementation
    return r
def files(src):  # single file, or standard-json {{...}} / {...} multi-file
    if src.startswith('{'):
        j = json.loads(src[1:-1] if src.startswith('{{') else src)
        return {k: v['content'] for k, v in j.get('sources', j).items()}
    return {'main': src}
GENERIC = r'(?i)pair|router|factory|^w?eth$|^weth9$|^(erc|bep)20(token)?$|^token$|proxy$'
STD = set('transfer transferFrom approve increaseAllowance decreaseAllowance permit renounceOwnership transferOwnership'.split())
def name(f): return (re.match(r'function\s+(\w+)', f) or [0, ''])[1]
def entry(f): h = f.split('{')[0]; return bool(re.search(r'\b(public|external)\b', h)) and not re.search(r'\b(view|pure)\b', h)
def candidates(src):  # public/external non-view fns + internal fns they call (1 hop)
    A = {name(f): f for f in funcs(src)}
    E = [n for n in A if entry(A[n])]
    return {n: A[n] for n in E + [m for m in A if m not in E and any(re.search(rf'\b{m}\s*\(', A[e]) for e in E)]}
def main_code(src, cname):  # main contract + its non-library inheritance chain
    K = {}
    for m in re.finditer(r'\b(contract|library|interface)\s+(\w+)(?:\s+is\s+([^{]+))?\{', src):
        d, i = 1, m.end()
        while d and i < len(src): d += {'{': 1, '}': -1}.get(src[i], 0); i += 1
        K[m[2]] = (m[1], src[m.start():i], re.findall(r'\w+(?=\s*(?:\(|,|$))', (m[3] or '').strip()))
    todo, seen = [cname], []
    while todo:
        n = todo.pop()
        if n in K and n not in seen and K[n][0] == 'contract': seen.append(n); todo += K[n][2]
    return '\n'.join(K[n][1] for n in seen) or src
SEL = os.environ.get('SEL', 'jev')  # 2026-10-19: default jev picker beats PoC-call-count heuristic on cross-contract victim selection (BeatXswap, InternetToken, Flamincome); no regression
FLASH = r'^(Morpho\w*|Vault|BalancerVault|DPP\w*|DVM|DSP|DODO\w*|Pool|L2Pool|PoolInstance|UniswapV3Pool|PancakeV3Pool|AlgebraPool|FlashLoan\w*)$'
def addrs(c):  # (chain, addr, commented) for every address in the PoC; commented vuln/victim first
    com = re.findall(r'(?im)^.*(?:vuln|victim).*?https?://(?:www\.)?([\w.]+)/address/(0x[0-9a-fA-F]{40})', c['poc'])
    fk = re.findall(r'createSelectFork\(\s*"(\w+)"', c['poc'])
    ch = FORK.get(fk[0].lower().replace('_archive', '')) if fk else None
    ch = ch or next((CHAIN[h] for h, _ in com if h in CHAIN), None)
    out = [(CHAIN.get(h), a.lower(), True) for h, a in com if h in CHAIN]
    if SEL != 'old' and ch:
        seen = {a for _, a, _ in out}
        out += [(ch, a, False) for a in dict.fromkeys(x.lower() for x in re.findall(r'0x[0-9a-fA-F]{40}', c['poc'])) if a not in seen]
    return out[:15]
def victim(c):  # new: prefer non-generic contract whose non-standard fns the PoC calls; old: commented addrs only
    called, best, c['cands'] = set(re.findall(r'\.(\w+)\(', c['poc'])), [], {}
    for ch, addr, com in addrs(c):
        try: r = get(ch, addr)
        except Exception as e: print('ERR', c['id'], e); continue
        if not r: continue
        src = '\n'.join(v for k, v in files(r['SourceCode']).items() if not re.search(r'@openzeppelin|/interfaces?/|/lib/', k, re.I))
        C = candidates(main_code(src, r['ContractName']))
        c['cands'][addr] = {'name': r['ContractName'], 'fns': list(C)}
        hit = sum(n in called and n not in STD for n in C)
        custom = sum(entry(f) and n not in STD for n, f in C.items())
        key = (not re.search(GENERIC, r['ContractName']), hit, com, custom) if SEL != 'old' else (com, not re.search(GENERIC, r['ContractName']), custom)
        best.append((key, addr, C))
    if not best: return {}
    best.sort(key=lambda x: x[0], reverse=True)
    PAIRSTD = STD | set('swap skim sync getReserves token0 token1 balanceOf mint burn'.split())
    keep = [b for b in best if not re.search(FLASH + '|' + GENERIC[4:] + r'|^(BEP20USDT|WBTC|USDT|BUSD|TetherToken|FiatToken\w*|BEP20Token|WBNB|Dai|BscPegToken)$', c['cands'][b[1]]['name'], re.I) and not (re.search(r'(?i)pair', c['cands'][b[1]]['name'])
            and not any(n in called and n not in PAIRSTD for n in b[2]))]  # drop flashloan sources / pairs only used for swap/skim/sync
    best = (keep or best)[:8]
    if SEL == 'jev' and len(best) > 1:  # Jev picks the victim among candidates (uses PoC usage, fine for auditor-provided target)
        crit = {f'a{i}': f"{c['cands'][a]['name']}: PoC-called fns {[n for n in C if n in called][:15]}; fns {list(C)[:30]}" for i, (_, a, C) in enumerate(best)}
        a = jev({'poc_calls': sorted(called)[:200], 'poc': re.sub(r'\n\s*\n', '\n', strip(c['poc']))[:5000]},
                {'victim': {'type': 'choice', 'instructions': 'Which candidate is the vulnerable victim contract (custom logic the exploit abuses), not a generic pair/router/WETH/standard token?', 'criteria': crit}})['victim']
        if a.get('type') == 'choice' and a.get('choice') in crit: best.insert(0, best.pop(int(a['choice'][1:])))
    k, c['vaddr'], C = best[0]; return C
def gated(f): return bool(re.search(r'\b(only\w+|auth|requiresAuth)\b', f.split('{')[0]) or re.search(r'require\(\s*(msg\.sender|_msgSender\(\))\s*==\s*(owner|admin|_owner|governance)', f[:600]))
INH = os.environ.get('INH', '1') == '1'
CHECKQ = [  # (weight ~ mechanism count in analysis/summary.md taxonomy [corpus-level, mild leakage], concrete yes/no question)
    (50, 'spot price', 'Does this function (or a function it calls) compute a price, exchange rate, collateral value, mint/payout/settlement amount from pool reserves (getReserves, slot0, balanceOf of a pair/pool/vault) or a spot DEX quote, instead of a TWAP or external oracle?'),
    (26, 'missing access control', 'Can ANY external address reach this function (no onlyOwner/role/msg.sender check on the path) AND does it move tokens/ETH, mint/burn, change balances, prices, owners, or other critical state?'),
    (24, 'balance manipulation', 'Does its result depend on token balances, reserves or totalSupply that an attacker can change within the same transaction (direct transfer, flashloan, swap, skim/sync/burn on a pair) before calling it?'),
    (22, 'reentrancy/callback', 'Does it send ETH or tokens to msg.sender or a caller-chosen address, or call a caller-supplied contract (ERC777/ERC667 transferAndCall hooks, onERC721Received, flashloan/swap callbacks, low-level call), BEFORE it has finished writing balances, debt, shares or reserves, so a re-entering call sees stale state? Answer no if a nonReentrant/lock modifier covers it.'),
    (6, 'arbitrary call', 'Does it call an address or forward calldata that the caller supplies (arbitrary target.call, user-provided router/token/pool address) without a whitelist?'),
    (7, 'rounding', 'Does it divide (shares, rates, fees) where rounding in the user\'s favor or a truncation to zero can be repeated for profit?'),
    (5, 'donation/share inflation', 'Does it compute shares or exchange rate as totalAssets/balanceOf divided by totalSupply so that a direct donation or first deposit can inflate it?'),
    (2, 'fee-on-transfer/pair burn', 'Does it burn or take fees from a liquidity pair\'s balance, or assume the received amount equals the transferred amount (fee-on-transfer/rebasing tokens)?'),
    (5, 'signature replay', 'Does it accept a signature, permit or meta-transaction whose signed message lacks a nonce, a deadline, or a chainid/contract-bound domain separator, or where the caller can supply the domain separator or signer data?'),
    (2, 'state machine', 'Do permissions or checks get relaxed after a deadline/expiry/state change, or can a step be called twice or out of order (re-initialize, double claim)?')]
THREATQ = [  # threat-model ranking (RANK=threat): one unified attacker-outcome question + one privilege/setup demoter. No function-name keyword special-casing.
    'Assume the caller is an arbitrary anonymous attacker who holds NO owner/admin/minter/whitelisted role and relies only on public on-chain actions available to anyone (their own funds, flashloans, swaps, direct token transfers, deploying helper contracts), within one or more transactions. Could invoking THIS function (alone or as the decisive step, possibly combined with those public actions) cause the victim contract or its users/LPs to suffer a NET OUTFLOW of tokens/ETH/shares, or let the attacker seize critical permissions or assets they should not control? Judge the realistic end economic/authority outcome, not whether the code merely looks unusual.',
    'For that attack to succeed, is a special PRECONDITION strictly REQUIRED that an anonymous attacker cannot arrange on their own: a privileged role (owner/admin/minter), a prior victim approval or victim-initiated interaction, a specific misconfiguration, or admin-only setup? Answer yes only if the attack is outright impossible without it.',
]
def jev_threat(C):  # per function: single attacker-outcome probability, demoted by a privilege/setup probability (+ call-graph context)
    sig = lambda n: re.sub(r'\s+', ' ', C[n].split('{')[0]).strip()[:150]
    Q = {'q0': {'type': 'noul', 'instructions': THREATQ[0]}, 'q1': {'type': 'noul', 'instructions': THREATQ[1]}}
    def one(n):
        st = {'contract_function_signatures': '\n'.join(map(sig, C))[:4000], 'function': C[n][:3000]}
        if os.environ.get('CG', '1') == '1':
            st['called_by'] = [sig(m) for m in C if m != n and re.search(rf'\b{n}\s*\(', C[m])] or ['(none in contract)']
            st['calls'] = {m: re.sub(r'\s+', ' ', C[m])[:400] for m in C if m != n and re.search(rf'\b{m}\s*\(', C[n])} or '(none)'
        a = jev(st, Q); pa = a.get('q0', {}).get('noul', 0); pp = a.get('q1', {}).get('noul', 0)
        w = pa * (1 - 0.6 * pp)  # attacker-outcome prob, demoted (not zeroed) when a privilege/setup precondition is needed
        return {'name': n, 'w': w, 'why': f'attacker net-outflow/seizure p={pa:.2f}; needs-privilege/setup p={pp:.2f}'}
    names = sorted(C, key=lambda n: (not entry(C[n]), -len(C[n])))[:25]
    return 'Function signatures:\n' + '\n'.join(map(sig, C)), sorted(ThreadPoolExecutor(16).map(one, names), key=lambda x: -x['w'])
ATTACK_CLASSES = """DeFi attack classes (sources: OWASP Smart Contract Top 10 2026, SWC Registry, s0sta/DeFiHackLabs attack-class intelligence):
1. Access control / unprotected privileged action: anyone can call a function that moves funds, mints/burns, sets owner/roles, upgrades, or changes critical config with no owner/role/msg.sender check.
2. Price oracle / spot manipulation: prices mints/loans/collateral/swaps from a manipulable spot source (getReserves, slot0, balanceOf of a pool) or single-source oracle with no TWAP/bounds.
3. Reentrancy / unsafe external callback: external call or token transfer to a caller-controlled address BEFORE updating balances/shares/debt (CEI violation, ERC777/677 hooks, onERC721Received, flash/swap callbacks) without a nonReentrant lock.
4. Flash-loan amplified logic: relies on caller balance / pool state / position size that a same-tx flash loan can inflate (vote weight, liquidation thresholds, share accounting).
5. Arithmetic / rounding / precision: share, interest, fee or AMM math where rounding in the attacker's favor, truncation-to-zero, or scaling error can be repeated for profit.
6. Token logic / custom transfer: nonstandard transfer/_transfer with fees, reflection, burn-on-pair or balance edits an attacker can trigger (fee-on-transfer, rebasing, pair burn).
7. Donation / share inflation: shares or exchange rate = assets/supply so a direct donation or first deposit inflates it.
8. Signature / permit replay: accepts a signature/permit/meta-tx missing nonce, deadline, or chainid/contract-bound domain, or caller supplies signer/domain data.
9. Unchecked / arbitrary external call: calls a caller-supplied target/calldata or forwards value without a whitelist, or ignores a return value causing inconsistent state.
10. Business-logic / accounting flaw: breaks intended economic rules in lending/vault/reward/liquidation (double claim, mispriced redeem, reward over-accrual) even when low-level checks pass.
11. Infinite / unauthorized mint: a path lets an attacker mint or obtain tokens/shares without paying corresponding value (fake-callback mint, unprotected mint).
12. State-machine / initialization: initialize/re-init or a step callable out of order, or a check relaxed after expiry/state change (double init, double claim)."""
def jev_aclabel(C):  # RANK=aclabel: access-control two-part label. risk = p_sensitive * (1 - p_gated). No name keywords.
    sig = lambda n: re.sub(r'\s+', ' ', C[n].split('{')[0]).strip()[:150]
    qa = ('Does invoking THIS function transfer out tokens/ETH, mint or burn tokens/shares, change ownership/roles/authorizations, or change critical configuration (prices, fees, addresses, limits, pause)? Answer yes if it performs any such sensitive privileged effect.')
    qg = ('Is the CALLER appropriately restricted so that an arbitrary anonymous address CANNOT reach this effect: an onlyOwner/role/whitelist modifier, an owner/admin/authorized require check, or an equivalent that binds the effect to the caller\'s own balance/position (e.g. a plain ERC20 transfer only moves the caller\'s own funds)? Answer yes if such a restriction effectively protects it; answer no if any anonymous caller can trigger the sensitive effect on other users\' or the contract\'s assets/state.')
    Q = {'sensitive': {'type': 'noul', 'instructions': qa}, 'gated': {'type': 'noul', 'instructions': qg}}
    def one(n):
        st = {'contract_function_signatures': '\n'.join(map(sig, C))[:4000], 'function': C[n][:3000]}
        if os.environ.get('CG', '1') == '1':
            st['called_by'] = [sig(m) for m in C if m != n and re.search(rf'\b{n}\s*\(', C[m])] or ['(none in contract)']
            st['calls'] = {m: re.sub(r'\s+', ' ', C[m])[:400] for m in C if m != n and re.search(rf'\b{m}\s*\(', C[n])} or '(none)'
        a = jev(st, Q); ps = a.get('sensitive', {}).get('noul', 0); pg = a.get('gated', {}).get('noul', 0)
        w = ps * (1 - pg)
        return {'name': n, 'w': w, 'why': f'sensitive p={ps:.2f}; caller-gated p={pg:.2f}; risk={w:.2f}'}
    names = sorted(C, key=lambda n: (not entry(C[n]), -len(C[n])))[:25]
    return 'Function signatures:\n' + '\n'.join(map(sig, C)), sorted(ThreadPoolExecutor(16).map(one, names), key=lambda x: -x['w'])
def jev_label(C):  # RANK=label: per-function single yes/no risk label against the attack-class taxonomy (no ranking, no name keywords)
    sig = lambda n: re.sub(r'\s+', ' ', C[n].split('{')[0]).strip()[:150]
    q = ('Considering the DeFi attack classes listed below, does THIS function contain a risk that an arbitrary ANONYMOUS attacker '
         '(holding no owner/admin/minter/whitelisted role, using only public actions available to anyone such as their own funds, flashloans, swaps, direct transfers) '
         'could exploit to cause the victim contract or its users a NET LOSS of funds or a seizure of assets/permissions? '
         'Answer yes only if a concrete class below plausibly applies to this function (alone or as the decisive step).\n\n' + ATTACK_CLASSES)
    Q = {'risk': {'type': 'noul', 'instructions': q}}
    def one(n):
        st = {'contract_function_signatures': '\n'.join(map(sig, C))[:4000], 'function': C[n][:3000]}
        if os.environ.get('CG', '1') == '1':
            st['called_by'] = [sig(m) for m in C if m != n and re.search(rf'\b{n}\s*\(', C[m])] or ['(none in contract)']
            st['calls'] = {m: re.sub(r'\s+', ' ', C[m])[:400] for m in C if m != n and re.search(rf'\b{m}\s*\(', C[n])} or '(none)'
        p = jev(st, Q).get('risk', {}).get('noul', 0)
        return {'name': n, 'w': p, 'why': f'risk p={p:.2f}'}
    names = sorted(C, key=lambda n: (not entry(C[n]), -len(C[n])))[:25]
    return 'Function signatures:\n' + '\n'.join(map(sig, C)), sorted(ThreadPoolExecutor(16).map(one, names), key=lambda x: -x['w'])
def jev_check(C):  # per function: concrete checklist noul questions weighted by mechanism frequency (+ call-graph context)
    sig = lambda n: re.sub(r'\s+', ' ', C[n].split('{')[0]).strip()[:150]
    Q = {f'q{i}': {'type': 'noul', 'instructions': q} for i, (_, _, q) in enumerate(CHECKQ)}
    def one(n):
        st = {'contract_function_signatures': '\n'.join(map(sig, C))[:4000], 'function': C[n][:3000]}
        if os.environ.get('CG', '1') == '1':
            st['called_by'] = [sig(m) for m in C if m != n and re.search(rf'\b{n}\s*\(', C[m])] or ['(none in contract)']
            st['calls'] = {m: re.sub(r'\s+', ' ', C[m])[:400] for m in C if m != n and re.search(rf'\b{m}\s*\(', C[n])} or '(none)'
        a = jev(st, Q); P = [a.get(f'q{i}', {}).get('noul', 0) for i in range(len(CHECKQ))]
        top = sorted([i for i in range(len(P)) if P[i] >= .45], key=lambda i: -P[i])[:4]  # reason: every likely mechanism, by probability
        return {'name': n, 'w': sum(p * w for p, (w, _, _) in zip(P, CHECKQ)), 'why': '; '.join(f'{CHECKQ[i][1]} (p={P[i]:.2f})' for i in top) or 'no checklist hit'}
    names = sorted(C, key=lambda n: (not entry(C[n]), -len(C[n])))[:25]
    return 'Function signatures:\n' + '\n'.join(map(sig, C)), sorted(ThreadPoolExecutor(16).map(one, names), key=lambda x: -x['w'])
def index(c):  # Jev checklist ranking, internal fns inherit caller rank, permission-gated last
    C = victim(c)
    if not C: return c.update(funcs=funcs(c['poc'])[:8], fnames=[], weights=[0] * 8, src='poc')
    RANKMODE = os.environ.get('RANK', 'check')
    _scorer = {'threat': jev_threat, 'label': jev_label, 'aclabel': jev_aclabel}.get(RANKMODE, jev_check)
    c['summary'], r = _scorer(C); c['top_w'] = max([x['w'] for x in r if not gated(C[x['name']])] or [0])
    if RANKMODE in ('label', 'aclabel'): c['labels'] = {x['name']: round(x['w'], 4) for x in r}
    sc, why = {x['name']: -k for k, x in enumerate(r)}, {x['name']: x['why'] for x in r}
    rk = [{'name': n, 'why': why[n]} for n in sorted(sc, key=lambda n: -sc[n]) if not re.search(r'\b(view|pure)\b', C[n].split('{')[0])]
    pos = {x['name']: k for k, x in enumerate(rk)}  # internal fns inherit rank from their entry callers
    for x in rk:
        cl = [e for e in pos if e != x['name'] and entry(C[e]) and re.search(rf"\b{x['name']}\s*\(", C[e])]
        if INH and not entry(C[x['name']]) and cl and min(pos[e] for e in cl) + 1.5 < pos[x['name']]:
            e = min(cl, key=pos.get); x['rank'] = pos[e] + 1.5; x['why'] += f' (internal, called by {e})'
    rk = sorted(rk, key=lambda x: x.get('rank', pos[x['name']])) if RANKMODE == 'threat' else sorted(rk, key=lambda x: (gated(C[x['name']]), x.get('rank', pos[x['name']])))  # threat: privilege via weight; check: permission-gated last
    byrank = list(dict.fromkeys([x['name'] for x in rk] + sorted(C, key=lambda n: -len(C[n]))))
    ent = [n for n in byrank if entry(C[n])][:12]  # <=12 entry fns + internal helpers they call (total <=20)
    order = (ent + [n for n in byrank if n not in ent and not entry(C[n]) and any(re.search(rf'\b{n}\s*\(', C[e]) for e in ent)])[:20]
    order = order or byrank[:12]
    w = {x['name']: max(0, 1 - k / 6) for k, x in enumerate(rk)} if RANKMODE == 'threat' else {x['name']: 0 if gated(C[x['name']]) else max(0, 1 - k / 6) for k, x in enumerate(rk)}  # top ranks -> weight up to 1
    c['allnames'] = list(C)
    c.update(funcs=[C[n][:3000] for n in order], fnames=order, weights=[w.get(n, 0) for n in order],
             picks=rk[:3], src='victim')
if __name__ == '__main__':
    cases = [json.loads(l) for l in open('cases.jsonl')]
    for c in cases: c.setdefault('poc', c['code'])
    sub = set(open(os.environ['SUBSET']).read().split('\n')) if os.environ.get('SUBSET') else None
    list(ThreadPoolExecutor(16).map(index, [c for c in cases if not sub or c['id'] in sub]))
    for c in cases: c['code'] = '\n'.join(c['funcs'])
    if sub: cases = [c for c in cases if c['id'] in sub]
    with open(os.environ.get('OUT', 'cases.jsonl'), 'w') as w:
        for c in cases: w.write(json.dumps(c) + '\n')
    print('victim source:', sum(c['src'] == 'victim' for c in cases), '/', len(cases), 'funcs:', sum(len(c['funcs']) for c in cases if c['src'] == 'victim'))
