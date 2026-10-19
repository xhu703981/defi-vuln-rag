# Live on-chain context helpers for loop.py: cast at fork block + build_context.
# Mutable values ALWAYS read live; never trust source constants. RPC/keys never printed.
# Structural-only hints (entry signatures, discovered address roles, live reads). NO attack-path / vuln-class leakage.
import re, json, os, sys, subprocess, time
from pathlib import Path
import fetch_source as fs
CAST = os.path.expanduser('~/.foundry/bin/cast')
WBNB, USDT, BUSD = '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c', '0x55d398326f99059fF775485246999027B3197955', '0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56'
KNOWN = {WBNB.lower(): 'WBNB', USDT.lower(): 'USDT', BUSD.lower(): 'BUSD'}
ZERO = '0x' + '0' * 40
def redact(s): return re.sub(r'https?://\S+', '<RPC>', s or '')
def cast(block, *args, timeout=30):
    try:
        r = subprocess.run([CAST, *[str(a) for a in args], '--block', str(block), '--rpc-url', os.environ['BSC_RPC']],
                           capture_output=True, text=True, timeout=timeout)
        return (r.stdout.strip() or ('ERR:' + redact(r.stderr.strip())[:120]))
    except Exception as e: return 'ERR:' + str(e)[:80]
def is_addr(s): return bool(re.match(r'0x[0-9a-fA-F]{40}$', (s or '').strip()))
def ok(v): return bool(v) and not v.startswith('ERR')
def first(v): return (v or '').split()[0]

def has_code(block, addr):
    c = cast(block, 'code', addr)
    return ok(c) and c not in ('0x', '0x0')

def probe_token(block, addr):
    out = {}
    for sig, key in [('symbol()(string)','symbol'),('decimals()(uint8)','decimals'),('totalSupply()(uint256)','totalSupply')]:
        v = cast(block,'call',addr,sig)
        if ok(v): out[key] = v
    return out
def probe_pool(block, addr):
    out = {}
    for sig, key in [('token0()(address)','token0'),('token1()(address)','token1'),
                     ('getReserves()(uint112,uint112,uint32)','getReserves'),
                     ('slot0()(uint160,int24,uint16,uint16,uint16,uint8,bool)','slot0'),
                     ('fee()(uint24)','fee'),('tickSpacing()(int24)','tickSpacing'),('liquidity()(uint128)','liquidity')]:
        v = cast(block,'call',addr,sig)
        if ok(v): out[key] = v.replace('\n',' | ')
    return out

def _label(addr, roles):
    a = (addr or '').lower()
    return roles.get(a) or KNOWN.get(a) or ''

def harvest_live_addrs(block, victim, src, roles):
    """Call every zero-arg public/external getter + public var (ANY type, incl. structs) and
    extract address-typed words from the raw returndata. Catches struct members (e.g. poolData
    mainPool/token0Pool), custom-typed public addresses (IERC20 public baseToken) and plain
    address getters (TARGET_POOL, treasuryWallet) that primitive-typed probing misses.
    Returns {addr_lower: getter_name}. Structural only - just which contracts are wired in."""
    names = []
    for m in re.finditer(r'function\s+(\w+)\s*\(\s*\)\s*(?:public|external)[^;{]*?\bview\b', src):
        if m.group(1) not in names: names.append(m.group(1))
    for m in re.finditer(r'\b[A-Za-z_][\w\.]*(?:\[\])?\s+public\s+(?:constant\s+|immutable\s+)?(\w+)\s*[=;]', src):
        if m.group(1) not in names: names.append(m.group(1))
    found = {}
    for nm in names:
        raw = cast(block, 'call', victim, f'{nm}()')
        if not ok(raw): continue
        h = raw.replace('0x', '').replace('\n', '')
        if len(h) % 64: continue  # not a clean word-aligned ABI blob
        for i in range(0, len(h) - 63, 64):
            w = h[i:i+64]
            if w[:24] == '0' * 24 and w[24:] != '0' * 40:  # left-padded 20-byte word
                a = ('0x' + w[24:]).lower()
                found.setdefault(a, nm)
    # keep only real contracts (filters uint false-positives that look address-shaped)
    out = {}
    for a, nm in found.items():
        if a in (victim.lower(), ZERO): continue
        if has_code(block, a):
            out[a] = nm
            roles.setdefault(a, nm)
    return out

def build_context(block, victim, src):
    L = [f'ON-CHAIN CONTEXT at BSC block {block} (the fork block), all values read LIVE via `cast` at that block. Addresses + numbers only; mutable values are LIVE - do NOT trust source defaults/constants.']

    # roles from named address constants in source:  NAME = 0x...
    roles = {}
    for nm, a in re.findall(r'(\w+)\s*=\s*(?:I?\w*\(\s*)?(0x[0-9a-fA-F]{40})', src):
        roles.setdefault(a.lower(), nm)
    for a, nm in KNOWN.items(): roles.setdefault(a, nm)

    src_addrs = {a.lower() for a in re.findall(r'0x[0-9a-fA-F]{40}', src)}
    src_addrs -= {victim.lower(), ZERO}

    # LIVE: follow address-returning getters / struct members into the candidate set
    live_addrs = harvest_live_addrs(block, victim, src, roles)

    cand = set(src_addrs) | set(live_addrs) | {WBNB.lower(), USDT.lower()}
    tok_info, pool_info = {}, {}
    def classify(a):
        if a in tok_info or a in pool_info: return
        pl = probe_pool(block, a)
        if 'token0' in pl and 'token1' in pl:
            pool_info[a] = pl
        else:
            tk = probe_token(block, a)
            if tk: tok_info[a] = tk
    for a in cand: classify(a)
    # backfill: any pool's token0/token1 should appear in TOKENS too
    for a, pl in list(pool_info.items()):
        for k in ('token0', 'token1'):
            t = first(pl.get(k, '')).lower()
            if is_addr(t) and t not in tok_info and t not in pool_info and t != victim.lower():
                tk = probe_token(block, t)
                if tk: tok_info[t] = tk

    L.append('\nTOKENS:')
    for a, tk in sorted(tok_info.items(), key=lambda x: _label(x[0], roles), reverse=True):
        role = _label(a, roles); dec = first(tk.get('decimals','?'))
        sym = tk.get('symbol','').strip('"'); ts = tk.get('totalSupply','')
        L.append(f'- {role or sym or "token"}  {a}  decimals={dec}' + (f'  totalSupply={ts}' if ts else ''))

    L.append(f'\nVICTIM  {victim}')
    nb = cast(block,'balance',victim); L.append(f'  native(BNB) balance = {nb}')
    for a, tk in tok_info.items():
        bal = cast(block,'call',a,'balanceOf(address)(uint256)',victim)
        if ok(bal) and first(bal) not in ('0','0x0'):
            L.append(f'  holds {_label(a,roles) or tk.get("symbol","token").strip(chr(34))} ({a}) = {bal}')
    vtok = probe_token(block, victim)
    if vtok: L.append('  victim itself is a token: ' + json.dumps(vtok))
    vpool = probe_pool(block, victim)
    if 'token0' in vpool: L.append('  victim exposes pool getters: ' + json.dumps(vpool))

    params = []
    for ty, nm in re.findall(r'\b(address|uint\d*|int\d*|bool|bytes\d*)\s+public\s+(?:constant\s+|immutable\s+)?(\w+)\s*(?:=|;)', src):
        rt = 'uint256' if ty=='uint' else ('int256' if ty=='int' else ty)
        v = cast(block,'call',victim,f'{nm}()({rt})')
        if ok(v): params.append((nm, v))
    for nm, rets in re.findall(r'function\s+(\w+)\s*\(\s*\)\s*(?:public|external)[^;{]*?\bview\b[^;{]*?returns\s*\(([^)]*)\)', src):
        if any(nm==p[0] for p in params): continue
        rt = rets.strip(); sig = f'{nm}()({rt})' if rt else f'{nm}()'
        v = cast(block,'call',victim,sig)
        if ok(v): params.append((nm, v.replace('\n',' | ')))
    if params:
        L.append('\nLIVE victim parameters (read on-chain NOW - authoritative; source defaults are stale):')
        for nm, v in params:
            tgt = ('  <-- address; see roles below' if is_addr(first(v)) else '')
            L.append(f'  {nm}() = {v}{tgt}')

    non_pool_roles = [a for a in roles if a not in tok_info and a not in pool_info and a not in KNOWN
                      and a != victim.lower() and (a in src_addrs or a in live_addrs)]
    if pool_info or non_pool_roles:
        L.append('\nRELATED CONTRACTS (discovered live from source constants + address-returning getters; verify live):')
    for a, pl in pool_info.items():
        role = _label(a, roles) or 'pool'
        via = f' (via {live_addrs[a]}())' if a in live_addrs else ''
        t0, t1 = first(pl.get('token0','')).lower(), first(pl.get('token1','')).lower()
        line = [f'- {role}  {a}{via}', f'token0={_label(t0,roles) or t0} token1={_label(t1,roles) or t1}']
        for k in ('fee','tickSpacing','liquidity','slot0','getReserves'):
            if k in pl: line.append(f'{k}={pl[k]}')
        depth = []
        for t in (t0, t1):
            if is_addr(t):
                b = cast(block,'call',t,'balanceOf(address)(uint256)',a)
                if ok(b): depth.append(f'{_label(t,roles) or t[:8]}={first(b)}')
        if depth: line.append('poolBalances[' + ', '.join(depth) + ']')
        if 'getReserves' in pl:
            try:
                r0 = int(first(pl['getReserves']))
                if r0 < 10**15: line.append('(V2 pair looks near-empty - verify before relying on it)')
            except Exception: pass
        L.append('  ' + '  '.join(line))
    for a in non_pool_roles:
        nm = roles[a]
        via = f' (via {live_addrs[a]}())' if a in live_addrs else ''
        extra = ''
        if a in tok_info:
            tk = tok_info[a]; extra = f'  ERC20 decimals={first(tk.get("decimals","?"))}'
        nbnb = cast(block,'balance',a)
        vbal = cast(block,'call',USDT,'balanceOf(address)(uint256)',a)
        bal_s = f'  USDT={first(vbal)}' if ok(vbal) and first(vbal) not in ('0','0x0') else ''
        L.append(f'- {nm}  {a}{via}  native(BNB)={nbnb}{bal_s}{extra}')

    # Entry points WITH signatures + receive/fallback (structural; no attack hints)
    entries, special = [], []
    SKIP = set('renounceOwnership transferOwnership'.split())
    for m in re.finditer(r'function\s+(\w+)\s*\(([^)]*)\)\s*([^;{]*?)\{', src):
        h = m.group(3)
        if re.search(r'\b(public|external)\b', h) and not re.search(r'\b(view|pure)\b', h) and m.group(1) not in SKIP:
            args = re.sub(r'\s+', ' ', m.group(2).strip())
            pay = ' payable' if re.search(r'\bpayable\b', h) else ''
            sig = f'{m.group(1)}({args}){pay}'
            if sig not in entries: entries.append(sig)
    if re.search(r'\breceive\s*\(\s*\)\s*external\s+payable', src): special.append('receive() payable')
    if re.search(r'\bfallback\s*\(', src): special.append('fallback()' + (' payable' if re.search(r'fallback\s*\([^)]*\)\s*external\s+payable', src) else ''))
    if entries or special:
        L.append('\nVICTIM external/public state-changing entry points (full signatures; decide for yourself which matter):')
        for s in entries: L.append('  ' + s)
        for s in special: L.append('  ' + s + '  <-- raw value receiver')

    L.append('\nBSC generics: WBNB '+WBNB+', USDT '+USDT+', BUSD '+BUSD+'.')
    L.append('PancakeV2 pair: swap(uint,uint,address,bytes) + callback pancakeCall(address,uint,uint,bytes). PancakeV3 pool: swap(recipient,zeroForOne,amountSpecified,sqrtPriceLimitX96,data) + callback pancakeV3SwapCallback(int256,int256,bytes). MIN_SQRT_RATIO+1=4295128740; MAX_SQRT_RATIO-1=1461446703485210103287273052203988822378723970341.')
    L.append('REMINDER: in any Foundry test read mutable params live (e.g. victim.minDepositUSDT(), pool.slot0(), balanceOf) instead of hardcoding; fund via deal() in setUp only.')
    return '\n'.join(L)
