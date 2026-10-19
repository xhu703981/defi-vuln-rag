# Live on-chain context helpers for loop.py: cast at fork block + build_context.
# Mutable values ALWAYS read live; never trust source constants. RPC/keys never printed.
import re, json, os, sys, subprocess, time
from pathlib import Path
import fetch_source as fs
CAST = os.path.expanduser('~/.foundry/bin/cast')
WBNB, USDT, BUSD = '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c', '0x55d398326f99059fF775485246999027B3197955', '0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56'
def redact(s): return re.sub(r'https?://\S+', '<RPC>', s or '')
def cast(block, *args, timeout=30):
    try:
        r = subprocess.run([CAST, *[str(a) for a in args], '--block', str(block), '--rpc-url', os.environ['BSC_RPC']],
                           capture_output=True, text=True, timeout=timeout)
        return (r.stdout.strip() or ('ERR:' + redact(r.stderr.strip())[:120])) if True else ''
    except Exception as e: return 'ERR:' + str(e)[:80]
def is_addr(s): return bool(re.match(r'0x[0-9a-fA-F]{40}$', (s or '').strip()))
def probe_token(block, addr):
    out = {}
    for sig, key in [('symbol()(string)','symbol'),('decimals()(uint8)','decimals'),('totalSupply()(uint256)','totalSupply')]:
        v = cast(block,'call',addr,sig)
        if v and not v.startswith('ERR'): out[key] = v
    return out
def probe_pool(block, addr):
    out = {}
    for sig, key in [('token0()(address)','token0'),('token1()(address)','token1'),
                     ('getReserves()(uint112,uint112,uint32)','getReserves'),
                     ('slot0()(uint160,int24,uint16,uint16,uint16,uint8,bool)','slot0'),
                     ('fee()(uint24)','fee'),('tickSpacing()(int24)','tickSpacing'),('liquidity()(uint128)','liquidity')]:
        v = cast(block,'call',addr,sig)
        if v and not v.startswith('ERR'): out[key] = v.replace('\n',' | ')
    return out
def build_context(block, victim, src):
    lines = [f'ON-CHAIN CONTEXT at BSC block {block} (fork block), all read LIVE via cast. Addresses + numbers only; mutable values read live, do NOT trust source constants.']
    # victim self
    lines.append(f'\nVICTIM {victim}')
    nb = cast(block,'balance',victim); lines.append(f'  native(BNB) balance = {nb}')
    for t,nm in [(WBNB,'WBNB'),(USDT,'USDT'),(BUSD,'BUSD')]:
        v = cast(block,'call',t,'balanceOf(address)(uint256)',victim)
        if v and not v.startswith('ERR') and v.split()[0] not in ('0','0x0'): lines.append(f'  holds {nm} = {v}')
    vtok = probe_token(block, victim); vpool = probe_pool(block, victim)
    if vtok: lines.append('  victim is a token: ' + json.dumps(vtok))
    if vpool: lines.append('  victim exposes pool getters: ' + json.dumps(vpool))
    # no-arg public/external view getters in source -> call them live
    getters = re.findall(r'function\s+(\w+)\s*\(\s*\)\s*(?:public|external)[^;{]*?\bview\b[^;{]*?returns\s*\(([^)]*)\)', src)
    discovered = set()
    glines = []
    for name, rets in getters[:24]:
        rt = rets.strip().split()[0] if rets.strip() else ''
        sig = f'{name}()({rt})' if rt else f'{name}()'
        v = cast(block,'call',victim,sig)
        if v and not v.startswith('ERR'):
            glines.append(f'  {name}() = {v}')
            if is_addr(v): discovered.add(v.strip().lower())
    if glines: lines.append('  live view getters:'); lines += glines
    # also pull addresses hardcoded in source (if any) and chase
    for a in set(re.findall(r'0x[0-9a-fA-F]{40}', src)): discovered.add(a.lower())
    discovered -= {victim.lower(), WBNB.lower(), USDT.lower(), BUSD.lower(), '0x'+'0'*40}
    for a in list(discovered)[:8]:
        tk = probe_token(block, a); pl = {k:v for k,v in probe_pool(block,a).items() if k in ('token0','token1','getReserves','slot0','fee')}
        bal = cast(block,'call',a if False else a,'balanceOf(address)(uint256)',victim) if False else None
        nbnb = cast(block,'balance',a)
        info = {}
        if tk: info['token'] = tk
        if pl: info['pool'] = pl
        info['native'] = nbnb
        lines.append(f'\nDEP {a}: ' + json.dumps(info))
    lines.append('\nCommon BSC: WBNB '+WBNB+', USDT '+USDT+', BUSD '+BUSD+'. PancakeV2 pair swap(uint,uint,address,bytes)+pancakeCall; V3 pool swap(...)+pancakeV3SwapCallback. MIN_SQRT+1=4295128740; MAX_SQRT-1=1461446703485210103287273052203988822378723970341.')
    return '\n'.join(lines)
