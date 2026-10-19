# Reusable N=1 verifier with LIVE on-chain CONTEXT (no hardcoded constants), no mechanism hint, gpt-5.3-codex.
# NEW confirmation criterion: victim asset decreased AND that asset ended up with the attacker (same-asset gain).
# NEVER reads DeFiHackLabs PoCs/READMEs. Anti-cheat: fund via deal() BEFORE snapshot; no deal() after.
# Usage: BSC_RPC=... .venv/bin/python verify_ctx.py <id> <victim> <block> <outdir>
import re, json, os, sys, subprocess, time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from llm import gen_model
import fetch_source as fs
FORGE = os.path.expanduser('~/.foundry/bin/forge'); CAST = os.path.expanduser('~/.foundry/bin/cast')
MODEL = 'openai/gpt-5.3-codex'; TO = 150
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
RULES = '''Write a Foundry forge-std Test (Solidity) proving an EXTERNAL exploit on BSC of VICTIM.
CONFIRMATION CRITERION (this is what success means):
- The victim must LOSE some asset (a token or native BNB it holds), AND that same asset must end up controlled by the attacker (this test contract or an attacker-controlled address): the attacker's balance of THAT SAME asset must rise by ~the victim's loss.
- You do NOT need to convert the loot into USDT/WBNB profit. Draining the victim into attacker control is success.
Hard PoC rules:
- vm.createSelectFork("bsc", %d); the vulnerable contract VICTIM = %s.
- Fund yourself with deal() (WBNB/USDT/BUSD/native) FIRST, with enough to execute. THEN snapshot: the victim's balance of the asset you will drain AND the attacker's balance of that SAME asset.
- Do NOT hardcode thresholds/fees/balances/prices/token addresses: READ them live (view getters, balanceOf, slot0, getReserves). Source constants may be stale.
- After the snapshot: NO deal(). Attack only, using real on-chain state.
- End with: assertLt(victimAssetAfter, victimAssetBefore);  assertGt(attackerAssetAfter, attackerAssetBefore);  and the attacker-gain asset MUST be the exact same asset the victim lost.
- Reply with ONLY the .sol file contents (no markdown, no prose).
'''
def bogus(src):
    parts = re.split(r'[Bb]efore\s*=|snapshot', src)
    return len(parts) > 1 and 'deal(' in ''.join(parts[1:])
def main():
    cid, victim, block, outdir = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    D = Path(outdir); (D/'test').mkdir(parents=True, exist_ok=True)
    r = fs.get(56, victim); src = fs.main_code('\n'.join(fs.files(r['SourceCode']).values()), r['ContractName'])[:50000]
    # hypothesis (where to look) from pilot_rank: top pick only, no mechanism hint beyond tool output
    hyp = ''
    for c in map(json.loads, open('pilot_rank.jsonl')):
        if c['id'] == cid:
            p = (c.get('picks') or [{}])[0]
            cl = sorted(c.get('claims') or [], key=lambda x:-x.get('conf',0))
            path = (cl[0].get('path') if cl else '') or p.get('why','')
            hyp = f"Target function: {p.get('name','?')}\nPath: {path}"
    t0 = time.time(); ctx = build_context(block, victim, src); print('ctx built', round(time.time()-t0,1),'s', flush=True)
    (D/'CONTEXT.txt').write_text(ctx)
    prompt = (RULES % (block, victim)) + '\nCHAIN=bsc\n\nHypothesis from the auditor tool (where to look):\n' + hyp + '\n\n' + ctx + '\n\nVerified victim source:\n' + src
    (D/'prompt.txt').write_text(prompt); print('prompt chars', len(prompt), flush=True)
    t1 = time.time(); out = gen_model(MODEL, prompt, temp=0.2); print('gen', round(time.time()-t1,1),'s out', len(out), flush=True)
    sol = re.sub(r'^```\w*\n?|```$', '', out.strip(), flags=re.M)
    (D/'test/Attack.t.sol').write_text(sol); (D/'raw_out.txt').write_text(out)
    if bogus(sol): print('WARN anti-cheat: possible deal() after snapshot — inspect', flush=True)
    (D/'foundry.toml').write_text('[profile.default]\nsrc="src"\nout="out"\nlibs=["lib"]\n[rpc_endpoints]\nbsc="${BSC_RPC}"\n')
    if not (D/'lib/forge-std').exists(): subprocess.run([FORGE,'install','foundry-rs/forge-std','--no-git'], cwd=D, capture_output=True)
    (D/'remappings.txt').write_text('forge-std/=lib/forge-std/src/\n')
    print('sol written', len(sol), 'chars', flush=True)
if __name__ == '__main__': main()
