# Grok Build-style role-split exploit loop: Planner -> Coder -> run_forge -> Reflector (-> replan),
# then after MAXR rounds a FINAL DECISION model reviews all iterations and returns
# genuinely_cannot | should_continue. Does NOT auto-start a second cycle (reports only).
#
# Roles mirror Grok Build's Goal Harness (Planner writes a persistent plan.md; Strategist/Coder
# executes it; a reviewer judges completion). Layered prompt templates live in prompts/*.md;
# per-case runtime artifacts (plan.md, reflect.md, history.md, final.md) live under
# data/loop/<case>/roles/.
#
# Safety: never reads DeFiHackLabs PoC/README; keys/RPC redacted; cases.jsonl never written;
# confirm.py (verifier) untouched and independent; RAG refs exclude the query case.
import re, json, os, sys, time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from llm import gen_model
import fetch_source as fs
import verify_ctx as vc
import index as idx
from confirm import (THRESH, redact, csum, bogus, inject_confirm, write_proj, run_forge, parse_reason)

PLAN_MODEL   = os.environ.get('PLAN_MODEL',   'deepseek/deepseek-v3.2')      # cheap strategist
CODE_MODEL   = os.environ.get('CODE_MODEL',   'anthropic/claude-sonnet-4.5') # Claude writes Solidity
REFL_MODEL   = os.environ.get('REFL_MODEL',   'deepseek/deepseek-v3.2')      # cheap reflector
FINAL_MODEL  = os.environ.get('FINAL_MODEL',  'deepseek/deepseek-v3.2')      # cheap final reviewer
MAXR   = int(os.environ.get('MAXR', 4))
USE_RAG = os.environ.get('USE_RAG', '1') != '0'
RAG_K   = int(os.environ.get('RAG_K', 5))
PROMPTS = Path('prompts')

def _tpl(name, **kw):
    t = (PROMPTS / name).read_text()
    for k, v in kw.items():
        t = t.replace('[[%s]]' % k, str(v))
    return t

def _refs_block(ctx, src, cid):
    if not USE_RAG:
        return '', []
    try:
        refs = idx.retrieve_refs(ctx, src, query_id=cid, k=RAG_K)
    except Exception as e:
        return '', [{'error': f'{type(e).__name__}: {e}'}]
    if not refs:
        return '', []
    sec = 'SIMILAR HISTORICAL ATTACK PARADIGMS (inspiration only; NOT this contract\'s PoC):\n'
    for r in refs:
        sec += f"- [{r['category']}] {r['paradigm']} | {r['why']}\n"
    used = [{'id': r['id'], 'paradigm': r['paradigm'], 'score': r['score']} for r in refs]
    return '\n\n' + sec, used

def _json(text):
    try: return json.loads(re.search(r'\{[\s\S]*\}', text).group(0))
    except Exception: return {}

def plan_agent(base, victim, replan=None):
    rb = ''
    if replan:
        rb = ('RE-PLAN: the previous strategy failed. The reflector said:\n'
              f'- diagnosis: {replan.get("diagnosis","")}\n- change the strategy: {replan.get("instruction","")}\n'
              'Pick a DIFFERENT mechanism or target; do not repeat the failed approach.')
    prompt = _tpl('planner.md', victim=victim, replan_block=rb) + '\n\n' + base
    return gen_model(PLAN_MODEL, prompt, temp=0.3).strip()

def code_agent(base, victim, block, plan, prev_sol=None, prev_err=None):
    rb = ''
    if prev_sol:
        rb = ('REVISE: your previous test is below with its forge output. Fix per the plan; do not resend it verbatim.\n'
              f'--- previous .sol ---\n{prev_sol[:4000]}\n--- forge output tail ---\n{(prev_err or "")[-2000:]}')
    prompt = (_tpl('coder.md', victim=victim, block=block, revise_block=rb)
              + '\n\n# STRATEGY (plan.md)\n' + plan + '\n\n# CONTEXT & SOURCE\n' + base)
    out = gen_model(CODE_MODEL, prompt, temp=0.2)
    return re.sub(r'^```\w*\n?|```$', '', out.strip(), flags=re.M)

def reflect_agent(plan, sol, forge_out):
    prompt = (_tpl('reflector.md')
              + f'\n\n# STRATEGY (plan.md)\n{plan}\n\n# CODER TEST (key lines)\n{sol[:2500]}'
              + f'\n\n# FORGE OUTPUT\n{forge_out[-2200:]}')
    return _json(gen_model(REFL_MODEL, prompt, temp=0.2))

def final_agent(victim, rounds, history_md):
    prompt = _tpl('final.md', victim=victim, rounds=rounds) + '\n\n# FULL ITERATION HISTORY\n' + history_md
    return _json(gen_model(FINAL_MODEL, prompt, temp=0.2))

def one(cid, victim, block, outdir):
    D = Path(outdir); R = D / 'roles'; R.mkdir(parents=True, exist_ok=True)
    victim = csum(victim)
    r = fs.get(56, victim)
    src = fs.main_code('\n'.join(fs.files(r['SourceCode']).values()), r['ContractName'])[:48000]
    ctx = vc.build_context(block, victim, src)
    (D / 'CONTEXT.txt').write_text(ctx)
    refs_sec, refs_used = _refs_block(ctx, src, cid)
    base = ('PRE-READ live on-chain context:\n' + ctx + '\n\nVerified victim source:\n' + src + refs_sec)

    t0, hist_md, log = time.time(), [], []
    plan = plan_agent(base, victim)
    (R / 'plan.md').write_text(plan)
    hist_md.append(f'## Round 0 — initial plan\n{plan}')
    log.append(('plan', plan[:800]))

    prev_sol = prev_err = None
    reflect = None
    for rnd in range(1, MAXR + 1):
        sol = code_agent(base, victim, block, plan, prev_sol, prev_err)
        (R / f'try{rnd}.raw.sol').write_text(sol)
        why = bogus(sol)
        if why:
            fo = f'REJECTED anti-cheat: {why}'; ok = False
        else:
            sol2, ierr = inject_confirm(sol, victim)
            if ierr:
                fo = f'REJECTED inject: {ierr}'; ok = False
            else:
                (R / f'try{rnd}.sol').write_text(sol2)
                write_proj(D, sol2)
                ok, fo = run_forge(D)
        log.append(('forge', fo))
        if ok:
            (R / 'history.md').write_text('\n\n'.join(hist_md) + f'\n\n## Round {rnd} — VERIFIED')
            return {'id': cid, 'outcome': 'verified', 'rounds': rnd, 'sec': round(time.time()-t0),
                    'log': log, 'nread': 0, 'refs': refs_used, 'sol': sol[:400]}
        reason = parse_reason(ok, fo)
        reflect = reflect_agent(plan, sol, fo)
        (R / 'reflect.md').write_text('# round %d reflection\n```json\n%s\n```' % (rnd, json.dumps(reflect, ensure_ascii=False, indent=1)))
        log.append(('reflect', reflect))
        body = re.search(r'function\s+testExploit[\s\S]*?\n\s*\}', sol)
        keyln = (body.group(0) if body else sol)[:900]
        hist_md.append(f'## Round {rnd}\n**plan:** {plan[:400]}\n\n**test (key lines):**\n```solidity\n{keyln}\n```\n\n'
                       f'**forge ({reason}):**\n```\n{fo[-1200:]}\n```\n\n**reflect:** {json.dumps(reflect, ensure_ascii=False)}')
        prev_sol, prev_err = sol, fo
        if reflect.get('action') == 'replan' and rnd < MAXR:
            plan = plan_agent(base, victim, replan=reflect)
            (R / 'plan.md').write_text(plan)
            hist_md.append(f'## Round {rnd} — RE-PLAN\n{plan}')
            prev_sol = prev_err = None   # fresh approach: don't anchor coder to the dropped code

    history_md = '\n\n'.join(hist_md)
    (R / 'history.md').write_text(history_md)
    final = final_agent(victim, MAXR, history_md)
    (R / 'final.md').write_text('# FINAL DECISION\n```json\n%s\n```' % json.dumps(final, ensure_ascii=False, indent=1))
    log.append(('final', final))
    return {'id': cid, 'outcome': 'over_budget', 'rounds': MAXR, 'sec': round(time.time()-t0),
            'log': log, 'nread': 0, 'refs': refs_used, 'final_decision': final}

# reuse the same TARGETS as loop.py
from loop import TARGETS

if __name__ == '__main__':
    if not os.environ.get('BSC_RPC'): print('BLOCKER: set BSC_RPC'); sys.exit(2)
    slug = lambda s: re.sub(r'\W+', '_', s)
    ids = sys.argv[1:] or list(TARGETS)
    def run_one(cid):
        v, b = TARGETS[cid]
        res = one(cid, v, b, f'data/loop/{slug(cid)}')
        json.dump(res, open(f'data/loop/{slug(cid)}.roles.json', 'w'), ensure_ascii=False, indent=1)
        return {k: res[k] for k in res if k != 'log'}
    with ThreadPoolExecutor(max_workers=min(4, len(ids))) as ex:
        futs = {ex.submit(run_one, cid): cid for cid in ids}
        for fut in as_completed(futs):
            cid = futs[fut]
            try: print(json.dumps(fut.result(), ensure_ascii=False), flush=True)
            except Exception as e:
                err = {'id': cid, 'outcome': 'error', 'error': f'{type(e).__name__}: {e}'[:400]}
                print(json.dumps(err, ensure_ascii=False), flush=True)
