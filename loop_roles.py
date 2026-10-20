# Grok Build-style role-split exploit loop: Planner -> (3-4 hypotheses) -> Coder per hypothesis
# -> run_forge -> vote by confirm net-loss -> Reflector (-> replan), then after MAXR rounds a
# FINAL DECISION model reviews all iterations and returns genuinely_cannot | should_continue.
# Does NOT auto-start a second cycle (reports only).
#
# Planner now (1) enumerates every entrypoint + asset flow anchored to victim holdings before
# choosing, (2) evaluates the Jev vectorless-RAG paradigms as a case-by-case checklist, and
# (3) emits 3-4 structurally different hypotheses. The loop writes a minimal PoC for EACH
# hypothesis, runs each, and votes by the cross-asset net-loss result instead of riding one
# hypothesis for 4 rounds.
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
# Coder does NOT need a strong model (the bottleneck is upstream reasoning, not code volume);
# default back to Sonnet. CODE_MODEL / CODER_MODEL env still override.
CODE_MODEL   = os.environ.get('CODE_MODEL') or os.environ.get('CODER_MODEL') or 'anthropic/claude-sonnet-4.5'
REFL_MODEL   = os.environ.get('REFL_MODEL',   'deepseek/deepseek-v3.2')      # cheap reflector
FINAL_MODEL  = os.environ.get('FINAL_MODEL',  'deepseek/deepseek-v3.2')      # cheap final reviewer
MAXR   = int(os.environ.get('MAXR', 4))
USE_RAG = os.environ.get('USE_RAG', '1') != '0'
RAG_K   = int(os.environ.get('RAG_K', 5))
MAX_HYP = int(os.environ.get('MAX_HYP', 4))
PROMPTS = Path('prompts')

def _tpl(name, **kw):
    t = (PROMPTS / name).read_text()
    for k, v in kw.items():
        t = t.replace('[[%s]]' % k, str(v))
    return t

def _refs(ctx, src, cid):
    """Return (checklist_text, used_meta). checklist_text is fed to the PLANNER as a
    case-by-case checklist (not soft reference)."""
    if not USE_RAG:
        return '(RAG disabled)', []
    try:
        refs = idx.retrieve_refs(ctx, src, query_id=cid, k=RAG_K)
    except Exception as e:
        return '(RAG error: %s)' % (type(e).__name__), [{'error': f'{type(e).__name__}: {e}'}]
    if not refs:
        return '(no paradigms retrieved)', []
    lines = []
    for i, r in enumerate(refs, 1):
        lines.append(f"{i}. [{r['category']}] {r['paradigm']}  ({r['why']})")
    used = [{'id': r['id'], 'paradigm': r['paradigm'], 'score': r['score']} for r in refs]
    return '\n'.join(lines), used

def _json(text):
    try: return json.loads(re.search(r'\{[\s\S]*\}', text).group(0))
    except Exception: return {}

def parse_hypotheses(plan):
    """Pull the fenced ```json {"hypotheses":[...]} block the planner emits; fall back to one."""
    hyps = []
    for m in re.finditer(r'```json\s*([\s\S]*?)```', plan):
        try:
            obj = json.loads(m.group(1))
            if isinstance(obj, dict) and isinstance(obj.get('hypotheses'), list):
                hyps = obj['hypotheses']
        except Exception:
            continue
    if not hyps:  # fallback: treat whole plan as a single hypothesis
        return [{'id': 'H1', 'class': 'single', 'entry': '', 'asset_flow': '', 'signal': '', 'primary': True}]
    hyps = hyps[:MAX_HYP]
    # put the annotated guard+bypass real-chain FIRST: explicit primary flag, else first with a bypass, else first
    def _rank(h):
        if h.get('primary'): return 0
        if (h.get('bypass') or '').strip(): return 1
        return 2
    hyps = sorted(hyps, key=_rank)
    if hyps:
        hyps[0]['primary'] = True  # the loop treats position-0 as the real chain
    return hyps

def _hyp_text(h):
    s = (f"HYPOTHESIS {h.get('id','?')} — class={h.get('class','')}\n"
         f"entry: {h.get('entry','')}\nasset_flow: {h.get('asset_flow','')}\n"
         f"success signal: {h.get('signal','')}")
    if (h.get('precond') or '').strip():
        s += f"\nprecond (IMPLEMENT + ASSERT FIRST, before the attack action): {h.get('precond','')}"
    if (h.get('guard') or '').strip():
        s += f"\nguard: {h.get('guard','')}"
    if (h.get('bypass') or '').strip():
        s += f"\nbypass (MUST code this exact logic): {h.get('bypass','')}"
    return s

def plan_agent(base, victim, refs_checklist, replan=None):
    rb = ''
    if replan:
        rb = ('RE-PLAN: every hypothesis from the previous plan failed. The reflectors said:\n'
              + replan + '\nPropose NEW hypotheses using entrypoint classes you have NOT tried; '
              'do not repeat the failed mechanisms.')
    prompt = _tpl('planner.md', victim=victim, refs_checklist=refs_checklist, replan_block=rb) + '\n\n' + base
    return gen_model(PLAN_MODEL, prompt, temp=0.3).strip()

def code_agent(base, victim, block, plan, hyp, all_hyps, primary_hyp, prev_sol=None, prev_err=None):
    rb = ''
    if prev_sol:
        rb = ('REVISE: your previous test is below with its forge output. Fix per the plan; do not resend it verbatim.\n'
              f'--- previous .sol ---\n{prev_sol[:4000]}\n--- forge output tail ---\n{(prev_err or "")[-2000:]}')
    # The annotated guard+bypass real-chain goes FIRST, marked MUST-implement.
    must = ('# MUST-IMPLEMENT REAL CHAIN (do this FIRST, do NOT skip it)\n'
            'The planner marked the following hypothesis as the real attack chain. You MUST encode its\n'
            'EXACT entrypoint/reentrancy logic (the call order, which function re-enters which, and the\n'
            'guard bypass named below). Do not substitute a different, easier branch; this logic has to be\n'
            'in the test.\n' + _hyp_text(primary_hyp))
    # all hypotheses, for full context
    allh = '# ALL PLAN HYPOTHESES (for context; the one you build this candidate around is marked TARGET)\n' + \
           '\n\n'.join((('>>> TARGET: ' if h.get('id')==hyp.get('id') else '') + _hyp_text(h)) for h in all_hyps)
    same_as_primary = hyp.get('id') == primary_hyp.get('id')
    target = ('# THIS CANDIDATE\n' +
              ('You are building the REAL CHAIN candidate above — implement it directly.'
               if same_as_primary else
               'You are building a BACKUP candidate around TARGET hypothesis ' + str(hyp.get('id')) +
               '. Implement that target chain; you may also fold in the real-chain logic above if it helps net-drain.'))
    prompt = (_tpl('coder.md', victim=victim, block=block, revise_block=rb)
              + '\n\n' + must + '\n\n' + allh + '\n\n' + target
              + '\n\n# FULL STRATEGY (plan.md)\n' + plan + '\n\n# CONTEXT & SOURCE\n' + base)
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

def _run_candidate(D, victim, sol, tag):
    """Anti-cheat -> inject confirm -> write project -> forge. Returns (ok, forge_out, reason)."""
    why = bogus(sol)
    if why:
        return False, f'REJECTED anti-cheat: {why}', 'anti-cheat'
    sol2, ierr = inject_confirm(sol, victim)
    if ierr:
        return False, f'REJECTED inject: {ierr}', 'inject error'
    pd = D / tag
    pd.mkdir(parents=True, exist_ok=True)
    write_proj(pd, sol2)
    ok, fo = run_forge(pd)
    return ok, fo, parse_reason(ok, fo)

def one(cid, victim, block, outdir):
    D = Path(outdir); R = D / 'roles'; R.mkdir(parents=True, exist_ok=True)
    victim = csum(victim)
    r = fs.get(56, victim)
    src = fs.main_code('\n'.join(fs.files(r['SourceCode']).values()), r['ContractName'])[:48000]
    ctx = vc.build_context(block, victim, src)
    (D / 'CONTEXT.txt').write_text(ctx)
    refs_checklist, refs_used = _refs(ctx, src, cid)
    base = ('PRE-READ live on-chain context:\n' + ctx + '\n\nVerified victim source:\n' + src)

    t0, hist_md, log = time.time(), [], []
    plan = plan_agent(base, victim, refs_checklist)
    (R / 'plan.md').write_text(plan)
    hyps = parse_hypotheses(plan)
    # per-hypothesis running state
    st = {h['id']: {'hyp': h, 'alive': True, 'prev_sol': None, 'prev_err': None} for h in hyps}
    hist_md.append(f'## Round 0 — initial plan ({len(hyps)} hypotheses: ' + ', '.join(st) + ')\n' + plan)
    log.append(('plan', plan[:800]))

    for rnd in range(1, MAXR + 1):
        alive = [hid for hid in st if st[hid]['alive']]
        if not alive:
            break
        # write + run a PoC for each surviving hypothesis in parallel, vote by net-loss result
        all_hyps = [st[hid]['hyp'] for hid in st]
        primary_hyp = next((h for h in all_hyps if h.get('primary')), all_hyps[0])
        results = {}
        def work(hid):
            s = st[hid]
            sol = code_agent(base, victim, block, plan, s['hyp'], all_hyps, primary_hyp, s['prev_sol'], s['prev_err'])
            (R / f'try{rnd}_{hid}.raw.sol').write_text(sol)
            ok, fo, reason = _run_candidate(D, victim, sol, f'cand_{hid}')
            return hid, sol, ok, fo, reason
        with ThreadPoolExecutor(max_workers=min(len(alive), MAX_HYP)) as ex:
            for fut in as_completed([ex.submit(work, hid) for hid in alive]):
                hid, sol, ok, fo, reason = fut.result()
                results[hid] = (sol, ok, fo, reason)
        # winner?
        for hid, (sol, ok, fo, reason) in results.items():
            if ok:
                (R / f'try{rnd}_{hid}.sol').write_text(sol)
                (R / 'history.md').write_text('\n\n'.join(hist_md) + f'\n\n## Round {rnd} — VERIFIED by {hid}')
                log.append(('forge', f'{hid} VERIFIED'))
                return {'id': cid, 'outcome': 'verified', 'rounds': rnd, 'winner': hid,
                        'sec': round(time.time()-t0), 'log': log, 'nread': 0, 'refs': refs_used,
                        'sol': sol[:400]}
        # none verified: reflect per hypothesis, vote (drop replan=wrong-approach, keep revise=progress)
        round_summ = []
        for hid, (sol, ok, fo, reason) in results.items():
            reflect = reflect_agent(plan, sol, fo)
            st[hid]['reflect'] = reflect
            st[hid]['prev_sol'], st[hid]['prev_err'] = sol, fo
            if reflect.get('action') == 'replan':
                st[hid]['alive'] = False   # this mechanism is wrong; stop riding it
            body = re.search(r'function\s+testExploit[\s\S]*?\n\s*\}', sol)
            keyln = (body.group(0) if body else sol)[:600]
            round_summ.append(f"### {hid} [{reason}] alive={st[hid]['alive']}\n"
                              f"```solidity\n{keyln}\n```\nreflect: {json.dumps(reflect, ensure_ascii=False)}")
        (R / f'reflect{rnd}.md').write_text('\n\n'.join(round_summ))
        log.append(('round', {hid: results[hid][3] for hid in results}))
        hist_md.append(f'## Round {rnd}\n' + '\n\n'.join(round_summ))
        # if all hypotheses are dead, re-plan a fresh set before the next round
        if not any(st[hid]['alive'] for hid in st) and rnd < MAXR:
            replan_note = '\n'.join(f"{hid}: {st[hid].get('reflect',{}).get('diagnosis','')}" for hid in st)
            plan = plan_agent(base, victim, refs_checklist, replan=replan_note)
            (R / 'plan.md').write_text(plan)
            hyps = parse_hypotheses(plan)
            st = {h['id']: {'hyp': h, 'alive': True, 'prev_sol': None, 'prev_err': None} for h in hyps}
            hist_md.append(f'## Round {rnd} — RE-PLAN ({len(hyps)} new hypotheses)\n{plan}')

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
