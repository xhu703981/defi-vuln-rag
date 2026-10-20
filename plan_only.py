# PLANNER-ONLY harness: builds the same live context as loop_roles.one(), runs plan_agent,
# writes plan.md, parses hypotheses. No coder, no PoC, no forge, no confirm. Reports only.
import re, json, os, sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import loop_roles as L
import fetch_source as fs, verify_ctx as vc
from confirm import csum

def slug(s): return re.sub(r'\W+', '_', s)

def plan_only(cid, victim, block):
    victim = csum(victim)
    r = fs.get(56, victim)
    src = fs.main_code('\n'.join(fs.files(r['SourceCode']).values()), r['ContractName'])[:48000]
    ctx = vc.build_context(block, victim, src)
    refs_checklist, refs_used = L._refs(ctx, src, cid)
    base = ('PRE-READ live on-chain context:\n' + ctx + '\n\nVerified victim source:\n' + src)
    plan = L.plan_agent(base, victim, refs_checklist)
    outdir = Path(f'data/plan_only/{slug(cid)}'); outdir.mkdir(parents=True, exist_ok=True)
    (outdir / 'plan.md').write_text(plan)
    hyps = L.parse_hypotheses(plan)
    (outdir / 'hyps.json').write_text(json.dumps(hyps, ensure_ascii=False, indent=1))
    return {'id': cid, 'n_hyps': len(hyps), 'hyps': hyps, 'plan_chars': len(plan)}

if __name__ == '__main__':
    if not os.environ.get('BSC_RPC'): print('BLOCKER: set BSC_RPC'); sys.exit(2)
    ids = sys.argv[1:]
    def run(cid):
        v, b = L.TARGETS[cid]; return plan_only(cid, v, b)
    with ThreadPoolExecutor(max_workers=min(8, len(ids))) as ex:
        futs = {ex.submit(run, cid): cid for cid in ids}
        for fut in as_completed(futs):
            cid = futs[fut]
            try: print(json.dumps(fut.result(), ensure_ascii=False), flush=True)
            except Exception as e:
                print(json.dumps({'id': cid, 'error': f'{type(e).__name__}: {e}'[:300]}, ensure_ascii=False), flush=True)
