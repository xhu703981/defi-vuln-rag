# Simplified retrieval ablation: summary-embedding coarse prefilter (top-N) -> Jev per-candidate "reference value" noul -> top-k.
# No function-level embedding/RRF for the simplified path. Temporal split kept. Compares vs rag.py fused+sum RRF. Does NOT modify old logic.
import os, sys, json, numpy as np
os.environ.setdefault('CACHE_ONLY', '1')  # reuse cached DeepSeek descriptions/summaries; never generate here
import rag
from llm import jev
cases, E_sum, own = rag.cases, rag.E_sum, rag.own
PRE = int(os.environ.get('PRE', 10))  # coarse prefilter width

def jev_ref(i, j):  # does earlier case j provide reference value for auditing case i? (summary-level, mechanism-oriented)
    a = jev({'contract_under_audit_summary': cases[i]['summary'][:1500],
             'suspicious_functions': [p['name'] for p in cases[i].get('picks', [])][:3],
             'candidate_past_incident_summary': cases[j]['summary'][:1500]},
            {'useful': {'type': 'noul', 'instructions': 'Would the root cause / attack mechanism of this past incident give an auditor a USEFUL, transferable lead for finding a vulnerability in the contract under audit (same class of bug, similar risky pattern)? Judge by mechanism similarity, not surface wording.'}})
    return a['useful'].get('noul', 0)

def simple_retrieve(i, k=5):
    A = np.array([j for j, d in enumerate(cases) if d['date'] < cases[i]['date']])
    if len(A) == 0: return []
    pre = A[np.argsort(-(E_sum[A] @ E_sum[i]))[:PRE]]            # coarse: summary-embedding top-PRE
    scored = sorted(((jev_ref(i, int(j)), int(j)) for j in pre), reverse=True)  # Jev refine
    return [j for _, j in scored[:k]]

def baseline_retrieve(i, k=5):
    A = np.array([j for j, d in enumerate(cases) if d['date'] < cases[i]['date']])
    ch = rag.channels(i)
    return rag.rrf([list(A[np.argsort(-ch[n][A])]) for n in rag.MODES['fused+sum']])[:k]

def cat_rank(i, ranked):  # rank of first same-category (mechanism-match) hit
    for r, j in enumerate(ranked):
        if cases[j]['category'] == cases[i]['category']: return r
    return 99

if __name__ == '__main__':
    # eval batch: named cases + a few temporal-eval cases that have an earlier same-category incident
    want = set(sys.argv[1:]) or None
    byid = {c['id']: x for x, c in enumerate(cases)}
    Q = [i for i, c in enumerate(cases) if any(d['date'] < c['date'] and d['category'] == c['category'] for d in cases)]
    if want:
        batch = [byid[w] for w in want if w in byid]
    else:
        import random; random.seed(1)
        import os as _os
        n=int(_os.environ.get('BATCH','7'))
        rest=list(Q); random.shuffle(rest); batch = Q if n>=len(Q) else rest[:n]
    print(f'batch n={len(batch)}  (PRE={PRE})')
    rowsB, rowsS = [], []
    for i in batch:
        b = baseline_retrieve(i); s = simple_retrieve(i)
        rb, rs = cat_rank(i, b), cat_rank(i, s)
        rowsB.append(rb); rowsS.append(rs)
        print(f"  {cases[i]['id'][:30]:30s} cat={cases[i]['category'][:22]:22s} | baseline first-match@{rb if rb<99 else '-'}  simple@{rs if rs<99 else '-'}")
        print(f"     baseline top3: {[cases[j]['id'][:18]+'('+cases[j]['category'][:12]+')' for j in b[:3]]}")
        print(f"     simple   top3: {[cases[j]['id'][:18]+'('+cases[j]['category'][:12]+')' for j in s[:3]]}")
    def agg(rs):
        rs=np.array(rs); return f"R@1={np.mean(rs<1):.2f} R@3={np.mean(rs<3):.2f} R@5={np.mean(rs<5):.2f} MRR={np.mean([1/(r+1) if r<99 else 0 for r in rs]):.3f}"
    print('\nBASELINE (fused+sum RRF): ', agg(rowsB))
    print('SIMPLE  (sum-prefilter+Jev):', agg(rowsS))
