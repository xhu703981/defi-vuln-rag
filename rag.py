# Function-level index (raw / normalized / LLM description) + hybrid retrieval + RRF + LLM rerank + temporal LOO eval.
import re, json, os, sys, numpy as np
from concurrent.futures import ThreadPoolExecutor
from rank_bm25 import BM25Okapi
from sentence_transformers import SentenceTransformer
from rag_utils import norm, funcs, toks
from llm import gen
POOL = ThreadPoolExecutor(16)

def llm_describe(fn, ctx=''):  # HyDE: code only -> risk-oriented behavior description
    return gen('You are a smart-contract security auditor. From the Solidity function below ONLY, describe in 2-3 '
                  'sentences what it does from a risk perspective: which balances/reserves/prices/state it reads or '
                  'writes, external calls and their order, access checks, arithmetic/rounding, and what an attacker '
                  'could abuse. Generic terms, no project names.\n\n' + (f'Contract context:\n{ctx}\n\nFunction:\n' if ctx else '') + fn[:3000])

def llm_explain(q, j, qf, jf):  # one line: why similar + what to check (not used for ranking)
  try:
    return gen('Audited contract summary:\n' + cases[q]['summary'] + '\n\nAudited function:\n' + qf[:2000] + '\n\nHistorical contract summary:\n' + cases[j]['summary'] + '\n\nHistorical exploited function (category: ' + cases[j]['category'] +
                  '):\n' + jf[:2000] + '\n\nIn ONE line of Chinese: why they are similar in risk, and what the auditor '
                  'should check in the audited function.').strip()
  except Exception: return '（解释未生成：生成失败）'

M = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2', device='cpu')
def emb(xs): return M.encode([x[:2000] for x in xs], normalize_embeddings=True, batch_size=32)

cases = [c for c in map(json.loads, open('cases.jsonl')) if c['src'] == 'victim']
F = [f for c in cases for f in c['funcs']]
own = np.array([i for i, c in enumerate(cases) for _ in c['funcs']])
W = 1 + 0.1 * np.array([w for c in cases for w in c['weights']])  # mild LLM suspiciousness weight
D = list(POOL.map(llm_describe, F, [cases[i]['summary'] for i in own]))
descs = [[D[k] for k in np.where(own == i)[0]] for i in range(len(cases))]
E = {'raw': emb(F), 'norm': emb([norm(f) for f in F]), 'desc': emb(D)}
E_sum = emb([c['summary'] for c in cases])
bm = BM25Okapi([toks(f) for f in F])

def case_max(S, k, arg=False):  # S: (q funcs k, all funcs) weighted -> per-case max over function pairs
    S = S * W[k][:, None] * W[None, :]
    out = np.full(len(cases), -1e9); np.maximum.at(out, own, S.max(0))
    return (out, S) if arg else out

def channels(i):
    k = np.where(own == i)[0]
    ch = {n: case_max(E[n][k] @ E[n].T, k) for n in E}
    ch['bm25'] = case_max(np.array([bm.get_scores(toks(F[x])) for x in k]), k)
    ch['sum'] = E_sum @ E_sum[i]  # contract summary vs contract summary
    return ch

def rrf(lists, k=60):
    s = {}
    for rl in lists:
        for r, j in enumerate(rl): s[j] = s.get(j, 0) + 1 / (k + r)
    return sorted(s, key=s.get, reverse=True)

MODES = {'code': ['raw', 'norm', 'bm25'], 'desc': ['desc'], 'sum': ['sum'], 'fused': ['raw', 'norm', 'bm25', 'desc', 'desc'],
         'fused+sum': ['raw', 'norm', 'bm25', 'desc', 'desc', 'sum', 'sum']}
def evaluate(cut='20250201'):
    Q = [i for i, c in enumerate(cases) if any(d['date'] < c['date'] and d['category'] == c['category'] for d in cases)]
    res = {m: {} for m in MODES}
    for i in Q:
        A = np.array([j for j, d in enumerate(cases) if d['date'] < cases[i]['date']])  # temporal split
        ch = channels(i)
        for m, names in MODES.items(): res[m][i] = rrf([list(A[np.argsort(-ch[n][A])]) for n in names])
    from collections import Counter
    for name, sub in [('all', Q), (f'>= {cut} (post-cutoff)', [i for i in Q if cases[i]['date'] >= cut])]:
        maj = Counter(cases[i]['category'] for i in sub).most_common(1)[0][1] / len(sub)
        print(f'--- {name}: n={len(sub)}  majority R@1={maj:.3f}')
        for m, R in res.items():
            first = [next(r for r, j in enumerate(R[i]) if cases[j]['category'] == cases[i]['category']) for i in sub]
            print(f'{m:13s}' + ''.join(f' R@{k}={np.mean([f < k for f in first]):.3f}' for k in (1, 5, 10))
                  + f' MRR={np.mean([1 / (f + 1) for f in first]):.3f}')

def query(cid):  # auditor view for one case vs strictly earlier cases
    i = next(x for x, c in enumerate(cases) if c['id'] == cid); c = cases[i]
    A = np.array([j for j, d in enumerate(cases) if d['date'] < c['date']]); ch = channels(i)
    top = rrf([list(A[np.argsort(-ch[n][A])]) for n in MODES['fused+sum']])[:5]
    k = np.where(own == i)[0]; _, S = case_max(E['desc'][k] @ E['desc'].T, k, True)
    o = [f"# 审计提示：{c['id']}（类别仅供对照：{c['category']}）", '', '## 合约级摘要', c['summary'], '', '## LLM 可疑度排序（前 3）']
    o += [f"- `{p['name']}`：{p['why']}" for p in c.get('picks', [])] + ['', '## 相似历史案例 Top-5']
    for r, j in enumerate(top, 1):
        kj = np.where(own == j)[0]; qa, ja = np.unravel_index(np.argmax(S[:, kj]), (len(k), len(kj)))
        o += [f"### {r}. {cases[j]['id']}（{cases[j]['category']}，损失：{cases[j]['loss'][:80]}）",
              f"- 本合约函数 `{c['fnames'][qa]}` ↔ 历史函数 `{cases[j]['fnames'][ja]}`",
              '- ' + llm_explain(i, j, F[k[qa]], F[kj[ja]]), '']
    return '\n'.join(o)

if __name__ == '__main__':
    if len(sys.argv) > 1: open('example_output.md', 'w').write(query(sys.argv[1])); print(open('example_output.md').read())
    else: evaluate()
