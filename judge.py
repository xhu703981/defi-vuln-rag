# Primary eval: LLM judge of exploited-function hit@3 and reason hit, from README root cause vs top-3 picks.
import json, re, sys, os
from concurrent.futures import ThreadPoolExecutor
from llm import jev
from rag_utils import strip
def judge(c):  # Jev decisions: two yes/no questions, threshold 0.5
    a = jev({'real_root_cause': c['root_cause'], 'attack_poc': re.sub(r'\n\s*\n', '\n', strip(c['poc']))[:6000],
             'tool_top3_flagged_functions': [f"{p['name']}: {p['why']}" for p in c['picks'][:3]] or ['(none)']},
            {'func_hit': {'type': 'noul', 'instructions': 'Is one of the tool-flagged functions the actually exploited function (or directly contains the exploited issue), judging from the root cause and the attack PoC?'},
             'reason_hit': {'type': 'noul', 'instructions': 'Does one of the flagged functions that is actually exploited also come with a stated reason matching the real root-cause class?'}})
    P = {k: (v.get('noul', 0) if v.get('type') == 'noul' else 0) for k, v in a.items()}
    if os.environ.get('JUDGE_OLD') != '1':  # func_hit from names only, so reason wording cannot flip it
        n = jev({'real_root_cause': c['root_cause'], 'attack_poc': re.sub(r'\n\s*\n', '\n', strip(c['poc']))[:6000], 'tool_top3_flagged_functions': [p['name'] for p in c['picks'][:3]] or ['(none)']},
                {'func_hit': {'type': 'noul', 'instructions': 'Is one of the tool-flagged functions the actually exploited function (or directly contains the exploited issue), judging from the root cause and the attack PoC?'}})
        P['func_hit'] = n['func_hit'].get('noul', 0)
    fh = int(P.get('func_hit', 0) >= .5)
    return {'func_hit': fh, 'reason_hit': fh * int(P.get('reason_hit', 0) >= .5), 'p': P}  # reason only counts with func
MECH = ['spot_price_oracle', 'missing_access_control', 'reserve_or_balance_manipulation', 'reentrancy_callback', 'arbitrary_external_call',
        'rounding_precision', 'donation_share_inflation', 'fee_on_transfer_or_pair_burn', 'logic_state_machine']
def mech(c):  # Jev label of the ground-truth root cause (eval only)
    p = jev({'root_cause': c['root_cause'][:3000]}, {'m': {'type': 'choice', 'instructions': 'Which exploit mechanism class best describes this root cause?',
            'criteria': {m: m.replace('_', ' ') for m in MECH}}})['m']['probabilities']
    return max(p, key=p.get)
if __name__ == '__main__':  # judge.py A.jsonl B.jsonl ... -> totals + per-mechanism func/reason on common victim cases
    R = {f: {c['id']: c for c in map(json.loads, open(f)) if c['src'] == 'victim'} for f in sys.argv[1:]}
    ids = sorted(set.intersection(*map(set, R.values()))); M = dict(zip(ids, ThreadPoolExecutor(16).map(lambda i: mech(R[sys.argv[1]][i]), ids)))
    J = {f: dict(zip(ids, ThreadPoolExecutor(16).map(judge, [r[i] for i in ids]))) for f, r in R.items()}
    for m in sorted(set(M.values()), key=lambda m: -list(M.values()).count(m)) + ['ALL']:
        s = [i for i in ids if m in ('ALL', M[i])]
        print(f'{m[:24]:24s} n={len(s):2d} ' + '  '.join(f"{sum(J[f][i]['func_hit'] for i in s)}/{sum(J[f][i]['reason_hit'] for i in s)}" for f in R))
    print('files:', ' | '.join(R))
