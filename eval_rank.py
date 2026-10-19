# Jev-ranking-only eval (no forge, no PoC gen): func_hit@1 / func_hit@3 (strict names-only judge) overall + per mechanism.
import json, re, os, sys
from concurrent.futures import ThreadPoolExecutor
from llm import jev
from rag_utils import strip
MECH = ['spot_price_oracle','missing_access_control','reserve_or_balance_manipulation','reentrancy_callback','arbitrary_external_call',
        'rounding_precision','donation_share_inflation','fee_on_transfer_or_pair_burn','logic_state_machine']
def poc_txt(c): return re.sub(r'\n\s*\n','\n', strip(c['poc']))[:6000]
def fhit(c, k):  # strict names-only judge over top-k picks
    names = [p['name'] for p in c['picks'][:k]] or ['(none)']
    a = jev({'real_root_cause': c['root_cause'], 'attack_poc': poc_txt(c), 'tool_top3_flagged_functions': names},
            {'func_hit': {'type':'noul','instructions':'Is one of the tool-flagged functions the actually exploited function (or directly contains the exploited issue), judging from the root cause and the attack PoC?'}})
    return int(a['func_hit'].get('noul',0) >= .5)
def mech(c):
    p = jev({'root_cause': c['root_cause'][:3000]}, {'m':{'type':'choice','instructions':'Which exploit mechanism class best describes this root cause?','criteria':{m:m.replace('_',' ') for m in MECH}}})['m']['probabilities']
    return max(p, key=p.get)
if __name__=='__main__':
    cs=[json.loads(l) for l in open(sys.argv[1]) if json.loads(l).get('src')=='victim']
    ex=ThreadPoolExecutor(16)
    h1=dict(zip([c['id'] for c in cs], ex.map(lambda c: fhit(c,1), cs)))
    h3=dict(zip([c['id'] for c in cs], ex.map(lambda c: fhit(c,3), cs)))
    M =dict(zip([c['id'] for c in cs], ex.map(mech, cs)))
    N=len(cs)
    print(f'=== {sys.argv[1]}  n={N} ===')
    print(f'func_hit@1 = {sum(h1.values())}/{N} = {sum(h1.values())/N:.0%}')
    print(f'func_hit@3 = {sum(h3.values())}/{N} = {sum(h3.values())/N:.0%}')
    print('\n%-30s %4s %6s %6s' % ('mechanism','n','@1','@3'))
    for m in sorted(set(M.values()), key=lambda m:-list(M.values()).count(m)):
        s=[c['id'] for c in cs if M[c['id']]==m]
        print('%-30s %4d %6s %6s' % (m, len(s), f"{sum(h1[i] for i in s)}", f"{sum(h3[i] for i in s)}"))
    print('\n=== top-3 MISSES (for failure analysis) ===')
    for c in cs:
        if not h3[c['id']]:
            print(f"\n--- {c['id']}  [mech={M[c['id']]}]  hit@1={h1[c['id']]}")
            print('  picks(top3):', [p['name'] for p in c['picks'][:3]])
            print('  fnames(rank order):', c.get('fnames'))
            print('  root_cause:', c['root_cause'][:400])
    # dump for programmatic reuse
    json.dump({'h1':h1,'h3':h3,'mech':M}, open('/tmp/eval_rank.json','w'))
