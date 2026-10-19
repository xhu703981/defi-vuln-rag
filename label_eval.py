# RANK=label eval: per-function risk labels -> for each threshold, recall(true exploited fn labeled positive) + mean positive-list length.
import json, re, os, sys
from concurrent.futures import ThreadPoolExecutor
from llm import jev
from rag_utils import strip
MECH=['spot_price_oracle','missing_access_control','reserve_or_balance_manipulation','reentrancy_callback','arbitrary_external_call','rounding_precision','donation_share_inflation','fee_on_transfer_or_pair_burn','logic_state_machine']
def poc_txt(c): return re.sub(r'\n\s*\n','\n', strip(c['poc']))[:6000]
def fhit_set(c, names):  # strict names-only judge: is the true exploited fn among this positive set?
    names=names or ['(none)']
    a=jev({'real_root_cause':c['root_cause'],'attack_poc':poc_txt(c),'tool_top3_flagged_functions':names[:40]},
          {'func_hit':{'type':'noul','instructions':'Is one of the tool-flagged functions the actually exploited function (or directly contains the exploited issue), judging from the root cause and the attack PoC?'}})
    return int(a['func_hit'].get('noul',0)>=.5)
def mech(c):
    p=jev({'root_cause':c['root_cause'][:3000]},{'m':{'type':'choice','instructions':'Which exploit mechanism class best describes this root cause?','criteria':{m:m.replace('_',' ') for m in MECH}}})['m']['probabilities']
    return max(p,key=p.get)
if __name__=='__main__':
    cs=[json.loads(l) for l in open(sys.argv[1]) if json.loads(l).get('labels')]
    THR=[0.10,0.15,0.20,0.30,0.40,0.50]
    M=dict(zip([c['id'] for c in cs], ThreadPoolExecutor(16).map(mech,cs)))
    ex=ThreadPoolExecutor(16)
    # precompute positive sets and judge per (case,threshold)
    def ev(args):
        c,t=args; pos=[n for n,p in c['labels'].items() if p>=t]
        return (c['id'],t,fhit_set(c,pos),len(pos),len(c['labels']))
    jobs=[(c,t) for c in cs for t in THR]
    res=list(ex.map(ev,jobs))
    N=len(cs)
    print(f'=== {sys.argv[1]}  n={N} (RANK=label) ===')
    print('%-6s %10s %14s %10s' % ('thr','recall','mean_list_len','mean_total_fns'))
    byt={}
    for cid,t,hit,ln,tot in res: byt.setdefault(t,[]).append((cid,hit,ln,tot))
    for t in THR:
        rows=byt[t]; rec=sum(h for _,h,_,_ in rows); ml=sum(l for _,_,l,_ in rows)/N; mt=sum(x for _,_,_,x in rows)/N
        print('%-6.2f %10s %14.1f %10.1f' % (t, f'{rec}/{N}={rec/N:.0%}', ml, mt))
    # per-mechanism recall at a chosen threshold
    for t in [0.15,0.20,0.30]:
        print(f'\n-- per-mechanism recall @ thr={t} (recall / n, mean_len) --')
        rowmap={cid:(hit,ln) for cid,tt,hit,ln,_ in res if tt==t}
        for m in sorted(set(M.values()), key=lambda m:-list(M.values()).count(m)):
            ids=[c['id'] for c in cs if M[c['id']]==m]
            rec=sum(rowmap[i][0] for i in ids); ml=sum(rowmap[i][1] for i in ids)/len(ids)
            print('  %-30s %s  len~%.1f' % (m, f'{rec}/{len(ids)}', ml))
