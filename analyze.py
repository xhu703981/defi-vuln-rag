# Offline root-cause analysis (leakage OK): README + PoC + indexed victim code -> per-case JSON, then aggregate.
import json, re, collections
from concurrent.futures import ThreadPoolExecutor
from llm import gen
from rag_utils import strip
from fetch_source import CHECKQ; CHECK = '\n'.join(f'{i+1}. {q}' for i, (_, _, q) in enumerate(CHECKQ))
MECH = ('spot_price_oracle, reserve_or_balance_manipulation, donation_share_inflation, reentrancy_callback, '
        'readonly_reentrancy, missing_access_control, arbitrary_external_call, unprotected_init_or_upgrade, '
        'fee_on_transfer_or_pair_burn, reward_or_dividend_miscalc, rounding_precision, accounting_double_count, '
        'input_validation, signature_replay, logic_state_machine, other')
SIG = ('reads_balanceOf, reads_getReserves_or_spot, external_call_before_write, callback_hook, missing_modifier, '
       'public_burn_skim_sync_like, user_supplied_target_or_calldata, share_math_division, unchecked_return, '
       'time_or_expiry_gate, transfer_hook_side_effects, initializer_open, flashloan_sensitive_input, '
       'state_debited_twice_or_not, other')
def analyze(c):
    out = gen('Offline post-mortem. Ground truth root cause: ' + c['root_cause'] + '\n\nAttack PoC:\n' +
                 re.sub(r'\n\s*\n', '\n', strip(c['poc']))[:6000] + '\n\nIndexed victim functions:\n' + c['code'][:15000] +
                 '\n\nOur tool ranked top-3: ' + json.dumps(c.get('picks', [])[:3]) + '\n\nChecklist used by the tool:\n' + CHECK +
                 '\n\nReply ONLY JSON: {"exploited_functions": [names], "exploited_in_indexed": bool, "mechanism": "1-2 '
                 f'sentences", "mechanism_type": one of [{MECH}], "attacker_inputs": [..], "signals": subset of [{SIG}], '
                 '"scope": "single-function|cross-function|cross-contract", "top3_hit": bool, "miss_reason": "if not hit: '
                 'why the tool overlooked it (e.g. looks like plain ERC20 transfer, small/internal helper, not indexed) '
                 'and what it ranked instead", "checklist_items": [numbers covering this case], "missing_signal": "signal '
                 'not covered by the checklist, or empty"}')
    try: r = json.loads(re.search(r'\{[\s\S]*\}', out)[0])
    except Exception: r = {'parse_error': out[:200]}
    return dict(id=c['id'], date=c['date'], category=c['category'], **r)
if __name__ == '__main__':
    cs = [c for c in map(json.loads, open('cases.jsonl')) if c['src'] == 'victim']
    R = list(ThreadPoolExecutor(16).map(analyze, cs))
    with open('analysis/root_causes.jsonl', 'w') as w:
        for r in R: w.write(json.dumps(r, ensure_ascii=False) + '\n')
    ok = [r for r in R if 'parse_error' not in r]
    C = lambda key, rs: collections.Counter(x for r in rs for x in (r.get(key) if isinstance(r.get(key), list) else [r.get(key)]))
    miss = [r for r in ok if not r.get('top3_hit')]
    md = [f'# Root-cause analysis (n={len(ok)}, parse errors {len(R)-len(ok)})', '',
          f"top3_hit (self-reported by analyst LLM): {sum(bool(r.get('top3_hit')) for r in ok)}/{len(ok)}; "
          f"exploited fn indexed: {sum(bool(r.get('exploited_in_indexed')) for r in ok)}/{len(ok)}", '']
    for t, k, rs in [('Mechanism taxonomy', 'mechanism_type', ok), ('Scope', 'scope', ok), ('Code signals', 'signals', ok),
                     ('Signals in MISSED cases', 'signals', miss), ('Checklist items covering', 'checklist_items', ok)]:
        md += [f'## {t}', ''] + [f'- {k2}: {v}' for k2, v in C(k, rs).most_common()] + ['']
    md += ['## Missed cases (exploited fn not in top-3)', ''] + [
        f"- **{r['id']}** [{r.get('mechanism_type')}] exploited={r.get('exploited_functions')} :: {r.get('miss_reason')}" for r in miss]
    md += ['', '## Signals not covered by checklist', ''] + [f"- {r['id']}: {r['missing_signal']}" for r in ok if r.get('missing_signal')]
    md += ['', '## LLM synthesis of miss patterns and checklist gaps', '', gen(
        'Synthesize in concise Chinese (<=400 words): recurring patterns why the tool missed exploited functions, and which '
        'checklist items should be added/changed. Data:\n' + '\n'.join(md)[:60000])]
    open('analysis/summary.md', 'w').write('\n'.join(md)); print('\n'.join(md[:80]))
