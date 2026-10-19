# Indexing diagnostics: is the exploited function (from analysis/root_causes.jsonl) indexed / in the chosen contract?
import json, collections, sys
rc = {r['id']: r for r in map(json.loads, open('analysis/root_causes.jsonl'))}
for f in sys.argv[1:]:
    cs = [c for c in map(json.loads, open(f)) if c['id'] in rc and rc[c['id']].get('exploited_functions')]
    why = collections.Counter()
    for c in cs:
        ex = set(rc[c['id']]['exploited_functions'])
        if ex & set(c.get('fnames', [])): why['indexed'] += 1
        elif ex & set(c.get('allnames', [])): why['right contract, cut by cap/filter'] += 1
        elif any(ex & set(v['fns']) for v in c.get('cands', {}).values()): why['wrong contract chosen'] += 1
        elif c.get('src') != 'victim': why['no verified source / no address'] += 1
        else: why['exploited fn not in any fetched source (unverified/other contract)'] += 1
    print(f, f'n={len(cs)}', dict(why.most_common()))
