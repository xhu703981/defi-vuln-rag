# Index artifacts (cases.jsonl is NEVER written)

`cases.jsonl` md5 must stay `31f88a35e14b2d73b23a99c66e2ca145`.

## summaries_generated.jsonl
Sidecar summaries for cases whose `summary` field was empty. Fallback signal for indexing:
`(cases.summary) or (sidecar.summary) or (root_cause) or (existing paradigm)`.

Regenerate / resume: `python3 gen_summaries.py` (skips ids already present).
Model: `deepseek/deepseek-v3.2` (override with `SUM_MODEL=`).

## subclasses.jsonl
Per-case closed subclass chosen by Jev (`llm.jev` choice) from `taxonomy.TAXONOMY`
within the case's existing top `category` (category is never changed).

## paradigms_v2.jsonl
Paraphrased transferable paradigm sentences (DeepSeek V3.2), conditioned on
subclass + richer signal.

## catalogue.jsonl
Built by `python3 index.py build [--force]`. Each row:
`id, date, chain, category, subclass, loss_short, paradigm, tags`.

Retrieve: `python3 index.py retrieve <case_id>` (excludes query_id; diversifies
by subclass so generic classes cannot flood top-k).
