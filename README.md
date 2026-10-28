# defi-vuln-rag

Single-model DeFi exploit-writing pipeline. The active entrypoint is **`minimal_agent.py`**.

## Pipeline (`minimal_agent.py`)

Four model steps, then verify (up to 3 rounds, each retry feeds the prior code + error back):

1. **READ SOURCE** — verified Etherscan source (never a DeFiHackLabs PoC).
2. **READ CONTEXT** — assemble info layers 1–9 (case def, verified source, live on-chain reads,
   compile-safe skeleton, precise IVictim interface, transfer-constraint warnings, DEX reference,
   common PoC pitfalls, RAG paradigms).
3. **PLAN** — one LLM call: attack plan in prose (mechanism/strategy, not code).
4. **WRITE CODE** — one LLM call: fill the attack body into the pinned compile-safe skeleton.
5. **VERIFY** — `inject_confirm` → `write_proj` → `forge` → parse reason + depth. Up to
   `MINIMAL_ROUNDS` rounds; stops on VERIFIED.

## Run

```
python3 minimal_agent.py 20210817_XSURGE     # one case id (see loop.TARGETS)
```

Env vars:

- `MINIMAL_MODEL` (default `deepseek/deepseek-v4.1-flash`; falls back to `SIMPLE_MODEL`)
- `MINIMAL_ROUNDS` (default `3`) — max write→verify rounds
- `USE_RAG` (default `1`; set `0` to disable RAG paradigm retrieval)
- `MINIMAL_TEMP` (default `0.15`)

Requires `BSC_RPC`, `OPENROUTER_API_KEY`, `ETHERSCAN_API_KEY` in the environment (never printed).

## Layout

- `minimal_agent.py` — **the** agent entrypoint.
- Shared libraries imported by it: `loop.py` (TARGETS/parse_target), `verify_ctx.py`,
  `confirm.py`, `index.py` (RAG), `llm.py`, `rag_utils.py`, `taxonomy.py`, `fetch_source.py`.
- `simple_agent.py`, `loop_agent.py`, `loop_roles.py` — **helpers-only / demoted**. Kept solely
  as library modules that `minimal_agent` imports; not active entrypoints, do not run directly.
- `cases.jsonl` — immutable corpus (md5 `31f88a35e14b2d73b23a99c66e2ca145`); never feed
  PoC/README/attack-tx to the generator.
- `confirm.py` — immutable verifier (md5 `4ac9ce4e2685b16231629c64c3309209`).
- `data/` — caches + run artifacts (untracked except `data/index/`).
