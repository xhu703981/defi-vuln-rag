# defi-vuln-rag

Goal-driven DeFi smart-contract auditor loop (3 steps):

1. Fetch verified source (Etherscan, follow proxy) + live `cast` reads of mutable on-chain state at the fork block.
2. Strong LLM (`gemini-2.5-pro` via `llm.gen_model`) proposes an attack and writes a Foundry fork test.
3. `forge` confirms: victim asset balance drops AND the same asset moves into an attacker-controlled address.

Agent loop (`loop.py`) follows Grok Build's turn style: one tool call per round (`read_chain` / `run_test` / `declare_no_risk`), tool result fed back into history, until VERIFIED, NO_RISK, or `MAXR` (default 4).

```
.venv/bin/python loop.py 20210817_XSURGE          # one case
.venv/bin/python loop.py                          # all TARGETS in loop.py
```

Requires `BSC_RPC`, `OPENROUTER_API_KEY`, `ETHERSCAN_API_KEY` in the environment (never printed). `cases.jsonl` is the immutable corpus (md5 `31f88a35e14b2d73b23a99c66e2ca145`); never feed PoC/README/attack-tx to the generator.

Kept: `loop.py`, `fetch_source.py`, `llm.py`, `verify_ctx.py`, `rag_utils.py`, `cases.jsonl`, `iterations.md`, `README.md`, `data/` (caches + loop runs), `DeFiHackLabs/` (corpus source, post-hoc only).
