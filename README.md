# defi-vuln-rag

One coding agent tries to prove a BSC victim is exploitable by an unprivileged attacker. It keeps a single context and emits one JSON tool call per turn. Success is not the model's to declare: a Foundry fork test passes only when `confirm.py` accepts its attacker net-value invariant.

## Loop

Entry point is `loop_agent.py`.

Each turn the model (`AGENT_MODEL` or `CODE_MODEL`, default `anthropic/claude-sonnet-4.5`, via OpenRouter) returns one JSON action. The tool result is appended to the same transcript. The loop stops when a `rerun` passes the external verifier, or when the turn budget (`MAXR`, default 15) runs out. The pinned head — objective, live `cast` context, verified-source preview, paradigm hints, pitfalls — stays for the whole case. Only the transcript tail is windowed (`AGENT_CTX_CHARS`).

One tool per turn:

| tool | what it does |
|---|---|
| `read_source` | grep or line-range over the Etherscan-verified source and its files |
| `inspect_state` | `cast` `call` / `balance` / `storage` / `code` at the fork block |
| `probe` | one-off mini fork test (`testProbe` + `console2`); exploration only |
| `rerun` | full `.sol` → `confirm.inject_confirm` → `write_proj` → `forge -vvvv` |
| `edit_plan` | check, add, or replace items on the `plan.md` checklist |

`read_source`, `inspect_state`, and `probe` never finish the goal. A "giving up" phrase is detected and answered with a continuation nudge; it is not a terminal outcome.

## External criterion

`confirm.py` injects the acceptance test and does not call a model. After `setUp()` it snapshots attacker-controlled balances — the test contract plus every contract it `CREATE`s — and prices, runs the exploit body, then requires:

```
net = Σ (a1 − a0) × px_snapshot  >  LOOP_MIN_GAIN
```

Prices are the pre-attack snapshot, so a crash the attack itself causes cannot shrink the loot's valuation. Prefunded working capital is already in `a0` and nets out. Tracked assets are native BNB, WBNB, USDT, BUSD, up to four extra ERC-20s named in the test, and `token0()` / `token1()` when the victim answers those calls. Default `LOOP_MIN_GAIN_WEI` is `10**16` (0.01 base unit). The only terminal success is `outcome: verified`, when that `forge` rerun returns passed.

`setUp()` follows the SETUP SKELETON in the system prompt: fork BSC at the case block, `deal` only base assets (BNB, WBNB, USDT) before the snapshot, and buy any exotic token through the DEX. `deal()` inside a `test*` function, or after the snapshot, is rejected before forge runs.

## Steering inside the same loop

These shape the next action. None of them can accept a result.

- **`plan.md`.** A `## Task checklist` of `- [ ]` items. Each turn the first unchecked item is the next-step nudge. The agent updates it with `edit_plan`.
- **Advisory RAG.** `index.retrieve_refs` (no embeddings; Jev scores historical paradigms against the victim surface) injects hints and seeds extra checklist items. The case under test is excluded. The hints are paradigms, not a PoC for this contract.
- **Stall, strategist, reverify.** The same failure fingerprint on two `rerun`s in a row stalls. A separate read-only strategist pass then recommends a structural change of approach. It snapshots `plan.md` and restores those bytes afterward, so it cannot rewrite the checklist. Turns with no `rerun` accumulate reverify pressure; after `FORCE_RERUN_AFTER` (default 5) any non-`rerun` action is refused until a real `rerun` is submitted. `RERUN_CAP` (default 5) forces one deep reflection — a stuck reread of this case's own summary, plus a strategist note — and a second exhausted cap stops the run.
- **Pitfalls and the lessons ledger.** A static pitfalls block (gated entrypoints, fee-on-transfer, v3 price limits, reentrancy order, callback funding, prefunded capital, swap sizing) is advisory and does not change the criterion. Each failed `rerun` is also distilled into one constant-scrubbed line, deduped by gap fingerprint, ring-capped (`LESSONS_K`), written to `lessons.md`, and re-shown every turn until that gap stops recurring.
- **`max_depth`.** Furthest funnel stage any `rerun` reached: `0` did not compile, `1` reverted at runtime before the confirm assert, `2` hit `LOOP: attacker net value gain below threshold`, `3` verified. A timeout does not raise the depth. A depth-`0` submission can go through a cheap compile-fix subloop (`FIX_MODEL`) that sees only the current `.sol` and the compiler error, still on the same `inject_confirm` path.

## Corpus

`cases.jsonl` is the immutable corpus and is never written by the loop. The generator sees Etherscan-verified source (`fetch_source`) and live chain reads only. DeFiHackLabs PoC, README, and attack transactions are never fed in. RPC URLs and API keys are redacted from tool output.

Run targets are the `TARGETS` table in `loop.py`: victim address, fork block, and an optional separate logic-source address when the drained contract is not the contract that holds the bug. `loop_agent.py` imports that table.

## Run

Foundry `forge` and `cast`, plus `BSC_RPC`, `OPENROUTER_API_KEY`, and `ETHERSCAN_API_KEY` in the environment. Do not print them. Missing `BSC_RPC` exits immediately.

```
python loop_agent.py 20210817_XSURGE   # one TARGETS id
python loop_agent.py                   # every id in TARGETS (up to 4 at once)
```

Each case writes `data/loop_agent/<id>/` and a summary at `data/loop_agent/<id>.json` (`outcome`, `turns`, `max_depth`). The directory holds `transcript.md`, `tryN.raw.sol` for each submitted `rerun`, `plan.md` and `lessons.md` as the checklist and dead-end ledger are updated, and `VERIFIED.sol` when the run passes.
