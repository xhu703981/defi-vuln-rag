# Single-agent, goal-driven exploit loop — modeled on Grok Build (github.com/xai-org/grok-build).
#
# Grok Build's design we mirror here:
#   * ONE agent, ONE continuous (non-truncated) context; it drives everything via ONE JSON
#     action per turn, result fed back, until an external verifier accepts it or budget runs out.
#   * plan.md on disk with a `## Task checklist` of `- [ ]` items (its `todo`/`update_goal` tools);
#     each turn we surface the FIRST unchecked item as the next-step nudge; the agent edits it.
#   * Completion is gated EXTERNALLY (its `update_goal` completion is validated by a classifier the
#     agent cannot fake). Here the external gate is confirm.py's injected net-loss criterion, run via
#     forge — the agent CANNOT self-declare success; terminal success = a rerun the confirm wrapper
#     validates. Feedback accumulates in one context + on disk.
#
# Tools the agent calls, one per turn (replacing loop_roles.py's Planner/Coder/Reflector/Final):
#   read_source   {query|grep|range}  — grep/slice the VERIFIED on-chain source + its deps (NOT the PoC)
#   inspect_state {call}               — cast call/balance/storage/code at the fork block, UNCAPPED
#   probe         {body}               — one-off mini forge test body (fork + console2), exploration only
#   rerun         {sol}                — full .sol -> confirm.inject_confirm -> write_proj -> forge -vvvv (terminal gate)
#   edit_plan     {ops}                — tick/add/replace the plan.md checklist
#
# Entry (heuristic HINTS, not roles): verify_ctx.build_context + verified source, PLUS the Jev
# vectorless-RAG paradigms (index.retrieve_refs) injected as an advisory hints block and seeded into
# the plan.md checklist. THE RAG REFERENCE IS THE KEY FEATURE — kept.
#
# Safety: never reads DeFiHackLabs PoC/README (only Etherscan-verified source); RPC/keys never printed
# (confirm.redact / verify_ctx.cast redact); cases.jsonl never written; confirm.py + its net-loss
# criterion untouched and independent; RAG excludes the query case. No per-case special-casing.
import re, json, os, sys, subprocess, time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from llm import gen_model
import fetch_source as fs
import verify_ctx as vc
import index as idx
from confirm import (FORGE, THRESH, TO, redact, csum, bogus, inject_confirm, write_proj, parse_reason)

MODEL   = os.environ.get('AGENT_MODEL') or os.environ.get('CODE_MODEL') or 'anthropic/claude-sonnet-4.5'
MAXR    = int(os.environ.get('MAXR', 30))         # turn budget (each turn = one tool action)
USE_RAG = os.environ.get('USE_RAG', '1') != '0'
RAG_K   = int(os.environ.get('RAG_K', 5))
TEMP    = float(os.environ.get('AGENT_TEMP', '0.3'))
CTX_WINDOW = int(os.environ.get('AGENT_CTX_CHARS', 70000))  # sliding window over the TRANSCRIPT tail only
SRC_PREVIEW = int(os.environ.get('SRC_PREVIEW_CHARS', 6000))

SYS = '''You are a smart-contract exploit auditor working as ONE agent in a goal-driven loop (no teammates).
GOAL: decide if VICTIM is exploitable by an UNPRIVILEGED attacker and PROVE it with a Foundry fork test.

You act by replying EVERY turn with ONLY ONE JSON object — one tool call — then you get its result back and continue. The context is continuous: everything you and the tools have said so far is above. Investigate, form a hypothesis, implement it, read the real error, and iterate. There is NO "declare safe" / "give up" action and you CANNOT declare success yourself: the ONLY terminal success is a `rerun` that the loop's independent confirmation accepts.

TOOLS (exactly one per turn):
{"tool":"read_source","grep":"<regex>"}            # search the VERIFIED victim source + its dependency files
{"tool":"read_source","range":"<start>-<end>"}     # read those 1-indexed line numbers of the verified source
{"tool":"inspect_state","call":"<cast args>"}      # live read at the fork block, UNLIMITED. e.g. "call 0xADDR 'balanceOf(address)(uint256)' 0xWHO", or "balance 0xADDR", or "storage 0xADDR 5", or "code 0xADDR"
{"tool":"probe","body":"<solidity statements>"}    # EXPLORATION ONLY: your statements run inside testProbe() on the fork with console2 available; use it to try ONE sub-call / log an intermediate value. Never terminal.
{"tool":"rerun","sol":"<full forge-std .sol>"}     # the real attempt: your full test is wrapped with the loop's confirmation and run with forge -vvvv. A run the loop confirms = SUCCESS.
{"tool":"edit_plan","ops":[{"op":"check","id":"p1"},{"op":"add","text":"..."},{"op":"replace","items":[{"id":"p1","text":"...","done":false}]}]}

SELF-REFLECTION: if your previous action FAILED (a rerun that did not compile / reverted / failed confirmation, a probe revert, or a rejected action), add a "reflect" field BEFORE "tool": classify it (compile/syntax | wrong approach | almost-right needs fix) and name the concrete change you are making. Do not resend the same failing thing verbatim.

CONFIRMATION (enforced by the loop, injected into your test — do not re-implement it): victim LOSES some tracked asset AND the attacker GAINS some tracked asset (cross-asset OK) AND the value the victim lost exceeds the value it GAINED from you by more than %.1f%% — fair swaps and liquidity round-trips fail. Attacker sellability is NOT required.

TEST RULES for rerun:
- vm.createSelectFork("bsc", %d); VICTIM = %s (checksummed).
- ALL deal() funding ONLY in setUp(); testExploit() must NOT call deal().
- In testExploit: attack only, reading fees/mins/balances/prices LIVE (no hardcoded mutable constants).
- Prefer an assert-free body (the loop wraps it); require()s that assert your own preconditions are fine and encouraged.
- Only call functions that exist in the verified source. Use checksummed addresses.
- PRECONDITIONS FIRST: if your chain spends a victim/LP/share token (sell/transfer/redeem/burn), you MUST first ACQUIRE a NON-ZERO balance via the real buy/mint/add-liquidity path and assert balanceOf>0 before the attack action — selling/moving zero is a silent no-op. Implement approvals and any reserve/price/flag state-flip, each asserted, before the step that reads them.

WORKFLOW: keep plan.md current with edit_plan (tick an item when done, add newly-discovered steps). Use read_source/inspect_state/probe to SEE actual state instead of guessing; a wrong guess wastes a turn. The historical ATTACK PARADIGMS below are advisory hints (NOT this contract's PoC) — evaluate case-by-case whether this victim exposes each.'''

# ---------------- plan.md checklist (Grok Build `todo`) ----------------
def render_plan(items):
    L = ['## Task checklist']
    for it in items:
        L.append(f"- [{'x' if it['done'] else ' '}] ({it['id']}) {it['text']}")
    return '\n'.join(L)

def next_unchecked(items):
    for it in items:
        if not it['done']:
            return it
    return None

def apply_plan_ops(items, ops):
    msgs = []
    nextid = [max([int(re.sub(r'\D','',i['id']) or 0) for i in items] + [0]) + 1]
    def newid():
        i = nextid[0]; nextid[0] += 1; return f'p{i}'
    for op in (ops or []):
        if not isinstance(op, dict): continue
        kind = op.get('op')
        if kind == 'check' or kind == 'uncheck':
            tgt = str(op.get('id') or op.get('text') or '')
            hit = next((it for it in items if it['id'] == tgt or it['text'] == tgt), None)
            if hit: hit['done'] = (kind == 'check'); msgs.append(f"{kind} {hit['id']}")
            else: msgs.append(f"{kind}: no item {tgt}")
        elif kind == 'add':
            t = str(op.get('text') or '').strip()
            if t: items.append({'id': newid(), 'text': t, 'done': bool(op.get('done'))}); msgs.append(f"added {items[-1]['id']}")
        elif kind == 'replace':
            new = []
            for it in (op.get('items') or []):
                t = str(it.get('text') or '').strip()
                if t: new.append({'id': it.get('id') or newid(), 'text': t, 'done': bool(it.get('done'))})
            if new: items[:] = new; msgs.append(f"replaced ({len(new)} items)")
    return msgs or ['no-op']

# ---------------- forge: verbose trace for the agent + the terminal gate ----------------
def run_forge_verbose(d):
    """Run the injected test with -vvvv (full call tree + revert source + console2 logs), bigger tail.
    ok is derived EXACTLY as confirm.run_forge derives it (returncode 0 + 'N passed; 0 failed'); the
    net-loss criterion itself lives in the confirm.inject_confirm asserts, which are untouched."""
    try:
        r = subprocess.run([FORGE, 'test', '-vvvv', '--match-path', 'test/Attack.t.sol'],
                           cwd=d, capture_output=True, text=True, timeout=TO)
        out = redact(r.stdout + r.stderr)
        ok = r.returncode == 0 and bool(re.search(r'[1-9]\d* passed; 0 failed', out))
        return ok, out
    except subprocess.TimeoutExpired:
        return False, f'forge timeout {TO}s'

def _trace_for_agent(out):
    """Keep what the agent needs: compile errors in full-ish, else the tail with the call tree + logs."""
    if re.search(r'Compiler run failed|ParserError|Error \(\d+\)', out):
        errs = re.findall(r'(?:Error|ParserError)[^\n]*(?:\n[^\n]*){0,6}', out)
        head = '\n---\n'.join(errs[:6])
        return ('COMPILE ERRORS:\n' + head + '\n\n--- output tail ---\n' + out[-2500:])[:9000]
    return out[-9000:]

PROBE_TMPL = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";
import "forge-std/console2.sol";
interface IERC20{function balanceOf(address) external view returns(uint256);function transfer(address,uint256) external returns(bool);function approve(address,uint256) external returns(bool);function transferFrom(address,address,uint256) external returns(bool);}
contract Probe is Test {
    address constant VICTIM = %s;
    function setUp() public { vm.createSelectFork("bsc", %d); }
    function testProbe() public {
%s
    }
}
'''

# ---------------- verified source (NEVER the DeFiHackLabs PoC) ----------------
def load_full_source(victim):
    r = fs.get(56, victim)
    files = fs.files(r['SourceCode'])
    cname = r.get('ContractName', '')
    main = fs.main_code('\n'.join(files.values()), cname)[:48000]
    blocks = []
    for name, body in files.items():
        blocks.append(f'// ===== FILE: {name} =====\n{body}')
    full = '\n\n'.join(blocks)
    return main, full, cname

def read_source(full_lines, grep=None, rng=None):
    if rng:
        m = re.match(r'\s*(\d+)\s*[-: ]\s*(\d+)', rng)
        if not m: return 'ERR: range must be "start-end"'
        a, b = int(m.group(1)), int(m.group(2))
        b = min(b, a + 400, len(full_lines)); a = max(1, a)
        return '\n'.join(f'{i:>5}: {full_lines[i-1]}' for i in range(a, b + 1))[:9000]
    if grep:
        try: rx = re.compile(grep, re.I)
        except re.error as e: return f'ERR: bad regex: {e}'
        hits = [i for i, ln in enumerate(full_lines, 1) if rx.search(ln)]
        if not hits: return f'(no match for /{grep}/ in {len(full_lines)} lines)'
        out, shown = [], 0
        for i in hits[:80]:
            out.append(f'{i:>5}: {full_lines[i-1]}'); shown += 1
        tail = '' if len(hits) <= 80 else f'\n... (+{len(hits)-80} more matches; narrow the regex or use range)'
        return ('\n'.join(out) + tail)[:9000]
    return 'ERR: give grep or range'

def inspect_state(block, call):
    parts = (call or '').split()
    if not parts: return 'ERR: empty call'
    SUB = {'call', 'balance', 'storage', 'code'}
    if parts[0] not in SUB:
        parts = ['call'] + parts
    # checksum anything address-shaped
    parts = [csum(p) if re.match(r'0x[0-9a-fA-F]{40}$', p) else p for p in parts]
    v = vc.cast(block, *parts)
    return redact(v)[:1200]

def _parse_action(out):
    try: return json.loads(re.search(r'\{[\s\S]*\}', out).group(0))
    except Exception: return {}

def one(cid, victim, block, outdir):
    D = Path(outdir); D.mkdir(parents=True, exist_ok=True)
    victim = csum(victim)
    main_src, full_src, cname = load_full_source(victim)
    full_lines = full_src.split('\n')
    ctx = vc.build_context(block, victim, main_src)
    (D / 'CONTEXT.txt').write_text(ctx)

    # ---- RAG paradigms (advisory hints + seed checklist). KEY FEATURE. ----
    refs_used, hints = [], '(RAG disabled)'
    plan_items = [
        {'id': 'p1', 'text': 'Enumerate every unprivileged entrypoint on VICTIM and the contracts it routes value through; from CONTEXT + read_source, note who pays / who receives / what mutable state gates each.', 'done': False},
        {'id': 'p2', 'text': 'For each asset the victim actually holds at the fork block, find a function that can move it to an unprivileged caller WITHOUT equal payment (ordering bug, price/reserve skew, reentrancy, mint/burn, reward timing).', 'done': False},
        {'id': 'p3', 'text': 'Pick a candidate chain and list its PRECONDITIONS: acquire/hold the spent token via a working buy/mint path + assert balanceOf>0, approvals, state flips — each with its check.', 'done': False},
        {'id': 'p4', 'text': 'Implement preconditions (asserted) THEN the attack action in a rerun; read the -vvvv trace and fix the next concrete blocker.', 'done': False},
        {'id': 'p5', 'text': 'Get a rerun the loop confirms (victim net-loss above threshold).', 'done': False},
    ]
    if USE_RAG:
        try:
            refs = idx.retrieve_refs(ctx, main_src, query_id=cid, k=RAG_K)
        except Exception as e:
            refs, hints = [], f'(RAG error: {type(e).__name__}: {e})'
        if refs:
            refs_used = [{'id': r['id'], 'paradigm': r['paradigm'], 'score': r['score']} for r in refs]
            hints = '\n'.join(f"- [{r['category']}] {r['paradigm']}  ({r['why']})" for r in refs)
            for i, r in enumerate(refs, 1):
                plan_items.append({'id': f'r{i}', 'text': f"Evaluate paradigm — does this victim expose it? [{r['category']}] {r['paradigm']}", 'done': False})
        elif hints.startswith('(RAG error'):
            refs_used = [{'error': hints}]

    header = SYS % (THRESH * 100, block, victim)
    pins = (header
            + '\n\n# LIVE ON-CHAIN CONTEXT (fork block ' + str(block) + ', read via cast):\n' + ctx
            + f'\n\n# VERIFIED VICTIM SOURCE (contract {cname}; {len(full_lines)} lines across its files — PREVIEW below, use read_source grep/range for the rest):\n'
            + main_src[:SRC_PREVIEW] + ('\n...<preview truncated; read_source for more>' if len(main_src) > SRC_PREVIEW else '')
            + '\n\n# HISTORICAL ATTACK PARADIGMS (advisory hints only; NOT this contract\'s PoC):\n' + hints)

    transcript, log, t0 = [], [], time.time()
    nread, nrerun, best_reason = 0, 0, None
    prev_failed, last_fail = False, ''

    for rnd in range(1, MAXR + 1):
        nxt = next_unchecked(plan_items)
        nudge = ('\n\n# PLAN (plan.md)\n' + render_plan(plan_items)
                 + (f'\n\n[next unchecked] {nxt["id"]}: {nxt["text"]}' if nxt else '\n\n[plan] all items checked — if not yet confirmed, add the next concrete step.'))
        if prev_failed:
            nudge += (f'\n[reflect-required] Your previous action FAILED ({last_fail}). Add a "reflect" field BEFORE "tool": classify (compile/syntax | wrong approach | almost-right needs fix) and name the concrete change. Do NOT resend the same thing.')
        # sliding window over the transcript tail (pins + plan stay; oldest transcript drops)
        tbody, acc = [], 0
        for entry in reversed(transcript):
            acc += len(entry)
            if acc > CTX_WINDOW:
                tbody.append('...<older turns elided>...'); break
            tbody.append(entry)
        tbody = '\n\n'.join(reversed(tbody))
        prompt = pins + '\n\n# TRANSCRIPT (your turns + tool results)\n' + tbody + nudge + '\n\nYour next single JSON action:'

        out = gen_model(MODEL, prompt, temp=TEMP)
        act = _parse_action(out)
        tool = act.get('tool')
        reflect = str(act.get('reflect') or '').strip()
        if reflect: log.append(('reflect', reflect[:400]))
        echo = {k: act[k] for k in act if k not in ('sol', 'body')}
        if 'sol' in act: echo['sol'] = f'<full .sol, {len(act.get("sol") or "")} chars>'
        if 'body' in act: echo['body'] = f'<probe body, {len(act.get("body") or "")} chars>'
        transcript.append(f'[turn {rnd}] you: {json.dumps(echo, ensure_ascii=False)[:1200]}')
        prev_failed, last_fail = False, ''

        if tool == 'read_source':
            res = read_source(full_lines, grep=act.get('grep') or act.get('query'), rng=act.get('range'))
            log.append(('read_source', (act.get('grep') or act.get('range') or '')[:80]))
            transcript.append(f'[result read_source]\n{res}')
            prev_failed = res.startswith('ERR'); last_fail = 'read_source error'
            continue
        if tool == 'inspect_state':
            res = inspect_state(block, act.get('call'))
            nread += 1
            log.append(('inspect_state', redact(act.get('call') or '')[:80]))
            transcript.append(f'[result inspect_state] cast {redact(act.get("call") or "")} => {res}')
            prev_failed = res.startswith('ERR'); last_fail = 'inspect_state error'
            continue
        if tool == 'probe':
            body = (act.get('body') or '').strip()
            pd = D / 'probe'; pd.mkdir(parents=True, exist_ok=True)
            sol = PROBE_TMPL % (victim, block, body)
            (pd / 'probe.raw.sol').write_text(sol)
            write_proj(pd, sol)
            ok, fo = run_forge_verbose(pd)
            log.append(('probe', 'ran'))
            transcript.append(f'[result probe] (exploration only, never a confirmation)\n{_trace_for_agent(fo)}')
            prev_failed = not ok; last_fail = 'probe revert/compile' if not ok else ''
            continue
        if tool == 'rerun':
            nrerun += 1
            sol = re.sub(r'^```\w*\n?|```$', '', (act.get('sol') or '').strip(), flags=re.M)
            (D / f'try{rnd}.raw.sol').write_text(sol)
            why = bogus(sol)
            if why:
                transcript.append(f'[result rerun] REJECTED anti-cheat: {why}')
                log.append(('reject', why)); prev_failed = True; last_fail = 'anti-cheat reject'; continue
            sol2, err = inject_confirm(sol, victim)
            if err:
                transcript.append(f'[result rerun] REJECTED inject: {err}')
                log.append(('reject', err)); prev_failed = True; last_fail = 'inject reject'; continue
            (D / f'try{rnd}.sol').write_text(sol2)
            write_proj(D, sol2)
            ok, fo = run_forge_verbose(D)
            reason = parse_reason(ok, fo)
            best_reason = reason
            log.append(('rerun', reason))
            if ok:
                (D / 'VERIFIED.sol').write_text(sol)
                return {'id': cid, 'outcome': 'verified', 'turns': rnd, 'rounds': rnd,
                        'sec': round(time.time() - t0), 'log': log, 'nread': nread, 'nrerun': nrerun,
                        'refs': refs_used, 'sol': sol[:400]}
            prev_failed = True
            last_fail = 'compile error' if reason == 'compile error' else f'forge {reason}'
            transcript.append(f'[result rerun] forge FAILED ({last_fail}); test saved try{rnd}.raw.sol.\n--- forge -vvvv trace ---\n{_trace_for_agent(fo)}')
            continue
        if tool == 'edit_plan':
            msgs = apply_plan_ops(plan_items, act.get('ops'))
            (D / 'plan.md').write_text(render_plan(plan_items))
            log.append(('edit_plan', msgs))
            transcript.append(f'[result edit_plan] {", ".join(msgs)}\n{render_plan(plan_items)}')
            continue
        # unrecognized
        prev_failed = True; last_fail = 'unrecognized action'
        transcript.append('[result] Unrecognized. Reply ONLY one JSON tool: read_source | inspect_state | probe | rerun | edit_plan.')

    (D / 'plan.md').write_text(render_plan(plan_items))
    (D / 'transcript.md').write_text('\n\n'.join(transcript))
    return {'id': cid, 'outcome': 'over_budget', 'turns': MAXR, 'rounds': MAXR,
            'sec': round(time.time() - t0), 'log': log, 'nread': nread, 'nrerun': nrerun,
            'refs': refs_used, 'last_reason': best_reason}

# reuse the same TARGETS as loop.py
from loop import TARGETS

if __name__ == '__main__':
    if not os.environ.get('BSC_RPC'): print('BLOCKER: set BSC_RPC'); sys.exit(2)
    slug = lambda s: re.sub(r'\W+', '_', s)
    ids = sys.argv[1:] or list(TARGETS)
    def run_one(cid):
        v, b = TARGETS[cid]
        res = one(cid, v, b, f'data/loop_agent/{slug(cid)}')
        json.dump(res, open(f'data/loop_agent/{slug(cid)}.json', 'w'), ensure_ascii=False, indent=1)
        return {k: res[k] for k in res if k != 'log'}
    os.makedirs('data/loop_agent', exist_ok=True)
    with ThreadPoolExecutor(max_workers=min(4, len(ids))) as ex:
        futs = {ex.submit(run_one, cid): cid for cid in ids}
        for fut in as_completed(futs):
            cid = futs[fut]
            try: print(json.dumps(fut.result(), ensure_ascii=False), flush=True)
            except Exception as e:
                print(json.dumps({'id': cid, 'outcome': 'error', 'error': f'{type(e).__name__}: {e}'[:400]}, ensure_ascii=False), flush=True)
