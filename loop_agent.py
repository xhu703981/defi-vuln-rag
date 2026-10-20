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
import re, json, os, sys, subprocess, time, uuid
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
STRATEGY_MODEL = os.environ.get('STRATEGY_MODEL') or MODEL  # strategist reuses the agent model unless overridden

# =====================================================================================
# Grok Build verdict-stream mechanisms (faithfully reproduced from
# github.com/xai-org/grok-build  crates/codegen/xai-grok-shell/src/session/).
# All five are keyed to the EXTERNAL verifier verdict stream = confirm.py's forge rerun.
# A failed `rerun` (compile/revert/no-net-loss) is a `NotAchieved` verdict; a loop-confirmed
# rerun is `Achieved`. The agent's own narrative is NEVER a terminal signal (only a nudge).
# =====================================================================================

# goal_tracker.rs:13-21 — stall / strategist thresholds.
GOAL_CLASSIFIER_STALL_THRESHOLD = 2          # same-fingerprint repeats before a stall fires
GOAL_STRATEGIST_CAP_BONUS       = 3          # extra turn budget granted on a strategist fire
GOAL_STRATEGIST_STALL_THRESHOLD = GOAL_CLASSIFIER_STALL_THRESHOLD + GOAL_STRATEGIST_CAP_BONUS
GOAL_REVERIFY_AFTER = int(os.environ.get('GOAL_REVERIFY_AFTER', 3))  # dwell before reverify pressure
# goal_tracker.rs:455 consecutive_not_achieved + config.rs:2277 resolve_goal_strategist_every.
# SECOND strategist trigger: a cadence over the ALL-NotAchieved streak (ignores gap content),
# so whack-a-mole across DIFFERENT wrong branches (never the same fingerprint twice) still fires.
# Grok default = max(1, classifier_max_runs/2); our rerun budget stands in for the cap.
GOAL_STRATEGIST_EVERY = int(os.environ.get('GOAL_STRATEGIST_EVERY', 0)) or max(1, MAXR // 10)

# goal_strategist.rs:82 strategist_should_fire — skip-robust (>= last_fired + every, not strict %).
def strategist_should_fire(consecutive, last_fired, every):
    return every > 0 and consecutive >= last_fired + every

# acp_session_impl/goal_support.rs:229 — GOAL_CONTINUATION_BAIL_PREFACE (verbatim intent).
GOAL_CONTINUATION_BAIL_PREFACE = ("You appear to be stopping or handing off, but the goal is NOT "
    "complete and todos remain. Do not end the turn here — keep working.\n\n")

# ---- gap_fingerprint (goal_classifier.rs:995 + normalize_scratch_paths/extract_path_line_tokens) ----
# Operates on the undecorated failure evidence: normalize the revert reason / net-loss shortfall,
# strip per-attempt noise (scratch paths, addresses, gas, line numbers, raw integers), then
# sort+dedup+lowercase tokens so an identical gap maps to one fingerprint regardless of ordering.
_FP_ADDR = re.compile(r'0x[0-9a-fA-F]{6,}')
_FP_SRCLINE = re.compile(r'[^\s:]+\.sol:\d+(?::\d+)?')
_FP_GAS = re.compile(r'gas[:=]?\s*\d+', re.I)
_FP_SCRATCH = re.compile(r'/(?:tmp|var/folders|private/tmp|workspace/[^\s]*/(?:try|probe)\S*)')
_FP_NUM = re.compile(r'\b\d+\b')

def gap_fingerprint(reason, trace):
    """Mirror grok-build gap_fingerprint(): a stable signature of the failure 'gap'."""
    ev = [reason or '']
    for ln in (trace or '').splitlines():
        if re.search(r'revert|\[FAIL|\[Revert|panic|Error \(|assert|net.?loss|EvmError|'
                     r'does not have|insufficient|overflow|underflow|arithmetic', ln, re.I):
            ev.append(ln.strip())
    text = '\n'.join(ev)
    text = _FP_SCRATCH.sub('<scratch>', text)
    text = _FP_SRCLINE.sub('<src>', text)
    text = _FP_ADDR.sub('<addr>', text)
    text = _FP_GAS.sub('gas', text)
    text = _FP_NUM.sub('<n>', text)
    toks = sorted({t.strip().lower() for t in re.split(r'\s+', text) if t.strip()})
    return '\n'.join(toks)

# ---- premature-stop detector (goal_stop_detector.rs) ----
# Anchored (^) regexes scanned ONLY over the last non-empty paragraph of the agent's turn text.
# A hit means the agent is trying to bail/declare-cannot; it is a NUDGE trigger, never terminal.
_STOP_SRCS = [
    ('unable_to_proceed', r"^i (?:can(?:'?t|not)|am unable to) (?:proceed|continue|make (?:any )?progress|complete|fix this|exploit|do (?:this|it)|find)\b"),
    ('giving_up',         r"^(?:giving up|i(?:'m| am) giving up|the task is not actionable|this is a dead[- ]?end|dead[- ]?end\b)"),
    ('not_exploitable',   r"^(?:this (?:contract|victim) is (?:not|safe)|(?:the )?(?:contract|victim) is not exploitable|not exploitable|no (?:viable )?exploit|genuinely (?:cannot|can'?t|not))\b"),
    ('stopping_here',     r"^(?:stopping here|i've stopped here|i will stop|parked (?:the|this)|paused here)"),
    ('verdict_line',      r"^verdict: (?:pass|fail)\b"),
    ('check_back_later',  r"^(?:i will|i'll|will) (?:check back|re-?check|try again|retry|re-?run later)\b"),
]
_STOP_RES = [(lbl, re.compile(src, re.I)) for lbl, src in _STOP_SRCS]
# cannot-class labels: self-declared inability. Gated by GoalClassifierNudge (needs a real attempt).
_CANNOT_LABELS = {'unable_to_proceed', 'giving_up', 'not_exploitable', 'verdict_line'}

def last_non_empty_paragraph(text):
    paras = [p.strip() for p in (text or '').replace('\r\n', '\n').replace('\r', '\n').split('\n\n')]
    paras = [p for p in paras if p]
    return paras[-1] if paras else None

def matched_stop_pattern(text):
    """goal_stop_detector::matched_stop_pattern — ^-anchored, last paragraph only."""
    para = last_non_empty_paragraph(text)
    if not para:
        return None
    for line in (ln.strip() for ln in para.split('\n') if ln.strip()):
        for lbl, rx in _STOP_RES:
            if rx.search(line):
                return lbl
    return None

# ---- dwell-escalating reverify block (goal_support.rs:476 render_goal_reverify_block) ----
def render_goal_reverify_block(rounds_since_verify, refuted, threshold=GOAL_REVERIFY_AFTER):
    if (not refuted) or rounds_since_verify < threshold:
        return ''
    lead = ("STOP DRIFTING — PROVE THE REMAINING NET-LOSS GAP NOW."
            if rounds_since_verify >= threshold * 3
            else "Re-run the exploit attempt before continuing.")
    return (f"{lead} You have run {rounds_since_verify} rounds since the last confirmed "
            f"net-loss. The loop evaluates completion (confirm.py net-loss) after every rerun. "
            f"Fix the SINGLE concrete gap blocking net-loss rather than switching approaches or "
            f"making cosmetic edits.\n\n")

# ---- strategist (goal_strategist.rs + goal_strategist_prompt.md) ----
# A SEPARATE read-only pass that reads the FULL accumulated context (every PoC .sol, every
# -vvvv trace, plan.md, the RAG paradigm hits) and writes ONE structural 'change the HOW'
# recommendation. It must NOT touch plan.md (PlanGuard restores it byte-for-byte).
# ---- strategist (goal_strategist.rs + goal_strategist_prompt.md), DECISION via Jev ----
# A SEPARATE read-only pass fired on the verdict stream (same-fingerprint stall OR the
# consecutive_not_achieved cadence). It must change the HOW, never the WHAT, and must NOT edit
# plan.md (PlanGuard restores it byte-for-byte). Jev is the DECISION-MAKER here (cheap/fast,
# like index.retrieve_refs): it SCORES each candidate structural root-cause against the full
# accumulated failure context and we render the top pick into the advisory note. The generative
# coder model is never used for this judgment.
STRUCTURAL_DIAGNOSES = [
    {'key': 'wrong_entrypoint',
     'diag': 'Fixating on one entrypoint: the real value-leak is through a DIFFERENT unprivileged state-changing entrypoint that the attempts never exercise.',
     'fix': 'Pivot to a DIFFERENT unlocked state-changing entrypoint (e.g. the buy/mint/purchase/claim path), not the function you keep re-hitting; drive the leak through THAT one.'},
    {'key': 'reentrancy_wrong_target',
     'diag': 'The re-entry is aimed at a guarded/locked function; the exploitable re-entry is into an UNLOCKED path that mutates balances/supply while the outer call is mid-flight.',
     'fix': 'In the callback, re-enter the UNLOCKED path that changes balances/supply (often buy/mint) BEFORE the outer call settles its state (debit/burn) — not the locked transfer/sell you keep targeting.'},
    {'key': 'missing_precondition',
     'diag': 'A precondition (holding the spent token, an approval, or a flipped state flag) is never actually established on-chain before the attack action, so the leak step is a silent no-op.',
     'fix': 'Establish the missing precondition FIRST — acquire a non-zero balance via the real buy/mint/add-liquidity path and assert balanceOf>0 (plus approvals/state flips, each asserted) — then the attack step in one rerun.'},
    {'key': 'wrong_poc_shape',
     'diag': "The PoC's shape can never express a net value-leak (selling/transferring zero, or a fair round-trip that just pays fees both ways).",
     'fix': 'Restructure so the attacker ends holding MORE victim asset value than it paid in; nest the steps so the victim debit/burn happens while an inflated credit to the attacker is still pending.'},
    {'key': 'fair_value_dead_end',
     'diag': 'The chain only performs fair swaps/round-trips (paying both-side fees), which can never net-profit no matter how it is tuned.',
     'fix': 'Abandon the fee-paying buy/sell loop entirely; find a path that moves a victim asset to the attacker WITHOUT equal payment (ordering bug, price/reserve skew, reward/supply timing).'},
]

def _strategist_state(consecutive_failures, objective, plan_md, rerun_history):
    reasons = [r for (_, _, _, r) in rerun_history][-8:]
    last_poc = rerun_history[-1][1][-2500:] if rerun_history else ''
    last_trace = rerun_history[-1][2][-2500:] if rerun_history else ''
    return {
        'objective': (objective or '')[:800],
        'rounds_failed_in_a_row': consecutive_failures,
        'failure_verdicts_recent': reasons,
        'distinct_failure_classes': sorted(set(reasons)),
        'plan': (plan_md or '')[:1500],
        'last_poc_sol': last_poc,
        'last_forge_trace': last_trace,
    }

def run_strategist(D, consecutive_failures, objective, plan_md, hints, rerun_history):
    """Separate read-only strategist pass; Jev decides the root-cause pivot. Returns note text or ''.
    PlanGuard: snapshot plan.md bytes before, restore after (strategist must never alter the contract)."""
    plan_path = D / 'plan.md'
    plan_snapshot = plan_path.read_bytes() if plan_path.exists() else None
    note = ''
    try:
        from llm import jev
        state = _strategist_state(consecutive_failures, objective, plan_md, rerun_history)
        cand = list(STRUCTURAL_DIAGNOSES)
        # RAG paradigms the loop has NOT converged on become extra candidate pivots (KEY FEATURE kept).
        rag_lines = [ln[2:].strip() for ln in (hints or '').splitlines() if ln.strip().startswith('-')]
        for i, ln in enumerate(rag_lines[:6]):
            cand.append({'key': f'rag{i}',
                         'diag': f'An available attack paradigm is being ignored: {ln}',
                         'fix': f'Evaluate and, if the victim exposes it, pivot the exploit to this paradigm: {ln}'})
        Q = {c['key']: {'type': 'noul', 'instructions':
             ('Candidate structural root cause for why this exploit loop keeps FAILING the net-loss '
              'verifier round after round without converging: "' + c['diag'] + '" '
              'Given state (the objective, the recent failure verdicts, the last PoC and forge trace), '
              'how strongly does THIS explain the stall and name the pivot most likely to finally reach '
              'victim net-loss? Answer high ONLY if the traces/PoC actually show this pattern.')}
             for c in cand}
        ans = jev(state, Q)
        scored = sorted(((float((ans.get(c['key']) or {}).get('noul', 0) or 0), c) for c in cand),
                        key=lambda x: -x[0])
        top = scored[0][1] if scored else None
        if top:
            runners = '; '.join(f"{c['key']}={p:.2f}" for p, c in scored[:4])
            note = (
                '# Strategy: why the goal is stuck and how to unstick it\n\n'
                '## Diagnosis\n' + top['diag'] + '\n'
                f'(Jev root-cause scores: {runners})\n\n'
                '## Recommended restructure\n'
                '1. ' + top['fix'] + '\n'
                '2. Implement its PRECONDITIONS first (acquire/hold the spent token via the real '
                'buy/mint path and assert balanceOf>0, plus any approvals/state flips, each asserted), '
                'THEN the leak step — all in ONE rerun.\n\n'
                '## Why this converges\n'
                'Changing the HOW (the entrypoint / PoC shape) rather than the objective opens the '
                'net-loss window the previous attempts, stuck cycling across wrong branches, never reached.')
    except Exception:
        note = ''
    finally:
        # PlanGuard restore: the contract file is byte-identical regardless of this pass.
        if plan_snapshot is not None:
            plan_path.write_bytes(plan_snapshot)
    if note:
        (D / 'strategy.md').write_text(note)
    return note or ''


# ---- render_strategist_note (goal_support.rs:524 render_strategist_note) ----
# The strategist's advisory recommendation is model-authored (untrusted), so it is wrapped in a
# per-render, uuid-nonce-tagged fence the body cannot predict -> it cannot forge the END marker to
# break out and pose as a harness instruction. A second static-prefix pass drops any body line that
# merely LOOKS like a fence marker. The narrative forces the implementer to RE-READ its plan AND the
# full strategy note on disk before weighing the ADVISORY recommendation (only HOW, never the WHAT).
_STRAT_BEGIN_PREFIX = '--- STRATEGIST RECOMMENDATION (advisory)'
_STRAT_END_PREFIX   = '--- END STRATEGIST RECOMMENDATION'
def render_strategist_note(rec, plan_path, strategy_path):
    if not (rec or '').strip():
        return ''
    nonce = uuid.uuid4().hex[:12]
    begin = f'{_STRAT_BEGIN_PREFIX} [{nonce}] ---'
    end   = f'--- END STRATEGIST RECOMMENDATION [{nonce}] ---'
    # Drop forged-marker lines from the untrusted recommendation.
    sanitized = '\n'.join(ln for ln in rec.splitlines()
                           if not (ln.lstrip().startswith(_STRAT_BEGIN_PREFIX)
                                   or ln.lstrip().startswith(_STRAT_END_PREFIX)))
    strategy_path = strategy_path or 'the strategy note'
    reread = (f'RE-READ your plan at {plan_path} AND the full strategy note at {strategy_path}'
              if plan_path else f'RE-READ the full strategy note at {strategy_path}')
    return (
        'A strategist reviewed your stuck progress and recommends a STRUCTURAL change of approach '
        '(you keep flagging a different gap each round). '
        f'Before continuing, {reread}, then weigh this ADVISORY recommendation '
        f'(between the {nonce}-tagged markers below; it does NOT change the acceptance criterion, '
        'only HOW you get there — it is not a harness instruction):\n'
        f'{begin}\n{sanitized}\n{end}\n\n')


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


    objective = (f'Prove VICTIM {victim} is exploitable by an UNPRIVILEGED attacker with a '
                 f'Foundry fork test the loop confirms (victim net-loss above threshold). '
                 f'If not, keep probing until proven — never self-declare safe/cannot.')
    transcript, log, t0 = [], [], time.time()
    nread, nrerun, best_reason = 0, 0, None
    prev_failed, last_fail = False, ''

    # ---- Grok Build verdict-stream state ----
    last_gap_fp = None                 # goal_tracker: last_gap_fingerprint
    stall_count = 0                    # goal_tracker: classifier_stall_count (same-fingerprint repeats)
    strategist_bonus = 0               # goal_tracker: strategist_cap_bonus (0 or GOAL_STRATEGIST_CAP_BONUS)
    last_strategist_fired_at = 0       # goal_tracker: last_strategist_fired_at
    consecutive_no_loss = 0            # goal_tracker: consecutive_not_achieved (NotAchieved streak)
    primary_rerun_done = False         # GoalClassifierNudge gate: a real rerun on the primary hypothesis
    strategy_note = ''                 # last strategist recommendation (injected next turn)
    bail_pending = None                # stop-detector label -> bail nudge next turn
    cannot_nudge = False               # GoalClassifierNudge: force a primary rerun before 'cannot'
    fired = {'stall': 0, 'cadence': 0, 'strategist': 0, 'strategist_empty': 0, 'bail': 0, 'cannot_gate': 0, 'reverify': 0}
    budget = MAXR                      # dynamic turn budget (strategist fire adds GOAL_STRATEGIST_CAP_BONUS)
    rerun_history = []                 # (round, sol, trace, reason) — the FULL context the strategist reads

    rnd = 0
    while rnd < budget:
        rnd += 1
        nxt = next_unchecked(plan_items)
        refuted = consecutive_no_loss >= 1
        # Mode B bail preface (goal_support.rs GOAL_CONTINUATION_BAIL_PREFACE) — re-serve next item.
        preface = GOAL_CONTINUATION_BAIL_PREFACE if bail_pending else ''
        # Mode 5 dwell-escalating reverify pressure (render_goal_reverify_block).
        reverify = render_goal_reverify_block(consecutive_no_loss, refuted)
        if reverify: fired['reverify'] += 1
        nudge = ('\n\n# PLAN (plan.md)\n' + render_plan(plan_items)
                 + (f'\n\n[next unchecked] {nxt["id"]}: {nxt["text"]}' if nxt else '\n\n[plan] all items checked — if not yet confirmed, add the next concrete step.'))
        if reverify:
            nudge += '\n[reverify] ' + reverify.strip()
        # Mode A strategist note: render nonce-fenced at injection time and place it at the TOP of the
        # nudge (goal_continuation_directive.md: {strategist_note} sits ABOVE {reverify_block}/next-step),
        # so it is a high-salience, one-time interrupt — not a bottom-of-prompt wallpaper note.
        delivered_rec = strategy_note if strategy_note else None
        if delivered_rec:
            strat_block = render_strategist_note(delivered_rec, str(D / 'plan.md'), str(D / 'strategy.md'))
            if strat_block:
                nudge = '\n\n' + strat_block.rstrip('\n') + nudge
        if preface:
            nudge = '\n\n' + preface + nudge.lstrip('\n')
        # Mode 4 GoalClassifierNudge: 'cannot' is not eligible until a real primary rerun ran.
        if cannot_nudge:
            nudge += ('\n[classifier-nudge] You signalled you cannot proceed, but you have NOT run a '
                      'single rerun on the primary hypothesis. "cannot" is NOT acceptable yet — implement '
                      'the primary chain (preconditions first) and submit a rerun THIS turn.')
            fired['cannot_gate'] += 1
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
        # consume_strategist_note (goal.rs:1391): compare-and-clear once the directive is committed for
        # delivery, so the note shows in EXACTLY ONE turn; a fresh note only on a strategist re-fire.
        if delivered_rec is not None and strategy_note == delivered_rec:
            strategy_note = ''

        out = gen_model(MODEL, prompt, temp=TEMP)
        # Mode B premature-stop detector over the RAW turn text (anchored, last paragraph only).
        stop_lbl = matched_stop_pattern(out)
        act = _parse_action(out)
        tool = act.get('tool')
        reflect = str(act.get('reflect') or '').strip()
        if reflect: log.append(('reflect', reflect[:400]))
        echo = {k: act[k] for k in act if k not in ('sol', 'body')}
        if 'sol' in act: echo['sol'] = f'<full .sol, {len(act.get("sol") or "")} chars>'
        if 'body' in act: echo['body'] = f'<probe body, {len(act.get("body") or "")} chars>'
        transcript.append(f'[turn {rnd}] you: {json.dumps(echo, ensure_ascii=False)[:1200]}')
        prev_failed, last_fail = False, ''
        bail_pending, cannot_nudge = None, False
        # Evaluate the stop signal: it is a NUDGE, never terminal.
        if stop_lbl and (not primary_rerun_done) and stop_lbl in _CANNOT_LABELS:
            cannot_nudge = True      # GoalClassifierNudge gate wins: force a primary rerun first
            log.append(('cannot_gate', stop_lbl))
        elif stop_lbl:
            bail_pending = stop_lbl  # refuse to end: bail preface + re-serve next item next turn
            fired['bail'] += 1
            log.append(('bail', stop_lbl))
            transcript.append(f'[loop] premature-stop pattern "{stop_lbl}" detected — NOT terminal; continuing.')

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
            # A rerun that actually executed = a real attempt on the primary hypothesis (unlocks 'cannot').
            primary_rerun_done = True
            trace_for_ctx = _trace_for_agent(fo)
            rerun_history.append((rnd, sol[:6000], trace_for_ctx, reason))
            if ok:
                # Achieved: the EXTERNAL verifier accepted it. Only terminal success.
                (D / 'VERIFIED.sol').write_text(sol)
                (D / 'transcript.md').write_text('\n\n'.join(transcript))
                return {'id': cid, 'outcome': 'verified', 'turns': rnd, 'rounds': rnd,
                        'sec': round(time.time() - t0), 'log': log, 'nread': nread, 'nrerun': nrerun,
                        'refs': refs_used, 'sol': sol[:400], 'mech': fired}
            # NotAchieved verdict -> drive the counters (goal_tracker).
            prev_failed = True
            last_fail = 'compile error' if reason == 'compile error' else f'forge {reason}'
            consecutive_no_loss += 1                              # record_not_achieved_streak
            fp = gap_fingerprint(reason, fo)                      # gap_fingerprint
            # record_classifier_stall: same fingerprint -> increment, else reset to 1.
            if last_gap_fp == fp:
                stall_count += 1
            else:
                last_gap_fp = fp; stall_count = 1
            threshold = GOAL_STRATEGIST_STALL_THRESHOLD if strategist_bonus > 0 else GOAL_CLASSIFIER_STALL_THRESHOLD
            stalled = stall_count >= threshold
            # SECOND Grok Build counter (goal_tracker.rs:455 consecutive_not_achieved +
            # goal_strategist.rs:82 strategist_should_fire): fire on a CADENCE of the all-NotAchieved
            # streak, independent of gap content. This is what catches whack-a-mole ACROSS different
            # wrong branches (XSURGE alternated no-profit/no-loss, so the same-fingerprint stall never
            # tripped). Skip-robust `>= last_fired + every` (not strict `%`).
            cadence_fire = strategist_should_fire(consecutive_no_loss, last_strategist_fired_at, GOAL_STRATEGIST_EVERY)
            trigger = 'stall' if stalled else ('cadence' if cadence_fire else '')
            transcript.append(f'[result rerun] forge FAILED ({last_fail}); saved try{rnd}.raw.sol. '
                              f'[no-loss streak {consecutive_no_loss}, gap-repeat {stall_count}/{threshold}, '
                              f'strategist cadence every {GOAL_STRATEGIST_EVERY} (last fired @{last_strategist_fired_at})]\n'
                              f'--- forge -vvvv trace ---\n{trace_for_ctx}')
            # Mode A: fire the SEPARATE strategist on EITHER trigger. claim_strategist_fire guard:
            # never double-fire on the identical consecutive streak value. The cadence trigger already
            # implies consecutive_no_loss > last_strategist_fired_at, so the guard only constrains stall.
            if trigger and consecutive_no_loss != last_strategist_fired_at:
                last_strategist_fired_at = consecutive_no_loss    # claim_strategist_fire
                if strategist_bonus == 0:                          # idempotent, not stacked (goal_tracker.rs:1125)
                    budget += GOAL_STRATEGIST_CAP_BONUS            # budget bonus, granted once
                strategist_bonus = GOAL_STRATEGIST_CAP_BONUS       # raises the stall threshold
                # reset_classifier_stall_fields
                last_gap_fp = None; stall_count = 0
                fired[trigger] = fired.get(trigger, 0) + 1
                log.append(('strategist', f'fire[{trigger}]@streak{consecutive_no_loss}'))
                note = run_strategist(D, consecutive_no_loss, objective,
                                      render_plan(plan_items), hints, rerun_history)
                if note:
                    strategy_note = note
                    fired['strategist'] += 1
                else:
                    # produced nothing -> revoke the cap bonus (goal_tracker.revoke_strategist_cap_bonus).
                    if strategist_bonus:
                        budget -= GOAL_STRATEGIST_CAP_BONUS
                    strategist_bonus = 0
                    fired['strategist_empty'] += 1
                    log.append(('strategist', 'empty->revoked'))
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
    return {'id': cid, 'outcome': 'over_budget', 'turns': rnd, 'rounds': rnd,
            'sec': round(time.time() - t0), 'log': log, 'nread': nread, 'nrerun': nrerun,
            'refs': refs_used, 'last_reason': best_reason, 'mech': fired}


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
