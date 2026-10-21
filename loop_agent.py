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
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from llm import gen_model
import fetch_source as fs
import verify_ctx as vc
import index as idx
from taxonomy import TAXONOMY
from confirm import (FORGE, THRESH, TO, redact, csum, bogus, inject_confirm, write_proj, parse_reason)

MODEL   = os.environ.get('AGENT_MODEL') or os.environ.get('CODE_MODEL') or 'anthropic/claude-sonnet-4.5'
MAXR    = int(os.environ.get('MAXR', 15))         # TOTAL-turn ceiling (handle.rs max_turns analogue; each turn = one tool action)
# RERUN_CAP (grok-build goal_classifier.rs GOAL_CLASSIFIER_MAX_RUNS_DEFAULT=10 analogue): the max
# number of REAL forge verification reruns allowed before a mandatory deep reflection pass, kept
# INDEPENDENT of MAXR so it bounds hard-trying without inflating the total-turn budget. On hitting
# the cap the loop forces EXACTLY ONE deep reflection (stuck-reread + strategist); if a second full
# cap of reruns still does not confirm, it stops with a clear reason rather than grinding to MAXR.
RERUN_CAP = max(1, int(os.environ.get('RERUN_CAP', 5)))
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
# CHANGE 4 (early, skip-robust reread): the stuck-reread runs on its OWN cadence over the
# content-agnostic consecutive-NotAchieved streak, DECOUPLED from the strategist's
# last_strategist_fired_at (which the stall escalation pushes out to streak 5, so the strategist
# cadence only re-arms late and the reread, when chained to it, fired only on the last turn — the
# ORB bug). N small so the reread fires on the FIRST cadence hit; skip-robust `>= last_fired + N`.
GOAL_REREAD_EVERY = int(os.environ.get('GOAL_REREAD_EVERY', 2))
# ---- general operator knobs (env-driven; no per-case hardcoding, no exploit constants) ----
# ROUTE_HINT: an advisory, HOW-only route description the operator can pin so the agent spends
# its budget on PoC engineering rather than re-discovering a known-correct direction. It is a
# free-text method description (no addresses/amounts), injected as an advisory block + seeded as
# the top plan item. STRATEGIST_NO_REDIRECT: demote the strategist to NON-directional hints only
# (it may still advise precondition/poc-shape/fair-value/RAG pivots, but may NOT redirect the
# entrypoint). TRACE_CHARS: cap on the -vvvv trace tail fed back each rerun (raise for fuller traces).
ROUTE_HINT = (os.environ.get('ROUTE_HINT') or '').strip()
STRATEGIST_NO_REDIRECT = os.environ.get('STRATEGIST_NO_REDIRECT', '0') != '0'
TRACE_CHARS = int(os.environ.get('TRACE_CHARS', 9000))
# LESSONS_K: ring-cap on the number of distinct dead-end fingerprints kept in the lessons ledger.
LESSONS_K = int(os.environ.get('LESSONS_K', 6))
# FORCE_RERUN_AFTER: hard anti-paralysis gate. After this many CONSECUTIVE turns with NO actual
# rerun (rounds_since_rerun), the NEXT turn is FORCED to submit a PoC: any non-rerun action is
# refused unexecuted until a real forge rerun is submitted. Turns reflect-spin into execution
# feedback. 999 disables. The forced rerun counts into reruns_since_reflection (feeds RERUN_CAP).
FORCE_RERUN_AFTER = int(os.environ.get('FORCE_RERUN_AFTER', 5))
# RESUME_SEED (opt-in, default off): when on, one() loads the case's OWN prior-run accumulated
# knowledge (its lessons.md dead-ends + last failing PoC try*.raw.sol) at the START of the run and
# pre-populates the lessons ledger + a single synthetic transcript note, so the agent CONTINUES from
# where it got stuck instead of re-deriving from zero. It only ever re-feeds the agent's OWN prior
# output (no real-attack PoC/README/tx data, no per-case answers). Seed dir = RESUME_FROM if set,
# else <outdir>+RESUME_FROM_SUFFIX (per-case snapshot), else the case's own live dir. Missing seed
# files => silent fresh start. Normal (unset) runs are byte-identical to before.
RESUME_SEED = os.environ.get('RESUME_SEED', '0') != '0'
RESUME_FROM = (os.environ.get('RESUME_FROM') or '').strip()
RESUME_FROM_SUFFIX = (os.environ.get('RESUME_FROM_SUFFIX') or '').strip()
# REJECT_STALL: same-class pre-execution rejects (anti-cheat/inject) in a row before the loop injects
# a top-salience STRUCTURAL directive (via strategy_note). Structural, not mechanism — never fires strategist.
REJECT_STALL = int(os.environ.get('REJECT_STALL', 2))
# ---- PART 1: PITFALL_HINTS — a STATIC, baked-in list of general PoC-ENGINEERING traps (zero exploit
# constants, not per-case direction). Operator-overridable via the PITFALL_HINTS env: either newline
# `tag: hint` lines or a JSON list of {tag,hint}. Rendered once as a nonce-fenced advisory block in
# pins (below the objective/WHAT) with the SAME neutralize+fence+framing as render_strategist_note. ----
DEFAULT_PITFALLS = [
    {'tag': 'gated-fn', 'hint': 'The named entrypoint may be role/owner/MANAGER_ROLE-gated — read its '
     'modifiers; if you cannot pass the guard, find an UNPRIVILEGED equivalent that reaches the SAME state.'},
    {'tag': 'fee-on-transfer', 'hint': 'The token may tax transfers — measure the ACTUAL received delta '
     '(inspect_state/balanceOf before+after) and size the next step off THAT, never off the nominal 1:1 amount.'},
    {'tag': 'v3-price-limit', 'hint': 'sqrtPriceLimitX96 side depends on zeroForOne / token ordering — '
     'derive it from the live pool; the wrong side reverts with SPL.'},
    {'tag': 'reentrancy-order', 'hint': 'If victim state is updated AFTER an external call, re-enter from '
     'INSIDE the callback BEFORE that write lands.'},
    {'tag': 'callback-funding', 'hint': 'swap/flash callbacks must already hold the owed funds when they '
     'fire — stage that balance in setUp() BEFORE the snapshot, never mid-callback.'},
    {'tag': 'prefunded-capital', 'hint': 'You have UNLIMITED working capital — stage large base-asset '
     '(WBNB/BNB) and stablecoin (USDT/BUSD) balances to the attacker in setUp() BEFORE the snapshot '
     '(deal() pre-snapshot is allowed). Do NOT write flash loans or borrow to source capital; just '
     'swap/buy directly with the staged funds. Flash-loan orchestration is the most revert-prone step '
     'and is unnecessary here.'},
    {'tag': 'swap-size-liquidity', 'hint': 'Before ANY swap or market-buy, read the target pool LIVE (getReserves / balanceOf) and size amountIn to a SAFE fraction (~10-30%) of the relevant reserve. Fixed or oversized amounts trigger INSUFFICIENT_LIQUIDITY, TRANSFER_FAILED, or price-limit reverts. For fee-on-transfer tokens use the ...SupportingFeeOnTransferTokens router variant and approve the exact router.'},
]

def _load_pitfalls():
    """DEFAULT_PITFALLS unless the operator overrides via PITFALL_HINTS (JSON list or `tag: hint` lines)."""
    raw = (os.environ.get('PITFALL_HINTS') or '').strip()
    if not raw:
        return DEFAULT_PITFALLS
    try:
        j = json.loads(raw)
        if isinstance(j, list):
            out = [{'tag': str(d.get('tag') or '').strip(), 'hint': str(d.get('hint') or '').strip()}
                   for d in j if isinstance(d, dict) and str(d.get('hint') or '').strip()]
            if out:
                return out
    except Exception:
        pass
    out = []
    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        tag, _, hint = ln.partition(':')
        hint = hint.strip()
        if hint:
            out.append({'tag': tag.strip(), 'hint': hint})
    return out or DEFAULT_PITFALLS


# goal_strategist.rs:82 strategist_should_fire — skip-robust (>= last_fired + every, not strict %).
def strategist_should_fire(consecutive, last_fired, every):
    return every > 0 and consecutive >= last_fired + every

# acp_session_impl/goal_support.rs:229 — GOAL_CONTINUATION_BAIL_PREFACE (verbatim intent).
GOAL_CONTINUATION_BAIL_PREFACE = ("You have not submitted a rerun. Do not report conclusions or hand "
    "off; produce a concrete PoC and call rerun now.\n\n")

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
    ('ready_for_review',  r"^ready (?:for review|to (?:upload|merge|ship|land|submit))\b"),
    ('need_more_info',    r"^(?:i (?:need|require)|need|requires?) (?:more|additional) (?:info|information|context|details|input)\b"),
    ('in_summary',        r"^(?:in summary|to summari[sz]e|in conclusion)\b"),
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

# ---- anti-paralysis reverify pressure (goal_support.rs:476 render_goal_reverify_block +
# goal_tracker.rs:411-414 rounds_since_verify) ----
# KEYED ON rounds_since_rerun (turns since the agent last ACTUALLY invoked the terminal verifier),
# NOT on the NotAchieved streak. This is the anti-paralysis fix: completion is gated ONLY by a PASSing
# rerun, so pressure must build even when ZERO reruns have happened yet (pure read_source/inspect_state
# drift — e.g. PositionManager spending all 30 turns analyzing and never calling rerun). Gating on the
# NotAchieved streak could never catch that case (the streak only moves on a FAILED rerun). The lead
# hardens past 3*threshold; the live count is inlined.
def render_goal_reverify_block(rounds_since_rerun, threshold=GOAL_REVERIFY_AFTER):
    if rounds_since_rerun < threshold:
        return ''
    lead = ("STOP DRIFTING — SUBMIT A rerun NOW."
            if rounds_since_rerun >= threshold * 3
            else "Submit a rerun before continuing — the only way to finish is to PASS rerun, not to "
                 "keep reading.")
    return (f"{lead} You have gone {rounds_since_rerun} turns without submitting a rerun. The loop "
            f"evaluates completion (confirm.py net-loss) ONLY after a rerun; read_source/inspect_state/"
            f"probe never finish the goal. Write a concrete PoC and call rerun on the SINGLE concrete "
            f"gap blocking net-loss rather than continuing to analyze.\n\n")

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
    {'key': 'wrong_entrypoint', 'redirect': True,
     'diag': 'Fixating on one entrypoint: the real value-leak is through a DIFFERENT unprivileged state-changing entrypoint that the attempts never exercise.',
     'fix': 'Pivot to a DIFFERENT unlocked state-changing entrypoint (e.g. the buy/mint/purchase/claim path), not the function you keep re-hitting; drive the leak through THAT one.'},
    {'key': 'reentrancy_wrong_target', 'redirect': True,
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

def run_strategist(D, consecutive_failures, objective, plan_md, hints, rerun_history, trigger='stall', route_close=False):
    """Separate read-only strategist pass; Jev decides the root-cause pivot.
    Returns (note_text_or_'', top_pivot_key_or_None) — the key lets the caller's RAII
    bonus-guard tell a genuine pivot (new/changed hypothesis class) from a repeat/empty.
    PlanGuard: snapshot plan.md bytes before, restore after (strategist must never alter the contract)."""
    plan_path = D / 'plan.md'
    plan_snapshot = plan_path.read_bytes() if plan_path.exists() else None
    note = ''
    top_key = None
    try:
        from llm import jev
        state = _strategist_state(consecutive_failures, objective, plan_md, rerun_history)
        # CHANGE 1+4: the directional 'switch entrypoint' advice (redirect diagnoses) is eligible
        # ONLY on a repeated IDENTICAL-gap stall (trigger=='stall') AND only when the current route
        # is NOT measurably approaching success. On the cadence trigger (whack-a-mole: a DIFFERENT
        # gap each round) or when the route looks close, the redirect candidates are withheld so the
        # strategist cannot yank a near-working route onto a different entrypoint. Non-directional
        # diagnoses (precondition / poc-shape / fair-value) and unused RAG paradigms stay available.
        allow_redirect = (trigger == 'stall') and not route_close and not STRATEGIST_NO_REDIRECT
        cand = [c for c in STRUCTURAL_DIAGNOSES if allow_redirect or not c.get('redirect')]
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
            top_key = top['key']
            runners = '; '.join(f"{c['key']}={p:.2f}" for p, c in scored[:4])
            # CHANGE 4: a redirect pick is framed as an ADVISORY candidate, never a command.
            is_redirect = bool(top.get('redirect'))
            restructure = ('## Candidate alternative to weigh (ADVISORY)\n'
                           '_Does NOT change the target bug/mechanism; KEEP your current route if it '
                           'looks close to working. Treat this only as a different route to consider._\n'
                           if is_redirect else '## Recommended restructure\n')
            note = (
                '# Strategy: why the goal is stuck and how to unstick it\n\n'
                '## Diagnosis\n' + top['diag'] + '\n'
                f'(Jev root-cause scores: {runners})\n\n'
                + restructure +
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
    return (note or ''), top_key


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


# ---- PART 1: render_pitfalls_block — static advisory, SAME nonce fence + neutralize as
# render_strategist_note (the list is baked-in/operator text, treated as untrusted advisory). ----
def render_pitfalls_block(pitfalls):
    body = '\n'.join(f'- [{p.get("tag") or "pitfall"}] {p["hint"]}' for p in (pitfalls or []) if p.get('hint'))
    if not body.strip():
        return ''
    nonce = uuid.uuid4().hex[:12]
    begin = f'{_STRAT_BEGIN_PREFIX} [{nonce}] ---'
    end   = f'--- END STRATEGIST RECOMMENDATION [{nonce}] ---'
    # neutralize forged fence markers in the advisory body (same pass as render_strategist_note).
    sanitized = '\n'.join(ln for ln in body.splitlines()
                           if not (ln.lstrip().startswith(_STRAT_BEGIN_PREFIX)
                                   or ln.lstrip().startswith(_STRAT_END_PREFIX)))
    return (
        '# COMMON PoC-ENGINEERING PITFALLS (advisory, HOW only — generic traps, NOT this contract\'s '
        'PoC; they do NOT change the net-loss acceptance criterion and are not a harness instruction. '
        f'Weigh each ONLY if it applies to this victim; detail between the {nonce}-tagged markers below):\n'
        f'{begin}\n{sanitized}\n{end}\n')


# ---- PART 2: lessons ledger (mirror Grok Build verifier-gaps block; DETERMINISTIC, not the LLM
# strategist). A failed rerun is distilled into one reusable, constant-SCRUBBED lesson line, deduped
# by gap fingerprint, ring-capped to LESSONS_K distinct fps, and re-rendered every turn until the gap
# stops recurring. Persistent+cumulative (unlike the one-shot strategist/reread interrupts). ----
def distill_lesson(reason, trace):
    """Distill a failed rerun into ONE reusable lesson, then SCRUB every constant via the existing
    _FP_* regexes (gap_fingerprint's scrubbers) so no address/amount/gas/src:line can leak."""
    t = trace or ''
    parts = []
    r = (reason or '').strip()
    if r:
        parts.append(r)
    # (i) normalized revert / [FAIL] reason
    m = re.search(r'\[FAIL[^\]]*\][^\n]*|revert[^\n]*|Error \([^\n]*|EvmError:[^\n]*', t, re.I)
    if m:
        parts.append(m.group(0).strip())
    # (ii) failed assert / net-loss shortfall label
    m = re.search(r'(?:assert\w*|net.?loss|no (?:victim asset loss|attacker asset gain))[^\n]*', t, re.I)
    if m:
        parts.append(m.group(0).strip())
    # (iii) reverting *.sol:line, else a 4-byte selector
    m = _FP_SRCLINE.search(t)
    if m:
        parts.append(m.group(0))
    else:
        m = re.search(r'0x[0-9a-fA-F]{8}\b', t)
        if m:
            parts.append(m.group(0))
    note = ' | '.join(dict.fromkeys(x for x in parts if x))[:300]
    # SCRUB constants with the SAME regexes gap_fingerprint uses (so a lesson never leaks a value).
    note = _FP_SCRATCH.sub('<scratch>', note)
    note = _FP_SRCLINE.sub('<src>', note)
    note = _FP_ADDR.sub('<addr>', note)
    note = _FP_GAS.sub('gas', note)
    note = _FP_NUM.sub('<n>', note)
    return note.strip()

def render_lessons_block(lessons):
    """Nudge block re-rendered every turn above [next unchecked]; hardens a line once its repeat count
    reaches GOAL_CLASSIFIER_STALL_THRESHOLD (change the mechanic, not the constants)."""
    if not lessons:
        return ''
    lines = ['DEAD ENDS ALREADY HIT THIS RUN (do not repeat; full detail in lessons.md):']
    for L in lessons.values():
        line = f'- [x{L["count"]}] {L["note"]}'
        if L['count'] >= GOAL_CLASSIFIER_STALL_THRESHOLD:
            line += f' — hit this exact failure {L["count"]} times; change the mechanic, not the constants.'
        lines.append(line)
    return '\n'.join(lines) + '\n'

def render_lessons_md(lessons):
    L = ['# Lessons — deduped dead-ends this run (constant-scrubbed)', '']
    for v in lessons.values():
        L.append(f'- [x{v["count"]}] rounds {v["first_round"]}-{v["last_round"]}: {v["note"]}')
    return '\n'.join(L) + '\n'


# ---- RESUME-SEED: continue a case from its OWN prior run's accumulated knowledge ----------
# Parses a prior run dir (lessons.md + last try*.raw.sol) and returns (lessons OrderedDict,
# synthetic transcript note). Only re-feeds the agent's OWN prior output; never real-attack data,
# never per-case answers. Robust: any missing/unparseable file => returns ({}, '').
def _parse_lessons_md(txt):
    led = OrderedDict()
    rx = re.compile(r'^- \[x(\d+)\] rounds (\d+)-(\d+): (.*)$')
    for i, line in enumerate(txt.splitlines()):
        m = rx.match(line.strip())
        if not m:
            continue
        cnt, fr, lr, note = int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4).strip()
        led['seed:%d' % i] = {'note': note, 'count': cnt, 'first_round': fr, 'last_round': lr}
    return led

def load_resume_seed(seed_dir, refs_used):
    """Return (lessons_OrderedDict, synthetic_note_str) from a prior run dir, or ({}, '')."""
    try:
        sd = Path(seed_dir)
        if not sd.is_dir():
            return OrderedDict(), ''
        lessons = OrderedDict()
        lp = sd / 'lessons.md'
        if lp.exists():
            lessons = _parse_lessons_md(lp.read_text())
            # keep only the most-recent LESSONS_K distinct dead-ends
            while len(lessons) > LESSONS_K:
                lessons.popitem(last=False)
        # locate the last failing PoC attempt (highest tryN.raw.sol)
        tries = []
        for f in sd.glob('try*.raw.sol'):
            m = re.search(r'try(\d+)\.raw\.sol$', f.name)
            if m:
                tries.append((int(m.group(1)), f))
        last_try_n, last_sol = None, ''
        if tries:
            last_try_n, lf = max(tries, key=lambda x: x[0])
            last_sol = lf.read_text()[:6000]
        # last failing reason: most recently-updated lesson note (best available in the dir)
        last_reason = ''
        if lessons:
            last_reason = max(lessons.values(), key=lambda L: L['last_round'])['note']
        if not lessons and not last_sol:
            return OrderedDict(), ''
        paradigm = ''
        if refs_used and isinstance(refs_used, list) and refs_used and refs_used[0].get('paradigm'):
            paradigm = refs_used[0]['paradigm']
        parts = ['[RESUMING from a prior run on THIS case — continue, do not restart from zero.]']
        if lessons:
            dead = '; '.join('[x%d] %s' % (L['count'], L['note']) for L in lessons.values())
            parts.append('Known dead-ends/lessons already hit (do NOT repeat these): ' + dead)
        if last_reason:
            parts.append('Last failing PoC (try%s) failed with: %s' % (last_try_n, last_reason))
        if paradigm:
            parts.append('The attack MECHANISM/paradigm is likely: ' + paradigm + '.')
        parts.append('Build on the last PoC below toward a COMPILING, PASSING exploit; fix the next concrete blocker rather than re-deriving the mechanism.')
        if last_sol:
            parts.append('--- Last attempted PoC (try%s.raw.sol, trimmed) ---\n%s' % (last_try_n, last_sol))
        return lessons, '\n'.join(parts)
    except Exception as e:
        return OrderedDict(), ''



# ---- CHANGE 4: route-closeness detector ----------------------------------------------------
# Measurably "close": the PoC builds AND the key action actually executed (a manipulation/swap
# ran, value moved, or the run only failed on the net-loss MARGIN / an attacker-gain shortfall,
# or reverted LATE after real steps rather than doing nothing). Used to SUPPRESS the directional
# 'switch entrypoint' redirect so a near-working route is not evicted. General, no per-case keys.
def route_looks_close(reason, trace):
    r = (reason or '').lower()
    t = trace or ''
    if 'compile' in r or re.search(r'Compiler run failed|ParserError|Error \(\d+\)', t):
        return False                      # does not even build -> not close
    # Reached the attack action but fell short only on the net-loss margin / asymmetric gain.
    if 'net loss not above' in r or 'no attacker asset gain' in r:
        return True
    # "no victim asset loss" means nothing left the victim -> the key action did NOT land.
    if 'no victim asset loss' in r:
        return False
    # Direct evidence in the -vvvv tree that the manipulation/attack step actually executed.
    swap_executed = bool(re.search(r'\bSwap\b|::\s*swap|swapExact|\bMint\b|\bDeposit\b|\bBurn\b|\bskim\b|\bsync\b', t))
    moved = bool(re.search(r'emit Transfer\(|\bTransfer\(', t))
    late_revert = swap_executed and bool(re.search(r'revert|\[Revert|\[FAIL', t, re.I))
    return bool((swap_executed and moved) or late_revert)


# ---- CHANGE 5+6: stuck-fallback RE-READ agent --------------------------------------------
# Mirrors Grok Build's strategist reading the RAW traces itself (goal_strategist.rs:218) instead
# of trusting a pre-digested packet / a single RAG ranking. On a same-gap stall we re-read THIS
# case's OWN mechanism summary (cases.jsonl summary || sidecar || root_cause — case_signal's
# fallback chain), the verified source, and the failed transcript/dead-ends, then have Jev
# RE-DERIVE candidate hypothesis CLASSES from scratch over the CLOSED taxonomy. This can surface
# a paradigm/subclass that retrieval ranked too low or omitted entirely (e.g. reentrancy for ORB).
# cases.jsonl is READ-ONLY here; DeFiHackLabs PoC/README is never touched.
def run_stuck_reread(D, cid, victim, verified_src_excerpt, rerun_history):
    try:
        from llm import jev
        cases = {c['id']: c for c in idx._load()}
        sidecar = idx._load_sidecar()
        c = cases.get(cid)
        if not c:
            return '', [], []
        own_summary, src_kind = idx.case_signal(c, sidecar)
        own_summary = (own_summary or '').strip()
        if not own_summary:
            return '', [], []
        deadends = [f'round {rn}: {reason}' for (rn, _sol, _tr, reason) in rerun_history[-6:]]
        cands = [(cat, sid, defn) for cat, subs in TAXONOMY.items() for sid, defn in subs.items()]
        state = {
            'case_own_summary': own_summary[:4000],
            'summary_source': src_kind,
            'verified_source_excerpt': (verified_src_excerpt or '')[:6000],
            'dead_ends_already_tried': deadends,
        }
        Q = {f'c{i}': {'type': 'noul', 'instructions':
             (f'Hypothesis CLASS (category={cat}, subclass={sid}): "{defn}". '
              'Re-derive from the case_own_summary + verified_source_excerpt ALONE, IGNORING any '
              'earlier ranking: how strongly does THIS class explain how an unprivileged attacker '
              'drains this victim? Score HIGH only if the summary/source concretely exhibit this '
              'mechanism. dead_ends_already_tried are paths that FAILED, so prefer a class they did '
              'not exercise.')}
             for i, (cat, sid, defn) in enumerate(cands)}
        ans = jev(state, Q)
        scored = sorted(((float((ans.get(f'c{i}') or {}).get('noul', 0) or 0), cat, sid, defn)
                         for i, (cat, sid, defn) in enumerate(cands)), key=lambda x: -x[0])
        hyps = [{'category': cat, 'subclass': sid, 'def': defn, 'score': round(p, 3)}
                for p, cat, sid, defn in scored[:3]]
        return own_summary, deadends, hyps
    except Exception:
        return '', [], []


def render_reread_note(own_summary, deadends, hyps, plan_path):
    """CHANGE 6: force a RE-READ of the case summary + prior dead-ends before the next hypothesis,
    and feed the from-scratch re-derived hypothesis classes (CHANGE 5) back into context."""
    if not hyps:
        return ''
    sm = (own_summary or '').strip()
    sm = (sm[:1200] + ' …') if len(sm) > 1200 else sm
    hl = '\n'.join(f'- [{h["category"]}/{h["subclass"]}] {h["def"]} (re-derived p={h["score"]})' for h in hyps)
    dl = '; '.join(deadends) if deadends else '(none recorded)'
    reread = (f'RE-READ your plan at {plan_path} and the dead-ends you already tried'
              if plan_path else 'RE-READ the dead-ends you already tried')
    return (
        'You are STUCK on the SAME gap. Before proposing your next hypothesis, '
        f'{reread}, and re-read THIS case\'s own mechanism summary (independent of the earlier '
        'ranked paradigms):\n'
        f'--- CASE SUMMARY (re-read) ---\n{sm}\n--- END CASE SUMMARY ---\n'
        f'Dead-ends already tried (do NOT repeat): {dl}\n'
        'A from-scratch re-derivation (NOT the earlier RAG ranking) scores these hypothesis CLASSES '
        'highest for THIS victim — strongly consider one you have NOT yet exercised:\n'
        f'{hl}\n\n')


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
- ALL deal() ONLY in setUp(), never in testExploit(). Funding the attacker with large OWN working capital (incl. to bankroll a flash-free price-manipulation swap) is legitimate — follow the SETUP SKELETON below exactly.
- In testExploit: attack only, reading fees/mins/balances/prices LIVE (no hardcoded mutable constants).
- Prefer an assert-free body (the loop wraps it); require()s that assert your own preconditions are fine and encouraged.
- Only call functions that exist in the verified source. Use checksummed addresses.
- PRECONDITIONS FIRST: if your chain spends a victim/LP/share token (sell/transfer/redeem/burn), you MUST first ACQUIRE a NON-ZERO balance via the real buy/mint/add-liquidity path and assert balanceOf>0 before the attack action — selling/moving zero is a silent no-op. Implement approvals and any reserve/price/flag state-flip, each asserted, before the step that reads them.


SETUP SKELETON — your setUp() MUST follow this shape (fill the TODOs); testExploit() is yours:
---
// forge-std Test gives vm + deal(). Attacker == address(this) (+ contracts it deploys).
address constant WBNB   = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;
address constant USDT   = 0x55d398326f99059fF775485246999027B3197955;
address constant ROUTER = 0x10ED43C718714eb63d5aA57B78B54704E256024E; // PancakeSwap V2

function setUp() public {
    vm.createSelectFork("bsc", <BLOCK from the rule above>);
    // (1) working capital = BASE + STABLES ONLY, dealt to the attacker (pre-snapshot):
    vm.deal(address(this), 100000 ether);          // native BNB
    deal(WBNB, address(this), 100000 ether);       // WBNB
    deal(USDT, address(this), 10000000e18);        // USDT
    // (2) EXOTIC / victim-side tokens: NEVER deal() them (fee-on-transfer / rebase / blacklist
    //     => "Funding failed"/"TRANSFER_FAILED"). BUY them through the DEX with the base capital,
    //     still inside setUp (pre-snapshot):
    //   IERC20(WBNB).approve(ROUTER, type(uint256).max);
    //   IPancakeRouter(ROUTER).swapExactTokensForTokensSupportingFeeOnTransferTokens(
    //       amtIn, 0, path(WBNB,<EXOTIC>), address(this), block.timestamp);
    // (3) approvals the attack will need (victim / router / pool), for the tokens you will spend.
}
// testExploit(): attack ONLY. No deal() anywhere here. Read fees/mins/reserves/prices LIVE.
// Acquire a NON-ZERO balance of any token you will spend BEFORE spending it (preconditions first).
---

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
    """Keep what the agent needs: compile errors in full-ish, else the tail with the call tree + logs.
    The tail cap is TRACE_CHARS (operator-raisable for fuller -vvvv feedback)."""
    if re.search(r'Compiler run failed|ParserError|Error \(\d+\)', out):
        errs = re.findall(r'(?:Error|ParserError)[^\n]*(?:\n[^\n]*){0,6}', out)
        head = '\n---\n'.join(errs[:12])
        return ('COMPILE ERRORS:\n' + head + '\n\n--- output tail ---\n' + out[-(TRACE_CHARS//3):])[:TRACE_CHARS]
    return out[-TRACE_CHARS:]

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
def load_full_source(sources):
    # `sources` = the vulnerable-LOGIC contract(s) to READ/reason over (may differ from the
    # victim address confirm MEASURES). Accepts a single address or a list; concatenates their
    # verified Etherscan source. NEVER the DeFiHackLabs PoC. General, content-independent.
    if isinstance(sources, str): sources = [sources]
    mains, blocks, cnames = [], [], []
    for addr in sources:
        r = fs.get(56, addr)
        files = fs.files(r['SourceCode'])
        cname = r.get('ContractName', '')
        cnames.append(cname)
        m = fs.main_code('\n'.join(files.values()), cname)
        mains.append((f'// ===== CONTRACT {cname} @ {addr} =====\n' if len(sources) > 1 else '') + m)
        for name, body in files.items():
            tag = f'{name} ({cname} @ {addr})' if len(sources) > 1 else name
            blocks.append(f'// ===== FILE: {tag} =====\n{body}')
    main = ('\n\n'.join(mains))[:48000]
    full = '\n\n'.join(blocks)
    cname = ', '.join(c for c in cnames if c)
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

def one(cid, victim, block, outdir, sources=None):
    D = Path(outdir); D.mkdir(parents=True, exist_ok=True)
    victim = csum(victim)
    # DECOUPLED targets: `sources` = contract(s) whose verified source the agent READS /
    # reasons over (the vulnerable-logic contract); `victim` = address confirm MEASURES for
    # asset loss. Default source == victim (common case). General, no per-case hack.
    sources = [csum(a) for a in (sources or [victim])]
    source_differs = [a.lower() for a in sources] != [victim.lower()]
    main_src, full_src, cname = load_full_source(sources)
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
    # Operator ROUTE HINT (advisory, HOW-only): pin a known-correct direction as the TOP plan item so
    # the budget is spent engineering the PoC, not re-discovering the entrypoint. General mechanism;
    # the hint text carries no exploit constants.
    if ROUTE_HINT:
        plan_items.insert(0, {'id': 'r0', 'text': 'PINNED ROUTE (operator hint — engineer THIS; do not switch entrypoint): ' + ROUTE_HINT, 'done': False})

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
            + '\n\n# HISTORICAL ATTACK PARADIGMS (advisory hints only; NOT this contract\'s PoC):\n' + hints
            + (('\n\n# OPERATOR ROUTE HINT (advisory, HOW only — the entrypoint/direction is already '
                'known-correct; spend your turns ENGINEERING this PoC, do not re-discover or switch the '
                'entrypoint; still read live state and the verified source to get the mechanics right):\n'
                + ROUTE_HINT) if ROUTE_HINT else ''))
    # PART 1: static PoC-engineering pitfalls, below the objective/WHAT. Nonce-fenced advisory.
    _pit_block = render_pitfalls_block(_load_pitfalls())
    if _pit_block:
        pins = pins + '\n\n' + _pit_block.rstrip('\n')

    # Decoupled source/victim note: the verified source above is the vulnerable-LOGIC
    # contract(s); confirm measures a DIFFERENT victim address. Content-independent.
    if source_differs:
        pins = pins + ('\n\n# SOURCE vs MEASURED-VICTIM (read this): the VERIFIED SOURCE above is '
                       f'the vulnerable-LOGIC contract(s) {cname} at ' + ', '.join(sources)
                       + f'. The loop MEASURES asset loss on a DIFFERENT victim address {victim} '
                       '(where the drained value actually sits — e.g. an external LP pair). Reason '
                       'over the logic source to find the mechanism, but your PoC must cause net '
                       'loss at the MEASURED victim address; read its live state with inspect_state.')


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
    rounds_since_rerun = 0             # goal_tracker: rounds_since_verify — turns since a rerun ACTUALLY ran
    last_reread_fired_at = 0           # own cadence anchor for the stuck-reread (decoupled from strategist)
    primary_rerun_done = False         # GoalClassifierNudge gate: a real rerun on the primary hypothesis
    strategy_note = ''                 # last strategist recommendation (injected next turn)
    last_strategist_key = None         # last delivered strategist pivot key (claw-back 'changed class' test)
    reread_seen_classes = set()        # hypothesis classes already surfaced by the re-read agent (new-class test)
    reread_note = ''                   # CHANGE 5/6: stuck re-read block (injected next turn, consumed once)
    bail_pending = None                # stop-detector label -> bail nudge next turn
    cannot_nudge = False               # GoalClassifierNudge: force a primary rerun before 'cannot'
    fired = {'stall': 0, 'cadence': 0, 'strategist': 0, 'strategist_empty': 0, 'bail': 0, 'cannot_gate': 0, 'reverify': 0, 'reread': 0, 'rerun_cap': 0, 'force_rerun': 0}
    budget = MAXR                      # dynamic turn budget (strategist fire adds GOAL_STRATEGIST_CAP_BONUS)
    rerun_history = []                 # (round, sol, trace, reason) — the FULL context the strategist reads
    reruns_since_reflection = 0        # RERUN_CAP gate: real forge reruns since the last (or zero) reflection
    consecutive_rejects = 0            # bogus/inject pre-exec rejects in a row (reset on any REAL executed rerun)
    last_reject_fp = None              # constant-scrubbed class of the last reject, to detect repeats
    deep_reflection_done = False       # RERUN_CAP gate: the one mandatory deep reflection has been spent
    lessons = OrderedDict()            # PART 2: fp -> {note,count,first_round,last_round}; disk mirror lessons.md

    # ---- RESUME-SEED (opt-in via RESUME_SEED=1): continue from this case's OWN prior run ----
    # Load the prior run's lessons + last failing PoC and pre-seed the ledger + ONE transcript note,
    # so the agent builds on where it got stuck. Only the agent's own prior output is re-fed; never
    # real-attack PoC/README/tx data, never per-case answers. Missing seed => silent fresh start.
    if RESUME_SEED:
        if RESUME_FROM:
            _seed_dir = RESUME_FROM
        elif RESUME_FROM_SUFFIX:
            _seed_dir = str(outdir) + RESUME_FROM_SUFFIX
        else:
            _seed_dir = str(outdir)
        _seed_lessons, _seed_note = load_resume_seed(_seed_dir, refs_used)
        if _seed_lessons:
            lessons = _seed_lessons
            (D / 'lessons.md').write_text(render_lessons_md(lessons))
        if _seed_note:
            transcript.append('[resume-seed] ' + _seed_note)

    rnd = 0
    while rnd < budget:
        rnd += 1
        rounds_since_rerun += 1   # +1 every turn; reset to 0 only when a rerun ACTUALLY runs
        force_rerun_now = FORCE_RERUN_AFTER > 0 and rounds_since_rerun >= FORCE_RERUN_AFTER
        nxt = next_unchecked(plan_items)
        # Mode B bail preface (goal_support.rs GOAL_CONTINUATION_BAIL_PREFACE) — re-serve next item.
        preface = GOAL_CONTINUATION_BAIL_PREFACE if bail_pending else ''
        # Mode 5 anti-paralysis reverify pressure (render_goal_reverify_block) — keyed on
        # rounds_since_rerun so it fires even with ZERO reruns yet (PositionManager pure-analysis drift).
        reverify = render_goal_reverify_block(rounds_since_rerun)
        if reverify: fired['reverify'] += 1
        lessons_block = render_lessons_block(lessons)
        nudge = ('\n\n# PLAN (plan.md)\n' + render_plan(plan_items)
                 + (('\n\n' + lessons_block.rstrip('\n')) if lessons_block else '')
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
        # CHANGE 5/6: the stuck re-read block is itself a one-time high-salience interrupt at the TOP
        # of the nudge; like the strategist note it is delivered in EXACTLY one turn then cleared.
        delivered_reread = reread_note if reread_note else None
        if delivered_reread:
            nudge = '\n\n' + delivered_reread.rstrip('\n') + nudge
        if preface:
            nudge = '\n\n' + preface + nudge.lstrip('\n')
        # Hard FORCE_RERUN gate: highest-priority, top-of-prompt interrupt. After FORCE_RERUN_AFTER
        # turns with no actual rerun, this turn MUST submit a PoC; non-rerun actions are refused.
        if force_rerun_now:
            nudge = ('\n\n[FORCE-RERUN] You have gone ' + str(rounds_since_rerun) + ' turns without submitting a '
                     'rerun. THIS TURN you MUST return a "rerun" action with your current BEST complete PoC .sol. '
                     'Any other tool (read_source/inspect_state/probe/edit_plan) will be REFUSED unexecuted. '
                     'The forge trace itself is the signal you need — submit your best attempt now; do not keep analyzing.'
                     + nudge.lstrip('\n'))
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
        # Split the static head (pins = SYS + verified source) from the per-turn dynamic tail so the
        # head can be Anthropic prompt-cached across the case's turns. full prompt == pins + dynamic
        # (disk-cache keys are unchanged vs the old single-string form).
        dynamic = '\n\n# TRANSCRIPT (your turns + tool results)\n' + tbody + nudge + '\n\nYour next single JSON action:'
        # consume_strategist_note (goal.rs:1391): compare-and-clear once the directive is committed for
        # delivery, so the note shows in EXACTLY ONE turn; a fresh note only on a strategist re-fire.
        if delivered_rec is not None and strategy_note == delivered_rec:
            strategy_note = ''
        if delivered_reread is not None and reread_note == delivered_reread:
            reread_note = ''

        out = gen_model(MODEL, dynamic, temp=TEMP, prefix=pins)
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

        # FORCE_RERUN gate enforcement: refuse (do NOT execute) any non-rerun action while the gate
        # is active, and do NOT reset rounds_since_rerun — keep pressing until a real rerun lands.
        if force_rerun_now and tool != 'rerun':
            fired['force_rerun'] += 1
            log.append(('force_rerun', tool or '<none>'))
            transcript.append('[loop] FORCE-RERUN gate active — action "' + str(tool) + '" REFUSED unexecuted; '
                              'you must submit a "rerun" PoC this turn.')
            prev_failed = True; last_fail = 'force-rerun gate: non-rerun action refused'
            continue
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
                _msg = f'[result rerun] REJECTED anti-cheat: {why}'
                if 'deal(' in why:
                    _msg += (' Move this deal() into setUp() (before the snapshot). Dealing working capital to the attacker is allowed; '
                             'only its position after the snapshot is the problem. Do NOT abandon the attack approach - just relocate the funding.')
                transcript.append(_msg)
                log.append(('reject', why)); prev_failed = True; last_fail = 'anti-cheat reject'
                _r = why or err
                _rfp = re.sub(r'0x[0-9a-fA-F]+|\d+', '', _r)[:60]
                if _rfp == last_reject_fp: consecutive_rejects += 1
                else: last_reject_fp = _rfp; consecutive_rejects = 1
                _lfp = 'reject:' + _rfp
                if _lfp in lessons:
                    lessons[_lfp]['count'] += 1; lessons[_lfp]['last_round'] = rnd; lessons.move_to_end(_lfp)
                else:
                    lessons[_lfp] = {'note': f'Pre-exec reject: {_r[:120]} — STRUCTURAL fix needed; it never ran.',
                                     'count': 1, 'first_round': rnd, 'last_round': rnd}
                    while len(lessons) > LESSONS_K: lessons.popitem(last=False)
                (D / 'lessons.md').write_text(render_lessons_md(lessons))
                if consecutive_rejects >= REJECT_STALL:
                    strategy_note = ('REJECTED ' + str(consecutive_rejects) + 'x in a row for the SAME reason BEFORE your test '
                                     'ran: ' + _r[:160] + '. This is a STRUCTURAL PoC error, not a mechanism problem — do NOT '
                                     'change the attack idea. Fix the STRUCTURE now per the SETUP SKELETON (all deal() in setUp, '
                                     'exotic tokens via DEX, testExploit has no deal()). Resubmit a structurally-fixed PoC.')
                    fired['reject_stall'] = fired.get('reject_stall', 0) + 1
                    log.append(('reject_stall', _rfp)); consecutive_rejects = 0
                continue
            sol2, err = inject_confirm(sol, victim)
            if err:
                transcript.append(f'[result rerun] REJECTED inject: {err}')
                log.append(('reject', err)); prev_failed = True; last_fail = 'inject reject'
                _r = why or err
                _rfp = re.sub(r'0x[0-9a-fA-F]+|\d+', '', _r)[:60]
                if _rfp == last_reject_fp: consecutive_rejects += 1
                else: last_reject_fp = _rfp; consecutive_rejects = 1
                _lfp = 'reject:' + _rfp
                if _lfp in lessons:
                    lessons[_lfp]['count'] += 1; lessons[_lfp]['last_round'] = rnd; lessons.move_to_end(_lfp)
                else:
                    lessons[_lfp] = {'note': f'Pre-exec reject: {_r[:120]} — STRUCTURAL fix needed; it never ran.',
                                     'count': 1, 'first_round': rnd, 'last_round': rnd}
                    while len(lessons) > LESSONS_K: lessons.popitem(last=False)
                (D / 'lessons.md').write_text(render_lessons_md(lessons))
                if consecutive_rejects >= REJECT_STALL:
                    strategy_note = ('REJECTED ' + str(consecutive_rejects) + 'x in a row for the SAME reason BEFORE your test '
                                     'ran: ' + _r[:160] + '. This is a STRUCTURAL PoC error, not a mechanism problem — do NOT '
                                     'change the attack idea. Fix the STRUCTURE now per the SETUP SKELETON (all deal() in setUp, '
                                     'exotic tokens via DEX, testExploit has no deal()). Resubmit a structurally-fixed PoC.')
                    fired['reject_stall'] = fired.get('reject_stall', 0) + 1
                    log.append(('reject_stall', _rfp)); consecutive_rejects = 0
                continue
            (D / f'try{rnd}.sol').write_text(sol2)
            write_proj(D, sol2)
            ok, fo = run_forge_verbose(D)
            reason = parse_reason(ok, fo)
            best_reason = reason
            log.append(('rerun', reason))
            # A rerun that actually executed = a real attempt on the primary hypothesis (unlocks 'cannot').
            primary_rerun_done = True
            rounds_since_rerun = 0   # reset the anti-paralysis dwell ONLY on an actual rerun invocation
            consecutive_rejects = 0; last_reject_fp = None   # a real execution clears the reject-stall
            trace_for_ctx = _trace_for_agent(fo)
            rerun_history.append((rnd, sol[:6000], trace_for_ctx, reason))
            reruns_since_reflection += 1   # a REAL verification attempt (RERUN_CAP gate)
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
            # PART 2: distill + record a constant-scrubbed lesson, dedup by fp, ring-cap LESSONS_K.
            _lnote = distill_lesson(reason, fo)
            if _lnote:
                if fp in lessons:
                    lessons[fp]['count'] += 1
                    lessons[fp]['last_round'] = rnd
                    lessons.move_to_end(fp)
                else:
                    lessons[fp] = {'note': _lnote, 'count': 1, 'first_round': rnd, 'last_round': rnd}
                    while len(lessons) > LESSONS_K:
                        lessons.popitem(last=False)
                (D / 'lessons.md').write_text(render_lessons_md(lessons))
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
            # CHANGE 4: is the current route measurably approaching success? (suppresses redirect)
            route_close = route_looks_close(reason, fo)
            # CHANGE 4 (early, skip-robust reread): fire the stuck-reread on its OWN cadence over the
            # content-agnostic NotAchieved streak (consecutive_no_loss, +1 on EVERY failed rerun regardless
            # of fingerprint, reset on confirm), DECOUPLED from the strategist's last_strategist_fired_at.
            # The stall-strategist escalation bumps last_strategist_fired_at, so the strategist cadence only
            # re-arms at streak 5; chaining the reread to it fired it only on the final turn (the ORB bug).
            # Its own anchor last_reread_fired_at + a small GOAL_REREAD_EVERY => it fires on the FIRST cadence
            # hit, early enough to be actionable. Skip-robust `>= last_fired + N` (not strict `%`).
            reread_pivot = False
            if strategist_should_fire(consecutive_no_loss, last_reread_fired_at, GOAL_REREAD_EVERY):
                last_reread_fired_at = consecutive_no_loss   # claim this reread fire
                _rs, _de, _hy = run_stuck_reread(D, cid, victim, main_src, rerun_history)
                _rr = render_reread_note(_rs, _de, _hy, str(D / 'plan.md'))
                if _rr:
                    reread_note = _rr
                    fired['reread'] += 1
                    log.append(('reread', f'{len(_hy)} re-derived classes @streak{consecutive_no_loss}'))
                    # a re-derived class not previously surfaced = a genuine structural pivot (disarms claw-back)
                    for _h in _hy:
                        _k = (_h['category'], _h['subclass'])
                        if _k not in reread_seen_classes:
                            reread_pivot = True
                        reread_seen_classes.add(_k)
            transcript.append(f'[result rerun] forge FAILED ({last_fail}); saved try{rnd}.raw.sol. '
                              f'[no-loss streak {consecutive_no_loss}, gap-repeat {stall_count}/{threshold}, '
                              f'strategist cadence every {GOAL_STRATEGIST_EVERY} (last fired @{last_strategist_fired_at})]\n'
                              f'--- forge -vvvv trace ---\n{trace_for_ctx}')
            # Mode A: fire the SEPARATE strategist on EITHER trigger. claim_strategist_fire guard:
            # never double-fire on the identical consecutive streak value. The cadence trigger already
            # implies consecutive_no_loss > last_strategist_fired_at, so the guard only constrains stall.
            if trigger and consecutive_no_loss != last_strategist_fired_at:
                last_strategist_fired_at = consecutive_no_loss    # claim_strategist_fire
                # The claim grants the cap bonus UP FRONT (idempotent, not stacked; goal_tracker.rs:1125).
                if strategist_bonus == 0:
                    budget += GOAL_STRATEGIST_CAP_BONUS            # budget bonus, granted once
                strategist_bonus = GOAL_STRATEGIST_CAP_BONUS       # raises the stall threshold
                # reset_classifier_stall_fields
                last_gap_fp = None; stall_count = 0
                fired[trigger] = fired.get(trigger, 0) + 1
                log.append(('strategist', f'fire[{trigger}]@streak{consecutive_no_loss}'))
                # ---- TrackerDropGuard (goal_support.rs:1513 maybe_run_goal_strategist) ----
                # The claim granted the cap bonus up front; EVERY exit path that delivers no real
                # restructure must give it back. Armed by default (revoke on exit); disarmed ONLY
                # on a genuine pivot — mirroring the Rust RAII guard that disarms solely on the
                # `Advised` outcome. try/finally is the Python RAII. "Real restructure" = the
                # strategist produced a note whose hypothesis CLASS changed vs. the last delivery,
                # OR the re-read surfaced a hypothesis class not already tried (empty / same-as-before
                # recommendations do NOT keep the bonus).
                bonus_armed = True
                try:
                    note, strat_key = run_strategist(D, consecutive_no_loss, objective,
                                          render_plan(plan_items), hints, rerun_history,
                                          trigger=trigger, route_close=route_close)
                    # The stuck-reread fires on its OWN decoupled cadence (above, keyed on
                    # last_reread_fired_at), NOT chained to this strategist fire — so the stall
                    # escalation of last_strategist_fired_at cannot starve it to the last turn.
                    # reread_pivot was computed there and is reused here for the claw-back disarm.
                    # strategist pivot is "real" only with a note AND a changed hypothesis class.
                    strat_pivot = bool(note) and (strat_key is not None) and (strat_key != last_strategist_key)
                    if note:
                        strategy_note = note
                        fired['strategist'] += 1
                        last_strategist_key = strat_key
                    else:
                        fired['strategist_empty'] += 1
                        log.append(('strategist', 'empty'))
                    # Disarm the claw-back ONLY on a genuine restructure (mirrors bonus_guard.disarm()).
                    if strat_pivot or reread_pivot:
                        bonus_armed = False
                finally:
                    # revoke_strategist_cap_bonus() unless a real restructure disarmed the guard.
                    if bonus_armed:
                        if strategist_bonus:
                            budget -= GOAL_STRATEGIST_CAP_BONUS
                        strategist_bonus = 0
                        log.append(('strategist', 'no-restructure->bonus revoked'))
            # ---- RERUN_CAP hard gate (goal_classifier_max_runs analogue) --------------------
            # Bound real verification attempts independently of MAXR. On reaching RERUN_CAP reruns
            # without a confirm, force EXACTLY ONE mandatory deep reflection (stuck-reread +
            # strategist) regardless of the normal cadences, then give one more rerun window. If
            # that window ALSO exhausts RERUN_CAP without confirming, stop with a clear reason
            # rather than hard-trying all the way to the total-turn ceiling. Integrates with the
            # existing reread/strategist machinery (reuses the same renderers + injection slots).
            if reruns_since_reflection >= RERUN_CAP:
                if not deep_reflection_done:
                    deep_reflection_done = True
                    reruns_since_reflection = 0
                    fired['rerun_cap'] = fired.get('rerun_cap', 0) + 1
                    # force the stuck-reread regardless of its own cadence anchor
                    _rs, _de, _hy = run_stuck_reread(D, cid, victim, main_src, rerun_history)
                    _rr = render_reread_note(_rs, _de, _hy, str(D / 'plan.md'))
                    if _rr:
                        reread_note = _rr
                        fired['reread'] += 1
                        for _h in _hy:
                            reread_seen_classes.add((_h['category'], _h['subclass']))
                    # force the strategist regardless of the stall/cadence claim guard (non-directional
                    # trigger, so no entrypoint redirect); its note wins the injection slot this turn
                    _note, _skey = run_strategist(D, consecutive_no_loss, objective,
                                          render_plan(plan_items), hints, rerun_history,
                                          trigger='rerun_cap', route_close=route_close)
                    if _note:
                        strategy_note = _note
                        last_strategist_key = _skey
                        fired['strategist'] += 1
                    log.append(('rerun_cap', f'forced deep reflection @ {len(rerun_history)} reruns'))
                    transcript.append('[loop] RERUN_CAP reached — forced ONE mandatory deep reflection '
                                      '(stuck-reread + strategist). This is your final reflection window; '
                                      'use the re-derived hypotheses and strategy note, change the MECHANISM '
                                      '(not just constants), then resubmit.')
                else:
                    log.append(('rerun_cap', f'stop: {len(rerun_history)} reruns, reflection already spent'))
                    (D / 'plan.md').write_text(render_plan(plan_items))
                    (D / 'transcript.md').write_text('\n\n'.join(transcript))
                    return {'id': cid, 'outcome': 'rerun_cap', 'turns': rnd, 'rounds': rnd,
                            'sec': round(time.time() - t0), 'log': log, 'nread': nread, 'nrerun': nrerun,
                            'refs': refs_used, 'last_reason': best_reason, 'mech': fired,
                            'stop_reason': f'rerun cap ({RERUN_CAP}) exhausted twice, after one forced deep reflection, still unconfirmed'}
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
from loop import TARGETS, parse_target

if __name__ == '__main__':
    if not os.environ.get('BSC_RPC'): print('BLOCKER: set BSC_RPC'); sys.exit(2)
    slug = lambda s: re.sub(r'\W+', '_', s)
    ids = sys.argv[1:] or list(TARGETS)
    def run_one(cid):
        v, b, srcs = parse_target(TARGETS[cid])
        res = one(cid, v, b, f'data/loop_agent/{slug(cid)}', sources=srcs)
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
