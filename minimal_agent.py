#!/usr/bin/env python3
"""minimal_agent.py — the simplest possible single-model exploit pipeline.

A deliberate REBUILD: NO multi-role framework, NO strategist, NO reflection, NO compile-fix
subloop, NO error-retry loop. Exactly FOUR model steps, then verify ONCE and stop:

  1. READ SOURCE  — verified Etherscan source (NEVER a DeFiHackLabs PoC) via load_full_source.
  2. READ CONTEXT — assemble ALL info layers 1-9 into one context pack (reusing existing helpers).
  3. PLAN         — one LLM call: given the context pack + RAG paradigms + pitfalls, write an
                    ATTACK PLAN in prose (mechanism/strategy, NOT PoC code).
  4. WRITE CODE   — one LLM call: given the context pack + the plan, fill the attack body into the
                    pinned compile-safe skeleton.
  5. VERIFY ONCE  — inject_confirm -> write_proj -> run_forge_verbose -> parse_reason + depth_of.
                    Record the outcome and STOP. The error is NOT fed back. No retries.

Model: deepseek/deepseek-v4.1-flash (override via MINIMAL_MODEL / SIMPLE_MODEL). USE_RAG=1,
SKELETON always on. confirm.py / cases.jsonl are NEVER modified. No secrets / RPC printed.

Info layers 1-9 (all reused, nothing reinvented):
  1 case def (victim/block/sources)   : loop.TARGETS + loop.parse_target
  2 verified source                   : loop_agent.load_full_source
  3 live on-chain context             : verify_ctx.build_context
  4 compile-safe skeleton             : simple_agent.build_skeleton / parse_skel_output / SKEL_*
  5 precise IVictim interface         : simple_agent.extract_interface + extract_getters (+iface_compiles)
  6 static transfer-constraint warns  : simple_agent.extract_constraints (incl. generalized per-tx-cap rule)
  7 DEX interaction reference         : simple_agent.DEX_REF / DEX_IFACE / ROUTER/WBNB/FACTORY
  8 common PoC pitfalls               : loop_agent._load_pitfalls + render_pitfalls_block (DEFAULT_PITFALLS)
  9 RAG paradigms                     : index.retrieve_refs (vectorless, excludes the query case)
"""
import os, sys, re, json, time
from pathlib import Path

if not os.environ.get('BSC_RPC'):
    print('BLOCKER: set BSC_RPC'); sys.exit(2)
if not os.environ.get('OPENROUTER_API_KEY'):
    print('BLOCKER: set OPENROUTER_API_KEY'); sys.exit(2)

import llm
from confirm import inject_confirm, write_proj, parse_reason, redact, csum
from loop import TARGETS, parse_target
from loop_agent import (load_full_source, run_forge_verbose, depth_of,
                        _load_pitfalls, render_pitfalls_block, RAG_K)
import index as idx
import verify_ctx as vc
# REUSE every info-layer helper from simple_agent (importing it also wires llm._chat cost tracking).
import simple_agent as sa

MODEL = os.environ.get('MINIMAL_MODEL') or os.environ.get('SIMPLE_MODEL') or 'deepseek/deepseek-v4.1-flash'
USE_RAG = os.environ.get('USE_RAG', '1') != '0'
TEMP  = float(os.environ.get('MINIMAL_TEMP', '0.15'))


def build_rag_block(ctx, main_src, cid):
    """Layer 9: vectorless RAG paradigm hints (excludes the query case). Returns (hints_text, refs_used)."""
    if not USE_RAG:
        return '(RAG disabled)', []
    try:
        refs = idx.retrieve_refs(ctx, main_src, query_id=cid, k=RAG_K)
    except Exception as e:
        return f'(RAG error: {type(e).__name__}: {e})', [{'error': str(e)}]
    if not refs:
        return '(no transferable paradigms retrieved)', []
    hints = '\n'.join(f"- [{r['category']}] {r['paradigm']}  ({r['why']})" for r in refs)
    refs_used = [{'id': r['id'], 'paradigm': r['paradigm'], 'score': r['score']} for r in refs]
    return hints, refs_used


PLAN_SYS = (
    'You are a smart-contract exploit auditor. You are given the VERIFIED on-chain source of a '
    'contract (NOT any proof-of-concept), its live on-chain state at a fork block, the victim address '
    'and fork block, the target interface, static transfer-constraint warnings, a generic DEX '
    'interaction reference, common PoC-engineering pitfalls, and historical attack paradigms (advisory). '
    'The contract MAY be vulnerable.\n\n'
    'Your task in THIS step: write a concise ATTACK PLAN in PROSE describing the exploit MECHANISM and '
    'the concrete step-by-step strategy an UNPRIVILEGED attacker would run on a BSC mainnet fork to end '
    'with more net asset value than they started. Reason over the paradigms/pitfalls where they apply.\n\n'
    'HARD RULES: Output PROSE ONLY — NO Solidity, NO code blocks, NO PoC. Describe: (1) the specific '
    'vulnerability / value-flow being abused; (2) the ordered steps (acquire funds, buy/mint, trigger, '
    'extract, sell back) naming the exact victim functions involved; (3) the key constraints to respect '
    '(from the warnings) and how the plan stays within them. Keep it tight and actionable.'
)


def main():
    cid = sys.argv[1] if len(sys.argv) > 1 else '20240507_SATURN'
    if cid not in TARGETS:
        print(f'unknown case {cid}; known: {list(TARGETS)[:5]}...'); sys.exit(2)

    # ===== STEP 1: READ SOURCE (verified Etherscan source, NEVER a PoC) =====
    victim, block, sources = parse_target(TARGETS[cid])
    main_src, full_src, cname = load_full_source(sources)

    # ===== STEP 2: READ CONTEXT (assemble info layers 1-9) =====
    ctx = vc.build_context(block, victim, main_src)                 # layer 3
    warnings = sa.extract_constraints(block, victim, main_src)       # layer 6
    iface, nfunc, ngetter = sa.extract_interface(main_src)          # layer 5
    niface = nfunc + ngetter
    iface_ok, iface_note = sa.iface_compiles(iface)
    if not iface_ok:
        print(f'[minimal] WARNING: extracted IVictim did NOT compile standalone: {redact(iface_note)[:300]}', flush=True)
    rag_hints, refs_used = build_rag_block(ctx, main_src, cid)      # layer 9
    pit_block = render_pitfalls_block(_load_pitfalls())             # layer 8
    iface_txt = (iface + '\n') if iface else '(no elementary-typed external/public signatures extracted)\n'

    out = Path('data/minimal_agent') / re.sub(r'\W+', '_', cid)
    out.mkdir(parents=True, exist_ok=True)

    # shared CONTEXT PACK fed to BOTH the plan step and the write step
    ctx_pack = (
        f'# VICTIM (address the loop measures): {victim}\n'
        f'# FORK BLOCK: {block}\n'
        f'# VERIFIED SOURCE CONTRACT(S): {cname} @ {", ".join(sources)}\n'
        '\n# LIVE ON-CHAIN CONTEXT (read live via cast at the fork block):\n' + ctx
        + (('\n\n# ' + warnings + '\n') if warnings else '')
        + f'\n\n# TARGET INTERFACE (extracted external/public signatures + getters of {cname}; '
          f'call it as IVictim(VICTIM); {niface} signatures):\n' + iface_txt
        + '\n\n# ' + sa.DEX_REF + '\n'
        + '\n\n# ' + pit_block.rstrip('\n') + ('\n' if pit_block else '')
        + '\n\n# HISTORICAL ATTACK PARADIGMS (advisory hints only; NOT this contract\'s PoC):\n' + rag_hints
        + f'\n\n# VERIFIED CONTRACT SOURCE (contract {cname}; on-chain Etherscan source, NOT a PoC):\n'
        + main_src
    )
    (out / 'CONTEXT.txt').write_text(ctx_pack)
    (out / 'WARNINGS.txt').write_text(warnings or '')
    if warnings:
        print('[minimal] transfer-constraint warnings:\n' + redact(warnings), flush=True)
    print(f'[minimal] case={cid} victim={victim} block={block} source={cname} model={MODEL} '
          f'iface_sigs={niface} (fn={nfunc} getter={ngetter}) iface_compiles={iface_ok} '
          f'rag_refs={len(refs_used)} rag={USE_RAG}', flush=True)

    transcript = []

    def call(model, prompt, label):
        t0 = time.time()
        try:
            text = llm.gen_model(model, prompt, temp=TEMP)
        except Exception as e:
            msg = redact(str(e))
            if '402' in msg:
                print(f'[{label}] HTTP 402 payment required — STOPPING.', flush=True); raise SystemExit(3)
            print(f'[{label}] model error: {msg[:200]} — STOPPING.', flush=True); raise SystemExit(4)
        dt = time.time() - t0
        transcript.append({'step': label, 'gen_s': round(dt, 1), 'chars': len(text or '')})
        print(f'[{label}] done in {dt:.1f}s ({len(text or "")} chars)', flush=True)
        return text

    # ===== STEP 3: PLAN (one LLM call — prose mechanism/strategy, NOT PoC code) =====
    plan_prompt = (
        PLAN_SYS + '\n\n' + ctx_pack
        + '\n\n# NOW: write the ATTACK PLAN in prose (mechanism + ordered steps + constraints). '
          'No Solidity, no code fences.'
    )
    plan = (call(MODEL, plan_prompt, 'plan') or '').strip()
    (out / 'plan.md').write_text(plan)

    # ===== STEP 4: WRITE CODE (one LLM call — fill attack body into pinned skeleton) =====
    write_prompt = (
        sa.SKEL_SYS + '\n\n' + ctx_pack
        + '\n\n# ATTACK PLAN (your own prior analysis; follow this mechanism — strategy/prose, NOT a '
          'PoC; you now write the actual Solidity body):\n' + plan + '\n'
        + '\n# HISTORICAL ATTACK PARADIGMS (advisory, from RAG):\n' + rag_hints + '\n'
        + '\n# The scaffold (pragma/imports/Test/setUp fork+deal/testExploit + IPancakeRouter/IWBNB and '
          'ROUTER/WBNB/FACTORY constants + IVictim) is FIXED. Write ONLY the testExploit() body '
          '(+ optional //---EXTRA--- helper defs).'
    )
    raw = call(MODEL, write_prompt, 'write')
    body, extra = sa.parse_skel_output(raw)
    (out / 'round1.body.txt').write_text(body + ('\n//---EXTRA---\n' + extra if extra else ''))

    outcome, reason, depth, max_depth = 'no-code', None, None, -1
    if not body.strip():
        outcome, reason = 'empty-body', 'model returned empty attack body'
        print('[verify] empty body returned — nothing to verify', flush=True)
        sol = None
    else:
        sol = sa.build_skeleton(victim, block, iface, body, extra)
        (out / 'round1.sol').write_text(sol)
        # ===== STEP 5: VERIFY ONCE (same confirm path; NO retry) =====
        sol2, ierr = inject_confirm(sol, victim)
        if ierr:
            outcome, reason, depth = 'inject-reject', f'inject reject: {ierr}', 0
            print(f'[verify] inject rejected: {redact(str(ierr))[:160]}', flush=True)
        else:
            (out / 'round1.injected.sol').write_text(sol2)
            write_proj(out, sol2)
            t1 = time.time()
            ok, fo = run_forge_verbose(out)
            forge_dt = time.time() - t1
            reason = parse_reason(ok, fo)
            depth = depth_of(ok, reason, fo)
            if depth is not None:
                max_depth = max(max_depth, depth)
            outcome = 'VERIFIED' if ok else 'fail'
            if ok:
                (out / 'SUCCESS.sol').write_text(sol2)
            print(f'[verify] ok={ok} depth={depth} reason={redact(str(reason))[:160]} forge={forge_dt:.0f}s', flush=True)
    if depth is not None:
        max_depth = max(max_depth, depth)

    pt, ct, cost = sa.est_cost()
    result = {
        'case': cid, 'victim': victim, 'block': block, 'model': MODEL,
        'pipeline': 'read-source -> read-context -> plan -> write -> verify-once (NO retry)',
        'use_rag': USE_RAG, 'rag_refs': refs_used,
        'iface_sigs': niface, 'iface_fn': nfunc, 'iface_getter': ngetter, 'iface_compiles': iface_ok,
        'outcome': outcome, 'verified': outcome == 'VERIFIED', 'max_depth': max_depth,
        'reason': redact(str(reason)) if reason is not None else None,
        'prompt_tokens': pt, 'completion_tokens': ct, 'est_cost_usd': round(cost, 4),
        'steps': transcript,
    }
    (out / 'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=1))
    (out / 'transcript.jsonl').write_text('\n'.join(json.dumps(t, ensure_ascii=False) for t in transcript))
    print('\n=== RESULT ===')
    print(f'{outcome} | max_depth={max_depth} | reason={redact(str(reason))[:160]}')
    print(f'tokens in/out {pt}/{ct} | est cost ${cost:.4f} | artifacts: {out}')


if __name__ == '__main__':
    main()
