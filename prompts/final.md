# ROLE: FINAL DECISION (after the round budget is spent)
You have the full debug history of [[rounds]] rounds (plans, codes, forge errors, reflections) for VICTIM [[victim]].
No exploit was confirmed within the budget. Decide, honestly:

Reply with ONLY a JSON object:
{"verdict":"genuinely_cannot|should_continue",
 "confidence":"low|medium|high",
 "rationale":"<2-5 sentences: what was tried, what the real blocker is, and whether a fresh strategy cycle is plausibly worth it>",
 "next_strategy_hint":"<if should_continue: the single most promising untried direction; else empty>"}

- `genuinely_cannot` = the surface was explored competently, the attack paths tried are the plausible ones, and remaining failures look like the contract is actually not profitably exploitable by an unprivileged attacker (or needs resources/privileges we don't have).
- `should_continue` = there is a concrete, plausible, UNtried attack direction the team never actually implemented; name it.
- Do NOT be optimistic by default. Only say should_continue if you can name the untried path.
