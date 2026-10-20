# Iterations (dev = subset2g 11 + subset2j 16 = 27; holdout = holdout.txt, 10 random from the 144, seed 42, fixed)
Scores are func/reason hits in the top 3. Strict = Jev judge with func_hit decided from function names only (the default now).
Lenient = the old judge, which sees the reason text (JUDGE_OLD=1). Judge noise is about ±2-3 cases: identical picks flip when only the reason wording changes.
Baselines: one-shot check: dev strict 14/12, lenient 20/17. Gemini (11 cases only): strict 7/5, lenient 7/6.

| # | Hypothesis | Change | Dev strict | Dev lenient | Holdout (strict) | Qualitative | Kept |
|---|---|---|---|---|---|---|---|
| 1 | Precondition decomposition makes verification reliable | DeepSeek splits each neighbour's root cause into 3-4 preconditions; Jev answers each; confirm if min p ≥ T | - | 15/13 (11-case set: 8/7 at T=0.5) | - | precision 1/19 on dev (0/4 on the 11-case set); neighbours often of the wrong mechanism; generic preconditions are true for most functions | no |
| 2 | The reason text hides the true mechanism (top-2 by weight, so spot price always wins) | why = every mechanism with p ≥ 0.45, sorted by p | 14/12 | 21/18 | - | more honest reasons; ranking unchanged | yes |
| 3 | The access-control question gives every function a high p, so its weight is noise | weight 26 -> 8 | - | 19/17 | - | worse | no |
| 4 | The reentrancy question is too vague | concrete version: send / caller-supplied call before balances are written, unless nonReentrant | 14/12 | 22/20 | 9/7 (check 9/6, Gemini 8/7) | Visor and Bacon reasons now mention reentrancy | yes |
| 5 | A DeepSeek attack path per function improves the reason | 1-2 sentences per pick appended to why | 14/12 | 15/13 | - | the forced story per function hallucinates; it confuses the lenient judge | no |
| 6 | A single contract-level DeepSeek note (with "no concrete path" allowed) is useful and safe | explain.py: separate `attack` field, ranking untouched | 14/12 (=4) | = | - | good on BeatXswap (slot0 tick manipulation in _executeMint), partly right on Visor (owner() of a caller-supplied `from`), wrong on Aztec (guesses reentrancy) | yes (usefulness) |
| 7 | ERC20 wrapper functions crowd out the real ones | rank +3 for transfer/transferFrom/approve | 13/11 | 22/20 | - | no gain | no |
Stopped: rounds 5-7 gave no score gain (3 in a row). loop.py (verifier loop) was deleted as superseded; backup at /tmp/loop_final_backup.py; data/preconds.jsonl kept.

## Milestone: experiments A (safe contracts) and B (Code4rena proxy). Version: R4 ranking + R6 explain.py
A, 10 audited contracts with no known exploit: Uniswap V2 router and pair, Uniswap V3 SwapRouter, Aave V3 Pool, Compound cETH, Lido stETH, MetaMorpho, UNI StakingRewards, OP L1StandardBridge, DAI.
- explain.py asserts a concrete path (Jev p≥0.5) on 6/10 safe contracts, versus 20/27 on the exploited dev set. Every safe claim is a false positive.
  - Known or acceptable design (3): reserve skew before addLiquidity (Router; minAmount params cover it); flash-swap price manipulation (Pair; the K check covers it); DAI pull() spending an allowance the victim granted.
  - Plausible but wrong (3): cETH malicious cTokenCollateral (the comptroller checks the market is listed); Lido transferFrom share-rate manipulation; V3 recipient re-entrancy.
- top_w (checklist score of the top function) does not separate them: safe 42-106 (median ~80) vs dev 27-110 (median ~87). No usable threshold.
B, Code4rena 2025 (source at the contest commit; retrieval limited to cases before the contest):
- NextGen Forwarder (H-01 signature replay via domainSeparator, M-03 deadline), Kinetiq StakingManager (3H/5M), Virtuals AgentVeToken (H-02 stake delegate, M-19/M-20 withdraw), ServiceNft (H-03 public updateImpact), ContributionNft (H-04 public mint).
- Function overlap: in 5/5 contracts the top 3 includes a function with a High/Medium finding (execute; queue/confirmWithdrawal; stake/withdraw; updateImpact; mint).
- Mechanism/text: matches about 0-1 of 5 (AgentVeToken withdraw is loosely related to M-19). The checklist has no signature-replay item, so H-01 was missed.
- Noise: 5 concrete claims, all wrong or off-target. Kinetiq "steal others' withdrawals" is false: _processConfirmation is keyed by [user][id]. The callee code was cut off at 400 chars, so the model hallucinated the rest.
Design lessons: (1) ranking is a useful "where to look" signal; (2) free-text attack paths produce many false positives, so they need a skeptic step and a "no finding" output; (3) give callees in full; (4) add a signature/replay question.
Next phase plan: R8 structured claims plus a Jev skeptic (blocked by visible checks? needs privilege/misconfig/victim approval/hidden code? attacker gains?) -> confidence -> "no finding" threshold; R9 a signature/replay checklist question; R10 a report.py one-command end-to-end report (address/chain or source); then scale up 11 -> 27 -> holdout -> plus safe and C4.

| # | Hypothesis | Change | Dev (27) | Holdout (10) | Safe (10) / C4 (5) | Qualitative | Kept |
|---|---|---|---|---|---|---|---|
| 8 | Structured claims + Jev skeptic cut false positives | DeepSeek returns JSON claims; full callees given; Jev scores blocked/needs/gain; conf = gain·(1-blocked)·(1-needs); "no finding" below TAU | ranking unchanged; findings at TAU .15: 4/27, 2 with the right function | 4/10, 1 right | safe false-positive findings 6/10 -> 1/10 (TAU .15); C4 0/5 | the skeptic marks almost every claim low (conf 0.02-0.26), so the gain is mostly fewer claims, with weak discrimination; the AgentVeToken stake claim now states C4 H-02 exactly | yes (fewer FPs) |
| 9 | The checklist misses signature replay (C4 H-01) | add a 'signature replay' question (weight 5) | strict 15/12 vs 14/12; lenient 21/18 vs 22/20 | 8/6 vs 9/7 | Forwarder execute now carries a signature-replay reason (matches H-01) | within noise on dev/holdout | yes (coverage) |
| 10 | End-to-end tool | explain.py -> report.py: input 0xaddr [chainid] or file.sol -> markdown (ranked functions + similar cases + claims with confidence + verdict) | - | - | - | works on a live address (UNI StakingRewards: "no finding") | yes |
Note: report.py on cases uses the default SEL (new) contract selection, so dev ranking numbers from f_dev (13/11) are not comparable with the SEL=jev runs.
Stopped here: the solid version is reached; further Jev-skeptic tuning is not promising (conf is weakly discriminative).

## Phase: execution verification (R11) — BLOCKED
Hypothesis: Foundry fork PoCs at the incident block can confirm/reject attack hypotheses with ground truth (attacker profit).
Setup done:
- Foundry 1.8.5 installed (`~/.foundry/bin/forge`).
- Minimal `verify.py` (~45 lines): DeepSeek writes Attack.t.sol -> forge test (N<=3 repairs) -> confirmed only if suite ok. Never reads DeFiHackLabs PoCs. Needs BSC_RPC / ETH_RPC archive endpoints.
- Model plan: DeepSeek V3.2 ($0.21/$0.31 per M) — stronger Coding Index than Qwen3 Coder Next (44 vs 36) and cheaper on output; keep using it.
RPC probe (historical eth_getBalance / forge createSelectFork):
- bsc-dataseed*, defibit, ninicoin: missing trie node (pruned). Forge: "trying to fork from an older block with a non-archive node".
- ankr (bsc/eth): requires API key.
- publicnode / blastapi / drpc / 1rpc / meowrpc / blockreq / llamarpc: 403 or SSL fail.
- gnfd-bsc-archiver: only eth_getBlockByNumber, not eth_getBalance / eth_call.
- Even BeatXswap block 120873719 (recent) fails on public dataseeds.
Pilot not run (would invent nothing). Cost this round ≈ $0 (no LLM PoC generation).
Unblock: user provides BSC_RPC and ETH_RPC archive URLs (Ankr free tier with key, Alchemy, QuickNode, etc.), then re-run `BSC_RPC=... ETH_RPC=... .venv/bin/python verify.py pilot.jsonl pilot_out.jsonl` on 5 exploited + 2-3 safe cases.

## Phase: execution verification (R11–R13) — pilot complete, not promising to scale
Unblocked: user BSC_RPC archive works (eth_getBalance + forge fork at Wault 9728755 / BeatXswap 120873719). ETH skipped (no ETH_RPC).
Pilot: 5 exploited BSC (BeatXswap, SKP, XSURGE, Wault, P719) + 2 safe (PCS Router, PCS Pair). Never fed DeFiHackLabs PoCs/READMEs.
R11: N=3, TOP<=2; all 12 claim runs FAILED at runtime (compile+fork OK). Safe: Pancake:K / wrong assert — no false confirm. Cost ~$0.016, ~143s.
R12: richer prompt + similar earlier root causes. XSURGE `_transferFrom` "confirmed" in 2 attempts — FALSE POSITIVE: test used `deal(WBNB, attacker, before+flashLoan)` after snapshot; no real victim drain. Other 5/6 failed. BeatXswap missing from partial file.
R13: require snapshot AFTER funding; assertGt(attacker) AND assertLt(victim); reject deal()-after-snapshot in harness. Parallel 7 cases, FORGE_TO=45, N=3, TOP=1. All 7 FAILED in 201s (XSURGE correctly rejected). Cost ~$0.020. No true confirmations, no false confirmations.
Bottleneck: not RPC (fork ~0.1–0.3s); DeepSeek cannot invent a working multi-step exploit from checklist sketch alone in 3 repairs. Verdict: keep verify.py as optional gate; do not scale until hypotheses are stronger or we allow more attempts/tools.

- ctx1 (BeatXswap, N=1, +on-chain CONTEXT, no hint): gpt-5.3-codex 单轮生成，$0.16。形态上用对了 V3 TARGET_POOL 操纵现价（不再像 arm b 去空的 V2 闪贷），但 CONTEXT 里 minDepositUSDT 用了源码默认 1e17（实链是 1e22=1万 USDT），模型硬编码 10 USDT 存款 → deposit 立即 InsufficientDeposit() revert，比 arm a 还早挂。教训：周边状态必须 cast 实时取（含可变参数），且提示模型读链上值而非硬编码。
- ctx2 (BeatXswap, N=1, +修正后的实时 CONTEXT + 要求运行时读链上值): gpt-5.3-codex 单轮，$0.18。首次完整跑通攻击路径（deposit→warp→withdraw→砸 V3 现价→再 deposit→withdraw→变现）。victim BTX 被真实榨走 68.08 万（储备的 54.9%），assertLt(victim) 通过；但 assertGt(attacker) 失败——攻击者净亏约 3,429 USDT，因为把 68 万 BTX 倒进只有 4.7k BTX 的唯一池子直接把价砸没，榨到的 BTX 卖不出价。结论：机制成立且首次真实掏空受害者，差的是「赃物变现受制于 BTX 流动性深度」这一真实市场约束，不是代码错。比 ctx1（门槛即挂）和 arm a/b（都亏且没掏空）都更近一步。

## 确认判据变更 (2026-10-19)
verify 成功标准从「攻击者净赚 USDT」改为「受害者资产被真实转走/控制」：victim 某资产余额下降 且 该同一资产进入攻击者控制地址（攻击者该资产余额上升约等于受害者损失）。不再要求把赃物换成 USDT 利润。anti-cheat 保留：资金必须 snapshot 前 deal()，snapshot 后禁 deal()；攻击者增持的资产必须与受害者损失的是同一种，防止 deal 别的币冒充。
- ctx2 BeatXswap 按新判据 = **CONFIRMED（首个确认案例）**：掏空受害者 54.9% BTX（1,240,403→559,564，被攻击者转走 68.08 万 BTX）。旧判据因 BTX 无流动性卖不出价而判 fail；新判据正确反映"资产已被攻击者控制"。

## 新判据 N=1 批量验证 (2026-10-19, verify_ctx.py, 实时 cast CONTEXT + 无硬编码 + 无 hint + gpt-5.3-codex)
- XSURGE (0xe1e1..6c21, blk 10087723): **CONFIRMED**。sell 重入抽干底层 BNB，victim BNB 13,610→1,064（-92%，12,546 BNB 进攻击者）。
- WaultFinance WUSDMaster (0xa79f..759a, blk 9728755): **CONFIRMED**。redeem 用现货 wex.balanceOf 计价，捐赠抬高后赎回；victim 自有 WEX 109,399,572→108,631,834（净失 767,738 WEX，攻击者净 -51,750 USDT 换 +2.42M WEX）。
- P719Token (0x172f..f849=PancakeV3Pool, blk 43023423): **NOT confirmed**。模型选了 collectProtocol（权限函数，非 owner revert），单轮未命中。真洞应在 swap/flash/mint 回调，N=1 没写对。
- 成本：XSURGE $0.12 / Wault $0.08 / P719 $0.09，合计 ≈$0.29。判据变更后 4 案例中 3 个 confirmed（BeatXswap, XSURGE, Wault）。

## Jev 排序单独评测 (2026-10-19, eval_rank.py, f_dev 27 案例, 仅排序不跑 forge/PoC)
func_hit@1=8/27 (30%), func_hit@3=13/27 (48%)，严格 names-only judge，成本可忽略(全 Jev,多命中缓存)。
分机制 @3: spot_price 6/7, reentrancy 4/6, access_control 2/9(最弱), balance_manip 0/2, rounding 0/2, state_machine 1/1。
top-3 失败 14 例归类: (A)权限入口被通用 transfer/stake/mint 挤下 5 例[Civfund drain类#6-8, Unverified_8490 `drain`#7, LaunchZone#12, Shezmu borrowFor#10, Stead]; (B)真函数差一名在#4-5 共2例[JoeAgent removeLiquidityViaContract#5, Hundred redeemUnderlying#4]; (C)选错受害合约/跨合约 3例[BeatXswap 选了 Moolah 借贷而非 LiquidityVestingConvert(真合约在候选却落选), Thetanuts 选 Morpho, 0xf340 选 LinkToken]; (D)真函数是未索引的回调/跨合约入口 2例[InternetToken 伪造V3回调mint, Flamincome stakeFor#8+withdrawAll#5]; (E)judge 严格/locus 在已列内部 2例[SKP burn#2, KR _transfer#3]。
结论: 最大短板是 access_control 入口排序(被标准代币/质押函数压制)和受害合约选择(跨合约事件挑错合约)。

## 威胁模型排序实验 B (2026-10-19, RANK=threat 开关, fetch_source.py 新增 jev_threat, 不覆盖旧 check)
把 checklist 换成一条统一威胁问题(匿名无权限攻击者能否造成受害者净流出/夺权, noul 概率) + 一条前置权限降权问(w=p_attack*(1-0.6*p_priv))，无函数名关键词特判。同 27 个 f_dev、同受害合约(vaddr 27/27 一致)、同严格 judge。
结果: A(check) @1=8/27(30%) @3=13/27(48%) → B(threat) @1=7/27(26%) @3=11/27(41%)。**整体回退，不采用**。
分机制 @3: spot_price 6→6(持平,未回退), access_control 2→2(目标没改善), reentrancy 4→**2**(严重回退), balance_manip 0→0, rounding 0→0。
翻盘1(Shezmu access_control borrow 进前三); 翻落3(Cream/Bacon reentrancy 跌出 + MBC access_control)。
根因: 威胁问的"前置权限降权"把重入类入口误降(重入常被判为需回调/授权前置, p_priv 高), 价格类稳但重入塌 = 拆东墙补西墙; 对 access_control 也没正向帮助。保留开关备查, 默认仍 RANK=check。成本 ~$0.006(全 Jev)。

## 逐函数正负打标实验 C (2026-10-19, RANK=label 开关, fetch_source.py 新增 jev_label + ATTACK_CLASSES 分类清单, 不覆盖旧逻辑)
分类清单来源: OWASP Smart Contract Top 10 (2026)、SWC Registry、s0sta/DeFiHackLabs 攻击类别统计。12 类(访问控制/价格操纵/重入/闪贷放大/算术舍入/代币自定义transfer/捐赠份额膨胀/签名重放/未校验外部调用/业务会计/无授权增发/状态机初始化)，每类一句话写进 Jev 单问 noul。同 27 f_dev、同受害合约、口径改为"真函数是否被标正(recall) + 平均正例清单长度"。
阈值权衡(recall / 平均清单长度, 总函数均18.4): 0.10→67%/12.9, 0.15→67%/10.1, 0.20→67%/8.3, **0.30→70%/6.3(最佳)**, 0.40→63%/4.2, 0.50→33%/2.5。
对比旧排序 func_hit@3=48%(固定3个): label@0.3 recall 70% 用~6.3函数, label@0.4 63% 用4.2函数——**召回显著抬升且无回退**。分机制@0.3: reentrancy 6/6(排序4/6), spot_price 6/7(持平), balance_manip 2/2(排序0/2), access_control 4/9(排序2/9,翻倍但仍最弱), rounding 0/2, state_machine 1/1。
剩余8个 miss@0.3 多为结构性: 选错受害合约4例(BeatXswap/Thetanuts 选Morpho, 0xf340 选LinkToken, InternetToken 回调未索引) + access_control 残留3例(Civfund/Stead/Unverified_8490 未授权 drain/withdraw/mint 仍低于标准transfer) + 1边界(KR)。剔除选错合约的4例后约 19/23≈83%。成本~$0.012(全Jev)。结论: 打标口径优于排序, 推荐 RANK=label@0.3~0.4。

## access_control 专用两步打标实验 D (2026-10-19, RANK=aclabel, risk=p_sensitive*(1-p_gated))
对每个函数问 (a)是否转资金/增发/改权限配置 p_sensitive, (b)调用者是否被恰当限制(onlyOwner/角色/白名单/等价) p_gated, 风险=p_s*(1-p_g)。只在 9 个 access_control 案例上评。
结果: 未改善。aclabel 最佳 @0.20 recall=4/9(mean_pos 4.0), @0.30 退到 3/9(LaunchZone 跌出); label@0.3 已是 4/9。@0.20 命中集 = {CozyFinance, MBC&ZZSH, LaunchZone, Shezmu}, 与 label@0.3 完全相同——无新翻盘。
三个目标案例仍 miss: Civfund(只标到 transferFrom, withdrawERC20/withdrawETH/mintToken 没被捕捉)、Stead(pos=[])、Unverified_8490(标到授权函数但真 `drain` 没进)。推断这些不是"源码里明显未保护的敏感函数"模式: 真入口要么在源码里看着是 gated(owner), 要么是跨合约/其他合约, 两步问法抓不到。0xf340/InternetToken 属选错合约/未索引。结论: 两步 AC 问法不优于通用 label@0.3, 不采用。成本~$0.008。

## 入口选择攻关实验 E (2026-10-19, 默认 SEL 改为 jev, 维持 label@0.3)
诊断: victim() 用 PoC-call-count 打分, 偏向攻击路由经过的大型借贷/基础壳合约而非有漏洞的自定义合约 (BeatXswap 选 Moolah 44fns 而非 LiquidityVestingConvert; Thetanuts 选 Morpho; 0xf340 选 LinkToken; InternetToken 选 RewardToken)。
改动: 把默认 SEL 从 'new' 改为 'jev' (让 Jev 在候选里选"有自定义漏洞逻辑的受害合约, 而非通用 pair/router/WETH/标准代币/借贷壳")。无新增代码, 仅切换已有分支。
效果 (同 27 f_dev, RANK=label@0.3): recall 19/27(70%) -> **20/27(74%)**, meanpos 6.3->6.4, **零回退**。vaddr 修正 3 例: BeatXswap(Moolah->LiquidityVestingConvert, deposit=0.56/_executeMint=0.44 已标正), InternetToken(RewardToken->LiquidityUnifier, 救回 recall), Flamincome(BaseRewardPool->VaultYUSDT, 与 root "VaultYUSDT overpays" 一致)。
剩余结构性 miss 的天花板(非选择 bug): 真受害合约在候选里不可得——Thetanuts(0x80b8ee)/0xf340(0xf340bd3e)/Shezmu(0x641249)/Civfund(0x7caec5) 源码**未验证**(无源码可分析), Stead(0xf9ff93) 是 TransparentUpgradeableProxy(实现未解析)。这些是数据层面天花板, 选择/索引改不动。
BeatXswap 虽选对合约且 deposit 已标正, 严格 judge 仍判边界 miss(PoC 经 Moolah flashLoan 路由, judge 噪声±2-3)。结论: SEL=jev 采纳为默认。成本~$0.012(全 Jev)。

## 消融: 生成阶段历史相似案例参考 (2026-10-19, report.py 新增 NO_RAG=1 开关, 不覆盖旧逻辑)
NO_RAG=1 让 explain() 不把 similar earlier incidents 的 root_cause 拼进 DeepSeek prompt(并去掉提示里"root causes of similar past incidents"一句)。在 BeatXswap/XSURGE/Wault 上对比带/不带参考的生成假设(function/class/path + Jev skeptic conf):
- WaultFinance: **参考明显有帮助**。WITH 顶 claim = redeem(balance manipulation, 捐 wex 抬高 wex.balanceOf/wusd.totalSupply) conf 0.449 = finding, 正是已确认的真洞; NO_RAG 顶 claim 变成 stake(fee-on-transfer) conf 0.329, redeem 掉到 0.100 → finding 选错(stake)。参考把正确的 redeem 假设顶上来且 conf 提升 4.5x。
- BeatXswap: 中性。两版都顶 deposit + 价格操纵(slot0 tick), conf WITH 0.192 vs NO_RAG 0.204, 结论一致(finding=deposit)。
- XSURGE: 两版都偏弱。WITH 给出 sell(Reentrancy)claim 但 conf 仅 0.072 → no finding; NO_RAG 顶 _transferFrom(fee-on-transfer rounding)0.199 = finding(机制偏)。都没把 sell 重入自信地放首位; WITH 机制标注(显式 Reentrancy)更贴近真因。喂的相似案例是 SpankChain(重入)/Parity, 相关但没能抬高 conf。
结论: 历史参考总体有帮助(尤其 Wault 把 finding 从错误的 stake 纠正回 redeem 并大幅提 conf), 其余中性/略好, 未见明显负面。保留默认带参考, NO_RAG 仅作消融开关。成本~$0.012(WITH 命中缓存, 仅 NO_RAG 3 次 DeepSeek 新生成)。

## 2026-10-19 实验F：简化检索（summary嵌入粗筛top-10 + Jev判参考价值）vs 现有 fused+sum RRF
- 新文件 rag_jev.py（rag.py 没改，cases.jsonl 没改）。按时间切分，只用更早的案例；指标是类别匹配 R@k/MRR。
- 小批 n=7：简化 R@1 0.57 / R@5 0.86 / MRR 0.671，基线 0.43 / 0.71 / 0.571（看着像变好了，其实是小样本噪声）
- 全量 n=140：简化 R@1 0.43 R@3 0.69 R@5 0.81 MRR 0.574，基线 0.48 / 0.74 / 0.84 / 0.619 → 简化版小幅回退
- 结论：Jev 判参考价值替代不了多通道嵌入，默认不切换。成本约 1400 次 Jev 调用，约 $0.014

## 实验 G: 强 LLM 直读全部受害合约源码 vs report.py 流水线 (2026-10-19, 新脚本 exp_direct.py, 未改现有文件)
设置: 5 个 f_dev 案例(XSURGE 重入 / Wault 价格操纵 / MonoX 价格操纵 / LaunchZone 权限 / KR 精度); 受害合约用 SEL=jev 已选的 vaddr, 源码来自 fetch_source 缓存(去掉 OZ/interfaces/lib)。强模型 google/gemini-2.5-pro(1M 上下文, 比 gpt-5.3-codex 便宜且快), prompt 只给源码+地址+链, 输出 1~3 个函数+机制+路径。流水线 = RANK=label SEL=jev report.py, 函数顺序 = claims(按 skeptic conf) 后接 picks。严格 judge(names-only)。
| 案例 | 直读 @1/@3 | 流水线 @1/@3 | 备注 |
| XSURGE | 1/1 sell | 1/1 sell | 两边都选对函数, 都没说出重入(直读说成首次购买舍入, 流水线说成价格) |
| Wault | 1/1 stake | 1/1 redeem | 直读: stake 内 swap 无滑点被三明治→推 WEX 价, 贴近真机制; 流水线本次 DeepSeek 无 claim → finding=no finding |
| MonoX | 1/1 swapExactTokenForToken | 0/0 listNewToken | 直读准确说出 tokenIn==tokenOut 重复抬价——正是真因; 流水线完全错过 |
| LaunchZone | 0/1 | 0/0 | 两边机制都不对(真因为权限) |
| KR | 0/0 | 0/0 | 都没找到精度问题 |
合计: 直读 @1 3/5, @3 4/5; 流水线 @1 2/5(按 finding 只有 XSURGE/MonoX 有 finding, 且 MonoX 错), @3 2/5。无类别回退, 直读机制描述明显更具体。
成本/耗时: gemini-2.5-pro 每例 $0.066~0.132(推理 token 5k~9.6k 占大头), 5 例合计 ~$0.53; 单例 ~1~1.5 分钟。流水线每例 ~$0.003(Jev+DeepSeek)。
结论: 小样本(n=5, judge 噪声±1)下直读不差且更准, 尤其价格操纵类; 成本高约 40x 但绝对值仍低(~$0.1/合约)。值得在 27 个 f_dev 全量验证后再决定是否用直读替代 Jev 打标/排序/复核; 权限/精度两类两边都弱, 不是这一步的瓶颈。

## 实验 H: goal-driven loop (3步主线) 小量测 (2026-10-19, 新文件 loop.py, 复用 fetch_source/llm/verify_ctx)
参考 Grok Build (github.com/xai-org/grok-build) 的 agent loop: 每轮"组装上下文→模型产出单个工具调用(JSON)→分发执行→把结果回喂进对话历史→重复, 直到终止态或回合预算(MAXR=4)耗尽"。本 loop 把它特化成3个工具: read_chain(cast 实时读链上值)、run_test(forge fork 执行)、declare_no_risk(有理由地判无风险)。Goal 为运行时状态, 两终止态: VERIFIED(forge 跑通+反作弊) 或 NO_RISK。确认判据: 受害者某资产下降且同一资产进入攻击者=成功, 攻击者净赚不计。反作弊: deal() 只在快照前。链上周边状态(min值/余额/价格)全部 fork 区块 cast 实时读, 不用源码常量。模型 gemini-2.5-pro via gen_model。绝不读 PoC/README, 密钥/RPC 不打印, URL 遮蔽。
只测 BSC 案例(仅有 BSC_RPC; MonoX 在 mainnet, 无 RPC, 本轮跳过)。
| 案例 | 结局 | 轮数 | 耗时 |
| XSURGE(重入/首购价格) | **verified** | 2 | 116s |
| Wault(价格操纵) | over_budget | 4 | 243s |
| BeatXswap(价格操纵) | over_budget | 4 | 325s |
| SAFE_PCS_Pair_WBNB_BUSD(应判no-risk) | **误报 verified** | 4 | 495s |
成本: 本轮 loop 共约20次 gemini 调用, ~$1.6。
失败归因(有证据):
- Wault: 4 轮全花在 read_chain(读 usdt/wex/wusd 等地址), 没留回合写测试就超预算 → 预算分配问题, 模型读太多不动手。
- BeatXswap: 浪费一轮在 forge 编译错误——VICTIM 地址用了小写, forge 报 invalid checksum 直接编译失败(非逻辑错)。4 轮没跑通。
- SAFE pair 误报: loop 对安全的 PancakePair 也"跑通"了一个 test(burn/skim/加减流动性往返), 判成 verified。说明当前判据(同资产一增一减)对 AMM pair 这类合约太松, 普通 LP 操作就能让 pair 某资产减少、attacker 增加→假阳性。declare_no_risk 从未被触发。
可修方向(未改): (1) 给模型传 checksum 过的地址, 或 loop 侧自动 toChecksumAddress, 省掉编译往返; (2) 提高 MAXR 或区分"读预算/测试预算", 避免读爆预算; (3) 收紧判据防 AMM 假阳性(例如要求攻击者无需等额注入对价、或净头寸提升), 否则安全合约会被误报。结论: loop 骨架可用(XSURGE 两轮确认), 但判据与预算需要再打磨才能既确认真洞又对安全合约给出 no-risk。

## 独立确认验证器（confirm.py）
- 把确认逻辑从 loop.py 抽到 `confirm.py`（csum/fix_addrs/bogus/confirm_helper/inject_confirm/write_proj/run_forge）；loop.py 改成 import 这些函数，行为不变。
- CLI：`python3 confirm.py check <raw.sol> --victim ADDR --block N [--outdir DIR]` → `{ok, reason, forge_tail}`，不调用模型。
- 离线结果：SAFE 的 skim 往返 → FAIL（没有同资产流失，正确）；合成的原生 BNB 抽取正例 → PASS；XSURGE try2 → FAIL，但这是真阴性：一次买入/卖出，受害者 BNB +1.16，攻击者 −1.16，不是验证器的 bug。现有的 XSURGE 产物里没有一个真正抽到资金。
- 对比（data/confirm/compare.json）：在这 3 个案例上，硬规则、Claude Sonnet 4.5、Jev 的结论全部一致。
- 已知限制：注入点是文件里最后一个 `}`，所以 Test 合约必须是最后一个合约。

## 用 confirm.py 重跑 loop（Claude Sonnet 4.5，4 并行）
| 案例 | outcome | rounds | 失败/原因 |
|---|---|---|---|
| 20210817_XSURGE | over_budget | 4 | 模型写的测试都没真正抽走 BNB（revert / LOOP: no same-asset / 自写断言 "Victim BNB not drained"）；真洞未找到 |
| 20210804_WaultFinace | no_risk | 4 | 模型判定提款均受 onlyOwner/onlyWithdrawer 保护，redeem 为公平 1:1 兑换 |
| 20260909_BeatXswap | no_risk | 3 | 模型判定提款需 owner 权限或公平 USDT 存入+锁仓，无未授权即时抽取 |
| SAFE_PCS_Pair_WBNB_BUSD | over_budget | 4 | 等值操作被 LOOP 确认断言正确拒绝（no same-asset victim-loss/attacker-gain），未误报 |

## confirm criterion: cross-asset (offline only)
- `_loopConfirm` no longer requires same-asset. PASS iff victim net-loss on any tracked asset AND attacker net-gain on any tracked asset AND stolen > paid*(1+THRESH).
- Tracked assets expanded: BNB/WBNB/USDT/BUSD + up to 4 extras discovered from test source + runtime victim.token0()/token1(). Pricing via victim pair reserves or PCS V2 factory; unknown fallback 1e18.
- Offline re-check (no model): SAFE skim FAIL (`no victim asset loss`); XSURGE try2 FAIL (`no victim asset loss`); BeatXswap try3 FAIL (`no attacker asset gain` — BTX moved into LP, attacker held 0); POS native PASS. cases.jsonl md5 unchanged. No commit.

## Expand TARGETS + cross-asset confirm push
- Pushed confirm cross-asset: `62974d1`.
- Expanded `TARGETS` to 22 BSC cases (4 baseline + 18 new). Victim/block from PoC KeyInfo headers only; never fed to model. Skipped Unverified / PancakePair / proxy-only addresses.
- Batch run: `LOOP_MODEL=anthropic/claude-sonnet-4.5` parallel 4, MAXR=4.

## Expand batch (Claude Sonnet 4.5, 22 BSC TARGETS, cross-asset confirm)
- Model: `anthropic/claude-sonnet-4.5`, MAXR=4, workers≤4.
- Mid-run OpenRouter HTTP 402 once; resumed remaining 14 after probe OK. loop.py now catches per-case exceptions so one failure does not abort the pool.
- Outcome counts: **{'no_risk': 15, 'over_budget': 7}**. verified=none.
- Wall clock ~17:17–17:25 America/New_York (first wave + resume). Summary: `expand_batch_summary.json` (data/ still gitignored).
- cases.jsonl md5 unchanged `31f88a35e14b2d73b23a99c66e2ca145`.

| id | outcome | rounds | sec |
|---|---|---|---|
| 20210804_WaultFinace | no_risk | 4 | 42 |
| 20210817_XSURGE | over_budget | 4 | 50 |
| 20221001_BabySwap | no_risk | 2 | 19 |
| 20221006_RES-Token | no_risk | 4 | 34 |
| 20221012_ATK | no_risk | 4 | 51 |
| 20221018_HPAY | no_risk | 3 | 27 |
| 20221025_ULME | no_risk | 4 | 37 |
| 20230704_BambooIA | no_risk | 4 | 29 |
| 20240329_ETHFIN | over_budget | 4 | 49 |
| 20240507_SATURN | over_budget | 4 | 65 |
| 20240529_MetaDragon | no_risk | 3 | 65 |
| 20250121_Ast | no_risk | 4 | 35 |
| 20250316_wKeyDAO | no_risk | 3 | 18 |
| 20250426_Lifeprotocol | no_risk | 2 | 15 |
| 20250427_bitdog | over_budget | 4 | 20 |
| 20250519_BetaPresale | over_budget | 4 | 32 |
| 20260909_BeatXswap | over_budget | 4 | 47 |
| 20260911_GDC | no_risk | 4 | 14 |
| 20260911_ORB | no_risk | 3 | 11 |
| 20260929_LPBonus | no_risk | 4 | 50 |
| 20260930_PositionManager | over_budget | 4 | 37 |
| SAFE_PCS_Pair_WBNB_BUSD | no_risk | 3 | 38 |

## Fix 6 wrong victim addresses + strict goal-loop policy (Oct 19)

Expansion had extracted victim from PoC KeyInfo incorrectly for 6 cases (token/router instead of the "Vulnerable Contract"). Fixed TARGETS to the KeyInfo "Vulnerable Contract" address (metadata only; no PoC attack steps fed to the model):

| case | old (wrong) | new (Vulnerable Contract) |
|------|-------------|---------------------------|
| 20221001_BabySwap | 0x53e5…2657 | 0x5c9f1a9ced41ccc5dcecda5afc317b72f1e49636 (SwapMining) |
| 20221006_RES-Token | 0x04c0…2de7 (ALL_TOKEN) | 0xeccd8b08ac3b587b7175d40fb9c60a20990f8d21 (RES) |
| 20221018_HPAY | 0xc75a…521a (HPAY ERC20) | 0xe9bc03ef08e991a99f1bd095a8590499931dcc30 (MintableAutoCompundRelockBonus) |
| 20240329_ETHFIN | 0xa964…a96c | 0x17bd2e09fa4585c15749f40bb32a6e3db58522ba (EthernalFinanceII) |
| 20250426_Lifeprotocol | 0x19b2…4197 (lifeToken) | 0x42e2773508e2ae8ff9434bea599812e28449e2cd (LifeProtocolContract) |
| 20260929_LPBonus | 0xd8b3…97c1 (MSN token) | 0x52272524a22f941f5489c1233732797314bb054b (LPBonus; block→124759920) |

All 6 new addresses have verified source fetchable from BscScan.

**Goal-loop policy (SYS + loop.py):** each case must reach one of two terminal states — confirm an attack (verifier PASS) or solid evidence it cannot be drained. A single failed/reverting run_test is NOT evidence of safety: `declare_no_risk` is now REJECTED and fed back unless at least one run_test has COMPILED+EXECUTED (tracked via `ran_ok`, using `parse_reason != 'compile error'`), and the reason must cite concrete evidence. Compile/revert errors feed back for a fix within the same MAXR=4 budget (no jump to no_risk). Kept simple, Grok Build style.

Rerun of the 6 (Claude Sonnet 4.5, new policy): no premature no_risk occurred — every case ran ≥1 compiled test.
- BabySwap → no_risk (1 test, LOOP: no victim asset loss)
- ETHFIN → no_risk (1 test, LOOP: no victim asset loss)
- RES-Token → over_budget (2 tests, Pancake TRANSFER_FAILED)
- HPAY → over_budget (2 tests, revert)
- Lifeprotocol → over_budget (2 tests, Invalid trade amount)
- LPBonus → over_budget (2 tests, LOOP: no victim asset loss)

0 verified. cases.jsonl untouched (md5 31f88a35e14b2d73b23a99c66e2ca145).

---

## Densify build_context (max structural reads) + drop declare_no_risk

**Direction (user):** "能读进去的都应该读进去" — read everything readable into context (structural only, no attack-path/vuln-class leakage). And drop the "确凿无法攻击"/`declare_no_risk` terminal path: goal = confirm attack OR hit MAXR=4; one failed test must keep iterating.

### verify_ctx.py — new/expanded sections
- **Live address-getter harvesting (`harvest_live_addrs`)**: calls every zero-arg public/external view getter and every public var (ANY type, incl. custom/struct) raw via `cast call victim NAME()`, parses the returndata into 32-byte words and extracts left-padded 20-byte address words. Filters uint false-positives by requiring the candidate to have bytecode (`cast code`). This finally follows struct members (e.g. PositionManager `poolData` → mainPool/token0Pool/token1Pool/chainlinkDataFeed) and custom-typed public addresses (`IERC20 public baseToken`) that the old primitive-typed probing missed.
- **Discovered addresses auto-join RELATED + get probed** as pool (reserves/slot0/fee/liquidity/token0-1/pool balances) or token (symbol/decimals/supply), tagged `(via <getter>())`.
- **Pool token backfill**: any discovered pool's token0/token1 is probed and added to TOKENS so every referenced token has decimals/supply.
- **Entry points now full signatures** (params + `payable`) instead of names only, plus `receive()`/`fallback()` flagged as raw value receivers.
- **Related non-pool roles** now also show live USDT balance + ERC20 decimals when applicable, not just native BNB.
- Unchanged invariants: all mutable params read LIVE via cast at fork block; header is structural-only; no attack path / vuln class leaked.

**Density effect (CONTEXT.txt chars, before → after):**
- BeatXswap 2776 → 3122
- XSURGE 2090 → 2289
- SATURN 3539 → 4797
- PositionManager 2103 → 3359 (now surfaces the V3 main pool via `poolData()` with reserves/slot0/pool balances + backfilled BTCB — previously the pool was entirely absent)

### loop.py — policy
- Removed `declare_no_risk` entirely (tool + handler + budget hints). SYS states there is NO "declare safe" action; the only terminal success is a run_test the loop confirms.
- `MAXR=4` kept; on forge fail the error tail is fed back and the model keeps writing/fixing until the cap. Non-confirm terminal is now `over_budget`.

## 2026-10-19 — Vectorless RAG for attack paradigms (index.py)

Per t152u: no embeddings. Index all cases → compact structural paradigm sketches → Jev picks which are
transferable at query time. Fast + cheap.

**`index.py`**
- `build_catalogue()`: 347 cases → `data/index/catalogue.jsonl`. Each entry: `{id, date, chain, category,
  loss_short, paradigm, tags}`. `paradigm` = a cheap-LLM (deepseek-v3.2) abstraction of `root_cause` into a
  <=28-word reusable mechanism (e.g. "spot-price read inside a settlement path, moved by a flash-loaned swap,
  then an ungated accept() pays at the manipulated price"), tags = 2-5 mechanism keywords. Disk-cached via
  `llm.gen_model`; rebuild cost ≈ **$0.012** (24 batched calls, 15 cases each).
- `retrieve_refs(ctx, src, query_id, k, chain)`: Jev scores every OTHER case's paradigm against the current
  victim surface (dense CONTEXT + fn signatures) with a `noul` question each, batched 40/call (~9 Jev calls,
  ≈$0.0005/case). Returns top-k `{id, category, paradigm, score, why}`. **Always excludes `query_id`** so a
  target never sees its own PoC. Chain filter is soft (detector weak: 179 unknown) — falls back to all.

**Safety**: paradigms are writeup/KeyInfo-level abstractions (from `root_cause`, not raw PoC `.sol`), shown
only as REFERENCES for OTHER cases; the audited case is excluded from its own retrieval. `cases.jsonl`
untouched (md5 31f88a35e14b2d73b23a99c66e2ca145).

**Smoke** (stored CONTEXT): BeatXswap → access_control paradigms (BRAND, wKeyDAO…); XSURGE → surfaced
price_manipulation (Jimbo, SellToken02) alongside access_control — the right direction. Jev noul 0.59–0.68.

**Proposed hook (not yet wired)**: in `loop.py::one`, after `ctx = vc.build_context(...)`, add
`refs = index.retrieve_refs(ctx, src, query_id=cid, k=5)` and append a block
"SIMILAR HISTORICAL ATTACK PARADIGMS (inspiration only; NOT this contract's PoC):" + the k paradigm lines to
`hist`. Loop ids == case ids, so `query_id=cid` cleanly self-excludes. Next: wire it behind an env flag
(e.g. `USE_RAG=1`) and A/B a few over_budget cases (XSURGE, SATURN, PositionManager, ETHFIN).

## Vectorless RAG wired into loop (USE_RAG default on) + A/B on 4 over_budget cases
- loop.py::one now calls index.retrieve_refs(ctx, src, query_id=cid, k=5) after build_context, appends
  "SIMILAR HISTORICAL ATTACK PARADIGMS (inspiration only; NOT this contract's PoC)" section (paradigm + category + Jev why). Catalogue + Jev only; no embeddings. Query case excluded from candidates (no self-PoC leak).
- Claude Sonnet 4.5, refs on. Outcome vs prior dense-only (all 4 were over_budget):
  | case | before | after(refs) | rounds |
  |------|--------|-------------|--------|
  | 20260930_PositionManager | over_budget | over_budget | 4 |
  | 20210817_XSURGE | over_budget | over_budget | 4 |
  | 20240507_SATURN | over_budget | over_budget | 4 |
  | 20240329_ETHFIN | over_budget | over_budget | 4 |
- 0 flipped to verified. Refs were on-paradigm (XSURGE/SATURN -> price-manipulation; PositionManager -> reentrancy/access-control), but didn't move these 4 over the line within MAXR=4. cases.jsonl untouched.

## Victim pool-position exposure in build_context (USE_RAG kept on)
- `verify_ctx.py`: for each discovered RELATED pool, now reports how much of it the VICTIM itself owns as an LP (not just pool totals), read LIVE at the fork block:
  - V2 pair: victim LP-token balance + % of supply + `~claimable token0/token1` (reserves × share).
  - PancakeV3 pool: victim's concentrated position via `positions(keccak256(owner,tickLower,tickUpper))` using the victim's own int24-pair view getters (e.g. `getTickRange()`); emits `VICTIM V3 position [ticks a,b]: liquidity=… (of pool liquidity …) tokensOwed0/1`.
  - Helpers added: `_ints`, `_i24hex`, `keccak_hex` (cast keccak, no `--block`), `victim_pool_exposure`. Structural exposure only; no attack-path leakage.
- PositionManager CONTEXT now shows its real exposure (wallet USDT is 19 dust, but it holds V3 `liquidity=992703838161699941207` in the USDT/BTCB mainPool `0x46cf…`, ~0.16% of pool liquidity).
- Rerun (Claude sonnet-4.5, MAXR=4): PositionManager over_budget → over_budget. This run both run_test attempts died on a forge-std toolchain compile error (`vm.getNonce` / `vm.computeCreateAddress` undeclared in pinned forge-std), so the new exposure field was never exercised in a running test — not an exposure/context gap. XSURGE / SATURN / ETHFIN also still over_budget (unchanged; different bottlenecks: reentrancy write, routing, long reward chain).
- cases.jsonl untouched (md5 31f88a35…). RPC/keys redacted.

## forge-std pin + confirm injection placement fix (PositionManager rerun)
- Root cause of prior PM `vm.getNonce`/`vm.computeCreateAddress` "Undeclared identifier (vm)" compile errors was NOT the forge-std version (installed forge-std is already 1.17.0, which has both cheatcodes). `inject_confirm` appended the LOOP confirm helper (which calls `vm.getNonce`/`vm.computeCreateAddress`) at the file's last `}`, which for multi-contract tests landed inside a model-defined helper contract (e.g. `FakePool`) that does not inherit forge-std `Test`, so `vm` was out of scope.
- Fix (confirm.py): (1) pin `forge install foundry-rs/forge-std@v1.17.0` in write_proj (fallback to unpinned) so fresh projects deterministically get the cheatcodes; (2) new `_enclosing_close()` injects the confirm helper/wrappers inside the contract holding the renamed `_loop_user_*` test bodies (inherits Test → `vm` in scope) instead of the file's last `}`.
- Verified: PM try4.raw.sol (the FakePool case) now `Compiler run successful!` (runtime FAIL is the exploit reverting, not a compile/vm error). Regression: BeatXswap verified try2 still `confirmed` (ok:true). Single-contract tests unchanged.
- Rerun PositionManager (anthropic/claude-sonnet-4.5, dense ctx, USE_RAG=1, MAXR=4): still **over_budget**, but all 4 rounds now compile+execute (2 read_chain + 2 run_test) and reach the confirm gate ("LOOP: no victim asset loss" / revert) instead of burning 2 rounds on the vm-undeclared compile error. Toolchain/injection blocker removed; remaining gap is the attack path (victim ends with no net asset loss), not the toolchain. cases.jsonl untouched.

## Explicit self-reflection after failures (loop.py)
- SYS schema extended: after ANY failed action (compile error, revert, failed LOOP confirm, or a reject), the next JSON MUST carry a `"reflect"` field placed before `"tool"`: `{"reflect":"...","tool":"run_test","sol":"..."}` (same for read_chain). `reflect` must (a) CLASSIFY the prior failure as exactly `compile/syntax` | `wrong approach` | `almost-right needs fix`, and (b) NAME the concrete change. "Do not resend the same code" added to the trailing rule.
- Enforcement (one(...)): `prev_failed`/`last_fail` tracked; set True on anti-cheat/inject/budget/unrecognized rejects, forge compile/revert/confirm failures, and read_chain `ERR`; cleared on a clean read. When `prev_failed`, the round hint demands `reflect`; a bounded re-ask (up to 2 generations) rejects a missing `reflect` instead of silently burning the round. Reflections are logged (`('reflect', ...)`).
- hist truncation fixed: the per-round echo no longer dumps the whole `.sol` nor truncates to 500 chars — full `sol` is saved as `tryN.raw.sol` and echoed as a `<saved as tryN.raw.sol>` note, while `reflect`/`call` survive intact (echo capped 1400). On a forge failure, hist now appends the failing test's `testExploit` key lines (≤1200c) plus the forge tail (2200c) so the reflection can reference its own prior code.
- Smoke rerun (anthropic/claude-sonnet-4.5, dense ctx, USE_RAG=1, MAXR=4): both PositionManager and XSURGE still **over_budget**, but reflections now appear every post-failure turn and visibly change course:
  - PM r3 `almost-right needs fix` (poolData() returns a struct — read mainPool field), r4 `wrong approach` (callback drained 19 USDT but loot landed at the POOL, not attacker — must be msg.sender / pick a different vector).
  - XSURGE r2 `wrong approach` (equivalent buy→sell loses to 94% fees, victim net-gained — abandon the trade loop, dissect `purchase` prevBNBAmount math), r3/r4 keep pivoting off the prior failure instead of resending.
  - Behavior changed from "retry with error attached" to "classify failure → name change → try different path"; no verified flip within 4 rounds (as expected — still an attack-path reasoning gap, not a toolchain/context gap). cases.jsonl untouched; RPC/keys redacted.

## Grok Build–style role split (Planner / Coder / Reflector / Final decision)
- **What Grok Build does** (DeepWiki 4.4 + goal_planner.rs): Goal Harness orchestrates a team of
  subagents — **Planner** (`GoalPlanner`, writes a persistent `.grok/plan.md`), **Strategist**
  (executes the plan with tools), adversarial **Classifier/Skeptic** panel (majority-vote "done?"),
  and **Summarizer** (final user-facing report). Plan is a markdown file on disk; a scratch root holds
  per-attempt diffs/logs. Planner fails CLOSED; model/harness failures retry once (fail-open). We mirror
  the *role separation* and *persistent plan file*, not the Rust harness.
- **New loop: `loop_roles.py`** (old `loop.py` left intact). Per round:
  Planner → Coder → `run_forge` → (verified? return) → Reflector → if `replan`, Planner re-plans with
  the reflection; else Coder revises with prior sol+error. After MAXR rounds a **Final Decision** model
  reviews the whole history and returns `genuinely_cannot | should_continue` (+ confidence, rationale,
  next_strategy_hint). It does **not** auto-start a second cycle — report only, per request.
- **Layered prompts** in `prompts/` (committed): `planner.md`, `coder.md`, `reflector.md`, `final.md`,
  with `[[placeholder]]` substitution (avoids clashing with literal JSON braces in the templates).
- **Models**: Planner/Reflector/Final = `deepseek/deepseek-v3.2` (cheap); Coder = `anthropic/claude-sonnet-4.5`.
  Overridable via `PLAN_MODEL`/`CODE_MODEL`/`REFL_MODEL`/`FINAL_MODEL`. `USE_RAG=1` (Jev refs) kept, feeds the Planner.
- **Per-case artifacts** under `data/loop/<case>/roles/` (gitignored, runtime): `plan.md` (overwritten on
  replan), `reflect.md` (latest), `history.md` (full plan→code→forge→reflect per round), `final.md`,
  and `tryN.raw.sol`/`tryN.sol`.
- **Safety unchanged**: `confirm.py` verifier untouched and independent; no DeFiHackLabs PoC/README read;
  RAG refs exclude the query case; keys/RPC redacted; `cases.jsonl` never written (md5 31f88a35… stable).
- **Smoke — 20260930_PositionManager (MAXR=4)**: over_budget, 150s, both branches exercised —
  round 1 Reflector `replan` (dropped equivalent-swap framing → Planner re-planned to "stale-Chainlink +
  `reAddLiquidity()` rebalance" mechanism), rounds 2–4 `revise_code` (`almost-right needs fix`, swap
  math / `sqrtPriceLimitX96` bugs). **Final decision: `should_continue`** (medium) — rationale: failures
  were division-by-zero impl bugs in swap params, not an invalid path; `reAddLiquidity()` during
  Chainlink staleness remains untested in a working exploit. next_strategy_hint: stale feed → skew pool
  via large swap → `reAddLiquidity()` → reverse swap, with correct `sqrtPriceLimitX96`/decimals.
  (Per request, the suggested second cycle was NOT started.)


## 确认判据修订 (2026-10-20) — 单条经济不变量

把 N 个补丁式条件(victim 资产下降 / attacker 同资产增益 / stolen>paid·(1+THRESH) / 攻击后现价估值)收敛成一条:

    net = Σ_assets (a1 − a0) · px_snapshot  >  LOOP_MIN_GAIN

- `a0`/`a1` = `_loopSnapAttacker`（this + 所有 CREATE 合约），在 setUp 之后取 → 预充本金已在 a0，净出。
- `px_snapshot` = 新 `_loopSnapPx`，在 exploit body **之前**读一次；confirm 时不再读现价 → 自砸盘不影响估值、现价 oracle 不可操纵。
- 覆盖：铸币砸外部池(wKeyDAO)、掏走但砸没(BeatXswap)、普通抽干、价格操纵；均为「攻击者净值↑」的特例。
- `bogus()` 反作弊一字节未动；`cases.jsonl` md5 不变 (`31f88a35…`)。
- confirm.py 新 md5：`4ac9ce4e2685b16231629c64c3309209`。
- 新旋钮：`LOOP_MIN_GAIN_WEI`（默认 `1e16` = 0.01 base-unit；WBNB=USDT=BNB=1 单位，沿用旧约定）。
- 代价：profit 口径比 victim-drain 松 → 必须用 safe 集复核假阳性（靠阈值 + 快照定价 + a0 扣本金压）。
- 性质：与 2026-10-19 同属正当判据修订（在 confirm.py 内、新 md5、写进 iterations），不是 runner 后门。

### Offline / baseline+safe 复核结果 (zero-cost, 无模型调用)

从离线 `injected.sol` fixtures 反注入(deinject)恢复 raw：删 `/* === LOOP-INJECTED ... */` 到合约末 `}` 前、`_loop_user_(test\w*)`→`\1`；raw fixtures(POS、cheap `tryN.raw.sol`)直接用。每个过新 confirm.check（BSC_RPC 不打印，RPC 已 redact）。结果写 `data/confirm/offline_nv/summary.json`。

| case | expected | got | reason |
|---|---|---|---|
| SAFE (skim) | false | **false** | LOOP: attacker net value gain below threshold |
| SAFE_swap_roundtrip (合成 WBNB→USDT→WBNB) | false | **false** | 同上（本金在 a0 净出、手续费使 net<0） |
| POS (合成正例) | true | **true** | confirmed |
| POS_native | true | **true** | confirmed |
| XSURGE cheap try5 (已验证正例) | true | **true** | confirmed |
| XSURGE_try2 | — | false | net value gain below threshold（本就是失败 try） |
| BeatXswap_try3 | — | false | net value gain below threshold（未翻盘：赃物非攻击者持有/低于阈值） |
| BambooIA_try9 | — | false | net value gain below threshold |
| wKeyDAO_try11 | — | false | net value gain below threshold |
| LPBonus_try10 | — | false | setUp INSUFFICIENT_LIQUIDITY（工程错，非 confirm） |
| ULME_try11 | — | false | agent 自带 balanceOf require（非 confirm） |
| GDC_try11 | — | false | agent 自带 'Victim WBNB not decreased' require（非 confirm 判决） |

**无假阳性**：SAFE skim 与合成 LP round-trip 都保持 false；三个已知正例(POS/POS_native/XSURGE verified)全部保持 true。新判据对真利润/真安全的判别在离线集上与旧判据一致，口径放松未引入误报。LOOP_MIN_GAIN_WEI 仍为默认 `1e16`，暂无需调整。

### Agent 重跑 5 卡住案例 (新 confirm, cheap 配置 MAXR=8/RERUN_CAP=3/CTX=35k, nonce nv_1792534146)

| case | outcome | last_reason |
|---|---|---|
| BambooIA | over_budget | Ownable: caller is not the owner (agent) |
| LPBonus | over_budget | LOOP: net value gain below threshold |
| ULME | over_budget | Victim did not lose tokens (agent require) |
| wKeyDAO | over_budget | Initialization failed - already initialized (agent) |
| GDC | over_budget | LOOP: net value gain below threshold |

verified 0/5；reject 类全空；成本 ≈ $1.55，cache 命中 44%。新不变量未把任何一案翻成 verified；GDC/LPBonus 终局已是真正的净值判据（机制未打通），其余三案死在 agent 自身 require。SAFE 零假阳性。下一步证据指向 agent 推理深度，非 confirm。
