# 审计提示：20261015_KolanHook（类别仅供对照：access_control）

## 合约级摘要
This contract manages ETH and a custom `TOKEN` within a `POOL_MANAGER` (likely a concentrated liquidity AMM). The `LAUNCHER` initializes the pool with a starting `tick` and seeds it with `TOKEN`s, receiving ETH in return. Users can `buy` tokens by depositing ETH, which opens a "window" for a specified duration. During this window, the user can `cancel` to get their ETH back (if not expired) or `accept` to claim tokens. A `DEV` address can `claimDev` fees accumulated from taxes. The contract acts as a hook for the `POOL_MANAGER`, handling `beforeSwap` and `afterSwap` callbacks to apply a tax on ETH swaps. Funds are held in the contract and transferred to/from the `POOL_MANAGER` via `unlock`, `mint`, `burn`, and `take` calls.

1. Valuation/payout/mint uses spot price, pool reserves or balanceOf without TWAP/bounds?
    - Yes: `_seed` uses `TOKEN.balanceOf(address(this))` and `TickMath.getSqrtPriceAtTick(tick)` for initial liquidity calculation. `_checkSolvent` uses `TOKEN.balanceOf(address(this))` and `address(this).balance`. `_closeWindow` uses `_sqrtPrice()` (likely spot price from `POOL_MANAGER`).
2. External call or callback (ETH send, token/NFT/ERC777 hooks, flashloan, unlock) before state update / no reentrancy guard; OR callback entry points not validating msg.sender (uniswapV3SwapCallback, algebra/pancake callbacks, flashloan receivers, LayerZero receive, onERC721Received)?
    - Yes: `_send` (ETH transfer) is called after state updates in `launch`, `buy`, `cancel`, `claimDev`. `TOKEN.transfer` in `accept` is after state update. All external functions are `nonReentrant`. `unlockCallback`, `beforeSwap`, `afterSwap` are protected by `onlyPoolManager`.
3. Inputs manipulable within one tx via flashloan (prices, balances, totalSupply, rewards)?
    - Yes: `_sqrtPrice()` (used in `_closeWindow`) can be manipulated via flashloan if the `POOL_MANAGER` is a standard AMM. `TOKEN.balanceOf(address(this))` in `_checkSolvent` could be manipulated if `TOKEN` is a flashloanable token.
4. Missing access control on fund-moving functions, setters, init/initialize, mint/burn or arbitrary-call functions?
    - Yes: `launch` is restricted to `LAUNCHER`. `buy` is permissionless. `cancel` and `accept` are restricted to `w.owner`. `claimDev` is permissionless. `unlockCallback`, `beforeSwap`, `afterSwap` are `onlyPoolManager`. `_send` is private. `_tax` calls `POOL_MANAGER.mint` and `_redeem` calls `POOL_MANAGER.burn` and `POOL_MANAGER.take`, but these are internal and called from restricted/permissioned functions.
5. Direct token transfer to a pair + skim/sync, or token transfer logic that deducts/burns from the pair's balance?
    - No: No direct token transfers to a pair or skim/sync logic observed. `TOKEN.burn` is used in `launch` and `_close`. `TOKEN.transfer` is used in `accept`.
6. Shares/exchange rate computed from balanceOf or totalAssets (donation / first-depositor / empty-pool inflation)?
    - No: No explicit share/exchange rate calculation from `balanceOf` or `totalAssets` for a vault-like system.
7. Permissionless public/external op-like functions with no caller restriction (_xxx-named public, transferTokens, burn, skim, distribute, sweep)?
    - Yes: `buy` is permissionless. `claimDev` is permissionless.
8. User-supplied target address or calldata / unchecked return values?
    - Yes: `recipient` in `buy` is user-supplied. `_send` uses `to.call{value: amount}("")` with a check for `ok`. `TOKEN.transfer` in `accept` checks `!ok`. `POOL_MANAGER.unlock` return values are decoded and used.
9. Inconsistent checks across similar functions (one validates, a sibling path does not)?
    - No: Checks for `launched`, `deadline`, `recipient`, `msg.value` in `buy` are consistent. `cancel` and `accept` have similar `w.owner` and `w.expiry` checks.
10. Accounting inconsistency (double counting, state debited twice/not at all, wrong denominator, reward/dividend miscalc)?
    - No: `devOwed` is debited once in `claimDev`. `held` state is updated consistently in `_openWindow`.
11. Rounding direction, integer truncation/unsafe casting, divide-by-zero or empty-state edge cases?
    - Yes: `FullMath.mulDiv` is used, which can have rounding implications. `budget` calculation in `buy` uses `FullMath.mulDiv`. `_tax` also uses `FullMath.mulDiv`. `_seed` uses `FullMath.mulDiv` for liquidity calculation. `ROUNDING_ALLOWANCE` is used in `buy` to mitigate potential rounding issues with `premium`.
12. Fee-on-transfer / rebasing / reflection token assumptions; missing slippage/deadline on swaps?
    - Yes: `TOKEN` is assumed to be a standard ERC20. If it's a fee-on-transfer or rebasing token, `TOKEN.balanceOf` and `TOKEN.transfer` might behave unexpectedly. `buy` has a `minTokens` and `deadline` for slippage/time protection. Swaps within `POOL_MANAGER` are handled by hooks, but the contract itself doesn't directly perform swaps with slippage/deadline.
13. Permissions relaxed after expiry/timeout/state change (anyone can call once expired)?
    - Yes: `accept` allows `msg.sender != w.owner` if `block.timestamp >= w.expiry`, effectively allowing anyone to accept an expired window.
14. Other: signature replay, re-initializable proxy?
    - NA: No signature-based functions or proxy patterns observed in the provided code.

## LLM 可疑度排序（前 3）
- `buy`：Permissionless function with user-supplied `recipient` (8) and `_sqrtPrice()` (used in `_closeWindow` via `unlockCallback` and `_openWindow`) can be manipulated via flashloan (3). `budget` calculation uses `FullMath.mulDiv` (11). `minTokens` and `deadline` provide slippage/time protection, but the underlying price can still be manipulated.
- `accept`：Permissions are relaxed after expiry, allowing anyone to call `accept` on an expired window (13). `TOKEN.transfer` is called after state update (2). `TOKEN.transfer` return value is checked (8), but if `TOKEN` is a fee-on-transfer token, `TOKEN.transfer` might behave unexpectedly (12).
- `launch`：Uses `TOKEN.balanceOf(address(this))` for initial liquidity calculation (1), which could be manipulated if `TOKEN` is flashloanable (3). `_send` (ETH transfer) is called after state update (2). Restricted to `LAUNCHER` (4).

## 相似历史案例 Top-5
### 1. 20251007_TokenHolder（access_control，损失：20 WBNB）
- 本合约函数 `buy` ↔ 历史函数 `buy`
- 两者都存在外部调用后状态更新、价格操纵风险和潜在的舍入问题；审计师应检查`buy`函数中`POOL_MANAGER.unlock`的返回值处理、`_send`的安全性以及`FullMath.mulDiv`的舍入影响。

### 2. 20250819_PresaleV5（price_manipulation，损失：9,769.23 USD）
- 本合约函数 `buy` ↔ 历史函数 `buyWithETHWert`
- 两个合约都面临**价格操纵风险**，因为它们都依赖于可能被闪电贷操纵的**现货价格**（`_sqrtPrice()` / `getV3Price`）；审计师应检查`buy`函数中`_sqrtPrice()`的来源是否受闪电贷影响，并评估`premium`和`ROUNDING_ALLOWANCE`是否足以抵御价格波动或舍入攻击。

### 3. 20240828_AAVE（access_control，损失：52000）
- 本合约函数 `beforeSwap` ↔ 历史函数 `_buyOnParaSwap`
- **相似风险（中文）：**
两个合约都存在价格预言机（或池内价格）可被闪电贷操纵的风险，且都依赖于外部调用（如ParaSwap或POOL_MANAGER）的正确执行和返回值处理，同时对ERC20代币行为（如手续费）有假设。

**审计师应检查 `beforeSwap` 函数：**
审计师应检查 `_tax` 函数中用于计算费用的 `_ethIsSpecified` 和 `(specified < 0 ? -specified : specified).toUint256()` 逻辑是否正确处理了ETH数量的正负和溢出，以及 `toBeforeSwapDelta` 的转换是否准确，确保税费计算和返回的 `BeforeSwapDelta` 不会被操纵或导致意外的资金流失。

### 4. 20231122_KyberSwap（precision，损失：~$48M）
- 本合约函数 `buy` ↔ 历史函数 `flash`
- 两者都存在**外部回调后检查余额**的风险，审计师应检查`buy`函数中`POOL_MANAGER.unlock`回调后`_checkSolvent()`是否能被操纵。

### 5. 20230711_Libertify（reentrancy，损失：~$452k）
- 本合约函数 `_closeWindow` ↔ 历史函数 `deposit`
- 这两个合约都存在**价格操纵风险**（通过`_sqrtPrice()`或`balanceOf`），并且在**外部调用后更新状态**（可能导致重入），以及**舍入问题**。审计师应检查`_closeWindow`函数中`_sqrtPrice()`的来源是否可靠（是否易受闪电贷攻击），`_send`和`TOKEN.transfer`等外部调用是否在所有状态更新完成后执行，以及所有涉及计算（尤其是`FullMath.mulDiv`）的地方是否存在舍入误差或除零风险。
