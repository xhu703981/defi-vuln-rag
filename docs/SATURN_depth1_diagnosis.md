# SATURN depth-1 diagnosis — why every DEX buy reverts (Pancake: TRANSFER_FAILED)

Case `20240507_SATURN` · token `0x9bdf251435cbc6774c7796632e9c80b233055b93` (contract `Saturn`) · bsc fork @ block 38488208.
Pure diagnosis. confirm.py / cases.jsonl untouched (md5 verified before+after). Verified Etherscan source only.

## STEP 1 — guard inventory in Saturn `_transfer` (verified source)

`_transfer` runs the limit/fee block only when `enableSwitch` AND neither party is fee-excluded.
Guards that can block a buy/transfer **to a contract**:

| guard | require / condition | revert string | controlling var | live @ block |
|---|---|---|---|---|
| trading gate | `require(enableTrade, ...)` | `Err unable transfer` | `enableTrade` | `true` |
| mint/tx lock | `if (mintLocks[from].time > now) require(balanceOf(from)-mintLocks[from].num >= amount)` | `Transfer amount locked` | `mintLocks[from]` (set on every buy via `_lockUserTxToken`, lock=`lockTxTime`) | lockTxTime=`21600`s |
| **per-tx BUY cap** | `else if (from == uniswapV2Pair) require(amount <= everyTimeBuyLimitAmount)` | **`Exchange Overflow`** | `everyTimeBuyLimitAmount` | **`1e23` (~100k)** |
| per-tx SELL cap | `if (to == uniswapV2Pair) require(amount <= everyTimeSellLimitAmount)` | `Exchange Overflow` | `everyTimeSellLimitAmount` | `5e23` |
| accumulator swap | `if (balanceOf(tokenReciever) >= maxTxAmount && !swapIng && msg.sender != pair) _processSwap(...)` | (side effect) | `maxTxAmount` | `1e21` |
| fees | buy `amount*buyFee/commonDiv`, sell `amount*sellFee/commonDiv` | — | `buyFee=10 sellFee=5 commonDiv=100` | 10% / 5% |

NOTE: on a buy the pair calls `SATURN.transfer(recipient, amountOut)`, so `amount` in the buy branch =
**tokens delivered OUT of the swap**, not the WBNB put in.

NO EOA-only / `tx.origin==msg.sender` / `isContract(to)` check on the transfer path. (The only
`require(msg.sender == tx.origin, "Only EOA")` is inside the native-BNB `mint()` fn, not on buy/transfer.)

## STEP 2 — exact failing frame (re-ran saved Opus round1.injected.sol with forge -vvvv)

Opus bought 40 WBNB worth in ONE swapExactTokensForTokensSupportingFeeOnTransferTokens([WBNB,SATURN]).
The pair's swap() tries to deliver ~7.27e25 SATURN to the Exploit contract; SATURN's buy branch fires:

```
[34334] 0x49BA..6124(pair)::swap(72704704437404321144465125 [7.27e25], 0, Exploit, 0x)
  |- 0x9BDF..SATURN::transfer(Exploit, 72704704437404321144465125 [7.27e25])
  |    `-- <- [Revert] Exchange Overflow          <-- buy cap: 7.27e25 > everyTimeBuyLimitAmount 1e23
  `-- <- [Revert] Pancake: TRANSFER_FAILED        <-- pair wraps the failed delivery
```

So `Pancake: TRANSFER_FAILED` is **(b) the token's own `_transfer` buy guard firing inside the swap** —
the **per-tx buy cap `everyTimeBuyLimitAmount` ("Exchange Overflow")**. NOT an allowance/transferFrom
issue (the WBNB transferFrom returned true) and NOT the router output safeTransfer.

## STEP 3 — VERDICT: (A) ENVIRONMENT-KNOWLEDGE, fixable & generalizable

The buy reverts only because the swap pulled ~72.7M tokens in one tx while the token caps a single buy at
`everyTimeBuyLimitAmount`=1e23 (~100k). A contract buyer is fully allowed; it just must size each swap so
the **output** is `<= everyTimeBuyLimitAmount`, and split a larger position across multiple buys (warping
past `lockTxTime` between buy and sell, since each buy sets `mintLocks` -> `Transfer amount locked`).
All values are static/readable; nothing requires a real EOA.

### Encode into context (extends imp4)
imp4 already surfaces `everyTimeBuyLimitAmount [live ~1e23]`, but the warning must state the cap binds the
**token OUTPUT of the swap, not the WBNB input**:
- "Per-swap buy is capped at everyTimeBuyLimitAmount tokens OUT. Use getAmountsOut to size WBNB input so
  output <= cap; loop multiple swaps to accumulate. Each buy locks your tokens for lockTxTime
  (`Transfer amount locked`) — vm.warp past it before selling/transferring."

### Generalizes?
Yes — to the broad class of BSC antibot/limit tokens with per-tx buy/sell caps + post-buy tx-locks
(common everyTimeBuyLimitAmount / maxTxAmount / cooldown pattern). A generic "size swap output under the
live per-tx cap, split across warped blocks" rule removes this failure class with no case-specific
constant. A real depth-0->1->2 lever, not a structural ceiling.
