# Closed sub-paradigm taxonomy under the 4 top categories from cases.jsonl.
# Top category is NEVER changed (verbatim from cases.jsonl). Subclass is chosen
# by Jev from the closed list for that category. Used by index.build_catalogue.
TAXONOMY = {
    'price_manipulation': {
        'amm_spot_flashloan': 'spot price / pool reserves read inside a settlement path, moved by a flash-loaned swap, then ungated settle/accept pays at the manipulated price',
        'vault_share_inflation': 'vault / ERC4626 share or exchange-rate inflation via donation or first-depositor attack against totalAssets/totalSupply',
        'direct_reserve_no_flashloan': 'attacker directly changes pool/pair reserves (transfer + skim/sync/burn) without a flashloan, then drains at the skewed price',
        'internal_virtual_amm_formula': 'custom / internal / virtual AMM pricing formula (not an external pool) is gamed by attacker inputs',
        'twap_manipulation': 'TWAP or time-weighted oracle is moved over one or more blocks and then consumed by a payout/mint path',
        'stale_faulty_oracle': 'stale, wrong-decimal, wrong-pair, or otherwise faulty external oracle is trusted for valuation',
        'same_block_self_trade_latch': 'same-block self-trade or sandwich latches a manipulated spot into a cached price used later in the same tx',
        'governance_oracle_swap': 'governance / admin / oracle-address replacement lets an attacker point valuation at a fake feed',
    },
    'access_control': {
        'missing_permission_check': 'fund-moving or critical-state function lacks onlyOwner/role/msg.sender check and is callable by anyone',
        'arbitrary_external_call': 'caller-supplied target/calldata is forwarded (call/delegatecall) so the contract\'s privileges are borrowed',
        'unprotected_initialization': 'initialize / init is unguarded or re-callable, letting an attacker seize ownership or set critical params',
        'permissionless_state_feeds_downstream': 'anyone can mutate a state variable that a later privileged/payout path trusts as authority',
        'fake_pool_callback_drains_allowance': 'fake / unvalidated pool or callback tricks the contract into transferring from a user\'s allowance',
        'caller_context_bypass': 'msg.sender / tx.origin / callback-context check is wrong or lost across a hop, bypassing an intended gate',
        'proof_settlement_mismatch': 'rollup / bridge / proof verification does not match the settlement amounts or claims that follow',
    },
    'precision': {
        'donation_inflated_rate_rounding': 'donation inflates exchange rate / shares, then rounding on deposit/withdraw extracts value',
        'integer_division_truncation': 'integer division / first-divide-then-multiply truncates in the attacker\'s favor (or to zero repeatedly)',
        'fixedpoint_share_rounding': 'fixed-point or share-math rounding systematically favors the attacker on mint/burn/fee',
    },
    'reentrancy': {
        'classic_single_fn_cei': 'single function violates checks-effects-interactions: external call / ETH send before state update, same function re-entered',
        'read_only': 'view / price / collateral read is re-entered mid-update and returns stale values used by another protocol',
        'token_hook_callback': 'ERC777 / ERC667 / ERC721 / ERC1155 token hook callback re-enters before state settles',
        'cross_contract': 'reentrancy crosses into a different contract that shares or trusts the same state / accounting',
        'flashloan_reentrancy': 'flashloan funds the reentrancy (capital + callback) so the mid-state drain is large enough to profit',
        'cross_entrypoint_unlocked_sibling': 're-enter a DIFFERENT, unguarded state-changing fn (e.g. buy/mint) that the called fn\'s nonReentrant guard does not cover, acting against un-burned supply / un-updated reserves',
        'reentrancy_reward_logic': 'reentrancy combined with reward / share / stake accounting so the attacker mints or claims more than owed',
    },
}

def subclasses_for(category):
    return TAXONOMY.get(category) or {}

def criteria_for(category):
    '''Jev choice criteria dict: subclass_id -> one-line definition.'''
    return dict(subclasses_for(category))

def all_subclass_ids():
    out = []
    for cat, subs in TAXONOMY.items():
        for sid in subs:
            out.append((cat, sid))
    return out
