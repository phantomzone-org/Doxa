# Bug Report: Double `transferFrom` in `transferDepositAndRegister`

## Summary

`transferDepositAndRegister` performs two `transferFrom` calls for the same amount, causing the transaction to revert.

## Error

```
deposit tx reverted on-chain (tx=0xa80e124298653a4b9e52ce3503c8b685eded47c93c91ab09c344229550eee4e5)
```

The on-chain tx reverts at the second `transferFrom` because the user's allowance (or balance) has already been consumed by the first one.

## Buggy Code

```solidity
function transferDepositAndRegister(bytes32 noteCommitment, uint256 amount)
    external
    whenNotPaused
    returns (bytes32)
{
    // 1st transferFrom: moves `amount` from msg.sender to contract
    bool ok = IERC20MonitoredToken(monitoredToken).transferFrom(msg.sender, address(this), amount);
    if (!ok) revert TokenTransferFailed();

    // calls _depositAndRegister, which does a 2nd transferFrom for the same amount
    return _depositAndRegister(noteCommitment, msg.sender, msg.sender, amount);
}

function _depositAndRegister(
    bytes32 noteCommitment,
    address payer,
    address recipient,
    uint256 maxAmount
) internal returns (bytes32) {
    // ...
    // 2nd transferFrom: tries to move `maxAmount` again — reverts (no allowance left)
    bool ok = IERC20MonitoredToken(monitoredToken).transferFrom(payer, address(this), maxAmount);
    if (!ok) revert TokenTransferFailed();
    // ...
}
```

## Explanation

`transferDepositAndRegister` calls `transferFrom(msg.sender, contract, amount)` to pull tokens, then delegates to `_depositAndRegister` which independently performs its own `transferFrom(payer, contract, maxAmount)`. Since both calls transfer the same amount from the same sender, the second call fails:

- If the user approved exactly `amount`: the first call consumes the entire allowance, the second reverts with insufficient allowance.
- If the user approved `2 * amount`: the first call succeeds, but the second call fails because the user no longer has enough token balance (already transferred).

## Fix

Remove the redundant `transferFrom` from `transferDepositAndRegister` — `_depositAndRegister` already handles the transfer internally:

```solidity
function transferDepositAndRegister(bytes32 noteCommitment, uint256 amount)
    external
    whenNotPaused
    returns (bytes32)
{
    return _depositAndRegister(noteCommitment, msg.sender, msg.sender, amount);
}
```
