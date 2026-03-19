# E2E Report: Posting Deposits on the Contract

**Scope:** Everything needed to lock ERC20 tokens in `TesseraRollupV2` and create an
on-chain `Pending` deposit record.
**Reuse:** This document is self-contained. Cross-reference with
[e2e-report-deposit-validation.md](e2e-report-deposit-validation.md) for the next step.

---

## What "posting a deposit" means

Calling `depositAndRegister` on `TesseraRollupV2`:
- Pulls ERC20 tokens from the caller into the contract escrow.
- Creates an on-chain record `deposits[noteCommitment] = {value, recipient, Pending}`.
- Emits `DepositAvailable` so the sequencer can pick it up.

The **note commitment** (`bytes32`) is a Poseidon hash derived client-side from
deposit metadata. It binds the on-chain deposit to a specific ZK note the recipient
can later spend.

---

## Prerequisites

| Requirement | Detail |
|-------------|--------|
| Deployed `TesseraRollupV2` | address in `TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS` |
| Deployed `ToyUSDT` | address in `TESSERA_MONITORED_TOKEN` |
| ERC20 balance | `ToyUSDT.mint(user, amount)` — unlimited for the toy token |
| ERC20 allowance | `ToyUSDT.approve(rollup, maxAmount)` before calling deposit |
| Note commitment | Derived from `DepositNote.commitment()` — see below |

---

## Computing `noteCommitment` (Rust, client-side)

Source: [tessera-client/src/note.rs](../tessera-client/src/note.rs)

```rust
use tessera_client::{AccountAddress, AssetId, DepositNote, account::SubpoolId};
use tessera_trees::F;
use primitive_types::U256;

let note = DepositNote {
    identifier: [F::from_canonical_u64(rand_id_0), F::from_canonical_u64(rand_id_1)],
    recipient:  AccountAddress { subpool_id: SubpoolId(F::ONE), public_id: acc.public_id() },
    amount:     U256::from(1_000_000u64),  // 1.0 ToyUSDT (6 decimals)
    asset_id:   AssetId(F::from_canonical_u64(1)),
};
let commitment = note.commitment();   // DepositNoteCommitment(HashOutput([F; 4]))

// Pack to bytes32 (LE packing: e0 | e1<<64 | e2<<128 | e3<<192)
let nc_bytes: [u8; 32] = commitment.0.pack_to_bytes();
```

Hash preimage — 16 Goldilocks field elements:
```
input[0..2]  = identifier[2]
input[2]     = recipient.subpool_id
input[3..7]  = recipient.public_id[4]
input[7..15] = amount (U256 as 8×u32 limbs LE, each cast to F)
input[15]    = asset_id
```

---

## Solidity call: `depositAndRegister`

Source: [tessera-solidity/src/TesseraRollupV2.sol](../tessera-solidity/src/TesseraRollupV2.sol)

```solidity
function depositAndRegister(
    bytes32 noteCommitment,  // Poseidon hash of deposit metadata
    uint256 maxAmount        // contract measures actual received via balance delta
) external whenNotPaused returns (bytes32);
```

### Minimal sequence

```
1. ToyUSDT.mint(user, 1_000_000)
2. ToyUSDT.approve(address(rollup), 1_000_000)
3. rollup.depositAndRegister(noteCommitment, 1_000_000)
```

Emits: `DepositAvailable(bytes32 indexed noteCommitment, uint256 value, address recipient)`

### cast / shell equivalent

```bash
cast send $TOKEN "mint(address,uint256)" $USER 1000000 \
  --private-key $CLIENT_KEY --rpc-url $RPC

cast send $TOKEN "approve(address,uint256)" $ROLLUP 1000000 \
  --private-key $CLIENT_KEY --rpc-url $RPC

NC="0x$(printf '%064x' 42)"
cast send $ROLLUP "depositAndRegister(bytes32,uint256)" $NC 1000000 \
  --private-key $CLIENT_KEY --rpc-url $RPC
```

---

## Alternate: `depositAndRegisterFor` (delegated payer)

```solidity
function depositAndRegisterFor(
    bytes32 noteCommitment,
    address payer,      // who holds the tokens (needs prior approval to msg.sender)
    uint256 maxAmount
) external whenNotPaused returns (bytes32);
```

---

## Alternate: `ToyUser.depositAndRecord` (convenience wrapper)

Source: [tessera-solidity/src/ToyUser.sol](../tessera-solidity/src/ToyUser.sol)

```solidity
// Requires: ToyUSDT.approve(address(toyUser), amount) first
function depositAndRecord(bytes32 noteCommitment, uint256 amount)
    external returns (bytes32);
```

---

## Alternate: `ToyUser.depositAndRecordWithPermit` (EIP-2612, gasless)

```solidity
function depositAndRecordWithPermit(
    bytes32 noteCommitment, uint256 amount, uint256 deadline,
    uint8 v, bytes32 r, bytes32 s
) external returns (bytes32);
```
Signs an EIP-2612 permit off-chain; approve + deposit in a single transaction.

---

## Post-deposit on-chain state

```
deposits[noteCommitment] = {
    value:     <actual ERC20 received (may differ from maxAmount for fee-on-transfer)>,
    recipient: msg.sender  (or `payer` for the For variant),
    status:    Pending (1)
}
```

### Query

```bash
cast call $ROLLUP "getDeposit(bytes32)((uint256,address,uint8))" $NC --rpc-url $RPC
# => (value, recipient, 1)   1 = Pending
```

---

## Error conditions

| Error | Condition |
|-------|-----------|
| `InvalidAmount()` | amount == 0 |
| `DuplicateNoteCommitment(bytes32)` | noteCommitment already used (status != None) |
| `ZeroAddress()` | recipient or payer is `address(0)` |
| `NoTokenReceived()` | balance delta == 0 after transferFrom |
| `TokenTransferFailed()` | transferFrom returned false |
| `PausedErr()` | contract is paused |

---

## Cancellation (before validation)

If the deposit has not yet been included in a batch, the recipient can reclaim their tokens:

```solidity
rollup.withdrawPendingDeposit(noteCommitment);
// Requires: caller == deposit.recipient AND status == Pending
// Sets status = Withdrawn, returns tokens to recipient
```

Emits: `DepositWithdrawn(bytes32 noteCommitment, uint256 value, address recipient)`

---

## What happens next

The contract emits `DepositAvailable`. The sequencer watches for this event (or the
client calls `sequencer_handle.submit_deposit(nc_bytes, None).await?`). See
[e2e-report-deposit-validation.md](e2e-report-deposit-validation.md) for how the
deposit moves from `Pending` → `Validated`.
