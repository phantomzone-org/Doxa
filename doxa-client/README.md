# doxa-client

Rust client primitives for Doxa accounts, notes, and Plonky2 transaction proofs.

## Build

```bash
cargo check -p doxa-client
cargo test -p doxa-client --release
```

## Basic objects

```rust
use doxa_client::{AccountAddress, AssetId, StandardAccount, StandardNote, SubpoolId};
use doxa_utils::F;
use primitive_types::U256;
use rand::{SeedableRng, rngs::StdRng};

let mut rng = StdRng::seed_from_u64(1);
let alice = StandardAccount::sample(&mut rng, SubpoolId(F::ONE));
let bob = StandardAccount::sample(&mut rng, SubpoolId(F::ONE));

let bob_addr = AccountAddress::from_acc(&bob);
let note = StandardNote::create(
    &mut rng,
    bob_addr,
    AccountAddress::from_acc(&alice),
    U256::from(100u64),
    AssetId::from_u64(1)?,
    [0u8; 512],
);

let account_commitment = bob.commitment();
let note_commitment = note.commitment();
# anyhow::Ok(())
```

## Transaction examples

The snippets below show the builder flow. They assume you already have:

```rust,ignore
let mut rng = /* CryptoRng */;
let mut state_tree = doxa_trees::MerkleTree::<HashOutput>::new(STATE_TREE_DEPTH);
let approval_sk = PrivateKey::sample(&mut rng);
let approval_pk = approval_sk.public_key::<F>().into();
let subpool = SubpoolConfig::<HashOutput>::new(approval_pk);
let subpool_id = SubpoolId(F::ONE);
let mut main_pool = MainPoolConfigTree::new();
main_pool.insert_subpool_at_position(subpool_id, subpool.commitment())?;
let subpool_proof = main_pool.full_subpool_proof(&subpool, subpool_id)?;
```

### `priv_tx`: FreshAcc

Initializes a fresh account by setting its spend key and consume mode.

```rust,ignore
use doxa_client::{PIHelper, StandardAccount, build_priv_tx_circuit};
use doxa_client::plonky2_gadgets::priv_tx::builder::FreshAccTxBuilder;
use doxa_client::schnorr::PrivateKey;

let acc = StandardAccount::sample(&mut rng, subpool_id); // nonce = 0
let spend_sk = PrivateKey::sample(&mut rng);

let circuit = build_priv_tx_circuit();
let proof = FreshAccTxBuilder::new(acc)?
    .with_new_spend_key(spend_sk.public_key::<F>().into())
    .with_delegated_consume()
    .fill_dinotes(&mut rng)
    .fill_donotes(&mut rng)
    .build()?
    .approval_sign(&approval_sk, &mut rng)?
    .with_state_root(state_tree.root())
    .with_subpool_proof(subpool_proof)
    .into_priv_tx()?
    .prove(&circuit.circuit_data, &circuit.targets)?;

assert_eq!(proof.not_fake_tx(), F::ONE);
```

### `priv_tx`: spend

Consumes an input note and creates an output note.

```rust,ignore
use doxa_client::{AccountAddress, AssetId, SpendAuth, StandardAccount, StandardNote, build_priv_tx_circuit};
use doxa_client::plonky2_gadgets::priv_tx::builder::SpendTxBuilder;
use primitive_types::U256;

let spend_sk = PrivateKey::sample(&mut rng);
let mut acc = StandardAccount::sample(&mut rng, subpool_id).clone_with_incremented_nonce();
acc.spend_auth = SpendAuth::new(spend_sk.public_key::<F>().into());

let sender = StandardAccount::sample(&mut rng, SubpoolId(F::from_canonical_u64(2)));
let asset_id = AssetId::from_u64(1)?;
let inote = StandardNote::create(
    &mut rng,
    AccountAddress::from_acc(&acc),
    AccountAddress::from_acc(&sender),
    U256::from(100u64),
    asset_id,
    [0u8; 512],
);

let acc_pos = state_tree.insert(acc.commitment().0)?;
let note_pos = state_tree.insert(inote.commitment().0)?;

let acc_path = state_tree.merkle_proof(acc_pos)?;
let note_path = state_tree.merkle_proof(note_pos)?;
let circuit = build_priv_tx_circuit();

let proof = SpendTxBuilder::new(acc, asset_id)?
    .add_input_note(inote, note_pos)?
    .add_output_note(AccountAddress::from_acc(&sender), U256::from(25u64), [0u8; 512], &mut rng)?
    .fill_dinotes(&mut rng)
    .fill_donotes(&mut rng)
    .build()?
    .spend_sign(&spend_sk, &mut rng)?
    .approval_sign(&approval_sk, &mut rng)?
    .with_account_path(acc_path)
    .with_input_notes_path(vec![note_path])
    .with_rejected_notes_path(vec![])
    .with_subpool_proof(subpool_proof)
    .into_priv_tx()?
    .prove(&circuit.circuit_data, &circuit.targets)?;
```

### Deposit

Applies a `DepositNote` to an initialized account.

```rust,ignore
use doxa_client::{AccountAddress, AssetId, DepositNote, NoteIdentifier, StandardAccount, build_deposit_tx_circuit};
use doxa_client::plonky2_gadgets::deposit_tx::builder::DepositTxBuilder;
use primitive_types::{H160, U256};

let acc = StandardAccount::sample(&mut rng, subpool_id).clone_with_incremented_nonce();
let deposit_note = DepositNote {
    identifier: NoteIdentifier::from_rng(&mut rng),
    recipient: AccountAddress::from_acc(&acc),
    amount: U256::from(100u64),
    asset_id: AssetId::from_u64(1)?,
};

let acc_pos = state_tree.insert(acc.commitment().0)?;
let acc_path = state_tree.merkle_proof(acc_pos)?;
let eth_address = H160::repeat_byte(0x11);

let circuit = build_deposit_tx_circuit();
let proof = DepositTxBuilder::new(acc, deposit_note, eth_address)?
    .build()
    .approval_sign(&approval_sk, &mut rng)
    .with_account_path(acc_path)
    .with_subpool_proof(subpool_proof)
    .into_deposit_tx()?
    .prove(&circuit)?;

assert_eq!(proof.amount(), U256::from(100u64));
```

### Withdrawal

Withdraws one or more asset balances to an `H160` address.

```rust,ignore
use doxa_client::{AssetId, SpendAuth, StandardAccount, build_withdraw_tx_circuit};
use doxa_client::plonky2_gadgets::withdraw_tx::builder::WithdrawRealTxBuilder;
use primitive_types::{H160, U256};

let spend_sk = PrivateKey::sample(&mut rng);
let asset_id = AssetId::from_u64(1)?;
let mut acc = StandardAccount::sample(&mut rng, subpool_id).clone_with_incremented_nonce();
acc.spend_auth = SpendAuth::new(spend_sk.public_key::<F>().into());
acc.ast.insert_or_update_asset(asset_id, U256::from(250u64));

let acc_pos = state_tree.insert(acc.commitment().0)?;
let acc_path = state_tree.merkle_proof(acc_pos)?;
let withdrawal_address = H160::repeat_byte(0x22);

let mut builder = WithdrawRealTxBuilder::new(acc, withdrawal_address)?;
builder.add_withdrawal(asset_id, U256::from(50u64))?;

let circuit = build_withdraw_tx_circuit();
let proof = builder
    .build()?
    .approval_sign(&approval_sk, &mut rng)
    .spend_sign(&spend_sk, &mut rng)
    .with_account_path(acc_path)
    .with_subpool_proof(subpool_proof)
    .into_withdraw_tx()?
    .prove(&circuit)?;

assert_eq!(proof.withdrawal_address(), withdrawal_address);
```

## Public inputs

All proof wrappers implement `PIHelper`:

```rust,ignore
use doxa_client::PIHelper;

let state_root = proof.act_root();
let account_out = proof.accout_commitment();
let inserted_commitments = proof.output_commitments();
```

## Batch-size constants

```rust
use doxa_client::{BRIDGE_TX_BATCH_SIZE, NOTE_BATCH, PRIV_TX_BATCH_SIZE};

assert_eq!(NOTE_BATCH, 7);
assert_eq!(PRIV_TX_BATCH_SIZE, 64);
assert_eq!(BRIDGE_TX_BATCH_SIZE, 512);
```

These are circuit constants, not runtime options.
