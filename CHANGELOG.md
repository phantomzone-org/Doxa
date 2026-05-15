# Changelog — doxa-client (dev_rollup_v2 → jay/dev)

---

## Reject transaction

The `is_rjct` flag, `rejection_key` target, and `RejectCondTarget` were already in the circuit, but `is_rjct` was hardcoded to `false` in every witness setter and nothing in the circuit actually enforced the reject semantics.

Two things were added. In `cb.rs`, `assert_is_reject()` is a new circuit method that, when `is_rjct=1`, constrains each `(inote, onote)` pair to have matching `isactive`, `identifier`, `amount`, `asset_id`, and enforces `onote.spend_cond == inote.reject_cond` so that the note routes back to its sender. `assert_tx_signatures()` was also updated — it used to take `is_fake_tx` to gate the spend-sig requirement; it now takes `not_is_rjct` instead, so reject transactions never require a spend signature.

In `reject.rs` (new file), `set_reject_tx_witness()` is the first witness setter that actually sets `is_rjct=true`. `accout` is derived as a clone of `accin` with the nonce incremented; the AST is left unchanged since reject does not modify balances. Consume and approval signatures are real; the spend signature is gated out by the circuit. A full end-to-end test is included.

---

## Withdrawal transaction

There was no withdrawal circuit before. `plonky2_gadgets/withdraw_tx/` is an entirely new standalone circuit, separate from `priv_tx`.

The key structural difference from `priv_tx` is that the withdraw circuit supports up to `NOTE_BATCH` simultaneous asset withdrawals using chained AST updates: each slot proves one leaf transition `accin_amts[i] → accout_amts[i]` with intermediate virtual roots threading from `accin.acc_ast_root` to `accout.acc_ast_root`. The balance constraint `accin_amts[i] == accout_amts[i] + withdrawal_amts[i]` is enforced per slot. ACT membership for `accin` is conditioned on `not_fake_tx`. Only an approval signature is required. The public inputs are `not_fake_tx | act_root | mpct_root | accin_null | accout_comm | asset_ids[N] | amounts[8N] | w_addr[5]`.

`set_withdraw_tx_witness()` builds the per-slot AST proofs by sequentially mutating a cloned AST, so each intermediate proof is consistent with the previous slot's output root. A `WithdrawTxCircuitBuilder` trait with `derive_withdraw_tx_hash()` was added for the circuit side, and a native equivalent `derive_withdraw_tx_hash()` was added to `account.rs`.

---

## PrivTx: AN/AC/NN/NC override redesign

The old scheme: AN and NN were derived inside the circuit, then `_if(not_fake_tx, derived, override)` muxed between the derived value and a caller-supplied override. AC and NC had no override at all — there was no way for fake txs to control those PI fields. `TxCircuitTargets` had `override_an: HashOutTarget`.

The new scheme: all four (AN, AC, NN, NC) are free virtual targets registered directly as public inputs. For real txs (`not_fake_tx=1`), the circuit enforces `mul(not_fake_tx, derived - virtual) == 0`, which binds the free target to the derived value. For fake txs (`not_fake_tx=0`), the prover supplies arbitrary padding values directly, with no constraint applied. This gives the sequencer full control over all four PI fields when constructing padding proofs.

`TxCircuitTargets`: `override_an` was replaced by `accin_null` and `accout_comm`; `override_nc` was added alongside the existing `override_nn`.

---

## PrivTx: new public inputs

PI[77–80] (`act_root`) and PI[81–84] (`nct_root`) are now registered, binding each PrivTx proof to the ACT and NCT state at prove time. The total PrivTx PI count goes from 77 to 85.

---

## PrivTx: proving API

`prove_real_priv_tx` used to take a seed and always produced a FreshAcc proof. It now takes a `PrivTxInputs` enum and dispatches to the appropriate witness setter. The old seed-based behaviour is preserved as `prove_real_priv_tx_seeded`.

`prove_dummy_priv_tx` dropped its `seed` parameter and gained `accin_null_override`, `accout_comm_override`, and `override_nc` to match the expanded override scheme. `prove_dummy_priv_tx_inner` was removed, replaced by the `PrivTxInputs::Fake` dispatch path.

The flat parameter lists at call sites are replaced by typed input structs defined in `inputs.rs` (new file): `FreshAccInputs`, `SpendTxInputs`, `RejectTxInputs`, `FakeTxInputs`, and a `PrivTxInputs` enum over them. `FakeTxInputs` carries all four override fields.

---

## Deposit circuit

Two new public inputs were added: `act_root` and `asset_id`. This changes the deposit circuit's PI layout.

`DepositTxCircuitBuilder::assert_account_invariants` was removed from the trait. Its body was identical to the new `assert_account_invariants_simple` in `PrivTxCircuitBuilder`, so the deposit circuit now calls that directly. `assert_ast_update` was updated to receive `HashOutTarget` roots directly instead of full `AccountTarget` structs, matching the same signature change in `priv_tx/cb.rs`. The builder calls for authority key allocation and public identifier derivation were also updated to use the new shared helpers described below.

---

## `priv_tx/cb.rs` circuit trait

Several methods changed signature or were added.

`assert_account_invariants` gained an `is_rjct` parameter. The old version gated AST-root freeze on `!is_priv_tx` using only the existing flags; the new version also accounts for the reject path. A new unconditional variant, `assert_account_invariants_simple`, was added for circuits (deposit, withdraw) where no tx-kind gating is needed.

`assert_ast_update` now takes `accin_ast_root: HashOutTarget` and `accout_ast_root: HashOutTarget` directly instead of full `AccountTarget` structs.

`assert_tx_signatures` takes `not_is_rjct` instead of `is_fake_tx`.

`assert_is_reject` was added (see Reject section above).

Three helpers were extracted from inline code and promoted to trait methods: `add_virtual_authority_keys` (allocates all three pubkey targets together), `derive_public_identifier` (extracted from `priv_tx_circuit` and `deposit_tx_circuit`), and `add_virtual_dummy_account_target`.

---

## Witness helpers: deduplication

`spend.rs`, `freshacc.rs`, and `deposit_tx/mod.rs` each contained verbatim copies of: authority-key setting, subpool-proof derivation (constructing a `SubpoolConfigTree`, calling `full_subpool_proof`, filling the targets), Schnorr challenge computation and `set_schnorr_witness` calls, fake-key generation from fixed scalars, tx-kind flag setting, and tree-root + account filling.

These are now in two new files.

`plonky2_gadgets/witness.rs` contains the cross-circuit helpers: `set_authority_keys`, `set_subpool_full_proof`, `fake_authority_keys`, `set_real_schnorr_signature`, `set_fake_schnorr_signature`, and `set_hash_blocks`.

`plonky2_gadgets/priv_tx/witness.rs` contains the priv-tx-specific wrappers: `TxKindFlags` struct with `set_tx_kind_flags` (fills all 5 bool targets atomically), `set_common_tx_witness` (tree roots, authority keys, accin/accout), and `set_note_hash_overrides` (fills `override_nn` and `override_nc`).

`freshacc.rs` and `spend.rs` were updated to call these helpers. There are no logic changes in either file.

---

## `spend.rs`: witness setter

`set_fake_tx_witness` gained three parameters — `accin_null_override`, `accout_comm_override`, `override_nc` — so the fake-tx path can now control all four PI fields, consistent with the override redesign above.

`accout.ast.set_leaf(ast_index, leaf)` was replaced with `accout.ast.insert_or_update_asset(asset_id, amt)`, following the `AccountStateTree` API change below.

`circuit_merkle_root`, a local helper that recomputed the circuit-compatible Merkle root from a proof, was deleted. It was unused after circuit root computation moved entirely into the circuit gadget.

---

## `freshacc.rs`: witness setter

`set_freshacc_tx_witness` no longer takes `override_an` or `override_nn` parameters. AN and AC are now derived internally and written directly to the free virtual targets; NN and NC are filled by `set_note_hash_overrides`.

`accout.nonce = Nonce(F::ONE)` was replaced with `accin.clone_with_incremented_nonce()`. The old code hardcoded the output nonce to 1 regardless of the input nonce; the new code increments from whatever `accin.nonce` is.

---

## `AccountStateTree` API

`set_leaf(at_index, leaf)` was removed. It performed an unconditional overwrite and could silently corrupt the `assets` map if `at_index` did not match the slot already tracked for that `asset_id`.

It is replaced by three methods: `insert_asset` (errors if the asset is already tracked), `update_asset` (errors if the asset is not tracked, preserves the existing tree index), and `insert_or_update_asset` (upsert, returns the previous amount).

---

## `signature.rs`: bug fix

`CompressionGate::wires_per_op` was 15, causing `num_wires()` to undercount the gate's wire usage. The gate uses `w(5) + x(5) + y(5) + isactive(1) = 16` wires per operation. Corrected to 16.

---

## Visibility promotions

`Signature` in `schnorr.rs`, and `CommitmentTreeMerkleProof<D>` in `tree.rs`, were `pub(crate)` and are now `pub` — required because the new input structs in `inputs.rs` are public and carry these types. `PointEw<F>` and `LegendreSymbol` in `ecgfp5.rs` were similarly promoted to `pub`, required by the new `plonky2_gadgets/witness.rs`.

---

## Cleanups

`plonky2_gadgets/targets.rs` was deleted — it was an empty file.

`lib.rs`: `#![allow(clippy::all, warnings)]` was replaced with `#![allow(dead_code, unused_imports, unused_variables)]`.

`ecgfp5.rs`, `merkle.rs`, `tree.rs`, `u256.rs`, `signature.rs`: clippy-driven loop refactors (iterator zips, `>>=`, `is_multiple_of`, `index?`, `div_ceil`). No logic changes.

`ConsumeAuth` and `AccountStateTree` had hand-written `Default` impls that were equivalent to `#[derive(Default)]`; both replaced with the derive.

`pool_config.rs`: a TODO comment was added noting a known ordering inconsistency in the subpool config hash composition. No logic change.
