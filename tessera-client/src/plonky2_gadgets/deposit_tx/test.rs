use plonky2_field::types::Field;
use primitive_types::{H160, U256};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use tessera_trees::MerkleTree;
use tessera_utils::{F, hasher::HashOutput};

use super::{*, builder::{DepositTxBuilder, FakeDepositTxBuilder}};
use crate::{
	AccountAddress, AssetId, NoteIdentifier, Nonce, PIHelper, SpendAuth, STATE_TREE_DEPTH,
	StandardAccount, SubpoolId,
	note::DepositNote,
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfig},
	schnorr::PrivateKey,
};

#[test]
fn test_prove_deposit_tx() {
	let mut rng = ChaCha8Rng::seed_from_u64(42);

	// ── Keys for subpool ──────────────────────────────────────────────────
	let approval_sk = PrivateKey::sample(&mut rng);
	let approval_key: CompPubKey = approval_sk.public_key::<F>().into();

	let subpool_id = SubpoolId(F::ONE);
	let subpool = SubpoolConfig::<HashOutput>::new(approval_key);
	let mut main_pool = MainPoolConfigTree::new();
	main_pool
		.insert_subpool_at_position(subpool_id, subpool.commitment())
		.unwrap();

	// ── Sample accin ──────────────────────────────────────────────────────
	let mut accin = StandardAccount::sample(&mut rng, subpool_id);
	accin.nonce = Nonce(F::ONE);
	accin.spend_auth = SpendAuth::new(PrivateKey::sample(&mut rng).public_key().into());

	// ── Insert accin into ACT ─────────────────────────────────────────────
	let mut act = MerkleTree::<HashOutput>::new(STATE_TREE_DEPTH);
	act.insert(accin.commitment().0).unwrap();

	// ── DepositNote for accin ─────────────────────────────────────────────
	let asset_id = AssetId(F::from_canonical_u64(7));
	let deposit_amount = U256::from(1000u64);
	let deposit_note = DepositNote {
		identifier: NoteIdentifier([
			F::from_canonical_u64(11),
			F::from_canonical_u64(22),
		]),
		recipient: AccountAddress::from_acc(&accin),
		amount: deposit_amount,
		asset_id,
	};
	let eth_address = H160::random();

	// ── Pre-compute values for assertions ─────────────────────────────────
	let accin_null = accin.nullifier();
	let deposit_note_comm = deposit_note.commitment();
	let mut accout_check = accin.clone_with_incremented_nonce();
	accout_check.ast.insert_or_update_asset(asset_id, deposit_amount);
	let accout_comm = accout_check.commitment();

	// ── Build subpool proof ───────────────────────────────────────────────
	let subpool_proof = main_pool.full_subpool_proof(&subpool, subpool_id).unwrap();

	// ── Build circuit ─────────────────────────────────────────────────────
	let circuit = build_deposit_tx_circuit();

	// ── Use builder pattern ───────────────────────────────────────────────
	let mut built = DepositTxBuilder::new(accin, deposit_note, eth_address)
		.expect("builder construction failed")
		.build();
	built.approval_sign(&approval_sk, &mut rng);
	let provable = built
		.into_deposit_tx(&act, subpool_proof)
		.expect("into_deposit_tx failed");
	let dp = provable.prove(&circuit).expect("prove failed");

	// ── Verify ────────────────────────────────────────────────────────────
	circuit.circuit_data.verify(dp.proof.clone()).expect("verify failed");

	// ── PI accessor checks ────────────────────────────────────────────────
	let act_root = act.root();
	let main_pool_root = main_pool.root();

	assert_eq!(dp.act_root(), act_root, "act_root mismatch");
	assert_eq!(
		dp.mainpool_config_root(),
		main_pool_root,
		"mainpool_config_root mismatch"
	);
	assert_eq!(dp.not_fake_tx(), F::ONE, "not_fake_tx should be 1");
	assert_eq!(
		dp.accin_nullifier(),
		accin_null.0,
		"accin_nullifier mismatch"
	);
	assert_eq!(
		dp.accout_commitment(),
		accout_comm.0,
		"accout_commitment mismatch"
	);
	assert_eq!(
		dp.note_commitment(),
		deposit_note_comm.0,
		"note_commitment mismatch"
	);
	assert_eq!(dp.eth_address(), eth_address, "eth_address mismatch");
	assert_eq!(dp.amount(), deposit_amount, "amount mismatch");
	assert_eq!(dp.asset_id(), asset_id, "asset_id mismatch");
}

#[test]
fn test_fake_tx() {
	let circuit = build_deposit_tx_circuit();

	let deposit_tx = FakeDepositTxBuilder::new(
		HashOutput([F::ZERO; 4]),
		HashOutput([F::ZERO; 4]),
	)
	.build()
	.into_deposit_tx();

	let dp = deposit_tx.prove(&circuit).expect("prove failed");
	circuit.circuit_data.verify(dp.proof).expect("verify failed");
}
