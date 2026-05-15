use plonky2_field::types::{Field, PrimeField64};
use primitive_types::{H160, U256};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use doxa_trees::MerkleTree;
use doxa_utils::{F, hasher::HashOutput};

use crate::{
	AssetId, NOTE_BATCH, Nonce, PIHelper, STATE_TREE_DEPTH, SpendAuth, StandardAccount, SubpoolId,
	plonky2_gadgets::withdraw_tx::{
		builder::{FakeWithdrawTxBuilder, WithdrawRealTxBuilder},
		circuit::build_withdraw_tx_circuit,
	},
	pool_config::{MainPoolConfigTree, SubpoolConfig},
	schnorr::PrivateKey,
};

#[test]
fn test_prove_withdraw_tx() {
	const SEED: u64 = 42;
	let mut rng = ChaCha8Rng::seed_from_u64(SEED);

	// ── Keys for subpool ──────────────────────────────────────────────
	let approval_sk = PrivateKey::sample(&mut rng);
	let approval_cpk = approval_sk.public_key::<F>().into();

	let subpool_id = SubpoolId(F::ONE);
	let subpool = SubpoolConfig::<HashOutput>::new(approval_cpk);
	let mut main_pool = MainPoolConfigTree::new();
	main_pool
		.insert_subpool_at_position(subpool_id, subpool.commitment())
		.unwrap();

	// ── Sample accin ──────────────────────────────────────────────────
	let mut accin = StandardAccount::sample(&mut rng, subpool_id);
	accin.nonce = Nonce(F::ONE);
	let spend_sk = PrivateKey::sample(&mut rng);
	accin.spend_auth = SpendAuth::new(spend_sk.public_key().into());
	accin
		.ast
		.insert_asset(AssetId(F::from_canonical_u64(1)), U256::from(100u64))
		.unwrap();
	accin
		.ast
		.insert_asset(AssetId(F::from_canonical_u64(2)), U256::from(200u64))
		.unwrap();
	accin
		.ast
		.insert_asset(AssetId(F::from_canonical_u64(3)), U256::from(300u64))
		.unwrap();

	// ── Insert accin into ACT ─────────────────────────────────────────
	let mut act = MerkleTree::<HashOutput>::new(STATE_TREE_DEPTH);
	let accin_insert = act.insert(accin.commitment().0).unwrap();
	let accin_act_proof = act.merkle_proof(accin_insert).unwrap();
	assert!(accin_act_proof.verify());

	// ── Build and prove ───────────────────────────────────────────────
	let circuit = build_withdraw_tx_circuit();

	let mut builder = WithdrawRealTxBuilder::new(accin, H160::zero()).unwrap();
	builder
		.add_withdrawal(AssetId(F::from_canonical_u64(2)), U256::from(50u64))
		.unwrap();
	builder
		.add_withdrawal(AssetId(F::from_canonical_u64(3)), U256::from(60u64))
		.unwrap();

	let built = builder
		.build()
		.unwrap()
		.approval_sign(&approval_sk, &mut rng)
		.spend_sign(&spend_sk, &mut rng);

	let subpool = SubpoolConfig::new(approval_cpk);
	let subpool_proof = main_pool.full_subpool_proof(&subpool, subpool_id).unwrap();

	let accout = built.accout().clone();
	let withdraw_tx = built
		.with_account_path(accin_act_proof)
		.with_subpool_proof(subpool_proof)
		.into_withdraw_tx()
		.unwrap();

	let wp = withdraw_tx.prove(&circuit).expect("prove failed");
	circuit.circuit_data.verify(wp.proof.clone()).unwrap();

	// ── PI accessor checks ────────────────────────────────────────────
	assert_eq!(wp.act_root(), act.root(), "act_root mismatch");
	assert_eq!(
		wp.mainpool_config_root(),
		main_pool.root(),
		"mainpool_config_root mismatch"
	);
	assert_eq!(
		wp.not_fake_tx().to_canonical_u64(),
		1,
		"not_fake_tx should be 1"
	);
	assert_eq!(
		wp.accout_commitment(),
		accout.commitment().0,
		"accout_commitment mismatch"
	);

	let asset_ids = wp.asset_ids();
	assert_eq!(
		asset_ids[0],
		AssetId(F::from_canonical_u64(2)),
		"asset_ids[0] mismatch"
	);
	assert_eq!(
		asset_ids[1],
		AssetId(F::from_canonical_u64(3)),
		"asset_ids[1] mismatch"
	);
	for i in 2..NOTE_BATCH {
		assert_eq!(
			asset_ids[i],
			AssetId(F::ZERO),
			"asset_ids[{i}] padding should be zero"
		);
	}

	let amts = wp.withdrawal_amts();
	assert_eq!(amts[0], U256::from(50u64), "withdrawal_amts[0] mismatch");
	assert_eq!(amts[1], U256::from(60u64), "withdrawal_amts[1] mismatch");
	for i in 2..NOTE_BATCH {
		assert_eq!(
			amts[i],
			U256::zero(),
			"withdrawal_amts[{i}] padding should be zero"
		);
	}

	assert_eq!(
		wp.withdrawal_address(),
		H160::zero(),
		"withdrawal_address mismatch"
	);
}

#[test]
fn test_fake_withdraw_tx() {
	let circuit = build_withdraw_tx_circuit();

	let withdraw_tx =
		FakeWithdrawTxBuilder::new(HashOutput([F::ZERO; 4]), HashOutput([F::ZERO; 4]))
			.build()
			.into_withdraw_tx();

	let wp = withdraw_tx.prove(&circuit).expect("prove failed");
	circuit.circuit_data.verify(wp.proof).unwrap();
}
