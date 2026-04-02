use plonky2::plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig};
use plonky2_field::types::Field;
use primitive_types::{H160, U256};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use tessera_trees::MerkleTree;
use tessera_utils::{
	ConfigNative, D, F,
	hasher::{HashOutput, MerkleHashCircuit, MerkleHashTarget},
};

use crate::{
	AssetId, COM_TREE_DEPTH, NOTE_BATCH, Nonce, SpendAuth, StandardAccount, SubpoolId,
	account::AccountStateTreeLeaf,
	derive_withdraw_tx_hash,
	plonky2_gadgets::withdraw_tx::{
		circuit::withdraw_tx_circuit, targets::compute_withdrawal_slots,
	},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
	schnorr::{PrivateKey, Scalar, schnorr_sign},
};

#[test]
fn test_prove_withdraw_tx() {
	// ── Keys for subpool ──────────────────────────────────────────────
	let approval_sk = PrivateKey::from_raw([1, 2, 3, 4, 5]);
	let approval_cpk: CompPubKey = approval_sk.public_key::<F>().into();
	let rejection_sk = PrivateKey::from_raw([5, 6, 7, 8, 0]);
	let rejection_cpk: CompPubKey = rejection_sk.public_key::<F>().into();
	let consume_sk = PrivateKey::from_raw([9, 10, 11, 12, 0]);
	let consume_cpk: CompPubKey = consume_sk.public_key::<F>().into();

	let subpool_id = SubpoolId(F::ONE);
	let subpool = SubpoolConfigTree::<HashOutput>::new(approval_cpk, rejection_cpk, consume_cpk);
	let mut main_pool = MainPoolConfigTree::new();
	main_pool
		.insert_subpool(subpool_id, subpool.root())
		.unwrap();

	// ── Sample accin ──────────────────────────────────────────────────
	let mut rng = ChaCha8Rng::seed_from_u64(2);
	let mut accin = StandardAccount::sample(&mut rng, subpool_id);

	// ── Simulate FreshAcc: nonce = 1, set spend_pk ────────────────────
	accin.nonce = Nonce(F::ONE);
	accin.spend_auth = SpendAuth {
		spend_pk: Some(PrivateKey::from_raw([8, 7, 6, 5, 4]).public_key().into()),
	};

	// ── Mutate AST: set balances (asset_id=1 → 100, 2 → 200, 3 → 300) ─
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
	let mut act = MerkleTree::<HashOutput>::new(COM_TREE_DEPTH);
	let accin_insert = act.insert(accin.commitment().0).unwrap();

	let accin_act_proof = act.merkle_proof(accin_insert).unwrap();
	let act_root = act.root();
	assert!(accin_act_proof.verify());

	// ── Withdrawals: (asset_id=2, 50) and (asset_id=3, 50) ───────────
	let withdrawals = [
		(AssetId(F::from_canonical_u64(2)), U256::from(50u64)),
		(AssetId(F::from_canonical_u64(3)), U256::from(60u64)),
	];

	// ── Compute native TxHash and sign ────────────────────────────────
	// compute_withdrawal_slots mirrors the derivation inside set_real so the
	// approval signature is over exactly the same hash the circuit verifies.
	let (slot_asset_ids, slot_withdrawal_amts, _, _, _, _, _, accout) =
		compute_withdrawal_slots(&accin, &withdrawals);

	let accin_null = accin.nullifier();
	let tx_hash = derive_withdraw_tx_hash(
		accin_null,
		accout.commitment(),
		slot_asset_ids,
		slot_withdrawal_amts,
		H160::zero(),
	);

	let k = Scalar::from_raw([1, 2, 3, 4, 5]);
	let approval_sig = schnorr_sign(&approval_sk, &tx_hash.0, k);

	// ── Build circuit ─────────────────────────────────────────────────
	let config = CircuitConfig::standard_recursion_config();
	let mut builder = CircuitBuilder::<F, D>::new(config);
	let t = withdraw_tx_circuit::<HashOutput, _, _>(&mut builder);
	let data = builder.build::<ConfigNative>();

	// ── Fill witness ──────────────────────────────────────────────────
	let mut pw = plonky2::iop::witness::PartialWitness::new();
	t.set_real(
		&mut pw,
		&accin,
		accin_act_proof,
		act_root,
		&main_pool,
		&withdrawals,
		H160::zero(),
		approval_cpk,
		rejection_cpk,
		consume_cpk,
		subpool_id,
		approval_sig,
	);

	// ── Prove & verify ────────────────────────────────────────────────
	let proof = data.prove(pw).expect("prove failed");
	data.verify(proof).expect("verify failed");
}
