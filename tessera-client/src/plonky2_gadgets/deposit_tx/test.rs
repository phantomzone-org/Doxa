use plonky2::{
	iop::witness::PartialWitness,
	plonk::{
		circuit_builder::CircuitBuilder,
		circuit_data::CircuitConfig,
		config::{GenericConfig, Hasher, PoseidonGoldilocksConfig},
	},
};
use plonky2_field::types::{Field, PrimeField64};

use primitive_types::{H160, U256};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use tessera_trees::MerkleTree;
use tessera_utils::hasher::HashOutput;

use super::*;
use crate::{
	AccountAddress, AssetId, COM_TREE_DEPTH, Nonce, PIHelper, StandardAccount, SubpoolId,
	account::AccountStateTreeLeaf,
	derive_deposit_tx_hash,
	note::DepositNote,
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
	schnorr::{PrivateKey, Scalar, schnorr_sign},
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

#[test]
fn test_prove_deposit_tx() {
	// ── Keys for subpool ──────────────────────────────────────────────────
	let approval_sk = PrivateKey::from_raw([1, 2, 3, 4, 5]);
	let approval_key: CompPubKey = approval_sk.public_key::<F>().into();
	let rejection_sk = PrivateKey::from_raw([5, 6, 7, 8, 0]);
	let rejection_key: CompPubKey = rejection_sk.public_key::<F>().into();
	let consume_sk = PrivateKey::from_raw([9, 10, 11, 12, 0]);
	let consume_key: CompPubKey = consume_sk.public_key::<F>().into();

	let subpool_id = SubpoolId(F::ONE);
	let subpool = SubpoolConfigTree::<HashOutput>::new(approval_key, rejection_key, consume_key);
	let mut main_pool = MainPoolConfigTree::new();
	main_pool
		.insert_subpool(subpool_id, subpool.root())
		.unwrap();

	// ── Sample accin ──────────────────────────────────────────────────────
	let mut rng = ChaCha8Rng::seed_from_u64(42);
	let mut accin = StandardAccount::sample(&mut rng, subpool_id);

	// --- Simulate FreshAcc ------------------------------------------------
	accin.nonce = Nonce(F::ONE);
	accin.spend_auth = crate::SpendAuth {
		spend_pk: Some(PrivateKey::from_raw([8, 7, 6, 5, 4]).public_key().into()),
	};

	// ── Insert accin into ACT ─────────────────────────────────────────────
	let mut act = MerkleTree::<HashOutput>::new(COM_TREE_DEPTH);
	let accin_pos = act.insert(accin.commitment().0).unwrap();
	let accin_act_merkle_proof = act.merkle_proof(accin_pos).unwrap();

	// ── DepositNote targeting accin ───────────────────────────────────────
	let asset_id = AssetId(F::from_canonical_u64(7));
	let deposit_note = DepositNote {
		identifier: crate::NoteIdentifier([F::from_canonical_u64(11), F::from_canonical_u64(22)]),
		recipient: AccountAddress::from_acc(&accin),
		amount: U256::from(1000u64),
		asset_id,
	};
	let eth_address = H160::random();

	// ── Compute native TxHash ─────────────────────────────────────────────
	let mut accout = accin.clone();
	accout.nonce = Nonce(F::from_canonical_u64(accin.nonce.0.to_canonical_u64() + 1));
	accout
		.ast
		.insert_or_update_asset(asset_id, deposit_note.amount);

	let accin_null = accin.nullifier();
	let deposit_note_comm = deposit_note.commitment();
	let tx_hash = derive_deposit_tx_hash(
		accin_null,
		accout.commitment(),
		deposit_note_comm,
		eth_address,
	);

	// ── Sign ──────────────────────────────────────────────────────────────
	let k = Scalar::from_raw([1, 2, 3, 4, 5]);
	let consume_sig = schnorr_sign(&consume_sk, &tx_hash.0, k);
	let approval_sig = schnorr_sign(&approval_sk, &tx_hash.0, k);

	// ── Build circuit ─────────────────────────────────────────────────────
	let config = CircuitConfig::standard_recursion_config();
	let mut builder = CircuitBuilder::<F, D>::new(config);
	let t = deposit_tx_circuit::<HashOutput, _, _>(&mut builder);
	let data = builder.build::<C>();

	// ── Fill witness ──────────────────────────────────────────────────────
	let act_root = act.root();
	let main_pool_root = main_pool.root();
	let deposit_amount = deposit_note.amount;

	let mut pw = PartialWitness::new();

	t.set_real(
		&mut pw,
		act_root,
		main_pool,
		&accin,
		&accout,
		accin_act_merkle_proof,
		deposit_note,
		eth_address,
		approval_key,
		rejection_key,
		consume_key,
		subpool_id,
		consume_sig,
		approval_sig,
	);

	// ── Prove & verify ────────────────────────────────────────────────────
	let proof = data.prove(pw).expect("prove failed");
	data.verify(proof.clone()).expect("verify failed");

	// ── PI accessor checks ────────────────────────────────────────────────
	let dp = crate::DepositProof { proof };

	assert_eq!(dp.act_root(), act_root, "act_root mismatch");
	assert_eq!(dp.mainpool_config_root(), main_pool_root, "mainpool_config_root mismatch");
	assert_eq!(dp.not_fake_tx().to_canonical_u64(), 1, "not_fake_tx should be 1");
	assert_eq!(dp.accin_nullifier(), accin_null.0, "accin_nullifier mismatch");
	assert_eq!(dp.accout_commitment(), accout.commitment().0, "accout_commitment mismatch");
	assert_eq!(dp.note_commitment(), deposit_note_comm.0, "note_commitment mismatch");
	assert_eq!(dp.eth_address(), eth_address, "eth_address mismatch");
	assert_eq!(dp.amount(), deposit_amount, "amount mismatch");
	assert_eq!(dp.asset_id(), asset_id, "asset_id mismatch");
}

#[test]
fn test_fake_tx() {
	// ── Build circuit ──────────────────────────────────────────────────────
	let config = CircuitConfig::standard_recursion_config();
	let mut builder = CircuitBuilder::<F, D>::new(config);
	let t = deposit_tx_circuit::<HashOutput, _, _>(&mut builder);
	let data = builder.build::<C>();
	let mut pw = PartialWitness::new();

	t.set_fake(&mut pw);

	// ── Prove & verify ─────────────────────────────────────────────────────
	let proof = data.prove(pw).expect("prove failed");
	data.verify(proof).expect("verify failed");
}
