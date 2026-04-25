use std::{array, sync::Arc};

use itertools::Itertools;
use plonky2::{
	hash::poseidon::PoseidonHash,
	iop::witness::{PartialWitness, WitnessWrite},
	plonk::{
		circuit_builder::CircuitBuilder,
		circuit_data::CircuitConfig,
		config::{GenericConfig, Hasher, PoseidonGoldilocksConfig},
	},
	timed,
};
use plonky2_field::types::{Field, PrimeField64};
use primitive_types::U256;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use tessera_trees::{MerkleProof, MerkleTree};
use tessera_utils::{ConfigNative, D, F, hasher::HashOutput};

use super::*;
use crate::{
	AccountAddress, AssetId, ConsumeAuth, DS_PUBLIC_IDENTIFIER, NOTE_BATCH, Nonce, NoteCommitment,
	NoteIdentifier, NoteNullifier, PIHelper, PublicIdentifier, STATE_TREE_DEPTH, SpendAuth,
	StandardAccount, StandardNote, SubpoolId, derive_priv_tx_hash,
	plonky2_gadgets::{
		priv_tx::{
			builder::{FakeTxBuilder, FreshAccTxBuilder, SpendTxBuilder, SpendTxSignatures},
			targets::TxKindFlags,
		},
		tests::print_common_data,
	},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfig},
	schnorr::{CompressedPublicKey, PrivateKey, Scalar, schnorr_sign},
	time,
};

/// Set up a subpool environment for spend transaction tests.
///
/// Returns `(approval_sk, approval_cpk, subpool_id, main_pool)`.
fn spend_test_subpool<R: rand::Rng + CryptoRng>(
	rng: &mut R,
) -> (
	PrivateKey,
	CompPubKey,
	SubpoolId,
	Arc<MainPoolConfigTree<HashOutput>>,
) {
	let approval_sk = PrivateKey::sample(rng);
	let approval_cpk: CompPubKey = approval_sk.public_key::<F>().into();
	let subpool = SubpoolConfig::<HashOutput>::new(approval_cpk);
	let subpool_id = SubpoolId(F::ONE);
	let mut main_pool = MainPoolConfigTree::new();
	main_pool
		.insert_subpool(subpool_id, subpool.commitment())
		.unwrap();
	(approval_sk, approval_cpk, subpool_id, Arc::new(main_pool))
}

/// Set up a post-FreshAcc acc0 with a spend key.
///
/// Returns `(acc0, spend_sk)`.
fn spend_test_acc0<R: rand::Rng + CryptoRng>(
	rng: &mut R,
	subpool_id: SubpoolId,
) -> (StandardAccount, PrivateKey) {
	let spend_sk = PrivateKey::sample(rng);
	let mut acc0 = StandardAccount::sample(rng, subpool_id);
	acc0 = acc0.clone_with_incremented_nonce();
	acc0.spend_auth = SpendAuth::new(spend_sk.public_key::<F>().into());
	(acc0, spend_sk)
}

/// Consume an input note sent from acc1 to acc0, with delegated consume auth.
///
/// Delegated consume: consume_auth.config=false (default). The circuit does not
/// require a separate consume signature — approval covers authorization.
#[test]
fn test_spend_tx_consume_delegated() {
	let mut rng = ChaCha8Rng::seed_from_u64(200);
	let (approval_sk, approval_cpk, subpool_id, main_pool) = spend_test_subpool(&mut rng);
	let (acc0, _spend_sk) = spend_test_acc0(&mut rng, subpool_id);
	// consume_auth is delegated by default (config=false, pk=None)

	let acc1 = StandardAccount::sample(&mut rng, SubpoolId(F::from_canonical_u64(2)));
	let asset_id = AssetId(F::ONE);

	// Note sent from acc1 to acc0
	let n0 = StandardNote::create(
		&mut rng,
		AccountAddress::from_acc(&acc0),
		AccountAddress::from_acc(&acc1),
		U256::from(100u64),
		asset_id,
		[0u8; 512],
	);

	let mut state_tree = MerkleTree::<HashOutput>::new(STATE_TREE_DEPTH);
	let _acc0_pos = state_tree.insert(acc0.commitment().0).unwrap();
	let n0_pos = state_tree.insert(n0.commitment().0).unwrap();

	// Build: consume n0, no output notes
	let built = SpendTxBuilder::new(acc0, asset_id, approval_cpk)
		.unwrap()
		.add_input_note(n0, n0_pos)
		.unwrap()
		.fill_dinotes(&mut rng)
		.fill_donotes(&mut rng)
		.build()
		.unwrap();

	// Approval only — consume is delegated so no separate consume signature
	let approval_sig = built.approval_sign(&approval_sk, &mut rng).unwrap();
	let sigs = SpendTxSignatures::new(None, None, approval_sig);

	let circuit = build_priv_tx_circuit();
	let priv_tx = built
		.into_priv_tx_with_signatures(sigs, &state_tree, main_pool)
		.unwrap();
	let proven = priv_tx
		.prove(&circuit.circuit_data, &circuit.targets)
		.expect("prove failed");

	// Basic PI assertions
	// TODO: improve PI assertions
	let tp = crate::PrivateTransactionProof(proven.proof.clone());
	assert_eq!(tp.not_fake_tx().to_canonical_u64(), 1);
	assert_eq!(tp.act_root(), state_tree.root());

	circuit.circuit_data.verify(proven.proof).expect("verify failed");
}

/// Reject an input note sent from acc1 to acc0 (returns it to sender).
///
/// Reject pair: the note is consumed and a mirror output note (recipient=sender)
/// is produced. No regular inotes or onotes; approval signature only.
#[test]
fn test_spend_tx_reject_input_note() {
	let mut rng = ChaCha8Rng::seed_from_u64(201);
	let (approval_sk, approval_cpk, subpool_id, main_pool) = spend_test_subpool(&mut rng);
	let (acc0, _spend_sk) = spend_test_acc0(&mut rng, subpool_id);

	let acc1 = StandardAccount::sample(&mut rng, SubpoolId(F::from_canonical_u64(2)));
	let asset_id = AssetId(F::ONE);

	// Note sent from acc1 to acc0
	let n0 = StandardNote::create(
		&mut rng,
		AccountAddress::from_acc(&acc0),
		AccountAddress::from_acc(&acc1),
		U256::from(75u64),
		asset_id,
		[0u8; 512],
	);

	let mut state_tree = MerkleTree::<HashOutput>::new(STATE_TREE_DEPTH);
	let _acc0_pos = state_tree.insert(acc0.commitment().0).unwrap();
	let n0_pos = state_tree.insert(n0.commitment().0).unwrap();

	// Build: reject n0 (mirror output note is derived automatically)
	let built = SpendTxBuilder::new(acc0, asset_id, approval_cpk)
		.unwrap()
		.add_rejected_note(n0, n0_pos)
		.unwrap()
		.fill_dinotes(&mut rng)
		.fill_donotes(&mut rng)
		.build()
		.unwrap();

	let approval_sig = built.approval_sign(&approval_sk, &mut rng).unwrap();
	let sigs = SpendTxSignatures::new(None, None, approval_sig);

	let circuit = build_priv_tx_circuit();
	let priv_tx = built
		.into_priv_tx_with_signatures(sigs, &state_tree, main_pool)
		.unwrap();
	let proven = priv_tx
		.prove(&circuit.circuit_data, &circuit.targets)
		.expect("prove failed");

	let tp = crate::PrivateTransactionProof(proven.proof.clone());
	assert_eq!(tp.not_fake_tx().to_canonical_u64(), 1);
	assert_eq!(tp.act_root(), state_tree.root());

	circuit.circuit_data.verify(proven.proof).expect("verify failed");
}

/// Spend from acc0's existing balance, creating an output note to acc1.
///
/// No input notes; acc0 has a pre-existing AST balance and authorises the
/// spend with its spend key.
#[test]
fn test_spend_tx_spend_from_balance() {
	let mut rng = ChaCha8Rng::seed_from_u64(202);
	let (approval_sk, approval_cpk, subpool_id, main_pool) = spend_test_subpool(&mut rng);
	let (mut acc0, spend_sk) = spend_test_acc0(&mut rng, subpool_id);

	// Pre-load acc0's balance for the asset
	let asset_id = AssetId(F::ONE);
	acc0.ast
		.insert_or_update_asset(asset_id, U256::from(100u64));

	let acc1 = StandardAccount::sample(&mut rng, SubpoolId(F::from_canonical_u64(2)));

	let mut state_tree = MerkleTree::<HashOutput>::new(STATE_TREE_DEPTH);
	let _acc0_pos = state_tree.insert(acc0.commitment().0).unwrap();

	// Build: create output note to acc1 for 50, spending from existing balance
	let built = SpendTxBuilder::new(acc0, asset_id, approval_cpk)
		.unwrap()
		.add_output_note(
			AccountAddress::from_acc(&acc1),
			U256::from(50u64),
			[0u8; 512],
			&mut rng,
		)
		.unwrap()
		.fill_dinotes(&mut rng)
		.fill_donotes(&mut rng)
		.build()
		.unwrap();

	// Spend sig required (has output notes)
	let spend_sig = built.spend_sign(&spend_sk, &mut rng).unwrap();
	let approval_sig = built.approval_sign(&approval_sk, &mut rng).unwrap();
	let sigs = SpendTxSignatures::new(spend_sig, None, approval_sig);

	let circuit = build_priv_tx_circuit();
	let priv_tx = built
		.into_priv_tx_with_signatures(sigs, &state_tree, main_pool)
		.unwrap();
	let proven = priv_tx
		.prove(&circuit.circuit_data, &circuit.targets)
		.expect("prove failed");

	let tp = crate::PrivateTransactionProof(proven.proof.clone());
	assert_eq!(tp.not_fake_tx().to_canonical_u64(), 1);
	assert_eq!(tp.act_root(), state_tree.root());

	circuit.circuit_data.verify(proven.proof).expect("verify failed");
}

/// Consume an input note with non-delegated consume auth (own consume key).
///
/// consume_auth.config=true: acc0 holds its own consume key and must provide
/// a consume signature to authorise consuming notes.
#[test]
fn test_spend_tx_consume_non_delegated() {
	let mut rng = ChaCha8Rng::seed_from_u64(203);
	let (approval_sk, approval_cpk, subpool_id, main_pool) = spend_test_subpool(&mut rng);
	let (mut acc0, _spend_sk) = spend_test_acc0(&mut rng, subpool_id);

	// Set non-delegated consume auth with an explicit key
	let consume_sk = PrivateKey::sample(&mut rng);
	let consume_cpk: CompressedPublicKey<F> = consume_sk.public_key::<F>().into();
	acc0.consume_auth = ConsumeAuth {
		config: true,
		pk: Some(consume_cpk),
	};

	let acc1 = StandardAccount::sample(&mut rng, SubpoolId(F::from_canonical_u64(2)));
	let asset_id = AssetId(F::ONE);

	// Note sent from acc1 to acc0
	let n0 = StandardNote::create(
		&mut rng,
		AccountAddress::from_acc(&acc0),
		AccountAddress::from_acc(&acc1),
		U256::from(60u64),
		asset_id,
		[0u8; 512],
	);

	let mut state_tree = MerkleTree::<HashOutput>::new(STATE_TREE_DEPTH);
	let _acc0_pos = state_tree.insert(acc0.commitment().0).unwrap();
	let n0_pos = state_tree.insert(n0.commitment().0).unwrap();

	// Build: consume n0, no output notes
	let built = SpendTxBuilder::new(acc0, asset_id, approval_cpk)
		.unwrap()
		.add_input_note(n0, n0_pos)
		.unwrap()
		.fill_dinotes(&mut rng)
		.fill_donotes(&mut rng)
		.build()
		.unwrap();

	// Consume sig required (non-delegated, has inotes, no onotes)
	let consume_sig = built.consume_sign(&consume_sk, &mut rng).unwrap();
	let approval_sig = built.approval_sign(&approval_sk, &mut rng).unwrap();
	let sigs = SpendTxSignatures::new(None, consume_sig, approval_sig);

	let circuit = build_priv_tx_circuit();
	let priv_tx = built
		.into_priv_tx_with_signatures(sigs, &state_tree, main_pool)
		.unwrap();
	let proven = priv_tx
		.prove(&circuit.circuit_data, &circuit.targets)
		.expect("prove failed");

	let tp = crate::PrivateTransactionProof(proven.proof.clone());
	assert_eq!(tp.not_fake_tx().to_canonical_u64(), 1);
	assert_eq!(tp.act_root(), state_tree.root());

	circuit.circuit_data.verify(proven.proof).expect("verify failed");
}

#[test]
fn test_fake_spend_tx() {
	let zerohash = HashOutput([F::ZERO; 4]);
	let circuit = build_priv_tx_circuit();
	let priv_tx = FakeTxBuilder::new(zerohash, zerohash)
		.build()
		.into_priv_tx();
	let proven = priv_tx
		.prove(&circuit.circuit_data, &circuit.targets)
		.expect("prove failed");
	circuit.circuit_data.verify(proven.proof).expect("verify failed");
}

#[test]
fn test_prove_fresh_acc_tx() {
	let mut rng = ChaCha8Rng::seed_from_u64(42);

	// ── Subpool ───────────────────────────────────────────────────────────
	let approval_sk = PrivateKey::sample(&mut rng);
	let approval_cpk: CompPubKey = approval_sk.public_key::<F>().into();
	let subpool = SubpoolConfig::<HashOutput>::new(approval_cpk);
	let subpool_id = SubpoolId(F::ONE);
	let mut main_pool = MainPoolConfigTree::new();
	main_pool
		.insert_subpool(subpool_id, subpool.commitment())
		.unwrap();
	let main_pool = Arc::new(main_pool);

	// ── Account (nonce=0, not yet in state tree) ──────────────────────────
	let accin = StandardAccount::sample(&mut rng, subpool_id);
	let spend_sk = PrivateKey::sample(&mut rng);
	let spend_cpk: CompressedPublicKey<F> = spend_sk.public_key().into();

	// Empty state tree — FreshAcc account is not yet committed
	let state_tree = MerkleTree::<HashOutput>::new(STATE_TREE_DEPTH);

	// ── Build ─────────────────────────────────────────────────────────────
	let built = FreshAccTxBuilder::new(accin)
		.unwrap()
		.with_new_spend_key(spend_cpk)
		.with_delegated_consume()
		.fill_dinotes(&mut rng)
		.fill_donotes(&mut rng)
		.build()
		.unwrap();

	let approval_sig = built.approval_sign(&approval_sk, &mut rng).unwrap();
	let priv_tx = built
		.into_priv_tx_with_signature(approval_sig, &state_tree, main_pool, approval_cpk)
		.unwrap();

	// ── Prove & verify ────────────────────────────────────────────────────
	let circuit = build_priv_tx_circuit();
	let proven = priv_tx
		.prove(&circuit.circuit_data, &circuit.targets)
		.expect("prove failed");

	let tp = crate::PrivateTransactionProof(proven.proof.clone());
	assert_eq!(tp.not_fake_tx().to_canonical_u64(), 1);

	circuit.circuit_data.verify(proven.proof).expect("verify failed");
}
