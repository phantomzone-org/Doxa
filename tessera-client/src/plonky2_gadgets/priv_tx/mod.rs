use itertools::Itertools;
use plonky2::{
	hash::{
		hash_types::{HashOutTarget, RichField},
		poseidon::{Poseidon, PoseidonHash},
	},
	iop::target::{BoolTarget, Target},
	plonk::circuit_builder::CircuitBuilder,
};
use plonky2_field::{extension::Extendable, types::Field};
use rand::{CryptoRng, Rng};
use tessera_trees::{F, tree::hasher::MerkleHashCircuit};

use crate::{
	DS_PUBLIC_IDENTIFIER, NOTE_BATCH,
	plonky2_gadgets::{
		priv_tx::{
			cb::PrivTxCircuitBuilder,
			targets::{
				AccountNullifierTarget, ActRootTarget, AssetIdTarget, DummyNoteTarget,
				MainPoolConfigRootTarget, NctRootTarget, NoteCommitmentTarget, NoteNullifierTarget,
				NoteTarget, PublicIdentifierTaregt, SubpoolIdTarget, TxCircuitTargets,
			},
		},
		signature::{LocalQuinticExtension, PubkeyTarget},
		u256::CircuitBuilderU256,
	},
};

pub(crate) mod cb;
mod freshacc;
mod spend;
pub(crate) mod targets;

/// Public alias for the PrivTx circuit targets, used with [`build_priv_tx_circuit`]
/// and [`prove_real_priv_tx`].
pub type PrivTxTargets<const D: usize> = targets::TxCircuitTargets;

fn double_hash_native(elems: [F; 4]) -> [F; 4] {
	use plonky2::plonk::config::Hasher;
	let h0 = <PoseidonHash as Hasher<F>>::hash_no_pad(&elems).elements;
	<PoseidonHash as Hasher<F>>::hash_no_pad(&h0).elements
}

pub(crate) fn sample_dummy_notes<R: CryptoRng>(
	rng: &mut R,
) -> ([[F; 4]; NOTE_BATCH], [[F; 4]; NOTE_BATCH]) {
	// TODO: sample field element at random
	let mut sample_hash = || core::array::from_fn(|_| F::from_canonical_u64(rng.next_u64() >> 1));
	let dinotes = core::array::from_fn(|_| sample_hash());
	let donotes = core::array::from_fn(|_| sample_hash());
	(dinotes, donotes)
}

pub fn priv_tx_circuit<
	H: MerkleHashCircuit<F, D>,
	F: RichField + Extendable<D> + Poseidon,
	const D: usize,
>(
	builder: &mut CircuitBuilder<F, D>,
) -> TxCircuitTargets {
	// Mint constants
	// let ds_nullifier_key = builder.constant(F::from_canonical_u64(DS_NULLIFIER_KEY));
	let ds_public_identifier = builder.constant(F::from_canonical_u64(DS_PUBLIC_IDENTIFIER));

	// not_fake_tx is a PI and set to 1 for tx that are not fake. It may be se to 0 to produce a
	// dummy proof (used at proof aggregation stage)
	let not_fake_tx = builder.add_virtual_bool_target_safe();

	// Tx kinds
	// TODO: where is it checked that these are indeed bool targets?
	let is_rjct = builder.add_virtual_bool_target_safe();
	let is_fresh_acc = builder.add_virtual_bool_target_safe();
	let is_update_auth = builder.add_virtual_bool_target_safe();
	let is_priv_tx = builder.add_virtual_bool_target_safe();

	let act_root = ActRootTarget(builder.add_virtual_hash());
	let nct_root = NctRootTarget(builder.add_virtual_hash());
	let mainpool_config_root = MainPoolConfigRootTarget(builder.add_virtual_hash());

	// Subpool authority keys
	let approval_key = PubkeyTarget(LocalQuinticExtension(builder.add_virtual_target_arr()));
	let rejection_key = PubkeyTarget(LocalQuinticExtension(builder.add_virtual_target_arr()));
	let subpool_consume_key = PubkeyTarget(LocalQuinticExtension(builder.add_virtual_target_arr()));

	let asset_id = AssetIdTarget(builder.add_virtual_target());
	let accin_amt = builder.add_virtual_u256_target();
	let asset_exists_in_accin = builder.add_virtual_bool_target_safe();
	let accout_amt = builder.add_virtual_u256_target();
	let asset_exists_in_accout = builder.add_virtual_bool_target_safe();

	let accin = builder.add_virtual_account_target();
	let accout = builder.add_virtual_account_target();
	let private_identifier = accin.private_identifier;
	let subpool_id = accin.subpool_id;
	let public_identifier = {
		let mut input = vec![ds_public_identifier];
		input.extend(private_identifier.0);
		let pubid = builder.hash_n_to_hash_no_pad::<PoseidonHash>(input);
		PublicIdentifierTaregt(pubid)
	};
	let nk = builder.derive_nullifier_key(accin.private_identifier);

	let accin_comm = builder.derive_account_commitment(accin);
	let accout_comm = builder.derive_account_commitment(accout);

	// Assert AccIn matches FreshAccount defaults when is_fresh_acc
	builder.assert_fresh_account(accin, is_fresh_acc);

	// AccIn → AccOut transition invariants
	// private_identifier, subpool_id are immutable for all tx kinds — enforced by sharing the
	// same wires in `derive_account_commitment` for both accin and accout.
	builder.assert_account_invariants(accin, accout, is_fresh_acc, is_update_auth, is_priv_tx);

	// Check Comm(AccIn) in ACT iff !fresh && not_fake == 1
	let accin_pos = builder.add_virtual_target();
	let not_is_fresh_acc = builder.not(is_fresh_acc);
	let check_act = builder.and(not_is_fresh_acc, not_fake_tx);
	let accin_merkletrgts = builder.conditionally_assert_account_commitment_exists_in_act::<H>(
		accin_comm, act_root, check_act,
	);

	// AccIn nullifier — select fresh vs regular based on is_fresh_acc
	let accin_null_regular = builder.derive_account_nullifier(accin_comm, accin_pos, nk);
	let accin_null_fresh = builder.derive_fresh_account_nullifier(accin_comm, nk);
	let accin_null = AccountNullifierTarget(HashOutTarget {
		elements: core::array::from_fn(|i| {
			builder._if(
				is_fresh_acc,
				accin_null_fresh.0.elements[i],
				accin_null_regular.0.elements[i],
			)
		}),
	});

	// Verify asset/amt proofs in AccIn and AccOut ASTs; enforce same leaf position was updated
	let accin_ast_merkle = builder.assert_ast_update(
		asset_id,
		accin_amt,
		accout_amt,
		accin,
		accout,
		asset_exists_in_accin,
		asset_exists_in_accout,
	);

	// Input and Output notes //

	let inotes: [NoteTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_note_target());
	let inotes_pos: [Target; NOTE_BATCH] = core::array::from_fn(|_| builder.add_virtual_target());
	let inotes_isactive: [BoolTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_bool_target_safe());
	let inotes_comm = core::array::from_fn(|i| builder.derive_note_commitment(inotes[i]));
	let inotes_null: [NoteNullifierTarget; NOTE_BATCH] =
		core::array::from_fn(|i| builder.derive_note_nullifier(inotes_comm[i], inotes_pos[i], nk));

	let onotes: [NoteTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_note_target());
	let onotes_isactive: [BoolTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_bool_target_safe());
	let onotes_comm = onotes.map(|n| builder.derive_note_commitment(n));

	let dinotes: [DummyNoteTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_dummy_note_target());
	let dinotes_null: [NoteNullifierTarget; NOTE_BATCH] =
		core::array::from_fn(|i| builder.derive_dummy_note_nullifier(dinotes[i]));

	let donotes: [DummyNoteTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_dummy_note_target());
	let donotes_comm = donotes.map(|dn| builder.derive_dummy_note_commitment(dn));

	// All inotes and onotes share the same asset_id
	for note in inotes.iter().chain(onotes.iter()) {
		builder.connect(note.asset_id.0, asset_id.0);
	}

	// for each inote verify NCT membership, and check spend auth
	let inotes_mrkltrgt = builder.assert_inotes_valid::<H>(
		inotes,
		inotes_isactive,
		inotes_comm,
		public_identifier,
		subpool_id,
		nct_root,
	);

	// Balance invariant: AccIn.amt + Sum([INote.amt]) == AccOut.amt + Sum([Onote.amt]) //
	builder.assert_balance_invariant(
		accin_amt,
		accout_amt,
		inotes,
		onotes,
		inotes_isactive,
		onotes_isactive,
	);

	// Derive tx hash //

	// select valid inote nullifiers, onote commitments as per respective isactive selector
	let effective_inotes_null: [NoteNullifierTarget; NOTE_BATCH] = core::array::from_fn(|i| {
		NoteNullifierTarget(HashOutTarget {
			elements: core::array::from_fn(|j| {
				builder._if(
					inotes_isactive[i],
					inotes_null[i].0.elements[j],
					dinotes_null[i].0.elements[j],
				)
			}),
		})
	});
	let effective_onotes_comm: [NoteCommitmentTarget; NOTE_BATCH] = core::array::from_fn(|i| {
		NoteCommitmentTarget(HashOutTarget {
			elements: core::array::from_fn(|j| {
				builder._if(
					onotes_isactive[i],
					onotes_comm[i].0.elements[j],
					donotes_comm[i].0.elements[j],
				)
			}),
		})
	});

	let tx_hash = builder.derive_tx_hash(
		effective_inotes_null,
		effective_onotes_comm,
		accin_null,
		accout_comm,
	);

	// Override targets for nullifier-tree PIs (AN, NN).
	// When not_fake_tx=0, these replace the derived values so dummy TX proofs
	// can match tree padding (required for ungated multi-set equality).
	// AC/NC (commitment trees) use conditional connects in the SuperAggregator
	// instead, so no overrides are needed for those.
	let override_an = builder.add_virtual_hash();
	let override_nn: [[Target; 4]; NOTE_BATCH] =
		core::array::from_fn(|_| core::array::from_fn(|_| builder.add_virtual_target()));

	let final_an = AccountNullifierTarget(HashOutTarget {
		elements: core::array::from_fn(|i| {
			builder._if(
				not_fake_tx,
				accin_null.0.elements[i],
				override_an.elements[i],
			)
		}),
	});
	let final_nn: [NoteNullifierTarget; NOTE_BATCH] = core::array::from_fn(|i| {
		NoteNullifierTarget(HashOutTarget {
			elements: core::array::from_fn(|j| {
				builder._if(
					not_fake_tx,
					effective_inotes_null[i].0.elements[j],
					override_nn[i][j],
				)
			}),
		})
	});

	// Validate authorization //

	// Verify SubpoolFullProof: 3 authority key proofs (depth-2) + main pool proof (depth-20)
	// Skip subpoolProof verification if not_fake_tx = 0
	let subpool_proof_targets = builder.assert_subpool_full_proof(
		SubpoolIdTarget(accin.subpool_id.0),
		approval_key,
		rejection_key,
		subpool_consume_key,
		mainpool_config_root,
		not_fake_tx,
	);

	let sig_targets = builder.assert_tx_signatures(
		tx_hash,
		inotes_isactive,
		onotes_isactive,
		accin,
		subpool_consume_key,
		approval_key,
		not_fake_tx,
	);

	// Declare public inputs (75 explicit + 2 lookup metadata = 77 total):
	//  PI[0]     = subpool_id_in
	//  PI[1]     = subpool_id_out
	//  PI[2]     = not_fake_tx (is_real)
	//  PI[3..7]  = AN (account nullifier)
	//  PI[7..11] = AC (account commitment)
	//  PI[11..43]= NN (note nullifiers, 8×4)
	//  PI[43..75]= NC (note commitments, 8×4)
	builder.register_public_input(accin.subpool_id.0);
	builder.register_public_input(accout.subpool_id.0);
	builder.register_public_input(not_fake_tx.target);
	builder.register_public_inputs(&final_an.0.elements);
	builder.register_public_inputs(&accout_comm.0.elements);
	builder.register_public_inputs(
		final_nn
			.iter()
			.flat_map(|v| v.0.elements)
			.collect_vec()
			.as_slice(),
	);
	builder.register_public_inputs(
		effective_onotes_comm
			.iter()
			.flat_map(|v| v.0.elements)
			.collect_vec()
			.as_slice(),
	);

	TxCircuitTargets {
		not_fake_tx,
		is_rjct,
		is_fresh_acc,
		is_update_auth,
		is_priv_tx,
		act_root,
		nct_root,
		mainpool_config_root,
		approval_key,
		rejection_key,
		subpool_consume_key,
		accin,
		accout,
		accin_amt,
		accout_amt,
		asset_id,
		asset_exists_in_accin,
		asset_exists_in_accout,
		accin_pos,
		accin_act_merkle: accin_merkletrgts,
		accin_ast_merkle,
		inotes,
		inotes_pos,
		inotes_isactive,
		onotes,
		onotes_isactive,
		dinotes,
		donotes,
		subpool_proof_targets,
		sig_targets,
		inotes_nct_merkle: inotes_mrkltrgt,
		override_an,
		override_nn,
	}
}

/// Build the PrivTx circuit and generate a FreshAcc proof.
///
/// When `not_fake_tx = false`, produces a dummy proof for padding empty aggregation slots.
/// When `not_fake_tx = true`, produces a real proof with enforced constraints.
///
/// Returns `(circuit_data, proof)`.
fn build_circuit_and_proof_inner(
	not_fake_tx: bool,
) -> (tessera_trees::CircuitDataNative, tessera_trees::ProofNative) {
	build_circuit_and_proof_seeded(not_fake_tx, 0xDEAD_BEEF_CAFE_0000)
}

fn build_circuit_and_proof_seeded(
	not_fake_tx: bool,
	seed: u64,
) -> (tessera_trees::CircuitDataNative, tessera_trees::ProofNative) {
	use plonky2::plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig};
	use tessera_trees::tree::hasher::HashOutput;

	let config = CircuitConfig::standard_recursion_config();
	let mut builder = CircuitBuilder::<F, { tessera_trees::D }>::new(config);
	let t = priv_tx_circuit::<HashOutput, F, { tessera_trees::D }>(&mut builder);
	let circuit = builder.build::<tessera_trees::ConfigNative>();
	let proof = prove_priv_tx(&circuit, &t, not_fake_tx, seed);
	(circuit, proof)
}

/// Generate a PrivTx proof for the given circuit with a specific RNG seed.
///
/// Different seeds produce different accounts, notes, nullifiers, and commitments,
/// ensuring each proof is unique.
fn prove_priv_tx(
	circuit: &tessera_trees::CircuitDataNative,
	t: &PrivTxTargets<{ tessera_trees::D }>,
	not_fake_tx: bool,
	seed: u64,
) -> tessera_trees::ProofNative {
	use std::array;

	use plonky2::iop::witness::PartialWitness;
	use plonky2_field::types::Field;
	use rand::SeedableRng;
	use rand_chacha::ChaCha8Rng;
	use tessera_trees::tree::hasher::HashOutput;

	use crate::{
		ConsumeAuth, Nonce, NoteCommitment, NoteNullifier, SpendAuth, StandardAccount, SubpoolId,
		derive_priv_tx_hash,
		pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
		schnorr::{PrivateKey, Scalar, schnorr_sign},
	};

	let mut rng = ChaCha8Rng::seed_from_u64(seed);
	// Use Scalar::sample to ensure keys are properly reduced modulo the curve order.
	// PrivateKey::from_raw with arbitrary u64s can produce unreduced scalars that
	// break the Montgomery multiplication in Schnorr signature arithmetic.
	let approval_sk = PrivateKey::new(Scalar::sample(&mut rng));
	let approval_cpk: CompPubKey = approval_sk.public_key::<F>().into();
	let rejection_sk = PrivateKey::new(Scalar::sample(&mut rng));
	let rejection_cpk: CompPubKey = rejection_sk.public_key::<F>().into();
	let consume_sk = PrivateKey::new(Scalar::sample(&mut rng));
	let consume_cpk: CompPubKey = consume_sk.public_key::<F>().into();

	let subpool = SubpoolConfigTree::new(approval_cpk, rejection_cpk, consume_cpk);
	let subpool_id = SubpoolId(F::ONE);
	let mut main_pool = MainPoolConfigTree::new();
	main_pool.set_subpool(0, subpool_id, subpool.root());

	let accin = StandardAccount::sample(&mut rng, subpool_id);

	// For real proofs, set proper new auth keys; for dummy, use defaults.
	let (new_spend_auth, new_consume_auth) = if not_fake_tx {
		let nspend_sk = PrivateKey::new(Scalar::sample(&mut rng));
		let spend_cpk = nspend_sk.public_key::<F>().into();
		(
			SpendAuth {
				spend_pk: Some(spend_cpk),
			},
			accin.consume_auth.clone(),
		)
	} else {
		(SpendAuth::default(), ConsumeAuth::default())
	};

	let (dinotes, donotes) = sample_dummy_notes(&mut rng);
	let dinote_nulls: [NoteNullifier; crate::NOTE_BATCH] =
		array::from_fn(|i| NoteNullifier(double_hash_native(dinotes[i]).into()));
	let donote_comms: [NoteCommitment; crate::NOTE_BATCH] =
		array::from_fn(|i| NoteCommitment(double_hash_native(donotes[i]).into()));

	let mut accout = accin.clone();
	accout.nonce = Nonce(F::ONE);
	accout.spend_auth = new_spend_auth.clone();
	accout.consume_auth = new_consume_auth.clone();
	let tx_hash = derive_priv_tx_hash(
		accin.nullifier(None),
		accout.commitment(),
		dinote_nulls,
		donote_comms,
	);
	let k = Scalar::from_raw(array::from_fn(|_| 1u64));
	let approval_sig = schnorr_sign(&approval_sk, &tx_hash, k);

	let mut pw = PartialWitness::new();
	freshacc::set_freshacc_tx_witness(
		&mut pw,
		t,
		not_fake_tx,
		&accin,
		new_spend_auth,
		new_consume_auth,
		HashOutput([F::ZERO; 4]),
		HashOutput([F::ZERO; 4]),
		approval_cpk,
		rejection_cpk,
		consume_cpk,
		subpool_id,
		&main_pool,
		approval_sig,
		dinotes,
		donotes,
		[F::ZERO; 4],
		[[F::ZERO; 4]; crate::NOTE_BATCH],
	);

	let label = if not_fake_tx { "real" } else { "dummy" };
	let proof = circuit
		.prove(pw)
		.unwrap_or_else(|e| panic!("{label} PrivTx proof generation failed: {e}"));
	circuit
		.verify(proof.clone())
		.unwrap_or_else(|e| panic!("{label} PrivTx proof verification failed: {e}"));

	proof
}

/// Build the PrivTx plonky2 circuit and generate a dummy proof with `not_fake_tx=0`.
///
/// Returns `(circuit_data, dummy_proof)` where:
/// - `circuit_data` contains `common` and `verifier_only` needed for recursive verification.
/// - `dummy_proof` is a valid proof with `PI[0]=0` (not_fake_tx=false), used for padding empty
///   aggregation slots on the server.
pub fn build_circuit_and_dummy_proof()
-> (tessera_trees::CircuitDataNative, tessera_trees::ProofNative) {
	build_circuit_and_proof_inner(false)
}

/// Build the PrivTx plonky2 circuit and generate a real proof with `not_fake_tx=1`.
///
/// Returns `(circuit_data, real_proof)` where:
/// - `circuit_data` contains `common` and `verifier_only` needed for recursive verification.
/// - `real_proof` is a valid proof with `PI[0]=1` (not_fake_tx=true) and all constraints enforced.
///   Suitable for E2E testing with the full proof pipeline.
pub fn build_circuit_and_real_proof()
-> (tessera_trees::CircuitDataNative, tessera_trees::ProofNative) {
	build_circuit_and_proof_inner(true)
}

/// Build the PrivTx circuit and generate a real proof with a specific RNG seed.
///
/// Different seeds produce unique accounts, notes, nullifiers, and commitments.
/// The circuit is rebuilt each time; if generating many proofs, prefer
/// [`build_priv_tx_circuit`] + [`prove_real_priv_tx`] to reuse the circuit.
pub fn build_circuit_and_real_proof_seeded(
	seed: u64,
) -> (tessera_trees::CircuitDataNative, tessera_trees::ProofNative) {
	build_circuit_and_proof_seeded(true, seed)
}

/// Build the PrivTx plonky2 circuit without generating a proof.
///
/// Returns `(circuit_data, targets)` for use with [`prove_real_priv_tx`].
pub fn build_priv_tx_circuit() -> (
	tessera_trees::CircuitDataNative,
	PrivTxTargets<{ tessera_trees::D }>,
) {
	use plonky2::plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig};
	use tessera_trees::tree::hasher::HashOutput;

	let config = CircuitConfig::standard_recursion_config();
	let mut builder = CircuitBuilder::<F, { tessera_trees::D }>::new(config);
	let t = priv_tx_circuit::<HashOutput, F, { tessera_trees::D }>(&mut builder);
	let circuit = builder.build::<tessera_trees::ConfigNative>();
	(circuit, t)
}

/// Generate a real PrivTx proof (`not_fake_tx=1`) for a pre-built circuit with a
/// specific RNG seed. Each seed produces unique nullifiers/commitments.
pub fn prove_real_priv_tx(
	circuit: &tessera_trees::CircuitDataNative,
	targets: &PrivTxTargets<{ tessera_trees::D }>,
	seed: u64,
) -> tessera_trees::ProofNative {
	prove_priv_tx(circuit, targets, true, seed)
}

/// Generate a dummy PrivTx proof (`not_fake_tx=0`) with specific AN/NN override
/// values. The override values become the proof's public inputs for the
/// account-nullifier and note-nullifier fields, allowing alignment with
/// nullifier-tree padding leaves.
///
/// `seed` controls the RNG for all other witness data (accounts, notes, keys).
pub fn prove_dummy_priv_tx(
	circuit: &tessera_trees::CircuitDataNative,
	targets: &PrivTxTargets<{ tessera_trees::D }>,
	seed: u64,
	override_an: [F; 4],
	override_nn: [[F; 4]; NOTE_BATCH],
) -> tessera_trees::ProofNative {
	prove_dummy_priv_tx_inner(circuit, targets, seed, override_an, override_nn)
}

fn prove_dummy_priv_tx_inner(
	circuit: &tessera_trees::CircuitDataNative,
	t: &PrivTxTargets<{ tessera_trees::D }>,
	seed: u64,
	override_an: [F; 4],
	override_nn: [[F; 4]; NOTE_BATCH],
) -> tessera_trees::ProofNative {
	use std::array;

	use plonky2::iop::witness::PartialWitness;
	use plonky2_field::types::Field;
	use rand::SeedableRng;
	use rand_chacha::ChaCha8Rng;
	use tessera_trees::tree::hasher::HashOutput;

	use crate::{
		ConsumeAuth, Nonce, NoteCommitment, NoteNullifier, SpendAuth, StandardAccount, SubpoolId,
		derive_priv_tx_hash,
		pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
		schnorr::{PrivateKey, Scalar, schnorr_sign},
	};

	let mut rng = ChaCha8Rng::seed_from_u64(seed);
	let approval_sk = PrivateKey::new(Scalar::sample(&mut rng));
	let approval_cpk: CompPubKey = approval_sk.public_key::<F>().into();
	let rejection_sk = PrivateKey::new(Scalar::sample(&mut rng));
	let rejection_cpk: CompPubKey = rejection_sk.public_key::<F>().into();
	let consume_sk = PrivateKey::new(Scalar::sample(&mut rng));
	let consume_cpk: CompPubKey = consume_sk.public_key::<F>().into();

	let subpool = SubpoolConfigTree::new(approval_cpk, rejection_cpk, consume_cpk);
	let subpool_id = SubpoolId(F::ONE);
	let mut main_pool = MainPoolConfigTree::new();
	main_pool.set_subpool(0, subpool_id, subpool.root());

	let accin = StandardAccount::sample(&mut rng, subpool_id);

	let (dinotes, donotes) = sample_dummy_notes(&mut rng);
	let dinote_nulls: [NoteNullifier; NOTE_BATCH] =
		array::from_fn(|i| NoteNullifier(double_hash_native(dinotes[i]).into()));
	let donote_comms: [NoteCommitment; NOTE_BATCH] =
		array::from_fn(|i| NoteCommitment(double_hash_native(donotes[i]).into()));

	let mut accout = accin.clone();
	accout.nonce = Nonce(F::ONE);
	accout.spend_auth = SpendAuth::default();
	accout.consume_auth = ConsumeAuth::default();
	let tx_hash = derive_priv_tx_hash(
		accin.nullifier(None),
		accout.commitment(),
		dinote_nulls,
		donote_comms,
	);
	let k = Scalar::from_raw(array::from_fn(|_| 1u64));
	let approval_sig = schnorr_sign(&approval_sk, &tx_hash, k);

	let mut pw = PartialWitness::new();
	freshacc::set_freshacc_tx_witness(
		&mut pw,
		t,
		false,
		&accin,
		SpendAuth::default(),
		ConsumeAuth::default(),
		HashOutput([F::ZERO; 4]),
		HashOutput([F::ZERO; 4]),
		approval_cpk,
		rejection_cpk,
		consume_cpk,
		subpool_id,
		&main_pool,
		approval_sig,
		dinotes,
		donotes,
		override_an,
		override_nn,
	);

	let proof = circuit
		.prove(pw)
		.unwrap_or_else(|e| panic!("dummy PrivTx proof generation failed: {e}"));
	circuit
		.verify(proof.clone())
		.unwrap_or_else(|e| panic!("dummy PrivTx proof verification failed: {e}"));

	proof
}
