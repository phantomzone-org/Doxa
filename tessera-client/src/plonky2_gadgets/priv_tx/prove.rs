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
use tessera_utils::{
	D, F,
	hasher::{MerkleHashCircuit, MerkleHashTarget},
};

use crate::{
	FakeTxInputs, NOTE_BATCH, PrivTxInputs,
	plonky2_gadgets::{
		priv_tx::{
			circuit_builder::PrivTxCircuitBuilder,
			fake_tx::set_fake_tx_witness,
			freshacc_tx, priv_tx_circuit, reject_tx, spend_tx,
			targets::{
				AccountCommitmentTarget, AccountNullifierTarget, AssetIdTarget, DummyNoteTarget,
				MainPoolConfigRootTarget, NoteCommitmentTarget, NoteNullifierTarget, NoteTarget,
				StateRootTarget, SubpoolIdTarget, TxCircuitTargets, TxKindFlags,
			},
		},
		signature::PubkeyTarget,
		u256::CircuitBuilderU256,
		witness::set_hash_blocks,
	},
};

/// Public alias for the PrivTx circuit targets, used with [`build_priv_tx_circuit`]
/// and [`prove_priv_tx`].
pub type PrivTxTargets<const D: usize> = TxCircuitTargets;

/// Apply Poseidon twice natively: `H(H(elems))`.
///
/// Mirrors the in-circuit `double_hash` gadget.  Used to derive dummy note
/// nullifiers and commitments from raw seed values.
pub fn double_hash_native(elems: [F; 4]) -> [F; 4] {
	use plonky2::plonk::config::Hasher;
	let h0 = <PoseidonHash as Hasher<F>>::hash_no_pad(&elems).elements;
	<PoseidonHash as Hasher<F>>::hash_no_pad(&h0).elements
}

/// Sample `NOTE_BATCH` pairs of random dummy note seeds.
///
/// Returns `(dinotes, donotes)` where each element is a 4-element field array
/// that becomes a `DummyNoteTarget` seed.  The actual nullifiers / commitments
/// are derived by applying [`double_hash_native`] to each seed.
///
/// Different seeds → different dummy values → unique padding proofs (prevents
/// duplicate PI issues in aggregation).
pub fn sample_dummy_notes<R: CryptoRng>(
	rng: &mut R,
) -> ([[F; 4]; NOTE_BATCH], [[F; 4]; NOTE_BATCH]) {
	// TODO: sample field element at random
	let mut sample_hash = || core::array::from_fn(|_| F::from_canonical_u64(rng.next_u64() >> 1));
	let dinotes = core::array::from_fn(|_| sample_hash());
	let donotes = core::array::from_fn(|_| sample_hash());
	(dinotes, donotes)
}

/// Internal: build the circuit and generate a proof from the given `not_fake_tx` flag.
///
/// Delegates to [`build_circuit_and_proof_seeded`] with a fixed default seed.
/// Produces a FreshAcc proof for real tx and a dummy proof for `not_fake_tx=false`.
fn build_circuit_and_proof_inner(
	not_fake_tx: bool,
) -> (tessera_utils::CircuitDataNative, tessera_utils::ProofNative) {
	build_circuit_and_proof_seeded(not_fake_tx, 0xDEAD_BEEF_CAFE_0000)
}

/// Internal: build the circuit and generate a proof with a specific RNG seed.
///
/// All account / key / note values are derived from `seed` via a seeded RNG.
/// - `not_fake_tx = true`  → real FreshAcc proof with all constraints satisfied.
/// - `not_fake_tx = false` → dummy proof; constraints are bypassed (`is_fresh_acc=false`).
fn build_circuit_and_proof_seeded(
	not_fake_tx: bool,
	seed: u64,
) -> (tessera_utils::CircuitDataNative, tessera_utils::ProofNative) {
	use plonky2::plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig};
	use tessera_utils::hasher::HashOutput;

	let config = CircuitConfig::standard_recursion_config();
	let mut builder = CircuitBuilder::<F, D>::new(config);
	let t = priv_tx_circuit::<HashOutput, F, D>(&mut builder);
	let circuit = builder.build::<tessera_utils::ConfigNative>();
	let proof = prove_priv_tx_inner(&circuit, &t, not_fake_tx, seed);
	(circuit, proof)
}

/// Generate a PrivTx proof for the given circuit with a specific RNG seed.
///
/// Different seeds produce different accounts, notes, nullifiers, and commitments,
/// ensuring each proof is unique.
// TODO: is this used anywhere?
fn prove_priv_tx_inner(
	circuit: &tessera_utils::CircuitDataNative,
	t: &PrivTxTargets<{ tessera_utils::D }>,
	not_fake_tx: bool,
	seed: u64,
) -> tessera_utils::ProofNative {
	use std::array;

	use plonky2::iop::witness::PartialWitness;
	use plonky2_field::types::Field;
	use rand::SeedableRng;
	use rand_chacha::ChaCha8Rng;
	use tessera_utils::hasher::HashOutput;

	use crate::{
		ConsumeAuth, Nonce, NoteCommitment, NoteNullifier, SpendAuth, StandardAccount, SubpoolId,
		derive_priv_tx_hash,
		pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfig},
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

	let subpool = SubpoolConfig::<HashOutput>::new(approval_cpk);
	let subpool_id = SubpoolId(F::ONE);
	let mut main_pool = MainPoolConfigTree::new();
	main_pool
		.insert_subpool(subpool_id, subpool.commitment())
		.unwrap();

	let accin = StandardAccount::sample(&mut rng, subpool_id);

	// For real proofs, set proper new auth keys; for dummy, use defaults.
	let (new_spend_auth, new_consume_auth) = if not_fake_tx {
		let nspend_sk = PrivateKey::new(Scalar::sample(&mut rng));
		let spend_cpk = nspend_sk.public_key::<F>().into();
		(SpendAuth::new(spend_cpk), accin.consume_auth.clone())
	} else {
		(SpendAuth::default(), ConsumeAuth::default())
	};

	let (dinotes, donotes) = sample_dummy_notes(&mut rng);
	let dinote_nulls: [NoteNullifier; crate::NOTE_BATCH] =
		array::from_fn(|i| NoteNullifier(double_hash_native(dinotes[i]).into()));
	let donote_comms: [NoteCommitment; crate::NOTE_BATCH] =
		array::from_fn(|i| NoteCommitment(double_hash_native(donotes[i]).into()));

	let mut accout = accin.clone_with_incremented_nonce();
	accout.spend_auth = new_spend_auth.clone();
	accout.consume_auth = new_consume_auth.clone();
	let tx_hash = derive_priv_tx_hash(
		accin.nullifier(),
		accout.commitment(),
		dinote_nulls,
		donote_comms,
	);
	let karr = [1u8; 40];
	let k = Scalar::decode_reduce(&karr);
	let approval_sig = schnorr_sign(&approval_sk, &tx_hash.0, k);

	let mut pw = PartialWitness::new();
	t.set_tx_kind_flags(
		&mut pw,
		if not_fake_tx {
			TxKindFlags::FRESH_ACC
		} else {
			TxKindFlags::FAKE
		},
	);
	if not_fake_tx {
		// Real proof: use FreshAcc witness (is_fresh_acc=true, not_fake_tx=true set above).
		freshacc_tx::set_freshacc_tx_witness(
			&mut pw,
			t,
			&accin,
			new_spend_auth,
			new_consume_auth,
			HashOutput([F::ZERO; 4]),
			approval_cpk,
			subpool_id,
			&main_pool,
			approval_sig,
			dinotes,
			donotes,
		);
	} else {
		// Dummy proof: must use set_fake_tx_witness (is_fresh_acc=false).
		// Using set_freshacc_tx_witness here would set is_fresh_acc=true, which the circuit
		// constrains to imply not_fake_tx=true, forcing PI[2]=1 even for a dummy proof.
		//
		// All dummy PI values (AN, AC, NC, NN) must equal DUMMY_LEAF =
		// double_hash([0;4]) so that the batch builder's fixed padding matches
		// the circuit output.  NC/NN already equal this (derived from zero note
		// seeds), so we set AN/AC overrides to the same value.
		let dummy = double_hash_native([F::ZERO; 4]);
		set_fake_tx_witness(
			&mut pw,
			t,
			HashOutput([F::ZERO; 4]),
			HashOutput([F::ZERO; 4]),
			dummy,
			dummy,
			[dummy; crate::NOTE_BATCH],
		);
	}

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
-> (tessera_utils::CircuitDataNative, tessera_utils::ProofNative) {
	build_circuit_and_proof_inner(false)
}

/// Build the PrivTx plonky2 circuit and generate a real proof with `not_fake_tx=1`.
///
/// Returns `(circuit_data, real_proof)` where:
/// - `circuit_data` contains `common` and `verifier_only` needed for recursive verification.
/// - `real_proof` is a valid proof with `PI[0]=1` (not_fake_tx=true) and all constraints enforced.
///   Suitable for E2E testing with the full proof pipeline.
pub fn build_circuit_and_real_proof()
-> (tessera_utils::CircuitDataNative, tessera_utils::ProofNative) {
	build_circuit_and_proof_inner(true)
}

/// Build the PrivTx circuit and generate a real proof with a specific RNG seed.
///
/// Different seeds produce unique accounts, notes, nullifiers, and commitments.
/// The circuit is rebuilt each time; if generating many proofs, prefer
/// [`build_priv_tx_circuit`] + [`prove_priv_tx`] to reuse the circuit.
pub fn build_circuit_and_real_proof_seeded(
	seed: u64,
) -> (tessera_utils::CircuitDataNative, tessera_utils::ProofNative) {
	build_circuit_and_proof_seeded(true, seed)
}

/// Build the PrivTx plonky2 circuit without generating a proof.
///
/// Returns `(circuit_data, targets)` for use with [`prove_priv_tx`].
pub fn build_priv_tx_circuit() -> (
	tessera_utils::CircuitDataNative,
	PrivTxTargets<{ tessera_utils::D }>,
) {
	use plonky2::plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig};
	use tessera_utils::hasher::HashOutput;

	let config = CircuitConfig::standard_recursion_config();
	let mut builder = CircuitBuilder::<F, D>::new(config);
	let t = priv_tx_circuit::<HashOutput, F, D>(&mut builder);
	let circuit = builder.build::<tessera_utils::ConfigNative>();
	(circuit, t)
}

/// Generate a PrivTx proof for the given pre-built circuit.
///
/// `inputs` is a [`PrivTxInputs`] enum that selects the transaction kind and
/// carries all necessary witness data:
///
/// - [`PrivTxInputs::FreshAcc`] — real proof (`not_fake_tx=1`), creates a new account.
/// - [`PrivTxInputs::Spend`]    — real proof (`not_fake_tx=1`), spends/transfers assets.
/// - [`PrivTxInputs::Reject`]   — real proof (`not_fake_tx=1`), operator rejects notes.
/// - [`PrivTxInputs::Fake`]     — dummy proof (`not_fake_tx=0`), pads empty slots.
///
/// For real variants the `root` field in the input struct is registered as both
/// PI[77-80] and PI[81-84] (V2 uses a single on-chain IMT) and must match the
/// Merkle proofs supplied (the circuit enforces this when `not_fake_tx=1`).
pub fn prove_priv_tx(
	circuit: &tessera_utils::CircuitDataNative,
	targets: &PrivTxTargets<{ tessera_utils::D }>,
	inputs: PrivTxInputs,
) -> tessera_utils::ProofNative {
	use plonky2::iop::witness::{PartialWitness, WitnessWrite};
	use plonky2_field::types::Field;

	let mut pw = PartialWitness::new();
	let is_fake = matches!(inputs, PrivTxInputs::Fake(_));
	targets.set_tx_kind_flags(&mut pw, inputs.tx_kind_flags());

	match inputs {
		PrivTxInputs::FreshAcc(i) => freshacc_tx::set_freshacc_tx_witness(
			&mut pw,
			targets,
			&i.accin,
			i.new_spend_auth,
			i.new_consume_auth,
			i.state_root,
			i.approval_key,
			i.subpool_id,
			&i.main_pool,
			i.approval_sig,
			i.dinotes,
			i.donotes,
		),
		PrivTxInputs::Spend(i) => spend_tx::set_spend_tx_witness(
			&mut pw,
			targets,
			&i.accin,
			i.state_root,
			i.accin_merkle_proof,
			&i.inotes,
			&i.inotes_nct_proofs,
			&i.onotes,
			i.dinotes,
			i.donotes,
			i.approval_key,
			i.subpool_id,
			&i.main_pool,
			i.spend_sig,
			i.consume_sig,
			i.approval_sig,
		),
		PrivTxInputs::Reject(i) => reject_tx::set_reject_tx_witness(
			&mut pw,
			targets,
			&i.accin,
			i.accin_act_merkle_proof,
			i.root,
			&i.state_root,
			&i.inotes_nct_proofs,
			&i.onotes,
			i.dinotes,
			i.donotes,
			i.approval_key,
			i.subpool_id,
			&i.main_pool,
			i.consume_sig,
			i.approval_sig,
		),
		PrivTxInputs::Fake(i) => {
			set_fake_tx_witness(
				&mut pw,
				targets,
				i.state_root,
				i.mainpool_config_root,
				i.override_an,
				i.override_ac,
				i.override_nc,
			);
		},
	}

	let label = if is_fake { "dummy" } else { "real" };
	let proof = circuit
		.prove(pw)
		.unwrap_or_else(|e| panic!("{label} PrivTx proof generation failed: {e}"));
	circuit
		.verify(proof.clone())
		.unwrap_or_else(|e| panic!("{label} PrivTx proof verification failed: {e}"));
	proof
}

/// Generate a dummy PrivTx proof (`not_fake_tx=0`) with specific AN/AC/NN/NC
/// override values. Convenience wrapper around
/// [`prove_priv_tx`] with [`PrivTxInputs::Fake`].
///
/// The override fields become the proof's public inputs, allowing the sequencer
/// to align each padding slot with nullifier- and commitment-tree padding leaves.
pub fn prove_dummy_priv_tx(
	circuit: &tessera_utils::CircuitDataNative,
	targets: &PrivTxTargets<{ tessera_utils::D }>,
	override_an: [F; 4],
	override_nn: [[F; 4]; NOTE_BATCH],
	override_ac: [F; 4],
	override_nc: [[F; 4]; NOTE_BATCH],
) -> tessera_utils::ProofNative {
	use tessera_utils::hasher::HashOutput;

	prove_priv_tx(
		circuit,
		targets,
		PrivTxInputs::Fake(FakeTxInputs {
			state_root: HashOutput([F::ZERO; 4]),
			mainpool_config_root: HashOutput([F::ZERO; 4]),
			override_an,
			override_ac,
			override_nn,
			override_nc,
		}),
	)
}

/// Generate a synthetic real PrivTx proof from an RNG seed. **For testing and
/// demos only.** All account/note/key data is derived from `seed`; tree roots
/// are zero (valid because the underlying TX is FreshAcc, which has no ACT/NCT
/// membership constraints).
///
/// For production proofs provide a proper [`PrivTxInputs`] to [`prove_priv_tx`].
// TODO: why is this here?
pub fn prove_priv_tx_seeded(
	circuit: &tessera_utils::CircuitDataNative,
	targets: &PrivTxTargets<{ tessera_utils::D }>,
	seed: u64,
) -> tessera_utils::ProofNative {
	prove_priv_tx_inner(circuit, targets, true, seed)
}
