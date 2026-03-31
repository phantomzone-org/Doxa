use std::array;

use plonky2::{
	iop::witness::{PartialWitness, WitnessWrite},
	plonk::config::Hasher,
};
use plonky2_field::types::Field;
use rand::Rng;
use tessera_utils::{F, hasher::HashOutput};

use super::{
	double_hash_native,
	targets::TxCircuitTargets,
	witness::{TxKindFlags, set_common_tx_witness, set_tx_kind_flags},
};
use crate::{
	AccountAddress, AssetId, COM_TREE_DEPTH, ConsumeAuth, DEFAULT_SPEND_AUTH_PK,
	MAIN_POOL_CONFIG_DEPTH, NOTE_BATCH, Nonce, NoteCommitment, NoteNullifier, SUBPOOL_CONFIG_DEPTH,
	SpendAuth, StandardAccount, SubpoolId,
	account::PublicIdentifier,
	derive_priv_tx_hash,
	ecgfp5::CompressedPoint,
	note::{NoteIdentifier, StandardNote},
	plonky2_gadgets::{
		set_hash, set_u256_zero,
		witness::{
			set_fake_schnorr_signature, set_hash_blocks, set_real_schnorr_signature,
			set_subpool_full_proof,
		},
	},
	pool_config::{CompPubKey, MainPoolConfigTree},
	schnorr::{CompressedPublicKey, Signature},
};

/// Fill `pw` with a complete FreshAcc transaction witness.
///
/// `accout` is derived internally by cloning `accin` and applying
/// `new_spend_auth`, `new_consume_auth`, and incrementing the nonce to 1.
///
/// The subpool config tree is reconstructed internally from the three keys.
/// `main_pool` must already contain an entry for `subpool_id`; the function
/// panics otherwise.
/// Sample `NOTE_BATCH` random dummy input-note and output-note hashes.
///
/// Each hash is 4 Goldilocks field elements drawn uniformly at random.
/// The returned arrays are suitable as `dinotes` / `donotes` inputs to
/// [`set_freshacc_tx_witness`].
///
/// `root` is `HashOutput([F::ZERO; 4])` for a normal FreshAcc (account not yet
/// in the on-chain IMT; no notes to prove membership for).
#[allow(clippy::too_many_arguments)]
pub(crate) fn set_freshacc_tx_witness(
	pw: &mut PartialWitness<F>,
	t: &TxCircuitTargets,
	not_fake_tx: bool,
	accin: &StandardAccount,
	new_spend_auth: SpendAuth,
	new_consume_auth: ConsumeAuth,
	root: HashOutput,
	approval_key: CompPubKey,
	rejection_key: CompPubKey,
	consume_key: CompPubKey,
	subpool_id: SubpoolId,
	main_pool: &MainPoolConfigTree<HashOutput>,
	approval_sig: Signature,
	dinotes: [[F; 4]; NOTE_BATCH],
	donotes: [[F; 4]; NOTE_BATCH],
) {
	// ── Build accout ──────────────────────────────────────────────────────────
	let mut accout = accin.clone_with_incremented_nonce();
	accout.spend_auth = new_spend_auth;
	accout.consume_auth = new_consume_auth;

	// ── Dummy notes (needed for tx_hash) ──────────────────────────────────────
	let dinote_nulls = array::from_fn(|i| NoteNullifier(double_hash_native(dinotes[i]).into()));
	let donote_comms = array::from_fn(|i| NoteCommitment(double_hash_native(donotes[i]).into()));

	// ── Tx hash ───────────────────────────────────────────────────────────────
	let tx_hash = derive_priv_tx_hash(
		accin.nullifier(),
		accout.commitment(),
		dinote_nulls,
		donote_comms,
	);

	// ── Tx kind flags ─────────────────────────────────────────────────────────
	set_tx_kind_flags(
		pw,
		t,
		TxKindFlags {
			is_rjct: false,
			is_fresh_acc: true,
			is_update_auth: false,
			is_priv_tx: false,
			not_fake_tx,
		},
	);

	// ── Tree roots ────────────────────────────────────────────────────────────
	set_common_tx_witness(
		pw,
		t,
		main_pool.root(),
		root,
		&approval_key,
		&rejection_key,
		&consume_key,
		accin,
		&accout,
	);

	// ── Asset / amounts (all zeros for FreshAcc) ──────────────────────────────
	pw.set_target(t.asset_id.0, F::ZERO).unwrap();
	set_u256_zero(pw, &t.accin_amt);
	set_u256_zero(pw, &t.accout_amt);
	pw.set_bool_target(t.asset_exists_in_accin, false).unwrap();
	pw.set_bool_target(t.asset_exists_in_accout, false).unwrap();
	pw.set_target(t.accin_pos, F::ZERO).unwrap();

	// ── Merkle proofs ─────────────────────────────────────────────────────────

	// ACT: not enforced for FreshAcc
	t.accin_act_merkle.set_dummy_witness(pw);

	// accin AST at index 0 (asset not in tree → Empty leaf)
	t.accin_ast_merkle
		.set_witness(pw, &accin.ast.merkle_proof_at(0));
	// accout_ast_merkle is auto-filled via connect_array in the circuit

	// ── Input notes (all inactive) ────────────────────────────────────────────
	let zero_addr = AccountAddress::zero();
	let inote = StandardNote {
		identifier: NoteIdentifier::ZERO,
		asset_id: AssetId(F::ZERO),
		amt: primitive_types::U256::zero(),
		recipient: AccountAddress::from_acc(accin),
		sender: zero_addr,
		memo: [0u8; 512],
	};
	for i in 0..NOTE_BATCH {
		t.inotes[i].set_witness(pw, &inote);
		pw.set_target(t.inotes_pos[i], F::ZERO).unwrap();
		pw.set_bool_target(t.inotes_isactive[i], false).unwrap();
		// NCT: not enforced (selector = false)
		t.inotes_nct_merkle[i].set_dummy_witness(pw);
	}

	// ── Output notes (all inactive) ───────────────────────────────────────────
	let onote = StandardNote {
		identifier: NoteIdentifier::ZERO,
		asset_id: AssetId(F::ZERO),
		amt: primitive_types::U256::zero(),
		recipient: zero_addr,
		sender: zero_addr,
		memo: [0u8; 512],
	};
	for i in 0..NOTE_BATCH {
		t.onotes[i].set_witness(pw, &onote);
		pw.set_bool_target(t.onotes_isactive[i], false).unwrap();
	}

	// ── Dummy note hashes ─────────────────────────────────────────────────────
	set_hash_blocks(pw, &t.dinotes.map(|note| note.0), &dinotes);
	set_hash_blocks(pw, &t.donotes.map(|note| note.0), &donotes);

	// ── AN/AC/NN/NC override targets ─────────────────────────────────────────
	// For real TXs these equal the derived values (enforced by circuit).
	set_hash(pw, t.accin_null.0, accin.nullifier().0.0);
	set_hash(pw, t.accout_comm.0, accout.commitment().0.0);

	// ── Subpool full proof ────────────────────────────────────────────────────
	set_subpool_full_proof(
		pw,
		&t.subpool_proof_targets,
		main_pool,
		&approval_key,
		&rejection_key,
		&consume_key,
		subpool_id,
	);

	// ── Signatures ────────────────────────────────────────────────────────────

	// Spend (fake): is_spend_req = false → apply_check = false.
	set_fake_schnorr_signature(
		pw,
		&t.sig_targets.spend,
		CompressedPublicKey(CompressedPoint::from(DEFAULT_SPEND_AUTH_PK)),
		[42, 8, 2, 5, 1],
		[7, 12, 13, 14, 14],
	);

	// Consume (fake): consume_auth.config = false → circuit uses subpool_consume_key.
	set_fake_schnorr_signature(
		pw,
		&t.sig_targets.consume,
		consume_key,
		[13, 13, 5, 6, 7],
		[17, 19, 12, 13, 16],
	);

	// Approval (real): always enforced for FreshAcc.
	set_real_schnorr_signature(
		pw,
		&t.sig_targets.approval,
		approval_key,
		&tx_hash.0,
		approval_sig,
	);
}

#[cfg(test)]
mod tests {
	use std::array;

	use plonky2::{
		iop::witness::PartialWitness,
		plonk::{
			circuit_builder::CircuitBuilder,
			circuit_data::CircuitConfig,
			config::{GenericConfig, PoseidonGoldilocksConfig},
		},
	};
	use plonky2_field::types::Field;
	use rand::{SeedableRng, rand_core::Rng};
	use rand_chacha::ChaCha8Rng;
	use tessera_utils::hasher::{HashOutput, MerkleHashCircuit};

	use super::*;
	use crate::{
		Nonce, NoteCommitment, NoteNullifier, SpendAuth, StandardAccount, SubpoolId,
		derive_priv_tx_hash,
		plonky2_gadgets::priv_tx::{double_hash_native, priv_tx_circuit, sample_dummy_notes},
		pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
		schnorr::{CompressedPublicKey, PrivateKey, Scalar, schnorr_sign},
	};

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = <C as GenericConfig<D>>::F;

	fn sample_sk(rng: &mut impl Rng) -> PrivateKey {
		PrivateKey::from_raw(array::from_fn(|_| rng.next_u64()))
	}

	#[test]
	fn test_prove_fresh_acc_tx() {
		let mut rng = ChaCha8Rng::seed_from_u64(42);

		// ── Keys for one subpool ──────────────────────────────────────────────
		let approval_sk = sample_sk(&mut rng);
		let approval_cpk: CompPubKey = approval_sk.public_key::<F>().into();

		let rejection_sk = sample_sk(&mut rng);
		let rejection_cpk: CompPubKey = rejection_sk.public_key::<F>().into();

		let consume_sk = sample_sk(&mut rng);
		let consume_cpk: CompPubKey = consume_sk.public_key::<F>().into();

		let subpool =
			SubpoolConfigTree::<HashOutput>::new(approval_cpk, rejection_cpk, consume_cpk);
		let subpool_id = SubpoolId(F::ONE);

		let mut main_pool = MainPoolConfigTree::new();
		main_pool
			.insert_subpool(subpool_id, subpool.root())
			.unwrap();

		// ── Accounts ─────────────────────────────────────────────────────────
		let accin = StandardAccount::sample(&mut rng, subpool_id);

		let nspend_sk = sample_sk(&mut rng);
		let spend_cpk: CompressedPublicKey<F> = nspend_sk.public_key().into();
		let new_spend_auth = SpendAuth {
			spend_pk: Some(spend_cpk),
		};
		let new_consume_auth = accin.consume_auth.clone();

		// ── Compute tx_hash to produce the approval signature ─────────────────
		// Mirrors the dummy-note encoding inside set_freshacc_tx_witness.
		let mut accout = accin.clone();
		accout.nonce = Nonce(F::ONE);
		accout.spend_auth = new_spend_auth.clone();
		accout.consume_auth = new_consume_auth.clone();

		let (dinotes, donotes) = sample_dummy_notes(&mut rng);
		let dinote_nulls = array::from_fn(|i| NoteNullifier(double_hash_native(dinotes[i]).into()));
		let donote_comms =
			array::from_fn(|i| NoteCommitment(double_hash_native(donotes[i]).into()));
		let tx_hash = derive_priv_tx_hash(
			accin.nullifier(),
			accout.commitment(),
			dinote_nulls,
			donote_comms,
		);

		// TODO: sample randomly and reduce mod n
		let k = Scalar::from_raw(array::from_fn(|_| 1));
		let approval_sig = schnorr_sign(&approval_sk, &tx_hash.0, k);

		// ── Build circuit ─────────────────────────────────────────────────────
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let t = priv_tx_circuit::<HashOutput, _, _>(&mut builder);
		let data = builder.build::<C>();
		let mut pw = PartialWitness::new();

		// ── Fill witness ──────────────────────────────────────────────────────
		super::set_freshacc_tx_witness(
			&mut pw,
			&t,
			true,
			&accin,
			new_spend_auth,
			new_consume_auth,
			HashOutput([F::ZERO; 4]), // root: not in IMT yet; no notes for FreshAcc
			approval_cpk,
			rejection_cpk,
			consume_cpk,
			subpool_id,
			&main_pool,
			approval_sig,
			dinotes,
			donotes,
		);

		// ── Prove & verify ────────────────────────────────────────────────────
		let proof = data.prove(pw).expect("prove failed");
		data.verify(proof).expect("verify failed");
	}
}
