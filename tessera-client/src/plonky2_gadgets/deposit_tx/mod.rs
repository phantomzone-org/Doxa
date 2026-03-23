use plonky2::{
	hash::{
		hash_types::{HashOut, RichField},
		poseidon::Poseidon,
	},
	iop::{
		target::Target,
		witness::{PartialWitness, WitnessWrite},
	},
	plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};
use plonky2_field::{
	extension::Extendable,
	types::{Field, PrimeField64},
};
use primitive_types::{H160, U256};
use tessera_utils::{
	F,
	hasher::{HashOutput, MerkleHashCircuit, MerkleHashTarget},
	plonky2_gadgets::u32::gadgets::add_u8_range_check_lookup_table,
};

use crate::{
	ACC_AST_DEPTH, AccountAddress, AssetId, COM_TREE_DEPTH, MAIN_POOL_CONFIG_DEPTH, Nonce,
	SUBPOOL_CONFIG_DEPTH, StandardAccount, SubpoolId,
	account::{AccountStateTreeLeaf, PublicIdentifier},
	derive_deposit_tx_hash,
	ecgfp5::{CompressedPoint, PointEw},
	note::DepositNote,
	plonky2_gadgets::{
		deposit_tx::{
			cb::DepositTxCircuitBuilder,
			targets::{DepositNoteTarget, DepositTxSignatureTargets, DepositTxTargets},
		},
		merkle::{
			SetDummyMerklePathOfWitness, SetMerklePathOfWitness,
			conditional_merkle_verify_commitment_tree_gadget,
		},
		priv_tx::{
			circuit_builder::PrivTxCircuitBuilder,
			targets::{
				AccountNullifierTarget, AssetIdTarget, MainPoolConfigRootTarget,
				PublicIdentifierTaregt, RootTarget, SubpoolIdTarget,
			},
		},
		set_hash, set_u256_zero,
		signature::{LocalQuinticExtension, PubkeyTarget, conditional_schnorr_verify_gadget},
		u256::CircuitBuilderU256,
		witness::{
			fake_authority_keys, set_authority_keys, set_fake_schnorr_signature,
			set_real_schnorr_signature, set_subpool_full_proof,
		},
	},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
	schnorr::{CompressedPublicKey, Signature},
	tree::CommitmentTreeMerkleProof,
	utils::map_h160_to_f,
};

pub(crate) mod cb;
pub(crate) mod targets;

/// Build the Plonky2 deposit transaction circuit.
///
/// The circuit proves that an Ethereum user has deposited funds into a valid
/// Tessera account, with all authorization checks satisfied.
///
/// # Constraints enforced
/// 1. **ACT membership** — `accin`'s commitment exists in the Account Commitment Tree (conditional
///    on `not_fake_tx`).
/// 2. **Recipient match** — the deposit note's recipient address matches `accin`.
/// 3. **Account invariants** — `private_identifier`, `subpool_id`, `spend_auth`, `consume_auth` are
///    unchanged; nonce increments by 1.
/// 4. **AST update** — the asset leaf is updated consistently in both `accin` and `accout`'s
///    Account State Trees at the same leaf index.
/// 5. **Balance invariant** — `accout_amt == accin_amt + deposit_note.amount`.
/// 6. **Subpool membership** — authority keys are proven against `mainpool_config_root`.
/// 7. **Signatures** — both consume and approval Schnorr signatures over the tx hash are verified.
///
/// # Public inputs
/// ```text
/// not_fake_tx[1] | act_root[4] | accin_null[4] | accout_comm[4]
/// | deposit_note_comm[4] | eth_address[5] | amount[8] | asset_id[1]
/// ```
///
/// Returns all allocated targets; pass to [`set_deposit_tx_witness`] or
/// [`set_fake_deposit_tx_witness`] to fill a proof.
pub fn deposit_tx_circuit<
	H: MerkleHashCircuit<F, D, HashTarget = MerkleHashTarget<4>>,
	F: RichField + Extendable<D> + Poseidon,
	const D: usize,
>(
	builder: &mut CircuitBuilder<F, D>,
) -> DepositTxTargets
where
	HashOutput: MerkleHashCircuit<F, D, HashTarget = MerkleHashTarget<4>>,
{
	let not_fake_tx = builder.add_virtual_bool_target_safe();

	// Authority keys
	let (approval_key, rejection_key, subpool_consume_key) = builder.add_virtual_authority_keys();

	// Tree roots
	let root = RootTarget(builder.add_virtual_hash());
	let mainpool_config_root = MainPoolConfigRootTarget(builder.add_virtual_hash());

	// Accounts
	let accin = builder.add_virtual_account_target();
	let accout = builder.add_virtual_account_target();

	// Asset / amounts
	let asset_id = AssetIdTarget(builder.add_virtual_target());
	let accin_amt = builder.add_virtual_u256_target();
	let accout_amt = builder.add_virtual_u256_target();
	let asset_exists_in_accin = builder.add_virtual_bool_target_safe();
	let asset_exists_in_accout = builder.add_virtual_bool_target_safe();

	// AccIn position in ACT
	let accin_pos = builder.add_virtual_target();

	// Deposit note fields
	let deposit_note = DepositNoteTarget {
		identifier: builder.add_virtual_target_arr(),
		recipient_subpool_id: SubpoolIdTarget(builder.add_virtual_target()),
		recipient_public_id: PublicIdentifierTaregt(builder.add_virtual_hash()),
		amount: builder.add_virtual_u256_target(),
		asset_id: AssetIdTarget(builder.add_virtual_target()),
	};

	// Ethereum address (5 u32 field elements)
	let eth_address: [Target; 5] = builder.add_virtual_target_arr();

	// Derive public_identifier from accin.private_identifier
	let public_identifier = builder.derive_public_identifier(accin.private_identifier);

	// Derive nullifier key
	let nk = builder.derive_nullifier_key(accin.private_identifier);

	// Derive AccIn commitment
	let accin_comm = builder.derive_account_commitment(accin);

	// Derive AccOut commitment
	let accout_comm = builder.derive_account_commitment(accout);

	// AccIn nullifier (always position-based for deposit — account must exist in ACT)
	let accin_null = builder.derive_account_nullifier(accin_comm, nk);

	// Connect deposit_note.asset_id with the circuit-level asset_id
	builder.connect(deposit_note.asset_id.0, asset_id.0);

	// Step 1: Verify ACT membership.
	// Deposit always requires a live account — not gated by tx kind.
	let accin_act_merkle = conditional_merkle_verify_commitment_tree_gadget::<H, _, _, _>(
		builder,
		accin_comm.0,
		root.0,
		not_fake_tx,
	);

	// Step 2: Enforce recipient match — deposit note must target accin.
	builder.connect(deposit_note.recipient_subpool_id.0, accin.subpool_id.0);
	builder.connect_array(
		deposit_note.recipient_public_id.0.elements,
		public_identifier.0.elements,
	);

	// Step 3: Account invariants — identity fields frozen, nonce+1.
	builder.assert_account_invariants_simple(accin, accout);

	// Step 4: AST update — verify asset/amt proofs, enforce same leaf position.
	let accin_ast_merkle = builder.assert_ast_update(
		asset_id,
		accin_amt,
		accout_amt,
		accin.acc_ast_root,
		accout.acc_ast_root,
		asset_exists_in_accin,
		asset_exists_in_accout,
	);

	// Step 5: Balance invariant — accout_amt == accin_amt + deposit_note.amount.
	let range_lut = add_u8_range_check_lookup_table(builder);
	let sum = builder.u256_addition_chain::<1>(&accin_amt, &[deposit_note.amount], range_lut);
	builder.connect_u256(&sum, &accout_amt);

	// Step 6: Derive the deposit note commitment (Poseidon over note fields).
	let deposit_note_comm = builder.derive_deposit_note_comm(deposit_note);

	// Step 7: Derive the transaction hash (signed by consume and approval keys).
	let tx_hash =
		builder.derive_deposit_tx_hash(accin_null, accout_comm, deposit_note_comm, eth_address);

	// Step 8: Verify subpool full proof (authority key memberships).
	// Gated by not_fake_tx — dummy proofs skip main-pool root check.
	let subpool_proof_targets = builder.assert_subpool_full_proof(
		SubpoolIdTarget(accin.subpool_id.0),
		approval_key,
		rejection_key,
		subpool_consume_key,
		mainpool_config_root,
		not_fake_tx,
	);

	// Step 9: Verify Schnorr signatures.
	// Consume: accin.consume_auth.config selects between accin's own key (config=1)
	//          or the subpool consume key (config=0, delegation mode).
	let effective_consume_key = PubkeyTarget(LocalQuinticExtension(core::array::from_fn(|i| {
		builder._if(
			accin.consume_auth.config,
			accin.consume_auth.pk.0.0[i],
			subpool_consume_key.0.0[i],
		)
	})));
	let consume =
		conditional_schnorr_verify_gadget(builder, tx_hash, effective_consume_key, not_fake_tx);
	// Approval: always the subpool approval key.
	let approval = conditional_schnorr_verify_gadget(builder, tx_hash, approval_key, not_fake_tx);

	// Register public inputs
	//   - not_fake_tx
	//   - ACT root
	//   - AccIn nullifier
	//   - AccOut Commitment
	//   - deposit note commitment
	//   - eth_address
	//   - deposit note amount
	//   - deposit note asset_id
	builder.register_public_input(not_fake_tx.target);
	builder.register_public_inputs(&root.0.elements);
	builder.register_public_inputs(&accin_null.0.elements);
	builder.register_public_inputs(&accout_comm.0.elements);
	builder.register_public_inputs(&deposit_note_comm.0.elements);
	builder.register_public_inputs(&eth_address);
	builder.register_public_inputs(&deposit_note.amount.0.map(|v| v.0));
	builder.register_public_input(asset_id.0);

	DepositTxTargets {
		not_fake_tx,
		root,
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
		accin_act_merkle,
		accin_ast_merkle,
		deposit_note,
		deposit_note_comm,
		eth_address,
		subpool_proof_targets,
		sig_targets: DepositTxSignatureTargets {
			consume,
			approval,
		},
	}
}

/// Fill `pw` with a complete DepositTx witness.
///
/// `accout` is derived internally: cloned from `accin`, nonce incremented by one,
/// AST updated with `deposit_note.amount` credited to `deposit_note.asset_id`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn set_deposit_tx_witness(
	pw: &mut PartialWitness<F>,
	t: &DepositTxTargets,
	act_root: HashOutput,
	main_pool: MainPoolConfigTree,
	accin: &StandardAccount,
	accin_act_merkle_proof: CommitmentTreeMerkleProof<COM_TREE_DEPTH>,
	deposit_note: &DepositNote,
	eth_address: &H160,
	approval_key: &CompPubKey,
	rejection_key: &CompPubKey,
	consume_key: &CompPubKey,
	subpool_id: SubpoolId,
	consume_sig: Signature,
	approval_sig: Signature,
) {
	let asset_id = deposit_note.asset_id;
	let deposit_amt = deposit_note.amount;

	// ── Build accout ──────────────────────────────────────────────────────────
	let (ast_index, old_bal) = accin
		.ast
		.amount_for(asset_id)
		.unwrap_or_else(|| (accin.ast.next_index(), U256::zero()));
	let new_bal = old_bal + deposit_amt;
	let mut accout = accin.clone_with_incremented_nonce();
	accout.ast.insert_or_update_asset(asset_id, new_bal);

	// ── Amounts and exists flags ───────────────────────────────────────────────
	let (_, accin_amt) = accin.ast.amount_for(asset_id).unwrap_or((0, U256::zero()));
	let (_, accout_amt) = accout.ast.amount_for(asset_id).unwrap_or((0, U256::zero()));
	let asset_exists_in_accin = accin.ast.amount_for(asset_id).is_some();
	let asset_exists_in_accout = true; // always true after deposit

	// ── Native TxHash ─────────────────────────────────────────────────────────
	// H(accin_null[4] || accout_comm[4] || deposit_note_comm[4] || eth_address[5])
	let accin_null = accin.nullifier();
	let deposit_note_comm_native = deposit_note.commitment();
	let tx_hash = derive_deposit_tx_hash(
		accin_null,
		accout.commitment(),
		deposit_note_comm_native,
		*eth_address,
	);

	// --- Tx Flags -------------------------------------------------------------
	pw.set_bool_target(t.not_fake_tx, true).unwrap();

	// ── Tree roots ────────────────────────────────────────────────────────────
	set_hash(pw, t.root.0, act_root.0);
	set_hash(pw, t.mainpool_config_root.0, main_pool.root().0);

	// ── Authority keys ────────────────────────────────────────────────────────
	set_authority_keys(
		pw,
		&t.approval_key,
		&t.rejection_key,
		&t.subpool_consume_key,
		approval_key,
		rejection_key,
		consume_key,
	);

	// ── Accounts ──────────────────────────────────────────────────────────────
	t.accin.set_witness(pw, accin);
	t.accout.set_witness(pw, &accout);

	// ── Asset / amounts ───────────────────────────────────────────────────────
	pw.set_target(t.asset_id.0, asset_id.0).unwrap();
	t.accin_amt.set_witness(pw, accin_amt);
	t.accout_amt.set_witness(pw, accout_amt);
	pw.set_bool_target(t.asset_exists_in_accin, asset_exists_in_accin)
		.unwrap();
	pw.set_bool_target(t.asset_exists_in_accout, asset_exists_in_accout)
		.unwrap();
	pw.set_target(
		t.accin_pos,
		F::from_canonical_usize(accin_act_merkle_proof.pos),
	)
	.unwrap();

	// ── ACT Merkle proof ──────────────────────────────────────────────────────
	t.accin_act_merkle.set_witness(pw, &accin_act_merkle_proof);

	// ── AccIn AST Merkle proof ────────────────────────────────────────────────
	t.accin_ast_merkle
		.set_witness(pw, &accin.ast.merkle_proof_at(ast_index));

	// ── Deposit note ─────────────────────────────────────────────────────────
	t.deposit_note.set_witness(pw, deposit_note);

	// ── Eth address ───────────────────────────────────────────────────────────
	pw.set_target_arr(&t.eth_address, &map_h160_to_f(eth_address))
		.unwrap();

	// ── Subpool full proof ────────────────────────────────────────────────────
	set_subpool_full_proof(
		pw,
		&t.subpool_proof_targets,
		&main_pool,
		approval_key,
		rejection_key,
		consume_key,
		subpool_id,
	);

	// ── Signatures ────────────────────────────────────────────────────────────

	// Consume: uses accin.consume_auth.config to pick key (same as circuit)
	set_real_schnorr_signature(
		pw,
		&t.sig_targets.consume,
		if accin.consume_auth.config {
			accin.consume_auth.pk.unwrap()
		} else {
			*consume_key
		},
		&tx_hash.0,
		consume_sig,
	);

	// Approval
	set_real_schnorr_signature(
		pw,
		&t.sig_targets.approval,
		*approval_key,
		&tx_hash.0,
		approval_sig,
	);
}

/// Compiled deposit_tx circuit together with its targets.
///
/// The targets are kept private so that `DepositTxTargets` (which is
/// `pub(crate)`) does not need to be exposed publicly.
pub struct DepositTxCircuit {
	/// Compiled circuit data — exposes `common` and `verifier_only` to
	/// external callers (e.g. for constructing a `GenericAggregator`).
	pub circuit_data: tessera_utils::CircuitDataNative,
	targets: DepositTxTargets,
}

impl DepositTxCircuit {
	/// Generate a dummy deposit_tx proof (`not_fake_tx=0`).
	///
	/// Used to seed the `GenericAggregator` for artifact generation
	/// (O(log N) doubling) and as the padding proof at runtime.
	pub fn prove_dummy(&self) -> tessera_utils::ProofNative {
		use plonky2::iop::witness::PartialWitness;
		use tessera_utils::hasher::HashOutput;

		let mut pw = PartialWitness::new();
		let zero_root = HashOutput([F::ZERO; 4]);
		set_fake_deposit_tx_witness(&mut pw, &self.targets, zero_root, zero_root);
		self.circuit_data
			.prove(pw)
			.expect("dummy deposit_tx proof generation failed")
	}
}

/// Build the deposit_tx circuit using `HashOutput` as the Merkle hasher.
pub fn build_deposit_tx_circuit() -> DepositTxCircuit {
	use plonky2::plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig};
	use tessera_utils::hasher::HashOutput;

	let config = CircuitConfig::standard_recursion_config();
	let mut builder = CircuitBuilder::<F, { tessera_utils::D }>::new(config);
	let targets = deposit_tx_circuit::<HashOutput, F, { tessera_utils::D }>(&mut builder);
	let circuit_data = builder.build::<tessera_utils::ConfigNative>();
	DepositTxCircuit {
		circuit_data,
		targets,
	}
}

/// Fill `pw` with a dummy deposit-tx witness (`not_fake_tx=0`).
///
/// All secret values are deterministic placeholders.  No real Merkle proofs or
/// signatures are required because all constraint checks are gated on
/// `not_fake_tx`.  Used to pad empty aggregation slots.
///
/// # Subpool proof handling
/// The three per-key depth-2 membership proofs **are** real (reconstructed from
/// fixed fake keys) because those checks run unconditionally.  Only the main-pool
/// depth-20 inclusion proof is zeroed — that check is gated by `not_fake_tx`.
pub(crate) fn set_fake_deposit_tx_witness(
	pw: &mut PartialWitness<F>,
	t: &DepositTxTargets,
	act_root: HashOutput,
	mainpool_config_root: HashOutput,
) {
	// ── Sample accin ────────────────────────────────────────────────────────--
	let accin = StandardAccount::new_with(
		crate::PrivateIdentifier([F::from_canonical_u64(1), F::from_noncanonical_u64(2)]),
		SubpoolId(F::ZERO),
	);

	// ── Derive accout ─────────────────────────────────────────────────────────
	let accout = accin.clone_with_incremented_nonce();

	// ── Tx kind flags ---------------------------------------------------------
	pw.set_bool_target(t.not_fake_tx, false).unwrap();

	// ── Tree roots ─────────────────────────────────────────────────-----------
	set_hash(pw, t.mainpool_config_root.0, mainpool_config_root.0);
	set_hash(pw, t.root.0, act_root.0);

	// ── Authority keys (derived from fixed scalars) ───────────────────────────
	let (fake_approval_cpk, fake_rejection_cpk, fake_consume_cpk) = fake_authority_keys();
	set_authority_keys(
		pw,
		&t.approval_key,
		&t.rejection_key,
		&t.subpool_consume_key,
		&fake_approval_cpk,
		&fake_rejection_cpk,
		&fake_consume_cpk,
	);

	// ── Accounts ──────────────────────────────────────────────────────────────
	t.accin.set_witness(pw, &accin);
	t.accout.set_witness(pw, &accout);

	// ── Asset / amounts (all zeros) ───────────────────────────────────────────
	pw.set_target(t.asset_id.0, F::ZERO).unwrap();
	set_u256_zero(pw, &t.accin_amt);
	set_u256_zero(pw, &t.accout_amt);
	pw.set_bool_target(t.asset_exists_in_accin, false).unwrap();
	pw.set_bool_target(t.asset_exists_in_accout, false).unwrap();
	pw.set_target(t.accin_pos, F::ZERO).unwrap();

	// ── ACT Merkle proof (all zeros) ──────────────────────────────────────────
	t.accin_act_merkle.set_dummy_witness(pw, COM_TREE_DEPTH);

	// ── AST Merkle proof (real path of default leaf at index 0) ──────────────
	t.accin_ast_merkle
		.set_witness(pw, &accin.ast.merkle_proof_at(0));

	// ── Subpool proof ─────────────────────────────────────────────────────────
	// The three key-membership proofs are real (reconstructed from the fake keys).
	// Only the main-pool inclusion proof is zeroed — it is not enforced when
	// not_fake_tx = false.
	let fake_subpool =
		SubpoolConfigTree::new(fake_approval_cpk, fake_rejection_cpk, fake_consume_cpk);
	t.subpool_proof_targets
		.approval_proof
		.set_witness(pw, &fake_subpool.approval_key_proof());
	t.subpool_proof_targets
		.rejection_proof
		.set_witness(pw, &fake_subpool.rejection_key_proof());
	t.subpool_proof_targets
		.consume_proof
		.set_witness(pw, &fake_subpool.consume_key_proof());
	t.subpool_proof_targets
		.main_pool_proof
		.set_dummy_witness(pw, MAIN_POOL_CONFIG_DEPTH);
	pw.set_target_arr(
		&t.subpool_proof_targets.subpool_config_root.0.elements,
		&fake_subpool.root().0,
	)
	.unwrap();

	// ── Deposit note ─────────────────────────────────────────────────────────
	t.deposit_note.set_witness(
		pw,
		&DepositNote {
			identifier: [F::ZERO; 2],
			recipient: AccountAddress::from_acc(&accin),
			asset_id: AssetId(F::ZERO),
			amount: U256::zero(),
		},
	);

	// ── Eth address ───────────────────────────────────────────────────────────
	pw.set_target_arr(&t.eth_address, &map_h160_to_f(&H160::zero()))
		.unwrap();

	// Consume (fake)
	set_fake_schnorr_signature(
		pw,
		&t.sig_targets.consume,
		fake_consume_cpk,
		[13, 13, 13, 13, 13],
		[14, 15, 16, 17, 18],
	);

	// Approval (fake)
	set_fake_schnorr_signature(
		pw,
		&t.sig_targets.approval,
		fake_approval_cpk,
		[21, 22, 23, 24, 25],
		[31, 32, 33, 34, 35],
	);
}
#[cfg(test)]
mod tests {
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
	use tessera_trees::CommitmentTree;
	use tessera_utils::hasher::HashOutput;

	use super::*;
	use crate::{
		AccountAddress, AssetId, COM_TREE_DEPTH, Nonce, StandardAccount, SubpoolId,
		account::AccountStateTreeLeaf,
		derive_deposit_tx_hash,
		note::DepositNote,
		pool_config::{CompPubKey, MainPoolConfigNode, MainPoolConfigTree, SubpoolConfigTree},
		schnorr::{PrivateKey, Scalar, schnorr_sign},
	};

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = <C as GenericConfig<D>>::F;

	#[test]
	fn test_prove_deposit_tx() {
		// ── Keys for subpool ──────────────────────────────────────────────────
		let approval_sk = PrivateKey::from_raw([1, 2, 3, 4, 5]);
		let approval_cpk: CompPubKey = approval_sk.public_key::<F>().into();
		let rejection_sk = PrivateKey::from_raw([5, 6, 7, 8, 0]);
		let rejection_cpk: CompPubKey = rejection_sk.public_key::<F>().into();
		let consume_sk = PrivateKey::from_raw([9, 10, 11, 12, 0]);
		let consume_cpk: CompPubKey = consume_sk.public_key::<F>().into();

		let subpool_id = SubpoolId(F::ONE);
		let subpool = SubpoolConfigTree::new(approval_cpk, rejection_cpk, consume_cpk);
		let mut main_pool = MainPoolConfigTree::new();
		main_pool.set_subpool(0, subpool_id, subpool.root());

		// ── Sample accin ──────────────────────────────────────────────────────
		let mut rng = ChaCha8Rng::seed_from_u64(42);
		let mut accin = StandardAccount::sample(&mut rng, subpool_id);

		// --- Simulate FreshAcc ------------------------------------------------
		accin.nonce = Nonce(F::ONE);
		accin.spend_auth = crate::SpendAuth {
			spend_pk: Some(PrivateKey::from_raw([8, 7, 6, 5, 4]).public_key().into()),
		};

		// ── Insert accin into ACT ─────────────────────────────────────────────
		let mut act = CommitmentTree::<HashOutput>::new(COM_TREE_DEPTH);
		let accin_insert = act.insert(accin.commitment().0).unwrap();
		assert_eq!(&accin_insert.siblings_new, &accin_insert.siblings_old);
		let accin_merkle_proof = CommitmentTreeMerkleProof::new(
			accin.commitment().0,
			accin_insert.siblings_new,
			accin_insert.path,
			act.num_leaves(),
		);

		// ── DepositNote targeting accin ───────────────────────────────────────
		let asset_id = AssetId(F::from_canonical_u64(7));
		let deposit_note = DepositNote {
			identifier: [F::from_canonical_u64(11), F::from_canonical_u64(22)],
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
		let mut pw = PartialWitness::new();
		set_deposit_tx_witness(
			&mut pw,
			&t,
			act.get_root(),
			main_pool,
			&accin,
			accin_merkle_proof,
			&deposit_note,
			&eth_address,
			&approval_cpk,
			&rejection_cpk,
			&consume_cpk,
			subpool_id,
			consume_sig,
			approval_sig,
		);

		// ── Prove & verify ────────────────────────────────────────────────────
		let proof = data.prove(pw).expect("prove failed");
		data.verify(proof).expect("verify failed");
	}

	#[test]
	fn test_fake_tx() {
		// ── Build circuit ──────────────────────────────────────────────────────
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let t = deposit_tx_circuit::<HashOutput, _, _>(&mut builder);
		let data = builder.build::<C>();
		let mut pw = PartialWitness::new();

		let zerohash = HashOutput([F::ZERO; 4]);
		set_fake_deposit_tx_witness(&mut pw, &t, zerohash, zerohash);

		// ── Prove & verify ─────────────────────────────────────────────────────
		let proof = data.prove(pw).expect("prove failed");
		data.verify(proof).expect("verify failed");
	}
}
