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
	util::bits_u64,
};
use plonky2_field::{
	extension::Extendable,
	types::{Field, PrimeField64},
};
use primitive_types::{H160, U256};
use tessera_trees::MerkleProof;
use tessera_utils::{
	F,
	hasher::{HashOutput, MerkleHashCircuit, MerkleHashTarget},
	plonky2_gadgets::u32::gadgets::add_u8_range_check_lookup_table,
};

use crate::{
	ACC_AST_DEPTH, AccountAddress, AssetId, MAIN_POOL_CONFIG_DEPTH, Nonce, STATE_TREE_DEPTH,
	SUBPOOL_CONFIG_DEPTH, StandardAccount, SubpoolId,
	account::{AccountStateTreeLeaf, PublicIdentifier},
	derive_deposit_tx_hash,
	ecgfp5::{CompressedPoint, PointEw},
	note::DepositNote,
	plonky2_gadgets::{
		deposit_tx::{
			cb::DepositTxCircuitBuilder,
			targets::{
				DepositNoteTarget, DepositTxPrivateTargets, DepositTxPublicTargets,
				DepositTxSignatureTargets, DepositTxTargets,
			},
		},
		merkle::conditional_merkle_verify_gadget,
		priv_tx::{
			circuit_builder::PrivTxCircuitBuilder,
			targets::{
				AccountNullifierTarget, AssetIdTarget, MainPoolConfigRootTarget,
				PublicIdentifierTarget, StateRootTarget, SubpoolIdTarget,
			},
		},
		set_hash, set_u256_zero,
		signature::{LocalQuinticExtension, PubkeyTarget, conditional_schnorr_verify_gadget},
		u256::CircuitBuilderU256,
	},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfig},
	schnorr::{CompressedPublicKey, Signature},
	utils::map_h160_to_f,
};

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
	/// Generate a dummy deposit_tx proof (`not_fake_tx=0`) with zero roots.
	///
	/// Used to seed the `GenericAggregator` for artifact generation
	/// (O(log N) doubling) and as the padding proof at runtime.
	pub fn prove_dummy(&self) -> tessera_utils::ProofNative {
		use plonky2::iop::witness::PartialWitness;
		use tessera_utils::hasher::HashOutput;

		let mut pw = PartialWitness::new();
		self.targets.set_dummy(&mut pw);
		self.circuit_data
			.prove(pw)
			.expect("dummy deposit_tx proof generation failed")
	}

	/// Generate a padding deposit_tx proof (`not_fake_tx=0`) with the specified
	/// `act_root` and `mainpool_config_root`, so that padding proofs share the
	/// same common PIs as the real proofs in their batch.
	pub fn prove_padding(
		&self,
		act_root: HashOutput,
		mainpool_config_root: HashOutput,
	) -> tessera_utils::ProofNative {
		use plonky2::iop::witness::PartialWitness;

		let mut pw = PartialWitness::new();
		self.targets
			.set_dummy_with_roots(&mut pw, act_root, mainpool_config_root);
		self.circuit_data
			.prove(pw)
			.expect("padding deposit_tx proof generation failed")
	}

	/// Generate a real deposit_tx proof (`not_fake_tx=1`).
	///
	/// Wraps [`set_deposit_tx_witness`] so that external callers do not need
	/// access to the private `DepositTxTargets`.
	#[allow(clippy::too_many_arguments)]
	pub fn prove_real(
		&self,
		act_root: HashOutput,
		main_pool: MainPoolConfigTree<HashOutput>,
		accin: &StandardAccount,
		accout: &StandardAccount,
		accin_act_merkle_proof: MerkleProof<HashOutput>,
		deposit_note: DepositNote,
		eth_address: H160,
		approval_key: CompPubKey,
		subpool_id: SubpoolId,
		consume_sig: Option<Signature>,
		approval_sig: Signature,
	) -> tessera_utils::ProofNative {
		let mut pw = PartialWitness::new();
		self.targets.set(
			&mut pw,
			act_root,
			&main_pool,
			accin,
			accout,
			accin_act_merkle_proof,
			deposit_note,
			eth_address,
			approval_key,
			subpool_id,
			consume_sig,
			approval_sig,
		);
		self.circuit_data
			.prove(pw)
			.expect("real deposit_tx proof generation failed")
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
/// not_fake_tx[1] | mainpool_config_root[4] | act_root[4] | accin_null[4]
/// | accout_comm[4] | note_comm[4] | eth_address[5] | amount[8] | asset_id[1]
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
	let approval_key = PubkeyTarget(LocalQuinticExtension(builder.add_virtual_target_arr()));

	// Tree roots
	let state_root = StateRootTarget(builder.add_virtual_hash());
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

	// Deposit note fields
	let deposit_note = DepositNoteTarget {
		identifier: builder.add_virtual_target_arr(),
		recipient_subpool_id: SubpoolIdTarget(builder.add_virtual_target()),
		recipient_public_id: PublicIdentifierTarget(builder.add_virtual_hash()),
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
	// Deposit always requires a live account
	let accin_act_merkle = conditional_merkle_verify_gadget::<F, D>(
		builder,
		accin_comm.0,
		state_root.0,
		not_fake_tx,
		STATE_TREE_DEPTH,
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
		mainpool_config_root,
		not_fake_tx,
	);

	// Step 9: Verify Schnorr signatures.
	// Consume: real sig from accin.consume_auth.pk is required if accin.consume_auth.config == 1.
	// Otherwise fake sig.
	let consume_sig_req = builder.and(accin.consume_auth.config, not_fake_tx);
	let consume =
		conditional_schnorr_verify_gadget(builder, tx_hash, accin.consume_auth.pk, consume_sig_req);
	// Approval: always the subpool approval key.
	let approval = conditional_schnorr_verify_gadget(builder, tx_hash, approval_key, not_fake_tx);

	let public_targets = DepositTxPublicTargets {
		not_fake_tx,
		mainpool_config_root,
		state_root,
		accin_null,
		accout_comm,
		note_comm: deposit_note_comm,
		eth_address,
		amount: deposit_note.amount,
		asset_id,
	};

	public_targets.register(builder);

	DepositTxTargets {
		public_targets,
		private_targets: DepositTxPrivateTargets {
			deposit_note,
			accin,
			accout,
			accin_act_merkle,
			accin_ast_merkle,
			accin_amt,
			accout_amt,
			asset_exists_in_accin,
			asset_exists_in_accout,
			approval_key,
			subpool_proof_targets,
			sig_targets: DepositTxSignatureTargets {
				consume,
				approval,
			},
		},
	}
}
