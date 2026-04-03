use plonky2::{
	hash::{
		hash_types::{HashOutTarget, RichField},
		poseidon::Poseidon,
	},
	iop::{
		target::{BoolTarget, Target},
		witness::PartialWitness,
	},
	plonk::circuit_builder::CircuitBuilder,
};
use plonky2_field::extension::Extendable;
use tessera_utils::{
	hasher::{HashOutput, MerkleHashCircuit, MerkleHashTarget},
	plonky2_gadgets::u32::add_u8_range_check_lookup_table,
};

use crate::{
	AssetId, COM_TREE_DEPTH, NOTE_BATCH,
	plonky2_gadgets::{
		merkle::conditional_merkle_verify_gadget,
		priv_tx::{
			circuit_builder::PrivTxCircuitBuilder,
			targets::{
				AccountNullifierTarget, AssetIdTarget, MainPoolConfigRootTarget, RootTarget,
				SubpoolIdTarget,
			},
		},
		signature::conditional_schnorr_verify_gadget,
		u256::CircuitBuilderU256,
		withdraw_tx::{
			cb::WithdrawTxCircuitBuilder,
			targets::{WithdrawTxPrivateTargets, WithdrawTxPublicTargets, WithdrawTxTargets},
		},
	},
};

/// Build the Plonky2 withdrawal transaction circuit.
///
/// A withdrawal moves up to `NOTE_BATCH` asset balances from a Tessera account
/// to an Ethereum address, with each slot proved in a single Plonky2 proof.
///
/// # Constraints enforced
/// 1. **ACT membership** — `accin`'s commitment exists in the ACT (gated by `not_fake_tx`).
/// 2. **Account invariants** — `private_identifier`, `subpool_id`, `spend_auth`, `consume_auth` are
///    unchanged; nonce increments by 1.
/// 3. **Chained AST updates** — each withdrawal slot reduces the asset balance and proves the leaf
///    update at the correct position.  The root of slot `i`'s output AST equals the input root of
///    slot `i+1`.
/// 4. **Balance invariant per slot** — `accin_amts[i] == accout_amts[i] + withdrawal_amts[i]`.
/// 5. **Subpool membership** — authority keys proven against `mainpool_config_root`.
/// 6. **Approval signature** — signed over the tx hash by the subpool approval key.
///
/// # Public inputs
/// ```text
/// subpool_id_in[1] | subpool_id_out[1] | not_fake_tx[1] | act_root[4] | mainpool_config_root[4]
/// | accin_null[4] | accout_comm[4] | asset_ids[NOTE_BATCH] | withdrawal_amts_f[8×NOTE_BATCH]
/// | w_acc_addr[5]
/// ```
pub fn withdraw_tx_circuit<
	H: MerkleHashCircuit<F, D, HashTarget = MerkleHashTarget<4>>,
	F: RichField + Extendable<D> + Poseidon,
	const D: usize,
>(
	builder: &mut CircuitBuilder<F, D>,
) -> WithdrawTxTargets
where
	HashOutput: MerkleHashCircuit<F, D, HashTarget = MerkleHashTarget<4>>,
{
	// ── Tx flag ───────────────────────────────────────────────────────────────
	let not_fake_tx = builder.add_virtual_bool_target_safe();

	// ── Authority keys ────────────────────────────────────────────────────────
	let (approval_key, rejection_key, subpool_consume_key) = builder.add_virtual_authority_keys();

	// ── Tree roots ────────────────────────────────────────────────────────────
	let act_root = RootTarget(builder.add_virtual_hash());
	let mainpool_config_root = MainPoolConfigRootTarget(builder.add_virtual_hash());

	// ── Accounts ──────────────────────────────────────────────────────────────
	let accin = builder.add_virtual_account_target();
	let accout = builder.add_virtual_account_target();
	let accin_pos = builder.add_virtual_target();

	// ── Per-asset withdrawal fields ───────────────────────────────────────────
	let asset_ids: [AssetIdTarget; NOTE_BATCH] =
		core::array::from_fn(|_| AssetIdTarget(builder.add_virtual_target()));
	let withdrawal_amts = core::array::from_fn(|_| builder.add_virtual_u256_target());
	let accin_amts = core::array::from_fn(|_| builder.add_virtual_u256_target());
	let accout_amts = core::array::from_fn(|_| builder.add_virtual_u256_target());
	let asset_exists_in_accin: [BoolTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_bool_target_safe());
	let asset_exists_in_accout: [BoolTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_bool_target_safe());

	// ── Withdrawal destination ────────────────────────────────────────────────
	let w_acc_addr: [Target; 5] = builder.add_virtual_target_arr();

	// ── Commitment / nullifier / nullifier-key derivation ─────────────────────
	let nk = builder.derive_nullifier_key(accin.private_identifier);
	let accin_comm = builder.derive_account_commitment(accin);
	let accout_comm = builder.derive_account_commitment(accout);
	// Withdrawal always requires an existing account — position-based nullifier.
	let accin_null = AccountNullifierTarget(builder.derive_account_nullifier(accin_comm, nk).0);

	// ── ACT membership ───────────────────────────────────────────────────────
	let accin_act_merkle = conditional_merkle_verify_gadget::<F, D>(
		builder,
		accin_comm.0,
		act_root.0,
		not_fake_tx,
		COM_TREE_DEPTH,
	);

	// ── Account invariants ───────────────────────────────────────────────────
	// Enforces unconditionally: private_identifier, subpool_id, nonce+1,
	// spend_auth, and consume_auth are all immutable. AST root may change.
	builder.assert_account_invariants_simple(accin, accout);

	// ── Chained AST updates ───────────────────────────────────────────────────
	// Process NOTE_BATCH withdrawal slots in sequence.
	//
	// Each slot subtracts withdrawal_amts[i] from asset_ids[i] in the AST.
	// Intermediate roots thread through so that each slot's output is the
	// next slot's input:
	//
	//   accin.acc_ast_root
	//     → (slot 0) → intermediate_roots[0]
	//     → (slot 1) → intermediate_roots[1]
	//     → ...
	//     → (slot N-1) → accout.acc_ast_root
	//
	// This proves the full sequence of balance deductions atomically.
	let intermediate_roots: Vec<HashOutTarget> = (0..NOTE_BATCH - 1)
		.map(|_| builder.add_virtual_hash())
		.collect();

	let range_lut = add_u8_range_check_lookup_table(builder);

	let ast_merkles = core::array::from_fn(|i| {
		let prev_root = if i == 0 {
			accin.acc_ast_root
		} else {
			intermediate_roots[i - 1]
		};
		let curr_root = if i < NOTE_BATCH - 1 {
			intermediate_roots[i]
		} else {
			accout.acc_ast_root
		};

		// Per-slot balance invariant: accin_amts[i] == accout_amts[i] + withdrawal_amts[i].
		let rhs =
			builder.u256_addition_chain::<1>(&accout_amts[i], &[withdrawal_amts[i]], range_lut);
		builder.connect_u256(&accin_amts[i], &rhs);

		// AST update proof: same leaf position updated in prev_root → curr_root.
		builder.assert_ast_update(
			asset_ids[i],
			accin_amts[i],
			accout_amts[i],
			prev_root,
			curr_root,
			asset_exists_in_accin[i],
			asset_exists_in_accout[i],
		)
	});

	// ── Tx hash ───────────────────────────────────────────────────────────────
	let tx_hash = builder.derive_withdraw_tx_hash(
		accin_null,
		accout_comm,
		asset_ids,
		withdrawal_amts,
		w_acc_addr,
	);

	// ── Subpool full proof ────────────────────────────────────────────────────
	let subpool_proof_targets = builder.assert_subpool_full_proof(
		SubpoolIdTarget(accin.subpool_id.0),
		approval_key,
		rejection_key,
		subpool_consume_key,
		mainpool_config_root,
		not_fake_tx,
	);

	// ── Approval signature ────────────────────────────────────────────────────
	let approval_sig =
		conditional_schnorr_verify_gadget(builder, tx_hash.0, approval_key, not_fake_tx);

	// ── Public inputs ─────────────────────────────────────────────────────────
	let public = WithdrawTxPublicTargets {
		not_fake_tx,
		root: act_root,
		mainpool_config_root,
		accin_null,
		accout_comm,
		asset_ids,
		withdrawal_amts,
		w_acc_addr,
	};
	public.register(builder);

	WithdrawTxTargets {
		public,
		private: WithdrawTxPrivateTargets {
			approval_key,
			rejection_key,
			subpool_consume_key,
			accin,
			accout,
			accin_pos,
			accin_amts,
			accout_amts,
			asset_exists_in_accin,
			asset_exists_in_accout,
			accin_act_merkle,
			ast_merkles,
			subpool_proof_targets,
			approval_sig,
			acc_in_subpool_id: accin.subpool_id,
			acc_out_subpool_id: accout.subpool_id,
		},
	}
}

// ---------------------------------------------------------------------------
// WithdrawTxCircuit
// ---------------------------------------------------------------------------

/// Pre-built withdrawal transaction circuit, analogous to [`DepositTxCircuit`].
pub struct WithdrawTxCircuit {
	/// Compiled circuit data — exposes `common` and `verifier_only` to external
	/// callers (e.g. for constructing a `GenericAggregator`).
	pub circuit_data: tessera_utils::CircuitDataNative,
	targets: WithdrawTxTargets,
}

impl WithdrawTxCircuit {
	/// Generate a dummy withdrawal proof (`not_fake_tx=0`) with zero roots.
	pub fn prove_dummy(&self) -> tessera_utils::ProofNative {
		let mut pw = PartialWitness::new();
		self.targets.set_fake(&mut pw);
		self.circuit_data
			.prove(pw)
			.expect("dummy withdraw_tx proof generation failed")
	}

	/// Generate a padding withdrawal proof (`not_fake_tx=0`) with the specified
	/// `act_root` and `mainpool_config_root`, so that padding proofs share the
	/// same common PIs as the real proofs in their batch.
	pub fn prove_padding(
		&self,
		act_root: HashOutput,
		mainpool_config_root: HashOutput,
	) -> tessera_utils::ProofNative {
		let mut pw = PartialWitness::new();
		self.targets
			.set_fake_with_roots(&mut pw, act_root, mainpool_config_root);
		self.circuit_data
			.prove(pw)
			.expect("padding withdraw_tx proof generation failed")
	}
}

/// Build the withdraw_tx circuit using `HashOutput` as the Merkle hasher.
pub fn build_withdraw_tx_circuit() -> WithdrawTxCircuit {
	use plonky2::plonk::circuit_data::CircuitConfig;

	let config = CircuitConfig::standard_recursion_config();
	let mut builder = CircuitBuilder::<tessera_utils::F, { tessera_utils::D }>::new(config);
	let targets =
		withdraw_tx_circuit::<HashOutput, tessera_utils::F, { tessera_utils::D }>(&mut builder);
	let circuit_data = builder.build::<tessera_utils::ConfigNative>();
	WithdrawTxCircuit {
		circuit_data,
		targets,
	}
}
