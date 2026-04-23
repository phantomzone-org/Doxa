//! Builder for Withdrawal transactions.

use core::fmt;

use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2_field::types::Field;
use primitive_types::{H160, U256};
use rand::CryptoRng;
use tessera_trees::MerkleTree;
use tessera_utils::{F, hasher::{HashOutput, ToHashOut}};

use super::circuit::WithdrawTxCircuit;
use crate::{
	AssetId, NOTE_BATCH, STATE_TREE_DEPTH, StandardAccount, derive_withdraw_tx_hash,
	plonky2_gadgets::{
		priv_tx::utils::fake_approval_key,
		withdraw_tx::targets::compute_withdrawal_slots,
	},
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfig, SubpoolFullProof},
	schnorr::{PrivateKey, Scalar, Signature, schnorr_sign},
	utils::map_h160_to_f,
};

use super::WithdrawProof;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum WithdrawTxBuilderError {
	AccountNotInitialized,
	TooManyWithdrawals {
		limit: usize,
	},
	NoWithdrawals,
	InsufficientBalance {
		asset_id: AssetId,
		balance: U256,
		withdrawal: U256,
	},
	AccinNotInStateTree,
	ApprovalSignRequired,
	SubpoolNotFound,
	TreeError(anyhow::Error),
}

impl fmt::Display for WithdrawTxBuilderError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::AccountNotInitialized => write!(
				f,
				"Account not initialized (nonce=0). Must perform FreshAcc first"
			),
			Self::TooManyWithdrawals { limit } => {
				write!(f, "Too many withdrawals: limit is {limit}")
			},
			Self::NoWithdrawals => write!(f, "Must add at least one withdrawal before build()"),
			Self::InsufficientBalance {
				asset_id,
				balance,
				withdrawal,
			} => write!(
				f,
				"Insufficient balance for asset {asset_id:?}: balance={balance}, withdrawal={withdrawal}"
			),
			Self::AccinNotInStateTree => {
				write!(f, "Account commitment not found in state tree")
			},
			Self::ApprovalSignRequired => {
				write!(f, "Must call approval_sign() before into_withdraw_tx()")
			},
			Self::SubpoolNotFound => write!(f, "Subpool not found in main pool config"),
			Self::TreeError(e) => write!(f, "Tree error: {e}"),
		}
	}
}

impl std::error::Error for WithdrawTxBuilderError {}

// ── WithdrawRealTxBuilder ─────────────────────────────────────────────────────

/// Builder for constructing real withdrawal transactions.
pub struct WithdrawRealTxBuilder {
	accin: StandardAccount,
	w_acc_addr: H160,
	withdrawals: Vec<(AssetId, U256)>,
}

impl WithdrawRealTxBuilder {
	/// Create a new withdrawal transaction builder.
	///
	/// # Errors
	/// - `AccountNotInitialized`: `accin.nonce == 0` (FreshAcc required first)
	pub fn new(
		accin: StandardAccount,
		w_acc_addr: H160,
	) -> Result<Self, WithdrawTxBuilderError> {
		if accin.nonce.0 == F::ZERO {
			return Err(WithdrawTxBuilderError::AccountNotInitialized);
		}
		Ok(Self {
			accin,
			w_acc_addr,
			withdrawals: Vec::new(),
		})
	}

	/// Add a withdrawal slot.
	///
	/// # Errors
	/// - `TooManyWithdrawals`: already at the `NOTE_BATCH` limit
	pub fn add_withdrawal(
		&mut self,
		asset_id: AssetId,
		amount: U256,
	) -> Result<(), WithdrawTxBuilderError> {
		if self.withdrawals.len() == NOTE_BATCH {
			return Err(WithdrawTxBuilderError::TooManyWithdrawals { limit: NOTE_BATCH });
		}
		self.withdrawals.push((asset_id, amount));
		Ok(())
	}

	/// Validate withdrawals and produce a [`BuiltWithdrawRealTx`].
	///
	/// # Errors
	/// - `NoWithdrawals`: no withdrawal slots were added
	/// - `InsufficientBalance`: an asset's balance is less than the requested withdrawal
	pub fn build(self) -> Result<BuiltWithdrawRealTx, WithdrawTxBuilderError> {
		if self.withdrawals.is_empty() {
			return Err(WithdrawTxBuilderError::NoWithdrawals);
		}

		// Validate balances
		for &(asset_id, withdrawal) in &self.withdrawals {
			let balance = self
				.accin
				.ast
				.amount_for(asset_id)
				.map(|(_, b)| b)
				.unwrap_or_default();
			if balance < withdrawal {
				return Err(WithdrawTxBuilderError::InsufficientBalance {
					asset_id,
					balance,
					withdrawal,
				});
			}
		}

		// Derive accout and compute tx_hash
		let (slot_asset_ids, slot_withdrawal_amts, _, _, _, _, _, accout) =
			compute_withdrawal_slots(&self.accin, &self.withdrawals);

		let accin_null = self.accin.nullifier();
		let tx_hash = derive_withdraw_tx_hash(
			accin_null,
			accout.commitment(),
			slot_asset_ids,
			slot_withdrawal_amts,
			self.w_acc_addr,
		);

		Ok(BuiltWithdrawRealTx {
			accin: self.accin,
			accout,
			withdrawals: self.withdrawals,
			w_acc_addr: self.w_acc_addr,
			tx_hash,
			approval_key: None,
			approval_sig: None,
		})
	}
}

// ── BuiltWithdrawRealTx ───────────────────────────────────────────────────────

/// Validated, ready-to-sign real withdrawal transaction.
///
/// Call [`approval_sign`](Self::approval_sign), then
/// [`into_withdraw_tx`](Self::into_withdraw_tx) to attach proofs.
pub struct BuiltWithdrawRealTx {
	accin: StandardAccount,
	accout: StandardAccount,
	withdrawals: Vec<(AssetId, U256)>,
	w_acc_addr: H160,
	tx_hash: HashOutput,
	/// Set when `approval_sign` is called.
	approval_key: Option<CompPubKey>,
	/// Set when `approval_sign` is called.
	approval_sig: Option<Signature>,
}

impl BuiltWithdrawRealTx {
	/// Return the transaction hash that needs to be signed.
	pub fn tx_hash(&self) -> &HashOutput {
		&self.tx_hash
	}

	/// Return the output account (post-withdrawal state).
	pub fn accout(&self) -> &StandardAccount {
		&self.accout
	}

	/// Generate and store an approval signature from the subpool authority key.
	///
	/// Must be called before [`into_withdraw_tx`](Self::into_withdraw_tx).
	pub fn approval_sign<R: CryptoRng + rand::Rng>(
		&mut self,
		approval_sk: &PrivateKey,
		rng: &mut R,
	) {
		let approval_key: CompPubKey = approval_sk.public_key().into();
		let k = Scalar::sample(rng);
		let sig = schnorr_sign(approval_sk, &self.tx_hash.0, k);
		self.approval_key = Some(approval_key);
		self.approval_sig = Some(sig);
	}

	/// Attach state-tree and main-pool proofs to produce a [`BuiltWithdrawTx`].
	///
	/// # Errors
	/// - `ApprovalSignRequired`: [`approval_sign`](Self::approval_sign) was not called
	/// - `AccinNotInStateTree`: commitment not present in `state_tree`
	/// - `SubpoolNotFound`: account's subpool not in `main_pool`
	/// - `TreeError`: Merkle proof generation failed
	pub fn into_withdraw_tx(
		self,
		state_tree: &MerkleTree<HashOutput>,
		main_pool: &MainPoolConfigTree<HashOutput>,
	) -> Result<BuiltWithdrawTx, WithdrawTxBuilderError> {
		let approval_key = self
			.approval_key
			.ok_or(WithdrawTxBuilderError::ApprovalSignRequired)?;
		let approval_sig = self
			.approval_sig
			.ok_or(WithdrawTxBuilderError::ApprovalSignRequired)?;

		let accin_comm = self.accin.commitment().0;
		let pos = state_tree
			.leaves()
			.iter()
			.position(|l| l == &accin_comm)
			.ok_or(WithdrawTxBuilderError::AccinNotInStateTree)?;

		let accin_act_merkle_proof = state_tree
			.merkle_proof(pos)
			.map_err(|e| WithdrawTxBuilderError::TreeError(anyhow::anyhow!("{}", e)))?;

		let subpool = SubpoolConfig::new(approval_key);
		let subpool_proof = main_pool
			.full_subpool_proof(&subpool, self.accin.subpool_id)
			.map_err(|_| WithdrawTxBuilderError::SubpoolNotFound)?;

		let state_root = state_tree.root();
		let main_pool_root = main_pool.root();

		Ok(BuiltWithdrawTx {
			not_fake_tx: true,
			accin: self.accin,
			withdrawals: self.withdrawals,
			w_acc_addr: self.w_acc_addr,
			approval_key,
			state_root,
			main_pool_root,
			accin_act_merkle_proof,
			subpool_proof,
			approval_sig: Some(approval_sig),
		})
	}
}

// ── FakeWithdrawTxBuilder ─────────────────────────────────────────────────────

/// Builder for constructing fake (dummy) withdrawal transactions.
///
/// Fake transactions have `not_fake_tx = false` and are used to pad empty
/// aggregation slots. No circuit constraints are enforced beyond the boolean
/// shape of `not_fake_tx`.
pub struct FakeWithdrawTxBuilder {
	state_root: HashOutput,
	mainpool_config_root: HashOutput,
}

/// Validated fake withdrawal transaction ready to be converted to [`BuiltWithdrawTx`].
pub struct BuiltFakeWithdrawTx {
	state_root: HashOutput,
	mainpool_config_root: HashOutput,
}

impl FakeWithdrawTxBuilder {
	/// Create a new fake withdrawal transaction builder.
	pub fn new(state_root: HashOutput, mainpool_config_root: HashOutput) -> Self {
		Self {
			state_root,
			mainpool_config_root,
		}
	}

	/// Build the fake transaction (infallible — no validation needed).
	pub fn build(self) -> BuiltFakeWithdrawTx {
		BuiltFakeWithdrawTx {
			state_root: self.state_root,
			mainpool_config_root: self.mainpool_config_root,
		}
	}
}

impl BuiltFakeWithdrawTx {
	/// Convert this fake transaction into a unified [`BuiltWithdrawTx`].
	///
	/// All fields are populated with dummy/zero values. Since `not_fake_tx = false`,
	/// the circuit does not enforce any of these values.
	pub fn into_withdraw_tx(self) -> BuiltWithdrawTx {
		let accin = StandardAccount::fake();
		let approval_key = fake_approval_key();

		let dummy_merkle_proof = tessera_trees::MerkleProof {
			leaf: HashOutput([F::ZERO; 4]),
			siblings: vec![HashOutput([F::ZERO; 4]); STATE_TREE_DEPTH],
			path: vec![false; STATE_TREE_DEPTH],
			pos: 0,
			num_leaves: 0,
			root: HashOutput([F::ZERO; 4]),
		};

		BuiltWithdrawTx {
			not_fake_tx: false,
			accin,
			withdrawals: vec![],
			w_acc_addr: H160::zero(),
			approval_key,
			state_root: self.state_root,
			main_pool_root: self.mainpool_config_root,
			accin_act_merkle_proof: dummy_merkle_proof,
			subpool_proof: SubpoolFullProof::default(),
			approval_sig: None,
		}
	}
}

// ── BuiltWithdrawTx ───────────────────────────────────────────────────────────

/// Fully-specified withdrawal transaction ready for proving.
///
/// Produced by [`BuiltWithdrawRealTx::into_withdraw_tx`] (real) or
/// [`BuiltFakeWithdrawTx::into_withdraw_tx`] (fake/padding).
pub struct BuiltWithdrawTx {
	not_fake_tx: bool,
	accin: StandardAccount,
	withdrawals: Vec<(AssetId, U256)>,
	w_acc_addr: H160,
	approval_key: CompPubKey,
	state_root: HashOutput,
	main_pool_root: HashOutput,
	accin_act_merkle_proof: tessera_trees::MerkleProof<HashOutput>,
	subpool_proof: SubpoolFullProof<HashOutput>,
	/// `Some` for real transactions, `None` for fake (not enforced by circuit).
	approval_sig: Option<Signature>,
}

impl BuiltWithdrawTx {
	/// Generate a zero-knowledge proof for this withdrawal transaction.
	pub fn prove(self, circuit: &WithdrawTxCircuit) -> WithdrawProof {
		let mut pw = PartialWitness::new();
		let t = &circuit.targets;

		let (
			slot_asset_ids,
			slot_withdrawal_amts,
			slot_accin_amts,
			slot_accout_amts,
			slot_exists_in,
			slot_exists_out,
			slot_proofs,
			accout,
		) = compute_withdrawal_slots(&self.accin, &self.withdrawals);

		// ── Public inputs ─────────────────────────────────────────────────────
		pw.set_bool_target(t.public.not_fake_tx, self.not_fake_tx)
			.unwrap();
		pw.set_hash_target(t.public.root.0, self.state_root.to_hash_out())
			.unwrap();
		pw.set_hash_target(
			t.public.mainpool_config_root.0,
			self.main_pool_root.to_hash_out(),
		)
		.unwrap();
		for (i, id) in slot_asset_ids.iter().enumerate() {
			pw.set_target(t.public.asset_ids[i].0, id.0).unwrap();
		}
		for (i, amt) in slot_withdrawal_amts.iter().enumerate() {
			t.public.withdrawal_amts[i].set(&mut pw, *amt);
		}
		pw.set_target_arr(&t.public.w_acc_addr, &map_h160_to_f(self.w_acc_addr))
			.unwrap();

		// ── Private witness ───────────────────────────────────────────────────
		let priv_t = &t.private;

		priv_t.accin.set_witness(&mut pw, &self.accin);
		priv_t.accout.set_witness(&mut pw, &accout);

		for i in 0..NOTE_BATCH {
			priv_t.accin_amts[i].set(&mut pw, slot_accin_amts[i]);
			priv_t.accout_amts[i].set(&mut pw, slot_accout_amts[i]);
			pw.set_bool_target(priv_t.asset_exists_in_accin[i], slot_exists_in[i])
				.unwrap();
			pw.set_bool_target(priv_t.asset_exists_in_accout[i], slot_exists_out[i])
				.unwrap();
			priv_t.ast_merkles[i].set_witness(&mut pw, &slot_proofs[i]);
		}

		priv_t
			.accin_act_merkle
			.set_witness(&mut pw, &self.accin_act_merkle_proof);
		priv_t.approval_key.set_witness(&mut pw, self.approval_key);
		priv_t
			.subpool_proof_targets
			.set_witness(&mut pw, &self.subpool_proof);

		// ── Tx hash and signature ─────────────────────────────────────────────
		let accin_null = self.accin.nullifier();
		let tx_hash = derive_withdraw_tx_hash(
			accin_null,
			accout.commitment(),
			slot_asset_ids,
			slot_withdrawal_amts,
			self.w_acc_addr,
		);

		match &self.approval_sig {
			Some(sig) => priv_t
				.approval_sig
				.set(&mut pw, self.approval_key, tx_hash, sig),
			None => priv_t.approval_sig.set_dummy(&mut pw, self.approval_key),
		}

		let proof = circuit
			.circuit_data
			.prove(pw)
			.expect("withdraw proof generation failed");
		WithdrawProof { proof }
	}
}
