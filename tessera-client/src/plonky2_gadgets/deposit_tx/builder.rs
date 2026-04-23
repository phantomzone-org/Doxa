//! Builder for Deposit transactions.

use core::fmt;

use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2_field::types::Field;
use primitive_types::{H160, U256};
use rand::CryptoRng;
use tessera_trees::MerkleTree;
use tessera_utils::{F, hasher::HashOutput};

use super::{DepositProof, circuit::DepositTxCircuit};
use crate::{
	AccountAddress, STATE_TREE_DEPTH, StandardAccount, derive_deposit_tx_hash,
	note::DepositNote,
	plonky2_gadgets::priv_tx::utils::fake_approval_key,
	pool_config::{CompPubKey, SubpoolFullProof},
	schnorr::{CompressedPublicKey, PrivateKey, Scalar, Signature, schnorr_sign},
};

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum DepositTxBuilderError {
	AccountNotInitialized,
	RecipientMismatch,
	AccinNotInStateTree,
	ApprovalSignRequired,
	ConsumeSignRequired,
	TreeError(anyhow::Error),
}

impl fmt::Display for DepositTxBuilderError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::AccountNotInitialized => write!(
				f,
				"Account not initialized (nonce=0). Must perform FreshAcc first"
			),
			Self::RecipientMismatch => {
				write!(f, "Deposit note recipient does not match accin address")
			},
			Self::AccinNotInStateTree => {
				write!(f, "Account commitment not found in state tree")
			},
			Self::ApprovalSignRequired => {
				write!(f, "Must call approval_sign() before into_deposit_tx()")
			},
			Self::ConsumeSignRequired => {
				write!(
					f,
					"Must call consume_sign() before into_deposit_tx() when consume_auth.config is set"
				)
			},
			Self::TreeError(e) => write!(f, "Tree error: {e}"),
		}
	}
}

impl std::error::Error for DepositTxBuilderError {}

// ── Sign errors ───────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum DepositTxSignError {
	ConsumeDelegated,
	ConsumeKeyNotSet,
	KeyMismatch {
		key_type: &'static str,
		expected: CompressedPublicKey<F>,
		provided: CompressedPublicKey<F>,
	},
}

impl fmt::Display for DepositTxSignError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::ConsumeDelegated => {
				write!(
					f,
					"Consume auth is delegated to subpool owner (config=false)"
				)
			},
			Self::ConsumeKeyNotSet => {
				write!(f, "Consume key not set (consume_auth.pk is None)")
			},
			Self::KeyMismatch {
				key_type,
				expected,
				provided,
			} => write!(
				f,
				"{key_type} key mismatch: expected {expected:?}, provided {provided:?}"
			),
		}
	}
}

impl std::error::Error for DepositTxSignError {}

// ── DepositTxBuilder ──────────────────────────────────────────────────────────

/// Builder for constructing real deposit transactions with validation.
pub struct DepositTxBuilder {
	accin: StandardAccount,
	deposit_note: DepositNote,
	eth_address: H160,
}

impl DepositTxBuilder {
	/// Create a new deposit transaction builder.
	///
	/// # Errors
	/// - `AccountNotInitialized`: `accin.nonce == 0` (FreshAcc required first)
	/// - `RecipientMismatch`: `deposit_note.recipient` does not match `accin`'s address
	pub fn new(
		accin: StandardAccount,
		deposit_note: DepositNote,
		eth_address: H160,
	) -> Result<Self, DepositTxBuilderError> {
		if accin.nonce.0 == F::ZERO {
			return Err(DepositTxBuilderError::AccountNotInitialized);
		}
		if deposit_note.recipient != AccountAddress::from_acc(&accin) {
			return Err(DepositTxBuilderError::RecipientMismatch);
		}
		Ok(Self {
			accin,
			deposit_note,
			eth_address,
		})
	}

	/// Compute derived values and produce a [`BuiltRealDepositTx`].
	pub fn build(self) -> BuiltRealDepositTx {
		let asset_id = self.deposit_note.asset_id;
		let deposit_amt = self.deposit_note.amount;

		let accin_amt = self
			.accin
			.ast
			.amount_for(asset_id)
			.map(|(_, amt)| amt)
			.unwrap_or_default();
		let accout_amt = accin_amt + deposit_amt;

		let mut accout = self.accin.clone_with_incremented_nonce();
		accout.ast.insert_or_update_asset(asset_id, accout_amt);

		let accin_null = self.accin.nullifier();
		let deposit_note_comm = self.deposit_note.commitment();
		let tx_hash = derive_deposit_tx_hash(
			accin_null,
			accout.commitment(),
			deposit_note_comm,
			self.eth_address,
		);

		BuiltRealDepositTx {
			accin: self.accin,
			accout,
			deposit_note: self.deposit_note,
			eth_address: self.eth_address,
			tx_hash,
			approval_key: None,
			consume_sig: None,
			approval_sig: None,
		}
	}
}

// ── BuiltRealDepositTx ────────────────────────────────────────────────────────

/// Validated, ready-to-sign real deposit transaction.
///
/// Call [`consume_sign`](Self::consume_sign) and [`approval_sign`](Self::approval_sign)
/// to attach signatures, then [`into_deposit_tx`](Self::into_deposit_tx) to attach
/// state-tree and subpool proofs.
pub struct BuiltRealDepositTx {
	accin: StandardAccount,
	accout: StandardAccount,
	deposit_note: DepositNote,
	eth_address: H160,
	tx_hash: HashOutput,
	/// Set when `approval_sign` is called.
	approval_key: Option<CompPubKey>,
	/// Set when `consume_sign` is called (None if consume is delegated).
	consume_sig: Option<Signature>,
	/// Set when `approval_sign` is called.
	approval_sig: Option<Signature>,
}

impl BuiltRealDepositTx {
	/// Return the transaction hash that needs to be signed.
	pub fn tx_hash(&self) -> &HashOutput {
		&self.tx_hash
	}

	/// Generate and store a consume signature.
	///
	/// Required only when `accin.consume_auth.config == true`; skip for delegated accounts.
	///
	/// # Errors
	/// - `ConsumeDelegated`: `consume_auth.config == false`
	/// - `ConsumeKeyNotSet`: key absent in `consume_auth`
	/// - `KeyMismatch`: provided key does not match `consume_auth.pk`
	pub fn consume_sign<R: CryptoRng + rand::Rng>(
		&mut self,
		consume_sk: &PrivateKey,
		rng: &mut R,
	) -> Result<(), DepositTxSignError> {
		if !self.accin.consume_auth.config {
			return Err(DepositTxSignError::ConsumeDelegated);
		}
		let expected_pk = self
			.accin
			.consume_auth
			.pk
			.ok_or(DepositTxSignError::ConsumeKeyNotSet)?;
		let provided_pk: CompressedPublicKey<F> = consume_sk.public_key().into();
		if expected_pk != provided_pk {
			return Err(DepositTxSignError::KeyMismatch {
				key_type: "consume",
				expected: expected_pk,
				provided: provided_pk,
			});
		}
		let k = Scalar::sample(rng);
		self.consume_sig = Some(schnorr_sign(consume_sk, &self.tx_hash.0, k));
		Ok(())
	}

	/// Generate and store an approval signature from the subpool authority key.
	///
	/// Also records the approval public key for later witness-setting.
	/// Must be called before [`into_deposit_tx`](Self::into_deposit_tx).
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

	/// Attach state-tree and subpool proofs to produce a [`BuiltDepositTx`].
	///
	/// Looks up `accin` in `state_tree` by its commitment.
	/// The main-pool root is read from `subpool_proof.main_pool_proof.root`.
	///
	/// # Errors
	/// - `ApprovalSignRequired`: [`approval_sign`](Self::approval_sign) was not called
	/// - `ConsumeSignRequired`: `consume_auth.config == true` but
	///   [`consume_sign`](Self::consume_sign) was not called
	/// - `AccinNotInStateTree`: commitment not present in `state_tree`
	/// - `TreeError`: Merkle proof generation failed
	pub fn into_deposit_tx(
		self,
		state_tree: &MerkleTree<HashOutput>,
		subpool_proof: SubpoolFullProof<HashOutput>,
	) -> Result<BuiltDepositTx, DepositTxBuilderError> {
		let approval_key = self
			.approval_key
			.ok_or(DepositTxBuilderError::ApprovalSignRequired)?;
		let approval_sig = self
			.approval_sig
			.ok_or(DepositTxBuilderError::ApprovalSignRequired)?;

		if self.accin.consume_auth.config && self.consume_sig.is_none() {
			return Err(DepositTxBuilderError::ConsumeSignRequired);
		}

		let accin_comm = self.accin.commitment().0;
		let pos = state_tree
			.leaves()
			.iter()
			.position(|l| l == &accin_comm)
			.ok_or(DepositTxBuilderError::AccinNotInStateTree)?;

		let accin_act_merkle_proof = state_tree
			.merkle_proof(pos)
			.map_err(|e| DepositTxBuilderError::TreeError(anyhow::anyhow!("{}", e)))?;

		let state_root = state_tree.root();
		let main_pool_root = subpool_proof.main_pool_proof.root;

		Ok(BuiltDepositTx {
			not_fake_tx: true,
			accin: self.accin,
			accout: self.accout,
			deposit_note: self.deposit_note,
			eth_address: self.eth_address,
			tx_hash: self.tx_hash,
			approval_key,
			state_root,
			main_pool_root,
			accin_act_merkle_proof,
			subpool_proof,
			consume_sig: self.consume_sig,
			approval_sig: Some(approval_sig),
		})
	}
}

// ── FakeDepositTxBuilder ──────────────────────────────────────────────────────

/// Builder for constructing fake (dummy) deposit transactions.
///
/// Fake transactions have `not_fake_tx = false` and are used to pad empty
/// aggregation slots. No circuit constraints are enforced beyond the boolean
/// shape of `not_fake_tx`.
pub struct FakeDepositTxBuilder {
	state_root: HashOutput,
	mainpool_config_root: HashOutput,
}

/// Validated fake deposit transaction, ready to be converted to [`BuiltDepositTx`].
pub struct BuiltFakeDepositTx {
	state_root: HashOutput,
	mainpool_config_root: HashOutput,
}

impl FakeDepositTxBuilder {
	/// Create a new fake deposit transaction builder.
	pub fn new(state_root: HashOutput, mainpool_config_root: HashOutput) -> Self {
		Self {
			state_root,
			mainpool_config_root,
		}
	}

	/// Build the fake transaction (infallible — no validation needed).
	pub fn build(self) -> BuiltFakeDepositTx {
		BuiltFakeDepositTx {
			state_root: self.state_root,
			mainpool_config_root: self.mainpool_config_root,
		}
	}
}

impl BuiltFakeDepositTx {
	/// Convert this fake transaction into a unified [`BuiltDepositTx`].
	///
	/// All fields are populated with dummy/zero values. Since `not_fake_tx = false`,
	/// the circuit does not enforce any of these values.
	pub fn into_deposit_tx(self) -> BuiltDepositTx {
		let accin = StandardAccount::fake();
		let accout = accin.clone_with_incremented_nonce();
		let approval_key = fake_approval_key();
		let deposit_note = DepositNote::default_for_recipient(accin.address());

		let dummy_merkle_proof = tessera_trees::MerkleProof {
			leaf: HashOutput([F::ZERO; 4]),
			siblings: vec![HashOutput([F::ZERO; 4]); STATE_TREE_DEPTH],
			path: vec![false; STATE_TREE_DEPTH],
			pos: 0,
			num_leaves: 0,
			root: HashOutput([F::ZERO; 4]),
		};

		BuiltDepositTx {
			not_fake_tx: false,
			accin,
			accout,
			deposit_note,
			eth_address: H160::zero(),
			tx_hash: HashOutput([F::ZERO; 4]),
			approval_key,
			state_root: self.state_root,
			main_pool_root: self.mainpool_config_root,
			accin_act_merkle_proof: dummy_merkle_proof,
			subpool_proof: SubpoolFullProof::default(),
			consume_sig: None,
			approval_sig: None,
		}
	}
}

// ── BuiltDepositTx ────────────────────────────────────────────────────────────

/// Fully-specified deposit transaction ready for proving.
///
/// Produced by [`BuiltRealDepositTx::into_deposit_tx`] (real) or
/// [`BuiltFakeDepositTx::into_deposit_tx`] (fake/padding).
pub struct BuiltDepositTx {
	not_fake_tx: bool,
	accin: StandardAccount,
	accout: StandardAccount,
	deposit_note: DepositNote,
	eth_address: H160,
	tx_hash: HashOutput,
	approval_key: CompPubKey,
	state_root: HashOutput,
	main_pool_root: HashOutput,
	accin_act_merkle_proof: tessera_trees::MerkleProof<HashOutput>,
	subpool_proof: SubpoolFullProof<HashOutput>,
	consume_sig: Option<Signature>,
	/// `Some` for real transactions, `None` for fake (not enforced by circuit).
	approval_sig: Option<Signature>,
}

impl BuiltDepositTx {
	/// Generate a zero-knowledge proof for this deposit transaction.
	pub fn prove(self, circuit: &DepositTxCircuit) -> DepositProof {
		let mut pw = PartialWitness::new();
		let t = &circuit.targets;

		// ── Public inputs ─────────────────────────────────────────────────────
		t.public_targets.set(
			&mut pw,
			self.not_fake_tx,
			self.main_pool_root,
			self.state_root,
			self.accin.nullifier(),
			self.accout.commitment(),
			self.eth_address,
			self.deposit_note.amount,
			self.deposit_note.asset_id,
		);

		// ── AST-derived values ────────────────────────────────────────────────
		let asset_id = self.deposit_note.asset_id;
		let (ast_index, accin_amt, asset_exists_in_accin) = self
			.accin
			.ast
			.amount_for(asset_id)
			.map(|(i, b)| (i, b, true))
			.unwrap_or_else(|| (self.accin.ast.next_index(), U256::zero(), false));
		let accout_amt = accin_amt + self.deposit_note.amount;
		let asset_exists_in_accout = self.accout.ast.amount_for(asset_id).is_some();

		let priv_t = &t.private_targets;

		// ── Private witness ───────────────────────────────────────────────────
		priv_t.deposit_note.set(&mut pw, self.deposit_note);
		priv_t.accin_amt.set(&mut pw, accin_amt);
		priv_t.accout_amt.set(&mut pw, accout_amt);
		pw.set_bool_target(priv_t.asset_exists_in_accin, asset_exists_in_accin)
			.unwrap();
		pw.set_bool_target(priv_t.asset_exists_in_accout, asset_exists_in_accout)
			.unwrap();
		priv_t
			.accin_act_merkle
			.set_witness(&mut pw, &self.accin_act_merkle_proof);
		priv_t
			.accin_ast_merkle
			.set_witness(&mut pw, &self.accin.ast.merkle_proof_at(ast_index));
		priv_t
			.subpool_proof_targets
			.set_witness(&mut pw, &self.subpool_proof);
		priv_t.approval_key.set_witness(&mut pw, self.approval_key);
		priv_t.accin.set_witness(&mut pw, &self.accin);
		priv_t.accout.set_witness(&mut pw, &self.accout);

		// ── Signatures ────────────────────────────────────────────────────────
		let consume_pk = self.accin.consume_pk_or_default();
		match &self.consume_sig {
			Some(sig) => priv_t
				.sig_targets
				.consume
				.set(&mut pw, consume_pk, self.tx_hash, sig),
			None => priv_t.sig_targets.consume.set_dummy(&mut pw, consume_pk),
		}
		match &self.approval_sig {
			Some(sig) => {
				priv_t
					.sig_targets
					.approval
					.set(&mut pw, self.approval_key, self.tx_hash, sig)
			},
			None => priv_t
				.sig_targets
				.approval
				.set_dummy(&mut pw, self.approval_key),
		}

		let proof = circuit
			.circuit_data
			.prove(pw)
			.expect("deposit proof generation failed");
		DepositProof {
			proof,
		}
	}
}
