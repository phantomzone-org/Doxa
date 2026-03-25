//! Client-side state management for E2E tests.
//!
//! [`TesseraClientState`] tracks an account and a local flat `CommitmentTree`
//! in sync with the chain.  It provides helpers that build circuit inputs,
//! generate real Plonky2 proofs, and return the leaf bytes the sequencer
//! needs for `submit_private_tx`.

use std::array;

use plonky2::field::types::{Field, PrimeField64};
use primitive_types::H160;
use rand::{Rng, RngExt};
pub use tessera_client::PrivTxTargets;
use tessera_client::{
	build_priv_tx_circuit, derive_deposit_tx_hash, derive_priv_tx_hash, double_hash_native,
	pool_config::{CompPubKey, MainPoolConfigTree, SubpoolConfigTree},
	prove_real_priv_tx, sample_dummy_notes,
	schnorr::{schnorr_sign, PrivateKey, Scalar},
	AccountAddress, AssetId, ConsumeAuth, DepositNote, DepositTxCircuit, FreshAccInputs, Nonce,
	NoteCommitment, NoteNullifier, PrivTxInputs, PrivateIdentifier, SpendAuth, SpendTxInputs,
	StandardAccount, SubpoolId, COM_TREE_DEPTH, NOTE_BATCH,
};
use tessera_trees::MerkleTree;
use tessera_utils::{hasher::HashOutput, CircuitDataNative, D, F};

/// Client-side state mirroring what is committed on-chain.
///
/// The local `CommitmentTree` is a flat append-only tree of depth 32 that
/// accumulates every account commitment and note commitment inserted during
/// the session.  Merkle paths are generated from this tree for `SpendTx`.
///
/// **Important**: insert ALL leaves before calling `prove_spend`, because
/// each insertion changes the root (Plonky2 "partition set twice" rule).
pub struct TesseraClientState {
	/// The shared Plonky2 PrivTx circuit (build once, reuse).
	pub circuit: CircuitDataNative,
	/// Shared circuit targets.
	pub targets: tessera_client::PrivTxTargets<D>,
	/// Current account (None until first FreshAcc is proven).
	pub account: Option<StandardAccount>,
	/// Position of the current account commitment in `local_tree`.
	pub account_pos: Option<u64>,
	/// Local flat commitment tree (accounts + notes interleaved).
	pub local_tree: MerkleTree<HashOutput>,
	/// Subpool ID this client operates in.
	pub subpool_id: SubpoolId,
	/// Subpool keys.
	pub approval_sk: PrivateKey,
	pub rejection_sk: PrivateKey,
	pub consume_sk: PrivateKey,
	/// Pool config tree.
	pub pool_config: MainPoolConfigTree<HashOutput>,
}

impl TesseraClientState {
	/// Create a new client state with a single subpool at `subpool_idx` (0-based).
	pub fn new<R: Rng + rand::CryptoRng>(rng: &mut R, subpool_idx: usize) -> Self {
		let (circuit, targets) = build_priv_tx_circuit();

		let approval_sk = PrivateKey::from_raw(Scalar::sample(rng).0);
		let rejection_sk = PrivateKey::from_raw(Scalar::sample(rng).0);
		let consume_sk = PrivateKey::from_raw(Scalar::sample(rng).0);

		let approval_pk: CompPubKey = approval_sk.public_key::<F>().into();
		let rejection_pk: CompPubKey = rejection_sk.public_key::<F>().into();
		let consume_pk: CompPubKey = consume_sk.public_key::<F>().into();

		let subpool_config =
			SubpoolConfigTree::<HashOutput>::new(approval_pk, rejection_pk, consume_pk);
		let subpool_id = SubpoolId(F::from_canonical_u64(subpool_idx as u64));

		let mut pool_config = MainPoolConfigTree::<HashOutput>::new();
		pool_config
			.insert_subpool(subpool_id, subpool_config.root())
			.expect("insert_subpool");

		Self {
			circuit,
			targets,
			account: None,
			account_pos: None,
			local_tree: MerkleTree::new(COM_TREE_DEPTH),
			subpool_id,
			approval_sk,
			rejection_sk,
			consume_sk,
			pool_config,
		}
	}

	/// Prove a `FreshAcc` transaction for a brand-new account.
	///
	/// Returns the proof and PI leaf bytes.  Call
	/// [`insert_account_commitment`] before any subsequent `prove_spend`.
	pub fn prove_freshacc<R: Rng + rand::CryptoRng>(
		&mut self,
		rng: &mut R,
	) -> anyhow::Result<ProvenTx> {
		// Sample a fresh account (nonce=0, no keys, empty AST).
		let priv_id = PrivateIdentifier([
			F::from_canonical_u64(rng.random::<u64>() >> 1),
			F::from_canonical_u64(rng.random::<u64>() >> 1),
		]);
		let accin = StandardAccount::new_with(priv_id, self.subpool_id);

		// Derive output account: nonce+1, new spend key.
		let new_spend_sk = PrivateKey::from_raw(Scalar::sample(rng).0);
		let new_spend_pk: CompPubKey = new_spend_sk.public_key::<F>().into();
		let new_spend_auth = SpendAuth {
			spend_pk: Some(new_spend_pk),
		};
		let new_consume_auth = ConsumeAuth {
			config: false,
			pk: None,
		};

		let mut accout = accin.clone();
		accout.nonce = Nonce(accout.nonce.0 + F::ONE);
		accout.spend_auth = new_spend_auth.clone();
		accout.consume_auth = new_consume_auth.clone();

		// Sample dummy notes.
		let (dinotes, donotes) = sample_dummy_notes(rng);
		let dinote_nulls: [_; NOTE_BATCH] =
			array::from_fn(|i| NoteNullifier(double_hash_native(dinotes[i]).into()));
		let donote_comms: [_; NOTE_BATCH] =
			array::from_fn(|i| NoteCommitment(double_hash_native(donotes[i]).into()));

		// Compute tx_hash and sign.
		let tx_hash = derive_priv_tx_hash(
			accin.nullifier(),
			accout.commitment(),
			dinote_nulls,
			donote_comms,
		);
		let k = Scalar::from_raw([1u64; 5]);
		let approval_sig = schnorr_sign(&self.approval_sk, &tx_hash.0, k);

		let approval_pk: CompPubKey = self.approval_sk.public_key::<F>().into();
		let rejection_pk: CompPubKey = self.rejection_sk.public_key::<F>().into();
		let consume_pk: CompPubKey = self.consume_sk.public_key::<F>().into();

		// Genesis root is always confirmed.
		let genesis_root = HashOutput::new([F::ZERO; 4]);

		let inputs = PrivTxInputs::FreshAcc(FreshAccInputs {
			accin,
			new_spend_auth,
			new_consume_auth,
			root: genesis_root,
			approval_key: approval_pk,
			rejection_key: rejection_pk,
			consume_key: consume_pk,
			subpool_id: self.subpool_id,
			main_pool: self.pool_config.clone(),
			approval_sig,
			dinotes,
			donotes,
		});

		let proof = prove_real_priv_tx(&self.circuit, &self.targets, inputs);

		self.account = Some(accout);

		Ok(extract_proven_tx(proof))
	}

	/// Insert the current account commitment into the local tree.
	///
	/// Must be called after `prove_freshacc` and before `prove_spend`.
	/// Returns the leaf position.
	pub fn insert_account_commitment(&mut self) -> anyhow::Result<u64> {
		let acc = self
			.account
			.as_ref()
			.ok_or_else(|| anyhow::anyhow!("no account — call prove_freshacc first"))?;
		let commitment_hash: HashOutput = acc.commitment().0;
		let pos = self
			.local_tree
			.insert(commitment_hash)
			.map_err(|e| anyhow::anyhow!("ACT insert: {e:?}"))?;
		self.account_pos = Some(pos as u64);
		Ok(pos as u64)
	}

	/// Insert output note commitments (from a previous TX's `nc` array) into
	/// the local tree.  Returns each leaf's position.
	pub fn insert_note_commitments(
		&mut self,
		nc: &[[u8; 32]; NOTE_BATCH],
	) -> anyhow::Result<Vec<u64>> {
		let mut positions = Vec::with_capacity(NOTE_BATCH);
		for nc_bytes in nc {
			let hash = bytes32_to_hash_output(*nc_bytes);
			let pos = self
				.local_tree
				.insert(hash)
				.map_err(|e| anyhow::anyhow!("NCT insert: {e:?}"))?;
			positions.push(pos as u64);
		}
		Ok(positions)
	}

	/// Prove a `SpendTx` with no active notes (nonce-bump only).
	///
	/// This is the simplest valid Spend TX — no real input/output notes,
	/// all slots filled with dummy values.  Use for E2E pipeline validation
	/// without requiring prior note deposits.
	pub fn prove_spend_dummy<R: Rng + rand::CryptoRng>(
		&mut self,
		rng: &mut R,
	) -> anyhow::Result<ProvenTx> {
		let accin = self
			.account
			.clone()
			.ok_or_else(|| anyhow::anyhow!("no account — call prove_freshacc first"))?;
		let acc_pos = self.account_pos.ok_or_else(|| {
			anyhow::anyhow!("no account position — call insert_account_commitment first")
		})?;

		let root = self.local_tree.root();

		// Merkle proof for the account commitment in the local ACT.
		let accin_merkle_proof = self
			.local_tree
			.merkle_proof(acc_pos as usize)
			.map_err(|e| anyhow::anyhow!("ACT merkle_proof: {e:?}"))?;

		// Derive output account: nonce+1.
		let mut accout = accin.clone();
		accout.nonce = Nonce(accout.nonce.0 + F::ONE);

		// Dummy notes for all inactive slots.
		let (dinotes, donotes) = sample_dummy_notes(rng);
		let dinote_nulls: [_; NOTE_BATCH] =
			array::from_fn(|i| NoteNullifier(double_hash_native(dinotes[i]).into()));
		let donote_comms: [_; NOTE_BATCH] =
			array::from_fn(|i| NoteCommitment(double_hash_native(donotes[i]).into()));

		let tx_hash = derive_priv_tx_hash(
			accin.nullifier(),
			accout.commitment(),
			dinote_nulls,
			donote_comms,
		);
		let k = Scalar::from_raw([1u64; 5]);
		let approval_sig = schnorr_sign(&self.approval_sk, &tx_hash.0, k);

		let approval_pk: CompPubKey = self.approval_sk.public_key::<F>().into();
		let rejection_pk: CompPubKey = self.rejection_sk.public_key::<F>().into();
		let consume_pk: CompPubKey = self.consume_sk.public_key::<F>().into();

		let inputs = PrivTxInputs::Spend(SpendTxInputs {
			accin,
			root,
			accin_merkle_proof,
			inotes: vec![],
			inotes_nct_proofs: vec![],
			onotes: vec![],
			dinotes,
			donotes,
			approval_key: approval_pk,
			rejection_key: rejection_pk,
			consume_key: consume_pk,
			subpool_id: self.subpool_id,
			main_pool: self.pool_config.clone(),
			spend_sig: None,
			consume_sig: None,
			approval_sig,
		});

		let proof = prove_real_priv_tx(&self.circuit, &self.targets, inputs);

		self.account = Some(accout);

		Ok(extract_proven_tx(proof))
	}

	/// Prove a real deposit transaction and return the serialized proof + note commitment.
	///
	/// The caller must have already activated the account via [`prove_freshacc`] +
	/// [`insert_account_commitment`] so that a valid ACT Merkle proof exists.
	///
	/// Returns `(proof_bytes, note_commitment)` where `note_commitment` is the
	/// 32-byte BE encoding of `DepositNote::commitment()` — this is the value
	/// that must be passed to `depositAndRegister` on-chain and `submit_deposit`.
	#[allow(clippy::too_many_arguments)]
	pub fn prove_deposit<R: Rng + rand::CryptoRng>(
		&mut self,
		rng: &mut R,
		deposit_circuit: &DepositTxCircuit,
		eth_address: &H160,
		amount: primitive_types::U256,
		asset_id: AssetId,
	) -> anyhow::Result<ProvenDeposit> {
		let accin = self
			.account
			.clone()
			.ok_or_else(|| anyhow::anyhow!("no account — call prove_freshacc first"))?;
		let acc_pos = self.account_pos.ok_or_else(|| {
			anyhow::anyhow!("no account position — call insert_account_commitment first")
		})?;

		let act_root = self.local_tree.root();

		// ACT Merkle proof for accin
		let accin_act_merkle_proof = self
			.local_tree
			.merkle_proof(acc_pos as usize)
			.map_err(|e| anyhow::anyhow!("ACT merkle_proof: {e:?}"))?;

		// Build deposit note targeting this account
		let identifier = [
			F::from_canonical_u64(rng.random::<u64>() >> 1),
			F::from_canonical_u64(rng.random::<u64>() >> 1),
		];
		let deposit_note = DepositNote {
			identifier,
			recipient: AccountAddress::from_acc(&accin),
			amount,
			asset_id,
		};
		let deposit_note_comm = deposit_note.commitment();
		let note_commitment = hash_output_to_bytes32(&deposit_note_comm.0 .0);

		// Derive accout (nonce + 1, AST updated with deposit amount)
		let mut accout = accin.clone_with_incremented_nonce();
		let (_, old_bal) = accin
			.ast
			.amount_for(asset_id)
			.unwrap_or_else(|| (accin.ast.next_index(), primitive_types::U256::zero()));
		accout
			.ast
			.insert_or_update_asset(asset_id, old_bal + amount);

		// Compute tx_hash and sign
		let tx_hash = derive_deposit_tx_hash(
			accin.nullifier(),
			accout.commitment(),
			deposit_note_comm,
			*eth_address,
		);
		let k = Scalar::from_raw([1u64; 5]);

		let approval_pk: CompPubKey = self.approval_sk.public_key::<F>().into();
		let rejection_pk: CompPubKey = self.rejection_sk.public_key::<F>().into();
		let consume_pk: CompPubKey = self.consume_sk.public_key::<F>().into();

		// consume_auth.config=false → subpool consume key signs
		let consume_sig = schnorr_sign(&self.consume_sk, &tx_hash.0, k);
		let approval_sig = schnorr_sign(&self.approval_sk, &tx_hash.0, k);

		let proof = deposit_circuit.prove_real(
			act_root,
			self.pool_config.clone(),
			&accin,
			accin_act_merkle_proof,
			&deposit_note,
			eth_address,
			&approval_pk,
			&rejection_pk,
			&consume_pk,
			self.subpool_id,
			consume_sig,
			approval_sig,
		);

		let proof_bytes = proof.to_bytes();

		// Update client state
		self.account = Some(accout);

		Ok(ProvenDeposit {
			proof_bytes,
			note_commitment,
		})
	}
}

// ---------------------------------------------------------------------------
// Output structs
// ---------------------------------------------------------------------------

/// Result of proving a deposit transaction.
pub struct ProvenDeposit {
	/// Serialized Plonky2 proof bytes to pass as `consume_proof` to `submit_deposit`.
	pub proof_bytes: Vec<u8>,
	/// The deposit note commitment (32-byte BE) — must match the value passed to
	/// `depositAndRegister` on-chain and `submit_deposit`.
	pub note_commitment: [u8; 32],
}

// ---------------------------------------------------------------------------
// Output struct
// ---------------------------------------------------------------------------

/// Proven transaction: proof bytes + PI leaf values for `submit_private_tx`.
pub struct ProvenTx {
	pub proof_bytes: Vec<u8>,
	/// Account nullifier leaf (AN) — 32 bytes, big-endian u64s.
	pub an: [u8; 32],
	/// Account commitment leaf (AC) — 32 bytes, big-endian u64s.
	pub ac: [u8; 32],
	/// Note nullifier leaves — NOTE_BATCH × 32 bytes.
	pub nn: [[u8; 32]; NOTE_BATCH],
	/// Note commitment leaves — NOTE_BATCH × 32 bytes.
	pub nc: [[u8; 32]; NOTE_BATCH],
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn extract_proven_tx(proof: tessera_utils::ProofNative) -> ProvenTx {
	let pi = &proof.public_inputs;
	// PI layout (TX_DATA_OFFSET=5): [5..9]=AN, [9..13]=AC,
	// [13..13+NOTE_BATCH*4]=NN, [13+NOTE_BATCH*4..]=NC
	const AN_OFF: usize = 5;
	const AC_OFF: usize = 9;
	const NN_OFF: usize = 13;
	const NC_OFF: usize = 13 + NOTE_BATCH * 4; // = 41 when NOTE_BATCH=7
	let an = hash_output_to_bytes32(&pi[AN_OFF..AN_OFF + 4]);
	let ac = hash_output_to_bytes32(&pi[AC_OFF..AC_OFF + 4]);
	let mut nn = [[0u8; 32]; NOTE_BATCH];
	let mut nc = [[0u8; 32]; NOTE_BATCH];
	for i in 0..NOTE_BATCH {
		nn[i] = hash_output_to_bytes32(&pi[NN_OFF + i * 4..NN_OFF + i * 4 + 4]);
		nc[i] = hash_output_to_bytes32(&pi[NC_OFF + i * 4..NC_OFF + i * 4 + 4]);
	}
	let proof_bytes = proof.to_bytes();
	ProvenTx {
		proof_bytes,
		an,
		ac,
		nn,
		nc,
	}
}

/// Pack 4 Goldilocks field elements into a 32-byte big-endian array.
pub fn hash_output_to_bytes32(elems: &[F]) -> [u8; 32] {
	let mut out = [0u8; 32];
	for (i, &fi) in elems.iter().enumerate().take(4) {
		let v = fi.to_canonical_u64();
		out[i * 8..(i + 1) * 8].copy_from_slice(&v.to_be_bytes());
	}
	out
}

/// Decode a 32-byte big-endian array into a `HashOutput`.
pub fn bytes32_to_hash_output(bytes: [u8; 32]) -> HashOutput {
	let arr: [F; 4] = array::from_fn(|i| {
		let mut b = [0u8; 8];
		b.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
		F::from_canonical_u64(u64::from_be_bytes(b))
	});
	HashOutput::new(arr)
}
