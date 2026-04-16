use plonky2::{
	hash::hash_types::{HashOut, HashOutTarget, RichField},
	iop::{
		target::{BoolTarget, Target},
		witness::{PartialWitness, WitnessWrite},
	},
	plonk::circuit_builder::CircuitBuilder,
};
use plonky2_field::{extension::Extendable, types::Field};
use tessera_utils::{
	F,
	hasher::{HashOutput, ToHashOut},
};

use crate::{
	DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER, DEFAULT_SPEND_AUTH_PK, NOTE_BATCH, STATE_TREE_DEPTH,
	StandardAccount, SubpoolId,
	plonky2_gadgets::{
		merkle::MerkleRootTarget,
		signature::{PubkeyTarget, SchnorrTargets},
		u256::U256Target,
	},
	pool_config::{CompPubKey, SubpoolFullProof},
};

// ----- Account related targets -----

/// In-circuit representation of [`PrivateIdentifier`](crate::account::PrivateIdentifier).
///
/// Never registered as a public input — it stays private in the ZK proof.
#[derive(Clone, Copy)]
pub(crate) struct PrivateIdentifierTarget(pub(crate) [Target; 2]);

/// In-circuit representation of [`PublicIdentifier`](crate::account::PublicIdentifier).
///
/// Derived from `PrivateIdentifierTarget` via `derive_public_identifier`.
#[derive(Clone, Copy)]
pub(crate) struct PublicIdentifierTarget(pub(crate) HashOutTarget);

/// In-circuit representation of [`NullifierKey`](crate::account::NullifierKey).
///
/// Derived from `PrivateIdentifierTarget` via `derive_nullifier_key`.
/// Kept private; used only to derive note and account nullifiers inside the circuit.
#[derive(Clone, Copy)]
pub(crate) struct NullifierKeyTarget(pub(crate) HashOutTarget);

/// In-circuit representation of [`SubpoolId`](crate::account::SubpoolId).
///
/// Registered as a public input so the aggregation layer can sort/route proofs
/// by subpool.
#[derive(Clone, Copy)]
pub(crate) struct SubpoolIdTarget(pub(crate) Target);

/// In-circuit representation of [`ConsumeAuth`](crate::account::ConsumeAuth).
#[derive(Clone, Copy)]
pub(crate) struct ConsumeAuthTarget {
	/// 0 → subpool owner can consume (delegation mode).
	/// 1 → requires signature from `self.pk`.
	pub(crate) config: BoolTarget,
	/// The account's own consume public key (or a placeholder when `config=0`).
	pub(crate) pk: PubkeyTarget,
}

/// In-circuit representation of a [`StandardAccount`](crate::account::StandardAccount).
///
/// All fields are private witnesses. `subpool_id` is a plain target; each circuit
/// registers it as a public input explicitly in its own PI block.
#[derive(Clone, Copy)]
pub(crate) struct AccountTarget {
	pub(crate) private_identifier: PrivateIdentifierTarget,
	pub(crate) nonce: Target,
	pub(crate) subpool_id: SubpoolIdTarget,
	/// Root of the account's Asset State Tree.
	pub(crate) acc_ast_root: HashOutTarget,
	/// Spend authorization public key (GFp5 compressed point, 5 targets).
	pub(crate) spend_auth: PubkeyTarget,
	pub(crate) consume_auth: ConsumeAuthTarget,
}

impl AccountTarget {
	/// Fill all account targets from a concrete [`StandardAccount`].
	///
	/// When a key is absent (`spend_pk = None` or `consume_pk = None`), the
	/// corresponding placeholder constant is used so the commitment hash is
	/// consistent with the native [`StandardAccount::commitment`].
	// TODO: make the function generic over Field
	pub(crate) fn set_witness(&self, pw: &mut PartialWitness<F>, acc: &StandardAccount) {
		pw.set_target(self.private_identifier.0[0], acc.private_identifier.0[0])
			.unwrap();
		pw.set_target(self.private_identifier.0[1], acc.private_identifier.0[1])
			.unwrap();
		pw.set_target(self.nonce, acc.nonce.0).unwrap();
		pw.set_target(self.subpool_id.0, acc.subpool_id.0).unwrap();
		for (i, &x) in acc.ast.root().0.iter().enumerate() {
			pw.set_target(self.acc_ast_root.elements[i], x).unwrap();
		}
		let spend_cpk: [F; 5] = acc.spend_auth.spend_pk.map_or_else(
			|| DEFAULT_SPEND_AUTH_PK.map(F::from_canonical_u64),
			|pk| pk.0.w.0,
		);
		for (t, v) in self.spend_auth.0.0.iter().zip(spend_cpk.iter()) {
			pw.set_target(*t, *v).unwrap();
		}
		pw.set_bool_target(self.consume_auth.config, acc.consume_auth.config)
			.unwrap();
		let consume_cpk: [F; 5] = acc.consume_auth.pk.map_or_else(
			|| DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER.map(F::from_canonical_u64),
			|pk| pk.0.w.0,
		);
		for (t, v) in self.consume_auth.pk.0.0.iter().zip(consume_cpk.iter()) {
			pw.set_target(*t, *v).unwrap();
		}
	}
}

/// In-circuit type for an account commitment (`H(account_fields)`).
///
/// A newtype over `HashOutTarget` so the compiler rejects accidental swaps with
/// `AccountNullifierTarget` or note targets.
#[derive(Clone, Copy)]
pub struct AccountCommitmentTarget(pub HashOutTarget);

/// In-circuit type for an account nullifier (`H(commitment || nk)`).
#[derive(Clone, Copy)]
pub struct AccountNullifierTarget(pub HashOutTarget);

/// Opaque hash target used as a padding account in dummy proofs.
#[derive(Clone, Copy)]
pub(crate) struct DummyAccountTarget(pub(crate) HashOutTarget);

/// Commitment derived from a [`DummyAccountTarget`] via double-hash.
#[derive(Clone, Copy)]
pub(crate) struct DummyAccountCommitment(pub(crate) HashOutTarget);

/// Nullifier derived from a [`DummyAccountTarget`] via double-hash.
#[derive(Clone, Copy)]
pub(crate) struct DummyAccountNullifier(pub(crate) HashOutTarget);

// ---- Note related targets ----

/// In-circuit representation of a [`StandardNote`](crate::note::StandardNote).
///
/// `spend_cond` encodes the recipient (who can spend),
/// `reject_cond` encodes the sender (who can reclaim via reject).
#[derive(Clone, Copy)]
pub(crate) struct NoteTarget {
	/// Random 2-element note identifier (uniquifies commitments).
	pub(crate) identifier: [Target; 2],
	pub(crate) amount: U256Target,
	pub(crate) asset_id: AssetIdTarget,
	// TODO: change the naming to match of StandardNote
	/// Spend condition: `(subpool_id, public_id)` of the recipient.
	pub(crate) spend_cond: ConsumeCondTarget,
	/// Reject condition: `(subpool_id, public_id)` of the sender.
	pub(crate) reject_cond: RejectCondTarget,
}

impl NoteTarget {
	/// Fill all note targets from a concrete [`StandardNote`].
	pub(crate) fn set_witness(&self, pw: &mut PartialWitness<F>, note: &crate::note::StandardNote) {
		pw.set_target(self.identifier[0], note.identifier.0[0])
			.unwrap();
		pw.set_target(self.identifier[1], note.identifier.0[1])
			.unwrap();
		self.amount.set(pw, note.amt);
		pw.set_target(self.asset_id.0, note.asset_id.0).unwrap();
		pw.set_target(self.spend_cond.subpool_id.0, note.recipient.subpool_id.0)
			.unwrap();
		for (j, &x) in note.recipient.public_id.0.0.iter().enumerate() {
			pw.set_target(self.spend_cond.public_identifier.0.elements[j], x)
				.unwrap();
		}
		pw.set_target(self.reject_cond.subpool_id.0, note.sender.subpool_id.0)
			.unwrap();
		for (j, &x) in note.sender.public_id.0.0.iter().enumerate() {
			pw.set_target(self.reject_cond.public_identifier.0.elements[j], x)
				.unwrap();
		}
	}
}

/// Note spend condition: `(subpool_id, public_identifier)` of the recipient.
///
/// The circuit verifies that the `public_identifier` of the spender (derived
/// from their `private_identifier`) matches this target.
#[derive(Clone, Copy)]
pub(crate) struct ConsumeCondTarget {
	pub(crate) subpool_id: SubpoolIdTarget,
	pub(crate) public_identifier: PublicIdentifierTarget,
}

/// Note reject condition: `(subpool_id, public_identifier)` of the original sender.
///
/// The circuit uses this for reject transactions — the sender reclaims the note.
#[derive(Clone, Copy)]
pub(crate) struct RejectCondTarget {
	pub(crate) subpool_id: SubpoolIdTarget,
	pub(crate) public_identifier: PublicIdentifierTarget,
}

/// In-circuit type for a note commitment (`H(note_fields)`).
#[derive(Clone, Copy)]
pub struct NoteCommitmentTarget(pub HashOutTarget);

/// In-circuit type for a note nullifier (`H(commitment || pos || nk)`).
#[derive(Clone, Copy)]
pub struct NoteNullifierTarget(pub HashOutTarget);

/// Opaque hash target used as a padding note in inactive note slots.
///
/// Dummy note nullifiers and commitments are derived via double-hash from this
/// value, ensuring they are deterministic but unlinkable.
#[derive(Clone, Copy)]
pub(crate) struct DummyNoteTarget(pub(crate) HashOutTarget);

// ---- Other tx related targets ----

/// The transaction hash signed by spend / consume / approval keys.
///
/// For private tx: `H(accin_null || accout_comm || NN[NOTE_BATCH] || NC[NOTE_BATCH])`.
#[derive(Clone, Copy)]
pub(crate) struct TxHashTarget(pub(crate) HashOutTarget);

/// The three Schnorr signature targets required for a private transaction.
///
/// - `spend`: signed by the account's spend key (required for spend-kind tx).
/// - `consume`: signed by own (required if consume.auth=1 and tx has >=1 input notes but 0 output
///   notes).
/// - `approval`: signed by the subpool approval key (always required).
#[derive(Clone)]
pub(crate) struct TxSignatureTargets {
	pub(crate) spend: SchnorrTargets,
	pub(crate) consume: SchnorrTargets,
	pub(crate) approval: SchnorrTargets,
}

/// The Note/Account Commitment Tree root (shared ACT + NCT root in V2).
#[derive(Clone, Copy)]
pub struct StateRootTarget(pub HashOutTarget);

/// Root of the main pool configuration tree (depth [`MAIN_POOL_CONFIG_DEPTH`]).
#[derive(Clone, Copy)]
pub struct MainPoolConfigRootTarget(pub HashOutTarget);

/// Root of a single subpool's authority-key tree (depth [`SUBPOOL_CONFIG_DEPTH`]).
#[derive(Clone, Copy)]
pub(crate) struct SubpoolConfigCommitmentTarget(pub(crate) HashOutTarget);

/// In-circuit representation of an [`AssetId`](crate::account::AssetId).
#[derive(Clone, Copy)]
pub struct AssetIdTarget(pub Target);

/// All targets needed to prove subpool authority key membership.
///
/// Each of the three keys (approval, rejection, consume) is proven to be a
/// leaf in the per-subpool depth-2 tree, and that tree's root is proven to be
/// a leaf in the main pool depth-20 tree.
#[derive(Clone)]
pub(crate) struct SubpoolFullProofTargets {
	/// Depth-20 Merkle proof that the subpool config root is in the main pool tree.
	pub(crate) main_pool_proof: MerkleRootTarget,
}

impl SubpoolFullProofTargets {
	pub fn set_witness(
		&self,
		pw: &mut PartialWitness<F>,
		subpool_proof: &SubpoolFullProof<HashOutput>,
	) {
		self.main_pool_proof
			.set_witness(pw, &subpool_proof.main_pool_proof);
	}

	pub fn set_fake(&self, pw: &mut PartialWitness<F>) {
		self.main_pool_proof.set_dummy_witness(pw);
	}
}

/// All targets allocated by
/// [`priv_tx_circuit`](crate::plonky2_gadgets::priv_tx::circuit::priv_tx_circuit).
///
/// Also exported as [`PrivTxTargets`](crate::PrivTxTargets) for use by external callers.
///
/// # Public-input layout (76 elements for NOTE_BATCH=7)
/// ```text
/// [0]     subpool_id_in
/// [1]     subpool_id_out
/// [2]     not_fake_tx
/// [3-6]   root (4 elements)
/// [7-10]  mainpool_config_root (4 elements)
/// [11-14] accin_null  (AN, 4 elements)
/// [15-18] accout_comm (AC, 4 elements)
/// [19-46] effective inote nullifiers (7×4)
/// [47-74] effective onote commitments (7×4, donote_comm when slot inactive)
/// [75]    asset_id
/// ```
pub struct TxCircuitTargets {
	pub(crate) public: TxCircuitPublicTargets,
	pub(crate) private: TxCircuitPrivateTargets,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TxKindFlags {
	pub(crate) is_rjct: bool,
	pub(crate) is_fresh_acc: bool,
	pub(crate) is_update_auth: bool,
	pub(crate) is_priv_tx: bool,
	pub(crate) not_fake_tx: bool,
}

impl TxKindFlags {
	/// Flags for a Fake (dummy) transaction.
	pub(crate) const FAKE: Self = Self {
		is_rjct: false,
		is_fresh_acc: false,
		is_update_auth: false,
		is_priv_tx: false,
		not_fake_tx: false,
	};
	/// Flags for a FreshAcc real transaction.
	pub(crate) const FRESH_ACC: Self = Self {
		is_rjct: false,
		is_fresh_acc: true,
		is_update_auth: false,
		is_priv_tx: false,
		not_fake_tx: true,
	};
	/// Flags for a Reject real transaction.
	pub(crate) const REJECT: Self = Self {
		is_rjct: true,
		is_fresh_acc: false,
		is_update_auth: false,
		is_priv_tx: false,
		not_fake_tx: true,
	};
	/// Flags for a Spend (private) real transaction.
	pub(crate) const SPEND: Self = Self {
		is_rjct: false,
		is_fresh_acc: false,
		is_update_auth: false,
		is_priv_tx: true,
		not_fake_tx: true,
	};
}

impl TxCircuitTargets {
	pub(crate) fn set_tx_kind_flags(&self, pw: &mut PartialWitness<F>, flags: TxKindFlags) {
		pw.set_bool_target(self.private.is_rjct, flags.is_rjct)
			.unwrap();
		pw.set_bool_target(self.private.is_fresh_acc, flags.is_fresh_acc)
			.unwrap();
		pw.set_bool_target(self.private.is_update_auth, flags.is_update_auth)
			.unwrap();
		pw.set_bool_target(self.private.is_priv_tx, flags.is_priv_tx)
			.unwrap();
		pw.set_bool_target(self.public.not_fake_tx, flags.not_fake_tx)
			.unwrap();
	}

	pub(crate) fn set_common_witnesses(
		&self,
		pw: &mut PartialWitness<F>,
		mainpool_config_root: HashOutput,
		state_root: HashOutput,
		approval_key: CompPubKey,
		subpool_proof: &crate::pool_config::SubpoolFullProof<HashOutput>,
		accin: &StandardAccount,
		accout: &StandardAccount,
	) {
		pw.set_hash_target(self.public.state_root.0, state_root.to_hash_out())
			.unwrap();
		pw.set_hash_target(
			self.public.mainpool_config_root.0,
			mainpool_config_root.to_hash_out(),
		)
		.unwrap();

		self.private.approval_key.set_witness(pw, approval_key);
		self.private
			.subpool_proof_targets
			.set_witness(pw, &subpool_proof);
		self.private.accin.set_witness(pw, accin);
		self.private.accout.set_witness(pw, accout);
	}

	/// Set witness for a spend signature.
	pub(crate) fn set_spend_sig_witness(
		&self,
		pw: &mut PartialWitness<F>,
		sig: &crate::schnorr::Signature,
	) {
		self.private.spend_sig.set_witness(pw, sig);
	}

	/// Set witness for a fake/dummy spend signature.
	pub(crate) fn set_fake_spend_sig_witness(&self, pw: &mut PartialWitness<F>) {
		self.private.spend_sig.set_fake_witness(pw);
	}

	/// Set witness for a consume signature.
	pub(crate) fn set_consume_sig_witness(
		&self,
		pw: &mut PartialWitness<F>,
		sig: &crate::schnorr::Signature,
	) {
		self.private.consume_sig.set_witness(pw, sig);
	}

	/// Set witness for a fake/dummy consume signature.
	pub(crate) fn set_fake_consume_sig_witness(&self, pw: &mut PartialWitness<F>) {
		self.private.consume_sig.set_fake_witness(pw);
	}

	/// Set witness for an approval signature.
	pub(crate) fn set_approval_sig_witness(
		&self,
		pw: &mut PartialWitness<F>,
		sig: &crate::schnorr::Signature,
	) {
		self.private.approval_sig.set_witness(pw, sig);
	}

	/// Set witness for an input note at the given index.
	pub(crate) fn set_input_note_witness(
		&self,
		pw: &mut PartialWitness<F>,
		index: usize,
		note: &crate::StandardNote,
		proof: &tessera_trees::MerkleProof<HashOutput>,
	) {
		self.private.inotes[index].set_witness(pw, note);
		self.private.inotes_nct_merkle[index].set_witness(pw, proof);
	}

	/// Set witness for a dummy input note at the given index.
	pub(crate) fn set_dummy_input_note_witness(
		&self,
		pw: &mut PartialWitness<F>,
		index: usize,
		seed: [F; 4],
	) {
		use plonky2::iop::witness::WitnessWrite;
		// Set the dummy note seed
		for (i, &val) in seed.iter().enumerate() {
			pw.set_target(self.private.dinotes[index][i], val).unwrap();
		}
	}

	/// Set witness for an output note at the given index.
	pub(crate) fn set_output_note_witness(
		&self,
		pw: &mut PartialWitness<F>,
		index: usize,
		note: &crate::StandardNote,
	) {
		self.private.onotes[index].set_witness(pw, note);
	}

	/// Set witness for a dummy output note at the given index.
	pub(crate) fn set_dummy_output_note_witness(
		&self,
		pw: &mut PartialWitness<F>,
		index: usize,
		seed: [F; 4],
	) {
		use plonky2::iop::witness::WitnessWrite;
		// Set the dummy note seed
		for (i, &val) in seed.iter().enumerate() {
			pw.set_target(self.private.donotes[index][i], val).unwrap();
		}
	}
}

pub struct TxCircuitPublicTargets {
	/// [0..4]: Combined ACT / NCT Merkle root.
	pub state_root: StateRootTarget,
	/// [4..8]: Main pool configuration tree root.
	pub mainpool_config_root: MainPoolConfigRootTarget,
	/// [8]: 1 for a real transaction, 0 for a dummy/padding proof.
	pub not_fake_tx: BoolTarget,
	/// [9..13]: Account nullifier (public input; constrained == derived when `not_fake_tx=1`).
	pub accin_null: AccountNullifierTarget,
	/// [13..17]: Account output commitment (public input; constrained == derived when `not_fake_tx=1`).
	pub accout_comm: AccountCommitmentTarget,
	/// [17..45]: Input notes nullifiers
	pub inotes_null: [NoteNullifierTarget; NOTE_BATCH],
	/// [45..73]: Output notes commitments
	pub onotes_comm: [NoteCommitmentTarget; NOTE_BATCH],
}

impl TxCircuitPublicTargets {
	pub(crate) fn register<F, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>)
	where
		F: RichField + Extendable<D>,
	{
		builder.register_public_inputs(&self.state_root.0.elements);
		builder.register_public_inputs(&self.mainpool_config_root.0.elements);
		builder.register_public_input(self.not_fake_tx.target);
		builder.register_public_inputs(&self.accin_null.0.elements);
		builder.register_public_inputs(&self.accout_comm.0.elements);
		builder.register_public_inputs(
			&self
				.inotes_null
				.iter()
				.flat_map(|c| c.0.elements)
				.collect::<Vec<_>>(),
		);

		builder.register_public_inputs(
			&self
				.onotes_comm
				.iter()
				.flat_map(|c| c.0.elements)
				.collect::<Vec<_>>(),
		);
	}

	/// Construct from a flat PI slice. Reads fields in the same order as `register()`.
	/// No named offset constants — sequential split_at cursor only.
	pub fn from_pis(pis: &[Target]) -> Self {
		let (root_s, rest) = pis.split_at(4);
		let (main_s, rest) = rest.split_at(4);
		let (nft_s, rest) = rest.split_at(1);
		let (ain_s, rest) = rest.split_at(4);
		let (aout_s, rest) = rest.split_at(4);
		let (inull_s, rest) = rest.split_at(NOTE_BATCH * 4);
		let (ocomm_s, _) = rest.split_at(NOTE_BATCH * 4);
		Self {
			state_root: StateRootTarget(HashOutTarget {
				elements: root_s.try_into().unwrap(),
			}),
			mainpool_config_root: MainPoolConfigRootTarget(HashOutTarget {
				elements: main_s.try_into().unwrap(),
			}),
			not_fake_tx: BoolTarget::new_unsafe(nft_s[0]),
			accin_null: AccountNullifierTarget(HashOutTarget {
				elements: ain_s.try_into().unwrap(),
			}),
			accout_comm: AccountCommitmentTarget(HashOutTarget {
				elements: aout_s.try_into().unwrap(),
			}),
			inotes_null: core::array::from_fn(|j| {
				NoteNullifierTarget(HashOutTarget {
					elements: inull_s[j * 4..j * 4 + 4].try_into().unwrap(),
				})
			}),
			onotes_comm: core::array::from_fn(|j| {
				NoteCommitmentTarget(HashOutTarget {
					elements: ocomm_s[j * 4..j * 4 + 4].try_into().unwrap(),
				})
			}),
		}
	}

	/// SR leaf order: [AC, NC0..NC6] — uses only named fields.
	pub fn output_commitments(&self) -> [[Target; 4]; 1 + NOTE_BATCH] {
		core::array::from_fn(|j| {
			if j == 0 {
				self.accout_comm.0.elements
			} else {
				self.onotes_comm[j - 1].0.elements
			}
		})
	}

	/// Unique PI targets (not_fake_tx onwards) for Keccak preimage.
	/// Matches PIHelper::batch_unique_pis() order. Uses only named fields.
	pub fn unique_pi_targets(&self) -> Vec<Target> {
		let mut out = vec![self.not_fake_tx.target];
		out.extend(self.accin_null.0.elements);
		out.extend(self.accout_comm.0.elements);
		for nn in &self.inotes_null {
			out.extend(nn.0.elements);
		}
		for nc in &self.onotes_comm {
			out.extend(nc.0.elements);
		}
		out
	}
}

pub struct TxCircuitPrivateTargets {
	// ── Tx kind flags ─────────────────────────────────────────────────────────
	/// Reject transaction: operator reclaims notes on behalf of the sender.
	pub(crate) is_rjct: BoolTarget,
	/// FreshAcc transaction: account creation, sets initial auth keys.
	pub(crate) is_fresh_acc: BoolTarget,
	/// UpdateAuth transaction: rotates spend or consume keys.
	pub(crate) is_update_auth: BoolTarget,
	/// Spend/transfer transaction: moves asset balance via notes.
	pub(crate) is_priv_tx: BoolTarget,
	// ── Tree roots ─────────────────────────────────────────────────────────────

	// ── Authority public keys ──────────────────────────────────────────────────
	pub(crate) approval_key: PubkeyTarget,
	// ── Accounts ──────────────────────────────────────────────────────────────
	pub(crate) accin: AccountTarget,
	pub(crate) accout: AccountTarget,
	/// AccIn balance for `asset_id` before the transaction.
	pub(crate) accin_amt: U256Target,
	/// AccOut balance for `asset_id` after the transaction.
	pub(crate) accout_amt: U256Target,

	pub(crate) asset_exists_in_accin: BoolTarget,
	pub(crate) asset_exists_in_accout: BoolTarget,
	// ── Merkle targets ────────────────────────────────────────────────────────
	/// ACT membership proof for AccIn (conditional on `!is_fresh_acc && not_fake_tx`).
	pub(crate) accin_act_merkle: MerkleRootTarget,
	/// AST leaf update proof (accin → accout for `asset_id`).
	pub(crate) accin_ast_merkle: MerkleRootTarget,
	/// NCT membership proofs for each active input note.
	pub(crate) inotes_nct_merkle: [MerkleRootTarget; NOTE_BATCH],

	// ── Notes ────────────────────────────────────────────────────────────────
	/// Input notes (NOTE_BATCH slots; inactive slots are zero-padded).
	pub(crate) inotes: [NoteTarget; NOTE_BATCH],
	/// NCT leaf positions of the input notes.
	pub(crate) inotes_pos: [Target; NOTE_BATCH],
	/// Whether each input note slot is active (being spent).
	pub(crate) inotes_isactive: [BoolTarget; NOTE_BATCH],
	/// Output notes (NOTE_BATCH slots; inactive slots are zero-padded).
	pub(crate) onotes: [NoteTarget; NOTE_BATCH],
	/// Whether each output note slot is active (being created).
	pub(crate) onotes_isactive: [BoolTarget; NOTE_BATCH],
	/// Dummy input note hashes (used for nullifiers in inactive inote slots).
	pub(crate) dinotes: [DummyNoteTarget; NOTE_BATCH],
	/// Dummy output note hashes (used for commitments in inactive onote slots).
	pub(crate) donotes: [DummyNoteTarget; NOTE_BATCH],
	/// Authority key membership proofs.
	pub(crate) subpool_proof_targets: SubpoolFullProofTargets,
	pub(crate) sig_targets: TxSignatureTargets,
	/// Input account subpool ID
	pub(crate) accin_subpool_id: SubpoolIdTarget,
	/// Output account subpool ID
	pub(crate) accout_subpool_id: SubpoolIdTarget,
	/// Asset ID
	pub(crate) asset_id: AssetIdTarget,
}
