use plonky2::{
	hash::{
		hash_types::{HashOutTarget, RichField},
		poseidon::PoseidonHash,
	},
	iop::target::Target,
	plonk::circuit_builder::CircuitBuilder,
};
use plonky2_field::extension::Extendable;

use crate::plonky2_gadgets::{
	deposit_tx::targets::{DepositNoteCommitmentTarget, DepositNoteTarget},
	priv_tx::targets::{AccountCommitmentTarget, AccountNullifierTarget},
};

/// Circuit-builder extension for deposit-transaction-specific hash derivations.
///
/// Implemented for [`CircuitBuilder`] so that deposit-tx logic can be expressed
/// as method calls on the builder, keeping the main circuit function readable.
pub(crate) trait DepositTxCircuitBuilder {
	/// Derive the deposit note commitment in-circuit.
	///
	/// Mirrors [`crate::DepositNote::commitment`] natively.
	///
	/// Hash input (16 targets):
	/// ```text
	/// identifier[2] recipient_subpool_id[1] || recipient_public_id[4]
	/// || amount[8 u32 targets] || asset_id[1]
	/// ```
	fn derive_deposit_note_comm(
		&mut self,
		deposit_note: DepositNoteTarget,
	) -> DepositNoteCommitmentTarget;

	/// Derive the deposit transaction hash in-circuit.
	///
	/// Mirrors [`derive_deposit_tx_hash`](crate::derive_deposit_tx_hash) natively.
	///
	/// Hash input (17 targets):
	/// ```text
	/// accin_null[4] || accout_comm[4] || deposit_note_comm[4] || eth_address[5]
	/// ```
	fn derive_deposit_tx_hash(
		&mut self,
		accin_null: AccountNullifierTarget,
		accout_comm: AccountCommitmentTarget,
		deposit_note_comm: DepositNoteCommitmentTarget,
		eth_address: [Target; 5],
	) -> HashOutTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> DepositTxCircuitBuilder
	for CircuitBuilder<F, D>
{
	fn derive_deposit_note_comm(
		&mut self,
		deposit_note: DepositNoteTarget,
	) -> DepositNoteCommitmentTarget {
		// H(identifier[2] || recipient_subpool_id[1] || recipient_public_id[4]
		//   || amount[8] || asset_id[1])  → 16 elements
		let mut inp: Vec<Target> = Vec::with_capacity(16);
		inp.extend_from_slice(&deposit_note.identifier);
		inp.push(deposit_note.recipient_subpool_id.0);
		inp.extend_from_slice(&deposit_note.recipient_public_id.0.elements);
		for u32t in deposit_note.amount.0.iter() {
			inp.push(u32t.0);
		}
		inp.push(deposit_note.asset_id.0);
		debug_assert_eq!(inp.len(), 16);
		DepositNoteCommitmentTarget(self.hash_n_to_hash_no_pad::<PoseidonHash>(inp))
	}

	fn derive_deposit_tx_hash(
		&mut self,
		accin_null: AccountNullifierTarget,
		accout_comm: AccountCommitmentTarget,
		deposit_note_comm: DepositNoteCommitmentTarget,
		eth_address: [Target; 5],
	) -> HashOutTarget {
		// H(accin_null[4] || accout_comm[4] || deposit_note_comm[4] ||
		// eth_address[5]) = 17 elements
		let mut inp: Vec<Target> = Vec::with_capacity(17);
		inp.extend_from_slice(&accin_null.0.elements);
		inp.extend_from_slice(&accout_comm.0.elements);
		inp.extend_from_slice(&deposit_note_comm.0.elements);
		inp.extend_from_slice(&eth_address);
		debug_assert_eq!(inp.len(), 17);
		self.hash_n_to_hash_no_pad::<PoseidonHash>(inp)
	}
}
