use plonky2::{
	hash::{hash_types::RichField, poseidon::PoseidonHash},
	iop::target::Target,
	plonk::circuit_builder::CircuitBuilder,
};
use plonky2_field::extension::Extendable;

use crate::{
	NOTE_BATCH,
	plonky2_gadgets::{
		priv_tx::targets::{
			AccountCommitmentTarget, AccountNullifierTarget, AccountTarget, AssetIdTarget,
			TxHashTarget,
		},
		u256::U256Target,
	},
};

pub trait WithdrawTxCircuitBuilder<F: RichField + Extendable<D>, const D: usize> {
	/// Enforce the withdrawal account invariants:
	/// - accin.private_identifier == accout.private_identifier
	/// - accin.subpool_id         == accout.subpool_id
	/// - accout.nonce             == accin.nonce + 1
	/// - accin.spend_auth         == accout.spend_auth
	/// - accin.consume_auth       == accout.consume_auth
	fn assert_account_invariants(&mut self, accin: AccountTarget, accout: AccountTarget);

	/// Derive the withdrawal transaction hash:
	/// H(accin_null[4] || accout_comm[4] || asset_ids[NOTE_BATCH]
	///   || amounts_f[8*NOTE_BATCH] || w_acc_addr[5])
	///
	/// amounts_f flattens each U256Target as 8 u32 targets (little-endian limb order,
	/// matching U256Target's internal layout).
	fn derive_withdraw_tx_hash(
		&mut self,
		accin_null: AccountNullifierTarget,
		accout_comm: AccountCommitmentTarget,
		asset_ids: [AssetIdTarget; NOTE_BATCH],
		amounts: [U256Target; NOTE_BATCH],
		w_acc_addr: [Target; 5],
	) -> TxHashTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> WithdrawTxCircuitBuilder<F, D>
	for CircuitBuilder<F, D>
{
	fn assert_account_invariants(&mut self, accin: AccountTarget, accout: AccountTarget) {
		// private_identifier and subpool_id are immutable
		self.connect_array(accin.private_identifier.0, accout.private_identifier.0);
		self.connect(accin.subpool_id.0, accout.subpool_id.0);

		// Nonce must increment by exactly 1
		let one = self.one();
		let expected_nonce = self.add(accin.nonce, one);
		self.connect(accout.nonce, expected_nonce);

		// spend_auth is immutable
		for i in 0..5 {
			self.connect(accout.spend_auth.0.0[i], accin.spend_auth.0.0[i]);
		}

		// consume_auth (config flag + pk) is immutable
		self.connect(
			accout.consume_auth.config.target,
			accin.consume_auth.config.target,
		);
		for i in 0..5 {
			self.connect(accout.consume_auth.pk.0.0[i], accin.consume_auth.pk.0.0[i]);
		}
	}

	fn derive_withdraw_tx_hash(
		&mut self,
		accin_null: AccountNullifierTarget,
		accout_comm: AccountCommitmentTarget,
		asset_ids: [AssetIdTarget; NOTE_BATCH],
		amounts: [U256Target; NOTE_BATCH],
		w_acc_addr: [Target; 5],
	) -> TxHashTarget {
		// capacity: 4 + 4 + NOTE_BATCH + 8*NOTE_BATCH + 5
		let mut inp = Vec::with_capacity(4 + 4 + NOTE_BATCH + 8 * NOTE_BATCH + 5);
		inp.extend_from_slice(&accin_null.0.elements);
		inp.extend_from_slice(&accout_comm.0.elements);
		for id in &asset_ids {
			inp.push(id.0);
		}
		// Flatten each U256Target as its 8 u32 limbs (little-endian, matching set_witness)
		for amt in &amounts {
			for u in amt.0 {
				inp.push(u.0);
			}
		}
		inp.extend_from_slice(&w_acc_addr);
		TxHashTarget(self.hash_n_to_hash_no_pad::<PoseidonHash>(inp))
	}
}
