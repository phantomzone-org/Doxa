mod circuit;
pub(crate) mod circuit_builder;
mod fake_tx;
mod freshacc_tx;
pub mod inputs;
mod prove;
mod reject_tx;
mod spend_tx;
pub(crate) mod targets;
pub(crate) mod utils;

pub use circuit::*;
pub use inputs::{FakeTxInputs, FreshAccInputs, PrivTxInputs, RejectTxInputs, SpendTxInputs};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_field::types::{Field, PrimeField64};
pub use prove::*;
use tessera_utils::{ConfigNative, D, F, hasher::HashOutput};

use crate::{AssetId, DepositProof, NOTE_BATCH, PIHelper, SubpoolId};

#[cfg(test)]
mod tests;

/// See [`crate::plonky2_gadgets::priv_tx::targets::TxCircuitPublicTargets`] for PI layout.
pub struct PrivateTransactionProof {
	pub proof: ProofWithPublicInputs<F, ConfigNative, D>,
}

impl PIHelper for PrivateTransactionProof {
	fn proof(&self) -> &ProofWithPublicInputs<F, ConfigNative, D> {
		&self.proof
	}

	/// PI[0]: Input account subpool ID.
	fn acc_in_subpool_id(&self) -> SubpoolId {
		SubpoolId(self.pis()[0])
	}

	/// PI[1]: Output account subpool ID.
	fn acc_out_subpool_id(&self) -> SubpoolId {
		SubpoolId(self.pis()[1])
	}

	/// PI[2]: `true` for a real transaction, `false` for a dummy/padding proof.
	fn not_fake_tx(&self) -> bool {
		self.pis()[2].is_one()
	}

	/// PI[3..7]: Combined ACT / NCT Merkle root.
	fn act_root(&self) -> HashOutput {
		HashOutput(self.pis()[3..7].try_into().unwrap())
	}

	/// PI[7..11]: Main pool configuration tree root.
	fn mainpool_config_root(&self) -> HashOutput {
		HashOutput(self.pis()[7..11].try_into().unwrap())
	}

	/// PI[11..15]: Input account nullifier.
	fn accin_nullifier(&self) -> HashOutput {
		HashOutput(self.pis()[11..15].try_into().unwrap())
	}

	/// PI[15..19]: Output account commitment.
	fn accout_commitment(&self) -> HashOutput {
		HashOutput(self.pis()[15..19].try_into().unwrap())
	}
}

impl PrivateTransactionProof
where
	Self: PIHelper,
{
	/// PI[19..47]: Input note nullifiers (one per NOTE_BATCH slot).
	pub fn input_note_nullifiers(&self) -> [HashOutput; NOTE_BATCH] {
		core::array::from_fn(|i| {
			let base = 19 + i * 4;
			HashOutput(self.pis()[base..base + 4].try_into().unwrap())
		})
	}

	/// PI[47..75]: Output note commitments (one per NOTE_BATCH slot).
	pub fn output_note_commitments(&self) -> [HashOutput; NOTE_BATCH] {
		core::array::from_fn(|i| {
			let base = 47 + i * 4;
			HashOutput(self.pis()[base..base + 4].try_into().unwrap())
		})
	}

	/// PI[75]: Asset ID for this transaction.
	pub fn asset_id(&self) -> AssetId {
		AssetId(self.pis()[75])
	}
}
