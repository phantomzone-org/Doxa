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
use plonky2_field::types::PrimeField64;
pub use prove::*;
use tessera_utils::{ConfigNative, D, F, hasher::HashOutput};

use crate::{NOTE_BATCH, PIHelper};

#[cfg(test)]
mod tests;

/// See [`crate::plonky2_gadgets::priv_tx::targets::TxCircuitPublicTargets`] for PI layout.
///
/// PI layout (73 elements for NOTE_BATCH=7):
/// ```text
/// [0..4]  root (ACT/NCT Merkle root)
/// [4..8]  mainpool_config_root
/// [8]     not_fake_tx
/// [9..13] accin_null
/// [13..17] accout_comm
/// [17..45] inote nullifiers (7×4)
/// [45..73] onote commitments (7×4)
/// ```
#[derive(Clone)]
pub struct PrivateTransactionProof(pub ProofWithPublicInputs<F, ConfigNative, D>);

impl PIHelper for PrivateTransactionProof {
	fn proof(&self) -> &ProofWithPublicInputs<F, ConfigNative, D> {
		&self.0
	}

	fn output_commitments(&self) -> Vec<tessera_utils::hasher::HashOutput> {
		let mut v = vec![self.accout_commitment()];
		v.extend(self.output_note_commitments());
		v
	}
}

impl PrivateTransactionProof {
	/// PI[17..45]: Input note nullifiers (one per NOTE_BATCH slot).
	pub fn input_note_nullifiers(&self) -> [HashOutput; NOTE_BATCH] {
		core::array::from_fn(|i| {
			let base = 17 + i * 4;
			HashOutput(self.pis()[base..base + 4].try_into().unwrap())
		})
	}

	/// PI[45..73]: Output note commitments (one per NOTE_BATCH slot).
	pub fn output_note_commitments(&self) -> [HashOutput; NOTE_BATCH] {
		core::array::from_fn(|i| {
			let base = 45 + i * 4;
			HashOutput(self.pis()[base..base + 4].try_into().unwrap())
		})
	}
}
