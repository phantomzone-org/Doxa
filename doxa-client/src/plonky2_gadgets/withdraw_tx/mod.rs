pub mod builder;
pub(crate) mod cb;
pub mod circuit;
pub mod targets;

pub use circuit::{WithdrawTxCircuit, build_withdraw_tx_circuit};

#[cfg(test)]
mod tests;

use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_field::types::PrimeField64;
use primitive_types::{H160, U256};
use doxa_utils::{ConfigNative, D, F, hasher::HashOutput};

use crate::{AssetId, NOTE_BATCH, PIHelper};

/// See [`crate::plonky2_gadgets::withdraw_tx::targets::WithdrawTxPublicTargets`] for PI layout.
///
/// PI layout (85 elements for NOTE_BATCH=7):
/// ```text
/// [0..4]  root (ACT root)
/// [4..8]  mainpool_config_root
/// [8]     not_fake_tx
/// [9..13] accin_null
/// [13..17] accout_comm
/// [17..24] asset_ids (NOTE_BATCH elements)
/// [24..80] withdrawal_amts (8 × NOTE_BATCH elements)
/// [80..85] w_acc_addr (5 × u32 LE limbs)
/// ```
#[derive(Clone)]
pub struct WithdrawProof {
	pub proof: ProofWithPublicInputs<F, ConfigNative, D>,
}

impl PIHelper for WithdrawProof {
	fn proof(&self) -> &ProofWithPublicInputs<F, ConfigNative, D> {
		&self.proof
	}

	fn output_commitments(&self) -> Vec<doxa_utils::hasher::HashOutput> {
		vec![self.accout_commitment()]
	}
}

impl WithdrawProof {
	/// PI[17..24]: Asset IDs for each withdrawal slot (zero for padding slots).
	pub fn asset_ids(&self) -> [AssetId; NOTE_BATCH] {
		core::array::from_fn(|i| AssetId(self.pis()[17 + i]))
	}

	/// PI[24..80]: Withdrawal amounts per slot.
	pub fn withdrawal_amts(&self) -> [U256; NOTE_BATCH] {
		core::array::from_fn(|i| {
			let base = 24 + i * 8;
			let words: [u64; 4] = core::array::from_fn(|j| {
				let lo = self.pis()[base + 2 * j].to_canonical_u64() as u32;
				let hi = self.pis()[base + 2 * j + 1].to_canonical_u64() as u32;
				lo as u64 | ((hi as u64) << 32)
			});
			U256(words)
		})
	}

	/// PI[80..85]: Ethereum destination address.
	pub fn withdrawal_address(&self) -> H160 {
		let mut bytes = [0u8; 20];
		for i in 0..5 {
			let limb = self.pis()[80 + i].to_canonical_u64() as u32;
			bytes[4 * i..4 * i + 4].copy_from_slice(&limb.to_le_bytes());
		}
		H160(bytes)
	}
}
