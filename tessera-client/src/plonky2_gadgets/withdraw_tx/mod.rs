pub(crate) mod cb;
pub(crate) mod circuit;
pub(crate) mod targets;

#[cfg(test)]
mod tests;

use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_field::types::{Field, PrimeField64};
use primitive_types::{H160, U256};
use tessera_utils::{ConfigNative, D, F, hasher::HashOutput};

use crate::{AssetId, NOTE_BATCH, PIHelper, SubpoolId};

/// See [`crate::plonky2_gadgets::withdraw_tx::targets::WithdrawTxPublicTargets`] for PI layout.
pub struct WithdrawProof {
	pub proof: ProofWithPublicInputs<F, ConfigNative, D>,
}

impl PIHelper for WithdrawProof {
	fn proof(&self) -> &ProofWithPublicInputs<F, ConfigNative, D> {
		&self.proof
	}

	/// PI[3..7]: Account Commitment Tree root.
	fn act_root(&self) -> HashOutput {
		HashOutput(self.pis()[3..7].try_into().unwrap())
	}

	/// PI[0]: Input account subpool ID.
	fn acc_in_subpool_id(&self) -> SubpoolId {
		SubpoolId(self.pis()[0])
	}

	/// PI[1]: Output account subpool ID.
	fn acc_out_subpool_id(&self) -> SubpoolId {
		SubpoolId(self.pis()[1])
	}

	/// PI[11..15]: Input account nullifier.
	fn accin_nullifier(&self) -> HashOutput {
		HashOutput(self.pis()[11..15].try_into().unwrap())
	}

	/// PI[15..19]: Output account commitment.
	fn accout_commitment(&self) -> HashOutput {
		HashOutput(self.pis()[15..19].try_into().unwrap())
	}

	/// PI[2]: `true` for a real withdrawal, `false` for a dummy/padding proof.
	fn not_fake_tx(&self) -> bool {
		self.pis()[2].is_one()
	}

	/// PI[7..11]: Main pool configuration tree root.
	fn mainpool_config_root(&self) -> HashOutput {
		HashOutput(self.pis()[7..11].try_into().unwrap())
	}
}

impl WithdrawProof {
	/// PI[19..26]: Asset IDs for each withdrawal slot (zero for padding slots).
	pub fn asset_ids(&self) -> [AssetId; NOTE_BATCH] {
		core::array::from_fn(|i| AssetId(self.pis()[19 + i]))
	}

	/// PI[26..82]: Withdrawal amounts per slot.
	pub fn withdrawal_amts(&self) -> [U256; NOTE_BATCH] {
		core::array::from_fn(|i| {
			let base = 26 + i * 8;
			let words: [u64; 4] = core::array::from_fn(|j| {
				let lo = self.pis()[base + 2 * j].to_canonical_u64() as u32;
				let hi = self.pis()[base + 2 * j + 1].to_canonical_u64() as u32;
				lo as u64 | ((hi as u64) << 32)
			});
			U256(words)
		})
	}

	/// PI[82..87]: Ethereum destination address.
	pub fn withdrawal_address(&self) -> H160 {
		let mut bytes = [0u8; 20];
		for i in 0..5 {
			let limb = self.pis()[82 + i].to_canonical_u64() as u32;
			bytes[4 * i..4 * i + 4].copy_from_slice(&limb.to_le_bytes());
		}
		H160(bytes)
	}
}
