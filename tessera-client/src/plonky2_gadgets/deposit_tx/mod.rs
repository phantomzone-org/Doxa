pub(crate) mod cb;
pub(crate) mod circuit;
pub(crate) mod targets;

pub use circuit::*;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_field::types::{Field, PrimeField64};
use primitive_types::{H160, U256};
use tessera_utils::{ConfigNative, D, F, hasher::HashOutput};

use crate::{AssetId, PIHelper, SubpoolId};

#[cfg(test)]
mod test;

/// See [`crate::plonky2_gadgets::deposit_tx::targets::DepositTxPublicTargets`] for PI layout.
pub struct DepositProof {
	pub proof: ProofWithPublicInputs<F, ConfigNative, D>,
}

impl PIHelper for DepositProof {
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

	/// PI[3..7]: Main pool configuration tree root.
	fn mainpool_config_root(&self) -> HashOutput {
		HashOutput(self.pis()[3..7].try_into().unwrap())
	}

	/// PI[7..11]: Account Commitment Tree root.
	fn act_root(&self) -> HashOutput {
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

impl DepositProof
where
	Self: PIHelper,
{
	/// PI[19..23]: Deposit note commitment.
	pub fn note_commitment(&self) -> HashOutput {
		HashOutput(self.pis()[19..23].try_into().unwrap())
	}

	/// PI[23..28]: Ethereum destination address.
	pub fn eth_address(&self) -> H160 {
		let mut bytes = [0u8; 20];
		for i in 0..5 {
			let limb = self.pis()[23 + i].to_canonical_u64() as u32;
			bytes[4 * i..4 * i + 4].copy_from_slice(&limb.to_le_bytes());
		}
		H160(bytes)
	}

	/// PI[28..36]: Deposit amount.
	pub fn amount(&self) -> U256 {
		let words: [u64; 4] = core::array::from_fn(|i| {
			let lo = self.pis()[28 + 2 * i].to_canonical_u64() as u32;
			let hi = self.pis()[28 + 2 * i + 1].to_canonical_u64() as u32;
			lo as u64 | ((hi as u64) << 32)
		});
		U256(words)
	}

	/// PI[36]: Asset being deposited.
	pub fn asset_id(&self) -> AssetId {
		AssetId(self.pis()[36])
	}
}
