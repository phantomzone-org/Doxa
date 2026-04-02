pub(crate) mod cb;
pub(crate) mod circuit;
pub(crate) mod targets;

pub use circuit::*;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_field::types::PrimeField64;
use primitive_types::{H160, U256};
use tessera_utils::{ConfigNative, D, F, hasher::HashOutput};

use crate::{AssetId, PIHelper};

#[cfg(test)]
mod test;

/// See [`crate::plonky2_gadgets::deposit_tx::targets::DepositTxPublicTargets`] for PI layout.
///
/// PI layout (35 elements):
/// ```text
/// [0..4]  act_root
/// [4..8]  mainpool_config_root
/// [8]     not_fake_tx
/// [9..13] accin_null
/// [13..17] accout_comm
/// [17..21] note_comm (deposit note commitment)
/// [21..26] eth_address (5 × u32 LE limbs)
/// [26..34] amount (8 × u32 limbs)
/// [34]    asset_id
/// ```
pub struct DepositProof {
	pub proof: ProofWithPublicInputs<F, ConfigNative, D>,
}

impl PIHelper for DepositProof {
	fn proof(&self) -> &ProofWithPublicInputs<F, ConfigNative, D> {
		&self.proof
	}
}

impl DepositProof {
	/// PI[17..21]: Deposit note commitment.
	pub fn note_commitment(&self) -> HashOutput {
		HashOutput(self.pis()[17..21].try_into().unwrap())
	}

	/// PI[21..26]: Ethereum destination address.
	pub fn eth_address(&self) -> H160 {
		let mut bytes = [0u8; 20];
		for i in 0..5 {
			let limb = self.pis()[21 + i].to_canonical_u64() as u32;
			bytes[4 * i..4 * i + 4].copy_from_slice(&limb.to_le_bytes());
		}
		H160(bytes)
	}

	/// PI[26..34]: Deposit amount.
	pub fn amount(&self) -> U256 {
		let words: [u64; 4] = core::array::from_fn(|i| {
			let lo = self.pis()[26 + 2 * i].to_canonical_u64() as u32;
			let hi = self.pis()[26 + 2 * i + 1].to_canonical_u64() as u32;
			lo as u64 | ((hi as u64) << 32)
		});
		U256(words)
	}

	/// PI[34]: Asset being deposited.
	pub fn asset_id(&self) -> AssetId {
		AssetId(self.pis()[34])
	}
}
