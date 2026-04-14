use itertools::Itertools;
use plonky2::{hash::poseidon::PoseidonHash, plonk::config::Hasher};
use plonky2_field::types::{Field, Field64};
use primitive_types::U256;
use rand::{CryptoRng, Rng, RngExt, distr::Uniform};
use serde::{Deserialize, Serialize};
use tessera_utils::{
	F,
	hasher::{HashOutput, MerkleHash},
};

use crate::{AccountAddress, AssetId, account::NullifierKey, double_hash_native};

#[derive(Debug, Clone, Copy)]
/// Commitment to a [`DepositNote`]
pub struct DepositNoteCommitment(pub HashOutput);

#[derive(Debug, Clone, Copy)]
/// An external deposit intent created by a sender (e.g. an Ethereum user).
///
/// The deposit note specifies which Tessera account should receive the funds
/// and how much of which asset is being deposited.  Its commitment is
/// computed by the deposit circuit and exposed as a public input, linking
/// the on-chain Ethereum event to the ZK proof.
pub struct DepositNote {
	/// 2-element random identifier that makes each note unique.
	pub identifier: NoteIdentifier,
	/// The Tessera account address that will receive the deposit.
	pub recipient: AccountAddress,
	/// Amount to deposit (U256).
	pub amount: U256,
	/// Asset type being deposited.
	pub asset_id: AssetId,
}

impl DepositNote {
	pub(crate) const ZERO: Self = Self {
		identifier: NoteIdentifier::ZERO,
		recipient: AccountAddress::ZERO,
		amount: U256::zero(),
		asset_id: AssetId::ZERO,
	};

	/// Compute the Poseidon commitment to this deposit note.
	///
	/// Hash input (16 field elements):
	/// ```text
	/// identifier[2] || recipient.subpool_id[1] || recipient.public_id[4]
	/// || amount[8 u32 limbs, LE] || asset_id[1]
	/// ```
	pub fn commitment(&self) -> DepositNoteCommitment {
		// 2 + 1 + 4 + 8 + 1 = 16 elements
		// identifier[2] || recipient.subpool_id[1] || recipient.public_id[4]
		// || amount[8 u32 limbs, LE] || asset_id[1]
		let mut input = [F::ZERO; 16];
		input[0..2].copy_from_slice(&self.identifier.0);
		input[2] = self.recipient.subpool_id.0;
		input[3..7].copy_from_slice(&self.recipient.public_id.0.0);
		for (i, word) in self.amount.0.iter().enumerate() {
			input[7 + i * 2] = F::from_canonical_u32(*word as u32);
			input[7 + i * 2 + 1] = F::from_canonical_u32((*word >> 32) as u32);
		}
		input[15] = self.asset_id.0;
		DepositNoteCommitment(HashOutput(
			<PoseidonHash as Hasher<F>>::hash_no_pad(&input).elements,
		))
	}
}

/// Commitment to a [`StandardNote`]
///
/// Computed as a Poseidon hash over all note fields (see [`StandardNote::commitment`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteCommitment(pub HashOutput);

impl NoteCommitment {
	pub const fn zero() -> Self {
		Self(HashOutput::ZERO)
	}
}

/// Spend-once nullifier for a note, derived from its commitment, tree position,
/// and the owner's nullifier key.
///
/// `nullifier = H(note_commitment || position || nk)`
///
/// Publishing the nullifier in a private transaction proves the note was spent
/// without revealing which note or who owns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteNullifier(pub HashOutput);

impl NoteNullifier {
	pub const fn zero() -> Self {
		Self(HashOutput::ZERO)
	}
}

/// Random 2-field-element nonce that makes each note commitment unique.
///
/// Sampled fresh for every note creation to prevent commitment collisions.
#[derive(Clone, Copy, Debug)]
pub struct NoteIdentifier(pub [F; 2]);

impl NoteIdentifier {
	/// All-zero identifier used as a padding value in dummy notes.
	pub(crate) const ZERO: Self = Self([F::ZERO; 2]);

	/// Sample a fresh random identifier uniformly from the Goldilocks field.
	pub fn from_rng<R: CryptoRng + Rng>(rng: &mut R) -> Self {
		Self(
			rng.sample_iter(Uniform::new(0, F::ORDER).unwrap())
				.take(2)
				.map(F::from_canonical_u64)
				.collect_array()
				.unwrap(),
		)
	}
}

/// A private note carrying a fungible asset balance between accounts.
///
/// Notes are the primary transfer primitive in Tessera.  A sender creates a
/// note targeting a recipient and places its commitment in the NCT.  The
/// recipient later spends the note by revealing its nullifier.
///
/// # Spend and reject conditions
/// - **Spend** (`spend_cond`): the note can only be spent by the `recipient`.
/// - **Reject** (`reject_cond`): the `sender` can reclaim the note if the recipient refuses to
///   process it.
#[derive(Clone, Copy)]
pub struct StandardNote {
	pub identifier: NoteIdentifier,
	pub asset_id: AssetId,
	pub amt: U256,
	/// Account that will receive the funds.
	pub recipient: AccountAddress,
	/// Account that originally sent the funds (used for rejection).
	pub sender: AccountAddress,
	/// Arbitrary memo, up to 512 bytes; zero-padded.
	pub memo: [u8; 512],
}

impl StandardNote {
	/// Create a new note with a randomly sampled identifier.
	pub fn create<R: CryptoRng + Rng>(
		rng: &mut R,
		recipient: AccountAddress,
		sender: AccountAddress,
		amt: U256,
		asset_id: AssetId,
		memo: [u8; 512],
	) -> Self {
		StandardNote {
			identifier: NoteIdentifier::from_rng(rng),
			asset_id,
			amt,
			recipient,
			sender,
			memo,
		}
	}

	/// Create a note with an explicit identifier (for use by external crates).
	pub fn new(
		identifier: NoteIdentifier,
		asset_id: AssetId,
		amt: U256,
		recipient: AccountAddress,
		sender: AccountAddress,
		memo: [u8; 512],
	) -> Self {
		StandardNote {
			identifier,
			asset_id,
			amt,
			recipient,
			sender,
			memo,
		}
	}

	/// Returns the note amount.
	pub fn amt(&self) -> U256 {
		self.amt
	}

	/// Compute the Poseidon commitment for this note.
	///
	/// Hash input (21 field elements):
	/// ```text
	/// identifier[2]
	/// || amount[8 u32 limbs, LE]
	/// || asset_id[1]
	/// || recipient.subpool_id[1] || recipient.public_id[4]   (spend condition)
	/// || sender.subpool_id[1]   || sender.public_id[4]       (reject condition)
	/// ```
	pub fn commitment(&self) -> NoteCommitment {
		let mut input = [F::ZERO; 21];
		input[..2].copy_from_slice(self.identifier.0.as_slice());
		// amount: U256.0 is [u64; 4] little-endian words, split into lo/hi u32 limbs
		for (i, word) in self.amt.0.iter().enumerate() {
			input[2 + i * 2] = F::from_canonical_u32(*word as u32);
			input[2 + i * 2 + 1] = F::from_canonical_u32((*word >> 32) as u32);
		}
		input[10] = self.asset_id.0;
		// recipient condition (spend)
		input[11] = self.recipient.subpool_id.0;
		input[12..16].copy_from_slice(self.recipient.public_id.0.0.as_slice());
		// sender condition (reject)
		input[16] = self.sender.subpool_id.0;
		input[17..].copy_from_slice(self.sender.public_id.0.0.as_slice());

		NoteCommitment(HashOutput(
			<PoseidonHash as Hasher<F>>::hash_no_pad(input.as_ref()).elements,
		))
	}

	pub fn nullifier(
		commitment: &NoteCommitment,
		position: usize,
		nk: &NullifierKey,
	) -> anyhow::Result<NoteNullifier> {
		anyhow::ensure!(
			(position as u64) < F::ORDER,
			"position {position} exceeds field order"
		);
		let mut input = [F::ZERO; 9];
		input[..4].copy_from_slice(&commitment.0.0);
		input[4] = F::from_canonical_u64(position as u64);
		input[5..9].copy_from_slice(nk.0.as_slice());
		Ok(NoteNullifier(HashOutput(
			<PoseidonHash as Hasher<F>>::hash_no_pad(input.as_ref()).elements,
		)))
	}
}

#[cfg(test)]
mod tests {
	use rand::rng;

	use super::*;

	impl StandardNote {
		pub fn sample_with(
			recipient: AccountAddress,
			sender: AccountAddress,
			amt: U256,
			asset_id: AssetId,
		) -> Self {
			let mut rng = rng();
			StandardNote {
				identifier: NoteIdentifier::from_rng(&mut rng),
				asset_id,
				amt,
				recipient,
				sender,
				memo: [0u8; 512],
			}
		}
	}
}
