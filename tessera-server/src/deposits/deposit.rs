use anyhow::{anyhow, Result};
use digest::{Digest, Output};
use serde::{Deserialize, Serialize};
use tessera_trees::tree::hasher::Hash;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deposit {
	note_commitment: [u8; 32],
	address: [u8; 20],
	amount: u64,
}

impl Deposit {
	pub fn new(note_commitment: [u8; 32], address: [u8; 20], amount: u64) -> Self {
		Self {
			note_commitment,
			address,
			amount,
		}
	}

	pub fn note_commitment(&self) -> [u8; 32] {
		self.note_commitment
	}

	pub fn address(&self) -> [u8; 20] {
		self.address
	}

	pub fn amount(&self) -> u64 {
		self.amount
	}

	/// Compute the deposit commitment using SHA-256 (native, outside the circuit).
	///
	/// Encoding: `sha256(DOMAIN_SEP || noteCommitment || value || recipient)`
	/// where:
	///   - DOMAIN_SEP  = sha256("tessera.pending-deposit.v1") — 32 bytes
	///   - noteCommitment — 32 bytes
	///   - value (amount) — 32 bytes, big-endian uint256 (left-padded from u64)
	///   - recipient (address) — 20 bytes
	///
	/// This matches the Solidity `computeCommitment` function exactly. The
	/// 32-byte digest is converted to [`Hash`] via [`Hash::from_32bytes_digest`],
	/// which clears the MSB of each 8-byte chunk (Goldilocks field constraint).
	pub fn hash_inplace<H: Digest>(&self, out: &mut Output<H>) {
		let mut hasher = H::new();
		hasher.update(domain_sep::<H>());
		hasher.update(&self.note_commitment);
		// value as big-endian uint256: left-pad u64 with 24 zero bytes
		let mut value_padded = [0u8; 32];
		value_padded[24..].copy_from_slice(&self.amount.to_be_bytes());
		hasher.update(&value_padded);
		hasher.update(&self.address);
		*out = hasher.finalize();
	}

	pub fn hash<H: Digest>(&self) -> Output<H> {
		let mut out = Output::<H>::default();
		self.hash_inplace::<H>(&mut out);
		out
	}

	pub fn as_field_hash<H: Digest>(&self) -> Hash {
		Hash::from_32bytes_digest(*self.hash::<H>().as_array::<32>().unwrap())
	}
}

/// Returns the domain separator: `sha256("tessera.pending-deposit.v1")`.
///
/// This matches the Solidity constant `DOMAIN_SEP = sha256("tessera.pending-deposit.v1")`.
fn domain_sep<H: Digest>() -> Output<H> {
	H::digest(b"tessera.pending-deposit.v1")
}

#[cfg(test)]
mod tests {

	use super::*;

	/// Known-vector test: `sha256(DOMAIN_SEP || [0x01;32] || [0x00..01] || [0x01;20])`.
	///
	/// Deposit:
	///   noteCommitment = [0x01; 32]
	///   address        = [0x01; 20]
	///   amount         = 1  (encoded as 32-byte big-endian uint256)
	///
	/// The same inputs can be verified in Solidity with:
	///   `bridge.computeCommitment(bytes32(hex"0101...01"), 1, address(0x0101...01))`
	/// (before MSB clearing the raw sha256 matches this test's `leaf`).
	#[test]
	fn test_hash_sha256_known_vector() {
		let deposit: Deposit = Deposit::new(
			[1u8; 32], // 32 bytes of 1
			[1u8; 20], // 20 bytes of 1
			1,
		);

		let leaf = deposit.hash::<sha2::Sha256>();
		let hex = hex::encode(leaf.as_slice());
		println!("0x{hex}");

		// sha256(domain_sep || [0x01;32] || [0x00*31,0x01] || [0x01;20])
		let expected =
			hex::decode("78ee2c67c361a384e9587e5839beb9e2cac364079ecd903b88dbd6117ad46371")
				.unwrap();
		assert_eq!(leaf.as_slice(), expected.as_slice());
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositsBatch {
	pub deposits: Vec<Deposit>,
	batch_size: usize,
}

impl DepositsBatch {
	pub fn new(batch_size: usize) -> Self {
		Self {
			deposits: Vec::with_capacity(batch_size),
			batch_size,
		}
	}

	pub fn add_deposit(&mut self, deposit: Deposit) -> Result<()> {
		if self.deposits.len() >= self.batch_size {
			return Err(anyhow!("Batch is full"));
		}
		self.deposits.push(deposit);
		Ok(())
	}

	/// Compute leaf hashes using SHA-256 (for native leaf hashing mode).
	pub fn leaves<H: Digest>(&self) -> Vec<Output<H>> {
		self.deposits.iter().map(|d| d.hash::<H>()).collect()
	}

	pub fn leaves_as_field_hashes<H: Digest>(&self) -> Vec<Hash> {
		self.deposits
			.iter()
			.map(|d| d.as_field_hash::<H>().into())
			.collect()
	}
}

pub struct DepositBatchReady {
	pub batch: DepositsBatch,
	pub new_root: Hash,
}
