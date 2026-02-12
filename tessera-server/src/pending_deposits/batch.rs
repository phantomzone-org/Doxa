use anyhow::{anyhow, Ok, Result};
use digest::{Digest, Output};
use serde::{Deserialize, Serialize};
use tessera_trees::tree::hasher::Hash;

use crate::pending_deposits::PendingDeposit;

const BATCH_SIZE: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingDepositsBatch {
	pub deposits: Vec<PendingDeposit>,
}

impl PendingDepositsBatch {
	pub fn new() -> Self {
		Self {
			deposits: Vec::with_capacity(BATCH_SIZE),
		}
	}

	pub fn add_deposit(&mut self, deposit: PendingDeposit) -> Result<()> {
		if self.deposits.len() >= BATCH_SIZE {
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
