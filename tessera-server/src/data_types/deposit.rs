use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tessera_client::NoteCommitment;
use tessera_utils::hasher::HashOutput;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deposit {
	note_commitment: NoteCommitment,
	address: [u8; 20],
	amount: u64,
}

impl Deposit {
	pub fn new(note_commitment: NoteCommitment, address: [u8; 20], amount: u64) -> Self {
		Self {
			note_commitment,
			address,
			amount,
		}
	}

	pub fn note_commitment(&self) -> NoteCommitment {
		self.note_commitment
	}

	pub fn address(&self) -> [u8; 20] {
		self.address
	}

	pub fn amount(&self) -> u64 {
		self.amount
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

	pub fn leaves_as_field_hashes(&self) -> Vec<HashOutput> {
		self.deposits
			.iter()
			.map(|d| d.note_commitment().0)
			.collect()
	}
}

pub struct DepositBatchReady {
	pub batch: DepositsBatch,
	pub new_root: HashOutput,
}
