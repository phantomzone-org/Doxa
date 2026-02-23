use anyhow::{anyhow, Result};
use digest::{Digest, Output};
use serde::{Deserialize, Serialize};
use tessera_client::NoteCommitment;
use tessera_trees::tree::hasher::Hash;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteCommitmentBatch {
	pub notes: Vec<NoteCommitment>,
	batch_size: usize,
}

impl NoteCommitmentBatch {
	pub fn new(batch_size: usize) -> Self {
		Self {
			notes: Vec::with_capacity(batch_size),
			batch_size,
		}
	}

	pub fn add_deposit(&mut self, deposit: NoteCommitment) -> Result<()> {
		if self.notes.len() >= self.batch_size {
			return Err(anyhow!("Batch is full"));
		}
		self.notes.push(deposit);
		Ok(())
	}

	/// Compute leaf hashes using SHA-256 (for native leaf hashing mode).
	pub fn leaves<H: Digest>(&self) -> Vec<Output<H>> {
		self.notes.iter().map(|d| d.hash::<H>()).collect()
	}

	pub fn leaves_as_field_hashes<H: Digest>(&self) -> Vec<Hash> {
		self.notes.iter().map(|d| d.as_field_hash()).collect()
	}
}

pub struct NoteCommitmentBatchReady {
	pub batch: NoteCommitmentBatch,
	pub new_root: Hash,
}
