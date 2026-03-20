use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tessera_client::NoteCommitment;
use tessera_utils::hasher::HashOutput;

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

	pub fn leaves_as_field_hashes(&self) -> Vec<HashOutput> {
		self.notes.iter().map(|d| d.0).collect()
	}
}

pub struct NoteCommitmentBatchReady {
	pub batch: NoteCommitmentBatch,
	pub new_root: HashOutput,
}
