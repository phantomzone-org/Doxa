use anyhow::{anyhow, Result};
use digest::{Digest, Output};
use serde::{Deserialize, Serialize};
use tessera_trees::tree::hasher::Hash;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteCommitment([u8; 32]);

impl AsRef<[u8]> for NoteCommitment {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteCommitmentBatch {
	notes: Vec<NoteCommitment>,
	batch_size: usize,
}

impl NoteCommitment {
	pub fn new(note_commitment: [u8; 32]) -> Self {
		Self(note_commitment)
	}

	pub fn note_commitment(&self) -> [u8; 32] {
		self.0
	}

	pub fn hash_inplace<H: Digest>(&self, out: &mut Output<H>) {
		let mut hasher = H::new();
		hasher.update(self.note_commitment());
		*out = hasher.finalize();
	}

	pub fn hash<H: Digest>(&self) -> Output<H> {
		let mut out = Output::<H>::default();
		self.hash_inplace::<H>(&mut out);
		out
	}

	pub fn as_field_hash<H: Digest>(&self) -> Hash {
		let digest = self.hash::<H>();
		let mut bytes = [0u8; 32];
		bytes.copy_from_slice(&digest[..32]);
		Hash::from_32bytes_digest(bytes)
	}
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
		self.notes.iter().map(|d| d.as_field_hash::<H>()).collect()
	}
}

pub struct NoteCommitmentBatchReady {
	pub batch: NoteCommitmentBatch,
	pub new_root: Hash,
}
