use anyhow::Result;
use plonky2::field::types::{Field, PrimeField64};
use tessera_client::{DepositProof, PIHelper, DEPOSIT_BATCH_SIZE};
use tessera_utils::{
	hasher::{HashOutput, MerkleHash},
	plonky2_gadgets::keccak256::utils::solidity_keccak256,
	F,
};

use crate::proof_aggregation::{
	deposit_super_aggregator_v2::DEPOSIT_LEAF_PI_SIZE, SubtreeRootCircuit,
};

// ---------------------------------------------------------------------------
// SubmitDepositRequest
// ---------------------------------------------------------------------------

// DEPOSIT_LEAF_PI_SIZE and related offsets are defined in
// proof_aggregation::deposit_super_aggregator_v2.

pub const DEPOSIT_FAKE_TX_PIS: [F; DEPOSIT_LEAF_PI_SIZE] = [F::ZERO; DEPOSIT_LEAF_PI_SIZE];

fn push_pis_as_u32(words: &mut Vec<u32>, pis: &[F]) {
	for pi in pis {
		let v: u64 = pi.to_canonical_u64();
		words.push((v) as u32);
		words.push(v as u32);
	}
}

/// Incrementally builds a deposit batch of up to [`DEPOSIT_BATCH_SIZE`] slots.
pub struct DepositBatch {
	/// Poseidon Merkle root over `note_commiment` in [Deposit].
	pub batch_root: Option<HashOutput>,
	/// Deposit entries, padded to [`DEPOSIT_BATCH_SIZE`]
	pub deposits: Vec<DepositProof>,
}

impl DepositBatch {
	pub fn new() -> Self {
		Self {
			deposits: Vec::new(),
			batch_root: None,
		}
	}

	pub fn len(&self) -> usize {
		self.deposits.len()
	}

	pub fn is_empty(&self) -> bool {
		self.deposits.is_empty()
	}

	pub fn is_full(&self) -> bool {
		self.deposits.len() >= DEPOSIT_BATCH_SIZE
	}

	/// Add a deposit to the batch.
	///
	/// Returns `Ok(true)` when the batch is now full (caller should flush),
	/// `Ok(false)` otherwise.
	///
	/// # Errors
	/// Returns `Err`:
	/// * if the batch is already full.
	/// * if act_root differ from previous deposit
	/// * if deposit has empty proof
	pub fn add_deposit(&mut self, deposit: DepositProof) -> anyhow::Result<bool> {
		anyhow::ensure!(!self.is_full(), "deposit batch is already full");
		anyhow::ensure!(
			deposit.act_root() == self.deposits[0].act_root(),
			"act_root mismatch"
		);
		self.deposits.push(deposit);
		Ok(self.is_full())
	}

	/// Finalize the batch: pad NC leaves to `DEPOSIT_BATCH_SIZE`, compute the
	/// Poseidon subtree root, and return an immutable [`FinalizedDepositBatch`].
	pub fn finalize(&mut self) -> Result<()> {
		anyhow::ensure!(
			self.batch_root.is_none(),
			"deposit batch is already validated"
		);
		anyhow::ensure!(!self.deposits.is_empty(), "deposit batch is empty");

		let mut leaves: Vec<HashOutput> =
			self.deposits.iter().map(|d| d.note_commitment()).collect();
		for _ in self.len()..DEPOSIT_BATCH_SIZE {
			leaves.push(HashOutput::ZERO);
		}

		self.batch_root = Some(SubtreeRootCircuit::compute_root_native(leaves));

		Ok(())
	}

	/// Compute the public-input (PI) commitment for a finalized deposit batch.
	///
	/// Keccak256(main_pool_cfg_root | batch_root | deposit[0].pis | ... |
	/// deposit[DEPOSIT_BATCH_SIZE-1].pis)
	fn pi_commitment(&self, main_pool_cfg_root: HashOutput) -> Result<[u32; 8]> {
		anyhow::ensure!(
			!self.batch_root.is_none(),
			"deposit batch has not been validated"
		);

		let mut words: Vec<u32> = Vec::with_capacity(DEPOSIT_BATCH_SIZE * DEPOSIT_LEAF_PI_SIZE * 2);

		push_pis_as_u32(&mut words, &main_pool_cfg_root.0);
		push_pis_as_u32(&mut words, &self.batch_root.unwrap().0);

		for deposit in &self.deposits {
			push_pis_as_u32(&mut words, deposit.pis());
		}

		for _ in self.len()..DEPOSIT_BATCH_SIZE {
			push_pis_as_u32(&mut words, &DEPOSIT_FAKE_TX_PIS)
		}

		let result = solidity_keccak256(&words);

		Ok(result)
	}
}

impl Default for DepositBatch {
	fn default() -> Self {
		Self::new()
	}
}
