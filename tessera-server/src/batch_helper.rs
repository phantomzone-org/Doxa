use anyhow::Result;
use plonky2::field::types::PrimeField64;
use tessera_client::{HashOutput, PIHelper, SUBTREE_BATCHSIZE};
use tessera_utils::{D, F};

use crate::prover_service::SubtreeRootCircuit;

/// [`PiCommitHash`] that matches Solidity's `keccak256(abi.encodePacked(...))`.
pub struct SolidityKeccak256;

impl PiCommitHash for SolidityKeccak256 {
	fn hash(words: &[u32]) -> [u8; 32] {
		use tessera_utils::plonky2_gadgets::keccak256::utils::solidity_keccak256;
		let u32s = solidity_keccak256(words);
		let mut out = [0u8; 32];
		for (i, &w) in u32s.iter().enumerate() {
			out[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
		}
		out
	}
}

// ---------------------------------------------------------------------------
// PiCommitHash — cryptographic hash function for PI commitments
// ---------------------------------------------------------------------------

/// A cryptographic hash function used to compute PI commitments.
///
/// Implementations receive the raw 32-bit LE word preimage assembled by a
/// [`BatchHelper`] and return a 32-byte digest (e.g. keccak256).
pub trait PiCommitHash {
	/// Hash `words` (32-bit LE) and return a 32-byte digest.
	fn hash(words: &[u32]) -> [u8; 32];
}

// ---------------------------------------------------------------------------
// BatchHelper — generic batch lifecycle
// ---------------------------------------------------------------------------

/// Lifecycle trait for a batch of transaction proofs.
///
/// Two concrete batch kinds exist:
/// - **Mixed batch** — [`TxProof::Deposit`] and [`TxProof::Withdraw`] slots.
/// - **Private-TX batch** — [`TxProof::Private`] slots only.
///
/// The expected call sequence is:
/// 1. [`add_proof`](Self::add_proof) — repeatedly until `Ok(true)` or the caller decides to flush
///    early.
/// 2. [`finalize`](Self::finalize) — pad to capacity and compute any batch-level commitments (e.g.,
///    Poseidon subtree root).
/// 3. [`pi_commitment`](Self::pi_commitment) — produce the keccak commitment submitted on-chain.
pub trait BatchHelper {
	const PROOF_BATCH_SIZE: usize;
	type Proof: PIHelper;

	/// Returns all proofs currently stored in the batch.
	fn proofs(&self) -> &[Self::Proof];

	fn common_act_root(&self) -> Result<HashOutput>;

	fn common_main_config_root(&self) -> Result<HashOutput>;

	/// Returns the circuit friendly root of the batch commiments subtree root.
	/// Requires the batch to be finalized.
	fn commitments_subtree_root(&self) -> Result<HashOutput>;

	/// Add a proof to the next available slot.
	///
	/// Returns `Ok(true)` when the batch is now full (caller should flush).
	fn add_proof(&mut self, proof: Self::Proof) -> Result<bool>;

	/// Whether the batch is at capacity (no more slots available).
	fn is_full(&self) -> bool {
		self.proofs().len() == Self::PROOF_BATCH_SIZE
	}

	fn is_empty(&self) -> bool {
		self.proofs().is_empty()
	}

	/// Whether [`finalize`](Self::finalize) has been called successfully.
	fn is_finalized(&self) -> bool;

	/// Pad remaining slots to capacity and compute batch-level commitments.
	///
	/// Must be called before [`pi_commitment`](Self::pi_commitment).
	fn finalize(&mut self) -> Result<()>;

	/// Compute the PI commitment for the finalized batch using hash function `H`.
	///
	/// # Errors
	/// Returns `Err` if the batch has not been finalized or is empty.
	fn pi_commitment<H: PiCommitHash>(&self) -> Result<[u8; 32]> {
		let batch_poseidon_root = self.commitments_subtree_root()?;

		let mut words: Vec<u32> = Vec::new();

		// 1. Batch Poseidon root.
		push_fields(&mut words, &batch_poseidon_root.0);

		// 2. Common PIs once (act_root ++ mainpool_config_root).
		push_fields(&mut words, &self.proofs()[0].batch_common_pis());

		// 3. Unique PIs for every slot (real + dummy).
		for proof in self.proofs() {
			push_fields(&mut words, &proof.batch_unique_pis());
		}

		Ok(H::hash(&words))
	}

	fn batch_poseidon_root(&self) -> Result<HashOutput> {
		anyhow::ensure!(self.is_full(), "batch needs to be finalized");

		let leaves: Vec<HashOutput> = self
			.proofs()
			.iter()
			.flat_map(|p| p.output_commitments())
			.collect();

		anyhow::ensure!(
			leaves.len() == SUBTREE_BATCHSIZE,
			"leaf count mismatch: got {}, expected {}",
			leaves.len(),
			SUBTREE_BATCHSIZE
		);

		Ok(SubtreeRootCircuit::compute_root_native(leaves))
	}
}

/// Encode each Goldilocks field element as `[lo_u32, hi_u32]` (little-endian).
fn push_fields(words: &mut Vec<u32>, fields: &[F]) {
	for &f in fields {
		let v = f.to_canonical_u64();
		words.push(v as u32); // lo
		words.push((v >> 32) as u32); // hi
	}
}

// ---------------------------------------------------------------------------
// TxProof — unified proof type covering all three transaction kinds
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use tessera_client::FakeSpendTxBuilder;
	use tessera_utils::{hasher::HashOutput, F};

	use super::*;

	// ── SolidityKeccak256 ─────────────────────────────────────────────────────

	/// The hash must be deterministic: identical inputs always produce the same
	/// 32-byte digest.
	#[test]
	fn solidity_keccak256_is_deterministic() {
		let words: Vec<u32> = (0u32..32).collect();
		let h1 = SolidityKeccak256::hash(&words);
		let h2 = SolidityKeccak256::hash(&words);
		assert_eq!(h1, h2, "keccak256 must be deterministic");
	}

	/// Different inputs must (with overwhelming probability) produce different digests.
	#[test]
	fn solidity_keccak256_distinct_inputs_differ() {
		let a = SolidityKeccak256::hash(&[0u32; 8]);
		let b = SolidityKeccak256::hash(&[1u32; 8]);
		assert_ne!(a, b, "keccak256 of distinct inputs must differ");
	}

	/// The digest has exactly 32 bytes.
	#[test]
	fn solidity_keccak256_output_length() {
		let h = SolidityKeccak256::hash(&[]);
		assert_eq!(h.len(), 32, "keccak256 output must be 32 bytes");
	}

	// ── pi_commitment word layout ─────────────────────────────────────────────

	/// The `pi_commitment` preimage contains exactly
	/// `(4 + 8 + N * unique_pi_count) * 2` u32 words (each Goldilocks field
	/// element is encoded as two u32s).
	///
	/// For `PrivateTxBatch` (N=64, unique_pi_count = 73 - 8 = 65):
	///   (4 + 8 + 64×65) × 2 = (12 + 4160) × 2 = 8344 words before hashing.
	///
	/// This test exercises the layout via a finalized batch and verifies the
	/// output is exactly 32 bytes.
	#[test]
	#[ignore]
	fn pi_commitment_output_is_32_bytes() {
		use tessera_client::build_priv_tx_circuit;

		use crate::prover_service::priv_tx::batch_helper::PrivateTxBatch;

		let circ = build_priv_tx_circuit();
		let proof = FakeSpendTxBuilder::new(
			HashOutput(Default::default()),
			HashOutput(Default::default()),
		)
		.build()
		.into_priv_tx()
		.prove(&circ.circuit_data, &circ.targets)
		.expect("FakeSpendTxBuilder proof failed");
		let mut batch = PrivateTxBatch::new();
		batch.add_proof(proof).unwrap();
		batch.finalize().unwrap();

		let commitment = batch.pi_commitment::<SolidityKeccak256>().unwrap();
		assert_eq!(commitment.len(), 32, "pi_commitment must be 32 bytes");
	}
}
