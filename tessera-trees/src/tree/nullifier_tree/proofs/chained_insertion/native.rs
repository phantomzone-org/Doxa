//! Chained insertion proof for indexed Merkle trees.
//!
//! This module implements a batch insertion proof that chains multiple
//! single insertion proofs together, achieving O(N log N) complexity
//! instead of the O(N² log N) complexity of the Aztec-style batch proof.
//!
//! ## Design Overview
//!
//! The proof chains N single insertions:
//! ```text
//! old_root_0 → new_root_0 = old_root_1 → new_root_1 = ... → new_root_{N-1}
//! ```
//!
//! The key constraint is: `proof[i].new_root == proof[i+1].old_root`
//!
//! ## Complexity Analysis
//!
//! - Single insertion: O(log N) - 4 Merkle path computations
//! - Chained batch of K insertions: O(K log N)
//! - Aztec-style batch of K insertions: O(K² log N) (due to predecessor tracking)
//!
//! ## Trade-offs
//!
//! | Aspect                | Chained Proof          | Aztec Batch Proof      |
//! |-----------------------|------------------------|------------------------|
//! | Complexity            | O(K log N)             | O(K² log N)            |
//! | Witness size          | K × single proof size  | Smaller (shared paths) |
//! | Parallelization       | Sequential dependency  | More parallelizable    |
//! | Predecessor handling  | Simple (tree only)     | Complex (pending)      |

use plonky2::{
	field::{extension::Extendable, types::Field},
	hash::hash_types::RichField,
};

use crate::tree::{NullifierInsertProof, hasher::{CommitmentPreimage, DataCommitment, MerkleHash, ToHashOut}};

/// A chained insertion proof that proves multiple sequential insertions.
///
/// This structure chains multiple single insertion proofs together,
/// where each proof's `new_root` becomes the next proof's `old_root`.
///
/// ## Public Inputs
/// - `initial_root`: The tree root before any insertions
/// - `final_root`: The tree root after all insertions
/// - `inserted_values`: The values that were inserted (in order)
///
/// ## Private Witnesses
/// - `proofs`: The individual insertion proofs (with intermediate roots)
#[derive(Debug, Clone)]
pub struct NullifierChainedInsertProof<H: MerkleHash> {
	/// The individual insertion proofs, chained together
	pub proofs: Vec<NullifierInsertProof<H>>,
}

impl<H: MerkleHash> NullifierChainedInsertProof<H> {
	/// Creates a new chained insertion proof from a vector of insertion proofs.
	///
	/// # Arguments
	/// * `proofs` - The individual insertion proofs to chain
	///
	/// # Panics
	/// Panics if the proofs are not properly chained (new_root[i] != old_root[i+1])
	pub fn new(proofs: Vec<NullifierInsertProof<H>>) -> Self {
		// Verify chaining constraint
		for i in 0..proofs.len().saturating_sub(1) {
			assert_eq!(
				proofs[i].new_root,
				proofs[i + 1].old_root,
				"Proofs not properly chained at index {}: new_root[{}] != old_root[{}]",
				i,
				i,
				i + 1
			);
		}

		Self {
			proofs,
		}
	}

	pub fn depth(&self) -> usize {
		self.proofs[0].depth()
	}

	/// Returns the number of insertions in this proof.
	pub fn len(&self) -> usize {
		self.proofs.len()
	}

	/// Returns true if this proof contains no insertions.
	pub fn is_empty(&self) -> bool {
		self.proofs.is_empty()
	}

	/// Returns the initial tree root (before any insertions).
	pub fn initial_root(&self) -> Option<H::Digest> {
		self.proofs.first().map(|p| p.old_root)
	}

	/// Returns the final tree root (after all insertions).
	pub fn final_root(&self) -> Option<H::Digest> {
		self.proofs.last().map(|p| p.new_root)
	}

	/// Returns the values that were inserted, in order.
	pub fn inserted_values(&self) -> Vec<H::Digest> {
		self.proofs.iter().map(|p| p.new_node_value).collect()
	}

	/// Computes the commitment digest from this proof using the given
	/// [`DataCommitment`] implementation.
	///
	/// Returns the field elements that should match the STARK proof's
	/// `public_inputs` when the circuit was built with the same commitment.
	///
	/// ```ignore
	/// let expected_pi = native_proof.compute_commitment::<F, D>(&PoseidonCommitment);
	/// // or equivalently:
	/// let expected_pi = PoseidonCommitment.commit_native(&native_proof);
	/// assert_eq!(expected_pi, stark_proof.public_inputs);
	/// ```
	pub fn compute_commitment<F, const D: usize>(
		&self,
		commitment: &dyn DataCommitment<F, D>,
	) -> Vec<F>
	where
		F: RichField + Extendable<D>,
		H::Digest: ToHashOut<F>,
	{
		commitment.commit_native(self)
	}

	/// Verifies the chained insertion proof.
	///
	/// This verifies:
	/// 1. Each individual insertion proof is valid
	/// 2. The proofs are properly chained (new_root[i] == old_root[i+1])
	/// 3. The num_leaves are properly chained (index[i]+1 == index[i+1])
	///
	/// # Returns
	/// `true` if the proof is valid, `false` otherwise.
	pub fn verify(&self) -> bool {
		if self.proofs.is_empty() {
			return true;
		}

		// Verify each individual proof
		for (i, proof) in self.proofs.iter().enumerate() {
			if !proof.verify() {
				eprintln!("Individual proof {} failed verification", i);
				return false;
			}
		}

		// Verify chaining constraints
		for i in 0..self.proofs.len() - 1 {
			// Root chaining
			if self.proofs[i].new_root != self.proofs[i + 1].old_root {
				eprintln!(
					"Chain broken at index {}: new_root[{}] != old_root[{}]",
					i,
					i,
					i + 1
				);
				return false;
			}

			// num_leaves chaining
			if self.proofs[i].new_node_path + 1 != self.proofs[i + 1].new_node_path {
				eprintln!(
					"num_leaves chain broken at index {}: num_leaves_new[{}] != num_leaves_old[{}]",
					i,
					i,
					i + 1
				);
				return false;
			}
		}

		true
	}
}

/// Preimage layout: `old_root || new_root || value[0] || ... || value[n-1]`
///
/// Matches the circuit's [`ChainedInsertProofTargets::new`](crate::tree::ChainedInsertProofTargets::new).
impl<F: Field, H: MerkleHash> CommitmentPreimage<F> for NullifierChainedInsertProof<H>
where
	H::Digest: ToHashOut<F>,
{
	fn write_preimage(&self, buf: &mut Vec<F>) {
		buf.reserve((self.proofs.len() + 2) * 4);
		buf.extend_from_slice(&self.proofs[0].old_root.to_hash_out().elements);
		buf.extend_from_slice(
			&self.proofs[self.proofs.len() - 1]
				.new_root
				.to_hash_out()
				.elements,
		);
		for proof in &self.proofs {
			buf.extend_from_slice(&proof.new_node_value.to_hash_out().elements);
		}
	}
}

#[cfg(test)]
mod test {
	use anyhow::Result;

	use crate::tree::{
		NullifierTree,
		hasher::{Hash, NewFromU64, NewRandom},
		nullifier_tree::proofs::chained_insertion::NullifierChainedInsertProof,
	};

	#[test]
	fn test_chained_insert_proof_native() -> Result<()> {
		const DEPTH: usize = 16;
		const NUM_INSERTIONS: usize = 8;

		println!("=== Chained Insert Proof Native Test ===\n");

		let mut tree: NullifierTree<Hash> = NullifierTree::new(DEPTH);

		// Collect individual insertion proofs
		let mut proofs = Vec::with_capacity(NUM_INSERTIONS);

		for i in 0..NUM_INSERTIONS {
			let value = Hash::new_from_u64((i + 1) as u64 * 1000);
			let proof = tree.insert(value)?;

			println!("Insertion {}: value={}", i, value);
			println!("  old_root: {:?}", proof.old_root);
			println!("  new_root: {:?}", proof.new_root);

			proofs.push(proof);
		}

		// Create chained proof
		let chained_proof = NullifierChainedInsertProof::new(proofs);

		println!("\nChained proof:");
		println!("  num_insertions: {}", chained_proof.len());
		println!("  initial_root: {:?}", chained_proof.initial_root());
		println!("  final_root: {:?}", chained_proof.final_root());

		// Verify
		assert!(chained_proof.verify(), "Chained proof verification failed");
		println!("\nChained proof verified successfully!");

		// Verify final root matches tree root
		assert_eq!(
			chained_proof.final_root(),
			Some(tree.get_root()),
			"Final root mismatch"
		);

		println!("\n=== Test Passed! ===");
		Ok(())
	}

	#[test]
	fn test_chained_insert_proof_random() -> Result<()> {
		use rand::{SeedableRng, rngs::StdRng};

		const DEPTH: usize = 32;
		const NUM_INSERTIONS: usize = 16;

		println!("=== Chained Insert Proof Random Test ===\n");

		let mut tree: NullifierTree<Hash> = NullifierTree::new(DEPTH);
		let mut rng = StdRng::from_seed([42u8; 32]);

		// Pre-populate tree
		for _ in 0..100 {
			tree.insert(Hash::new_random(&mut rng))?;
		}

		// Collect random insertion proofs
		let mut proofs = Vec::with_capacity(NUM_INSERTIONS);

		for _ in 0..NUM_INSERTIONS {
			let value = Hash::new_random(&mut rng);
			let proof = tree.insert(value)?;
			proofs.push(proof);
		}

		// Create and verify chained proof
		let chained_proof: NullifierChainedInsertProof<Hash> =
			NullifierChainedInsertProof::new(proofs);
		assert!(
			chained_proof.verify(),
			"Random chained proof verification failed"
		);

		println!("Verified {} random insertions", NUM_INSERTIONS);
		println!("\n=== Test Passed! ===");
		Ok(())
	}
}
