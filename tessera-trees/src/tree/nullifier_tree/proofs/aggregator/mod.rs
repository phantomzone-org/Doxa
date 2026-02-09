//! Proof aggregation module for sequential insertion proofs.
//!
//! This module implements recursive proof aggregation using a binary tree structure.
//! Given N sequential insertion proofs with chained roots:
//!
//! ```text
//! proof_0: (old_root, new_root_0)
//! proof_1: (old_root = new_root_0, new_root_1)
//! ...
//! proof_N: (old_root = new_root_{N-1}, new_root_N)
//! ```
//!
//! The aggregator produces a single proof with public inputs `(old_root, new_root_N)`.
//!
//! ## Architecture
//!
//! Uses heterogeneous recursion with separate circuit types per level:
//! - Level 0: Leaf insert proofs (from `InsertProofTargets`)
//! - Level 1+: Aggregation proofs that verify two child proofs and chain roots
//!
//! Each aggregation circuit:
//! 1. Verifies left child proof in-circuit
//! 2. Verifies right child proof in-circuit
//! 3. Enforces `left.new_root == right.old_root`
//! 4. Outputs `(left.old_root, right.new_root)` as public inputs

mod streaming;
mod tree;

use plonky2::{
	field::extension::Extendable,
	hash::hash_types::RichField,
	plonk::{circuit_data::CircuitData, config::GenericConfig, proof::ProofWithPublicInputs},
};
pub use streaming::*;
pub use tree::*;

/// Size of a hash in field elements (Poseidon outputs 4 Goldilocks elements)
pub const HASH_SIZE: usize = 4;

/// Public input layout for insert proofs:
/// [0..4]: old_root
/// [4..8]: new_root
/// [8..12]: new_node_value
pub const OLD_ROOT_START: usize = 0;
pub const NEW_ROOT_START: usize = 4;
pub const NEW_NODE_VALUE_START: usize = 8;
pub const LEAF_PI_LEN: usize = 12;

/// An aggregated proof containing both the proof and its circuit data.
///
/// This is necessary for heterogeneous recursion where each level
/// has different circuit structure.
#[derive(Debug)]
pub struct AggregatedProof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
{
	/// The actual proof
	pub proof: ProofWithPublicInputs<F, C, D>,
	/// Circuit data needed to verify (and recurse on) this proof
	pub circuit_data: CircuitData<F, C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
	AggregatedProof<F, C, D>
{
	/// Returns the old_root from public inputs (first 4 elements)
	pub fn old_root(&self) -> &[F] {
		&self.proof.public_inputs[OLD_ROOT_START..OLD_ROOT_START + HASH_SIZE]
	}

	/// Returns the new_root from public inputs (elements 4..8)
	pub fn new_root(&self) -> &[F] {
		&self.proof.public_inputs[NEW_ROOT_START..NEW_ROOT_START + HASH_SIZE]
	}

	/// Returns all public inputs
	pub fn public_inputs(&self) -> &[F] {
		&self.proof.public_inputs
	}
}
