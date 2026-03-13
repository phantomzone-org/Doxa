//! Binary tree aggregation for sequential insertion proofs.
//!
//! This module provides the core logic for aggregating pairs of proofs
//! and building a complete aggregation tree.

use anyhow::{Result, bail};
use plonky2::{
	field::extension::Extendable,
	hash::hash_types::RichField,
	iop::witness::{PartialWitness, WitnessWrite},
	plonk::{
		circuit_builder::CircuitBuilder,
		circuit_data::{CircuitConfig, CommonCircuitData, VerifierOnlyCircuitData},
		config::GenericConfig,
		proof::ProofWithPublicInputs,
	},
};

use super::{AggregatedProof, HASH_SIZE, NEW_ROOT_START, OLD_ROOT_START};

/// Aggregates a pair of proofs into a single proof.
///
/// This circuit:
/// 1. Verifies both child proofs in-circuit
/// 2. Enforces chaining: `left.new_root == right.old_root`
/// 3. Outputs `(left.old_root, right.new_root)` as public inputs
///
/// # Arguments
/// * `left` - The left (earlier) proof
/// * `right` - The right (later) proof
/// * `common_data` - Common circuit data for the child proofs
/// * `verifier_data` - Verifier-only circuit data for the child proofs
///
/// # Returns
/// An `AggregatedProof` containing the combined proof and new circuit data.
pub fn aggregate_pair<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
	left: &ProofWithPublicInputs<F, C, D>,
	right: &ProofWithPublicInputs<F, C, D>,
	common_data: &CommonCircuitData<F, D>,
	verifier_data: &VerifierOnlyCircuitData<C, D>,
) -> Result<AggregatedProof<F, C, D>>
where
	C::Hasher: plonky2::plonk::config::AlgebraicHasher<F>,
{
	let config = CircuitConfig::standard_recursion_config();
	let mut builder = CircuitBuilder::<F, D>::new(config);

	// Add verifier data target (shared by both proofs since they use same circuit)
	let verifier_data_target =
		builder.add_virtual_verifier_data(common_data.fri_params.config.cap_height);

	// Add and verify left proof
	let left_proof_target = builder.add_virtual_proof_with_pis(common_data);
	builder.verify_proof::<C>(&left_proof_target, &verifier_data_target, common_data);

	// Add and verify right proof
	let right_proof_target = builder.add_virtual_proof_with_pis(common_data);
	builder.verify_proof::<C>(&right_proof_target, &verifier_data_target, common_data);

	// Extract root targets from public inputs
	// Layout: [old_root(4), new_root(4), new_node_value(4)]
	let left_old_root =
		&left_proof_target.public_inputs[OLD_ROOT_START..OLD_ROOT_START + HASH_SIZE];
	let left_new_root =
		&left_proof_target.public_inputs[NEW_ROOT_START..NEW_ROOT_START + HASH_SIZE];
	let right_old_root =
		&right_proof_target.public_inputs[OLD_ROOT_START..OLD_ROOT_START + HASH_SIZE];
	let right_new_root =
		&right_proof_target.public_inputs[NEW_ROOT_START..NEW_ROOT_START + HASH_SIZE];

	// Chaining constraint: left.new_root == right.old_root
	for i in 0..HASH_SIZE {
		builder.connect(left_new_root[i], right_old_root[i]);
	}

	// Register public inputs: (left.old_root, right.new_root)
	// This is the information needed by the next level
	builder.register_public_inputs(left_old_root);
	builder.register_public_inputs(right_new_root);

	// Build the aggregation circuit
	let circuit_data = builder.build::<C>();

	// Create witness
	let mut pw = PartialWitness::new();
	pw.set_verifier_data_target(&verifier_data_target, verifier_data)?;
	pw.set_proof_with_pis_target(&left_proof_target, left)?;
	pw.set_proof_with_pis_target(&right_proof_target, right)?;

	// Generate the aggregated proof
	let proof = circuit_data.prove(pw)?;

	Ok(AggregatedProof {
		proof,
		circuit_data,
	})
}

/// Aggregates a vector of proofs into a single proof using a binary tree.
///
/// The proofs must be sequential with chained roots:
/// - `proofs[0].new_root == proofs[1].old_root`
/// - `proofs[1].new_root == proofs[2].old_root`
/// - etc.
///
/// # Arguments
/// * `leaf_proofs` - Vector of leaf proofs (must be a power of 2)
/// * `common_data` - Common circuit data for the leaf proofs
/// * `verifier_data` - Verifier-only circuit data for the leaf proofs
///
/// # Returns
/// Final aggregated proof with public inputs `(first_old_root, last_new_root)`
pub fn aggregate_to_tree<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
	leaf_proofs: Vec<ProofWithPublicInputs<F, C, D>>,
	common_data: &CommonCircuitData<F, D>,
	verifier_data: &VerifierOnlyCircuitData<C, D>,
) -> Result<AggregatedProof<F, C, D>>
where
	C::Hasher: plonky2::plonk::config::AlgebraicHasher<F>,
{
	if leaf_proofs.is_empty() {
		bail!("Cannot aggregate empty proof list");
	}

	if !leaf_proofs.len().is_power_of_two() {
		bail!(
			"Number of proofs must be a power of 2, got {}",
			leaf_proofs.len()
		);
	}

	// Single proof case - wrap it in an AggregatedProof
	// (In practice, you'd want at least 2 proofs)
	if leaf_proofs.len() == 1 {
		bail!("Need at least 2 proofs to aggregate");
	}

	println!(
		"Aggregating {} leaf proofs in {} levels",
		leaf_proofs.len(),
		(leaf_proofs.len() as f64).log2() as usize
	);

	// Level 0: Aggregate leaf proofs pairwise
	let mut current_level: Vec<AggregatedProof<F, C, D>> = leaf_proofs
		.chunks(2)
		.enumerate()
		.map(|(i, pair)| {
			println!("  Level 0, pair {}: aggregating...", i);
			aggregate_pair(&pair[0], &pair[1], common_data, verifier_data)
		})
		.collect::<Result<Vec<_>>>()?;

	println!(
		"  Level 0 complete: {} aggregated proofs",
		current_level.len()
	);

	// Subsequent levels: aggregate using previous level's circuit data
	let mut level = 1;
	while current_level.len() > 1 {
		// All proofs at this level use the same circuit
		let level_common = current_level[0].circuit_data.common.clone();
		let level_verifier = current_level[0].circuit_data.verifier_only.clone();

		let next_level: Vec<AggregatedProof<F, C, D>> = current_level
			.chunks(2)
			.enumerate()
			.map(|(i, pair)| {
				println!("  Level {}, pair {}: aggregating...", level, i);
				aggregate_pair(
					&pair[0].proof,
					&pair[1].proof,
					&level_common,
					&level_verifier,
				)
			})
			.collect::<Result<Vec<_>>>()?;

		println!(
			"  Level {} complete: {} aggregated proofs",
			level,
			next_level.len()
		);

		current_level = next_level;
		level += 1;
	}

	// Return the single root proof
	Ok(current_level.into_iter().next().unwrap())
}

#[cfg(test)]
mod tests {
	use std::time::Instant;

	use anyhow::Result;
	use plonky2::{
		field::{goldilocks_field::GoldilocksField, types::PrimeField64},
		iop::witness::PartialWitness,
		plonk::{
			circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
			config::PoseidonGoldilocksConfig,
		},
	};

	use super::aggregate_to_tree;
	use crate::tree::{
		NullifierInsertProof, NullifierInsertProofTargets, NullifierTree,
		hasher::{HashOutput, MerkleHashCircuit, NewFromU64},
	};

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = GoldilocksField;

	// Note: make_node removed - use Hash::new_from_u64 directly for insert_leaf

	/// Builds the leaf circuit and returns (circuit_data, targets)
	fn build_insert_circuit(
		depth: usize,
	) -> (
		plonky2::plonk::circuit_data::CircuitData<F, C, D>,
		NullifierInsertProofTargets<4>,
	) {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let ctx = HashOutput::register_luts(&mut builder);
		let targets =
			NullifierInsertProofTargets::new::<HashOutput, F, D>(&mut builder, depth, true, true);
		targets.connect::<HashOutput, F, D>(&mut builder, &ctx);
		let circuit_data = builder.build::<C>();
		(circuit_data, targets)
	}

	#[test]
	fn test_aggregate_8_proofs() -> Result<()> {
		const DEPTH: usize = 8; // Small depth for faster testing
		const NUM_PROOFS: usize = 8;

		println!(
			"=== Aggregation Test: {} proofs, depth {} ===\n",
			NUM_PROOFS, DEPTH
		);

		// 1. Create tree and generate sequential insertion proofs
		println!(
			"Step 1: Creating tree and generating {} insertion proofs",
			NUM_PROOFS
		);
		let now = Instant::now();
		let mut tree: NullifierTree<HashOutput> = NullifierTree::<HashOutput>::new(DEPTH);
		let mut insert_proofs: Vec<NullifierInsertProof<HashOutput>> =
			Vec::with_capacity(NUM_PROOFS);

		for i in 0..NUM_PROOFS {
			let value = HashOutput::new_from_u64((i + 1) as u64 * 100);
			let proof = tree.insert(value)?;
			assert!(proof.verify(), "Native proof {} verification failed", i);

			// Verify chaining
			if let Some(prev) = insert_proofs.last() {
				assert_eq!(
					prev.new_root, proof.old_root,
					"Proof {} not chained correctly",
					i
				);
			}

			insert_proofs.push(proof);
		}
		println!("  Generated {} proofs in {:?}", NUM_PROOFS, now.elapsed());

		// Verify overall chain
		let initial_root = insert_proofs[0].old_root;
		let final_root = insert_proofs.last().unwrap().new_root;
		println!("  Initial root: {}", initial_root);
		println!("  Final root: {}", final_root);

		// 2. Build the leaf circuit
		println!("\nStep 2: Building leaf circuit");
		let now = Instant::now();
		let (leaf_circuit_data, targets) = build_insert_circuit(DEPTH);
		println!("  Built in {:?}", now.elapsed());

		// 3. Generate leaf circuit proofs
		println!("\nStep 3: Generating {} leaf circuit proofs", NUM_PROOFS);
		let now = Instant::now();
		let mut leaf_circuit_proofs = Vec::with_capacity(NUM_PROOFS);

		for (i, proof) in insert_proofs.iter().enumerate() {
			let mut pw = PartialWitness::new();
			targets.set::<HashOutput, F, D, DEPTH>(&mut pw, proof)?;
			let circuit_proof = leaf_circuit_data.prove(pw)?;
			leaf_circuit_proofs.push(circuit_proof);
			println!("  Proof {} generated", i);
		}
		println!("  All proofs generated in {:?}", now.elapsed());

		// 4. Aggregate proofs
		println!("\nStep 4: Aggregating proofs into tree");
		let now = Instant::now();
		let aggregated = aggregate_to_tree(
			leaf_circuit_proofs,
			&leaf_circuit_data.common,
			&leaf_circuit_data.verifier_only,
		)?;
		println!("  Aggregation complete in {:?}", now.elapsed());

		// 5. Verify the aggregated proof
		println!("\nStep 5: Verifying aggregated proof");
		let now = Instant::now();
		aggregated.circuit_data.verify(aggregated.proof.clone())?;
		println!("  Verification passed in {:?}", now.elapsed());

		// 6. Check public inputs
		println!("\nStep 6: Checking public inputs");
		let pi = aggregated.public_inputs();
		println!("  Public inputs length: {}", pi.len());
		println!("  Expected: 8 (old_root: 4, new_root: 4)");

		// Convert back to Hash for comparison
		let agg_old_root: [u64; 4] = [
			pi[0].to_canonical_u64(),
			pi[1].to_canonical_u64(),
			pi[2].to_canonical_u64(),
			pi[3].to_canonical_u64(),
		];
		let agg_new_root: [u64; 4] = [
			pi[4].to_canonical_u64(),
			pi[5].to_canonical_u64(),
			pi[6].to_canonical_u64(),
			pi[7].to_canonical_u64(),
		];

		println!("  Aggregated old_root: {:?}", agg_old_root);
		println!("  Expected old_root:   {:?}", initial_root.to_u64());
		println!("  Aggregated new_root: {:?}", agg_new_root);
		println!("  Expected new_root:   {:?}", final_root.to_u64());

		assert_eq!(agg_old_root, initial_root.to_u64(), "Old root mismatch");
		assert_eq!(agg_new_root, final_root.to_u64(), "New root mismatch");

		// 7. Print proof size
		let proof_bytes = aggregated.proof.to_bytes();
		println!("\nProof size: {} KB", proof_bytes.len() / 1024);

		println!("\n=== All checks passed! ===");
		Ok(())
	}

	#[test]
	fn test_aggregate_2_proofs() -> Result<()> {
		const DEPTH: usize = 8;

		println!("=== Simple 2-proof aggregation test ===\n");

		// Create tree and 2 proofs
		let mut tree: NullifierTree<HashOutput> = NullifierTree::<HashOutput>::new(DEPTH);

		let value1 = HashOutput::new_from_u64(100);
		let proof1 = tree.insert(value1)?;
		assert!(proof1.verify());

		let value2 = HashOutput::new_from_u64(200);
		let proof2 = tree.insert(value2)?;
		assert!(proof2.verify());

		// Verify chaining
		assert_eq!(proof1.new_root, proof2.old_root, "Proofs not chained");

		let initial_root = proof1.old_root;
		let final_root = proof2.new_root;

		// Build circuit and generate proofs
		let (leaf_circuit_data, targets) = build_insert_circuit(DEPTH);

		let mut pw1 = PartialWitness::new();
		targets.set::<HashOutput, F, D, DEPTH>(&mut pw1, &proof1)?;
		let circuit_proof1 = leaf_circuit_data.prove(pw1)?;

		let mut pw2 = PartialWitness::new();
		targets.set::<HashOutput, F, D, DEPTH>(&mut pw2, &proof2)?;
		let circuit_proof2 = leaf_circuit_data.prove(pw2)?;

		// Aggregate
		let aggregated = aggregate_to_tree(
			vec![circuit_proof1, circuit_proof2],
			&leaf_circuit_data.common,
			&leaf_circuit_data.verifier_only,
		)?;

		// Verify
		aggregated.circuit_data.verify(aggregated.proof.clone())?;

		// Check roots
		let pi = aggregated.public_inputs();
		let agg_old_root: [u64; 4] = [
			pi[0].to_canonical_u64(),
			pi[1].to_canonical_u64(),
			pi[2].to_canonical_u64(),
			pi[3].to_canonical_u64(),
		];
		let agg_new_root: [u64; 4] = [
			pi[4].to_canonical_u64(),
			pi[5].to_canonical_u64(),
			pi[6].to_canonical_u64(),
			pi[7].to_canonical_u64(),
		];

		assert_eq!(agg_old_root, initial_root.to_u64());
		assert_eq!(agg_new_root, final_root.to_u64());

		println!("2-proof aggregation test passed!");
		Ok(())
	}
}
