//! Streaming proof aggregator for concurrent, eager aggregation.
//!
//! This module provides a stateful aggregator that can receive proofs
//! from multiple threads and aggregate them as soon as pairs are available,
//! without waiting for a full batch.
//!
//! # Example
//!
//! ```ignore
//! // Create aggregator expecting 8 proofs (depth 3)
//! let aggregator = StreamingAggregator::new(leaf_common, leaf_verifier, 3);
//!
//! // Submit proofs from multiple threads
//! for proof in proofs {
//!     aggregator.submit(proof);
//! }
//!
//! // Wait for the final aggregated proof
//! let root_proof = aggregator.take_result()?;
//! ```

use std::sync::{
	Arc, Mutex, RwLock,
	mpsc::{self, Receiver, SyncSender},
};

use anyhow::{Result, bail};
use plonky2::{
	field::extension::Extendable,
	hash::hash_types::RichField,
	iop::witness::{PartialWitness, WitnessWrite},
	plonk::{
		circuit_builder::CircuitBuilder,
		circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
		config::{AlgebraicHasher, GenericConfig},
		proof::ProofWithPublicInputs,
	},
};
use rayon::ThreadPool;

use super::{HASH_SIZE, NEW_ROOT_START, OLD_ROOT_START};

/// Cached circuit data for an aggregation level.
///
/// This is built once (lazily or eagerly) and reused for all aggregations
/// at that level.
pub struct AggregationCircuit<
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F>,
	const D: usize,
> {
	pub circuit_data: CircuitData<F, C, D>,
	pub left_proof_target: plonky2::plonk::proof::ProofWithPublicInputsTarget<D>,
	pub right_proof_target: plonky2::plonk::proof::ProofWithPublicInputsTarget<D>,
	pub verifier_data_target: plonky2::plonk::circuit_data::VerifierCircuitTarget,
}

/// Result of streaming aggregation, containing the proof and a reference to the circuit.
pub struct StreamingAggregatedProof<
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F>,
	const D: usize,
> {
	/// The aggregated proof
	pub proof: ProofWithPublicInputs<F, C, D>,
	/// Reference to the circuit used to create this proof
	pub circuit: Arc<AggregationCircuit<F, C, D>>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
	StreamingAggregatedProof<F, C, D>
{
	/// Verifies this proof.
	pub fn verify(&self) -> anyhow::Result<()> {
		self.circuit.circuit_data.verify(self.proof.clone())?;
		Ok(())
	}

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

	/// Returns the circuit data for external verification
	pub fn circuit_data(&self) -> &CircuitData<F, C, D> {
		&self.circuit.circuit_data
	}
}

/// Internal state for a single level of the aggregation tree.
///
/// Proofs are tracked by their position to ensure correct pairing even
/// when aggregation completes out of order.
struct LevelState<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
	/// Proofs waiting for their sibling, keyed by position.
	/// Position 2k pairs with position 2k+1.
	pending: std::collections::HashMap<usize, ProofWithPublicInputs<F, C, D>>,
	/// Count of pairs aggregated at this level
	pairs_completed: usize,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> Default
	for LevelState<F, C, D>
{
	fn default() -> Self {
		Self {
			pending: std::collections::HashMap::new(),
			pairs_completed: 0,
		}
	}
}

/// A streaming, concurrent proof aggregator.
///
/// Proofs can be submitted from multiple threads. Aggregation happens
/// eagerly as soon as pairs are available at any level.
pub struct StreamingAggregator<
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F>,
	const D: usize,
> {
	/// Leaf circuit data (for verifying incoming leaf proofs)
	leaf_common: Arc<CommonCircuitData<F, D>>,
	leaf_verifier: Arc<VerifierOnlyCircuitData<C, D>>,

	/// Per-level state: pending proof waiting for its pair
	/// Index 0 = leaf level, index N = root level
	levels: Vec<Mutex<LevelState<F, C, D>>>,

	/// Cached aggregation circuits per level (built lazily or eagerly)
	/// Index 0 = circuit for aggregating leaf proofs
	/// Index 1 = circuit for aggregating level-0 aggregated proofs
	/// etc.
	#[allow(clippy::type_complexity)]
	level_circuits: Vec<RwLock<Option<Arc<AggregationCircuit<F, C, D>>>>>,

	/// Channel to send the final root proof
	result_tx: SyncSender<StreamingAggregatedProof<F, C, D>>,

	/// Receiver for the final root proof (wrapped in Mutex for take semantics)
	result_rx: Mutex<Option<Receiver<StreamingAggregatedProof<F, C, D>>>>,

	/// Tree depth (log2 of expected total proofs)
	/// depth=3 means 8 proofs, 3 levels of aggregation
	depth: usize,

	/// Thread pool for parallel aggregation
	pool: ThreadPool,
}

impl<F, C, const D: usize> StreamingAggregator<F, C, D>
where
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F> + 'static,
	C::Hasher: AlgebraicHasher<F>,
{
	/// Creates a new streaming aggregator with lazy circuit building.
	///
	/// Circuits for each aggregation level are built on first use.
	///
	/// # Arguments
	/// * `leaf_common` - Common circuit data for leaf proofs
	/// * `leaf_verifier` - Verifier data for leaf proofs
	/// * `depth` - Tree depth (expects 2^depth leaf proofs)
	pub fn new(
		leaf_common: CommonCircuitData<F, D>,
		leaf_verifier: VerifierOnlyCircuitData<C, D>,
		depth: usize,
	) -> Arc<Self> {
		Self::with_thread_pool(
			leaf_common,
			leaf_verifier,
			depth,
			rayon::ThreadPoolBuilder::new()
				.build()
				.expect("Failed to create thread pool"),
		)
	}

	/// Creates a new streaming aggregator with a custom thread pool.
	pub fn with_thread_pool(
		leaf_common: CommonCircuitData<F, D>,
		leaf_verifier: VerifierOnlyCircuitData<C, D>,
		depth: usize,
		pool: ThreadPool,
	) -> Arc<Self> {
		let (result_tx, result_rx) = mpsc::sync_channel(1);

		let levels: Vec<_> = (0..depth)
			.map(|_| Mutex::new(LevelState::default()))
			.collect();

		let level_circuits: Vec<_> = (0..depth).map(|_| RwLock::new(None)).collect();

		Arc::new(Self {
			leaf_common: Arc::new(leaf_common),
			leaf_verifier: Arc::new(leaf_verifier),
			levels,
			level_circuits,
			result_tx,
			result_rx: Mutex::new(Some(result_rx)),
			depth,
			pool,
		})
	}

	/// Creates a new streaming aggregator with eagerly pre-built circuits.
	///
	/// All aggregation circuits are built upfront, which takes longer to
	/// initialize but provides consistent performance during aggregation.
	///
	/// # Arguments
	/// * `leaf_common` - Common circuit data for leaf proofs
	/// * `leaf_verifier` - Verifier data for leaf proofs
	/// * `depth` - Tree depth (expects 2^depth leaf proofs)
	pub fn new_eager(
		leaf_common: CommonCircuitData<F, D>,
		leaf_verifier: VerifierOnlyCircuitData<C, D>,
		depth: usize,
	) -> Arc<Self> {
		let aggregator = Self::new(leaf_common, leaf_verifier, depth);

		// Pre-build all circuits
		println!("Pre-building {} aggregation circuits...", depth);

		// Build level 0 circuit (aggregates leaf proofs)
		let level0_circuit = Self::build_aggregation_circuit(&aggregator.leaf_common);
		let mut current_common = level0_circuit.circuit_data.common.clone();
		*aggregator.level_circuits[0].write().unwrap() = Some(Arc::new(level0_circuit));
		println!("  Level 0 circuit built");

		// Build subsequent level circuits
		for level in 1..depth {
			let circuit = Self::build_aggregation_circuit(&current_common);
			current_common = circuit.circuit_data.common.clone();
			*aggregator.level_circuits[level].write().unwrap() = Some(Arc::new(circuit));
			println!("  Level {} circuit built", level);
		}

		println!("All circuits pre-built");
		aggregator
	}

	/// Builds an aggregation circuit for a given child circuit.
	fn build_aggregation_circuit(
		child_common: &CommonCircuitData<F, D>,
	) -> AggregationCircuit<F, C, D> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		// Add verifier data target (shared by both child proofs)
		let verifier_data_target =
			builder.add_virtual_verifier_data(child_common.fri_params.config.cap_height);

		// Add and verify left proof
		let left_proof_target = builder.add_virtual_proof_with_pis(child_common);
		builder.verify_proof::<C>(&left_proof_target, &verifier_data_target, child_common);

		// Add and verify right proof
		let right_proof_target = builder.add_virtual_proof_with_pis(child_common);
		builder.verify_proof::<C>(&right_proof_target, &verifier_data_target, child_common);

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
		builder.register_public_inputs(left_old_root);
		builder.register_public_inputs(right_new_root);

		let circuit_data = builder.build::<C>();

		AggregationCircuit {
			circuit_data,
			left_proof_target,
			right_proof_target,
			verifier_data_target,
		}
	}

	/// Gets or builds the aggregation circuit for a given level.
	fn get_or_build_circuit(
		self: &Arc<Self>,
		level: usize,
		child_common: &CommonCircuitData<F, D>,
	) -> Arc<AggregationCircuit<F, C, D>> {
		// Fast path: check if already cached
		{
			let cache = self.level_circuits[level].read().unwrap();
			if let Some(circuit) = cache.as_ref() {
				return circuit.clone();
			}
		}

		// Slow path: build and cache
		let mut cache = self.level_circuits[level].write().unwrap();
		// Double-check after acquiring write lock
		if let Some(circuit) = cache.as_ref() {
			return circuit.clone();
		}

		let circuit = Arc::new(Self::build_aggregation_circuit(child_common));
		*cache = Some(circuit.clone());
		circuit
	}

	/// Submits a leaf proof for aggregation at a specific position.
	///
	/// This method is thread-safe and can be called from multiple threads.
	/// Aggregation happens automatically when pairs are available.
	///
	/// # Arguments
	/// * `position` - The leaf index (0, 1, 2, ..., 2^depth - 1)
	/// * `proof` - The leaf proof to aggregate
	pub fn submit_with_position(
		self: &Arc<Self>,
		position: usize,
		proof: ProofWithPublicInputs<F, C, D>,
	) {
		self.submit_at_level(0, position, proof);
	}

	/// Submits leaf proofs in order (0, 1, 2, ...).
	///
	/// This is a convenience method that tracks position internally.
	///
	/// **WARNING**: This method is NOT safe for concurrent calls from multiple
	/// threads. For concurrent submission, use `submit_with_position` instead.
	///
	/// Proofs MUST be submitted in sequential order when using this method.
	pub fn submit(self: &Arc<Self>, proof: ProofWithPublicInputs<F, C, D>) {
		// Use pairs_completed at level 0 to track how many have been submitted
		let position = {
			let state = self.levels[0].lock().unwrap();
			// Position = 2 * pairs_completed + pending.len()
			state.pairs_completed * 2 + state.pending.len()
		};
		self.submit_at_level(0, position, proof);
	}

	/// Internal: submits a proof at a specific level and position.
	///
	/// Position at level N corresponds to which "slot" in the tree this proof occupies.
	/// Positions 2k and 2k+1 form a pair that will be aggregated together.
	fn submit_at_level(
		self: &Arc<Self>,
		level: usize,
		position: usize,
		proof: ProofWithPublicInputs<F, C, D>,
	) {
		// Sibling position: 0↔1, 2↔3, 4↔5, etc. (XOR with 1)
		let sibling_position = position ^ 1;

		let pair = {
			let mut state = self.levels[level].lock().unwrap();

			if let Some(sibling) = state.pending.remove(&sibling_position) {
				// Sibling exists! Form a pair with correct ordering.
				state.pairs_completed += 1;

				// Left is the one with smaller (even) position
				if position < sibling_position {
					Some((position, proof, sibling))
				} else {
					Some((sibling_position, sibling, proof))
				}
			} else {
				// No sibling yet, store as pending
				state.pending.insert(position, proof);
				None
			}
		};

		// Spawn aggregation task outside the lock
		if let Some((left_position, left, right)) = pair {
			let this = Arc::clone(self);
			// Result position at next level = left_position / 2
			let result_position = left_position / 2;
			self.pool.spawn(move || {
				this.aggregate_pair(level, result_position, left, right);
			});
		}
	}

	/// Aggregates a pair of proofs at the given level.
	///
	/// # Arguments
	/// * `level` - The aggregation level (0 = aggregating leaf proofs)
	/// * `result_position` - The position of the result at the next level
	/// * `left` - The left (earlier) proof
	/// * `right` - The right (later) proof
	fn aggregate_pair(
		self: &Arc<Self>,
		level: usize,
		result_position: usize,
		left: ProofWithPublicInputs<F, C, D>,
		right: ProofWithPublicInputs<F, C, D>,
	) {
		// Get child circuit data for this level
		let (child_common, child_verifier) = if level == 0 {
			(
				Arc::clone(&self.leaf_common),
				Arc::clone(&self.leaf_verifier),
			)
		} else {
			// For higher levels, get from the previous level's cached circuit
			let prev_circuit = self.level_circuits[level - 1]
				.read()
				.unwrap()
				.as_ref()
				.expect("Previous level circuit should exist")
				.clone();
			(
				Arc::new(prev_circuit.circuit_data.common.clone()),
				Arc::new(prev_circuit.circuit_data.verifier_only.clone()),
			)
		};

		// Get or build the aggregation circuit for this level
		let agg_circuit = self.get_or_build_circuit(level, &child_common);

		// Create witness and prove
		let mut pw = PartialWitness::new();
		pw.set_verifier_data_target(&agg_circuit.verifier_data_target, &child_verifier)
			.expect("Failed to set verifier data");
		pw.set_proof_with_pis_target(&agg_circuit.left_proof_target, &left)
			.expect("Failed to set left proof");
		pw.set_proof_with_pis_target(&agg_circuit.right_proof_target, &right)
			.expect("Failed to set right proof");

		let proof = agg_circuit
			.circuit_data
			.prove(pw)
			.expect("Failed to prove aggregation");

		// Check if this is the root level
		if level + 1 == self.depth {
			// We're done! Send the root proof
			let aggregated = StreamingAggregatedProof {
				proof,
				circuit: agg_circuit,
			};
			let _ = self.result_tx.send(aggregated);
		} else {
			// Submit to the next level with the computed result position
			self.submit_at_level(level + 1, result_position, proof);
		}
	}

	/// Blocks until the final aggregated proof is ready and returns it.
	///
	/// This method can only be called once. Subsequent calls will return an error.
	pub fn take_result(&self) -> Result<StreamingAggregatedProof<F, C, D>> {
		let rx = self
			.result_rx
			.lock()
			.unwrap()
			.take()
			.ok_or_else(|| anyhow::anyhow!("Result already taken"))?;

		rx.recv()
			.map_err(|_| anyhow::anyhow!("Aggregation failed or was cancelled"))
	}

	/// Non-blocking check if the result is ready.
	pub fn try_result(&self) -> Result<Option<StreamingAggregatedProof<F, C, D>>> {
		let guard = self.result_rx.lock().unwrap();
		if let Some(rx) = guard.as_ref() {
			match rx.try_recv() {
				Ok(result) => Ok(Some(result)),
				Err(mpsc::TryRecvError::Empty) => Ok(None),
				Err(mpsc::TryRecvError::Disconnected) => {
					bail!("Aggregation channel disconnected")
				},
			}
		} else {
			bail!("Result already taken")
		}
	}

	/// Returns the expected number of leaf proofs.
	pub fn expected_proofs(&self) -> usize {
		1 << self.depth
	}

	/// Returns the tree depth.
	pub fn depth(&self) -> usize {
		self.depth
	}

	/// Returns the current status of each level.
	pub fn status(&self) -> Vec<LevelStatus> {
		self.levels
			.iter()
			.enumerate()
			.map(|(i, level)| {
				let state = level.lock().unwrap();
				LevelStatus {
					level: i,
					pending_count: state.pending.len(),
					pairs_completed: state.pairs_completed,
					circuit_built: self.level_circuits[i].read().unwrap().is_some(),
				}
			})
			.collect()
	}
}

/// Status information for a single aggregation level.
#[derive(Debug, Clone)]
pub struct LevelStatus {
	pub level: usize,
	pub pending_count: usize,
	pub pairs_completed: usize,
	pub circuit_built: bool,
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

	use super::StreamingAggregator;
	use crate::tree::{
		NullifierInsertProof, NullifierInsertProofTargets, NullifierTree,
		hasher::{Hash, NewFromU64},
	};

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = GoldilocksField;

	// Note: make_node removed - use Hash::new_from_u64 directly for insert_leaf

	fn build_insert_circuit(
		depth: usize,
	) -> (
		plonky2::plonk::circuit_data::CircuitData<F, C, D>,
		NullifierInsertProofTargets,
	) {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let targets = NullifierInsertProofTargets::new(&mut builder, depth, true, true);
		targets.connect::<Hash, F, D>(&mut builder);
		let circuit_data = builder.build::<C>();
		(circuit_data, targets)
	}

	#[test]
	fn test_streaming_aggregator_lazy() -> Result<()> {
		const DEPTH: usize = 8;
		const TREE_DEPTH: usize = 3;
		const NUM_PROOFS: usize = 1 << TREE_DEPTH;

		println!("=== Streaming Aggregator Test (Lazy) ===\n");

		// 1. Generate leaf proofs
		println!("Step 1: Generating {} insertion proofs", NUM_PROOFS);
		let now = Instant::now();
		let mut tree: NullifierTree<Hash> = NullifierTree::new(DEPTH);
		let mut insert_proofs: Vec<NullifierInsertProof<Hash>> = Vec::with_capacity(NUM_PROOFS);

		for i in 0..NUM_PROOFS {
			let value = Hash::new_from_u64((i + 1) as u64 * 100);
			let proof = tree.insert(value)?;
			insert_proofs.push(proof);
		}

		let initial_root = insert_proofs[0].old_root;
		let final_root = insert_proofs.last().unwrap().new_root;
		println!("  Generated in {:?}", now.elapsed());

		// 2. Build leaf circuit
		println!("\nStep 2: Building leaf circuit");
		let now = Instant::now();
		let (leaf_circuit_data, targets) = build_insert_circuit(DEPTH);
		println!("  Built in {:?}", now.elapsed());

		// 3. Create streaming aggregator (lazy)
		println!("\nStep 3: Creating streaming aggregator (lazy mode)");
		let now = Instant::now();
		let aggregator = StreamingAggregator::<F, C, D>::new(
			leaf_circuit_data.common.clone(),
			leaf_circuit_data.verifier_only.clone(),
			TREE_DEPTH,
		);
		println!("  Created in {:?}", now.elapsed());
		println!("  Expected proofs: {}", aggregator.expected_proofs());

		// 4. Generate and submit leaf circuit proofs
		println!("\nStep 4: Generating and submitting leaf proofs");
		let now = Instant::now();

		for (i, proof) in insert_proofs.iter().enumerate() {
			let mut pw = PartialWitness::new();
			targets.set::<Hash, F, DEPTH>(&mut pw, proof)?;
			let circuit_proof = leaf_circuit_data.prove(pw)?;

			println!("  Submitting proof {}", i);
			aggregator.submit(circuit_proof);

			// Print status after each submission
			for status in aggregator.status() {
				if status.pairs_completed > 0 || status.pending_count > 0 {
					println!(
						"    Level {}: pending={}, completed={}, circuit={}",
						status.level,
						status.pending_count,
						status.pairs_completed,
						status.circuit_built
					);
				}
			}
		}
		println!("  All proofs submitted in {:?}", now.elapsed());

		// 5. Wait for result
		println!("\nStep 5: Waiting for final proof");
		let now = Instant::now();
		let result = aggregator.take_result()?;
		println!("  Got result in {:?}", now.elapsed());

		// 6. Verify
		println!("\nStep 6: Verifying final proof");
		result.verify()?;

		// Check roots and num_leaves
		let pi = result.public_inputs();
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

		assert_eq!(agg_old_root, initial_root.to_u64(), "Old root mismatch");
		assert_eq!(agg_new_root, final_root.to_u64(), "New root mismatch");
		println!("\n=== Streaming aggregator test passed! ===");
		Ok(())
	}

	#[test]
	fn test_streaming_aggregator_eager() -> Result<()> {
		const DEPTH: usize = 8;
		const TREE_DEPTH: usize = 3; // log2(4) = 2
		const NUM_PROOFS: usize = 1 << TREE_DEPTH;

		println!("=== Streaming Aggregator Test (Eager) ===\n");

		// 1. Generate leaf proofs
		let mut tree: NullifierTree<Hash> = NullifierTree::new(DEPTH);
		let mut insert_proofs: Vec<NullifierInsertProof<Hash>> = Vec::with_capacity(NUM_PROOFS);

		for i in 0..NUM_PROOFS {
			let value = Hash::new_from_u64((i + 1) as u64 * 100);
			let proof = tree.insert(value)?;
			insert_proofs.push(proof);
		}

		let initial_root: Hash = insert_proofs[0].old_root;
		let final_root: Hash = insert_proofs.last().unwrap().new_root;

		// 2. Build leaf circuit
		let (leaf_circuit_data, targets) = build_insert_circuit(DEPTH);

		// 3. Create streaming aggregator (eager - pre-build all circuits)
		println!("Creating aggregator with eager initialization...");
		let now = Instant::now();
		let aggregator = StreamingAggregator::<F, C, D>::new_eager(
			leaf_circuit_data.common.clone(),
			leaf_circuit_data.verifier_only.clone(),
			TREE_DEPTH,
		);
		println!("Eager init completed in {:?}\n", now.elapsed());

		// Verify all circuits are pre-built
		for status in aggregator.status() {
			assert!(
				status.circuit_built,
				"Level {} circuit not built",
				status.level
			);
		}

		// 4. Submit proofs
		println!("Submitting {} proofs...", NUM_PROOFS);
		let now = Instant::now();
		for (i, proof) in insert_proofs.iter().enumerate() {
			let mut pw = PartialWitness::new();
			targets.set::<Hash, F, DEPTH>(&mut pw, proof)?;
			let circuit_proof = leaf_circuit_data.prove(pw)?;
			aggregator.submit(circuit_proof);
			println!("  Proof {} submitted", i);
		}

		// 5. Get result
		let result = aggregator.take_result()?;
		println!("Aggregation completed in {:?}", now.elapsed());

		// Verify
		result.verify()?;

		let pi = result.public_inputs();
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

		println!("\n=== Eager aggregator test passed! ===");
		Ok(())
	}
}
