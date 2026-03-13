use std::{
	cmp::Ordering,
	fmt::{Debug, Display},
};

use anyhow::Result;
use plonky2::{
	field::{
		goldilocks_field::GoldilocksField,
		types::{Field, PrimeField64},
	},
	iop::{
		target::{BoolTarget, Target},
		witness::PartialWitness,
	},
	plonk::circuit_builder::CircuitBuilder,
};
use serde::{Deserialize, Serialize};

use super::hasher::{MerkleHash, MerkleHashCircuit, MerkleHashTarget};
use crate::{
	ConfigNative, F,
	plonky2_gadgets::{
		keccak256::{builder::BuilderKeccak256, utils::solidity_keccak256},
		sha256::circuit::decompose_field_to_u32_pair,
		u32::add_u8_range_check_lookup_table,
	},
};

/// Keccak-256 hash output: 8 field elements, each holding one u32 word
/// (via `F::from_canonical_u32`).
#[derive(Clone, Copy, Eq, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct KeccakHashOutput(pub [F; 8]);

impl KeccakHashOutput {
	/// Create from 8 u32 words (the raw keccak output).
	pub fn from_u32_array(words: [u32; 8]) -> Self {
		Self(words.map(F::from_canonical_u32))
	}

	/// Extract 8 u32 words from the field elements.
	pub fn to_u32_array(&self) -> [u32; 8] {
		core::array::from_fn(|i| self.0[i].to_canonical_u64() as u32)
	}
}

impl PartialOrd for KeccakHashOutput {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

impl Ord for KeccakHashOutput {
	fn cmp(&self, other: &Self) -> Ordering {
		let a = self.to_u32_array();
		let b = other.to_u32_array();
		a.cmp(&b)
	}
}

impl Display for KeccakHashOutput {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "0x")?;
		for &elem in &self.0 {
			write!(f, "{:08x}", elem.to_canonical_u64() as u32)?;
		}
		Ok(())
	}
}

// ---------------------------------------------------------------------------
// Helper: convert 8 field elements → 8 u32 words for keccak input
// ---------------------------------------------------------------------------

fn fields_to_u32_words(fields: &[F; 8]) -> [u32; 8] {
	core::array::from_fn(|i| fields[i].to_canonical_u64() as u32)
}

// ---------------------------------------------------------------------------
// MerkleHash implementation (native)
// ---------------------------------------------------------------------------

impl MerkleHash for KeccakHashOutput {
	type Digest = KeccakHashOutput;

	const HEAD: Self::Digest = KeccakHashOutput([F::ZERO; 8]);
	// TAIL: max u32 in each element. GoldilocksField(u32::MAX as u64) is
	// canonical since u32::MAX < Goldilocks prime.
	const TAIL: Self::Digest = KeccakHashOutput([GoldilocksField(u32::MAX as u64); 8]);

	fn hash_2_to_1(left: &Self::Digest, right: &Self::Digest, dir: bool) -> Self::Digest {
		let (l, r) = if dir { (right, left) } else { (left, right) };
		let mut input = [0u32; 16];
		input[..8].copy_from_slice(&fields_to_u32_words(&l.0));
		input[8..].copy_from_slice(&fields_to_u32_words(&r.0));
		KeccakHashOutput::from_u32_array(solidity_keccak256(&input))
	}

	fn hash_root(num_leaves: usize, left: &Self::Digest, right: &Self::Digest) -> Self::Digest {
		let mut input = [0u32; 18];
		input[0] = (num_leaves as u64 >> 32) as u32;
		input[1] = num_leaves as u32;
		input[2..10].copy_from_slice(&fields_to_u32_words(&left.0));
		input[10..18].copy_from_slice(&fields_to_u32_words(&right.0));
		KeccakHashOutput::from_u32_array(solidity_keccak256(&input))
	}

	fn commit_node(
		value: &Self::Digest,
		next_index: usize,
		next_value: &Self::Digest,
	) -> Self::Digest {
		let mut input = [0u32; 18];
		input[0] = (next_index as u64 >> 32) as u32;
		input[1] = next_index as u32;
		input[2..10].copy_from_slice(&fields_to_u32_words(&value.0));
		input[10..18].copy_from_slice(&fields_to_u32_words(&next_value.0));
		KeccakHashOutput::from_u32_array(solidity_keccak256(&input))
	}
}

// ---------------------------------------------------------------------------
// Circuit context — holds range-check LUT index
// ---------------------------------------------------------------------------

/// Keccak circuit context — holds the range-check LUT index.
/// Constructed once per circuit via `KeccakHashOutput::register_luts(builder)`.
#[derive(Clone, Copy, Debug)]
pub struct KeccakCircuitContext {
	pub range_lut: usize,
}

// ---------------------------------------------------------------------------
// MerkleHashCircuit implementation (N=8, no packing)
// ---------------------------------------------------------------------------

impl MerkleHashCircuit<F, 2> for KeccakHashOutput {
	type CircuitContext = KeccakCircuitContext;
	type HashTarget = MerkleHashTarget<8>;

	fn digest_elements(d: &Self::Digest) -> &[F] {
		&d.0
	}

	fn register_luts(builder: &mut CircuitBuilder<F, 2>) -> Self::CircuitContext {
		KeccakCircuitContext {
			range_lut: add_u8_range_check_lookup_table(builder),
		}
	}

	fn hash_target_elements(t: &Self::HashTarget) -> &[Target] {
		&t.elements
	}

	fn add_virtual_hash(builder: &mut CircuitBuilder<F, 2>) -> Self::HashTarget {
		MerkleHashTarget::<8>::add_virtual(builder)
	}

	fn add_virtual_hash_public_input(builder: &mut CircuitBuilder<F, 2>) -> Self::HashTarget {
		MerkleHashTarget::<8>::add_virtual_public_input(builder)
	}

	fn constant_hash(builder: &mut CircuitBuilder<F, 2>, value: &Self::Digest) -> Self::HashTarget {
		MerkleHashTarget {
			elements: core::array::from_fn(|i| builder.constant(value.0[i])),
		}
	}

	fn connect_hashes(
		builder: &mut CircuitBuilder<F, 2>,
		a: &Self::HashTarget,
		b: &Self::HashTarget,
	) {
		MerkleHashTarget::connect(builder, a, b);
	}

	fn select_hash(
		builder: &mut CircuitBuilder<F, 2>,
		dir: BoolTarget,
		a: &Self::HashTarget,
		b: &Self::HashTarget,
	) -> Self::HashTarget {
		MerkleHashTarget::select(builder, dir, a, b)
	}

	fn set_hash_witness(
		pw: &mut PartialWitness<F>,
		target: &Self::HashTarget,
		value: &Self::Digest,
	) -> Result<()> {
		MerkleHashTarget::set_witness(pw, target, &value.0)
	}

	fn hash_2_to_1_circuit(
		builder: &mut CircuitBuilder<F, 2>,
		_ctx: &Self::CircuitContext,
		cur: Self::HashTarget,
		sib: Self::HashTarget,
		dir: BoolTarget,
	) -> Self::HashTarget {
		// Elements are already u32 targets — no unpacking needed
		let left = Self::select_hash(builder, dir, &sib, &cur);
		let right = Self::select_hash(builder, dir, &cur, &sib);

		let mut input = Vec::with_capacity(16);
		input.extend_from_slice(&left.elements);
		input.extend_from_slice(&right.elements);
		let hash: [Target; 8] = builder.keccak256::<ConfigNative>(&input);
		MerkleHashTarget {
			elements: hash,
		}
	}

	fn hash_root_circuit(
		builder: &mut CircuitBuilder<F, 2>,
		ctx: &Self::CircuitContext,
		num_leaves: Target,
		left: Self::HashTarget,
		right: Self::HashTarget,
	) -> Self::HashTarget {
		let [nl_hi, nl_lo] = decompose_field_to_u32_pair(builder, num_leaves, ctx.range_lut);

		let mut input = Vec::with_capacity(18);
		input.push(nl_hi.0);
		input.push(nl_lo.0);
		input.extend_from_slice(&left.elements);
		input.extend_from_slice(&right.elements);
		let hash: [Target; 8] = builder.keccak256::<ConfigNative>(&input);
		MerkleHashTarget {
			elements: hash,
		}
	}

	fn commit_node_circuit(
		builder: &mut CircuitBuilder<F, 2>,
		ctx: &Self::CircuitContext,
		value: Self::HashTarget,
		next_index: Target,
		next_value: Self::HashTarget,
	) -> Self::HashTarget {
		let [idx_hi, idx_lo] = decompose_field_to_u32_pair(builder, next_index, ctx.range_lut);

		let mut input = Vec::with_capacity(18);
		input.push(idx_hi.0);
		input.push(idx_lo.0);
		input.extend_from_slice(&value.elements);
		input.extend_from_slice(&next_value.elements);
		let hash: [Target; 8] = builder.keccak256::<ConfigNative>(&input);
		MerkleHashTarget {
			elements: hash,
		}
	}
}

#[cfg(test)]
mod tests {
	use plonky2::iop::witness::WitnessWrite;

	use super::*;

	#[test]
	fn keccak_hash_output_ordering() {
		let a = KeccakHashOutput::from_u32_array([0; 8]);
		let b = KeccakHashOutput::from_u32_array([1, 0, 0, 0, 0, 0, 0, 0]);
		assert!(a < b);
		assert!(a < <KeccakHashOutput as MerkleHash>::TAIL);
		assert_eq!(a, <KeccakHashOutput as MerkleHash>::HEAD);
	}

	#[test]
	fn hash_2_to_1_dir_swap() {
		let left = KeccakHashOutput::from_u32_array([1; 8]);
		let right = KeccakHashOutput::from_u32_array([2; 8]);
		let h_lr = KeccakHashOutput::hash_2_to_1(&left, &right, false);
		let h_rl = KeccakHashOutput::hash_2_to_1(&left, &right, true);
		let h_rl2 = KeccakHashOutput::hash_2_to_1(&right, &left, false);
		assert_eq!(h_rl, h_rl2);
		assert_ne!(h_lr, h_rl);
	}

	#[test]
	fn merkle_tree_basic() {
		use crate::tree::MerkleTree;

		let mut tree = MerkleTree::<KeccakHashOutput>::new(4);
		let leaf = KeccakHashOutput::from_u32_array([42; 8]);
		tree.insert(leaf).unwrap();
		tree.verify().unwrap();
	}

	#[test]
	fn native_merkle_path_depth_25() {
		use crate::tree::MerkleTree;

		let mut tree = MerkleTree::<KeccakHashOutput>::new(25);
		let leaf = KeccakHashOutput::from_u32_array([1, 2, 3, 4, 5, 6, 7, 8]);
		tree.insert(leaf).unwrap();
		tree.verify().unwrap();

		let root = tree.compute_root();
		let siblings = tree.merkle_path(0, 0, 25).unwrap();

		// Recompute root from path
		let mut current = leaf;
		for (level, sibling) in siblings.iter().enumerate() {
			let bit = ((0usize >> level) & 1) == 1; // index=0, all bits false
			if level == 24 {
				let (l, r) = if bit {
					(sibling, &current)
				} else {
					(&current, sibling)
				};
				current = KeccakHashOutput::hash_root(tree.num_leaves(), l, r);
			} else {
				current = KeccakHashOutput::hash_2_to_1(&current, sibling, bit);
			}
		}
		assert_eq!(current, root, "native path recomputation mismatch");
	}

	#[test]
	fn hash_2_to_1_circuit_test() {
		use plonky2::plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig};

		use crate::{ConfigNative, D, F};

		let left = KeccakHashOutput::from_u32_array([1; 8]);
		let right = KeccakHashOutput::from_u32_array([2; 8]);

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let ctx = KeccakHashOutput::register_luts(&mut builder);
		let dir_target = builder.add_virtual_bool_target_safe();
		let left_target = KeccakHashOutput::add_virtual_hash(&mut builder);
		let right_target = KeccakHashOutput::add_virtual_hash(&mut builder);
		let out_target = KeccakHashOutput::add_virtual_hash(&mut builder);
		let have_target = KeccakHashOutput::hash_2_to_1_circuit(
			&mut builder,
			&ctx,
			left_target,
			right_target,
			dir_target,
		);
		KeccakHashOutput::connect_hashes(&mut builder, &have_target, &out_target);

		// Exercise commit_node_circuit to ensure the range-check LUT is used
		// (plonky2 panics on unused LUTs during build)
		let dummy_idx = builder.add_virtual_target();
		let dummy_val = KeccakHashOutput::add_virtual_hash(&mut builder);
		let dummy_next = KeccakHashOutput::add_virtual_hash(&mut builder);
		let _ = KeccakHashOutput::commit_node_circuit(
			&mut builder,
			&ctx,
			dummy_val,
			dummy_idx,
			dummy_next,
		);
		let data = builder.build::<ConfigNative>();

		let dummy_zero = KeccakHashOutput::from_u32_array([0; 8]);
		for dir in [false, true] {
			let out = KeccakHashOutput::hash_2_to_1(&left, &right, dir);
			let mut pw = PartialWitness::new();
			KeccakHashOutput::set_hash_witness(&mut pw, &left_target, &left).unwrap();
			KeccakHashOutput::set_hash_witness(&mut pw, &right_target, &right).unwrap();
			KeccakHashOutput::set_hash_witness(&mut pw, &out_target, &out).unwrap();
			pw.set_bool_target(dir_target, dir).unwrap();
			// Set dummy targets so the prover has all witnesses
			pw.set_target(dummy_idx, F::ZERO).unwrap();
			KeccakHashOutput::set_hash_witness(&mut pw, &dummy_val, &dummy_zero).unwrap();
			KeccakHashOutput::set_hash_witness(&mut pw, &dummy_next, &dummy_zero).unwrap();
			let proof = data.prove(pw).unwrap();
			data.verify(proof).unwrap();
		}
	}

	#[test]
	#[ignore = "slow: 25 keccak STARK proofs in-circuit"]
	fn keccak_merkle_tree_depth_25_circuit() {
		use std::time::Instant;

		use plonky2::{
			field::types::Field,
			iop::witness::{PartialWitness, WitnessWrite},
			plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
		};

		use crate::{ConfigNative, D, F, tree::MerkleTree};

		const DEPTH: usize = 1;

		// ── 1. Native tree ──────────────────────────────────────────
		let t0 = Instant::now();
		let mut tree = MerkleTree::<KeccakHashOutput>::new(DEPTH);
		let leaf = KeccakHashOutput::from_u32_array([1, 2, 3, 4, 5, 6, 7, 8]);
		tree.insert(leaf).unwrap();
		tree.verify().unwrap();

		let root = tree.compute_root();
		let siblings = tree.merkle_path(0, 0, DEPTH).unwrap();
		let leaf_index: usize = 0;
		println!("[1/5] Native tree + path:        {:>8.2?}", t0.elapsed());

		// ── 2. Build circuit using MerkleHashCircuit ─────────────────
		let t1 = Instant::now();
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let ctx = KeccakHashOutput::register_luts(&mut builder);
		let leaf_target = KeccakHashOutput::add_virtual_hash(&mut builder);
		let expected_root = KeccakHashOutput::add_virtual_hash(&mut builder);
		let num_leaves_target = builder.add_virtual_target();

		// Build path: hash_2_to_1 for levels 0..DEPTH-1, hash_root for last level
		let mut siblings_targets = Vec::with_capacity(DEPTH);
		let mut bits_targets = Vec::with_capacity(DEPTH);

		let mut current = leaf_target;
		for level in 0..DEPTH {
			let sib = KeccakHashOutput::add_virtual_hash(&mut builder);
			let bit = builder.add_virtual_bool_target_safe();
			siblings_targets.push(sib);
			bits_targets.push(bit);

			if level == DEPTH - 1 {
				let left = KeccakHashOutput::select_hash(&mut builder, bit, &sib, &current);
				let right = KeccakHashOutput::select_hash(&mut builder, bit, &current, &sib);
				current = KeccakHashOutput::hash_root_circuit(
					&mut builder,
					&ctx,
					num_leaves_target,
					left,
					right,
				);
			} else {
				current =
					KeccakHashOutput::hash_2_to_1_circuit(&mut builder, &ctx, current, sib, bit);
			}
		}

		// Constrain computed root == expected root
		KeccakHashOutput::connect_hashes(&mut builder, &current, &expected_root);

		// Register expected root as public inputs
		builder.register_public_inputs(&expected_root.elements);

		println!("[2/5] Circuit gates built:       {:>8.2?}", t1.elapsed());

		// ── 3. Build circuit data ────────────────────────────────────
		let t2 = Instant::now();
		let circuit_data = builder.build::<ConfigNative>();
		println!(
			"[3/5] Circuit compiled (degree=2^{}): {:>8.2?}",
			circuit_data.common.degree_bits(),
			t2.elapsed()
		);

		// ── 4. Set witness and prove ────────────────────────────────
		let t3 = Instant::now();
		let mut pw = PartialWitness::new();

		KeccakHashOutput::set_hash_witness(&mut pw, &leaf_target, &leaf).unwrap();
		KeccakHashOutput::set_hash_witness(&mut pw, &expected_root, &root).unwrap();
		pw.set_target(
			num_leaves_target,
			F::from_canonical_usize(tree.num_leaves()),
		)
		.unwrap();

		for level in 0..DEPTH {
			KeccakHashOutput::set_hash_witness(&mut pw, &siblings_targets[level], &siblings[level])
				.unwrap();
			let bit = ((leaf_index >> level) & 1) == 1;
			pw.set_bool_target(bits_targets[level], bit).unwrap();
		}

		let proof = circuit_data.prove(pw).unwrap();
		println!("[4/5] Proof generated:           {:>8.2?}", t3.elapsed());

		// ── 5. Verify ────────────────────────────────────────────────
		let t4 = Instant::now();
		circuit_data.verify(proof).unwrap();
		println!("[5/5] Proof verified:            {:>8.2?}", t4.elapsed());

		println!(
			"\nKeccak Merkle tree depth-{DEPTH} circuit proof verified! (total: {:.2?})",
			t0.elapsed()
		);
	}
}
