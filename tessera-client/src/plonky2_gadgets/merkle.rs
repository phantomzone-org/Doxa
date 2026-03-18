use std::{
	array,
	hash::{BuildHasherDefault, Hash},
	sync::Arc,
};

use itertools::{Itertools, izip};
use plonky2::{
	hash::{
		hash_types::{HashOutTarget, RichField},
		hashing::PlonkyPermutation,
		poseidon::{Poseidon, PoseidonHash, PoseidonPermutation},
	},
	iop::{
		target::{BoolTarget, Target},
		witness::{PartialWitness, WitnessWrite},
	},
	plonk::{
		circuit_builder::CircuitBuilder,
		config::{AlgebraicHasher, Hasher},
	},
};
use plonky2_field::{
	extension::Extendable,
	types::{Field, Field64},
};
use tessera_trees::{
	F,
	tree::{
		HASH_SIZE,
		hasher::{HashOutput, MerkleHashCircuit, MerkleHashTarget},
	},
};

use crate::tree::{CommitmentTreeMerkleProof, MerkleProof, Node};

fn set_merkle_siblings_and_bits<F: Field, const DEPTH: usize>(
	pw: &mut PartialWitness<F>,
	t_siblings: &[HashOutTarget; DEPTH],
	t_bits: &[BoolTarget; DEPTH],
	siblings: [[F; HASH_SIZE]; DEPTH],
	bits: [bool; DEPTH],
) {
	for ((t_sib, sib), (t_bit, bit)) in t_siblings
		.iter()
		.zip(siblings.iter())
		.zip(t_bits.iter().zip(bits.iter()))
	{
		for (elem_t, &elem_v) in t_sib.elements.iter().zip(sib.iter()) {
			pw.set_target(*elem_t, elem_v).unwrap();
		}
		pw.set_bool_target(*t_bit, *bit).unwrap();
	}
}

pub(crate) trait SetMerklePathOfWitness<Proof> {
	fn set_witness(&self, pw: &mut PartialWitness<F>, proof: &Proof);
}

pub(crate) trait SetMerkleRootOfWitness<Proof> {
	fn set_witness(&self, pw: &mut PartialWitness<F>, proof: &Proof);
}

pub(crate) trait SetDummyMerklePathOfWitness {
	fn set_dummy_witness(&self, pw: &mut PartialWitness<F>, depth: usize);
}

#[derive(Clone, Copy)]
pub struct ConditionalMerkleTarget<const DEPTH: usize> {
	pub siblings: [HashOutTarget; DEPTH],
	pub bits: [BoolTarget; DEPTH],
}

impl<N: Node, const D: usize> SetMerklePathOfWitness<MerkleProof<N, D>>
	for ConditionalMerkleTarget<D>
where
	N::Leaf: Clone,
{
	fn set_witness(&self, pw: &mut PartialWitness<F>, proof: &MerkleProof<N, D>) {
		let (siblings, bits) = proof.extract_siblings_bits();
		set_merkle_siblings_and_bits(pw, &self.siblings, &self.bits, siblings, bits);
	}
}

impl<const D: usize> SetDummyMerklePathOfWitness for ConditionalMerkleTarget<D> {
	fn set_dummy_witness(&self, pw: &mut PartialWitness<F>, _depth: usize) {
		set_merkle_siblings_and_bits(
			pw,
			&self.siblings,
			&self.bits,
			[[F::ZERO; 4]; D],
			[false; D],
		);
	}
}

#[derive(Clone, Copy)]
pub struct ComputeMerkleRootTarget<const DEPTH: usize> {
	pub root: HashOutTarget,
	pub siblings: [HashOutTarget; DEPTH],
	// TODO:Change bits to bool
	pub bits: [BoolTarget; DEPTH],
}

impl<N: Node, const D: usize> SetMerklePathOfWitness<MerkleProof<N, D>>
	for ComputeMerkleRootTarget<D>
where
	N::Leaf: Clone,
{
	fn set_witness(&self, pw: &mut PartialWitness<F>, proof: &MerkleProof<N, D>) {
		let (siblings, bits) = proof.extract_siblings_bits();
		set_merkle_siblings_and_bits(pw, &self.siblings, &self.bits, siblings, bits);
	}
}

pub struct CommitmentTreeMerkleTarget<const DEPTH: usize> {
	pub siblings: [HashOutTarget; DEPTH],
	pub bits: [BoolTarget; DEPTH],
	pub num_leaves: Target,
}

impl<const D: usize> SetMerklePathOfWitness<CommitmentTreeMerkleProof<D>>
	for CommitmentTreeMerkleTarget<D>
{
	fn set_witness(&self, pw: &mut PartialWitness<F>, proof: &CommitmentTreeMerkleProof<D>) {
		let (siblings, bits) = proof.extract_siblings_bits();
		set_merkle_siblings_and_bits(pw, &self.siblings, &self.bits, siblings, bits);
		assert!(proof.num_leaves < F::ORDER as usize);
		pw.set_target(self.num_leaves, F::from_canonical_usize(proof.num_leaves))
			.unwrap();
	}
}

impl<const D: usize> SetDummyMerklePathOfWitness for CommitmentTreeMerkleTarget<D> {
	fn set_dummy_witness(&self, pw: &mut PartialWitness<F>, _depth: usize) {
		set_merkle_siblings_and_bits(
			pw,
			&self.siblings,
			&self.bits,
			[[F::ZERO; 4]; D],
			[false; D],
		);
		pw.set_target(self.num_leaves, F::ZERO).unwrap();
	}
}

/// Builds a depth-32 Merkle path verification gadget using the existing
/// PoseidonGate.
///
/// Each of the 32 levels adds one `PoseidonGate` via
/// `PoseidonHash::permute_swapped`. The gate's built-in SWAP wire handles
/// left/right child ordering: when `bit=0` the node is the left child, when
/// `bit=1` the node is the right child.
///
/// After all 32 levels, if `selector=1` the computed root is constrained to
/// equal `expected_root`; if `selector=0` no equality is enforced.
pub fn conditional_merkle_verify_gadget<
	F: RichField + Extendable<D> + Poseidon,
	const D: usize,
	const DEPTH: usize,
>(
	builder: &mut CircuitBuilder<F, D>,
	leaf: HashOutTarget,
	expected_root: HashOutTarget,
	selector: BoolTarget,
) -> ConditionalMerkleTarget<DEPTH> {
	let merkletrgt = compute_merkle_root_gagdet(builder, leaf);
	for i in 0..HASH_SIZE {
		builder.conditional_assert_eq(
			selector.target,
			merkletrgt.root.elements[i],
			expected_root.elements[i],
		);
	}
	ConditionalMerkleTarget {
		siblings: merkletrgt.siblings,
		bits: merkletrgt.bits,
	}
}

// TODO: both conditional_merkle_verify_commitment_tree_gadget, condtional_merkle_verify_gadget can
// use compute_merkle_root_gadget if the fn computes node till depth-1, since the two parent
// functions only differ in root computation. However, the compute_merkle_root_gadget is
// independently useful. Hence, it'll suit better if it takes DEPTH to compute node until as a
// parameter.
pub fn compute_merkle_root_gagdet<
	F: RichField + Extendable<D> + Poseidon,
	const D: usize,
	const DEPTH: usize,
>(
	builder: &mut CircuitBuilder<F, D>,
	leaf: HashOutTarget,
) -> ComputeMerkleRootTarget<DEPTH> {
	let siblings: [HashOutTarget; DEPTH] = core::array::from_fn(|_| builder.add_virtual_hash());
	let bits: [BoolTarget; DEPTH] =
		core::array::from_fn(|_| builder.add_virtual_bool_target_safe());

	let mut current: [Target; HASH_SIZE] = leaf.elements;
	for level in 0..DEPTH {
		// Build the 12-element Poseidon input:
		//   [current[0..4] || sibling[0..4] || zero[0..4]]
		// PoseidonGate SWAP will swap the first 4 with the next 4 when bit=1,
		// so the permutation always receives [left || right || zeros].
		let zero = builder.zero();
		let perm_inputs = PoseidonPermutation::new(
			current
				.iter()
				.chain(siblings[level].elements.iter())
				.copied()
				//TODO(jay): why removing zeros fails the test?
				.chain(core::iter::repeat(zero)),
		);

		let perm_output = PoseidonHash::permute_swapped(perm_inputs, bits[level], builder);
		let output = perm_output.squeeze();

		let parent: [Target; HASH_SIZE] = core::array::from_fn(|i| output[i]);
		current = parent;
	}

	ComputeMerkleRootTarget {
		root: HashOutTarget {
			elements: current,
		},
		siblings,
		bits,
	}
}

/// Merkle verification of logic of commitment tree is different from other merkle trees.
///
/// Uptill level depth-1, the nodes are compressed in binary structure, like any other merkle tree.
/// For the root, the hash function computes H(num_leaves | left | right) (not H(left, right)).
/// Hence, merkle path verification of CommitmentTree requires a distinct gadget
pub fn conditional_merkle_verify_commitment_tree_gadget<
	H: MerkleHashCircuit<F, D, HashTarget = MerkleHashTarget<4>>,
	F: RichField + Extendable<D> + Poseidon,
	const D: usize,
	const DEPTH: usize,
>(
	builder: &mut CircuitBuilder<F, D>,
	leaf: HashOutTarget,
	expected_root: HashOutTarget,
	selector: BoolTarget,
	ctx: &H::CircuitContext,
) -> CommitmentTreeMerkleTarget<DEPTH> {
	let siblings: [HashOutTarget; DEPTH] = core::array::from_fn(|_| builder.add_virtual_hash());
	let bits: [BoolTarget; DEPTH] =
		core::array::from_fn(|_| builder.add_virtual_bool_target_safe());
	let num_leaves = builder.add_virtual_target();

	let mut current = MerkleHashTarget::from_hash_out_target(leaf);
	for level in 0..DEPTH {
		if level == DEPTH - 1 {
			let dir = bits[DEPTH - 1];
			let sib = MerkleHashTarget::from_hash_out_target(siblings[DEPTH - 1]);
			let left = H::select_hash(builder, dir, &sib, &current);
			let right = H::select_hash(builder, dir, &current, &sib);
			current = H::hash_root_circuit(builder, ctx, num_leaves, left, right);
		} else {
			let sib = MerkleHashTarget::from_hash_out_target(siblings[level]);
			current = H::hash_2_to_1_circuit(builder, ctx, current, sib, bits[level]);
		}
	}

	// Selector-gated root equality
	let expected = MerkleHashTarget::from_hash_out_target(expected_root);
	MerkleHashTarget::conditional_connect(builder, selector, &current, &expected);

	CommitmentTreeMerkleTarget {
		siblings,
		bits,
		num_leaves,
	}
}

#[cfg(test)]
mod tests {
	use plonky2::{
		hash::{hash_types::HashOut, poseidon::PoseidonHash},
		iop::witness::{PartialWitness, WitnessWrite},
		plonk::{
			circuit_data::CircuitConfig,
			config::{GenericConfig, PoseidonGoldilocksConfig},
		},
	};
	use plonky2_field::{goldilocks_field::GoldilocksField, types::Field};

	use super::*;

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = <C as GenericConfig<D>>::F;

	/// Build a depth-32 Merkle tree from a leaf and return the root along with
	/// the sibling and bit arrays for the path at index 0 (all bits = 0 means
	/// the target leaf is always the left child at every level).
	fn build_merkle_path(leaf: HashOut<F>) -> (HashOut<F>, [HashOut<F>; 32], [bool; 32]) {
		// All siblings are a fixed non-zero hash so the tree is non-trivial.
		let sibling_val = HashOut {
			elements: [
				GoldilocksField::from_canonical_u64(0xdeadbeef),
				GoldilocksField::from_canonical_u64(0xcafebabe),
				GoldilocksField::from_canonical_u64(0x12345678),
				GoldilocksField::from_canonical_u64(0xabcdef01),
			],
		};

		// Index 0 → all bits = 0 (leaf is always the left child).
		let bits = [false; 32];
		let siblings = [sibling_val; 32];

		let mut current = leaf;
		for i in 0..32 {
			// bit=0 means current is left child
			current = <PoseidonHash as plonky2::plonk::config::Hasher<F>>::two_to_one(
				current,
				siblings[i],
			);
		}

		(current, siblings, bits)
	}

	#[test]
	fn test_merkle_gadget_valid() {
		let leaf_elements = [
			GoldilocksField::from_canonical_u64(1),
			GoldilocksField::from_canonical_u64(2),
			GoldilocksField::from_canonical_u64(3),
			GoldilocksField::from_canonical_u64(4),
		];
		let leaf = HashOut {
			elements: leaf_elements,
		};

		let (root, siblings, bits) = build_merkle_path(leaf);

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let expected_root_targets = builder.add_virtual_hash();
		let selector = builder.add_virtual_bool_target_safe();
		let leaf_target = builder.add_virtual_hash();
		let targets = conditional_merkle_verify_gadget::<F, D, 32>(
			&mut builder,
			leaf_target,
			expected_root_targets,
			selector,
		);

		let data = builder.build::<C>();

		let mut pw = PartialWitness::new();

		// Set leaf
		for i in 0..4 {
			pw.set_target(leaf_target.elements[i], leaf_elements[i])
				.unwrap();
		}
		// Set siblings and bits
		for level in 0..32 {
			for i in 0..4 {
				pw.set_target(
					targets.siblings[level].elements[i],
					siblings[level].elements[i],
				)
				.unwrap();
			}
			pw.set_bool_target(targets.bits[level], bits[level])
				.unwrap();
		}
		// Set expected root = computed root
		for i in 0..4 {
			pw.set_target(expected_root_targets.elements[i], root.elements[i])
				.unwrap();
		}
		pw.set_bool_target(selector, true).unwrap();

		let proof = data.prove(pw).expect("prove failed");
		data.verify(proof).expect("verify failed");
	}

	#[test]
	fn test_merkle_gadget_selector_off() {
		let leaf_elements = [
			GoldilocksField::from_canonical_u64(1),
			GoldilocksField::from_canonical_u64(2),
			GoldilocksField::from_canonical_u64(3),
			GoldilocksField::from_canonical_u64(4),
		];
		let leaf = HashOut {
			elements: leaf_elements,
		};
		let (_, siblings, bits) = build_merkle_path(leaf);

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let expected_root_targets = builder.add_virtual_hash();
		let selector = builder.add_virtual_bool_target_safe();
		let leaf_target = builder.add_virtual_hash();
		let targets = conditional_merkle_verify_gadget::<F, D, 32>(
			&mut builder,
			leaf_target,
			expected_root_targets,
			selector,
		);

		let data = builder.build::<C>();
		let mut pw = PartialWitness::new();

		for i in 0..4 {
			pw.set_target(leaf_target.elements[i], leaf_elements[i])
				.unwrap();
		}
		for level in 0..32 {
			for i in 0..4 {
				pw.set_target(
					targets.siblings[level].elements[i],
					siblings[level].elements[i],
				)
				.unwrap();
			}
			pw.set_bool_target(targets.bits[level], bits[level])
				.unwrap();
		}

		// Wrong expected root — but selector = 0, so no equality is enforced.
		let wrong_root = [
			GoldilocksField::from_canonical_u64(0xbad),
			GoldilocksField::from_canonical_u64(0xbad),
			GoldilocksField::from_canonical_u64(0xbad),
			GoldilocksField::from_canonical_u64(0xbad),
		];
		for i in 0..4 {
			pw.set_target(expected_root_targets.elements[i], wrong_root[i])
				.unwrap();
		}
		pw.set_bool_target(selector, false).unwrap();

		let proof = data.prove(pw).expect("prove failed");
		data.verify(proof).expect("verify failed");
	}

	#[test]
	fn test_merkle_gadget_wrong_root_selector_on() {
		let leaf_elements = [
			GoldilocksField::from_canonical_u64(1),
			GoldilocksField::from_canonical_u64(2),
			GoldilocksField::from_canonical_u64(3),
			GoldilocksField::from_canonical_u64(4),
		];
		let leaf = HashOut {
			elements: leaf_elements,
		};
		let (_, siblings, bits) = build_merkle_path(leaf);

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let expected_root_targets = builder.add_virtual_hash();
		let selector = builder.add_virtual_bool_target_safe();
		let leaf_target = builder.add_virtual_hash();
		let targets = conditional_merkle_verify_gadget::<F, D, 32>(
			&mut builder,
			leaf_target,
			expected_root_targets,
			selector,
		);

		let data = builder.build::<C>();
		let mut pw = PartialWitness::new();

		for i in 0..4 {
			pw.set_target(leaf_target.elements[i], leaf_elements[i])
				.unwrap();
		}
		for level in 0..32 {
			for i in 0..4 {
				pw.set_target(
					targets.siblings[level].elements[i],
					siblings[level].elements[i],
				)
				.unwrap();
			}
			pw.set_bool_target(targets.bits[level], bits[level])
				.unwrap();
		}

		// Wrong expected root with selector = 1 — must fail.
		let wrong_root = [
			GoldilocksField::from_canonical_u64(0xbad),
			GoldilocksField::from_canonical_u64(0xbad),
			GoldilocksField::from_canonical_u64(0xbad),
			GoldilocksField::from_canonical_u64(0xbad),
		];
		for i in 0..4 {
			pw.set_target(expected_root_targets.elements[i], wrong_root[i])
				.unwrap();
		}
		pw.set_bool_target(selector, true).unwrap();

		assert!(
			data.prove(pw).is_err(),
			"Expected proof to fail with wrong root and selector=1"
		);
	}

	// ── Native helper functions for test_prove_fresh_acc_tx ──────────────────

	/// Matches `derive_fresh_account_nullifier`: 8-element Poseidon hash of comm || nk.
	fn fresh_acc_null_native(comm: [F; 4], nk: [F; 4]) -> [F; 4] {
		use plonky2::plonk::config::Hasher;
		let inp: Vec<F> = comm.iter().chain(nk.iter()).copied().collect();
		<PoseidonHash as Hasher<F>>::hash_no_pad(&inp).elements
	}

	// ── Witness-setting helpers ───────────────────────────────────────────────
}
