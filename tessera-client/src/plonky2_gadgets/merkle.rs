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
	plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use plonky2_field::{extension::Extendable, types::Field};
use tessera_trees::tree::HASH_SIZE;

use crate::tree::{MerkleProof, Node};

pub(crate) fn set_merkle_siblings_and_bits<
	F: Field,
	T: MerkleSiblingsBits<DEPTH>,
	const DEPTH: usize,
>(
	pw: &mut PartialWitness<F>,
	t: &T,
	siblings: [[F; 4]; DEPTH],
	bits: [bool; DEPTH],
) {
	for lvl in 0..DEPTH {
		for i in 0..4 {
			pw.set_target(t.siblings()[lvl][i], siblings[lvl][i])
				.unwrap();
		}
		pw.set_bool_target(BoolTarget::new_unsafe(t.bits()[lvl]), bits[lvl])
			.unwrap();
	}
}

/// Extract siblings and direction bits from a native MerkleProof.
/// Direction::Left  (sibling on left, current is right child) → bit = true
/// Direction::Right (sibling on right, current is left child) → bit = false
fn proof_siblings_bits<F: Field, N: Node, const DEPTH: usize>(
	proof: &crate::tree::MerkleProof<N, DEPTH>,
) -> ([[F; 4]; DEPTH], [bool; DEPTH]) {
	let siblings: [[F; 4]; DEPTH] = core::array::from_fn(|i| {
		proof.path[i].sibling.inner().0.map(|f| {
			use plonky2_field::types::PrimeField64;
			F::from_canonical_u64(f.to_canonical_u64())
		})
	});
	let bits: [bool; DEPTH] =
		core::array::from_fn(|i| proof.path[i].direction == crate::tree::Direction::Left);
	(siblings, bits)
}

pub(crate) trait MerkleSiblingsBits<const DEPTH: usize> {
	fn siblings(&self) -> &[[Target; HASH_SIZE]; DEPTH];
	fn bits(&self) -> &[Target; DEPTH];

	fn set_witness<F: Field, N: Node>(
		&self,
		pw: &mut PartialWitness<F>,
		proof: &MerkleProof<N, DEPTH>,
	) where
		Self: Sized,
	{
		let (siblings, bits) = proof_siblings_bits::<F, N, DEPTH>(proof);
		set_merkle_siblings_and_bits(pw, self, siblings, bits);
	}
}

impl<const DEPTH: usize> MerkleSiblingsBits<DEPTH> for ConditionalMerkleTarget<DEPTH> {
	fn siblings(&self) -> &[[Target; HASH_SIZE]; DEPTH] {
		&self.siblings
	}

	fn bits(&self) -> &[Target; DEPTH] {
		&self.bits
	}
}

impl<const DEPTH: usize> MerkleSiblingsBits<DEPTH> for MerkleTarget<DEPTH> {
	fn siblings(&self) -> &[[Target; HASH_SIZE]; DEPTH] {
		&self.siblings
	}

	fn bits(&self) -> &[Target; DEPTH] {
		&self.bits
	}
}

#[derive(Clone, Copy)]
pub struct ConditionalMerkleTarget<const DEPTH: usize> {
	pub siblings: [[Target; HASH_SIZE]; DEPTH],
	pub bits: [Target; DEPTH],
}

#[derive(Clone, Copy)]
pub struct MerkleTarget<const DEPTH: usize> {
	pub root: [Target; HASH_SIZE],
	pub siblings: [[Target; HASH_SIZE]; DEPTH],
	pub bits: [Target; DEPTH],
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
	let merkletrgt = merkle_verify_gadget(builder, leaf);

	// Selector-gated root equality: selector * (computed_root[i] -
	// expected_root[i]) = 0
	let computed_root = merkletrgt.root;
	for i in 0..HASH_SIZE {
		let diff = builder.sub(computed_root[i], expected_root.elements[i]);
		let product = builder.mul(selector.target, diff);
		builder.assert_zero(product);
	}

	ConditionalMerkleTarget {
		siblings: merkletrgt.siblings,
		bits: merkletrgt.bits,
	}
}

pub fn merkle_verify_gadget<
	F: RichField + Extendable<D> + Poseidon,
	const D: usize,
	const DEPTH: usize,
>(
	builder: &mut CircuitBuilder<F, D>,
	leaf: HashOutTarget,
) -> MerkleTarget<DEPTH> {
	let mut current: [Target; HASH_SIZE] = leaf.elements;
	let mut siblings: [[Target; HASH_SIZE]; DEPTH] = [[builder.zero(); 4]; DEPTH];
	let mut bits: [Target; DEPTH] = [builder.zero(); DEPTH];

	for level in 0..DEPTH {
		let sibling: [Target; 4] = core::array::from_fn(|_| builder.add_virtual_target());

		let bit = builder.add_virtual_bool_target_safe();

		// Build the 12-element Poseidon input:
		//   [current[0..4] || sibling[0..4] || zero[0..4]]
		// PoseidonGate SWAP will swap the first 4 with the next 4 when bit=1,
		// so the permutation always receives [left || right || zeros].
		let zero = builder.zero();
		let perm_inputs = PoseidonPermutation::new(
			current
				.iter()
				.chain(sibling.iter())
				.copied()
				.chain(core::iter::repeat(zero).take(4)),
		);

		let perm_output = PoseidonHash::permute_swapped(perm_inputs, bit, builder);
		let output = perm_output.squeeze();

		let parent: [Target; HASH_SIZE] = core::array::from_fn(|i| output[i]);

		siblings[level] = sibling;
		bits[level] = bit.target;
		current = parent;
	}

	MerkleTarget {
		root: current,
		siblings,
		bits,
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
				pw.set_target(targets.siblings[level][i], siblings[level].elements[i])
					.unwrap();
			}
			pw.set_bool_target(BoolTarget::new_unsafe(targets.bits[level]), bits[level])
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
				pw.set_target(targets.siblings[level][i], siblings[level].elements[i])
					.unwrap();
			}
			pw.set_bool_target(BoolTarget::new_unsafe(targets.bits[level]), bits[level])
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
				pw.set_target(targets.siblings[level][i], siblings[level].elements[i])
					.unwrap();
			}
			pw.set_bool_target(BoolTarget::new_unsafe(targets.bits[level]), bits[level])
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

// TODO: assert account is fresh
//
// AccountFresh
// if account is fresh, then what things need to be chcked:
//  - all values of the account are set to default
//  - one should only be allowed to update the configuration of the account
//  - if acc_fresh, then it's a new type of tx
//
// PrivateTrafer
//      - for each inote:
//          - Comm(inote) exists in NCT
//          - Null(inote) is derived correctly
//          - inote.spend_cond = AccIn
//      - for each dinote:
//          - Comm(dinote) is derived correctly
//      - for each onote:
//          - Comm(onote) is derived correctly
//      - accin.amt + sum(inote) == accout.amt + sum(onote)
//      - approval signature
//      - if [onote].len > 0: user spend sig
//      - if [inote].len > 0 && [onote].len == 0: consume sig
//      - approval_key exists in MainConfigTree root
//
//
