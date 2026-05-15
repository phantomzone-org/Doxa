use plonky2::{
	hash::hash_types::{HashOutTarget, RichField},
	iop::{
		target::BoolTarget,
		witness::{PartialWitness, WitnessWrite},
	},
	plonk::circuit_builder::CircuitBuilder,
};
use plonky2_field::{extension::Extendable, types::Field};
use doxa_trees::MerkleProof;
use doxa_utils::{
	F, HASH_SIZE,
	hasher::{HashOutput, MerkleHashCircuit, MerkleHashTarget},
};

/// Set witness values for a Merkle path (siblings + direction bits).
fn set_merkle_path_witness(
	pw: &mut PartialWitness<F>,
	t_siblings: &[HashOutTarget],
	t_bits: &[BoolTarget],
	proof: &MerkleProof<HashOutput>,
) {
	let (siblings, bits) = proof.extract_siblings_bits();
	assert_eq!(t_siblings.len(), siblings.len());
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

/// Set dummy (all-zero) witness values for a Merkle path.
fn set_dummy_merkle_path_witness(
	pw: &mut PartialWitness<F>,
	t_siblings: &[HashOutTarget],
	t_bits: &[BoolTarget],
) {
	for (t_sib, t_bit) in t_siblings.iter().zip(t_bits.iter()) {
		for elem_t in t_sib.elements.iter() {
			pw.set_target(*elem_t, F::ZERO).unwrap();
		}
		pw.set_bool_target(*t_bit, false).unwrap();
	}
}

#[derive(Clone)]
pub struct MerkleRootTarget {
	pub root: HashOutTarget,
	pub siblings: Vec<HashOutTarget>,
	pub bits: Vec<BoolTarget>,
}

impl MerkleRootTarget {
	pub(crate) fn set_witness(&self, pw: &mut PartialWitness<F>, proof: &MerkleProof<HashOutput>) {
		set_merkle_path_witness(pw, &self.siblings, &self.bits, proof);
	}

	pub(crate) fn set_dummy_witness(&self, pw: &mut PartialWitness<F>) {
		set_dummy_merkle_path_witness(pw, &self.siblings, &self.bits);
	}
}

/// Compute the Merkle root from a leaf and virtual sibling/bit targets.
pub fn compute_merkle_root_gadget<F: RichField + Extendable<D>, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
	leaf: HashOutTarget,
	depth: usize,
) -> MerkleRootTarget
where
	HashOutput: MerkleHashCircuit<F, D, HashTarget = MerkleHashTarget<4>>,
{
	let siblings = builder.add_virtual_hashes(depth);
	let bits: Vec<_> = (0..depth)
		.map(|_| builder.add_virtual_bool_target_safe())
		.collect();

	let sib_targets: Vec<_> = siblings
		.iter()
		.map(|s| MerkleHashTarget::from_hash_out_target(*s))
		.collect();
	let root = <HashOutput as MerkleHashCircuit<F, D>>::merkle_root_circuit(
		builder,
		MerkleHashTarget::from_hash_out_target(leaf),
		&sib_targets,
		&bits,
	);

	MerkleRootTarget {
		root: root.to_hash_out_target(),
		siblings,
		bits,
	}
}

/// Compute a Merkle root and conditionally constrain it to equal `expected_root`.
///
/// When `selector=1` the computed root must match; when `selector=0` no
/// equality is enforced.
pub fn conditional_merkle_verify_gadget<F: RichField + Extendable<D>, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
	leaf: HashOutTarget,
	expected_root: HashOutTarget,
	selector: BoolTarget,
	depth: usize,
) -> MerkleRootTarget
where
	HashOutput: MerkleHashCircuit<F, D, HashTarget = MerkleHashTarget<4>>,
{
	let target = compute_merkle_root_gadget::<F, D>(builder, leaf, depth);
	let root = MerkleHashTarget::from_hash_out_target(target.root);
	let expected = MerkleHashTarget::from_hash_out_target(expected_root);
	MerkleHashTarget::conditional_connect(builder, selector, &root, &expected);
	target
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

	fn build_merkle_path(leaf: HashOut<F>) -> (HashOut<F>, [HashOut<F>; 32], [bool; 32]) {
		let sibling_val = HashOut {
			elements: [
				GoldilocksField::from_canonical_u64(0xdeadbeef),
				GoldilocksField::from_canonical_u64(0xcafebabe),
				GoldilocksField::from_canonical_u64(0x12345678),
				GoldilocksField::from_canonical_u64(0xabcdef01),
			],
		};
		let bits = [false; 32];
		let siblings = [sibling_val; 32];

		let mut current = leaf;
		for i in 0..32 {
			current = <PoseidonHash as plonky2::plonk::config::Hasher<F>>::two_to_one(
				current,
				siblings[i],
			);
		}
		(current, siblings, bits)
	}

	fn set_test_witness(
		pw: &mut PartialWitness<F>,
		targets: &MerkleRootTarget,
		siblings: &[HashOut<F>],
		bits: &[bool],
	) {
		for level in 0..siblings.len() {
			for i in 0..HASH_SIZE {
				pw.set_target(
					targets.siblings[level].elements[i],
					siblings[level].elements[i],
				)
				.unwrap();
			}
			pw.set_bool_target(targets.bits[level], bits[level])
				.unwrap();
		}
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
		let targets = conditional_merkle_verify_gadget::<F, D>(
			&mut builder,
			leaf_target,
			expected_root_targets,
			selector,
			32,
		);

		let data = builder.build::<C>();
		let mut pw = PartialWitness::new();

		pw.set_hash_target(leaf_target, leaf).unwrap();
		set_test_witness(&mut pw, &targets, &siblings, &bits);
		pw.set_hash_target(expected_root_targets, root).unwrap();
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
		let targets = conditional_merkle_verify_gadget::<F, D>(
			&mut builder,
			leaf_target,
			expected_root_targets,
			selector,
			32,
		);

		let data = builder.build::<C>();
		let mut pw = PartialWitness::new();

		pw.set_hash_target(leaf_target, leaf).unwrap();
		set_test_witness(&mut pw, &targets, &siblings, &bits);
		let wrong_root = HashOut {
			elements: [GoldilocksField::from_canonical_u64(0xbad); 4],
		};
		pw.set_hash_target(expected_root_targets, wrong_root)
			.unwrap();
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
		let targets = conditional_merkle_verify_gadget::<F, D>(
			&mut builder,
			leaf_target,
			expected_root_targets,
			selector,
			32,
		);

		let data = builder.build::<C>();
		let mut pw = PartialWitness::new();

		pw.set_hash_target(leaf_target, leaf).unwrap();
		set_test_witness(&mut pw, &targets, &siblings, &bits);
		let wrong_root = HashOut {
			elements: [GoldilocksField::from_canonical_u64(0xbad); 4],
		};
		pw.set_hash_target(expected_root_targets, wrong_root)
			.unwrap();
		pw.set_bool_target(selector, true).unwrap();

		assert!(
			data.prove(pw).is_err(),
			"Expected proof to fail with wrong root and selector=1"
		);
	}
}
