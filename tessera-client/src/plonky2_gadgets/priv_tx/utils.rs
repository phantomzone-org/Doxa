use plonky2::{
	hash::{
		hash_types::{HashOutTarget, RichField},
		poseidon::PoseidonHash,
	},
	plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};
use plonky2_field::extension::Extendable;
use tessera_utils::F;

/// Apply Poseidon twice natively: `H(H(input))`.
///
/// Used to compute dummy note nullifiers and commitments from seeds.
pub(crate) fn double_hash_native(elems: [F; 4]) -> [F; 4] {
	let h0 = <PoseidonHash as Hasher<F>>::hash_no_pad(&elems).elements;
	<PoseidonHash as Hasher<F>>::hash_no_pad(&h0).elements
}

/// Apply Poseidon twice: `H(H(input))`.
///
/// Used for dummy note and account commitments / nullifiers so they are
/// deterministic, collision-resistant values that cannot be predicted from the
/// raw dummy seed.
pub(crate) fn double_hash<F: RichField + Extendable<D>, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
	input: HashOutTarget,
) -> HashOutTarget {
	let out0 = builder.hash_n_to_hash_no_pad::<PoseidonHash>(input.elements.to_vec());
	builder.hash_n_to_hash_no_pad::<PoseidonHash>(out0.elements.to_vec())
}
