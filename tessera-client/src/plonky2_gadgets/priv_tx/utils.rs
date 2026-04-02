use plonky2::{
	hash::{
		hash_types::{HashOutTarget, RichField},
		poseidon::PoseidonHash,
	},
	plonk::circuit_builder::CircuitBuilder,
};
use plonky2_field::extension::Extendable;

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
