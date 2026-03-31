pub mod groth;
pub mod hasher;
pub mod plonky2_gadgets;

/// Size of a hash in field elements (Poseidon outputs 4 Goldilocks elements)
pub const HASH_SIZE: usize = 4;

use plonky2::{
	field::goldilocks_field::GoldilocksField,
	plonk::{
		circuit_data::CircuitData, config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs,
	},
};

pub const D: usize = 2;
pub type F = GoldilocksField;
pub type ConfigNative = PoseidonGoldilocksConfig;

pub type CircuitDataNative = CircuitData<F, ConfigNative, D>;
pub type ProofNative = ProofWithPublicInputs<F, ConfigNative, D>;
