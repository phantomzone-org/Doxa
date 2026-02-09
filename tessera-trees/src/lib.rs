#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

extern crate alloc;
pub mod groth;
pub mod tree;
pub mod plonky2_gadgets;

use plonky2::{
	field::goldilocks_field::GoldilocksField,
	plonk::{
		circuit_data::CircuitData, config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs,
	},
};

use crate::groth::poseidon_bn128::config::PoseidonBN128GoldilocksConfig;

pub const D: usize = 2;
pub type F = GoldilocksField;
pub type ConfigNative = PoseidonGoldilocksConfig;
pub type ConfigBN128 = PoseidonBN128GoldilocksConfig;

pub type CircuitDataNative = CircuitData<F, ConfigNative, D>;
pub type ProofNative = ProofWithPublicInputs<F, ConfigNative, D>;

pub type ProofBN128 = ProofWithPublicInputs<F, ConfigBN128, D>;
pub type CircuitDataBN128 = CircuitData<F, ConfigBN128, D>;
