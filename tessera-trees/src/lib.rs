#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

extern crate alloc;
pub mod plonky2_gadgets;
pub mod tree;

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
