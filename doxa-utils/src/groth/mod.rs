pub(crate) mod poseidon_bn128;
pub mod serializer;
mod wrapper;
use plonky2::plonk::{circuit_data::CircuitData, proof::ProofWithPublicInputs};
use poseidon_bn128::config::PoseidonBN128GoldilocksConfig;
pub use serializer::DoxaGeneratorSerializer;
pub use wrapper::{BN128Wrapper, Groth16Wrapper};

use crate::{D, F};

pub type ConfigBN128 = PoseidonBN128GoldilocksConfig;
pub type ProofBN128 = ProofWithPublicInputs<F, ConfigBN128, D>;
pub type CircuitDataBN128 = CircuitData<F, ConfigBN128, D>;
