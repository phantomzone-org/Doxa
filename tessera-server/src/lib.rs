mod data_types;

pub mod aggregation_pipeline;
pub mod config;
pub mod contract;
pub mod dummy;
pub mod groth;
pub mod proof_aggregation;
pub mod prover_client;
pub mod prover_v2;
pub mod sequencer;
pub mod states;
pub mod tree_store;
pub mod types;

pub use data_types::*;

pub const TREE_DEPTH: usize = 32;

use groth::poseidon_bn128::config::PoseidonBN128GoldilocksConfig;
use plonky2::plonk::{circuit_data::CircuitData, proof::ProofWithPublicInputs};
use tessera_trees::{ConfigNative, D, F};

pub type ConfigBN128 = PoseidonBN128GoldilocksConfig;
pub type ProofBN128 = ProofWithPublicInputs<F, ConfigBN128, D>;
pub type CircuitDataBN128 = CircuitData<F, ConfigBN128, D>;
