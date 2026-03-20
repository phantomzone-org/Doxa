mod data_types;

pub mod aggregation_pipeline;
pub mod config;
pub mod contract;
pub mod dummy;
pub mod proof_aggregation;
pub mod prover_client;
pub mod prover_v2;
pub mod sequencer;
pub mod states;
pub mod types;

pub use data_types::*;

pub const TREE_DEPTH: usize = 32;

pub use tessera_utils::groth::{
	BN128Wrapper, CircuitDataBN128, ConfigBN128, Groth16Wrapper, ProofBN128,
	TesseraGeneratorSerializer,
};
use tessera_utils::{ConfigNative, F};
