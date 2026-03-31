mod data_types;

pub mod aggregation_pipeline;
pub mod config;
pub mod contract;
pub mod proof_aggregation;
pub mod prover_client;
pub mod sequencer;
pub mod types;
pub mod state_service;

pub use data_types::*;

pub const TREE_DEPTH: usize = 32;


pub use tessera_utils::groth::{
	BN128Wrapper, CircuitDataBN128, ConfigBN128, Groth16Wrapper, ProofBN128,
	TesseraGeneratorSerializer,
};
use tessera_utils::{ConfigNative, F};
