mod data_types;

pub mod aggregation_pipeline;
pub mod config;
pub mod contract;
pub mod dummy;
pub mod prover_client;
pub mod prover_v2;
pub mod sequencer;
pub mod states;
pub mod tree_store;
pub mod types;

pub use data_types::*;

pub const TREE_DEPTH: usize = 32;
