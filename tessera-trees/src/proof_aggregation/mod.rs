//! Generic recursive proof aggregator for Tessera.
//!
//! See [`generic::GenericAggregator`] for the primary entry point and usage
//! examples.

mod artifacts;
pub mod generic;
pub mod node_prover;
pub mod super_aggregator;

pub use generic::{
	AggregatedProof, GenericAggregator, GenericAggregatorConfig, LevelCircuit,
	MAX_AGGREGATION_LEAVES, ReducerKind,
};
pub use node_prover::{LocalNodeProver, NodeProver};
pub use super_aggregator::{SuperAggregator, SuperAggregatorCircuitData};
