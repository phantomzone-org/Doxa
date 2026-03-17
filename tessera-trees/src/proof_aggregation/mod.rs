//! Generic recursive proof aggregator for Tessera.
//!
//! See [`generic::GenericAggregator`] for the primary entry point and usage
//! examples.

mod artifacts;
pub mod generic;
pub mod node_prover;
pub mod subtree_root;
pub mod super_aggregator;
pub mod super_aggregator_v2;

pub use generic::{
	AggregatedProof, GenericAggregator, GenericAggregatorConfig, LevelCircuit,
	MAX_AGGREGATION_LEAVES, ReducerKind,
};
pub use node_prover::{LocalNodeProver, NodeProver};
pub use subtree_root::SubtreeRootCircuit;
pub use super_aggregator::{
	IS_REAL_OFFSET, LEAF_OFFSET, LUT_PI_COUNT, SuperAggregator, SuperAggregatorCircuitData,
	TX_DATA_OFFSET, TX_LEAF_PI_SIZE, validate_ac_offcircuit, validate_an_offcircuit,
	validate_nc_offcircuit, validate_nn_offcircuit,
};
pub use super_aggregator_v2::{
	SuperAggregatorV2, SuperAggregatorV2CircuitData, validate_subtree_nc_offcircuit,
};
