//! Generic recursive proof aggregator for Tessera.
//!
//! See [`generic::GenericAggregator`] for the primary entry point and usage
//! examples.

mod artifacts;
pub mod generic;
pub mod node_prover;
pub mod subtree_root;
pub mod super_aggregator_v2;

pub use generic::{
	AggregatedProof, GenericAggregator, GenericAggregatorConfig, LevelCircuit,
	MAX_AGGREGATION_LEAVES,
};
pub use node_prover::{LocalNodeProver, NodeProver};
pub use subtree_root::SubtreeRootCircuit;
pub use super_aggregator_v2::{
	IS_REAL_OFFSET, SuperAggregatorV2, SuperAggregatorV2CircuitData, TX_DATA_OFFSET,
	TX_LEAF_PI_SIZE, validate_subtree_nc_offcircuit,
};
