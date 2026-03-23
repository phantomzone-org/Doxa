//! Generic recursive proof aggregator for Tessera.
//!
//! See [`generic::GenericAggregator`] for the primary entry point and usage
//! examples.

mod artifacts;
pub mod deposit_super_aggregator_v2;
pub mod generic;
pub mod node_prover;
pub mod plonky2_gadgets;
pub mod subtree_root;
pub mod super_aggregator_v2;

pub use deposit_super_aggregator_v2::{
	validate_deposit_subtree_nc_offcircuit, DepositSuperAggregatorV2,
	DepositSuperAggregatorV2CircuitData, DEPOSIT_IS_REAL_OFFSET, DEPOSIT_LEAF_PI_SIZE,
	DEPOSIT_NOTE_COMM_OFFSET,
};
pub use generic::{
	AggregatedProof, GenericAggregator, GenericAggregatorConfig, LevelCircuit,
	MAX_AGGREGATION_LEAVES,
};
pub use node_prover::{LocalNodeProver, NodeProver};
pub use subtree_root::SubtreeRootCircuit;
pub use super_aggregator_v2::{
	validate_subtree_nc_offcircuit, SuperAggregatorV2, SuperAggregatorV2CircuitData,
	IS_REAL_OFFSET, TX_DATA_OFFSET, TX_LEAF_PI_SIZE,
};
