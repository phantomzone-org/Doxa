//! Generic recursive proof aggregator for Tessera.
//!
//! See [`generic::GenericAggregator`] for the primary entry point and usage
//! examples.

mod artifacts;
pub mod generic;

pub use generic::{
	AggregatedProof, GenericAggregator, GenericAggregatorConfig, MAX_AGGREGATION_LEAVES,
	ReducerKind,
};
