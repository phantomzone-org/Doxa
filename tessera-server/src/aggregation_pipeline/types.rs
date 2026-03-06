//! HTTP serialization types for the distributed aggregation prover protocol.
//!
//! These are the only types exchanged between the coordinator and remote
//! `aggregation_prover` workers.  They carry no circuit data — workers load
//! their own artifacts.

use serde::{Deserialize, Serialize};

/// Sent by the coordinator to a remote aggregation prover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveNodeRequest {
	/// Aggregation level (0 = bottom, `depth-1` = root).
	pub level: usize,
	/// Node index within the level (used only for logging).
	pub node_idx: usize,
	/// Hex-encoded `ProofWithPublicInputs::to_bytes()` for each child proof,
	/// in order (index 0 = position 0 within the node).
	pub children: Vec<String>,
}

/// Returned by a remote aggregation prover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProveNodeResponse {
	/// Hex-encoded `ProofWithPublicInputs::to_bytes()` of the proven node.
	pub proof: String,
}
