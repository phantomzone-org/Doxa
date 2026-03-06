//! Streaming aggregation pipeline for parallel distributed proof aggregation.
//!
//! Key public surface:
//!
//! - [`pool::NodeProverPool`] — least-inflight dispatch to local / remote workers.
//! - [`session::start_aggregation_session`] — creates a streaming session actor.
//! - [`types`] — HTTP serialization types shared with the `aggregation_prover` binary.

pub mod pool;
pub mod session;
pub mod types;

pub use pool::{AsyncNodeProver, LocalAsyncNodeProver, NodeProverPool, RemoteNodeProver};
pub use session::{start_aggregation_session, AggregationInputHandle, AggregationRootFuture};
pub use types::{ProveNodeRequest, ProveNodeResponse};
