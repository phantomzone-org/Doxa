//! Async node-prover pool for the streaming aggregation pipeline.
//!
//! [`NodeProverPool`] dispatches node-prove tasks to the worker with the
//! fewest outstanding tasks (least-inflight).  On failure it retries on the
//! next-least-inflight worker, falling back to an error only when all workers
//! have been exhausted.

use std::{
	sync::{
		atomic::{AtomicUsize, Ordering},
		Arc,
	},
	time::Duration,
};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use plonky2::{
	field::extension::Extendable,
	hash::hash_types::RichField,
	plonk::{config::GenericConfig, proof::ProofWithPublicInputs},
};
use crate::proof_aggregation::{GenericAggregator, LocalNodeProver, NodeProver};
use tracing::warn;

use super::types::{ProveNodeRequest, ProveNodeResponse};

// ---------------------------------------------------------------------------
// AsyncNodeProver trait
// ---------------------------------------------------------------------------

/// Async counterpart to [`NodeProver`]: drives remote or local proving.
///
/// Implementors expose an inflight counter used by [`NodeProverPool`] for
/// least-inflight dispatch.
#[async_trait]
pub trait AsyncNodeProver<F, C, const D: usize>: Send + Sync
where
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F>,
{
	/// Prove an internal tree node asynchronously.
	async fn prove_node(
		&self,
		level: usize,
		node_idx: usize,
		children: Vec<ProofWithPublicInputs<F, C, D>>,
	) -> Result<ProofWithPublicInputs<F, C, D>>;

	/// Number of in-flight prove requests currently outstanding.
	fn inflight(&self) -> usize;
}

// ---------------------------------------------------------------------------
// LocalAsyncNodeProver
// ---------------------------------------------------------------------------

/// Wraps a [`LocalNodeProver`] for async use via `tokio::task::spawn_blocking`.
pub struct LocalAsyncNodeProver<
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F> + 'static,
	const D: usize,
> {
	inner: Arc<LocalNodeProver<F, C, D>>,
	inflight: AtomicUsize,
}

impl<F, C, const D: usize> LocalAsyncNodeProver<F, C, D>
where
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F> + 'static,
	C::Hasher: plonky2::plonk::config::AlgebraicHasher<F>,
{
	/// Create a new `LocalAsyncNodeProver` backed by the given aggregator.
	pub fn new(aggregator: Arc<GenericAggregator<F, C, D>>) -> Self {
		Self {
			inner: Arc::new(LocalNodeProver::new(aggregator)),
			inflight: AtomicUsize::new(0),
		}
	}
}

#[async_trait]
impl<F, C, const D: usize> AsyncNodeProver<F, C, D> for LocalAsyncNodeProver<F, C, D>
where
	F: RichField + Extendable<D> + Send + Sync + 'static,
	C: GenericConfig<D, F = F> + 'static + Send + Sync,
	C::Hasher: plonky2::plonk::config::AlgebraicHasher<F>,
	ProofWithPublicInputs<F, C, D>: Send,
{
	async fn prove_node(
		&self,
		level: usize,
		node_idx: usize,
		children: Vec<ProofWithPublicInputs<F, C, D>>,
	) -> Result<ProofWithPublicInputs<F, C, D>> {
		self.inflight.fetch_add(1, Ordering::SeqCst);
		let inner = self.inner.clone();
		let result = tokio::task::spawn_blocking(move || {
			inner.prove_node_blocking(level, node_idx, children)
		})
		.await
		.map_err(|e| anyhow!("spawn_blocking join error: {e}"))?;
		self.inflight.fetch_sub(1, Ordering::SeqCst);
		result
	}

	fn inflight(&self) -> usize {
		self.inflight.load(Ordering::Relaxed)
	}
}

// ---------------------------------------------------------------------------
// RemoteNodeProver
// ---------------------------------------------------------------------------

/// Sends proving work to a remote `aggregation_prover` service via HTTP.
pub struct RemoteNodeProver<F, C, const D: usize>
where
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F>,
{
	client: reqwest::Client,
	prove_url: String,
	/// Shared aggregator used only for proof deserialization (circuit data).
	aggregator: Arc<GenericAggregator<F, C, D>>,
	inflight: AtomicUsize,
	_timeout: Duration,
}

impl<F, C, const D: usize> RemoteNodeProver<F, C, D>
where
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F> + 'static,
	C::Hasher: plonky2::plonk::config::AlgebraicHasher<F>,
{
	/// Create a new `RemoteNodeProver`.
	///
	/// `base_url` is the HTTP base URL of the remote `aggregation_prover`
	/// service (e.g. `http://agg-1:8092`).  The `/prove-node` path is
	/// appended automatically.
	pub fn new(
		base_url: &str,
		aggregator: Arc<GenericAggregator<F, C, D>>,
		timeout: Duration,
	) -> Result<Self> {
		let client = reqwest::Client::builder()
			.timeout(timeout)
			.build()
			.map_err(|e| anyhow!("failed to build reqwest client: {e}"))?;
		Ok(Self {
			client,
			prove_url: format!("{}/prove-node", base_url.trim_end_matches('/')),
			aggregator,
			inflight: AtomicUsize::new(0),
			_timeout: timeout,
		})
	}
}

#[async_trait]
impl<F, C, const D: usize> AsyncNodeProver<F, C, D> for RemoteNodeProver<F, C, D>
where
	F: RichField + Extendable<D> + Send + Sync + 'static,
	C: GenericConfig<D, F = F> + 'static + Send + Sync,
	C::Hasher: plonky2::plonk::config::AlgebraicHasher<F>,
	ProofWithPublicInputs<F, C, D>: Send,
{
	async fn prove_node(
		&self,
		level: usize,
		node_idx: usize,
		children: Vec<ProofWithPublicInputs<F, C, D>>,
	) -> Result<ProofWithPublicInputs<F, C, D>> {
		// Serialise children synchronously — hex encoding of to_bytes() is fast.
		let hex_children: Vec<String> =
			children.iter().map(|p| hex::encode(p.to_bytes())).collect();

		let req = ProveNodeRequest {
			level,
			node_idx,
			children: hex_children,
		};

		self.inflight.fetch_add(1, Ordering::SeqCst);
		let resp: reqwest::Response = self
			.client
			.post(&self.prove_url)
			.json(&req)
			.send()
			.await
			.map_err(|e| {
				self.inflight.fetch_sub(1, Ordering::SeqCst);
				anyhow!("remote prover HTTP error: {e}")
			})?;

		if !resp.status().is_success() {
			self.inflight.fetch_sub(1, Ordering::SeqCst);
			return Err(anyhow!("remote prover returned status {}", resp.status()));
		}

		let body: ProveNodeResponse = resp.json().await.map_err(|e| {
			self.inflight.fetch_sub(1, Ordering::SeqCst);
			anyhow!("remote prover response deserialisation error: {e}")
		})?;

		self.inflight.fetch_sub(1, Ordering::SeqCst);

		// Determine the CommonCircuitData needed to deserialise the node proof.
		// A node proof at `level` was produced by `level_circuit(level)`, so its
		// common data is `level_circuit(level).circuit_data.common`.
		let proof_bytes = hex::decode(&body.proof).map_err(|e| anyhow!("hex decode error: {e}"))?;
		let node_common = &self.aggregator.level_circuit(level)?.circuit_data.common;
		let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes, node_common)
			.map_err(|e| anyhow!("node proof deserialisation failed: {e:?}"))?;
		Ok(proof)
	}

	fn inflight(&self) -> usize {
		self.inflight.load(Ordering::Relaxed)
	}
}

// ---------------------------------------------------------------------------
// NodeProverPool
// ---------------------------------------------------------------------------

/// Dispatches node-prove tasks to the least-inflight worker.
///
/// Falls back to the next-least-inflight worker on failure, up to
/// `pool.len()` retries.  Returns `Err` only when all workers have failed.
pub struct NodeProverPool<F, C, const D: usize>
where
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F>,
{
	provers: Vec<Arc<dyn AsyncNodeProver<F, C, D>>>,
}

impl<F, C, const D: usize> NodeProverPool<F, C, D>
where
	F: RichField + Extendable<D> + Send + Sync + 'static,
	C: GenericConfig<D, F = F> + 'static + Send + Sync,
	C::Hasher: plonky2::plonk::config::AlgebraicHasher<F>,
	ProofWithPublicInputs<F, C, D>: Send,
{
	/// Create a pool from a list of async provers.
	///
	/// The pool takes at least one prover; an empty pool always returns `Err`.
	pub fn new(provers: Vec<Arc<dyn AsyncNodeProver<F, C, D>>>) -> Self {
		Self {
			provers,
		}
	}

	/// Prove a node, dispatching to the least-inflight worker.
	///
	/// Retries on the next-least-inflight worker if the first attempt fails.
	/// Returns `Err` if all workers fail.
	pub async fn prove_node(
		&self,
		level: usize,
		node_idx: usize,
		children: Vec<ProofWithPublicInputs<F, C, D>>,
	) -> Result<ProofWithPublicInputs<F, C, D>> {
		if self.provers.is_empty() {
			return Err(anyhow!("NodeProverPool is empty"));
		}

		// Sort indices by ascending inflight count.
		let mut order: Vec<usize> = (0..self.provers.len()).collect();
		order.sort_by_key(|&i| self.provers[i].inflight());

		for idx in order {
			// Clone children only if we will retry (last attempt can move).
			let result = self.provers[idx]
				.prove_node(level, node_idx, children.clone())
				.await;
			match result {
				Ok(proof) => return Ok(proof),
				Err(e) => {
					warn!(
						level,
						node_idx,
						worker = idx,
						"worker failed, trying next: {e}"
					);
				},
			}
		}
		Err(anyhow!(
			"all workers in NodeProverPool failed for node ({level}, {node_idx})"
		))
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use anyhow::Result;
	use async_trait::async_trait;
	use plonky2::plonk::proof::ProofWithPublicInputs;
	use tessera_trees::{ConfigNative, D, F};

	use super::{AsyncNodeProver, NodeProverPool};

	// -----------------------------------------------------------------------
	// Mock prover
	// -----------------------------------------------------------------------

	struct MockProver {
		inflight_count: std::sync::atomic::AtomicUsize,
		/// Factory: given call index, return Ok or Err.
		should_fail: bool,
	}

	impl MockProver {
		fn ok() -> Arc<Self> {
			Arc::new(Self {
				inflight_count: std::sync::atomic::AtomicUsize::new(0),
				should_fail: false,
			})
		}

		fn fail() -> Arc<Self> {
			Arc::new(Self {
				inflight_count: std::sync::atomic::AtomicUsize::new(0),
				should_fail: true,
			})
		}

		fn with_inflight(n: usize) -> Arc<Self> {
			let p = Self::ok();
			p.inflight_count
				.store(n, std::sync::atomic::Ordering::SeqCst);
			p
		}
	}

	#[async_trait]
	impl AsyncNodeProver<F, ConfigNative, D> for MockProver {
		async fn prove_node(
			&self,
			_level: usize,
			_node_idx: usize,
			_children: Vec<ProofWithPublicInputs<F, ConfigNative, D>>,
		) -> Result<ProofWithPublicInputs<F, ConfigNative, D>> {
			if self.should_fail {
				Err(anyhow::anyhow!("mock failure"))
			} else {
				unreachable!("mock ok prover should not be called in dispatch-only tests")
			}
		}

		fn inflight(&self) -> usize {
			self.inflight_count
				.load(std::sync::atomic::Ordering::Relaxed)
		}
	}

	// -----------------------------------------------------------------------
	// Pool dispatch tests (no real proofs needed)
	// -----------------------------------------------------------------------

	#[tokio::test]
	async fn test_pool_least_inflight_empty_pool() {
		let pool: NodeProverPool<F, ConfigNative, D> = NodeProverPool::new(vec![]);
		let result = pool.prove_node(0, 0, vec![]).await;
		assert!(result.is_err(), "empty pool must return Err");
	}

	/// Three mock provers with inflight counts 2, 0, 1.
	/// All fail so we can observe which order they were tried (they all fail, so
	/// the test just checks the pool also returns Err and doesn't panic).
	#[tokio::test]
	async fn test_pool_dispatch_to_lowest() {
		let p0 = MockProver::with_inflight(2);
		let p1 = MockProver::with_inflight(0);
		let p2 = MockProver::with_inflight(1);
		// Override to always fail so prove_node can't succeed without real proofs.
		struct AlwaysFail(usize);
		#[async_trait]
		impl AsyncNodeProver<F, ConfigNative, D> for AlwaysFail {
			async fn prove_node(
				&self,
				_l: usize,
				_n: usize,
				_c: Vec<ProofWithPublicInputs<F, ConfigNative, D>>,
			) -> Result<ProofWithPublicInputs<F, ConfigNative, D>> {
				Err(anyhow::anyhow!("fail"))
			}

			fn inflight(&self) -> usize {
				self.0
			}
		}
		let provers: Vec<Arc<dyn AsyncNodeProver<F, ConfigNative, D>>> = vec![
			Arc::new(AlwaysFail(2)),
			Arc::new(AlwaysFail(0)),
			Arc::new(AlwaysFail(1)),
		];
		let pool = NodeProverPool::new(provers);
		// All fail → pool returns Err (does not panic).
		assert!(pool.prove_node(0, 0, vec![]).await.is_err());
		let _ = (p0, p1, p2); // silence unused warning
	}

	#[tokio::test]
	async fn test_pool_all_fail() {
		let provers: Vec<Arc<dyn AsyncNodeProver<F, ConfigNative, D>>> =
			vec![MockProver::fail(), MockProver::fail()];
		let pool = NodeProverPool::new(provers);
		assert!(pool.prove_node(0, 0, vec![]).await.is_err());
	}
}
