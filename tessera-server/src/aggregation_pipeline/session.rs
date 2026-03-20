//! Streaming aggregation session actor.
//!
//! [`start_aggregation_session`] spawns a Tokio actor that tracks per-node
//! state and fires node-prove tasks as soon as each node's `arity` children
//! are ready.  Callers submit leaf proofs via [`AggregationInputHandle`] and
//! await the root proof via [`AggregationRootFuture`].
//!
//! ## Channel design
//!
//! Two separate channels keep user-facing and internal concerns apart:
//!
//! * **input channel** (`mpsc::Sender<LeafMsg>` → actor): carries user-submitted leaf proofs.  When
//!   all [`AggregationInputHandle`] clones are dropped the channel closes, and the actor detects
//!   abandonment if the root has not yet been produced.
//!
//! * **dispatch channel** (`mpsc::Sender<DispatchMsg>` held internally): carries [`NodeProven`] /
//!   [`NodeFailed`] callbacks from pool proving tasks back to the actor.  The actor holds this
//!   sender, so the channel never closes unexpectedly while the actor is alive.

use std::{
	future::Future,
	pin::Pin,
	sync::Arc,
	task::{Context, Poll},
};

use anyhow::{anyhow, Result};
use plonky2::{
	field::extension::Extendable,
	hash::hash_types::RichField,
	plonk::{circuit_data::CommonCircuitData, config::GenericConfig, proof::ProofWithPublicInputs},
};
use tokio::sync::{mpsc, oneshot};

use super::pool::NodeProverPool;
use crate::proof_aggregation::GenericAggregator;

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

struct NodeState<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
	children: Vec<Option<ProofWithPublicInputs<F, C, D>>>,
	filled: usize,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> NodeState<F, C, D> {
	fn new(arity: usize) -> Self {
		Self {
			children: (0..arity).map(|_| None).collect(),
			filled: 0,
		}
	}

	fn insert(&mut self, pos: usize, proof: ProofWithPublicInputs<F, C, D>) -> Result<()> {
		if pos >= self.children.len() {
			return Err(anyhow!(
				"position {} out of range (arity={})",
				pos,
				self.children.len()
			));
		}
		if self.children[pos].is_some() {
			return Err(anyhow!("duplicate proof at position {pos}"));
		}
		self.children[pos] = Some(proof);
		self.filled += 1;
		Ok(())
	}

	fn is_full(&self) -> bool {
		self.filled == self.children.len()
	}

	/// Take all children out, leaving slots empty again.
	fn drain_children(&mut self) -> Vec<ProofWithPublicInputs<F, C, D>> {
		self.children
			.iter_mut()
			.map(|slot| slot.take().expect("drain_children called on non-full node"))
			.collect()
	}
}

/// Message sent by the user via [`AggregationInputHandle`].
struct LeafMsg<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
	leaf_idx: usize,
	proof: ProofWithPublicInputs<F, C, D>,
}

/// Message sent back to the actor by a dispatch (pool proving) task.
enum DispatchMsg<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
	NodeProven {
		level: usize,
		node_idx: usize,
		proof: Box<ProofWithPublicInputs<F, C, D>>,
	},
	NodeFailed {
		level: usize,
		node_idx: usize,
		error: anyhow::Error,
	},
}

// ---------------------------------------------------------------------------
// Public handle types
// ---------------------------------------------------------------------------

/// Clonable handle for submitting leaf proofs into a streaming session.
///
/// Drop all handles when you have submitted all leaves; the actor will detect
/// channel closure and send an "abandoned" error if the root proof has not
/// yet been produced.
#[derive(Clone)]
pub struct AggregationInputHandle<
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F>,
	const D: usize,
> {
	tx: mpsc::Sender<LeafMsg<F, C, D>>,
	n_leaves: usize,
	leaf_common: Arc<CommonCircuitData<F, D>>,
}

impl<F, C, const D: usize> AggregationInputHandle<F, C, D>
where
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F>,
{
	/// Submit the deserialized proof for slot `leaf_idx`.
	pub async fn submit(
		&self,
		leaf_idx: usize,
		proof: ProofWithPublicInputs<F, C, D>,
	) -> Result<()> {
		if leaf_idx >= self.n_leaves {
			return Err(anyhow!(
				"leaf_idx {leaf_idx} out of range (n_leaves={})",
				self.n_leaves
			));
		}
		self.tx
			.send(LeafMsg {
				leaf_idx,
				proof,
			})
			.await
			.map_err(|_| anyhow!("aggregation session actor has exited"))
	}

	/// Convenience: deserialise from bytes and submit.
	pub async fn submit_bytes(&self, leaf_idx: usize, bytes: Vec<u8>) -> Result<()> {
		let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(bytes, &self.leaf_common)
			.map_err(|e| anyhow!("leaf proof deserialisation failed: {e:?}"))?;
		self.submit(leaf_idx, proof).await
	}
}

/// A future that resolves to the root aggregation proof (or `Err` if the
/// session failed or was abandoned before completion).
pub struct AggregationRootFuture<
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F>,
	const D: usize,
>(oneshot::Receiver<Result<ProofWithPublicInputs<F, C, D>>>);

impl<F, C, const D: usize> Future for AggregationRootFuture<F, C, D>
where
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F>,
{
	type Output = Result<ProofWithPublicInputs<F, C, D>>;

	fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		match Pin::new(&mut self.0).poll(cx) {
			Poll::Ready(Ok(result)) => Poll::Ready(result),
			Poll::Ready(Err(_)) => Poll::Ready(Err(anyhow!(
				"aggregation session dropped before root proof"
			))),
			Poll::Pending => Poll::Pending,
		}
	}
}

// ---------------------------------------------------------------------------
// Session constructor
// ---------------------------------------------------------------------------

/// Start a streaming aggregation session.
///
/// Returns:
/// - An [`AggregationInputHandle`] for submitting leaf proofs (clonable).
/// - An [`AggregationRootFuture`] that resolves when the root proof is ready.
///
/// The internal actor runs as a Tokio task and manages all per-node state.
/// Node-prove tasks are dispatched via `pool` as soon as each node is full.
pub fn start_aggregation_session<F, C, const D: usize>(
	aggregator: Arc<GenericAggregator<F, C, D>>,
	pool: Arc<NodeProverPool<F, C, D>>,
) -> (
	AggregationInputHandle<F, C, D>,
	AggregationRootFuture<F, C, D>,
)
where
	F: RichField + Extendable<D> + Send + Sync + 'static,
	C: GenericConfig<D, F = F> + 'static + Send + Sync,
	C::Hasher: plonky2::plonk::config::AlgebraicHasher<F>,
	ProofWithPublicInputs<F, C, D>: Send,
{
	let config = aggregator.config();
	let arity = config.arity;
	let depth = config.depth;
	let n_leaves = arity.pow(depth as u32);

	// User → actor: only leaf proofs.  Closing this channel signals the actor
	// that no more leaves will arrive.
	let (input_tx, input_rx) = mpsc::channel::<LeafMsg<F, C, D>>(n_leaves);

	// Pool tasks → actor: NodeProven / NodeFailed callbacks.  The actor holds
	// the sender, so this channel stays open as long as the actor is alive.
	let (dispatch_tx, dispatch_rx) = mpsc::channel::<DispatchMsg<F, C, D>>(n_leaves);

	let (root_tx, root_rx) = oneshot::channel::<Result<ProofWithPublicInputs<F, C, D>>>();

	// Build the per-node state grid: depth levels, each with the right number
	// of nodes.
	// level l has arity^(depth-1-l) nodes.
	let mut tree: Vec<Vec<NodeState<F, C, D>>> = Vec::with_capacity(depth);
	for l in 0..depth {
		let n_nodes = arity.pow((depth - 1 - l) as u32);
		let nodes: Vec<NodeState<F, C, D>> = (0..n_nodes).map(|_| NodeState::new(arity)).collect();
		tree.push(nodes);
	}

	let leaf_common = Arc::new(aggregator.leaf_common().clone());

	tokio::spawn(actor_loop(
		input_rx,
		dispatch_rx,
		dispatch_tx,
		root_tx,
		pool,
		tree,
		arity,
		depth,
	));

	let handle = AggregationInputHandle {
		tx: input_tx,
		n_leaves,
		leaf_common,
	};
	(handle, AggregationRootFuture(root_rx))
}

// ---------------------------------------------------------------------------
// Actor loop
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn actor_loop<F, C, const D: usize>(
	mut input_rx: mpsc::Receiver<LeafMsg<F, C, D>>,
	mut dispatch_rx: mpsc::Receiver<DispatchMsg<F, C, D>>,
	dispatch_tx: mpsc::Sender<DispatchMsg<F, C, D>>,
	root_tx: oneshot::Sender<Result<ProofWithPublicInputs<F, C, D>>>,
	pool: Arc<NodeProverPool<F, C, D>>,
	mut tree: Vec<Vec<NodeState<F, C, D>>>,
	arity: usize,
	depth: usize,
) where
	F: RichField + Extendable<D> + Send + Sync + 'static,
	C: GenericConfig<D, F = F> + 'static + Send + Sync,
	C::Hasher: plonky2::plonk::config::AlgebraicHasher<F>,
	ProofWithPublicInputs<F, C, D>: Send,
{
	// `input_done`: set when the input channel closes (all user handles dropped).
	// `pending`:    number of pool-prove tasks currently in flight.
	//
	// When input_done && pending == 0 the actor knows no root proof will ever
	// arrive and sends an "abandoned" error.
	let mut input_done = false;
	let mut pending: usize = 0;

	loop {
		// Abandonment: all user input is gone and no in-flight proving work remains.
		if input_done && pending == 0 {
			let _ = root_tx.send(Err(anyhow!(
				"aggregation session abandoned before root proof"
			)));
			return;
		}

		// select! panics if ALL branches are disabled.  The guard structure
		// ensures at least one branch is always active here:
		//   • if !input_done → input branch is active
		//   • if pending > 0 → dispatch branch is active
		//   • both false is caught by the check above
		tokio::select! {
			// Dispatch callbacks: node proven or failed.
			msg = dispatch_rx.recv(), if pending > 0 => {
				match msg {
					None => { /* impossible: we hold dispatch_tx */ }

					Some(DispatchMsg::NodeProven { level, node_idx, proof }) => {
						pending -= 1;

						if level == depth - 1 {
							// Root proof ready.
							let _ = root_tx.send(Ok(*proof));
							return;
						}

						let parent_level = level + 1;
						let parent_idx = node_idx / arity;
						let pos = node_idx % arity;

						if let Err(e) = tree[parent_level][parent_idx].insert(pos, *proof) {
							let _ = root_tx.send(Err(e));
							return;
						}

						if tree[parent_level][parent_idx].is_full() {
							let children = tree[parent_level][parent_idx].drain_children();
							dispatch(
								pool.clone(),
								dispatch_tx.clone(),
								parent_level,
								parent_idx,
								children,
							);
							pending += 1;
						}
					},

					Some(DispatchMsg::NodeFailed { level, node_idx, error }) => {
						let _ = root_tx.send(Err(anyhow!(
							"node ({level},{node_idx}) failed: {error}"
						)));
						return;
					},
				}
			},

			// User-submitted leaf proofs.
			msg = input_rx.recv(), if !input_done => {
				match msg {
					// Channel closed: no more leaves will arrive.
					None => { input_done = true; },

					Some(LeafMsg { leaf_idx, proof }) => {
						let node_idx = leaf_idx / arity;
						let pos = leaf_idx % arity;

						if let Err(e) = tree[0][node_idx].insert(pos, proof) {
							let _ = root_tx.send(Err(e));
							return;
						}

						if tree[0][node_idx].is_full() {
							let children = tree[0][node_idx].drain_children();
							dispatch(pool.clone(), dispatch_tx.clone(), 0, node_idx, children);
							pending += 1;
						}
					},
				}
			},
		}
	}
}

// ---------------------------------------------------------------------------
// Dispatch helper
// ---------------------------------------------------------------------------

/// Spawn a task that proves one node and reports back via `dispatch_tx`.
fn dispatch<F, C, const D: usize>(
	pool: Arc<NodeProverPool<F, C, D>>,
	dispatch_tx: mpsc::Sender<DispatchMsg<F, C, D>>,
	level: usize,
	node_idx: usize,
	children: Vec<ProofWithPublicInputs<F, C, D>>,
) where
	F: RichField + Extendable<D> + Send + Sync + 'static,
	C: GenericConfig<D, F = F> + 'static + Send + Sync,
	C::Hasher: plonky2::plonk::config::AlgebraicHasher<F>,
	ProofWithPublicInputs<F, C, D>: Send,
{
	tokio::spawn(async move {
		match pool.prove_node(level, node_idx, children).await {
			Ok(proof) => {
				let _ = dispatch_tx
					.send(DispatchMsg::NodeProven {
						level,
						node_idx,
						proof: Box::new(proof),
					})
					.await;
			},
			Err(e) => {
				let _ = dispatch_tx
					.send(DispatchMsg::NodeFailed {
						level,
						node_idx,
						error: e,
					})
					.await;
			},
		}
	});
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use std::{sync::Arc, time::Instant};

	use anyhow::Result;
	use plonky2::{
		field::types::Field,
		iop::{
			target::Target,
			witness::{PartialWitness, WitnessWrite},
		},
		plonk::{
			circuit_builder::CircuitBuilder,
			circuit_data::{CircuitConfig, CircuitData},
			proof::ProofWithPublicInputs,
		},
	};
	use tessera_utils::{ConfigNative, D, F};

	use super::*;
	use crate::{
		aggregation_pipeline::pool::{AsyncNodeProver, LocalAsyncNodeProver, NodeProverPool},
		proof_aggregation::GenericAggregatorConfig,
	};

	// -----------------------------------------------------------------------
	// Helpers
	// -----------------------------------------------------------------------

	fn build_leaf_circuit(n_pi: usize) -> (CircuitData<F, ConfigNative, D>, Vec<Target>) {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let targets: Vec<Target> = (0..n_pi).map(|_| builder.add_virtual_target()).collect();
		for &t in &targets {
			builder.register_public_input(t);
		}
		(builder.build::<ConfigNative>(), targets)
	}

	fn prove_leaf(
		circuit: &CircuitData<F, ConfigNative, D>,
		targets: &[Target],
		values: &[u64],
	) -> Result<ProofWithPublicInputs<F, ConfigNative, D>> {
		let mut pw = PartialWitness::new();
		for (&t, &v) in targets.iter().zip(values.iter()) {
			pw.set_target(t, F::from_canonical_u64(v))?;
		}
		circuit.prove(pw)
	}

	fn make_aggregator(
		arity: usize,
		depth: usize,
		leaf_circuit: &CircuitData<F, ConfigNative, D>,
	) -> Result<Arc<GenericAggregator<F, ConfigNative, D>>> {
		let cfg = GenericAggregatorConfig {
			arity,
			depth,
		};
		let agg = GenericAggregator::new(
			cfg,
			leaf_circuit.common.clone(),
			leaf_circuit.verifier_only.clone(),
		)?;
		Ok(Arc::new(agg))
	}

	fn make_local_pool(
		agg: Arc<GenericAggregator<F, ConfigNative, D>>,
	) -> Arc<NodeProverPool<F, ConfigNative, D>> {
		let local: Arc<dyn AsyncNodeProver<F, ConfigNative, D>> =
			Arc::new(LocalAsyncNodeProver::new(agg));
		Arc::new(NodeProverPool::new(vec![local]))
	}

	// -----------------------------------------------------------------------
	// NodeState unit tests
	// -----------------------------------------------------------------------

	#[test]
	fn test_node_state_fill_and_drain() -> Result<()> {
		let (leaf_circuit, targets) = build_leaf_circuit(2);
		let mut node: NodeState<F, ConfigNative, D> = NodeState::new(2);
		assert!(!node.is_full());

		let p0 = prove_leaf(&leaf_circuit, &targets, &[1, 2])?;
		let p1 = prove_leaf(&leaf_circuit, &targets, &[3, 4])?;

		node.insert(0, p0)?;
		assert!(!node.is_full());
		node.insert(1, p1)?;
		assert!(node.is_full(), "node must be full after arity insertions");

		let drained = node.drain_children();
		assert_eq!(drained.len(), 2);
		Ok(())
	}

	#[test]
	fn test_node_state_duplicate_insert() -> Result<()> {
		let (leaf_circuit, targets) = build_leaf_circuit(2);
		let mut node: NodeState<F, ConfigNative, D> = NodeState::new(2);

		let p0 = prove_leaf(&leaf_circuit, &targets, &[1, 2])?;
		let p1 = prove_leaf(&leaf_circuit, &targets, &[1, 2])?;

		node.insert(0, p0)?;
		let result = node.insert(0, p1);
		assert!(result.is_err(), "duplicate position must return Err");
		Ok(())
	}

	// -----------------------------------------------------------------------
	// Session integration tests
	// -----------------------------------------------------------------------

	/// Submitting out-of-range leaf_idx must return Err immediately.
	#[tokio::test]
	async fn test_session_oob_leaf_idx() -> Result<()> {
		let (leaf_circuit, targets) = build_leaf_circuit(2);
		let agg = make_aggregator(2, 1, &leaf_circuit)?;
		let pool = make_local_pool(agg.clone());

		let (handle, _root_fut) = start_aggregation_session(agg, pool);

		let p0 = prove_leaf(&leaf_circuit, &targets, &[1, 2])?;
		let result = handle.submit(99, p0).await;
		assert!(result.is_err(), "oob leaf_idx must return Err");
		Ok(())
	}

	/// 2 leaf proofs → root  (arity=2, depth=1).
	#[tokio::test]
	async fn test_session_arity2_depth1() -> Result<()> {
		let (leaf_circuit, targets) = build_leaf_circuit(2);
		let agg = make_aggregator(2, 1, &leaf_circuit)?;
		let pool = make_local_pool(agg.clone());

		let (handle, root_fut) = start_aggregation_session(agg.clone(), pool);

		let p0 = prove_leaf(&leaf_circuit, &targets, &[10, 20])?;
		let p1 = prove_leaf(&leaf_circuit, &targets, &[30, 40])?;
		handle.submit(0, p0).await?;
		handle.submit(1, p1).await?;
		drop(handle);

		let root = root_fut.await?;
		agg.verify_root(&root)?;
		Ok(())
	}

	/// 4 leaf proofs → root  (arity=2, depth=2).
	#[tokio::test]
	async fn test_session_arity2_depth2() -> Result<()> {
		let (leaf_circuit, targets) = build_leaf_circuit(2);
		let agg = make_aggregator(2, 2, &leaf_circuit)?;
		let pool = make_local_pool(agg.clone());

		let (handle, root_fut) = start_aggregation_session(agg.clone(), pool);

		for i in 0u64..4 {
			let p = prove_leaf(&leaf_circuit, &targets, &[i * 10, i * 10 + 1])?;
			handle.submit(i as usize, p).await?;
		}
		drop(handle);

		let root = root_fut.await?;
		agg.verify_root(&root)?;
		Ok(())
	}

	/// Submitting in reverse order must still produce a valid root.
	#[tokio::test]
	async fn test_session_out_of_order_submit() -> Result<()> {
		let (leaf_circuit, targets) = build_leaf_circuit(2);
		let agg = make_aggregator(2, 2, &leaf_circuit)?;
		let pool = make_local_pool(agg.clone());

		let (handle, root_fut) = start_aggregation_session(agg.clone(), pool);

		// Submit in reverse order.
		for i in (0u64..4).rev() {
			let p = prove_leaf(&leaf_circuit, &targets, &[i, i + 1])?;
			handle.submit(i as usize, p).await?;
		}
		drop(handle);

		let root = root_fut.await?;
		agg.verify_root(&root)?;
		Ok(())
	}

	/// Submitting the same leaf_idx twice must cause the root future to resolve
	/// to `Err`.
	#[tokio::test]
	async fn test_session_duplicate_leaf_idx() -> Result<()> {
		let (leaf_circuit, targets) = build_leaf_circuit(2);
		let agg = make_aggregator(2, 1, &leaf_circuit)?;
		let pool = make_local_pool(agg.clone());

		let (handle, root_fut) = start_aggregation_session(agg, pool);

		let p0 = prove_leaf(&leaf_circuit, &targets, &[1, 2])?;
		let p0b = prove_leaf(&leaf_circuit, &targets, &[1, 2])?;
		let p1 = prove_leaf(&leaf_circuit, &targets, &[3, 4])?;

		handle.submit(0, p0).await?;
		handle.submit(0, p0b).await?; // duplicate — actor will exit with Err
								// The actor may have already exited by now; ignore send errors.
		let _ = handle.submit(1, p1).await;
		drop(handle);

		let result = root_fut.await;
		assert!(result.is_err(), "duplicate leaf must propagate as Err");
		Ok(())
	}

	/// Drop handle early (before all leaves submitted) → root future resolves
	/// to Err containing "abandoned".
	#[tokio::test]
	async fn test_session_handle_dropped_early() -> Result<()> {
		let (leaf_circuit, targets) = build_leaf_circuit(2);
		let agg = make_aggregator(2, 1, &leaf_circuit)?;
		let pool = make_local_pool(agg.clone());

		let (handle, root_fut) = start_aggregation_session(agg, pool);

		// Submit only 1 of 2 required leaf proofs, then drop the handle.
		let p0 = prove_leaf(&leaf_circuit, &targets, &[1, 2])?;
		handle.submit(0, p0).await?;
		drop(handle);

		let result = root_fut.await;
		assert!(result.is_err(), "abandoned session must resolve to Err");
		let msg = result.unwrap_err().to_string();
		assert!(
			msg.contains("abandoned"),
			"error message must mention 'abandoned', got: {msg}"
		);
		Ok(())
	}

	/// `ARITY^DEPTH` leaf proofs → root, submitted in random order.
	/// Gated under `#[ignore]` because building the aggregator takes ~10 s.
	/// Add -- --include-ignored to run it.
	/// Adjust `ARITY` and `DEPTH` to test different tree shapes.
	#[tokio::test]
	#[ignore]
	async fn test_session_arity2_depth3() -> Result<()> {
		const ARITY: usize = 2;
		const DEPTH: usize = 7;

		let n_leaves = ARITY.pow(DEPTH as u32);

		let (leaf_circuit, targets) = build_leaf_circuit(ARITY);
		let agg = make_aggregator(ARITY, DEPTH, &leaf_circuit)?;
		let pool = make_local_pool(agg.clone());

		let (handle, root_fut) = start_aggregation_session(agg.clone(), pool);

		// Submit all leaves in shuffled order (Fisher-Yates via sort_by on hash).
		let mut indices: Vec<usize> = (0..n_leaves).collect();
		indices.sort_by_key(|&i| (i * 2654435761) % n_leaves); // deterministic shuffle
		let now = Instant::now();
		for i in indices {
			let p = prove_leaf(&leaf_circuit, &targets, &[i as u64, i as u64 + 1])?;
			handle.submit(i, p).await?;
			println!("submitted: {i}");
		}
		drop(handle);
		println!("proved: {:?}", now.elapsed());

		let root = root_fut.await?;
		println!("proved: {:?}", now.elapsed());
		agg.verify_root(&root)?;
		Ok(())
	}
}
