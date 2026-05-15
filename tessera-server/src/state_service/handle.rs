use tessera_trees::MerkleProof;
use tessera_utils::hasher::HashOutput;
use tokio::sync::{mpsc, oneshot};

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// A request sent from a [`StateServiceHandle`] to the [`StateService`] actor.
pub enum StateServiceRequest {
	/// Look up the zero-based tree index for a leaf commitment.
	GetLeafIndex {
		/// The raw 32-byte leaf commitment to look up.
		commitment: [u8; 32],
		/// Channel on which the result is returned.
		///
		/// `None` if the commitment is not in the local tree.
		reply: oneshot::Sender<Option<usize>>,
	},
	/// Return the full Merkle proof (siblings) for a leaf identified by its
	/// commitment.
	GetSiblings {
		/// The raw 32-byte leaf commitment whose siblings are requested.
		commitment: [u8; 32],
		/// Channel on which the result is returned.
		///
		/// `Err` if the commitment is unknown or the proof cannot be
		/// generated.
		reply: oneshot::Sender<anyhow::Result<MerkleProof<HashOutput>>>,
	},
	/// Check whether `root` is in the set of confirmed on-chain roots.
	IsConfirmedRoot {
		root: HashOutput,
		reply: oneshot::Sender<bool>,
	},
	/// Check whether `nullifier` has been recorded as spent on-chain.
	ContainsNullifier {
		nullifier: [u8; 32],
		reply: oneshot::Sender<bool>,
	},
	/// Return the current Poseidon root of the local tree.
	///
	/// This mirrors the on-chain `currentRoot()` after all proven batches have
	/// been applied by the sync loop.
	GetCurrentRoot { reply: oneshot::Sender<HashOutput> },
}

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

/// A cheap-to-clone handle for communicating with the [`StateService`] actor.
///
/// All methods are async and return once the actor has processed the request.
/// The handle can be freely shared across tasks.
#[derive(Clone)]
pub struct StateServiceHandle {
	pub(super) tx: mpsc::Sender<StateServiceRequest>,
}

impl StateServiceHandle {
	/// Return the zero-based tree index for `commitment`.
	///
	/// Returns `Ok(None)` if the commitment is not yet in the local tree.
	///
	/// # Errors
	/// Returns `Err` if the actor channel is closed.
	pub async fn get_leaf_index(&self, commitment: [u8; 32]) -> anyhow::Result<Option<usize>> {
		let (reply_tx, reply_rx) = oneshot::channel();
		self.tx
			.send(StateServiceRequest::GetLeafIndex {
				commitment,
				reply: reply_tx,
			})
			.await
			.map_err(|_| anyhow::anyhow!("StateService actor is no longer running"))?;
		reply_rx
			.await
			.map_err(|_| anyhow::anyhow!("StateService dropped the reply sender"))
	}

	/// Return the full Merkle proof for the leaf identified by `commitment`.
	///
	/// The returned [`MerkleProof`] contains:
	/// - the leaf value,
	/// - siblings at every level from depth 0 to the root,
	/// - direction bits (left/right) for each level,
	/// - the current tree root.
	///
	/// # Errors
	/// Returns `Err` if the commitment is unknown, the proof cannot be
	/// generated, or the actor channel is closed.
	pub async fn get_siblings(
		&self,
		commitment: [u8; 32],
	) -> anyhow::Result<MerkleProof<HashOutput>> {
		let (reply_tx, reply_rx) = oneshot::channel();
		self.tx
			.send(StateServiceRequest::GetSiblings {
				commitment,
				reply: reply_tx,
			})
			.await
			.map_err(|_| anyhow::anyhow!("StateService actor is no longer running"))?;
		reply_rx
			.await
			.map_err(|_| anyhow::anyhow!("StateService dropped the reply sender"))?
	}

	/// Return `true` if `root` is in the set of confirmed on-chain roots.
	///
	/// # Errors
	/// Returns `Err` if the actor channel is closed.
	pub async fn is_confirmed_root(&self, root: HashOutput) -> anyhow::Result<bool> {
		let (reply_tx, reply_rx) = oneshot::channel();
		self.tx
			.send(StateServiceRequest::IsConfirmedRoot {
				root,
				reply: reply_tx,
			})
			.await
			.map_err(|_| anyhow::anyhow!("StateService actor is no longer running"))?;
		reply_rx
			.await
			.map_err(|_| anyhow::anyhow!("StateService dropped the reply sender"))
	}

	/// Return `true` if `nullifier` has been recorded as spent on-chain.
	///
	/// # Errors
	/// Returns `Err` if the actor channel is closed.
	pub async fn contains_nullifier(&self, nullifier: [u8; 32]) -> anyhow::Result<bool> {
		let (reply_tx, reply_rx) = oneshot::channel();
		self.tx
			.send(StateServiceRequest::ContainsNullifier {
				nullifier,
				reply: reply_tx,
			})
			.await
			.map_err(|_| anyhow::anyhow!("StateService actor is no longer running"))?;
		reply_rx
			.await
			.map_err(|_| anyhow::anyhow!("StateService dropped the reply sender"))
	}

	/// Return the current Poseidon root of the local mirror tree.
	///
	/// This value is updated by the sync loop whenever a new proven batch is
	/// applied and reflects the latest on-chain `currentRoot()` as seen by the
	/// [`StateService`].
	///
	/// # Errors
	/// Returns `Err` if the actor channel is closed.
	pub async fn current_root(&self) -> anyhow::Result<HashOutput> {
		let (reply_tx, reply_rx) = oneshot::channel();
		self.tx
			.send(StateServiceRequest::GetCurrentRoot {
				reply: reply_tx,
			})
			.await
			.map_err(|_| anyhow::anyhow!("StateService actor is no longer running"))?;
		reply_rx
			.await
			.map_err(|_| anyhow::anyhow!("StateService dropped the reply sender"))
	}
}
