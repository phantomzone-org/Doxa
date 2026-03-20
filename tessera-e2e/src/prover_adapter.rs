//! In-process prover adapter that implements [`ProverClient`] using
//! [`ProverRuntimeV2`] directly (no HTTP round-trip).
//!
//! Loaded from artifact directories; returns `None` from [`InProcessProver::from_artifacts`]
//! when the artifact directories are absent so tests can skip gracefully.

use std::{future::Future, path::Path, pin::Pin, sync::Arc};

use tessera_server::{
	prover_client::ProverClient,
	prover_v2::ProverRuntimeV2,
	types::{ConsumeOutcome, ConsumeProveRequest, ProveOutcomeV2, ProveRequestV2},
};
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// InProcessProver
// ---------------------------------------------------------------------------

/// Wraps [`ProverRuntimeV2`] behind an async-safe mutex so it can be used
/// from the sequencer's `tokio::spawn` tasks.
pub struct InProcessProver {
	runtime: Arc<Mutex<ProverRuntimeV2>>,
}

impl InProcessProver {
	/// Load from pre-built artifact directories.
	///
	/// Expects the standard Tessera artifact layout under `artifact_dir`:
	/// ```text
	/// artifact_dir/
	///   subtree-root/                  SubtreeRootCircuit
	///   v2-tx-aggregator/              GenericAggregator + dummy proof
	///   super-aggregator-v2/           SAV2 Plonky2 + BN128 + Groth16
	/// ```
	///
	/// Returns `None` if any required directory is absent.
	pub fn from_artifacts(artifact_dir: &Path) -> Option<Self> {
		let sr_path = artifact_dir.join("subtree-root");
		let sav2_path = artifact_dir.join("super-aggregator-v2");
		let agg_path = artifact_dir.join("v2-tx-aggregator");

		if !sr_path.exists() || !sav2_path.exists() || !agg_path.exists() {
			return None;
		}

		let sr_batch_size = tessera_client::PRIV_TX_BATCH_SIZE * tessera_client::NOTE_BATCH;

		let runtime = ProverRuntimeV2::init(
			sr_path,
			sr_batch_size,
			sav2_path,
			Some(agg_path),
			vec![],
			300,
		)
		.ok()?;

		Some(Self {
			runtime: Arc::new(Mutex::new(runtime)),
		})
	}
}

impl ProverClient for InProcessProver {
	fn prove_v2(
		&self,
		req: ProveRequestV2,
	) -> Pin<Box<dyn Future<Output = anyhow::Result<ProveOutcomeV2>> + Send + 'static>> {
		let runtime = self.runtime.clone();
		Box::pin(async move {
			let outcome = tokio::task::spawn_blocking(move || {
				// Block until the mutex is available then prove.
				let rt = tokio::runtime::Handle::current();
				rt.block_on(async { runtime.lock().await })
					.prove_request_v2(req)
			})
			.await
			.map_err(|e| anyhow::anyhow!("spawn_blocking join error: {e}"))?;
			Ok(outcome)
		})
	}

	fn prove_consume(
		&self,
		req: ConsumeProveRequest,
	) -> Pin<Box<dyn Future<Output = anyhow::Result<ConsumeOutcome>> + Send + 'static>> {
		let runtime = self.runtime.clone();
		Box::pin(async move {
			let outcome = tokio::task::spawn_blocking(move || {
				let rt = tokio::runtime::Handle::current();
				rt.block_on(async { runtime.lock().await })
					.prove_consume_request(req)
			})
			.await
			.map_err(|e| anyhow::anyhow!("spawn_blocking join error: {e}"))?;
			Ok(outcome)
		})
	}
}
