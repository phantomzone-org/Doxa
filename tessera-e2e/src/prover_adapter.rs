//! In-process prover adapter that implements [`ProverClient`] using
//! [`ProverRuntimeV2`] directly (no HTTP round-trip).
//!
//! Loaded from artifact directories; returns `None` from [`InProcessProver::from_artifacts`]
//! when the artifact directories are absent so tests can skip gracefully.

use std::{future::Future, path::Path, pin::Pin, sync::Arc};

use tessera_server::{
	prover_client::ProverClient,
	sequencer::TransactionProverRuntime,
	types::{ProveOutcome, ProveRequest},
};
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// InProcessProver
// ---------------------------------------------------------------------------

/// Wraps [`ProverRuntimeV2`] behind an async-safe mutex so it can be used
/// from the sequencer's `tokio::spawn` tasks.
pub struct InProcessProver {
	runtime: Arc<Mutex<TransactionProverRuntime>>,
}

impl InProcessProver {
	/// Load from pre-built artifact directories.
	///
	/// Expects the standard Tessera artifact layout under `artifact_dir`:
	/// ```text
	/// artifact_dir/
	///   subtree-root/                  SubtreeRootCircuit (TX)
	///   v2-tx-aggregator/              GenericAggregator + dummy proof (TX)
	///   super-aggregator-v2/           Final Plonky2 Proof Plonky2 + BN128 + Groth16 (TX)
	///   deposit-tx-aggregator/         GenericAggregator + dummy proof (deposit, optional)
	///   deposit-subtree-root/          SubtreeRootCircuit (deposit, optional)
	///   deposit-super-aggregator-v2/   DSAV2 Plonky2 + BN128 + Groth16 (deposit, optional)
	/// ```
	///
	/// Returns `None` if any required TX directory is absent.
	/// Deposit directories are loaded when present; absent deposit dirs disable the deposit
	/// pipeline.
	pub fn from_artifacts(artifact_dir: &Path) -> Option<Self> {
		let tx_root = artifact_dir.join("transactions");
		let sr_path = tx_root.join("subtree-root");
		let sav2_path = tx_root.join("super-aggregator");
		let agg_path = tx_root.join("tx-aggregator");

		for (name, path) in [
			("transactions/subtree-root", &sr_path),
			("transactions/super-aggregator", &sav2_path),
			("transactions/tx-aggregator", &agg_path),
		] {
			if !path.exists() {
				eprintln!(
					"InProcessProver: required TX artifact dir '{}' not found at {}",
					name,
					path.display()
				);
				return None;
			}
		}

		// SR has NOTE_BATCH NC leaves + 1 AC leaf per TX slot = (NOTE_BATCH+1) leaves per slot.
		let sr_batch_size = tessera_client::PRIV_TX_BATCH_SIZE * (tessera_client::NOTE_BATCH + 1);

		let runtime = match TransactionProverRuntime::init(
			sr_path,
			sr_batch_size,
			sav2_path,
			Some(agg_path),
			vec![],
			300,
		) {
			Ok(r) => r,
			Err(e) => {
				eprintln!("ProverRuntimeV2::init failed: {e:#}");
				return None;
			},
		};

		Some(Self {
			runtime: Arc::new(Mutex::new(runtime)),
		})
	}
}

impl ProverClient for InProcessProver {
	fn prove_tx(
		&self,
		req: ProveRequest,
	) -> Pin<Box<dyn Future<Output = anyhow::Result<ProveOutcome>> + Send + 'static>> {
		let runtime = self.runtime.clone();
		Box::pin(async move {
			let outcome = tokio::task::spawn_blocking(move || {
				// Block until the mutex is available then prove.
				let rt = tokio::runtime::Handle::current();
				rt.block_on(async { runtime.lock().await })
					.prove_request(req)
			})
			.await
			.map_err(|e| anyhow::anyhow!("spawn_blocking join error: {e}"))?;
			Ok(outcome)
		})
	}
}
