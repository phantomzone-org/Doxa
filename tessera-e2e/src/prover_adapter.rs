//! In-process prover adapter that implements [`ProverClient`] using
//! [`ProverRuntimeV2`] directly (no HTTP round-trip).
//!
//! Loaded from artifact directories; returns `None` from [`InProcessProver::from_artifacts`]
//! when the artifact directories are absent so tests can skip gracefully.

use std::{future::Future, path::Path, pin::Pin, sync::Arc};

use tessera_server::{
	prover_client::ProverClient,
	prover_v2::{DepositPipelineConfig, ProverRuntimeV2},
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
	///   subtree-root/                  SubtreeRootCircuit (TX)
	///   v2-tx-aggregator/              GenericAggregator + dummy proof (TX)
	///   super-aggregator-v2/           SAV2 Plonky2 + BN128 + Groth16 (TX)
	///   deposit-tx-aggregator/         GenericAggregator + dummy proof (deposit, optional)
	///   deposit-subtree-root/          SubtreeRootCircuit (deposit, optional)
	///   deposit-super-aggregator-v2/   DSAV2 Plonky2 + BN128 + Groth16 (deposit, optional)
	/// ```
	///
	/// Returns `None` if any required TX directory is absent.
	/// Deposit directories are loaded when present; absent deposit dirs disable the deposit
	/// pipeline.
	pub fn from_artifacts(artifact_dir: &Path) -> Option<Self> {
		let sr_path = artifact_dir.join("subtree-root");
		let sav2_path = artifact_dir.join("super-aggregator-v2");
		let agg_path = artifact_dir.join("v2-tx-aggregator");

		for (name, path) in [
			("subtree-root", &sr_path),
			("super-aggregator-v2", &sav2_path),
			("v2-tx-aggregator", &agg_path),
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

		let sr_batch_size = tessera_client::PRIV_TX_BATCH_SIZE * tessera_client::NOTE_BATCH;

		// Deposit pipeline is optional — load when all three directories are present.
		let dep_agg_path = artifact_dir.join("deposit-tx-aggregator");
		let dep_sr_path = artifact_dir.join("deposit-subtree-root");
		let dep_sav2_path = artifact_dir.join("deposit-super-aggregator-v2");
		let deposit = if dep_agg_path.exists() && dep_sr_path.exists() && dep_sav2_path.exists() {
			Some(DepositPipelineConfig {
				deposit_tx_aggregator_path: dep_agg_path,
				deposit_subtree_root_path: dep_sr_path,
				deposit_super_aggregator_path: dep_sav2_path,
			})
		} else {
			None
		};

		let runtime = match ProverRuntimeV2::init(
			sr_path,
			sr_batch_size,
			sav2_path,
			Some(agg_path),
			vec![],
			300,
			deposit,
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
