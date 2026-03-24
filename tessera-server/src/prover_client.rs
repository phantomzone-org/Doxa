use std::{future::Future, pin::Pin, time::Duration};

use anyhow::Context;
use reqwest::StatusCode;

use crate::types::{ProveOutcome, ProveRequest};

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Abstract interface for the proving service.
///
/// Both [`HttpProverClient`] (remote prover over HTTP) and
/// `InProcessProver` (from `tessera-e2e`) implement this trait.
pub trait ProverClient: Send + Sync {
	fn prove_tx(
		&self,
		req: ProveRequest,
	) -> Pin<Box<dyn Future<Output = anyhow::Result<ProveOutcome>> + Send + 'static>>;
}

// ---------------------------------------------------------------------------
// HttpProverClient
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct HttpProverClient {
	client: reqwest::Client,
	base_url: String,
}

impl HttpProverClient {
	pub fn new(base_url: String, timeout: Duration) -> anyhow::Result<Self> {
		let client = reqwest::Client::builder()
			.timeout(timeout)
			.build()
			.context("build prover HTTP client")?;
		Ok(Self {
			client,
			base_url: base_url.trim_end_matches('/').to_string(),
		})
	}
}

impl ProverClient for HttpProverClient {
	fn prove_tx(
		&self,
		req: ProveRequest,
	) -> Pin<Box<dyn Future<Output = anyhow::Result<ProveOutcome>> + Send + 'static>> {
		let client = self.client.clone();
		let base_url = self.base_url.clone();
		Box::pin(async move {
			let url = format!("{base_url}/prove-v2");
			let response = client
				.post(url)
				.json(&req)
				.send()
				.await
				.context("send prove-v2 request to prover service")?;
			let status = response.status();
			if status != StatusCode::OK {
				let body = response.text().await.unwrap_or_default();
				return Err(anyhow::anyhow!("prover service returned {status}: {body}"));
			}
			response
				.json::<ProveOutcome>()
				.await
				.context("decode prove-v2 response from prover service")
		})
	}
}
