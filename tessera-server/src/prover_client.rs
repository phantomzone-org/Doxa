use std::time::Duration;

use anyhow::Context;
use reqwest::StatusCode;

use crate::types::{ProveOutcome, ProveRequest};

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

	pub async fn prove(&self, request: ProveRequest) -> anyhow::Result<ProveOutcome> {
		let url = format!("{}/prove", self.base_url);
		let response = self
			.client
			.post(url)
			.json(&request)
			.send()
			.await
			.context("send prove request to prover service")?;

		let status = response.status();
		if status != StatusCode::OK {
			let body = response.text().await.unwrap_or_default();
			return Err(anyhow::anyhow!("prover service returned {status}: {body}"));
		}

		response
			.json::<ProveOutcome>()
			.await
			.context("decode prove response from prover service")
	}
}
