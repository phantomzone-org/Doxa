use std::time::Duration;

use anyhow::Context;
use reqwest::StatusCode;

use crate::types::{
	ConsumeOutcome, ConsumeProveRequest, ProveOutcome, ProveOutcomeV2, ProveRequest, ProveRequestV2,
};

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

	pub async fn prove_consume(
		&self,
		request: ConsumeProveRequest,
	) -> anyhow::Result<ConsumeOutcome> {
		let url = format!("{}/prove-consume", self.base_url);
		let response = self
			.client
			.post(url)
			.json(&request)
			.send()
			.await
			.context("send prove-consume request to prover service")?;

		let status = response.status();
		if status != StatusCode::OK {
			let body = response.text().await.unwrap_or_default();
			return Err(anyhow::anyhow!("prover service returned {status}: {body}"));
		}

		response
			.json::<ConsumeOutcome>()
			.await
			.context("decode prove-consume response from prover service")
	}

	pub async fn prove_v2(&self, request: ProveRequestV2) -> anyhow::Result<ProveOutcomeV2> {
		let url = format!("{}/prove-v2", self.base_url);
		let response = self
			.client
			.post(url)
			.json(&request)
			.send()
			.await
			.context("send prove-v2 request to prover service")?;

		let status = response.status();
		if status != StatusCode::OK {
			let body = response.text().await.unwrap_or_default();
			return Err(anyhow::anyhow!("prover service returned {status}: {body}"));
		}

		response
			.json::<ProveOutcomeV2>()
			.await
			.context("decode prove-v2 response from prover service")
	}
}
