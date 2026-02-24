#![cfg(feature = "integration-tests")]

use std::{
	path::{Path, PathBuf},
	process::{Child, Command, Stdio},
	thread,
	time::{Duration, Instant},
};

fn workspace_root() -> PathBuf {
	Path::new(env!("CARGO_MANIFEST_DIR"))
		.parent()
		.expect("tessera-server must live under workspace root")
		.to_path_buf()
}

struct ChildGuard {
	child: Child,
}

impl ChildGuard {
	fn spawn_anvil() -> anyhow::Result<Self> {
		let child = Command::new("anvil")
			.arg("--host")
			.arg("127.0.0.1")
			.arg("--port")
			.arg("8545")
			.arg("--chain-id")
			.arg("31337")
			.stdin(Stdio::null())
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.spawn()?;
		Ok(Self {
			child,
		})
	}
}

impl Drop for ChildGuard {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

fn wait_for_rpc(rpc_url: &str, timeout: Duration) -> anyhow::Result<()> {
	let deadline = Instant::now() + timeout;
	while Instant::now() < deadline {
		let ok = Command::new("cast")
			.arg("block-number")
			.arg("--rpc-url")
			.arg(rpc_url)
			.stdin(Stdio::null())
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.status()
			.map(|s| s.success())
			.unwrap_or(false);
		if ok {
			return Ok(());
		}
		thread::sleep(Duration::from_millis(500));
	}
	anyhow::bail!("RPC did not become ready at {rpc_url} within {:?}", timeout)
}

fn run_script(script: &str, timeout: Duration) -> anyhow::Result<()> {
	let root = workspace_root();
	let mut child = Command::new("bash")
		.arg(root.join(script))
		.current_dir(&root)
		.spawn()?;

	let deadline = Instant::now() + timeout;
	loop {
		if let Some(status) = child.try_wait()? {
			anyhow::ensure!(status.success(), "script failed: {script}");
			return Ok(());
		}
		if Instant::now() >= deadline {
			let _ = child.kill();
			let _ = child.wait();
			anyhow::bail!("script timed out: {script}");
		}
		thread::sleep(Duration::from_secs(1));
	}
}

fn run_cmd_with_timeout(mut cmd: Command, timeout: Duration, context: &str) -> anyhow::Result<()> {
	let mut child = cmd.spawn()?;
	let deadline = Instant::now() + timeout;
	loop {
		if let Some(status) = child.try_wait()? {
			anyhow::ensure!(status.success(), "{context} failed");
			return Ok(());
		}
		if Instant::now() >= deadline {
			let _ = child.kill();
			let _ = child.wait();
			anyhow::bail!("{context} timed out");
		}
		thread::sleep(Duration::from_secs(1));
	}
}

fn artifacts_ready(root: &Path) -> bool {
	let required = [
		"tessera-server/artifacts/commitment-tree/plonky2-proof/bn128_circuit_data.bin",
		"tessera-server/artifacts/commitment-tree/groth-artifacts/Verifier.sol",
		"tessera-server/artifacts/commitment-tree/groth-artifacts/proving.key",
		"tessera-server/artifacts/nullifier-tree/plonky2-proof/bn128_circuit_data.bin",
		"tessera-server/artifacts/nullifier-tree/groth-artifacts/Verifier.sol",
		"tessera-server/artifacts/nullifier-tree/groth-artifacts/proving.key",
	];
	required.iter().all(|p| root.join(p).is_file())
}

fn ensure_artifacts(root: &Path) -> anyhow::Result<()> {
	let force = std::env::var("TESSERA_REBUILD_ARTIFACTS").ok().as_deref() == Some("1");
	if artifacts_ready(root) && !force {
		eprintln!("Artifacts already present; skipping regeneration.");
		return Ok(());
	}

	eprintln!("Generating commitment-tree artifacts...");
	let mut commitment_cmd = Command::new("cargo");
	commitment_cmd
		.arg("run")
		.arg("--bin")
		.arg("commitment_tree_artifacts")
		.arg("--release")
		.current_dir(root.join("tessera-server"));
	run_cmd_with_timeout(
		commitment_cmd,
		Duration::from_secs(60 * 60),
		"commitment_tree_artifacts generation",
	)?;

	eprintln!("Generating nullifier-tree artifacts...");
	let mut nullifier_cmd = Command::new("cargo");
	nullifier_cmd
		.arg("run")
		.arg("--bin")
		.arg("nullifier_tree_artifacts")
		.arg("--release")
		.current_dir(root.join("tessera-server"));
	run_cmd_with_timeout(
		nullifier_cmd,
		Duration::from_secs(60 * 60),
		"nullifier_tree_artifacts generation",
	)?;

	anyhow::ensure!(
		artifacts_ready(root),
		"artifact generation completed but required files are still missing"
	);
	Ok(())
}

/// End-to-end scripted integration — full optimistic two-phase flow:
/// 1) start anvil
/// 2) ensure artifacts exist (cached by presence on disk)
/// 3) deploy contracts
/// 4) run full-flow orchestrator which:
///    - starts the prover service
///    - starts the sequencer service
///    - submits a private-tx covering REQUEST_COUNT deposited notes via `/private-tx`
///    - waits for Phase A (registerTransactionBatchUpdate on-chain, deposits Validated)
///    - waits for Phase B (all 4 confirmTreeUpdate calls complete, confirmed roots advance)
///
/// This test is opt-in by design.
#[test]
fn scripted_full_flow_e2e() -> anyhow::Result<()> {
	if std::env::var("TESSERA_RUN_INTEGRATION_SCRIPTS")
		.ok()
		.as_deref()
		!= Some("1")
	{
		eprintln!(
			"Skipping integration script test. Set TESSERA_RUN_INTEGRATION_SCRIPTS=1 to enable."
		);
		return Ok(());
	}

	let root = workspace_root();
	ensure_artifacts(&root)?;

	let _anvil = ChildGuard::spawn_anvil()?;
	wait_for_rpc("http://127.0.0.1:8545", Duration::from_secs(30))?;

	run_script(
		"scripts/local_e2e_toy_b_deploy.sh",
		Duration::from_secs(240),
	)?;
	// Timeout budget breakdown:
	//   wait_for_prover_api  ≤ 300 s  (circuit load blocks server bind)
	//   wait_for_sequencer   ≤  90 s
	//   deposit creation     ≤ 200 s  (256 × cast send on anvil)
	//   Phase A register     ≤ 120 s
	//   Phase B 4 proofs     ≤ 1800 s (4 sequential Groth16 proofs)
	run_script(
		"scripts/local_e2e_toy_full_flow.sh",
		Duration::from_secs(3600),
	)?;

	Ok(())
}

/// End-to-end scripted integration:
/// 1) start anvil
/// 2) ensure artifacts exist (cached by presence on disk)
/// 3) deploy contracts
/// 4) run chain-recovery scenario
///
/// This test is opt-in by design.
#[test]
fn scripted_chain_recovery_e2e() -> anyhow::Result<()> {
	if std::env::var("TESSERA_RUN_INTEGRATION_SCRIPTS")
		.ok()
		.as_deref()
		!= Some("1")
	{
		eprintln!(
			"Skipping integration script test. Set TESSERA_RUN_INTEGRATION_SCRIPTS=1 to enable."
		);
		return Ok(());
	}

	let root = workspace_root();
	ensure_artifacts(&root)?;

	let _anvil = ChildGuard::spawn_anvil()?;
	wait_for_rpc("http://127.0.0.1:8545", Duration::from_secs(30))?;

	run_script(
		"scripts/local_e2e_toy_b_deploy.sh",
		Duration::from_secs(240),
	)?;
	run_script(
		"scripts/local_recover_from_chain.sh",
		Duration::from_secs(900),
	)?;

	Ok(())
}
