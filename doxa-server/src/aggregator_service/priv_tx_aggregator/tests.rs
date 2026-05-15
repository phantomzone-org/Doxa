use doxa_client::{FakeSpendTxBuilder, NOTE_BATCH, PRIV_TX_BATCH_SIZE, SUBTREE_BATCHSIZE};

// ── E2E test ─────────────────────────────────────────────────────────────────
//
// Requires pre-generated artifacts under `<workspace>/artifacts/priv-tx/`.
// If missing, the test fails with instructions to generate them.
//
// Run with:
//   cargo test -p doxa-server --release -- --include-ignored priv_tx_batch_to_groth16_e2e
#[test]
#[ignore]
fn priv_tx_batch_to_groth16_e2e() {
	use std::path::Path;

	use plonky2::field::types::PrimeField64;
	use doxa_client::{build_priv_tx_circuit, DoxaGateSerializer};
	use doxa_utils::{
		groth::{BN128Wrapper, Groth16Wrapper},
		hasher::HashOutput,
	};

	use super::PrivTxAggregator;
	use crate::{
		batch_helper::{BatchHelper, SolidityKeccak256},
		prover_service::priv_tx::PrivateTxBatch,
	};

	// ── Artifact paths ───────────────────────────────────────────────────────
	let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
	let agg_path = workspace.join("artifacts/priv-tx");
	let plonky2_path = agg_path.join("plonky2-proof");
	let groth_path = agg_path.join("groth-artifacts");

	const GEN_CMD: &str = "  cargo run -p doxa-e2e --bin priv_tx_artifacts --release";

	if !PrivTxAggregator::has_full_artifacts(&agg_path).unwrap_or(false) {
		panic!(
			"PrivTxAggregator artifacts not found at {agg_path:?}.\n\
			 Generate them with:\n{GEN_CMD}"
		);
	}
	if !BN128Wrapper::has_full_artifacts(&plonky2_path) {
		panic!(
			"BN128 plonky2-proof artifacts not found at {plonky2_path:?}.\n\
			 Generate them with:\n{GEN_CMD}"
		);
	}
	let pk = groth_path.join("proving.key");
	let vk = groth_path.join("verifying.key");
	let r1cs = groth_path.join("r1cs");
	if !pk.exists() || !vk.exists() || !r1cs.exists() {
		panic!(
			"Groth16 artifacts not found at {groth_path:?} (missing proving.key / verifying.key / r1cs).\n\
			 Generate them with:\n{GEN_CMD}"
		);
	}

	// ── 1. Load PrivTxAggregator from artifacts ──────────────────────────────
	let agg = PrivTxAggregator::from_artifacts(&agg_path, &DoxaGateSerializer)
		.expect("PrivTxAggregator::from_artifacts");

	// ── 2. Populate and finalize a PrivateTxBatch ────────────────────────────
	// Add 1 dummy proof; finalize() pads the remaining 63 slots automatically.
	let privtx_circ = build_priv_tx_circuit();
	let fake_privtx_proof = FakeSpendTxBuilder::new(
		HashOutput(Default::default()),
		HashOutput(Default::default()),
	)
	.build()
	.into_priv_tx()
	.prove(&privtx_circ.circuit_data, &privtx_circ.targets)
	.expect("FakeSpendTxBuilder prove failed");

	let mut batch = PrivateTxBatch::new();
	batch.add_proof(fake_privtx_proof).expect("add_proof");
	batch.finalize().expect("finalize");

	assert_eq!(batch.proofs().len(), PRIV_TX_BATCH_SIZE);

	let pi_commitment = batch
		.pi_commitment::<SolidityKeccak256>()
		.expect("pi_commitment");

	// ── 3. Prove the batch → super proof (8 u32 public inputs) ──────────────
	let super_proof = agg.prove(&batch).expect("PrivTxAggregator::prove");
	assert_eq!(super_proof.public_inputs.len(), 8);

	// TODO: better way to map PI to Vec<u8>
	let pi_from_proof: [u8; 32] = {
		let mut out = [0u8; 32];
		for (i, f) in super_proof.public_inputs.iter().enumerate() {
			let w = f.to_canonical_u64() as u32;
			out[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
		}
		out
	};
	assert_eq!(
		pi_from_proof, pi_commitment,
		"super proof PIs must match batch pi_commitment"
	);

	// ── 4. BN128 wrap (in-memory; uses pre-built circuit structure) ──────────
	let bn128 = BN128Wrapper::new(agg.super_circuit_data().clone(), super_proof.clone())
		.expect("BN128Wrapper::new");

	// ── 5. Load Groth16 from pre-built artifacts + prove + verify ────────────
	let label = "priv_tx_e2e";
	Groth16Wrapper::init_with_label(label, &plonky2_path, &groth_path)
		.expect("Groth16Wrapper::init_with_label");

	let bn128_proof = bn128
		.wrap_proof_to_bn128(super_proof)
		.expect("wrap_proof_to_bn128");
	let (g16_proof, g16_pub_inp) =
		Groth16Wrapper::prove_with_label(label, bn128_proof).expect("Groth16 prove");
	Groth16Wrapper::verify_with_label(label, g16_proof, g16_pub_inp).expect("Groth16 verify");
}

// ── Config / preimage tests ───────────────────────────────────────────────────

use crate::aggregator_service::generic_aggregator::GenericAggregatorConfig;

/// `GenericAggregatorConfig{arity=8, depth=2}` must be valid (`8^2 = 64 slots`).
#[test]
fn priv_tx_agg_config_is_valid() {
	let cfg = GenericAggregatorConfig {
		arity: 8,
		depth: 2,
	};
	assert!(cfg.validate().is_ok(), "config must be valid");
	assert_eq!(
		cfg.arity.pow(cfg.depth as u32),
		PRIV_TX_BATCH_SIZE,
		"8^2 must equal PRIV_TX_BATCH_SIZE"
	);
}

/// Each PrivTx slot produces `1 + NOTE_BATCH` SR leaves; total must equal
/// `SUBTREE_BATCHSIZE`.
#[test]
fn priv_tx_sr_leaf_count_matches() {
	let leaves_per_slot = 1 + NOTE_BATCH;
	assert_eq!(
		PRIV_TX_BATCH_SIZE * leaves_per_slot,
		SUBTREE_BATCHSIZE,
		"PRIV_TX_BATCH_SIZE * (1+NOTE_BATCH) must equal SUBTREE_BATCHSIZE"
	);
}

/// Verify the expected Keccak preimage word count matches `BatchHelper::pi_commitment`.
///
/// Preimage = sr_root[4] + act_root[4] + mcr[4] + 64 * unique_pis_per_slot
/// unique_pis_per_slot = not_fake_tx[1] + accin_null[4] + accout_comm[4]
///   + inotes_null[7×4=28] + onotes_comm[7×4=28] = 65 fields
/// Total fields = 12 + 64×65 = 4172 → u32 words = 4172×2 = 8344.
#[test]
fn priv_tx_preimage_word_count() {
	let unique_per_slot = 1 + 4 + 4 + NOTE_BATCH * 4 + NOTE_BATCH * 4; // = 65
	let total_fields = 4 + 4 + 4 + PRIV_TX_BATCH_SIZE * unique_per_slot;
	assert_eq!(total_fields, 4172, "total preimage fields");
	assert_eq!(total_fields * 2, 8344, "total preimage u32 words");
}
