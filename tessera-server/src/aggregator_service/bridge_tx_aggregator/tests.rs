use tessera_client::{
	FakeDepositTxBuilder, FakeWithdrawTxBuilder, BRIDGE_TX_BATCH_SIZE, NOTE_BATCH,
	SUBTREE_BATCHSIZE,
};

// ── E2E test ─────────────────────────────────────────────────────────────────
//
// Requires pre-generated artifacts under `<workspace>/artifacts/bridge-tx/`.
// If missing, the test fails with instructions to generate them.
//
// Run with:
//   cargo test -p tessera-server --release -- --include-ignored bridge_tx_batch_to_groth16_e2e
#[test]
#[ignore]
fn bridge_tx_batch_to_groth16_e2e() {
	use std::path::Path;

	use plonky2::field::types::PrimeField64;
	use tessera_client::{
		build_deposit_tx_circuit, build_withdraw_tx_circuit, TesseraGateSerializer,
	};
	use tessera_utils::{
		groth::{BN128Wrapper, Groth16Wrapper},
		hasher::HashOutput,
	};

	use super::BridgeTxAggregator;
	use crate::{
		batch_helper::{BatchHelper, SolidityKeccak256},
		prover_service::bridge_tx::BridgeTxBatch,
	};

	// ── Artifact paths ───────────────────────────────────────────────────────
	let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
	let agg_path = workspace.join("artifacts/bridge-tx");
	let plonky2_path = agg_path.join("plonky2-proof");
	let groth_path = agg_path.join("groth-artifacts");

	const GEN_CMD: &str = "  cargo run -p tessera-e2e --bin bridge_tx_artifacts --release";

	if !BridgeTxAggregator::has_full_artifacts(&agg_path).unwrap_or(false) {
		panic!(
			"BridgeTxAggregator artifacts not found at {agg_path:?}.\n\
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

	// ── 1. Load BridgeTxAggregator from artifacts ────────────────────────────
	let agg = BridgeTxAggregator::from_artifacts(
		&agg_path,
		&TesseraGateSerializer,
		&TesseraGateSerializer,
	)
	.expect("BridgeTxAggregator::from_artifacts");

	// ── 2. Populate and finalize a BridgeTxBatch ─────────────────────────────
	// Add 1 withdraw + 1 deposit proof; finalize() pads the remaining slots.
	let w_circuit = build_withdraw_tx_circuit();
	let d_circuit = build_deposit_tx_circuit();
	let sr = HashOutput(Default::default());
	let mr = HashOutput(Default::default());
	let w_proof = FakeWithdrawTxBuilder::new(sr, mr)
		.build()
		.into_withdraw_tx()
		.prove(&w_circuit)
		.expect("FakeWithdrawTxBuilder build failed");
	let d_proof = FakeDepositTxBuilder::new(sr, mr)
		.build()
		.into_deposit_tx()
		.prove(&d_circuit)
		.expect("FakeDepositTxBuilder build failed");

	let mut batch = BridgeTxBatch::new();
	batch.add_proof(w_proof.into()).expect("add withdraw proof");
	batch.add_proof(d_proof.into()).expect("add deposit proof");
	batch.finalize().expect("finalize");

	assert_eq!(batch.proofs().len(), BRIDGE_TX_BATCH_SIZE);

	let pi_commitment = batch
		.pi_commitment::<SolidityKeccak256>()
		.expect("pi_commitment");

	// ── 3. Prove the batch → super proof (8 u32 public inputs) ──────────────
	let super_proof = agg.prove(&batch).expect("BridgeTxAggregator::prove");
	assert_eq!(super_proof.public_inputs.len(), 8);

	// TODO: come up with better method to translate PI to Vec<u8>
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
	let label = "bridge_tx_e2e";
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

const HALF: usize = BRIDGE_TX_BATCH_SIZE / 2;

/// The pair aggregator config: arity=4, depth=4 → 4^4 = 256 pair slots.
#[test]
fn bridge_tx_pair_agg_config_is_valid() {
	let cfg = GenericAggregatorConfig {
		arity: 4,
		depth: 4,
	};
	assert!(cfg.validate().is_ok(), "pair agg config must be valid");
	assert_eq!(
		cfg.arity.pow(cfg.depth as u32),
		HALF,
		"4^4 must equal HALF (256)"
	);
}

/// `HALF == 4^4 == 256` — the pair aggregator handles one pair per slot.
#[test]
fn bridge_tx_half_is_arity_power() {
	assert_eq!(HALF, 4_usize.pow(4), "HALF must equal 4^4");
	assert_eq!(
		HALF * 2,
		BRIDGE_TX_BATCH_SIZE,
		"2*HALF must equal BRIDGE_TX_BATCH_SIZE"
	);
}

/// SR leaf count: withdraw(256) + deposit(256) = 512 == SUBTREE_BATCHSIZE.
#[test]
fn bridge_tx_sr_leaf_count_matches() {
	assert_eq!(
		HALF + HALF,
		SUBTREE_BATCHSIZE,
		"2*HALF must equal SUBTREE_BATCHSIZE"
	);
}

/// Verify the expected pair PI count and Keccak preimage word count.
///
/// Pair PI layout per slot:
///   common[8] = act_root(4) + mainpool(4)
///   w_unique  = not_fake_tx(1) + accin_null(4) + accout_comm(4) + asset_ids(7)
///             + withdrawal_amts(7×8=56) + w_acc_addr(5) = 77
///   d_unique  = not_fake_tx(1) + accin_null(4) + accout_comm(4) + note_comm(4)
///             + eth_address(5) + amount(8) + asset_id(1) = 27
///   pair_pi_size = 8 + 77 + 27 = 112
///
/// Pair aggregator root PIs = 256 × 112 = 28672
///
/// Preimage = sr_root[4] + act_root[4] + mcr[4]
///   + 256 × w_unique + 256 × d_unique
/// Total fields = 12 + 256×77 + 256×27 = 26636 → u32 words = 53272
/// (unchanged from the old two-aggregator design).
#[test]
fn bridge_tx_pair_pi_and_preimage_word_count() {
	let w_unique = 1 + 4 + 4 + NOTE_BATCH + NOTE_BATCH * 8 + 5; // = 77
	let d_unique = 1 + 4 + 4 + 4 + 5 + 8 + 1; // = 27
	let pair_pi_size = 8 + w_unique + d_unique; // = 112
	let pair_agg_root_pis = HALF * pair_pi_size; // = 28672
	let total_preimage_fields = 4 + 4 + 4 + HALF * w_unique + HALF * d_unique;

	assert_eq!(w_unique, 77, "w_unique mismatch");
	assert_eq!(d_unique, 27, "d_unique mismatch");
	assert_eq!(pair_pi_size, 112, "pair_pi_size mismatch");
	assert_eq!(pair_agg_root_pis, 28672, "pair_agg root PI count mismatch");
	assert_eq!(
		total_preimage_fields, 26636,
		"total preimage fields unchanged"
	);
	assert_eq!(
		total_preimage_fields * 2,
		53272,
		"total preimage u32 words unchanged"
	);
}
