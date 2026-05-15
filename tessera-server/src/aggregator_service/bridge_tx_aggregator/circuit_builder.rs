use plonky2::{
	iop::target::Target,
	plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
};
use tessera_client::{
	plonky2_gadgets::{
		deposit_tx::targets::DepositTxPublicTargets, withdraw_tx::targets::WithdrawTxPublicTargets,
	},
	BRIDGE_TX_BATCH_SIZE, SUBTREE_BATCHSIZE,
};
use tessera_utils::{
	plonky2_gadgets::{
		keccak256::builder::BuilderKeccak256, u32::gadgets::add_u8_range_check_lookup_table,
	},
	ConfigNative, D, F,
};

use super::targets::{BridgeTxPairLeafData, BridgeTxSuperCircuitData, BridgeTxSuperTargets};
use crate::aggregator_service::utils::fields_to_u32_words;

const HALF: usize = BRIDGE_TX_BATCH_SIZE / 2;

/// Offset of `accout_comm` within the unique-PI slice of either W or D:
/// unique = [not_fake_tx(1) | accin_null(4) | accout_comm(4) | …]
///                                                ^^^^ starts here
const ACCOUT_COMM_UNIQUE_OFF: usize = 5; // 1 + 4

// ---------------------------------------------------------------------------
// Pair-leaf circuit builder
// ---------------------------------------------------------------------------

/// Build a circuit that verifies one (Withdraw, Deposit) pair.
///
/// PI layout per pair (total = 8 + w_unique + d_unique):
/// ```text
/// [0..4]          act_root    (from W; connected to D.comm_root)
/// [4..8]          mainpool    (from W; connected to D.mainpool_config_root)
/// [8..8+wu]       w_unique    (not_fake_tx | accin_null | accout_comm | …)
/// [8+wu..8+wu+du] d_unique    (not_fake_tx | accin_null | accout_comm | …)
/// ```
///
/// Returns `(builder, w_proof_target, d_proof_target)`.  The caller finishes
/// the circuit by calling `builder.build::<ConfigNative>()`.
pub(super) fn build_pair_leaf(
	inner: &BridgeTxPairLeafData,
) -> (
	CircuitBuilder<F, D>,
	plonky2::plonk::proof::ProofWithPublicInputsTarget<D>,
	plonky2::plonk::proof::ProofWithPublicInputsTarget<D>,
) {
	let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

	// 1. Allocate proof targets; fold verifier data into circuit constants.
	let w_proof = builder.add_virtual_proof_with_pis(&inner.withdraw_common);
	let w_vd = builder.constant_verifier_data(&inner.withdraw_verifier);
	let d_proof = builder.add_virtual_proof_with_pis(&inner.deposit_common);
	let d_vd = builder.constant_verifier_data(&inner.deposit_verifier);

	// 2. Verify both proofs in-circuit.
	builder.verify_proof::<ConfigNative>(&w_proof, &w_vd, &inner.withdraw_common);
	builder.verify_proof::<ConfigNative>(&d_proof, &d_vd, &inner.deposit_common);

	// 3. Build named wrappers for type-safe PI access.
	let w = WithdrawTxPublicTargets::from_pis(&w_proof.public_inputs);
	let d = DepositTxPublicTargets::from_pis(&d_proof.public_inputs);

	// 4. Connect common PIs (act_root and mainpool must be equal across the pair).
	builder.connect_hashes(w.root.0, d.state_root.0);
	builder.connect_hashes(w.mainpool_config_root.0, d.mainpool_config_root.0);

	// 5. Register combined pair public inputs.
	for &t in &w.root.0.elements {
		builder.register_public_input(t);
	}
	for &t in &w.mainpool_config_root.0.elements {
		builder.register_public_input(t);
	}
	for t in w.unique_pi_targets() {
		builder.register_public_input(t);
	}
	for t in d.unique_pi_targets() {
		builder.register_public_input(t);
	}

	(builder, w_proof, d_proof)
}

// ---------------------------------------------------------------------------
// Super circuit builder
// ---------------------------------------------------------------------------

pub(super) fn setup_super_builder(
	inner: &BridgeTxSuperCircuitData,
) -> (CircuitBuilder<F, D>, BridgeTxSuperTargets) {
	let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

	// 1. Allocate proof targets; fold verifier data as constants.
	let pair_proof = builder.add_virtual_proof_with_pis(&inner.pair_common);
	let pair_vd = builder.constant_verifier_data(&inner.pair_verifier);
	let sr_proof = builder.add_virtual_proof_with_pis(&inner.poseidon_root_common);
	let sr_vd = builder.constant_verifier_data(&inner.poseidon_root_verifier);

	// 2. Verify both inner proofs.
	builder.verify_proof::<ConfigNative>(&pair_proof, &pair_vd, &inner.pair_common);
	builder.verify_proof::<ConfigNative>(&sr_proof, &sr_vd, &inner.poseidon_root_common);

	// 3. Validate PI counts.
	let pair_pi_size = 8 + inner.w_unique_size + inner.d_unique_size;
	assert_eq!(
		pair_pi_size * HALF,
		inner.pair_common.num_public_inputs,
		"pair PI count ({}) must equal HALF ({HALF}) × pair_pi_size ({pair_pi_size})",
		inner.pair_common.num_public_inputs,
	);
	assert_eq!(
		inner.poseidon_root_common.num_public_inputs,
		(1 + SUBTREE_BATCHSIZE) * 4,
		"SR PI count ({}) must equal (1+SUBTREE_BATCHSIZE)*4 = {}",
		inner.poseidon_root_common.num_public_inputs,
		(1 + SUBTREE_BATCHSIZE) * 4,
	);

	let pair_pis = &pair_proof.public_inputs;
	let sr_pis = &sr_proof.public_inputs;
	let sr_leaf =
		|idx: usize| -> [Target; 4] { sr_pis[4 + idx * 4..4 + idx * 4 + 4].try_into().unwrap() };

	// 4. Cross-check SR leaves against TX output commitments (unconditional — SR is built from all
	//    proofs including padding). SR[s]        = pair[s].w.accout_comm SR[HALF + s] =
	//    pair[s].d.accout_comm
	for s in 0..HALF {
		let w_accout_start = s * pair_pi_size + 8 + ACCOUT_COMM_UNIQUE_OFF;
		let d_accout_start = s * pair_pi_size + 8 + inner.w_unique_size + ACCOUT_COMM_UNIQUE_OFF;

		let w_leaf = sr_leaf(s);
		let d_leaf = sr_leaf(HALF + s);

		for k in 0..4 {
			builder.connect(pair_pis[w_accout_start + k], w_leaf[k]);
			builder.connect(pair_pis[d_accout_start + k], d_leaf[k]);
		}
	}

	// 5. Assert uniform common PIs (act_root + mainpool) across all pair slots. pair[0] common =
	//    pair_pis[0..8]; pair[s] common = pair_pis[s*pair_pi_size..+8].
	for s in 1..HALF {
		let base = s * pair_pi_size;
		for k in 0..8 {
			builder.connect(pair_pis[base + k], pair_pis[k]);
		}
	}

	// 6. Build Keccak preimage.
	//
	//    Preimage (matches BatchHelper::pi_commitment / TesseraContract preimage):
	//      sr_root[4 GL] | act_root[4 GL] | mainpool[4 GL]
	//      | w_unique[slot 0] | … | w_unique[slot 255]
	//      | d_unique[slot 0] | … | d_unique[slot 255]
	let lut = add_u8_range_check_lookup_table(&mut builder);
	let mut u32_words: Vec<Target> = Vec::new();

	// batch_poseidon_root = SR proof PI[0..4]
	let sr_root: [Target; 4] = sr_pis[..4].try_into().unwrap();
	u32_words.extend(fields_to_u32_words(&mut builder, &sr_root, lut));

	// act_root and mainpool from pair[0] (equality to all other pairs asserted above)
	u32_words.extend(fields_to_u32_words(&mut builder, &pair_pis[0..4], lut));
	u32_words.extend(fields_to_u32_words(&mut builder, &pair_pis[4..8], lut));

	// W unique PIs — all HALF slots in slot order
	for s in 0..HALF {
		let w_start = s * pair_pi_size + 8;
		u32_words.extend(fields_to_u32_words(
			&mut builder,
			&pair_pis[w_start..w_start + inner.w_unique_size],
			lut,
		));
	}
	// D unique PIs — all HALF slots in slot order
	for s in 0..HALF {
		let d_start = s * pair_pi_size + 8 + inner.w_unique_size;
		u32_words.extend(fields_to_u32_words(
			&mut builder,
			&pair_pis[d_start..d_start + inner.d_unique_size],
			lut,
		));
	}

	// 7. Keccak-256 → 8 u32 public inputs.
	let keccak_out = builder.keccak256::<ConfigNative>(&u32_words);
	for &w in &keccak_out {
		builder.register_public_input(w);
	}

	let targets = BridgeTxSuperTargets {
		pair_proof,
		poseidon_root_proof: sr_proof,
	};
	(builder, targets)
}
