use plonky2::{
	iop::target::Target,
	plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
};
use tessera_client::{
	BRIDGE_TX_BATCH_SIZE, SUBTREE_BATCHSIZE,
	plonky2_gadgets::{
		deposit_tx::targets::DepositTxPublicTargets,
		withdraw_tx::targets::WithdrawTxPublicTargets,
	},
};
use tessera_utils::{
	ConfigNative, D, F,
	plonky2_gadgets::{
		keccak256::builder::BuilderKeccak256,
		u32::gadgets::add_u8_range_check_lookup_table,
	},
};

use super::targets::{BridgeTxSuperCircuitData, BridgeTxSuperTargets};
use crate::aggregator_service::utils::fields_to_u32_words;

const HALF: usize = BRIDGE_TX_BATCH_SIZE / 2;

pub(super) fn setup_super_builder(
	inner: &BridgeTxSuperCircuitData,
) -> (CircuitBuilder<F, D>, BridgeTxSuperTargets) {
	let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

	// 1. Allocate proof targets, constant-fold verifier data.
	let w_proof = builder.add_virtual_proof_with_pis(&inner.withdraw_common);
	let w_vd = builder.constant_verifier_data(&inner.withdraw_verifier);
	let d_proof = builder.add_virtual_proof_with_pis(&inner.deposit_common);
	let d_vd = builder.constant_verifier_data(&inner.deposit_verifier);
	let sr_proof = builder.add_virtual_proof_with_pis(&inner.poseidon_root_common);
	let sr_vd = builder.constant_verifier_data(&inner.poseidon_root_verifier);

	// 2. Verify all three proofs in-circuit.
	builder.verify_proof::<ConfigNative>(&w_proof, &w_vd, &inner.withdraw_common);
	builder.verify_proof::<ConfigNative>(&d_proof, &d_vd, &inner.deposit_common);
	builder.verify_proof::<ConfigNative>(&sr_proof, &sr_vd, &inner.poseidon_root_common);

	// 3. Derive pi_sizes — no hardcoded constants.
	let w_pi_size = inner.withdraw_common.num_public_inputs / HALF;
	assert_eq!(
		w_pi_size * HALF,
		inner.withdraw_common.num_public_inputs,
		"W PI count ({}) must be divisible by HALF ({})",
		inner.withdraw_common.num_public_inputs,
		HALF
	);
	let d_pi_size = inner.deposit_common.num_public_inputs / HALF;
	assert_eq!(
		d_pi_size * HALF,
		inner.deposit_common.num_public_inputs,
		"D PI count ({}) must be divisible by HALF ({})",
		inner.deposit_common.num_public_inputs,
		HALF
	);
	assert_eq!(
		inner.poseidon_root_common.num_public_inputs,
		(1 + SUBTREE_BATCHSIZE) * 4,
		"SR PI count ({}) must equal (1+SUBTREE_BATCHSIZE)*4 = {}",
		inner.poseidon_root_common.num_public_inputs,
		(1 + SUBTREE_BATCHSIZE) * 4
	);

	// 4. Build named target wrappers — all PI access via named fields from here.
	let sr_pis = &sr_proof.public_inputs;
	let sr_leaf = |idx: usize| -> [Target; 4] {
		sr_pis[4 + idx * 4..4 + idx * 4 + 4].try_into().unwrap()
	};
	let w_slots: Vec<WithdrawTxPublicTargets> = (0..HALF)
		.map(|s| {
			WithdrawTxPublicTargets::from_pis(
				&w_proof.public_inputs[s * w_pi_size..(s + 1) * w_pi_size],
			)
		})
		.collect();
	let d_slots: Vec<DepositTxPublicTargets> = (0..HALF)
		.map(|s| {
			DepositTxPublicTargets::from_pis(
				&d_proof.public_inputs[s * d_pi_size..(s + 1) * d_pi_size],
			)
		})
		.collect();

	// 5. Cross-check: SR leaves == TX output_commitments (unconditional).
	//    Withdraw slots → SR[0..HALF), deposit slots → SR[HALF..2*HALF).
	for (s, slot) in w_slots.iter().enumerate() {
		let leaf = sr_leaf(s);
		let oc = slot.output_commitment();
		for k in 0..4 {
			builder.connect(oc[k], leaf[k]);
		}
	}
	for (s, slot) in d_slots.iter().enumerate() {
		let leaf = sr_leaf(HALF + s);
		let oc = slot.output_commitment();
		for k in 0..4 {
			builder.connect(oc[k], leaf[k]);
		}
	}

	// 6. Assert uniform common PIs across all slots.
	//    Reference: w_slots[0].
	for slot in w_slots.iter().skip(1) {
		builder.connect_hashes(slot.root.0, w_slots[0].root.0);
		builder.connect_hashes(
			slot.mainpool_config_root.0,
			w_slots[0].mainpool_config_root.0,
		);
	}
	for slot in &d_slots {
		// DepositTxPublicTargets uses `comm_root` for the ACT root.
		builder.connect_hashes(slot.comm_root.0, w_slots[0].root.0);
		builder.connect_hashes(
			slot.mainpool_config_root.0,
			w_slots[0].mainpool_config_root.0,
		);
	}

	// 7. Build Keccak preimage (all via named fields).
	//    Preimage: sr_root | common_pis_once | unique_pis_per_slot (withdraw first, deposit second).
	let lut = add_u8_range_check_lookup_table(&mut builder);
	let mut u32_words: Vec<Target> = Vec::new();

	let sr_root: [Target; 4] = sr_pis[..4].try_into().unwrap();
	u32_words.extend(fields_to_u32_words(&mut builder, &sr_root, lut));
	u32_words.extend(fields_to_u32_words(
		&mut builder,
		&w_slots[0].root.0.elements,
		lut,
	));
	u32_words.extend(fields_to_u32_words(
		&mut builder,
		&w_slots[0].mainpool_config_root.0.elements,
		lut,
	));
	for slot in &w_slots {
		u32_words.extend(fields_to_u32_words(
			&mut builder,
			&slot.unique_pi_targets(),
			lut,
		));
	}
	for slot in &d_slots {
		u32_words.extend(fields_to_u32_words(
			&mut builder,
			&slot.unique_pi_targets(),
			lut,
		));
	}

	// 8. Keccak-256 → 8 u32 public inputs.
	let keccak_out = builder.keccak256::<ConfigNative>(&u32_words);
	for &w in &keccak_out {
		builder.register_public_input(w);
	}

	let targets = BridgeTxSuperTargets {
		withdraw_proof: w_proof,
		deposit_proof: d_proof,
		poseidon_root_proof: sr_proof,
	};
	(builder, targets)
}
