use plonky2::plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig};
use tessera_client::{
	NOTE_BATCH, PRIV_TX_BATCH_SIZE, SUBTREE_BATCHSIZE,
	plonky2_gadgets::priv_tx::targets::TxCircuitPublicTargets,
};
use tessera_utils::{
	ConfigNative, D, F,
	plonky2_gadgets::{
		keccak256::builder::BuilderKeccak256,
		u32::gadgets::add_u8_range_check_lookup_table,
	},
};

use super::targets::{PrivTxSuperCircuitData, PrivTxSuperTargets};
use crate::aggregator_service::utils::fields_to_u32_words;

pub(super) fn setup_super_builder(
	inner: &PrivTxSuperCircuitData,
) -> (CircuitBuilder<F, D>, PrivTxSuperTargets) {
	let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

	// 1. Allocate proof targets, constant-fold verifier data.
	let tx_proof = builder.add_virtual_proof_with_pis(&inner.tx_common);
	let tx_vd = builder.constant_verifier_data(&inner.tx_verifier);
	let sr_proof = builder.add_virtual_proof_with_pis(&inner.sr_common);
	let sr_vd = builder.constant_verifier_data(&inner.sr_verifier);

	// 2. Verify both proofs in-circuit.
	builder.verify_proof::<ConfigNative>(&tx_proof, &tx_vd, &inner.tx_common);
	builder.verify_proof::<ConfigNative>(&sr_proof, &sr_vd, &inner.sr_common);

	// 3. Derive pi_size from actual circuit data — no hardcoded constants.
	let pi_size = inner.tx_common.num_public_inputs / PRIV_TX_BATCH_SIZE;
	assert_eq!(
		pi_size * PRIV_TX_BATCH_SIZE,
		inner.tx_common.num_public_inputs,
		"TX PI count ({}) must be divisible by PRIV_TX_BATCH_SIZE ({})",
		inner.tx_common.num_public_inputs,
		PRIV_TX_BATCH_SIZE
	);
	assert_eq!(
		inner.sr_common.num_public_inputs,
		(1 + SUBTREE_BATCHSIZE) * 4,
		"SR PI count ({}) must equal (1+SUBTREE_BATCHSIZE)*4 = {}",
		inner.sr_common.num_public_inputs,
		(1 + SUBTREE_BATCHSIZE) * 4
	);

	// 4. Build named target wrappers — all PI access via named fields from here.
	let sr_pis = &sr_proof.public_inputs;
	let sr_leaf = |idx: usize| -> [plonky2::iop::target::Target; 4] {
		sr_pis[4 + idx * 4..4 + idx * 4 + 4].try_into().unwrap()
	};
	let slots: Vec<TxCircuitPublicTargets> = (0..PRIV_TX_BATCH_SIZE)
		.map(|s| {
			TxCircuitPublicTargets::from_pis(
				&tx_proof.public_inputs[s * pi_size..(s + 1) * pi_size],
			)
		})
		.collect();

	// 5. Cross-check: SR leaves == TX output_commitments (unconditional — SR is
	//    built from ALL proofs, including padding).
	//    SR leaf order per slot: [AC, NC0..NC6] (8 leaves, 1 + NOTE_BATCH).
	let leaves_per_slot = 1 + NOTE_BATCH;
	for (s, slot) in slots.iter().enumerate() {
		for (j, tx_comm) in slot.output_commitments().iter().enumerate() {
			let leaf = sr_leaf(s * leaves_per_slot + j);
			for k in 0..4 {
				builder.connect(tx_comm[k], leaf[k]);
			}
		}
	}

	// 6. Assert uniform common PIs across all slots.
	for slot in slots.iter().skip(1) {
		builder.connect_hashes(slot.root.0, slots[0].root.0);
		builder.connect_hashes(
			slot.mainpool_config_root.0,
			slots[0].mainpool_config_root.0,
		);
	}

	// 7. Build Keccak preimage (all via named fields — no raw indices).
	let lut = add_u8_range_check_lookup_table(&mut builder);
	let mut u32_words: Vec<plonky2::iop::target::Target> = Vec::new();

	// batch_poseidon_root (SR proof PI[0..4])
	let sr_root: [plonky2::iop::target::Target; 4] = sr_pis[..4].try_into().unwrap();
	u32_words.extend(fields_to_u32_words(&mut builder, &sr_root, lut));
	// common PIs once — from slot 0 (all slots asserted equal above)
	u32_words.extend(fields_to_u32_words(
		&mut builder,
		&slots[0].root.0.elements,
		lut,
	));
	u32_words.extend(fields_to_u32_words(
		&mut builder,
		&slots[0].mainpool_config_root.0.elements,
		lut,
	));
	// unique_pis per slot (via named accessor — no raw indices)
	for slot in &slots {
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

	let targets = PrivTxSuperTargets { tx_proof, sr_proof };
	(builder, targets)
}
