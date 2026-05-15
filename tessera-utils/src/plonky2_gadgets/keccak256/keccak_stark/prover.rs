use anyhow::Result;
use plonky2::{
	field::{extension::Extendable, polynomial::PolynomialValues, types::Field},
	fri::oracle::PolynomialBatch,
	hash::hash_types::RichField,
	iop::challenger::Challenger,
	plonk::config::GenericConfig,
	util::timing::TimingTree,
};
use starky::{
	config::StarkConfig,
	cross_table_lookup::{CrossTableLookup, TableWithColumns, get_ctl_data},
	proof::StarkProofWithMetadata,
	prover::prove_with_commitment,
	stark::Stark,
};

use super::keccak_stark::{
	ctl_data_inputs, ctl_data_outputs, ctl_filter_inputs, ctl_filter_outputs,
};

pub(crate) fn keccak_ctls<F: Field>() -> Vec<CrossTableLookup<F>> {
	let mut cross_table_lookups = Vec::new();
	{
		let looked_table_input = TableWithColumns::new(0, ctl_data_inputs(), ctl_filter_inputs());
		cross_table_lookups.push(CrossTableLookup::new(vec![], looked_table_input));
		let looked_table_ouptut =
			TableWithColumns::new(0, ctl_data_outputs(), ctl_filter_outputs());
		cross_table_lookups.push(CrossTableLookup::new(vec![], looked_table_ouptut));
	}
	cross_table_lookups
}

pub(crate) fn prove<F, C, S, const D: usize>(
	stark: &S,
	config: &StarkConfig,
	trace: &[PolynomialValues<F>],
	cross_table_lookups: &[CrossTableLookup<F>],
	public_inputs: &[F],
	timing: &mut TimingTree,
) -> Result<StarkProofWithMetadata<F, C, D>>
where
	S: Stark<F, D>,
	F: RichField + Extendable<D>,
	C: GenericConfig<D, F = F>,
{
	let trace_commitment = PolynomialBatch::<F, C, D>::from_values(
		trace.to_vec(),
		config.fri_config.rate_bits,
		false,
		config.fri_config.cap_height,
		timing,
		None,
	);

	let mut challenger = Challenger::<F, C::Hasher>::new();
	challenger.observe_elements(public_inputs);
	config.observe(&mut challenger);
	challenger.observe_cap(&trace_commitment.merkle_tree.cap);

	let mut ctl_challenger = challenger.clone();
	let (ctl_challenges, ctl_data) = get_ctl_data::<F, C, D, 1>(
		config,
		&[trace.to_vec()],
		cross_table_lookups,
		&mut ctl_challenger,
		stark.constraint_degree(),
	);

	// Keep metadata for recursive wrapping, but do not compact the live challenger.
	// `get_challenges`-based verification assumes the same transcript progression used by
	// `prove_with_commitment`, i.e. without an extra pre-proving compact step.
	let init_challenger_state = challenger.clone().compact();
	let proof = prove_with_commitment(
		stark,
		config,
		trace,
		&trace_commitment,
		Some(&ctl_data[0]),
		Some(&ctl_challenges),
		&mut challenger,
		public_inputs,
		None,
		None,
		timing,
	)?;
	let proof_with_metadata = StarkProofWithMetadata {
		proof: proof.proof,
		init_challenger_state,
	};

	Ok(proof_with_metadata)
}
