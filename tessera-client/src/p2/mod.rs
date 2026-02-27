pub(crate) mod merkle;
pub(crate) mod signature;
pub(crate) mod u256;

mod tests {
	use plonky2::{hash::hash_types::RichField, plonk::circuit_data::CircuitConfig};
	use plonky2_field::extension::Extendable;

	pub(crate) fn avg(times: &[std::time::Duration]) -> std::time::Duration {
		times.iter().sum::<std::time::Duration>() / times.len() as u32
	}

	pub(crate) fn print_circuit_config(config: &CircuitConfig, label: &str) {
		println!("=== {label} ===");
		println!("num_wires:          {}", config.num_wires);
		println!("num_routed_wires:   {}", config.num_routed_wires);
		println!("num_constants:      {}", config.num_constants);
		println!("security_bits:      {}", config.security_bits);
		println!("num_challenges:     {}", config.num_challenges);
		println!("rate_bits (FRI):    {}", config.fri_config.rate_bits);
		println!("cap_height (FRI):   {}", config.fri_config.cap_height);
		println!(
			"PoW bits (FRI):     {}",
			config.fri_config.proof_of_work_bits
		);
		println!("query rounds (FRI): {}", config.fri_config.num_query_rounds);
	}

	pub(crate) fn print_common_data<F: RichField + Extendable<D>, const D: usize>(
		common: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
		label: &str,
	) {
		println!("=== {label} ===");
		println!("degree_bits:             {}", common.degree_bits());
		println!("degree (AIR table size): {}", common.degree());
		println!("num gate types:          {}", common.gates.len());
		println!("quotient_degree_factor:  {}", common.quotient_degree_factor);
		println!("num_gate_constraints:    {}", common.num_gate_constraints);
		let total_constraints: usize = common.gates.iter().map(|g| g.0.num_constraints()).sum();
		println!("total_constraints:       {}", total_constraints);
		println!("num_public_inputs:       {}", common.num_public_inputs);
		println!("num_partial_products:    {}", common.num_partial_products);
		println!("num_lookup_polys:        {}", common.num_lookup_polys);
		// for (i, g) in common.gates.iter().enumerate() {
		//     println!("  gate[{}]: {}", i, g.0.id());
		// }
	}
}
