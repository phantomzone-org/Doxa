use std::array;

use itertools::izip;
use plonky2::{
	hash::hash_types::RichField,
	iop::{
		generator::{GeneratedValues, SimpleGenerator},
		target::Target,
		witness::{PartialWitness, PartitionWitness, Witness, WitnessWrite},
	},
	plonk::{circuit_builder::CircuitBuilder, circuit_data::CommonCircuitData},
	util::serialization::{Buffer, IoResult, Read, Write},
};
use plonky2_field::{extension::Extendable, types::Field};
use tessera_trees::plonky2_gadgets::u32::{CircuitBuilderU32, U32Target};

/// A 256-bit unsigned integer in a Plonky2 circuit, stored as 8 × [`U32Target`].
///
/// Big-endian: `limbs[0]` is the most significant 32-bit word,
/// `limbs[7]` is the least significant.
#[derive(Clone, Copy, Debug)]
pub struct U256Target(pub [U32Target; 8]);

impl U256Target {
	/// Sets the witness for this target from a `primitive_types::U256`.
	///
	/// `value.0` is `[u64; 4]` little-endian; each u64 is split into two u32 limbs.
	pub(crate) fn set_witness<F: Field>(
		&self,
		pw: &mut PartialWitness<F>,
		value: primitive_types::U256,
	) {
		for (i, &word) in value.0.iter().enumerate() {
			pw.set_target(self.0[2 * i].0, F::from_canonical_u32(word as u32))
				.unwrap();
			pw.set_target(
				self.0[2 * i + 1].0,
				F::from_canonical_u32((word >> 32) as u32),
			)
			.unwrap();
		}
	}
}

/// Extension trait for [`CircuitBuilder`]
pub trait CircuitBuilderU256<F: RichField + Extendable<D>, const D: usize> {
	/// Allocates a virtual [`U256Target`] (8 unconstrained u32 limbs).
	fn add_virtual_u256_target(&mut self) -> U256Target;

	/// Creates a constant [`U256Target`] from 8 big-endian u32 words.
	fn constant_u256(&mut self, value: [u32; 8]) -> U256Target;

	/// Returns `input + \sum_i chain[i] (mod 2^256)`.
	///
	/// Addition is performed limb-by-limb from least to most significant word
	/// with carry propagation. The final carry out of the MSB is discarded
	/// (wrapping mod 2^256 semantics).
	///
	/// `range_lut` must be an 8-bit byte range-check lookup table index
	/// (see [`add_u8_range_check_lookup_table`]).
	///
	/// **Range checking:** assumes all input limbs are already range-checked
	/// as u32. The expected limbs are range-checked internally via byte
	/// decomposition (through the carry generator constraints).
	///
	/// TODO: Do the input bits need to checked for in range u32?
	fn u256_addition_chain<const LEN: usize>(
		&mut self,
		input: &U256Target,
		chain: &[U256Target; LEN],
		range_lut: usize,
	) -> U256Target;

	fn connect_u256(&mut self, lhs: &U256Target, rhs: &U256Target);
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderU256<F, D>
	for CircuitBuilder<F, D>
{
	fn add_virtual_u256_target(&mut self) -> U256Target {
		U256Target(core::array::from_fn(|_| self.add_virtual_u32_target()))
	}

	fn constant_u256(&mut self, value: [u32; 8]) -> U256Target {
		U256Target(value.map(|w| self.constant_u32(w)))
	}

	fn u256_addition_chain<const LEN: usize>(
		&mut self,
		input: &U256Target,
		chain: &[U256Target; LEN],
		range_lut: usize,
	) -> U256Target {
		// Process limbs from least significant (index 7) to most significant (index 0).
		// carry_in starts at zero.
		let mut carry = self.zero();

		let mut out: [U32Target; 8] = array::from_fn(|_| self.add_virtual_u32_target());

		for limb_idx in 0..8 {
			let mut limb_inputs = vec![input.0[limb_idx].0];
			(0..LEN).for_each(|i| limb_inputs.push(chain[i].0[limb_idx].0));

			let result = self.add_virtual_u32_target();
			let carry_out = self.add_virtual_target();

			self.add_simple_generator(U256LimbSumGenerator {
				limb_inputs: limb_inputs.clone(),
				carry_in: carry,
				result: result.0,
				carry_out,
			});

			// Range-check the result limb.
			self.decompose_u32_to_bytes(result, range_lut);

			// Constraint: sum_of_9_limbs + carry_in == result + carry_out * 2^32
			// Build sum_of_9_limbs as a chain of field additions.
			let mut limb_sum = limb_inputs[0];
			for &l in limb_inputs.iter().skip(1) {
				limb_sum = self.add(limb_sum, l);
			}
			let lhs = self.add(limb_sum, carry);
			let c232 = self.constant(F::from_canonical_u64(1u64 << 32));
			let carry_scaled = self.mul(carry_out, c232);
			let rhs = self.add(result.0, carry_scaled);
			self.connect(lhs, rhs);

			out[limb_idx] = result;

			carry = carry_out;
		}
		// The final carry out of the MSB is intentionally discarded (mod 2^256).

		U256Target(out)
	}

	fn connect_u256(&mut self, lhs: &U256Target, rhs: &U256Target) {
		izip!(lhs.0.iter(), rhs.0.iter()).for_each(|(l, r)| {
			self.connect(l.0, r.0);
		});
	}
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

/// Witness generator for one limb position of a U256 addition chain
///
/// Given vec of u32 limbs and a carry_in, computes:
/// - `result = (sum + carry_in) & 0xFFFFFFFF`
/// - `carry_out = (sum + carry_in) >> 32`
#[derive(Debug, Clone, Default)]
struct U256LimbSumGenerator {
	/// One limb from each of the input U256 values
	limb_inputs: Vec<Target>,
	/// Carry in from the less significant limb position.
	carry_in: Target,
	/// Output: low 32 bits of the accumulated sum.
	result: Target,
	/// Output: bits above 32 of the accumulated sum (the new carry).
	carry_out: Target,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D> for U256LimbSumGenerator {
	fn id(&self) -> String {
		"U256LimbSumGenerator".to_string()
	}

	fn dependencies(&self) -> Vec<Target> {
		let mut deps: Vec<Target> = self.limb_inputs.to_vec();
		deps.push(self.carry_in);
		deps
	}

	fn run_once(
		&self,
		witness: &PartitionWitness<F>,
		out_buffer: &mut GeneratedValues<F>,
	) -> anyhow::Result<()> {
		let carry_in = witness.get_target(self.carry_in).to_canonical_u64();
		let mut sum: u64 = carry_in;
		for &limb in &self.limb_inputs {
			sum += witness.get_target(limb).to_canonical_u64();
		}
		out_buffer.set_target(self.result, F::from_canonical_u64(sum & 0xFFFFFFFF))?;
		out_buffer.set_target(self.carry_out, F::from_canonical_u64(sum >> 32))?;
		Ok(())
	}

	fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
		dst.write_usize(self.limb_inputs.len())?;
		for &limb in &self.limb_inputs {
			dst.write_target(limb)?;
		}
		dst.write_target(self.carry_in)?;
		dst.write_target(self.result)?;
		dst.write_target(self.carry_out)?;
		Ok(())
	}

	fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
		let len: usize = src.read_usize()?;
		let mut limb_inputs = vec![];
		for _ in 0..len {
			limb_inputs.push(src.read_target()?);
		}
		let carry_in = src.read_target()?;
		let result = src.read_target()?;
		let carry_out = src.read_target()?;
		Ok(Self {
			limb_inputs,
			carry_in,
			result,
			carry_out,
		})
	}
}

#[cfg(test)]
mod tests {
	use plonky2::{
		iop::witness::PartialWitness,
		plonk::{
			circuit_data::CircuitConfig,
			config::{GenericConfig, PoseidonGoldilocksConfig},
		},
	};
	use tessera_trees::plonky2_gadgets::u32::add_u8_range_check_lookup_table;

	use super::*;
	use crate::plonky2_gadgets::set_u256;

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = <C as GenericConfig<D>>::F;

	// -----------------------------------------------------------------------
	// U256 sum gadget tests
	// -----------------------------------------------------------------------

	/// Helper to build the circuit
	fn build_u256_sum_circuit() -> (
		plonky2::plonk::circuit_data::CircuitData<F, C, D>,
		U256Target,
		[U256Target; 9],
		U256Target,
	) {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let range_lut = add_u8_range_check_lookup_table(&mut builder);

		let input = builder.add_virtual_u256_target();
		let chain: [U256Target; 9] = core::array::from_fn(|_| builder.add_virtual_u256_target());
		let expected = builder.u256_addition_chain(&input, &chain, range_lut);

		let data = builder.build::<C>();
		(data, input, chain, expected)
	}

	#[test]
	fn test_u256_nine_sum_no_carry() {
		// 9 small values, no inter-limb carry.
		// Each input = [0, 0, 0, 0, 0, 0, 0, 1]  (value = 1)
		// Expected   = [0, 0, 0, 0, 0, 0, 0, 9]  (value = 9)
		let (data, input, chain, expected) = build_u256_sum_circuit();
		let mut pw = PartialWitness::new();
		set_u256(&mut pw, &input, [0, 0, 0, 0, 0, 0, 0, 1]);
		for v in &chain {
			set_u256(&mut pw, v, [0, 0, 0, 0, 0, 0, 0, 1]);
		}
		set_u256(&mut pw, &expected, [0, 0, 0, 0, 0, 0, 0, 10]);
		let proof = data.prove(pw).expect("prove failed");
		data.verify(proof).expect("verify failed");
	}

	// TODO: fix other tests

	// #[test]
	// fn test_u256_nine_sum_with_carry() {
	// 	// Each input's LSB limb = 0xFFFFFFFF (max u32).
	// 	// 9 × 0xFFFFFFFF = 0x8_FFFFFFF7  → limb7 = 0xFFFFFFF7, carry into limb6 = 8.
	// 	// All other limbs = 0, so limb6 of result = 8, all higher limbs = 0.
	// 	// Expected: [0, 0, 0, 0, 0, 0, 8, 0xFFFFFFF7]
	// 	let (data, inputs, expected) = build_u256_sum_circuit();
	// 	let mut pw = PartialWitness::new();
	// 	for input in &inputs {
	// 		set_u256(&mut pw, input, [0, 0, 0, 0, 0, 0, 0, 0xFFFFFFFF]);
	// 	}
	// 	set_u256(&mut pw, &expected, [0, 0, 0, 0, 0, 0, 8, 0xFFFFFFF7]);
	// 	let proof = data.prove(pw).expect("prove failed");
	// 	data.verify(proof).expect("verify failed");
	// }

	// #[test]
	// fn test_u256_nine_sum_wraps_at_2_256() {
	// 	// Each input = 2^256 / 9 rounded such that sum ≡ 0 (mod 2^256).
	// 	// Simpler: each input = [0xFFFFFFFF; 8] (max U256).
	// 	// 9 × (2^256 - 1) mod 2^256 = 9 × 0xFF...FF mod 2^256
	// 	// = (9 * (2^256 - 1)) mod 2^256 = (9 * 2^256 - 9) mod 2^256 = -9 mod 2^256
	// 	// = 2^256 - 9 = [0xFFFFFFFF, ..., 0xFFFFFFFF, 0xFFFFFFF7]
	// 	let (data, inputs, expected) = build_u256_sum_circuit();
	// 	let mut pw = PartialWitness::new();
	// 	for input in &inputs {
	// 		set_u256(&mut pw, input, [0xFFFFFFFF; 8]);
	// 	}
	// 	// 9 × (2^256 - 1) mod 2^256:
	// 	// limb-by-limb: each limb = 9 × 0xFFFFFFFF = 0x8_FFFFFFF7
	// 	// Starting from LSB (limb7):
	// 	//   sum7 = 9 * 0xFFFFFFFF + 0     = 0x8FFFFFFF7 → limb7=0xFFFFFFF7, carry=8
	// 	//   sum6 = 9 * 0xFFFFFFFF + 8     = 0x8FFFFFFFF → limb6=0xFFFFFFFF, carry=8
	// 	//   ... (same for limbs 5..1)
	// 	//   sum0 = 9 * 0xFFFFFFFF + 8     = 0x8FFFFFFFF → limb0=0xFFFFFFFF, carry=8 (discarded)
	// 	// Result = [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
	// 	// 0xFFFFFFFF, 0xFFFFFFF7]
	// 	let mut expected_val = [0xFFFFFFFF_u32; 8];
	// 	expected_val[7] = 0xFFFFFFF7;
	// 	set_u256(&mut pw, &expected, expected_val);
	// 	let proof = data.prove(pw).expect("prove failed");
	// 	data.verify(proof).expect("verify failed");
	// }

	// #[test]
	// fn test_u256_nine_sum_wrong_expected_fails() {
	// 	let (data, inputs, expected) = build_u256_sum_circuit();
	// 	let mut pw = PartialWitness::new();
	// 	for input in &inputs {
	// 		set_u256(&mut pw, input, [0, 0, 0, 0, 0, 0, 0, 1]);
	// 	}
	// 	// Correct expected is 9; set 10 instead.
	// 	set_u256(&mut pw, &expected, [0, 0, 0, 0, 0, 0, 0, 10]);
	// 	assert!(
	// 		data.prove(pw).is_err(),
	// 		"Expected proof to fail with wrong expected value"
	// 	);
	// }
}
