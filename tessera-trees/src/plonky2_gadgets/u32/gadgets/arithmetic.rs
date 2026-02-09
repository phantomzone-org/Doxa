use plonky2::{
	field::extension::Extendable,
	hash::hash_types::RichField,
	iop::{
		generator::{GeneratedValues, SimpleGenerator},
		target::Target,
		witness::{PartitionWitness, Witness, WitnessWrite},
	},
	plonk::{circuit_builder::CircuitBuilder, circuit_data::CommonCircuitData},
	util::serialization::{Buffer, IoResult, Read, Write},
};

use super::{CircuitBuilderU32, U32Target};

/// Extension trait: wrapping addition and CRT-based assertion on [`U32Target`].
pub trait CircuitBuilderU32Arithmetic<F: RichField + Extendable<D>, const D: usize> {
	/// Computes `(a + b) mod 2^32` (wrapping addition).
	///
	/// Uses native field addition (exact since `a + b < 2^33 << p`) then
	/// byte-decomposes the low 32 bits for the range check.  The overflow
	/// bit is constrained to be boolean and discarded.
	///
	/// **Range checking:** assumes both inputs are already range-checked
	/// as u32 (the overflow-bit constraint relies on `a + b < 2^33`).
	/// The output is explicitly range-checked via byte decomposition.
	fn wrapping_add_u32(&mut self, a: U32Target, b: U32Target, range_lut: usize) -> U32Target;

	/// Asserts `result = lhs + rhs mod 2^32` using the CRT trick on 16-bit limbs.
	///
	/// All three arguments are `[lo, hi]` limb pairs (see
	/// [`decompose_u32_to_u16_limbs`]).  Uses only 2 degree-2 polynomial
	/// constraints (no overflow variable, no byte decomposition), making
	/// it more efficient in pipeline contexts like SHA256 where limbs
	/// are already maintained.
	///
	/// **Range checking:** assumes all limb pairs are already
	/// range-checked (e.g. via [`CircuitBuilderU32::decompose_u32_to_u16_limbs`]).
	/// This method adds no range checks of its own — it only asserts the
	/// modular-addition relationship.
	///
	/// # Constraints
	///
	/// Let `acc   = result_full - lhs_full - rhs_full` (full 32-bit diff)
	/// and `acc16 = result_lo   - lhs_lo   - rhs_lo`   (low-limb diff).
	///
	/// - `acc   * (acc   + 2^32) == 0`  ⟹  `acc ∈ {0, -2^32}`
	/// - `acc16 * (acc16 + 2^16) == 0`  ⟹  `acc16 ∈ {0, -2^16}`
	fn assert_add_u32_limbs(&mut self, result: [Target; 2], lhs: [Target; 2], rhs: [Target; 2]);
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderU32Arithmetic<F, D>
	for CircuitBuilder<F, D>
{
	fn wrapping_add_u32(&mut self, a: U32Target, b: U32Target, range_lut: usize) -> U32Target {
		let result = U32Target(self.add_virtual_target());
		let overflow = self.add_virtual_target();

		// Generator: result = (a + b) % 2^32, overflow = (a + b) >> 32
		self.add_simple_generator(U32WrappingAddGenerator {
			a: a.0,
			b: b.0,
			result: result.0,
			overflow,
		});

		// Range check result via byte decomposition
		self.decompose_u32_to_bytes(result, range_lut);

		// Constrain overflow ∈ {0, 1}: overflow² - overflow == 0
		let bool_check = self.mul_sub(overflow, overflow, overflow);
		self.assert_zero(bool_check);

		// Constrain: a + b == result + overflow * 2^32
		let c232 = self.constant(F::from_canonical_u64(1u64 << 32));
		let overflow_scaled = self.mul(overflow, c232);
		let lhs = self.add(a.0, b.0);
		let rhs = self.add(result.0, overflow_scaled);
		self.connect(lhs, rhs);

		result
	}

	fn assert_add_u32_limbs(&mut self, result: [Target; 2], lhs: [Target; 2], rhs: [Target; 2]) {
		// acc = result_full - lhs_full - rhs_full
		//     = (result[0] + result[1]*2^16) - (lhs[0] + lhs[1]*2^16) - (rhs[0] + rhs[1]*2^16)
		let c216 = F::from_canonical_u64(1u64 << 16);

		let result_full = self.mul_const_add(c216, result[1], result[0]);
		let lhs_full = self.mul_const_add(c216, lhs[1], lhs[0]);
		let rhs_full = self.mul_const_add(c216, rhs[1], rhs[0]);

		// acc = result_full - lhs_full - rhs_full
		let acc = self.sub(result_full, lhs_full);
		let acc = self.sub(acc, rhs_full);

		// acc16 = result[0] - lhs[0] - rhs[0]
		let acc16 = self.sub(result[0], lhs[0]);
		let acc16 = self.sub(acc16, rhs[0]);

		// Constraint 1: acc * (acc + 2^32) == 0
		let c232 = self.constant(F::from_canonical_u64(1u64 << 32));
		let acc_shifted = self.add(acc, c232);
		let check1 = self.mul(acc, acc_shifted);
		self.assert_zero(check1);

		// Constraint 2: acc16 * (acc16 + 2^16) == 0
		let c216_target = self.constant(F::from_canonical_u64(1u64 << 16));
		let acc16_shifted = self.add(acc16, c216_target);
		let check2 = self.mul(acc16, acc16_shifted);
		self.assert_zero(check2);
	}
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

/// Witness generator for wrapping u32 addition.
///
/// Given two u32 field elements, computes `result = (a + b) % 2^32`
/// and `overflow = (a + b) >> 32`.
#[derive(Debug, Clone)]
struct U32WrappingAddGenerator {
	a: Target,
	b: Target,
	result: Target,
	overflow: Target,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
	for U32WrappingAddGenerator
{
	fn id(&self) -> String {
		"U32WrappingAddGenerator".to_string()
	}

	fn dependencies(&self) -> Vec<Target> {
		vec![self.a, self.b]
	}

	fn run_once(
		&self,
		witness: &PartitionWitness<F>,
		out_buffer: &mut GeneratedValues<F>,
	) -> anyhow::Result<()> {
		let a_val = witness.get_target(self.a).to_canonical_u64();
		let b_val = witness.get_target(self.b).to_canonical_u64();
		let sum = a_val + b_val;
		out_buffer.set_target(self.result, F::from_canonical_u64(sum & 0xFFFFFFFF))?;
		out_buffer.set_target(self.overflow, F::from_canonical_u64(sum >> 32))?;
		Ok(())
	}

	fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
		dst.write_target(self.a)?;
		dst.write_target(self.b)?;
		dst.write_target(self.result)?;
		dst.write_target(self.overflow)?;
		Ok(())
	}

	fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
		let a = src.read_target()?;
		let b = src.read_target()?;
		let result = src.read_target()?;
		let overflow = src.read_target()?;
		Ok(Self {
			a,
			b,
			result,
			overflow,
		})
	}
}

#[cfg(test)]
mod tests {
	use anyhow::Result;
	use plonky2::{
		field::{goldilocks_field::GoldilocksField, types::Field},
		iop::witness::{PartialWitness, WitnessWrite},
		plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
	};

	use super::*;
	use crate::plonky2_gadgets::u32::gadgets::*;

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = GoldilocksField;

	#[test]
	fn test_wrapping_add_no_overflow() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);

		let a = builder.add_virtual_u32_target();
		let b = builder.add_virtual_u32_target();
		let c = builder.wrapping_add_u32(a, b, range_lut);

		builder.register_public_input(c.0);

		let data = builder.build::<C>();

		let a_val: u32 = 100;
		let b_val: u32 = 200;

		let mut pw = PartialWitness::new();
		pw.set_target(a.0, F::from_canonical_u32(a_val))?;
		pw.set_target(b.0, F::from_canonical_u32(b_val))?;

		let proof = data.prove(pw)?;

		assert_eq!(proof.public_inputs[0], F::from_canonical_u32(300),);

		data.verify(proof)?;
		Ok(())
	}

	#[test]
	fn test_wrapping_add_with_overflow() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);

		let a = builder.add_virtual_u32_target();
		let b = builder.add_virtual_u32_target();
		let c = builder.wrapping_add_u32(a, b, range_lut);

		builder.register_public_input(c.0);

		let data = builder.build::<C>();

		let a_val: u32 = 0xFFFFFFFF;
		let b_val: u32 = 1;
		let expected: u32 = a_val.wrapping_add(b_val); // 0

		let mut pw = PartialWitness::new();
		pw.set_target(a.0, F::from_canonical_u64(a_val as u64))?;
		pw.set_target(b.0, F::from_canonical_u32(b_val))?;

		let proof = data.prove(pw)?;

		assert_eq!(
			proof.public_inputs[0],
			F::from_canonical_u32(expected),
			"wrapping add mismatch: expected {:#010X}",
			expected,
		);

		data.verify(proof)?;
		Ok(())
	}

	#[test]
	fn test_wrapping_add_large_overflow() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);

		let a = builder.add_virtual_u32_target();
		let b = builder.add_virtual_u32_target();
		let c = builder.wrapping_add_u32(a, b, range_lut);

		builder.register_public_input(c.0);

		let data = builder.build::<C>();

		let a_val: u32 = 0xDEADBEEF;
		let b_val: u32 = 0xCAFEBABE;
		let expected: u32 = a_val.wrapping_add(b_val); // 0xA9AC79AD

		let mut pw = PartialWitness::new();
		pw.set_target(a.0, F::from_canonical_u64(a_val as u64))?;
		pw.set_target(b.0, F::from_canonical_u64(b_val as u64))?;

		let proof = data.prove(pw)?;

		assert_eq!(
			proof.public_inputs[0],
			F::from_canonical_u64(expected as u64),
			"wrapping add mismatch: expected {:#010X}",
			expected,
		);

		data.verify(proof)?;
		Ok(())
	}

	#[test]
	fn test_assert_add_u32_limbs_no_overflow() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);

		let a = builder.add_virtual_u32_target();
		let b = builder.add_virtual_u32_target();
		let c = builder.add_virtual_u32_target();

		let a_limbs = builder.decompose_u32_to_u16_limbs(a, range_lut);
		let b_limbs = builder.decompose_u32_to_u16_limbs(b, range_lut);
		let c_limbs = builder.decompose_u32_to_u16_limbs(c, range_lut);

		builder.assert_add_u32_limbs(c_limbs, a_limbs, b_limbs);

		builder.register_public_input(c.0);

		let data = builder.build::<C>();

		let a_val: u32 = 1000;
		let b_val: u32 = 2000;
		let expected: u32 = 3000;

		let mut pw = PartialWitness::new();
		pw.set_target(a.0, F::from_canonical_u32(a_val))?;
		pw.set_target(b.0, F::from_canonical_u32(b_val))?;
		pw.set_target(c.0, F::from_canonical_u32(expected))?;

		let proof = data.prove(pw)?;
		assert_eq!(proof.public_inputs[0], F::from_canonical_u32(expected));
		data.verify(proof)?;
		Ok(())
	}

	#[test]
	fn test_assert_add_u32_limbs_with_overflow() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);

		let a = builder.add_virtual_u32_target();
		let b = builder.add_virtual_u32_target();
		let c = builder.add_virtual_u32_target();

		let a_limbs = builder.decompose_u32_to_u16_limbs(a, range_lut);
		let b_limbs = builder.decompose_u32_to_u16_limbs(b, range_lut);
		let c_limbs = builder.decompose_u32_to_u16_limbs(c, range_lut);

		builder.assert_add_u32_limbs(c_limbs, a_limbs, b_limbs);

		builder.register_public_input(c.0);

		let data = builder.build::<C>();

		let a_val: u32 = 0xFFFFFFFF;
		let b_val: u32 = 1;
		let expected: u32 = a_val.wrapping_add(b_val); // 0

		let mut pw = PartialWitness::new();
		pw.set_target(a.0, F::from_canonical_u64(a_val as u64))?;
		pw.set_target(b.0, F::from_canonical_u32(b_val))?;
		pw.set_target(c.0, F::from_canonical_u32(expected))?;

		let proof = data.prove(pw)?;
		assert_eq!(proof.public_inputs[0], F::from_canonical_u32(expected));
		data.verify(proof)?;
		Ok(())
	}

	#[test]
	fn test_assert_add_u32_limbs_large_values() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);

		let a = builder.add_virtual_u32_target();
		let b = builder.add_virtual_u32_target();
		let c = builder.add_virtual_u32_target();

		let a_limbs = builder.decompose_u32_to_u16_limbs(a, range_lut);
		let b_limbs = builder.decompose_u32_to_u16_limbs(b, range_lut);
		let c_limbs = builder.decompose_u32_to_u16_limbs(c, range_lut);

		builder.assert_add_u32_limbs(c_limbs, a_limbs, b_limbs);

		builder.register_public_input(c.0);

		let data = builder.build::<C>();

		let a_val: u32 = 0xDEADBEEF;
		let b_val: u32 = 0xCAFEBABE;
		let expected: u32 = a_val.wrapping_add(b_val); // 0xA9AC79AD

		let mut pw = PartialWitness::new();
		pw.set_target(a.0, F::from_canonical_u64(a_val as u64))?;
		pw.set_target(b.0, F::from_canonical_u64(b_val as u64))?;
		pw.set_target(c.0, F::from_canonical_u64(expected as u64))?;

		let proof = data.prove(pw)?;
		assert_eq!(
			proof.public_inputs[0],
			F::from_canonical_u64(expected as u64)
		);
		data.verify(proof)?;
		Ok(())
	}

	#[test]
	fn test_wrapping_add_wrong_output() {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);

		let a = builder.constant_u32(100);
		let b = builder.constant_u32(200);
		let c = builder.wrapping_add_u32(a, b, range_lut);

		let wrong = builder.constant_u32(0);
		builder.connect(c.0, wrong.0);

		let data = builder.build::<C>();
		assert!(data.prove(PartialWitness::new()).is_err());
	}

	#[test]
	fn test_assert_add_u32_limbs_wrong_result() {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);

		let a = builder.constant_u32(1000);
		let b = builder.constant_u32(2000);
		let c = builder.constant_u32(9999); // wrong: correct is 3000

		let a_limbs = builder.decompose_u32_to_u16_limbs(a, range_lut);
		let b_limbs = builder.decompose_u32_to_u16_limbs(b, range_lut);
		let c_limbs = builder.decompose_u32_to_u16_limbs(c, range_lut);

		builder.assert_add_u32_limbs(c_limbs, a_limbs, b_limbs);

		let data = builder.build::<C>();
		assert!(data.prove(PartialWitness::new()).is_err());
	}
}
