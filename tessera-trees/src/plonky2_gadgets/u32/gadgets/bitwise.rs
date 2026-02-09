use plonky2::{
	field::extension::Extendable,
	hash::hash_types::RichField,
	iop::target::Target,
	plonk::circuit_builder::CircuitBuilder,
};

use super::{CircuitBuilderU32, U32Target};

/// Extension trait: bitwise XOR, AND, NOT on [`U32Target`].
pub trait CircuitBuilderU32Bitwise<F: RichField + Extendable<D>, const D: usize> {
	/// Computes `a ^ b` (bitwise XOR) using byte-pair lookup tables.
	///
	/// Both operands are decomposed into bytes, and each byte pair is
	/// XORed via a single lookup in the table at `xor_lut`.
	///
	/// **Range checking:** both inputs are range-checked via byte
	/// decomposition.  The output is implicitly a valid u32 (recomposed
	/// from lookup-output bytes in `[0, 255]`).
	fn xor_u32(
		&mut self,
		a: U32Target,
		b: U32Target,
		xor_lut: usize,
		range_lut: usize,
	) -> U32Target;

	/// Computes `a & b` (bitwise AND) using byte-pair lookup tables.
	///
	/// **Range checking:** both inputs are range-checked via byte
	/// decomposition.  The output is implicitly a valid u32 (recomposed
	/// from lookup-output bytes in `[0, 255]`).
	fn and_u32(
		&mut self,
		a: U32Target,
		b: U32Target,
		and_lut: usize,
		range_lut: usize,
	) -> U32Target;

	/// Computes `!a` (bitwise NOT).
	///
	/// Implemented as `0xFFFFFFFF - a`.
	///
	/// **Range checking:** assumes `a` is already range-checked.
	/// The output is inherently in `[0, 2^32)` but is **not** explicitly
	/// range-checked (no byte decomposition is performed).
	fn not_u32(&mut self, a: U32Target) -> U32Target;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderU32Bitwise<F, D>
	for CircuitBuilder<F, D>
{
	fn xor_u32(
		&mut self,
		a: U32Target,
		b: U32Target,
		xor_lut: usize,
		range_lut: usize,
	) -> U32Target {
		let a_bytes = self.decompose_u32_to_bytes(a, range_lut);
		let b_bytes = self.decompose_u32_to_bytes(b, range_lut);

		let c256 = F::from_canonical_u64(256);

		let xor_bytes: [Target; 4] = core::array::from_fn(|i| {
			let packed = self.mul_const_add(c256, a_bytes[i], b_bytes[i]);
			self.add_lookup_from_index(packed, xor_lut)
		});

		let mut result = xor_bytes[3];
		result = self.mul_const_add(c256, result, xor_bytes[2]);
		result = self.mul_const_add(c256, result, xor_bytes[1]);
		result = self.mul_const_add(c256, result, xor_bytes[0]);

		U32Target(result)
	}

	fn and_u32(
		&mut self,
		a: U32Target,
		b: U32Target,
		and_lut: usize,
		range_lut: usize,
	) -> U32Target {
		let a_bytes = self.decompose_u32_to_bytes(a, range_lut);
		let b_bytes = self.decompose_u32_to_bytes(b, range_lut);

		let c256 = F::from_canonical_u64(256);

		let and_bytes: [Target; 4] = core::array::from_fn(|i| {
			let packed = self.mul_const_add(c256, a_bytes[i], b_bytes[i]);
			self.add_lookup_from_index(packed, and_lut)
		});

		let mut result = and_bytes[3];
		result = self.mul_const_add(c256, result, and_bytes[2]);
		result = self.mul_const_add(c256, result, and_bytes[1]);
		result = self.mul_const_add(c256, result, and_bytes[0]);

		U32Target(result)
	}

	fn not_u32(&mut self, a: U32Target) -> U32Target {
		let mask = self.constant(F::from_canonical_u64(0xFFFFFFFF));
		U32Target(self.sub(mask, a.0))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::plonky2_gadgets::u32::gadgets::*;
	use anyhow::Result;
	use plonky2::{
		field::{goldilocks_field::GoldilocksField, types::Field},
		iop::witness::{PartialWitness, WitnessWrite},
		plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
	};

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = GoldilocksField;

	#[test]
	fn test_xor_u32() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);
		let xor_lut = add_xor_lookup_table(&mut builder);

		let a = builder.add_virtual_u32_target();
		let b = builder.add_virtual_u32_target();
		let c = builder.xor_u32(a, b, xor_lut, range_lut);

		builder.register_public_input(c.0);

		let data = builder.build::<C>();

		let a_val: u32 = 0xDEADBEEF;
		let b_val: u32 = 0xCAFEBABE;
		let expected: u32 = a_val ^ b_val;

		let mut pw = PartialWitness::new();
		pw.set_target(a.0, F::from_canonical_u64(a_val as u64))?;
		pw.set_target(b.0, F::from_canonical_u64(b_val as u64))?;

		let proof = data.prove(pw)?;

		assert_eq!(
			proof.public_inputs[0],
			F::from_canonical_u64(expected as u64),
			"XOR mismatch: expected {:#010X}",
			expected,
		);

		data.verify(proof)?;
		Ok(())
	}

	#[test]
	fn test_xor_self_is_zero() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);
		let xor_lut = add_xor_lookup_table(&mut builder);

		let a = builder.add_virtual_u32_target();
		let c = builder.xor_u32(a, a, xor_lut, range_lut);

		let zero = builder.zero();
		builder.connect(c.0, zero);

		let data = builder.build::<C>();

		let mut pw = PartialWitness::new();
		pw.set_target(a.0, F::from_canonical_u32(0x12345678))?;

		let proof = data.prove(pw)?;
		data.verify(proof)?;
		Ok(())
	}

	#[test]
	fn test_xor_with_zero_is_identity() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);
		let xor_lut = add_xor_lookup_table(&mut builder);

		let a = builder.add_virtual_u32_target();
		let zero = builder.constant_u32(0);
		let c = builder.xor_u32(a, zero, xor_lut, range_lut);

		builder.connect(c.0, a.0);

		let data = builder.build::<C>();

		let mut pw = PartialWitness::new();
		pw.set_target(a.0, F::from_canonical_u32(0xABCDEF01))?;

		let proof = data.prove(pw)?;
		data.verify(proof)?;
		Ok(())
	}

	#[test]
	fn test_xor_not() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);
		let xor_lut = add_xor_lookup_table(&mut builder);

		let a = builder.add_virtual_u32_target();
		let mask = builder.constant_u32(0xFFFFFFFF);
		let c = builder.xor_u32(a, mask, xor_lut, range_lut);

		builder.register_public_input(c.0);

		let data = builder.build::<C>();

		let a_val: u32 = 0x12345678;
		let expected: u32 = !a_val;

		let mut pw = PartialWitness::new();
		pw.set_target(a.0, F::from_canonical_u32(a_val))?;

		let proof = data.prove(pw)?;

		assert_eq!(
			proof.public_inputs[0],
			F::from_canonical_u64(expected as u64),
			"NOT mismatch: expected {:#010X}",
			expected,
		);

		data.verify(proof)?;
		Ok(())
	}

	#[test]
	fn test_and_u32() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);
		let and_lut = add_and_lookup_table(&mut builder);

		let a = builder.add_virtual_u32_target();
		let b = builder.add_virtual_u32_target();
		let c = builder.and_u32(a, b, and_lut, range_lut);

		builder.register_public_input(c.0);

		let data = builder.build::<C>();

		let a_val: u32 = 0xDEADBEEF;
		let b_val: u32 = 0xFF00FF00;
		let expected: u32 = a_val & b_val;

		let mut pw = PartialWitness::new();
		pw.set_target(a.0, F::from_canonical_u64(a_val as u64))?;
		pw.set_target(b.0, F::from_canonical_u64(b_val as u64))?;

		let proof = data.prove(pw)?;
		assert_eq!(
			proof.public_inputs[0],
			F::from_canonical_u64(expected as u64),
			"AND mismatch: expected {:#010X}",
			expected,
		);

		data.verify(proof)?;
		Ok(())
	}

	#[test]
	fn test_not_u32() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);

		let a = builder.add_virtual_u32_target();
		let na = builder.not_u32(a);

		builder.decompose_u32_to_bytes(a, range_lut);
		builder.register_public_input(na.0);

		let data = builder.build::<C>();

		let a_val: u32 = 0xDEADBEEF;
		let expected: u32 = !a_val;

		let mut pw = PartialWitness::new();
		pw.set_target(a.0, F::from_canonical_u64(a_val as u64))?;

		let proof = data.prove(pw)?;
		assert_eq!(
			proof.public_inputs[0],
			F::from_canonical_u64(expected as u64),
			"NOT mismatch: expected {:#010X}",
			expected,
		);

		data.verify(proof)?;
		Ok(())
	}

	#[test]
	fn test_xor_u32_wrong_output() {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);
		let xor_lut = add_xor_lookup_table(&mut builder);

		let a = builder.constant_u32(0xDEADBEEF);
		let b = builder.constant_u32(0xCAFEBABE);
		let c = builder.xor_u32(a, b, xor_lut, range_lut);

		let wrong = builder.constant_u32(0x00000000);
		builder.connect(c.0, wrong.0);

		let data = builder.build::<C>();
		assert!(data.prove(PartialWitness::new()).is_err());
	}

	#[test]
	fn test_and_u32_wrong_output() {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);
		let and_lut = add_and_lookup_table(&mut builder);

		let a = builder.constant_u32(0xDEADBEEF);
		let b = builder.constant_u32(0xFF00FF00);
		let c = builder.and_u32(a, b, and_lut, range_lut);

		let wrong = builder.constant_u32(0x00000000);
		builder.connect(c.0, wrong.0);

		let data = builder.build::<C>();
		assert!(data.prove(PartialWitness::new()).is_err());
	}

	#[test]
	fn test_not_u32_wrong_output() {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);

		let a = builder.constant_u32(0xDEADBEEF);
		let na = builder.not_u32(a);
		builder.decompose_u32_to_bytes(a, range_lut);

		let wrong = builder.constant_u32(0x00000000);
		builder.connect(na.0, wrong.0);

		let data = builder.build::<C>();
		assert!(data.prove(PartialWitness::new()).is_err());
	}
}
