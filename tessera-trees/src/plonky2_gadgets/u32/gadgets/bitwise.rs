use plonky2::{
	field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
	plonk::circuit_builder::CircuitBuilder,
};

use super::{BitwiseLuts, CircuitBuilderU32, U32Target};

/// Extension trait: bitwise XOR, AND, NOT on [`U32Target`].
pub trait CircuitBuilderU32Bitwise<F: RichField + Extendable<D>, const D: usize> {
	/// Computes `a ^ b` (bitwise XOR) using chunk-pair lookup tables.
	///
	/// Both operands are decomposed into `32 / chunk_bits` chunks, and
	/// each chunk pair is XORed via a single lookup.
	///
	/// **Range checking:** both inputs are range-checked via chunk
	/// decomposition.  The output is implicitly a valid u32 (recomposed
	/// from lookup-output chunks).
	fn xor_u32(&mut self, a: U32Target, b: U32Target, luts: &BitwiseLuts) -> U32Target;

	/// Computes `a & b` (bitwise AND) using chunk-pair lookup tables.
	///
	/// **Range checking:** both inputs are range-checked via chunk
	/// decomposition.  The output is implicitly a valid u32 (recomposed
	/// from lookup-output chunks).
	fn and_u32(&mut self, a: U32Target, b: U32Target, luts: &BitwiseLuts) -> U32Target;

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
	fn xor_u32(&mut self, a: U32Target, b: U32Target, luts: &BitwiseLuts) -> U32Target {
		let a_chunks = self.decompose_u32_to_chunks(a, luts.chunk_range_lut, luts.chunk_bits);
		let b_chunks = self.decompose_u32_to_chunks(b, luts.chunk_range_lut, luts.chunk_bits);

		let c_base = F::from_canonical_u64(1u64 << luts.chunk_bits);
		let num_chunks = 32 / luts.chunk_bits;

		let xor_chunks: Vec<Target> = (0..num_chunks)
			.map(|i| {
				let packed = self.mul_const_add(c_base, a_chunks[i], b_chunks[i]);
				self.add_lookup_from_index(packed, luts.xor_lut)
			})
			.collect();

		let mut result = xor_chunks[num_chunks - 1];
		for i in (0..num_chunks - 1).rev() {
			result = self.mul_const_add(c_base, result, xor_chunks[i]);
		}

		U32Target(result)
	}

	fn and_u32(&mut self, a: U32Target, b: U32Target, luts: &BitwiseLuts) -> U32Target {
		let a_chunks = self.decompose_u32_to_chunks(a, luts.chunk_range_lut, luts.chunk_bits);
		let b_chunks = self.decompose_u32_to_chunks(b, luts.chunk_range_lut, luts.chunk_bits);

		let c_base = F::from_canonical_u64(1u64 << luts.chunk_bits);
		let num_chunks = 32 / luts.chunk_bits;

		let and_chunks: Vec<Target> = (0..num_chunks)
			.map(|i| {
				let packed = self.mul_const_add(c_base, a_chunks[i], b_chunks[i]);
				self.add_lookup_from_index(packed, luts.and_lut)
			})
			.collect();

		let mut result = and_chunks[num_chunks - 1];
		for i in (0..num_chunks - 1).rev() {
			result = self.mul_const_add(c_base, result, and_chunks[i]);
		}

		U32Target(result)
	}

	fn not_u32(&mut self, a: U32Target) -> U32Target {
		let mask = self.constant(F::from_canonical_u64(0xFFFFFFFF));
		U32Target(self.sub(mask, a.0))
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

	/// Build a BitwiseLuts with only XOR + range tables registered.
	fn xor_only_luts(builder: &mut CircuitBuilder<F, D>) -> BitwiseLuts {
		let byte_range_lut = add_u8_range_check_lookup_table(builder);
		let xor_lut = add_xor_lookup_table(builder);
		BitwiseLuts {
			chunk_bits: 8,
			chunk_range_lut: byte_range_lut,
			xor_lut,
			and_lut: usize::MAX,
			byte_range_lut,
		}
	}

	/// Build a BitwiseLuts with only AND + range tables registered.
	fn and_only_luts(builder: &mut CircuitBuilder<F, D>) -> BitwiseLuts {
		let byte_range_lut = add_u8_range_check_lookup_table(builder);
		let and_lut = add_and_lookup_table(builder);
		BitwiseLuts {
			chunk_bits: 8,
			chunk_range_lut: byte_range_lut,
			xor_lut: usize::MAX,
			and_lut,
			byte_range_lut,
		}
	}

	#[test]
	fn test_xor_u32() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let luts = xor_only_luts(&mut builder);

		let a = builder.add_virtual_u32_target();
		let b = builder.add_virtual_u32_target();
		let c = builder.xor_u32(a, b, &luts);

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

		let luts = xor_only_luts(&mut builder);

		let a = builder.add_virtual_u32_target();
		let c = builder.xor_u32(a, a, &luts);

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

		let luts = xor_only_luts(&mut builder);

		let a = builder.add_virtual_u32_target();
		let zero = builder.constant_u32(0);
		let c = builder.xor_u32(a, zero, &luts);

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

		let luts = xor_only_luts(&mut builder);

		let a = builder.add_virtual_u32_target();
		let mask = builder.constant_u32(0xFFFFFFFF);
		let c = builder.xor_u32(a, mask, &luts);

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

		let luts = and_only_luts(&mut builder);

		let a = builder.add_virtual_u32_target();
		let b = builder.add_virtual_u32_target();
		let c = builder.and_u32(a, b, &luts);

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

		let luts = xor_only_luts(&mut builder);

		let a = builder.constant_u32(0xDEADBEEF);
		let b = builder.constant_u32(0xCAFEBABE);
		let c = builder.xor_u32(a, b, &luts);

		let wrong = builder.constant_u32(0x00000000);
		builder.connect(c.0, wrong.0);

		let data = builder.build::<C>();
		assert!(data.prove(PartialWitness::new()).is_err());
	}

	#[test]
	fn test_and_u32_wrong_output() {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let luts = and_only_luts(&mut builder);

		let a = builder.constant_u32(0xDEADBEEF);
		let b = builder.constant_u32(0xFF00FF00);
		let c = builder.and_u32(a, b, &luts);

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
