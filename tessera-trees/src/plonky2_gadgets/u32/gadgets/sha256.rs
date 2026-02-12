use plonky2::{
	field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
	plonk::circuit_builder::CircuitBuilder,
};

use super::{
	BitwiseLuts, CircuitBuilderU32, CircuitBuilderU32Bitwise, CircuitBuilderU32Rotation, U32Target,
};

/// Extension trait: SHA256 compound operations on [`U32Target`].
pub trait CircuitBuilderU32Sha256<F: RichField + Extendable<D>, const D: usize> {
	/// Computes `Ch(x, y, z) = (x & y) ^ (!x & z)`.
	///
	/// Implemented chunk-by-chunk using the algebraic identity
	/// `z ^ (x & (y ^ z))` (3 lookups per chunk).
	///
	/// **Range checking:** all three inputs are range-checked via chunk
	/// decomposition.  The output is implicitly a valid u32 (recomposed
	/// from lookup-output chunks).
	fn ch_u32(&mut self, x: U32Target, y: U32Target, z: U32Target, luts: &BitwiseLuts)
	-> U32Target;

	/// Computes `Maj(x, y, z) = (x & y) ^ (x & z) ^ (y & z)`.
	///
	/// Implemented chunk-by-chunk using the algebraic identity
	/// `(x & y) ^ ((x ^ y) & z)` (4 lookups per chunk).
	///
	/// **Range checking:** all three inputs are range-checked via chunk
	/// decomposition.  The output is implicitly a valid u32 (recomposed
	/// from lookup-output chunks).
	fn maj_u32(
		&mut self,
		x: U32Target,
		y: U32Target,
		z: U32Target,
		luts: &BitwiseLuts,
	) -> U32Target;

	/// `Σ₀(a) = ROTR(a,2) ⊕ ROTR(a,13) ⊕ ROTR(a,22)`
	///
	/// **Range checking:** assumes `a` is already range-checked as u32.
	/// The output is implicitly a valid u32 (produced by `xor_u32`).
	fn big_sigma0_u32(&mut self, a: U32Target, luts: &BitwiseLuts) -> U32Target;

	/// `Σ₁(e) = ROTR(e,6) ⊕ ROTR(e,11) ⊕ ROTR(e,25)`
	///
	/// **Range checking:** assumes `e` is already range-checked as u32.
	/// The output is implicitly a valid u32 (produced by `xor_u32`).
	fn big_sigma1_u32(&mut self, e: U32Target, luts: &BitwiseLuts) -> U32Target;

	/// `σ₀(x) = ROTR(x,7) ⊕ ROTR(x,18) ⊕ SHR(x,3)`
	///
	/// **Range checking:** assumes `x` is already range-checked as u32.
	/// The output is implicitly a valid u32 (produced by `xor_u32`).
	fn small_sigma0_u32(&mut self, x: U32Target, luts: &BitwiseLuts) -> U32Target;

	/// `σ₁(x) = ROTR(x,17) ⊕ ROTR(x,19) ⊕ SHR(x,10)`
	///
	/// **Range checking:** assumes `x` is already range-checked as u32.
	/// The output is implicitly a valid u32 (produced by `xor_u32`).
	fn small_sigma1_u32(&mut self, x: U32Target, luts: &BitwiseLuts) -> U32Target;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderU32Sha256<F, D>
	for CircuitBuilder<F, D>
{
	fn ch_u32(
		&mut self,
		x: U32Target,
		y: U32Target,
		z: U32Target,
		luts: &BitwiseLuts,
	) -> U32Target {
		let x_chunks = self.decompose_u32_to_chunks(x, luts.chunk_range_lut, luts.chunk_bits);
		let y_chunks = self.decompose_u32_to_chunks(y, luts.chunk_range_lut, luts.chunk_bits);
		let z_chunks = self.decompose_u32_to_chunks(z, luts.chunk_range_lut, luts.chunk_bits);

		let c_base = F::from_canonical_u64(1u64 << luts.chunk_bits);
		let num_chunks = 32 / luts.chunk_bits;

		// Per chunk: Ch(x,y,z) = z ^ (x & (y ^ z))
		let ch_chunks: Vec<Target> = (0..num_chunks)
			.map(|i| {
				let packed_yz = self.mul_const_add(c_base, y_chunks[i], z_chunks[i]);
				let y_xor_z = self.add_lookup_from_index(packed_yz, luts.xor_lut);

				let packed_x_yz = self.mul_const_add(c_base, x_chunks[i], y_xor_z);
				let x_and_yz = self.add_lookup_from_index(packed_x_yz, luts.and_lut);

				let packed_result = self.mul_const_add(c_base, z_chunks[i], x_and_yz);
				self.add_lookup_from_index(packed_result, luts.xor_lut)
			})
			.collect();

		let mut result = ch_chunks[num_chunks - 1];
		for i in (0..num_chunks - 1).rev() {
			result = self.mul_const_add(c_base, result, ch_chunks[i]);
		}

		U32Target(result)
	}

	fn maj_u32(
		&mut self,
		x: U32Target,
		y: U32Target,
		z: U32Target,
		luts: &BitwiseLuts,
	) -> U32Target {
		let x_chunks = self.decompose_u32_to_chunks(x, luts.chunk_range_lut, luts.chunk_bits);
		let y_chunks = self.decompose_u32_to_chunks(y, luts.chunk_range_lut, luts.chunk_bits);
		let z_chunks = self.decompose_u32_to_chunks(z, luts.chunk_range_lut, luts.chunk_bits);

		let c_base = F::from_canonical_u64(1u64 << luts.chunk_bits);
		let num_chunks = 32 / luts.chunk_bits;

		// Per chunk: Maj(x,y,z) = (x & y) ^ ((x ^ y) & z)
		let maj_chunks: Vec<Target> = (0..num_chunks)
			.map(|i| {
				let packed_xy = self.mul_const_add(c_base, x_chunks[i], y_chunks[i]);
				let x_and_y = self.add_lookup_from_index(packed_xy, luts.and_lut);
				let x_xor_y = self.add_lookup_from_index(packed_xy, luts.xor_lut);

				let packed_xory_z = self.mul_const_add(c_base, x_xor_y, z_chunks[i]);
				let xory_and_z = self.add_lookup_from_index(packed_xory_z, luts.and_lut);

				let packed_result = self.mul_const_add(c_base, x_and_y, xory_and_z);
				self.add_lookup_from_index(packed_result, luts.xor_lut)
			})
			.collect();

		let mut result = maj_chunks[num_chunks - 1];
		for i in (0..num_chunks - 1).rev() {
			result = self.mul_const_add(c_base, result, maj_chunks[i]);
		}

		U32Target(result)
	}

	fn big_sigma0_u32(&mut self, a: U32Target, luts: &BitwiseLuts) -> U32Target {
		let r2 = self.rotr_u32(a, 2, luts.byte_range_lut);
		let r13 = self.rotr_u32(a, 13, luts.byte_range_lut);
		let r22 = self.rotr_u32(a, 22, luts.byte_range_lut);
		let t = self.xor_u32(r2, r13, luts);
		self.xor_u32(t, r22, luts)
	}

	fn big_sigma1_u32(&mut self, e: U32Target, luts: &BitwiseLuts) -> U32Target {
		let r6 = self.rotr_u32(e, 6, luts.byte_range_lut);
		let r11 = self.rotr_u32(e, 11, luts.byte_range_lut);
		let r25 = self.rotr_u32(e, 25, luts.byte_range_lut);
		let t = self.xor_u32(r6, r11, luts);
		self.xor_u32(t, r25, luts)
	}

	fn small_sigma0_u32(&mut self, x: U32Target, luts: &BitwiseLuts) -> U32Target {
		let r7 = self.rotr_u32(x, 7, luts.byte_range_lut);
		let r18 = self.rotr_u32(x, 18, luts.byte_range_lut);
		let s3 = self.shr_u32(x, 3, luts.byte_range_lut);
		let t = self.xor_u32(r7, r18, luts);
		self.xor_u32(t, s3, luts)
	}

	fn small_sigma1_u32(&mut self, x: U32Target, luts: &BitwiseLuts) -> U32Target {
		let r17 = self.rotr_u32(x, 17, luts.byte_range_lut);
		let r19 = self.rotr_u32(x, 19, luts.byte_range_lut);
		let s10 = self.shr_u32(x, 10, luts.byte_range_lut);
		let t = self.xor_u32(r17, r19, luts);
		self.xor_u32(t, s10, luts)
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

	/// Build a BitwiseLuts with only XOR + range tables (no AND).
	/// Used by sigma-function tests that don't exercise AND.
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

	#[test]
	fn test_ch_u32() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let luts = BitwiseLuts::new(&mut builder, 8);

		let x = builder.add_virtual_u32_target();
		let y = builder.add_virtual_u32_target();
		let z = builder.add_virtual_u32_target();
		let c = builder.ch_u32(x, y, z, &luts);

		builder.register_public_input(c.0);

		let data = builder.build::<C>();

		let x_val: u32 = 0xDEADBEEF;
		let y_val: u32 = 0xCAFEBABE;
		let z_val: u32 = 0x12345678;
		let expected: u32 = (x_val & y_val) ^ (!x_val & z_val);

		let mut pw = PartialWitness::new();
		pw.set_target(x.0, F::from_canonical_u64(x_val as u64))?;
		pw.set_target(y.0, F::from_canonical_u64(y_val as u64))?;
		pw.set_target(z.0, F::from_canonical_u64(z_val as u64))?;

		let proof = data.prove(pw)?;
		assert_eq!(
			proof.public_inputs[0],
			F::from_canonical_u64(expected as u64),
			"Ch mismatch: expected {:#010X}",
			expected,
		);

		data.verify(proof)?;
		Ok(())
	}

	#[test]
	fn test_maj_u32() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let luts = BitwiseLuts::new(&mut builder, 8);

		let x = builder.add_virtual_u32_target();
		let y = builder.add_virtual_u32_target();
		let z = builder.add_virtual_u32_target();
		let m = builder.maj_u32(x, y, z, &luts);

		builder.register_public_input(m.0);

		let data = builder.build::<C>();

		let x_val: u32 = 0xDEADBEEF;
		let y_val: u32 = 0xCAFEBABE;
		let z_val: u32 = 0x12345678;
		let expected: u32 = (x_val & y_val) ^ (x_val & z_val) ^ (y_val & z_val);

		let mut pw = PartialWitness::new();
		pw.set_target(x.0, F::from_canonical_u64(x_val as u64))?;
		pw.set_target(y.0, F::from_canonical_u64(y_val as u64))?;
		pw.set_target(z.0, F::from_canonical_u64(z_val as u64))?;

		let proof = data.prove(pw)?;
		assert_eq!(
			proof.public_inputs[0],
			F::from_canonical_u64(expected as u64),
			"Maj mismatch: expected {:#010X}",
			expected,
		);

		data.verify(proof)?;
		Ok(())
	}

	#[test]
	fn test_big_sigma0_u32() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let luts = xor_only_luts(&mut builder);

		let a = builder.add_virtual_u32_target();
		let s = builder.big_sigma0_u32(a, &luts);

		builder.register_public_input(s.0);

		let data = builder.build::<C>();

		let a_val: u32 = 0x6A09E667; // SHA256 H0
		let expected: u32 = a_val.rotate_right(2) ^ a_val.rotate_right(13) ^ a_val.rotate_right(22);

		let mut pw = PartialWitness::new();
		pw.set_target(a.0, F::from_canonical_u64(a_val as u64))?;

		let proof = data.prove(pw)?;
		assert_eq!(
			proof.public_inputs[0],
			F::from_canonical_u64(expected as u64),
		);

		data.verify(proof)?;
		Ok(())
	}

	#[test]
	fn test_big_sigma1_u32() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let luts = xor_only_luts(&mut builder);

		let e = builder.add_virtual_u32_target();
		let s = builder.big_sigma1_u32(e, &luts);

		builder.register_public_input(s.0);

		let data = builder.build::<C>();

		let e_val: u32 = 0x510E527F; // SHA256 H4
		let expected: u32 = e_val.rotate_right(6) ^ e_val.rotate_right(11) ^ e_val.rotate_right(25);

		let mut pw = PartialWitness::new();
		pw.set_target(e.0, F::from_canonical_u64(e_val as u64))?;

		let proof = data.prove(pw)?;
		assert_eq!(
			proof.public_inputs[0],
			F::from_canonical_u64(expected as u64),
		);

		data.verify(proof)?;
		Ok(())
	}

	#[test]
	fn test_small_sigma0_u32() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let luts = xor_only_luts(&mut builder);

		let x = builder.add_virtual_u32_target();
		let s = builder.small_sigma0_u32(x, &luts);

		builder.register_public_input(s.0);

		let data = builder.build::<C>();

		let x_val: u32 = 0xDEADBEEF;
		let expected: u32 = x_val.rotate_right(7) ^ x_val.rotate_right(18) ^ (x_val >> 3);

		let mut pw = PartialWitness::new();
		pw.set_target(x.0, F::from_canonical_u64(x_val as u64))?;

		let proof = data.prove(pw)?;
		assert_eq!(
			proof.public_inputs[0],
			F::from_canonical_u64(expected as u64),
		);

		data.verify(proof)?;
		Ok(())
	}

	#[test]
	fn test_small_sigma1_u32() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let luts = xor_only_luts(&mut builder);

		let x = builder.add_virtual_u32_target();
		let s = builder.small_sigma1_u32(x, &luts);

		builder.register_public_input(s.0);

		let data = builder.build::<C>();

		let x_val: u32 = 0xDEADBEEF;
		let expected: u32 = x_val.rotate_right(17) ^ x_val.rotate_right(19) ^ (x_val >> 10);

		let mut pw = PartialWitness::new();
		pw.set_target(x.0, F::from_canonical_u64(x_val as u64))?;

		let proof = data.prove(pw)?;
		assert_eq!(
			proof.public_inputs[0],
			F::from_canonical_u64(expected as u64),
		);

		data.verify(proof)?;
		Ok(())
	}

	#[test]
	fn test_ch_u32_wrong_output() {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let luts = BitwiseLuts::new(&mut builder, 8);

		let x = builder.constant_u32(0xDEADBEEF);
		let y = builder.constant_u32(0xCAFEBABE);
		let z = builder.constant_u32(0x12345678);
		let c = builder.ch_u32(x, y, z, &luts);

		let wrong = builder.constant_u32(0x00000000);
		builder.connect(c.0, wrong.0);

		let data = builder.build::<C>();
		assert!(data.prove(PartialWitness::new()).is_err());
	}

	#[test]
	fn test_maj_u32_wrong_output() {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let luts = BitwiseLuts::new(&mut builder, 8);

		let x = builder.constant_u32(0xDEADBEEF);
		let y = builder.constant_u32(0xCAFEBABE);
		let z = builder.constant_u32(0x12345678);
		let m = builder.maj_u32(x, y, z, &luts);

		let wrong = builder.constant_u32(0x00000000);
		builder.connect(m.0, wrong.0);

		let data = builder.build::<C>();
		assert!(data.prove(PartialWitness::new()).is_err());
	}

	#[test]
	fn test_big_sigma0_wrong_output() {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let luts = xor_only_luts(&mut builder);

		let a = builder.constant_u32(0x6A09E667);
		let s = builder.big_sigma0_u32(a, &luts);

		let wrong = builder.constant_u32(0x00000000);
		builder.connect(s.0, wrong.0);

		let data = builder.build::<C>();
		assert!(data.prove(PartialWitness::new()).is_err());
	}

	#[test]
	fn test_big_sigma1_wrong_output() {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let luts = xor_only_luts(&mut builder);

		let e = builder.constant_u32(0x510E527F);
		let s = builder.big_sigma1_u32(e, &luts);

		let wrong = builder.constant_u32(0x00000000);
		builder.connect(s.0, wrong.0);

		let data = builder.build::<C>();
		assert!(data.prove(PartialWitness::new()).is_err());
	}

	#[test]
	fn test_small_sigma0_wrong_output() {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let luts = xor_only_luts(&mut builder);

		let x = builder.constant_u32(0xDEADBEEF);
		let s = builder.small_sigma0_u32(x, &luts);

		let wrong = builder.constant_u32(0x00000000);
		builder.connect(s.0, wrong.0);

		let data = builder.build::<C>();
		assert!(data.prove(PartialWitness::new()).is_err());
	}

	#[test]
	fn test_small_sigma1_wrong_output() {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let luts = xor_only_luts(&mut builder);

		let x = builder.constant_u32(0xDEADBEEF);
		let s = builder.small_sigma1_u32(x, &luts);

		let wrong = builder.constant_u32(0x00000000);
		builder.connect(s.0, wrong.0);

		let data = builder.build::<C>();
		assert!(data.prove(PartialWitness::new()).is_err());
	}
}
