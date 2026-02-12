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

/// Extension trait: right rotation and logical right shift on [`U32Target`].
pub trait CircuitBuilderU32Rotation<F: RichField + Extendable<D>, const D: usize> {
	/// Computes `a >> n | a << (32 - n)` (right rotation by `n` bits).
	///
	/// Uses the multiplication trick: `a * 2^(32-n) = hi * 2^32 + lo`,
	/// then `ROTR(a, n) = lo + hi`.  Both `lo` and `hi` are
	/// range-checked as `u32` via byte decomposition (8 lookups total).
	///
	/// **Range checking:** assumes `a` is already range-checked as u32
	/// (the split is only meaningful when `a * 2^(32-n) < 2^64`).
	/// The output is a valid u32 (non-overlapping halves) but is **not**
	/// explicitly range-checked — pass it through a decomposing gadget
	/// (e.g. `xor_u32`) or call `decompose_u32_to_bytes` if a downstream
	/// consumer requires it.
	fn rotr_u32(&mut self, a: U32Target, n: usize, range_lut: usize) -> U32Target;

	/// Computes `a >> n` (logical right shift by `n` bits).
	///
	/// Uses the same multiplication trick as [`rotr_u32`]: the high
	/// 32 bits of `a * 2^(32-n)` equal `a >> n`.
	///
	/// **Range checking:** assumes `a` is already range-checked as u32.
	/// The output (`hi` half) is explicitly range-checked via byte
	/// decomposition.
	fn shr_u32(&mut self, a: U32Target, n: usize, range_lut: usize) -> U32Target;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderU32Rotation<F, D>
	for CircuitBuilder<F, D>
{
	fn rotr_u32(&mut self, a: U32Target, n: usize, range_lut: usize) -> U32Target {
		assert!(n > 0 && n < 32);
		let shift = 32 - n;

		// product = a * 2^shift  (fits in < 2^64 << p)
		let factor = F::from_canonical_u64(1u64 << shift);
		let zero = self.zero();
		let product = self.mul_const_add(factor, a.0, zero);

		// Split: product = hi * 2^32 + lo
		let lo = self.add_virtual_target();
		let hi = self.add_virtual_target();
		self.add_simple_generator(SplitLowHighGenerator {
			product,
			lo,
			hi,
		});

		// Range check both halves as u32
		self.decompose_u32_to_bytes(U32Target(lo), range_lut);
		self.decompose_u32_to_bytes(U32Target(hi), range_lut);

		// Constrain: product == hi * 2^32 + lo
		let c232 = F::from_canonical_u64(1u64 << 32);
		let recomposed = self.mul_const_add(c232, hi, lo);
		self.connect(product, recomposed);

		// ROTR(a, n) = lo + hi
		U32Target(self.add(lo, hi))
	}

	fn shr_u32(&mut self, a: U32Target, n: usize, range_lut: usize) -> U32Target {
		assert!(n > 0 && n < 32);
		let shift = 32 - n;

		let factor = F::from_canonical_u64(1u64 << shift);
		let zero = self.zero();
		let product = self.mul_const_add(factor, a.0, zero);

		let lo = self.add_virtual_target();
		let hi = self.add_virtual_target();
		self.add_simple_generator(SplitLowHighGenerator {
			product,
			lo,
			hi,
		});

		self.decompose_u32_to_bytes(U32Target(lo), range_lut);
		self.decompose_u32_to_bytes(U32Target(hi), range_lut);

		let c232 = F::from_canonical_u64(1u64 << 32);
		let recomposed = self.mul_const_add(c232, hi, lo);
		self.connect(product, recomposed);

		// SHR(a, n) = hi
		U32Target(hi)
	}
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

/// Witness generator that splits a field element at the `2^32` boundary.
///
/// Given `product`, computes `lo = product mod 2^32` and `hi = product / 2^32`.
#[derive(Debug, Clone, Default)]
pub(crate) struct SplitLowHighGenerator {
	product: Target,
	lo: Target,
	hi: Target,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D> for SplitLowHighGenerator {
	fn id(&self) -> String {
		"SplitLowHighGenerator".to_string()
	}

	fn dependencies(&self) -> Vec<Target> {
		vec![self.product]
	}

	fn run_once(
		&self,
		witness: &PartitionWitness<F>,
		out_buffer: &mut GeneratedValues<F>,
	) -> anyhow::Result<()> {
		let val = witness.get_target(self.product).to_canonical_u64();
		out_buffer.set_target(self.lo, F::from_canonical_u64(val & 0xFFFFFFFF))?;
		out_buffer.set_target(self.hi, F::from_canonical_u64(val >> 32))?;
		Ok(())
	}

	fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
		dst.write_target(self.product)?;
		dst.write_target(self.lo)?;
		dst.write_target(self.hi)?;
		Ok(())
	}

	fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
		let product = src.read_target()?;
		let lo = src.read_target()?;
		let hi = src.read_target()?;
		Ok(Self {
			product,
			lo,
			hi,
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
	fn test_rotr_u32() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);

		let a = builder.add_virtual_u32_target();

		// Test all SHA256-relevant rotation amounts
		let r2 = builder.rotr_u32(a, 2, range_lut);
		let r6 = builder.rotr_u32(a, 6, range_lut);
		let r7 = builder.rotr_u32(a, 7, range_lut);
		let r11 = builder.rotr_u32(a, 11, range_lut);
		let r13 = builder.rotr_u32(a, 13, range_lut);
		let r17 = builder.rotr_u32(a, 17, range_lut);
		let r18 = builder.rotr_u32(a, 18, range_lut);
		let r19 = builder.rotr_u32(a, 19, range_lut);
		let r22 = builder.rotr_u32(a, 22, range_lut);
		let r25 = builder.rotr_u32(a, 25, range_lut);

		for t in [r2, r6, r7, r11, r13, r17, r18, r19, r22, r25] {
			builder.register_public_input(t.0);
		}

		let data = builder.build::<C>();

		let a_val: u32 = 0xDEADBEEF;
		let expected: Vec<u32> = [2, 6, 7, 11, 13, 17, 18, 19, 22, 25]
			.iter()
			.map(|&n| a_val.rotate_right(n))
			.collect();

		let mut pw = PartialWitness::new();
		pw.set_target(a.0, F::from_canonical_u64(a_val as u64))?;

		let proof = data.prove(pw)?;

		for (i, &exp) in expected.iter().enumerate() {
			assert_eq!(
				proof.public_inputs[i],
				F::from_canonical_u64(exp as u64),
				"ROTR mismatch at index {i}: expected {:#010X}",
				exp,
			);
		}

		data.verify(proof)?;
		Ok(())
	}

	#[test]
	fn test_shr_u32() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);

		let a = builder.add_virtual_u32_target();

		// SHA256-relevant shift amounts
		let s3 = builder.shr_u32(a, 3, range_lut);
		let s10 = builder.shr_u32(a, 10, range_lut);

		builder.register_public_input(s3.0);
		builder.register_public_input(s10.0);

		let data = builder.build::<C>();

		let a_val: u32 = 0xDEADBEEF;

		let mut pw = PartialWitness::new();
		pw.set_target(a.0, F::from_canonical_u64(a_val as u64))?;

		let proof = data.prove(pw)?;

		assert_eq!(
			proof.public_inputs[0],
			F::from_canonical_u64((a_val >> 3) as u64),
			"SHR(3) mismatch",
		);
		assert_eq!(
			proof.public_inputs[1],
			F::from_canonical_u64((a_val >> 10) as u64),
			"SHR(10) mismatch",
		);

		data.verify(proof)?;
		Ok(())
	}

	#[test]
	fn test_rotr_u32_wrong_output() {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);

		let a = builder.constant_u32(0xDEADBEEF);
		let r = builder.rotr_u32(a, 7, range_lut);

		let wrong = builder.constant_u32(0x00000000);
		builder.connect(r.0, wrong.0);

		let data = builder.build::<C>();
		assert!(data.prove(PartialWitness::new()).is_err());
	}

	#[test]
	fn test_shr_u32_wrong_output() {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);

		let a = builder.constant_u32(0xDEADBEEF);
		let s = builder.shr_u32(a, 3, range_lut);

		let wrong = builder.constant_u32(0x00000000);
		builder.connect(s.0, wrong.0);

		let data = builder.build::<C>();
		assert!(data.prove(PartialWitness::new()).is_err());
	}
}
