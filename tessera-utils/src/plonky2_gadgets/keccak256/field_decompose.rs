/// Decomposes a field element target into `[hi, lo]` u32 targets (big-endian).
///
/// Constrains `hi * 2^32 + lo == value` with both halves range-checked.
///
/// **Field restriction:** this canonicality check is specific to the
/// Goldilocks prime `p = 2^64 - 2^32 + 1`.
///
/// **Canonicality:** for Goldilocks (`p = 2^64 - 2^32 + 1`), the field
/// equation `hi * 2^32 + lo ≡ value (mod p)` has two u32-pair solutions
/// when `value < 2^32 - 1`: the canonical `(0, value)` and the non-canonical
/// `(0xFFFFFFFF, value + 1)`.  An additional is-zero gadget on
/// `0xFFFFFFFF - hi` enforces `hi = 0xFFFFFFFF → lo = 0`, ruling out
/// the non-canonical encoding while still allowing `p - 1 = (0xFFFFFFFF, 0)`.
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

use crate::plonky2_gadgets::u32::{CircuitBuilderU32, U32Target};

pub fn decompose_field_to_u32_pair<F: RichField + Extendable<D>, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
	value: Target,
	range_lut: usize,
) -> [U32Target; 2] {
	let lo = builder.add_virtual_u32_target();
	let hi = builder.add_virtual_u32_target();

	builder.add_simple_generator(FieldDecompositionGenerator {
		input: value,
		lo: lo.0,
		hi: hi.0,
	});

	// Range-check both halves
	builder.decompose_u32_to_bytes(lo, range_lut);
	builder.decompose_u32_to_bytes(hi, range_lut);

	// Constrain: hi * 2^32 + lo == value
	let c232 = F::from_canonical_u64(1u64 << 32);
	let recomposed = builder.mul_const_add(c232, hi.0, lo.0);
	builder.connect(recomposed, value);

	// --- Canonicality: enforce hi * 2^32 + lo < p (Goldilocks) ---
	// Non-canonical iff hi = 0xFFFFFFFF and lo >= 1.
	// Use is-zero gadget on diff = (0xFFFFFFFF - hi) to detect hi = max,
	// then constrain hi_is_max * lo = 0.
	let max_hi = builder.constant(F::from_canonical_u64(0xFFFFFFFF));
	let diff = builder.sub(max_hi, hi.0);

	let hi_is_max = builder.add_virtual_target();
	let diff_inv = builder.add_virtual_target();

	builder.add_simple_generator(CanonicalCheckGenerator {
		diff,
		hi_is_max,
		diff_inv,
	});

	// is-zero constraints: hi_is_max = 1 iff diff = 0
	let prod = builder.mul(hi_is_max, diff);
	let zero = builder.zero();
	builder.connect(prod, zero);

	let diff_times_inv = builder.mul(diff, diff_inv);
	let check = builder.add(diff_times_inv, hi_is_max);
	let one = builder.one();
	builder.connect(check, one);

	// Canonical: if hi = 0xFFFFFFFF, then lo must be 0
	let fail = builder.mul(hi_is_max, lo.0);
	builder.connect(fail, zero);

	[hi, lo]
}

/// Witness generator that splits a field element into high and low u32 halves.
#[derive(Debug, Clone, Default)]
pub struct FieldDecompositionGenerator {
	input: Target,
	lo: Target,
	hi: Target,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
	for FieldDecompositionGenerator
{
	fn id(&self) -> String {
		"FieldDecompositionGenerator".to_string()
	}

	fn dependencies(&self) -> Vec<Target> {
		vec![self.input]
	}

	fn run_once(
		&self,
		witness: &PartitionWitness<F>,
		out_buffer: &mut GeneratedValues<F>,
	) -> anyhow::Result<()> {
		let value = witness.get_target(self.input).to_canonical_u64();
		out_buffer.set_target(self.lo, F::from_canonical_u64(value & 0xFFFFFFFF))?;
		out_buffer.set_target(self.hi, F::from_canonical_u64(value >> 32))?;
		Ok(())
	}

	fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
		dst.write_target(self.input)?;
		dst.write_target(self.lo)?;
		dst.write_target(self.hi)?;
		Ok(())
	}

	fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
		let input = src.read_target()?;
		let lo = src.read_target()?;
		let hi = src.read_target()?;
		Ok(Self {
			input,
			lo,
			hi,
		})
	}
}

/// Witness generator for the is-zero gadget used in canonical decomposition.
///
/// Given `diff`, produces `hi_is_max = (diff == 0) ? 1 : 0` and
/// `diff_inv = (diff != 0) ? diff⁻¹ : 0`.
#[derive(Debug, Clone, Default)]
pub struct CanonicalCheckGenerator {
	diff: Target,
	hi_is_max: Target,
	diff_inv: Target,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
	for CanonicalCheckGenerator
{
	fn id(&self) -> String {
		"CanonicalCheckGenerator".to_string()
	}

	fn dependencies(&self) -> Vec<Target> {
		vec![self.diff]
	}

	fn run_once(
		&self,
		witness: &PartitionWitness<F>,
		out_buffer: &mut GeneratedValues<F>,
	) -> anyhow::Result<()> {
		let diff_val = witness.get_target(self.diff);
		if diff_val == F::ZERO {
			out_buffer.set_target(self.hi_is_max, F::ONE)?;
			out_buffer.set_target(self.diff_inv, F::ZERO)?;
		} else {
			out_buffer.set_target(self.hi_is_max, F::ZERO)?;
			out_buffer.set_target(self.diff_inv, diff_val.inverse())?;
		}
		Ok(())
	}

	fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
		dst.write_target(self.diff)?;
		dst.write_target(self.hi_is_max)?;
		dst.write_target(self.diff_inv)?;
		Ok(())
	}

	fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
		let diff = src.read_target()?;
		let hi_is_max = src.read_target()?;
		let diff_inv = src.read_target()?;
		Ok(Self {
			diff,
			hi_is_max,
			diff_inv,
		})
	}
}
