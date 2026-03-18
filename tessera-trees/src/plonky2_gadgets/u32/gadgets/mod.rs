//! U32 gadgets for Plonky2 circuits using lookup tables.
//!
//! Provides a [`U32Target`] type and operations (XOR, AND, rotation, etc.)
//! implemented via lookup tables for efficient constraint generation.
//!
//! # Architecture
//!
//! Bitwise operations decompose u32 values into chunks of configurable
//! bit-width (`chunk_bits` ∈ {1, 2, 4, 8}) and use lookup tables to
//! compute the operation per chunk pair:
//!
//! - **Range check table** (`2^chunk_bits` entries): identity map constrains a target to be a valid
//!   chunk.
//! - **XOR table** (`2^(2*chunk_bits)` entries): maps `(a << chunk_bits | b) -> (a ^ b)`
//! - **AND table** (`2^(2*chunk_bits)` entries): maps `(a << chunk_bits | b) -> (a & b)`
//!
//! Use [`BitwiseLuts`] to bundle these tables with a chosen `chunk_bits`.
//!
//! # Range checking
//!
//! Not all gadgets range-check their inputs.  Operations that decompose
//! their operands into bytes (XOR, AND, Ch, Maj) implicitly range-check
//! them.  Operations that work on the value algebraically (NOT, wrapping
//! add, ROTR, SHR, Sigma functions) **assume their inputs are already
//! range-checked** — the caller must ensure this, typically via a prior
//! call to [`CircuitBuilderU32::decompose_u32_to_bytes`] or by using an
//! output from a gadget that performs its own decomposition.
//!
//! Each gadget's doc comment specifies its range-checking behavior for
//! both inputs and output.
//!
//! # Modules
//!
//! - [`bitwise`] — XOR, AND, NOT
//! - [`arithmetic`] — wrapping addition, CRT-based assertion
//! - [`rotation`] — right rotation (ROTR), logical right shift (SHR)

pub mod arithmetic;
pub mod bitwise;
pub mod rotation;

use std::sync::Arc;

pub use arithmetic::*;
pub use bitwise::*;
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
pub use rotation::*;

/// A target representing a `u32` value in a Plonky2 circuit.
///
/// The inner [`Target`] holds a Goldilocks field element in `[0, 2^32)`.
/// Range validity is enforced by byte decomposition with lookup-based
/// range checks (see [`CircuitBuilderU32::decompose_u32_to_bytes`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct U32Target(pub Target);

// ---------------------------------------------------------------------------
// Lookup table constructors
// ---------------------------------------------------------------------------

/// Registers a range-check lookup table for `chunk_bits`-wide chunks.
///
/// Identity map `[0, 2^chunk_bits - 1] -> [0, 2^chunk_bits - 1]`.
/// A lookup against this table constrains a target to `[0, 2^chunk_bits)`.
///
/// `chunk_bits` must be one of `{1, 2, 4, 8}`.
pub fn add_chunk_range_check_lookup_table<F: RichField + Extendable<D>, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
	chunk_bits: usize,
) -> usize {
	assert!(
		matches!(chunk_bits, 1 | 2 | 4 | 8),
		"chunk_bits must be 1, 2, 4, or 8"
	);
	let max = (1u16 << chunk_bits) - 1;
	let table: Vec<(u16, u16)> = (0u16..=max).map(|i| (i, i)).collect();
	builder.add_lookup_table_from_pairs(Arc::new(table))
}

/// Registers a XOR lookup table for `chunk_bits`-wide chunk pairs.
///
/// Maps every packed pair `(a << chunk_bits | b)` to `a ^ b`
/// (`2^(2*chunk_bits)` entries).
///
/// `chunk_bits` must be one of `{1, 2, 4, 8}`.
pub fn add_chunk_xor_lookup_table<F: RichField + Extendable<D>, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
	chunk_bits: usize,
) -> usize {
	assert!(
		matches!(chunk_bits, 1 | 2 | 4 | 8),
		"chunk_bits must be 1, 2, 4, or 8"
	);
	let max = (1u16 << chunk_bits) - 1;
	let table: Vec<(u16, u16)> = (0u16..=max)
		.flat_map(|a| (0u16..=max).map(move |b| ((a << chunk_bits) | b, a ^ b)))
		.collect();
	builder.add_lookup_table_from_pairs(Arc::new(table))
}

/// Registers an AND lookup table for `chunk_bits`-wide chunk pairs.
///
/// Maps every packed pair `(a << chunk_bits | b)` to `a & b`
/// (`2^(2*chunk_bits)` entries).
///
/// `chunk_bits` must be one of `{1, 2, 4, 8}`.
pub fn add_chunk_and_lookup_table<F: RichField + Extendable<D>, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
	chunk_bits: usize,
) -> usize {
	assert!(
		matches!(chunk_bits, 1 | 2 | 4 | 8),
		"chunk_bits must be 1, 2, 4, or 8"
	);
	let max = (1u16 << chunk_bits) - 1;
	let table: Vec<(u16, u16)> = (0u16..=max)
		.flat_map(|a| (0u16..=max).map(move |b| ((a << chunk_bits) | b, a & b)))
		.collect();
	builder.add_lookup_table_from_pairs(Arc::new(table))
}

/// Convenience alias: 8-bit byte range-check table (256 entries).
pub fn add_u8_range_check_lookup_table<F: RichField + Extendable<D>, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
) -> usize {
	add_chunk_range_check_lookup_table(builder, 8)
}

/// Convenience alias: 8-bit XOR table (65 536 entries).
pub fn add_xor_lookup_table<F: RichField + Extendable<D>, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
) -> usize {
	add_chunk_xor_lookup_table(builder, 8)
}

/// Convenience alias: 8-bit AND table (65 536 entries).
pub fn add_and_lookup_table<F: RichField + Extendable<D>, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
) -> usize {
	add_chunk_and_lookup_table(builder, 8)
}

// ---------------------------------------------------------------------------
// BitwiseLuts — bundled lookup-table indices for parameterized chunk width
// ---------------------------------------------------------------------------

/// Bundles the lookup-table indices needed by bitwise U32 operations,
/// parameterized by the chunk bit-width.
///
/// The `chunk_bits` field controls how u32 values are decomposed for
/// XOR / AND lookups:
///
/// | `chunk_bits` | range LUT | XOR/AND LUT | chunks per u32 |
/// |:---:|---:|---:|---:|
/// | 1 | 2 | 4 | 32 |
/// | 2 | 4 | 16 | 16 |
/// | 4 | 16 | 256 | 8 |
/// | 8 | 256 | 65 536 | 4 |
///
/// Rotation, shift, and wrapping-add operations always use the 8-bit
/// `byte_range_lut`, regardless of `chunk_bits`.
#[derive(Clone, Copy, Debug)]
pub struct BitwiseLuts {
	/// Number of bits per chunk (1, 2, 4, or 8).
	pub chunk_bits: usize,
	/// Range-check table for chunks of `chunk_bits` bits.
	pub chunk_range_lut: usize,
	/// XOR table for `chunk_bits`-wide chunk pairs.
	pub xor_lut: usize,
	/// AND table for `chunk_bits`-wide chunk pairs.
	pub and_lut: usize,
	/// 8-bit byte range-check table (always registered; used by
	/// rotation, shift, and wrapping-add).
	pub byte_range_lut: usize,
}

impl BitwiseLuts {
	/// Registers all lookup tables and returns their bundled indices.
	///
	/// `chunk_bits` must be one of `{1, 2, 4, 8}`.
	/// When `chunk_bits == 8`, `chunk_range_lut` and `byte_range_lut`
	/// share the same table (no duplication).
	pub fn new<F: RichField + Extendable<D>, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
		chunk_bits: usize,
	) -> Self {
		let byte_range_lut = add_u8_range_check_lookup_table(builder);
		let chunk_range_lut = if chunk_bits == 8 {
			byte_range_lut
		} else {
			add_chunk_range_check_lookup_table(builder, chunk_bits)
		};
		Self {
			chunk_bits,
			chunk_range_lut,
			xor_lut: add_chunk_xor_lookup_table(builder, chunk_bits),
			and_lut: add_chunk_and_lookup_table(builder, chunk_bits),
			byte_range_lut,
		}
	}
}

// ---------------------------------------------------------------------------
// Core extension trait — decomposition and target helpers
// ---------------------------------------------------------------------------

/// Core extension trait for [`CircuitBuilder`]: target allocation and
/// byte/limb decomposition with lookup-based range checks.
pub trait CircuitBuilderU32<F: RichField + Extendable<D>, const D: usize> {
	/// Allocates a virtual [`U32Target`].
	///
	/// The caller must set its witness value via
	/// `pw.set_target(target.0, F::from_canonical_u32(val))`.
	fn add_virtual_u32_target(&mut self) -> U32Target;

	/// Creates a constant [`U32Target`].
	fn constant_u32(&mut self, value: u32) -> U32Target;

	/// Decomposes a [`U32Target`] into 4 little-endian byte targets.
	///
	/// Returns `[b0, b1, b2, b3]` with
	/// `value = b0 + b1*256 + b2*65536 + b3*16777216`.
	///
	/// Each byte is range-checked via the lookup table at `range_lut`
	/// (see [`add_u8_range_check_lookup_table`]).
	///
	/// **Range checking:** this is the primary mechanism for constraining
	/// a [`U32Target`] to `[0, 2^32)`.  The recomposition constraint
	/// together with the 4 byte-range lookups proves the value fits in
	/// 32 bits.  Call this on any target that needs to be proven u32.
	fn decompose_u32_to_bytes(&mut self, value: U32Target, range_lut: usize) -> [Target; 4];

	/// Decomposes a [`U32Target`] into two 16-bit little-endian limbs `[lo, hi]`.
	///
	/// Returns `[lo, hi]` with `value = lo + hi * 2^16`, where both
	/// limbs are range-checked via the provided lookup table.
	///
	/// **Range checking:** each limb is decomposed into 2 bytes
	/// (4 byte-range lookups total), proving the value fits in 32 bits.
	fn decompose_u32_to_u16_limbs(&mut self, value: U32Target, range_lut: usize) -> [Target; 2];

	/// Decomposes a [`U32Target`] into `32 / chunk_bits` little-endian chunks.
	///
	/// Each chunk is range-checked via `chunk_range_lut` and the
	/// Horner recomposition constraint proves the value fits in 32 bits.
	///
	/// `chunk_bits` must be one of `{1, 2, 4, 8}`.
	fn decompose_u32_to_chunks(
		&mut self,
		value: U32Target,
		chunk_range_lut: usize,
		chunk_bits: usize,
	) -> Vec<Target>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderU32<F, D>
	for CircuitBuilder<F, D>
{
	fn add_virtual_u32_target(&mut self) -> U32Target {
		U32Target(self.add_virtual_target())
	}

	fn constant_u32(&mut self, value: u32) -> U32Target {
		U32Target(self.constant(F::from_canonical_u32(value)))
	}

	fn decompose_u32_to_bytes(&mut self, value: U32Target, range_lut: usize) -> [Target; 4] {
		let bytes: [Target; 4] = core::array::from_fn(|_| self.add_virtual_target());

		self.add_simple_generator(ByteDecompositionGenerator {
			input: value.0,
			bytes,
		});

		for &byte in &bytes {
			let _range_checked = self.add_lookup_from_index(byte, range_lut);
		}

		// Constraint: ((b3*256 + b2)*256 + b1)*256 + b0 == value
		let c256 = F::from_canonical_u64(256);
		let mut sum = bytes[3];
		sum = self.mul_const_add(c256, sum, bytes[2]);
		sum = self.mul_const_add(c256, sum, bytes[1]);
		sum = self.mul_const_add(c256, sum, bytes[0]);
		self.connect(sum, value.0);

		bytes
	}

	fn decompose_u32_to_u16_limbs(&mut self, value: U32Target, range_lut: usize) -> [Target; 2] {
		let limbs: [Target; 2] = core::array::from_fn(|_| self.add_virtual_target());

		self.add_simple_generator(U16LimbDecompositionGenerator {
			input: value.0,
			limbs,
		});

		// Range check each limb: decompose into 2 bytes each
		for &limb in &limbs {
			let bytes: [Target; 2] = core::array::from_fn(|_| self.add_virtual_target());
			self.add_simple_generator(LimbByteDecompositionGenerator {
				input: limb,
				bytes,
			});

			for &byte in &bytes {
				let _range_checked = self.add_lookup_from_index(byte, range_lut);
			}

			let c256 = F::from_canonical_u64(256);
			let recomposed = self.mul_const_add(c256, bytes[1], bytes[0]);
			self.connect(recomposed, limb);
		}

		let c216 = F::from_canonical_u64(1u64 << 16);
		let recomposed = self.mul_const_add(c216, limbs[1], limbs[0]);
		self.connect(recomposed, value.0);

		limbs
	}

	fn decompose_u32_to_chunks(
		&mut self,
		value: U32Target,
		chunk_range_lut: usize,
		chunk_bits: usize,
	) -> Vec<Target> {
		assert!(
			matches!(chunk_bits, 1 | 2 | 4 | 8),
			"chunk_bits must be 1, 2, 4, or 8"
		);
		let num_chunks = 32 / chunk_bits;
		let chunks: Vec<Target> = (0..num_chunks).map(|_| self.add_virtual_target()).collect();

		self.add_simple_generator(ChunkDecompositionGenerator {
			input: value.0,
			chunks: chunks.clone(),
			chunk_bits,
		});

		for &chunk in &chunks {
			let _range_checked = self.add_lookup_from_index(chunk, chunk_range_lut);
		}

		// Horner recomposition: c[n-1]*base^(n-1) + ... + c[1]*base + c[0] == value
		let c_base = F::from_canonical_u64(1u64 << chunk_bits);
		let mut sum = chunks[num_chunks - 1];
		for i in (0..num_chunks - 1).rev() {
			sum = self.mul_const_add(c_base, sum, chunks[i]);
		}
		self.connect(sum, value.0);

		chunks
	}
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/// Witness generator that decomposes a `u32` field element into 4 LE bytes.
#[derive(Debug, Clone, Default)]
pub(crate) struct ByteDecompositionGenerator {
	input: Target,
	bytes: [Target; 4],
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
	for ByteDecompositionGenerator
{
	fn id(&self) -> String {
		"ByteDecompositionGenerator".to_string()
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
		for i in 0..4 {
			let byte_val = (value >> (8 * i)) & 0xFF;
			out_buffer.set_target(self.bytes[i], F::from_canonical_u64(byte_val))?;
		}
		Ok(())
	}

	fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
		dst.write_target(self.input)?;
		for &byte in &self.bytes {
			dst.write_target(byte)?;
		}
		Ok(())
	}

	fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
		let input = src.read_target()?;
		let bytes = [
			src.read_target()?,
			src.read_target()?,
			src.read_target()?,
			src.read_target()?,
		];
		Ok(Self {
			input,
			bytes,
		})
	}
}

/// Witness generator that decomposes a `u32` field element into LE chunks
/// of `chunk_bits` bits each.
#[derive(Debug, Clone, Default)]
pub(crate) struct ChunkDecompositionGenerator {
	input: Target,
	chunks: Vec<Target>,
	chunk_bits: usize,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
	for ChunkDecompositionGenerator
{
	fn id(&self) -> String {
		"ChunkDecompositionGenerator".to_string()
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
		let mask = (1u64 << self.chunk_bits) - 1;
		for (i, &chunk) in self.chunks.iter().enumerate() {
			let chunk_val = (value >> (self.chunk_bits * i)) & mask;
			out_buffer.set_target(chunk, F::from_canonical_u64(chunk_val))?;
		}
		Ok(())
	}

	fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
		dst.write_target(self.input)?;
		dst.write_usize(self.chunk_bits)?;
		for &chunk in &self.chunks {
			dst.write_target(chunk)?;
		}
		Ok(())
	}

	fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
		let input = src.read_target()?;
		let chunk_bits = src.read_usize()?;
		let num_chunks = 32 / chunk_bits;
		let mut chunks = Vec::with_capacity(num_chunks);
		for _ in 0..num_chunks {
			chunks.push(src.read_target()?);
		}
		Ok(Self {
			input,
			chunks,
			chunk_bits,
		})
	}
}

/// Witness generator that decomposes a `u32` field element into 2 LE 16-bit limbs.
#[derive(Debug, Clone, Default)]
pub(crate) struct U16LimbDecompositionGenerator {
	input: Target,
	limbs: [Target; 2],
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
	for U16LimbDecompositionGenerator
{
	fn id(&self) -> String {
		"U16LimbDecompositionGenerator".to_string()
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
		out_buffer.set_target(self.limbs[0], F::from_canonical_u64(value & 0xFFFF))?;
		out_buffer.set_target(self.limbs[1], F::from_canonical_u64((value >> 16) & 0xFFFF))?;
		Ok(())
	}

	fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
		dst.write_target(self.input)?;
		for &limb in &self.limbs {
			dst.write_target(limb)?;
		}
		Ok(())
	}

	fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
		let input = src.read_target()?;
		let limbs = [src.read_target()?, src.read_target()?];
		Ok(Self {
			input,
			limbs,
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

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = GoldilocksField;

	#[test]
	fn test_decompose_u32_to_bytes_wrong_value() {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);

		let a = builder.constant_u32(0xDEADBEEF);
		let _bytes = builder.decompose_u32_to_bytes(a, range_lut);

		// Connect value to a wrong constant — the byte recomposition
		// constraint will be unsatisfiable
		let wrong = builder.constant_u32(0x00000000);
		builder.connect(a.0, wrong.0);

		let data = builder.build::<C>();
		assert!(data.prove(PartialWitness::new()).is_err());
	}

	#[test]
	fn test_decompose_u32_out_of_range() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);

		let a = builder.add_virtual_u32_target();
		builder.decompose_u32_to_bytes(a, range_lut);

		let data = builder.build::<C>();

		// Set witness to 2^32 — does not fit in 4 bytes
		let mut pw = PartialWitness::new();
		pw.set_target(a.0, F::from_canonical_u64(0x1_00000000))?;

		assert!(data.prove(pw).is_err());
		Ok(())
	}

	#[test]
	fn test_decompose_u32_large_field_element() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let range_lut = add_u8_range_check_lookup_table(&mut builder);

		let a = builder.add_virtual_u32_target();
		builder.decompose_u32_to_bytes(a, range_lut);

		let data = builder.build::<C>();

		// Set witness to a large field element (near prime)
		let mut pw = PartialWitness::new();
		pw.set_target(a.0, F::from_canonical_u64(0xDEADBEEF_CAFEBABE))?;

		assert!(data.prove(pw).is_err());
		Ok(())
	}
}

/// Witness generator that decomposes a 16-bit limb into 2 LE bytes.
#[derive(Debug, Clone, Default)]
pub(crate) struct LimbByteDecompositionGenerator {
	input: Target,
	bytes: [Target; 2],
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
	for LimbByteDecompositionGenerator
{
	fn id(&self) -> String {
		"LimbByteDecompositionGenerator".to_string()
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
		out_buffer.set_target(self.bytes[0], F::from_canonical_u64(value & 0xFF))?;
		out_buffer.set_target(self.bytes[1], F::from_canonical_u64((value >> 8) & 0xFF))?;
		Ok(())
	}

	fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
		dst.write_target(self.input)?;
		for &byte in &self.bytes {
			dst.write_target(byte)?;
		}
		Ok(())
	}

	fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
		let input = src.read_target()?;
		let bytes = [src.read_target()?, src.read_target()?];
		Ok(Self {
			input,
			bytes,
		})
	}
}
