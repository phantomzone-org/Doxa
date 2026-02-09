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

use super::{Sha256Luts, Sha256Target};
use crate::plonky2_gadgets::u32::{
	CircuitBuilderU32, CircuitBuilderU32Arithmetic, CircuitBuilderU32Sha256, U32Target,
};

/// Extension trait: full SHA-256 hash on [`CircuitBuilder`].
pub trait CircuitBuilderSha256<F: RichField + Extendable<D>, const D: usize> {
	/// Expands 16 message words into the 64-word schedule W[0..63].
	///
	/// W[0..16] = input, W[16..64] computed per FIPS 180-4:
	/// `W[t] = σ₁(W[t-2]) + W[t-7] + σ₀(W[t-15]) + W[t-16]`
	///
	/// **Range checking:** all 16 input words **must** be range-checked
	/// (soundness requirement — `wrapping_add_u32` relies on inputs
	/// fitting in 32 bits).  All 64 output words are range-checked.
	fn sha256_message_schedule(
		&mut self,
		input: [U32Target; 16],
		luts: &Sha256Luts,
	) -> [U32Target; 64];

	/// Runs 64 rounds of SHA-256 compression.
	///
	/// Returns the 8 updated working variables (before the final
	/// addition with the incoming state).
	///
	/// **Range checking:** state and all W words **must** be range-checked
	/// (soundness requirement).  Output words are range-checked.
	fn sha256_compression(
		&mut self,
		state: Sha256Target,
		w: &[U32Target; 64],
		luts: &Sha256Luts,
	) -> Sha256Target;

	/// Processes one 512-bit block with an explicit initial state.
	///
	/// Computes message schedule, runs compression, and adds the
	/// compressed state back to the input state (Davies-Meyer).
	///
	/// **Range checking:** state and block words **must** be range-checked
	/// (soundness requirement).  Output words are range-checked.
	fn sha256_block_with_state(
		&mut self,
		state: Sha256Target,
		block: [U32Target; 16],
		luts: &Sha256Luts,
	) -> Sha256Target;

	/// Hashes a single 512-bit block with the standard IV.
	///
	/// **Range checking:** all 16 input words **must** be range-checked
	/// (soundness requirement).  Output words are range-checked.
	fn sha256_single_block(&mut self, input: [U32Target; 16], luts: &Sha256Luts) -> Sha256Target;

	/// Hashes multiple 512-bit blocks with the standard IV, chaining
	/// state across blocks.
	///
	/// The caller is responsible for SHA-256 padding.
	///
	/// **Range checking:** all input words **must** be range-checked
	/// (soundness requirement).  Output words are range-checked.
	fn sha256(&mut self, blocks: &[[U32Target; 16]], luts: &Sha256Luts) -> Sha256Target;

	/// Hashes a slice of field element targets using SHA-256.
	///
	/// Each field element is encoded as its canonical big-endian 8-byte
	/// (2-word) representation. SHA-256 padding is applied automatically.
	///
	/// **Field restriction:** this method enforces canonicality assuming the
	/// Goldilocks prime `p = 2^64 - 2^32 + 1`. It is not generic over other
	/// fields.
	///
	/// **Range checking:** all intermediate u32 targets from field
	/// decomposition are range-checked. Output words are range-checked.
	fn sha256_hash_field_elements(&mut self, input: &[Target], luts: &Sha256Luts) -> Sha256Target;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderSha256<F, D>
	for CircuitBuilder<F, D>
{
	fn sha256_message_schedule(
		&mut self,
		input: [U32Target; 16],
		luts: &Sha256Luts,
	) -> [U32Target; 64] {
		let mut w: Vec<U32Target> = input.to_vec();
		w.reserve(48);

		for t in 16..64 {
			let s1 = self.small_sigma1_u32(w[t - 2], luts.xor_lut, luts.range_lut);
			let s0 = self.small_sigma0_u32(w[t - 15], luts.xor_lut, luts.range_lut);

			let tmp = self.wrapping_add_u32(s1, w[t - 7], luts.range_lut);
			let tmp = self.wrapping_add_u32(tmp, s0, luts.range_lut);
			let wt = self.wrapping_add_u32(tmp, w[t - 16], luts.range_lut);

			w.push(wt);
		}

		w.try_into().unwrap()
	}

	fn sha256_compression(
		&mut self,
		state: Sha256Target,
		w: &[U32Target; 64],
		luts: &Sha256Luts,
	) -> Sha256Target {
		let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;

		for t in 0..64 {
			let k_t = self.constant_u32(super::constants::K[t]);

			// T1 = h + Σ₁(e) + Ch(e,f,g) + K[t] + W[t]
			let sigma1_e = self.big_sigma1_u32(e, luts.xor_lut, luts.range_lut);
			let ch_efg = self.ch_u32(e, f, g, luts.xor_lut, luts.and_lut, luts.range_lut);

			let t1 = self.wrapping_add_u32(h, sigma1_e, luts.range_lut);
			let t1 = self.wrapping_add_u32(t1, ch_efg, luts.range_lut);
			let t1 = self.wrapping_add_u32(t1, k_t, luts.range_lut);
			let t1 = self.wrapping_add_u32(t1, w[t], luts.range_lut);

			// T2 = Σ₀(a) + Maj(a,b,c)
			let sigma0_a = self.big_sigma0_u32(a, luts.xor_lut, luts.range_lut);
			let maj_abc = self.maj_u32(a, b, c, luts.xor_lut, luts.and_lut, luts.range_lut);
			let t2 = self.wrapping_add_u32(sigma0_a, maj_abc, luts.range_lut);

			// Update working variables
			h = g;
			g = f;
			f = e;
			e = self.wrapping_add_u32(d, t1, luts.range_lut);
			d = c;
			c = b;
			b = a;
			a = self.wrapping_add_u32(t1, t2, luts.range_lut);
		}

		[a, b, c, d, e, f, g, h]
	}

	fn sha256_block_with_state(
		&mut self,
		state: Sha256Target,
		block: [U32Target; 16],
		luts: &Sha256Luts,
	) -> Sha256Target {
		let w = self.sha256_message_schedule(block, luts);
		let compressed = self.sha256_compression(state, &w, luts);

		// Final addition: H[i] = H[i] + compressed[i]
		core::array::from_fn(|i| self.wrapping_add_u32(state[i], compressed[i], luts.range_lut))
	}

	fn sha256_single_block(&mut self, input: [U32Target; 16], luts: &Sha256Luts) -> Sha256Target {
		let init: Sha256Target =
			core::array::from_fn(|i| self.constant_u32(super::constants::H[i]));

		self.sha256_block_with_state(init, input, luts)
	}

	fn sha256(&mut self, blocks: &[[U32Target; 16]], luts: &Sha256Luts) -> Sha256Target {
		assert!(!blocks.is_empty(), "sha256 requires at least one block");

		let init: Sha256Target =
			core::array::from_fn(|i| self.constant_u32(super::constants::H[i]));

		let mut state = init;
		for block in blocks {
			state = self.sha256_block_with_state(state, *block, luts);
		}

		state
	}

	fn sha256_hash_field_elements(&mut self, input: &[Target], luts: &Sha256Luts) -> Sha256Target {
		let n = input.len();
		let msg_words = 2 * n;

		// Need room for: msg_words + 1 (0x80 pad) + 2 (length) words minimum
		let num_blocks = (msg_words + 3 + 15) / 16;
		let total_words = num_blocks * 16;

		let zero = self.constant_u32(0);
		let mut words = vec![zero; total_words];

		// Decompose each field element into [hi, lo] (big-endian word order)
		for (i, &elem) in input.iter().enumerate() {
			let [hi, lo] = decompose_field_to_u32_pair(self, elem, luts.range_lut);
			words[2 * i] = hi;
			words[2 * i + 1] = lo;
		}

		// SHA-256 padding: 0x80000000 after message
		words[msg_words] = self.constant_u32(0x80000000);

		// 64-bit big-endian bit length at end
		let bit_len: u64 = (n as u64) * 64;
		words[total_words - 2] = self.constant_u32((bit_len >> 32) as u32);
		words[total_words - 1] = self.constant_u32(bit_len as u32);

		// Build blocks and hash
		let blocks: Vec<[U32Target; 16]> = words
			.chunks_exact(16)
			.map(|chunk| chunk.try_into().unwrap())
			.collect();

		self.sha256(&blocks, luts)
	}
}

// ---------------------------------------------------------------------------
// Field element decomposition
// ---------------------------------------------------------------------------

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
fn decompose_field_to_u32_pair<F: RichField + Extendable<D>, const D: usize>(
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
#[derive(Debug, Clone)]
struct FieldDecompositionGenerator {
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
#[derive(Debug, Clone)]
struct CanonicalCheckGenerator {
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

// ---------------------------------------------------------------------------
// Native helper
// ---------------------------------------------------------------------------

/// Computes SHA-256 of field elements outside the circuit.
///
/// Each element is encoded as its canonical big-endian 8-byte representation.
/// Returns the 8-word digest in big-endian word order.
pub fn sha256_field_elements_native<F: RichField>(input: &[F]) -> [u32; 8] {
	use sha2::{Digest, Sha256};
	let mut hasher = Sha256::new();
	for &elem in input {
		hasher.update(elem.to_canonical_u64().to_be_bytes());
	}
	let result = hasher.finalize();
	core::array::from_fn(|i| u32::from_be_bytes(result[4 * i..4 * i + 4].try_into().unwrap()))
}

#[cfg(test)]
mod tests {
	use std::time::Instant;

	use anyhow::Result;
	use plonky2::{
		field::{goldilocks_field::GoldilocksField, types::Field},
		iop::witness::{PartialWitness, WitnessWrite},
		plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
	};

	use super::*;
	use crate::plonky2_gadgets::u32::CircuitBuilderU32;

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = GoldilocksField;

	#[test]
	fn test_sha256_constants() {
		assert_eq!(super::super::constants::K[0], 0x428a2f98);
		assert_eq!(super::super::constants::K[63], 0xc67178f2);
		assert_eq!(super::super::constants::K.len(), 64);

		assert_eq!(super::super::constants::H[0], 0x6a09e667);
		assert_eq!(super::super::constants::H[7], 0x5be0cd19);
		assert_eq!(super::super::constants::H.len(), 8);
	}

	/// SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	#[test]
	fn test_sha256_empty_string() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let luts = Sha256Luts::new(&mut builder);

		// Padded empty message: 0x80000000 followed by 15 zeros
		// (bit length = 0, so last two words are also zero)
		let mut input = [builder.constant_u32(0); 16];
		input[0] = builder.constant_u32(0x80000000);

		let hash = builder.sha256_single_block(input, &luts);

		for i in 0..8 {
			builder.register_public_input(hash[i].0);
		}

		let data = builder.build::<C>();
		let pw = PartialWitness::new();
		let proof = data.prove(pw)?;

		let expected: [u32; 8] = [
			0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924, 0x27ae41e4, 0x649b934c, 0xa495991b,
			0x7852b855,
		];

		for (i, &exp) in expected.iter().enumerate() {
			assert_eq!(
				proof.public_inputs[i],
				F::from_canonical_u64(exp as u64),
				"SHA256('') word {i} mismatch: expected {exp:#010X}",
			);
		}

		data.verify(proof)?;
		Ok(())
	}

	/// SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
	#[test]
	fn test_sha256_abc() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let luts = Sha256Luts::new(&mut builder);

		let mut input = [builder.constant_u32(0); 16];
		input[0] = builder.constant_u32(0x61626380); // "abc" + 0x80
		input[15] = builder.constant_u32(0x00000018); // 24 bits

		let hash = builder.sha256_single_block(input, &luts);

		for i in 0..8 {
			builder.register_public_input(hash[i].0);
		}

		let data = builder.build::<C>();
		let pw = PartialWitness::new();
		let proof = data.prove(pw)?;

		let expected: [u32; 8] = [
			0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61,
			0xf20015ad,
		];

		for (i, &exp) in expected.iter().enumerate() {
			assert_eq!(
				proof.public_inputs[i],
				F::from_canonical_u64(exp as u64),
				"SHA256('abc') word {i} mismatch: expected {exp:#010X}",
			);
		}

		data.verify(proof)?;
		Ok(())
	}

	/// SHA256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
	/// = 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
	#[test]
	fn test_sha256_two_blocks() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let luts = Sha256Luts::new(&mut builder);

		// Block 1: 56 bytes of message + padding bit
		let block1: [U32Target; 16] = [
			builder.constant_u32(0x61626364), // "abcd"
			builder.constant_u32(0x62636465), // "bcde"
			builder.constant_u32(0x63646566), // "cdef"
			builder.constant_u32(0x64656667), // "defg"
			builder.constant_u32(0x65666768), // "efgh"
			builder.constant_u32(0x66676869), // "fghi"
			builder.constant_u32(0x6768696a), // "ghij"
			builder.constant_u32(0x68696a6b), // "hijk"
			builder.constant_u32(0x696a6b6c), // "ijkl"
			builder.constant_u32(0x6a6b6c6d), // "jklm"
			builder.constant_u32(0x6b6c6d6e), // "klmn"
			builder.constant_u32(0x6c6d6e6f), // "lmno"
			builder.constant_u32(0x6d6e6f70), // "mnop"
			builder.constant_u32(0x6e6f7071), // "nopq"
			builder.constant_u32(0x80000000), // padding bit
			builder.constant_u32(0x00000000),
		];

		// Block 2: zeros + 64-bit big-endian length (448 bits = 0x1c0)
		let mut block2 = [builder.constant_u32(0); 16];
		block2[15] = builder.constant_u32(0x000001c0);

		let hash = builder.sha256(&[block1, block2], &luts);

		for i in 0..8 {
			builder.register_public_input(hash[i].0);
		}

		let data = builder.build::<C>();
		let pw = PartialWitness::new();
		let proof = data.prove(pw)?;

		let expected: [u32; 8] = [
			0x248d6a61, 0xd20638b8, 0xe5c02693, 0x0c3e6039, 0xa33ce459, 0x64ff2167, 0xf6ecedd4,
			0x19db06c1,
		];

		for (i, &exp) in expected.iter().enumerate() {
			assert_eq!(
				proof.public_inputs[i],
				F::from_canonical_u64(exp as u64),
				"SHA256(two-block) word {i} mismatch: expected {exp:#010X}",
			);
		}

		data.verify(proof)?;
		Ok(())
	}

	/// Test with witness inputs (non-constant message).
	#[test]
	fn test_sha256_with_witness_inputs() -> Result<()> {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let luts = Sha256Luts::new(&mut builder);

		let input: [U32Target; 16] = core::array::from_fn(|_| builder.add_virtual_u32_target());

		// Range-check witness inputs (caller responsibility)
		for &word in &input {
			builder.decompose_u32_to_bytes(word, luts.range_lut);
		}

		let hash = builder.sha256_single_block(input, &luts);

		for i in 0..8 {
			builder.register_public_input(hash[i].0);
		}

		let data = builder.build::<C>();

		// Set witness: padded "abc" message
		let mut pw = PartialWitness::new();
		let words: [u32; 16] = [0x61626380, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x18];
		for (i, &w) in words.iter().enumerate() {
			pw.set_target(input[i].0, F::from_canonical_u64(w as u64))?;
		}

		let proof = data.prove(pw)?;

		// Same expected output as test_sha256_abc
		let expected: [u32; 8] = [
			0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61,
			0xf20015ad,
		];

		for (i, &exp) in expected.iter().enumerate() {
			assert_eq!(proof.public_inputs[i], F::from_canonical_u64(exp as u64),);
		}

		data.verify(proof)?;
		Ok(())
	}

	/// Cross-validate against the `sha2` crate.
	#[test]
	fn test_sha256_cross_validate() -> Result<()> {
		use sha2::{Digest, Sha256};

		let msg = b"Hello, Plonky2!";
		let expected_bytes = Sha256::digest(msg);

		let expected: [u32; 8] = core::array::from_fn(|i| {
			u32::from_be_bytes(expected_bytes[4 * i..4 * i + 4].try_into().unwrap())
		});

		// Pad message manually: 15 bytes + 0x80 + 40 zeros + 8-byte length
		let mut padded = [0u8; 64];
		padded[..15].copy_from_slice(msg);
		padded[15] = 0x80;
		// Length in bits = 120 = 0x78
		padded[63] = 120;

		let words: [u32; 16] = core::array::from_fn(|i| {
			u32::from_be_bytes(padded[4 * i..4 * i + 4].try_into().unwrap())
		});

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let luts = Sha256Luts::new(&mut builder);

		let input: [U32Target; 16] = core::array::from_fn(|i| builder.constant_u32(words[i]));

		let hash = builder.sha256_single_block(input, &luts);
		for i in 0..8 {
			builder.register_public_input(hash[i].0);
		}

		let data = builder.build::<C>();
		let pw = PartialWitness::new();
		let proof = data.prove(pw)?;

		for (i, &exp) in expected.iter().enumerate() {
			assert_eq!(
				proof.public_inputs[i],
				F::from_canonical_u64(exp as u64),
				"SHA256 cross-validate word {i} mismatch: expected {exp:#010X}",
			);
		}

		data.verify(proof)?;
		Ok(())
	}

	/// Hash field elements with constant inputs, cross-validate against native helper.
	#[test]
	fn test_sha256_field_elements_constant() -> Result<()> {
		let values: Vec<F> = (1u64..=4).map(F::from_canonical_u64).collect();
		let expected = sha256_field_elements_native(&values);

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let luts = Sha256Luts::new(&mut builder);

		let targets: Vec<Target> = values.iter().map(|&v| builder.constant(v)).collect();

		let hash = builder.sha256_hash_field_elements(&targets, &luts);
		for i in 0..8 {
			builder.register_public_input(hash[i].0);
		}

		let data = builder.build::<C>();
		let proof = data.prove(PartialWitness::new())?;

		for (i, &exp) in expected.iter().enumerate() {
			assert_eq!(
				proof.public_inputs[i],
				F::from_canonical_u64(exp as u64),
				"SHA256 field elements word {i} mismatch: expected {exp:#010X}",
			);
		}

		data.verify(proof)?;
		Ok(())
	}

	/// Hash field elements with witness inputs, cross-validate against native helper.
	#[test]
	fn test_sha256_field_elements_witness() -> Result<()> {
		let mut values: Vec<F> = Vec::new();

		for _ in 0..1 {
			values.push(F::from_canonical_u64(0xDEADBEEF_CAFEBABE));
			values.push(F::from_canonical_u64(42));
			values.push(F::ZERO);
			values.push(F::NEG_ONE); // p - 1 (max Goldilocks value)
		}

		let expected = sha256_field_elements_native(&values);

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let luts = Sha256Luts::new(&mut builder);

		let targets: Vec<Target> = (0..values.len())
			.map(|_| builder.add_virtual_target())
			.collect();

		let hash = builder.sha256_hash_field_elements(&targets, &luts);
		for i in 0..8 {
			builder.register_public_input(hash[i].0);
		}

		println!("building");
		let now = Instant::now();
		let data = builder.build::<C>();
		println!("build: {:?}", now.elapsed());

		let mut pw = PartialWitness::new();
		for (i, &v) in values.iter().enumerate() {
			pw.set_target(targets[i], v)?;
		}

		let now = Instant::now();
		println!("proving");
		let proof = data.prove(pw)?;
		println!("proof: {:?}", now.elapsed());

		println!("proof size: {}", proof.to_bytes().len());

		for (i, &exp) in expected.iter().enumerate() {
			assert_eq!(
				proof.public_inputs[i],
				F::from_canonical_u64(exp as u64),
				"SHA256 field witness word {i} mismatch: expected {exp:#010X}",
			);
		}

		data.verify(proof)?;
		Ok(())
	}

	/// Hash a single field element.
	#[test]
	fn test_sha256_single_field_element() -> Result<()> {
		let values = [F::from_canonical_u64(123456789)];
		let expected = sha256_field_elements_native(&values);

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let luts = Sha256Luts::new(&mut builder);

		let target = builder.constant(values[0]);
		let hash = builder.sha256_hash_field_elements(&[target], &luts);
		for i in 0..8 {
			builder.register_public_input(hash[i].0);
		}

		let data = builder.build::<C>();
		let proof = data.prove(PartialWitness::new())?;

		for (i, &exp) in expected.iter().enumerate() {
			assert_eq!(proof.public_inputs[i], F::from_canonical_u64(exp as u64),);
		}

		data.verify(proof)?;
		Ok(())
	}

	/// SHA256("abc") with first output word connected to wrong value.
	#[test]
	fn test_sha256_abc_wrong_output() {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let luts = Sha256Luts::new(&mut builder);

		let mut input = [builder.constant_u32(0); 16];
		input[0] = builder.constant_u32(0x61626380); // "abc" + 0x80
		input[15] = builder.constant_u32(0x00000018); // 24 bits

		let hash = builder.sha256_single_block(input, &luts);

		// Connect first word to wrong value (correct is 0xba7816bf)
		let wrong = builder.constant_u32(0x00000000);
		builder.connect(hash[0].0, wrong.0);

		let data = builder.build::<C>();
		assert!(data.prove(PartialWitness::new()).is_err());
	}

	/// Non-canonical field element through SHA256 hash produces wrong digest.
	///
	/// If a non-canonical Goldilocks value (>= p) is provided via
	/// `F::from_noncanonical_u64`, the implicit modular reduction changes
	/// the decomposed bytes, so SHA256(non_canonical) != SHA256(canonical).
	/// This test verifies the circuit rejects the non-canonical hash output.
	#[test]
	fn test_sha256_field_non_canonical_input() -> Result<()> {
		// Goldilocks prime: p = 2^64 - 2^32 + 1
		let p: u64 = 0xFFFFFFFF00000001;
		// Non-canonical representation of 42: v = p + 42
		let v: u64 = p.wrapping_add(42);

		// Compute the "expected" hash as if v were not reduced
		// (raw bytes of the non-canonical value)
		let non_canonical_expected = {
			use sha2::{Digest, Sha256};
			let mut hasher = Sha256::new();
			hasher.update(v.to_be_bytes());
			let result = hasher.finalize();
			core::array::from_fn::<u32, 8, _>(|i| {
				u32::from_be_bytes(result[4 * i..4 * i + 4].try_into().unwrap())
			})
		};

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let luts = Sha256Luts::new(&mut builder);

		let input = builder.add_virtual_target();
		let hash = builder.sha256_hash_field_elements(&[input], &luts);

		// Connect output to the hash of the NON-CANONICAL byte representation
		for (i, &exp) in non_canonical_expected.iter().enumerate() {
			let expected_word = builder.constant_u32(exp);
			builder.connect(hash[i].0, expected_word.0);
		}

		let data = builder.build::<C>();

		// Set input to the non-canonical value (no modular reduction)
		// from_noncanonical_u64 stores the raw u64 without asserting < p
		let mut pw = PartialWitness::new();
		pw.set_target(input, F::from_noncanonical_u64(v))?;

		// The circuit decomposes to canonical bytes (of 42, not v),
		// so the hash differs from the non-canonical expected hash.
		assert!(data.prove(pw).is_err());
		Ok(())
	}
}
