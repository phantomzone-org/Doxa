use std::{
	cmp::Ordering,
	fmt::{Debug, Display},
	marker::PhantomData,
};

use plonky2::{
	field::{
		extension::Extendable,
		types::{Field, Field64},
	},
	hash::{
		hash_types::{HashOut, HashOutTarget, RichField},
		poseidon::PoseidonHash,
	},
	iop::target::{BoolTarget, Target},
	plonk::{
		circuit_builder::CircuitBuilder,
		config::{AlgebraicHasher, GenericConfig, Hasher},
	},
};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::{
	F,
	plonky2_gadgets::{
		keccak256::{builder::BuilderKeccak256, utils::keccak256_field_elements_native},
		sha256::{
			CircuitBuilderSha256, Sha256Luts, circuit::decompose_field_to_u32_pair,
			sha256_field_elements_native,
		},
		u32::add_u8_range_check_lookup_table,
	},
};

pub trait MerkleHash: Copy + Clone + Debug {
	type Digest: Clone + Copy + Eq + Ord + Display + Debug;

	/// This constant represents the smallest possible value of a [MerkleHash::Digest].
	///
	/// The value `HEAD` is used in the following ways:
	/// - As the starting point or initial value in the Merkle tree.
	/// - As a placeholder for empty or null nodes.
	const HEAD: Self::Digest;

	/// This constant represents the largest possible of a [MerkleHash::Digest].
	///
	/// In the context of a Merkle tree, this value is used to designates the last element.
	///
	/// The value `TAIL` is used in the following ways:
	/// - As the next pointer from the largest label in the current Merkle tree.
	/// - As the next pointer from inactive leaf nodes, effectively "pointing" to it.
	///
	/// This ensures that no value in the Merkle tree exceeds the modulus, maintaining proper order
	/// and integrity.
	const TAIL: Self::Digest;

	/// Hash a two [MerkleHash::Digest to one [MerkleHash::Digest].
	/// Output MUST fall uniformly between [MerkleHash::HEAD] and [MerkleHash::TAIL].
	fn hash_2_to_1(left: &Self::Digest, right: &Self::Digest, dir: bool) -> Self::Digest;

	/// Hash the root of a Merkle tree, committing to the number of leaves.
	/// root = H(num_leaves | left | right)
	fn hash_root(num_leaves: usize, left: &Self::Digest, right: &Self::Digest) -> Self::Digest;

	/// Hash a n [MerkleHash::Digest] to one [MerkleHash::Digest].
	/// Output MUST fall uniformly between [MerkleHash::HEAD] and [MerkleHash::TAIL].
	fn commit_node(
		value: &Self::Digest,
		next_index: usize,
		next_value: &Self::Digest,
	) -> Self::Digest;
}

/// Computes a binding commitment over proof data in-circuit and
/// registers the result as public inputs.
///
/// When a proof circuit exposes many field elements as public inputs
/// (roots, leaves, inserted values, …), the on-chain verification
/// cost scales linearly with their count.  A `DataCommitment`
/// replaces the raw public inputs with a short, fixed-size digest:
///
/// 1. All proof data targets are allocated as **private** witnesses.
/// 2. [`commit_public_inputs`](DataCommitment::commit_public_inputs) hashes those targets and
///    registers only the digest as public inputs.
/// 3. The verifier (on-chain or off-chain) checks the digest against the claimed data to confirm
///    binding.
///
/// # Implementations
///
/// | Struct | Hash | Public-input size |
/// |---|---|---|
/// | [`PoseidonCommitment`] | Poseidon | 4 Goldilocks elements (256 bit) |
/// | [`Sha256Commitment`] | SHA-256 | 8 `u32` words (256 bit) |
/// | [`Keccak256Commitment`] | Keccak-256 | 8 `u32` words (256 bit) |
///
/// # Usage
///
/// Pass `Some(&impl DataCommitment)` to enable commitment mode, or
/// `None` to expose proof data directly as public inputs:
///
/// ```ignore
/// // Poseidon commitment (no setup needed):
/// let targets = ProofTargets::new(&mut builder, depth, batch, Some(&PoseidonCommitment));
///
/// // SHA-256 commitment (registers lookup tables first):
/// let sha256 = Sha256Commitment::new(&mut builder, 8);
/// let targets = ProofTargets::new(&mut builder, depth, batch, Some(&sha256));
///
/// // Keccak-256 commitment (registers a byte-range lookup table):
/// let keccak = Keccak256Commitment::<C, D>::new(&mut builder);
/// let targets = ProofTargets::new(&mut builder, depth, batch, Some(&keccak));
///
/// // No commitment — raw public inputs:
/// let targets = ProofTargets::new(&mut builder, depth, batch, None);
/// ```
///
/// # Implementing a custom commitment
///
/// ```ignore
/// struct MyCommitment { /* any circuit-build-time state */ }
///
/// impl<F: RichField + Extendable<D>, const D: usize>
///     DataCommitment<F, D> for MyCommitment
/// {
///     fn commit_public_inputs(
///         &self,
///         builder: &mut CircuitBuilder<F, D>,
///         preimage: Vec<Target>,
///     ) {
///         let digest = my_hash_circuit(builder, &preimage);
///         builder.register_public_inputs(&digest);
///     }
/// }
/// ```
/// Provides the commitment preimage as field elements.
///
/// Proof types implement this trait so they can be passed directly
/// to [`DataCommitment::commit_native`] without an intermediate
/// allocation step.
pub trait CommitmentPreimage<F: Field> {
	/// Appends this object's commitment preimage field elements to `buf`.
	fn write_preimage(&self, buf: &mut Vec<F>);
}

pub trait DataCommitment<F: RichField + Extendable<D>, const D: usize> {
	/// Hashes the `preimage` targets and registers the resulting
	/// commitment as public inputs on the circuit builder.
	///
	/// The number and interpretation of the registered public inputs
	/// is implementation-defined (e.g. 4 field elements for Poseidon,
	/// 8 `u32` words for Keccak-256 or SHA-256).
	fn commit_public_inputs(&self, builder: &mut CircuitBuilder<F, D>, preimage: Vec<Target>);

	/// Computes the commitment digest natively (outside the circuit).
	///
	/// The `source` provides the preimage field elements (typically a
	/// native proof that implements [`CommitmentPreimage`]).
	///
	/// Returns the same field elements that would appear as public
	/// inputs when using [`commit_public_inputs`](Self::commit_public_inputs)
	/// in a circuit.
	///
	/// ```ignore
	/// let expected_pi = commitment.commit_native(&native_proof);
	/// assert_eq!(expected_pi, stark_proof.public_inputs);
	/// ```
	fn commit_native(&self, source: &dyn CommitmentPreimage<F>) -> Vec<F>;
}

/// Poseidon-based data commitment.
///
/// Computes `PoseidonHash::hash_n_to_hash_no_pad(preimage)` and
/// registers the 4-element hash output as public inputs.
#[derive(Clone, Copy, Debug)]
pub struct PoseidonCommitment;

impl<F: RichField + Extendable<D>, const D: usize> DataCommitment<F, D> for PoseidonCommitment {
	fn commit_public_inputs(&self, builder: &mut CircuitBuilder<F, D>, preimage: Vec<Target>) {
		let commitment = builder.hash_n_to_hash_no_pad::<PoseidonHash>(preimage);
		builder.register_public_inputs(&commitment.elements);
	}

	fn commit_native(&self, source: &dyn CommitmentPreimage<F>) -> Vec<F> {
		let mut preimage = Vec::new();
		source.write_preimage(&mut preimage);
		PoseidonHash::hash_no_pad(&preimage).elements.to_vec()
	}
}

/// SHA-256-based data commitment.
///
/// Computes `SHA256(preimage)` where each target is treated as a
/// Goldilocks field element encoded in big-endian 8-byte form.
/// Registers the 8-word (256-bit) digest as public inputs
/// (8 targets, each holding a `u32` value).
///
/// # Construction
///
/// The lookup tables required by the SHA-256 circuit are registered
/// when `Sha256Commitment::new` is called.  Create this **before**
/// passing it to proof-target constructors, and only once per circuit.
#[derive(Clone, Copy, Debug)]
pub struct Sha256Commitment {
	luts: Sha256Luts,
}

impl Sha256Commitment {
	/// Registers the SHA-256 lookup tables and returns a ready-to-use
	/// commitment object.  Call once per circuit builder.
	///
	/// `chunk_bits` controls the bitwise-LUT granularity (1, 2, 4, or 8).
	pub fn new<F: RichField + Extendable<D>, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
		chunk_bits: usize,
	) -> Self {
		Self {
			luts: Sha256Luts::new(builder, chunk_bits),
		}
	}
}

impl<F: RichField + Extendable<D>, const D: usize> DataCommitment<F, D> for Sha256Commitment {
	fn commit_public_inputs(&self, builder: &mut CircuitBuilder<F, D>, preimage: Vec<Target>) {
		let hash = builder.sha256_hash_field_elements(&preimage, &self.luts);
		for word in &hash {
			builder.register_public_input(word.0);
		}
	}

	fn commit_native(&self, source: &dyn CommitmentPreimage<F>) -> Vec<F> {
		let mut preimage = Vec::new();
		source.write_preimage(&mut preimage);
		sha256_field_elements_native(&preimage)
			.iter()
			.map(|&w| F::from_canonical_u64(w as u64))
			.collect()
	}
}

/// Keccak-256-based data commitment.
///
/// Computes `keccak256(preimage)` where each target is treated as a
/// Goldilocks field element encoded in big-endian 8-byte form (high
/// 32-bit word followed by low 32-bit word).
/// Registers the 8-word (256-bit) digest as public inputs
/// (8 targets, each holding a `u32` value).
///
/// The encoding is identical to [`Sha256Commitment`], so the preimage
/// byte layout is unchanged — only the hash function differs.
/// This makes the on-chain verifier input (`uint256[8]`) identical in
/// shape to the SHA-256 variant, avoiding ABI churn.
///
/// The circuit output matches `keccak256(abi.encodePacked(fields))`
/// in Solidity when each Goldilocks element maps to one big-endian
/// `uint64`.
///
/// # Construction
///
/// A byte-range lookup table is registered when
/// `Keccak256Commitment::new` is called.  Create this **before**
/// passing it to proof-target constructors, and only once per circuit.
#[derive(Clone, Copy, Debug)]
pub struct Keccak256Commitment<C, const D: usize> {
	byte_range_lut: usize,
	_marker: PhantomData<C>,
}

impl<C, const D: usize> Keccak256Commitment<C, D> {
	/// Registers the byte-range lookup table and returns a ready-to-use
	/// commitment object.  Call once per circuit builder.
	pub fn new<F: RichField + Extendable<D>>(builder: &mut CircuitBuilder<F, D>) -> Self
	where
		C: GenericConfig<D, F = F> + 'static,
		<C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
	{
		Self {
			byte_range_lut: add_u8_range_check_lookup_table(builder),
			_marker: PhantomData,
		}
	}
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
	DataCommitment<F, D> for Keccak256Commitment<C, D>
where
	<C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
	fn commit_public_inputs(&self, builder: &mut CircuitBuilder<F, D>, preimage: Vec<Target>) {
		// Decompose each Goldilocks field element into [hi, lo] u32 targets
		// (big-endian word order) and feed the resulting words to the Keccak-256
		// gadget, matching the native encoding.
		let mut u32_targets = Vec::with_capacity(preimage.len() * 2);
		for &elem in &preimage {
			let [hi, lo] = decompose_field_to_u32_pair(builder, elem, self.byte_range_lut);
			u32_targets.push(hi.0);
			u32_targets.push(lo.0);
		}
		let hash = builder.keccak256::<C>(&u32_targets);
		for word in &hash {
			builder.register_public_input(*word);
		}
	}

	fn commit_native(&self, source: &dyn CommitmentPreimage<F>) -> Vec<F> {
		let mut preimage = Vec::new();
		source.write_preimage(&mut preimage);
		keccak256_field_elements_native(&preimage)
			.iter()
			.map(|&w| F::from_canonical_u64(w as u64))
			.collect()
	}
}

pub trait MerkleHashCircuit<F: Field, const D: usize>: Clone + Debug {
	type Digest: ToHashOut<F>;

	const HEAD: HashOut<F>;
	const TAIL: HashOut<F>;

	fn hash_2_to_1_circuit(
		builder: &mut CircuitBuilder<F, D>,
		cur: HashOutTarget,
		sib: HashOutTarget,
		dir: BoolTarget,
	) -> HashOutTarget
	where
		F: RichField + Extendable<D>;

	fn hash_root_circuit(
		builder: &mut CircuitBuilder<F, D>,
		num_leaves: Target,
		left: HashOutTarget,
		right: HashOutTarget,
	) -> HashOutTarget
	where
		F: RichField + Extendable<D>;

	fn commit_node_circuit(
		builder: &mut CircuitBuilder<F, D>,
		value: HashOutTarget,
		next_index: Target,
		next_value: HashOutTarget,
	) -> HashOutTarget
	where
		F: RichField + Extendable<D>;
}

pub trait ToHashOut<F: Field> {
	fn to_hash_out(&self) -> HashOut<F>;
}

pub(crate) const HASH_SIZE: usize = 4;

#[derive(Clone, Copy, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct HashOutput(pub [F; HASH_SIZE]);

impl From<[F; HASH_SIZE]> for HashOutput {
	fn from(value: [F; HASH_SIZE]) -> Self {
		Self(value)
	}
}

impl HashOutput {
	pub const fn new(value: [F; HASH_SIZE]) -> Self {
		Self(value)
	}

	pub const fn to_u64(&self) -> [u64; HASH_SIZE] {
		[self.0[0].0, self.0[1].0, self.0[2].0, self.0[3].0]
	}

	pub const fn as_hash_out(&self) -> HashOut<F> {
		HashOut {
			elements: self.0,
		}
	}

	/// Converts a 32-byte digest into a [`Hash`].
	///
	/// Splits the digest into 4 big-endian u64 chunks and clears the
	/// MSB of each (mask `0x7FFF_FFFF_FFFF_FFFF`).  This guarantees
	/// every chunk is below 2^63 < GOLDILOCKS_PRIME, making the
	/// mapping injective on the 252-bit truncated digest (126-bit
	/// collision security under the birthday bound).
	pub fn from_32bytes_digest(digest: [u8; 32]) -> Self {
		let mut elems = [F::ZERO; HASH_SIZE];
		for i in 0..HASH_SIZE {
			let chunk = u64::from_be_bytes(digest[i * 8..(i + 1) * 8].try_into().unwrap());
			elems[i] = F::from_canonical_u64(chunk & 0x7FFFFFFFFFFFFFFF);
		}
		Self::new(elems)
	}
}

impl PartialOrd for HashOutput {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

impl Ord for HashOutput {
	fn cmp(&self, other: &Self) -> std::cmp::Ordering {
		self.to_u64().cmp(&other.to_u64())
	}
}

impl Display for HashOutput {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"[0x{:016X}, 0x{:016X}, 0x{:016X}, 0x{:016X}]",
			self.0[0].0, self.0[1].0, self.0[2].0, self.0[3].0
		)
	}
}

#[cfg(test)]
pub(crate) trait NewFromU64 {
	fn new_from_u64(value: u64) -> Self;
}

pub trait NewRandom {
	fn new_random<R: Rng + ?Sized>(rng: &mut R) -> Self;
}

#[cfg(test)]
impl NewFromU64 for HashOutput {
	fn new_from_u64(value: u64) -> Self {
		use crate::F;

		Self::new([F::from_canonical_u64(value), F::ZERO, F::ZERO, F::ZERO])
	}
}

impl NewRandom for HashOutput {
	fn new_random<R: Rng + ?Sized>(rng: &mut R) -> Self {
		Self([
			F::from_canonical_u64(rng.next_u64()),
			F::from_canonical_u64(rng.next_u64()),
			F::from_canonical_u64(rng.next_u64()),
			F::from_canonical_u64(rng.next_u64()),
		])
	}
}

impl ToHashOut<F> for HashOutput {
	fn to_hash_out(&self) -> HashOut<F> {
		HashOut {
			elements: self.0,
		}
	}
}

impl MerkleHash for HashOutput {
	type Digest = HashOutput;

	const HEAD: Self::Digest = Self::Digest::new([F::ZERO; HASH_SIZE]);
	const TAIL: Self::Digest = Self::Digest::new([F::NEG_ONE; HASH_SIZE]);

	fn hash_2_to_1(left: &Self::Digest, right: &Self::Digest, dir: bool) -> Self::Digest {
		let data = if dir {
			[
				right.0[0], right.0[1], right.0[2], right.0[3], left.0[0], left.0[1], left.0[2],
				left.0[3],
			]
		} else {
			[
				left.0[0], left.0[1], left.0[2], left.0[3], right.0[0], right.0[1], right.0[2],
				right.0[3],
			]
		};
		let out: HashOut<F> = PoseidonHash::hash_no_pad(&data);
		Self::Digest::new(out.elements)
	}

	fn hash_root(num_leaves: usize, left: &Self::Digest, right: &Self::Digest) -> Self::Digest {
		assert!((num_leaves as u64) < F::ORDER);
		let out: HashOut<F> = PoseidonHash::hash_no_pad(&[
			left.0[0],
			left.0[1],
			left.0[2],
			left.0[3],
			right.0[0],
			right.0[1],
			right.0[2],
			right.0[3],
			F::from_canonical_u64(num_leaves as u64), // TODO(Jay): @JP I've swapped the order
		]);
		Self::Digest::new(out.elements)
	}

	fn commit_node(
		value: &Self::Digest,
		next_index: usize,
		next_value: &Self::Digest,
	) -> Self::Digest {
		assert!((next_index as u64) < F::ORDER);
		let out: HashOut<F> = PoseidonHash::hash_no_pad(&[
			F::from_canonical_u64(next_index as u64),
			value.0[0],
			value.0[1],
			value.0[2],
			value.0[3],
			next_value.0[0],
			next_value.0[1],
			next_value.0[2],
			next_value.0[3],
		]);
		Self::Digest::new(out.elements)
	}
}

impl MerkleHashCircuit<F, 2> for HashOutput {
	type Digest = HashOutput;

	const HEAD: HashOut<F> = HashOut {
		elements: [F::ZERO; 4],
	};
	const TAIL: HashOut<F> = HashOut {
		elements: [F::NEG_ONE; 4],
	};

	fn hash_2_to_1_circuit(
		builder: &mut CircuitBuilder<F, 2>,
		cur: HashOutTarget,
		sib: HashOutTarget,
		dir: BoolTarget,
	) -> HashOutTarget {
		let data = vec![
			builder.select(dir, sib.elements[0], cur.elements[0]),
			builder.select(dir, sib.elements[1], cur.elements[1]),
			builder.select(dir, sib.elements[2], cur.elements[2]),
			builder.select(dir, sib.elements[3], cur.elements[3]),
			builder.select(dir, cur.elements[0], sib.elements[0]),
			builder.select(dir, cur.elements[1], sib.elements[1]),
			builder.select(dir, cur.elements[2], sib.elements[2]),
			builder.select(dir, cur.elements[3], sib.elements[3]),
		];
		builder.hash_n_to_hash_no_pad::<PoseidonHash>(data)
	}

	fn hash_root_circuit(
		builder: &mut CircuitBuilder<F, 2>,
		num_leaves: Target,
		left: HashOutTarget,
		right: HashOutTarget,
	) -> HashOutTarget {
		builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![
			left.elements[0],
			left.elements[1],
			left.elements[2],
			left.elements[3],
			right.elements[0],
			right.elements[1],
			right.elements[2],
			right.elements[3],
			num_leaves, // TODO(Jay): @JP I've swapped the order
		])
	}

	fn commit_node_circuit(
		builder: &mut CircuitBuilder<F, 2>,
		value: HashOutTarget,
		next_index: Target,
		next_value: HashOutTarget,
	) -> HashOutTarget {
		builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![
			next_index,
			value.elements[0],
			value.elements[1],
			value.elements[2],
			value.elements[3],
			next_value.elements[0],
			next_value.elements[1],
			next_value.elements[2],
			next_value.elements[3],
		])
	}
}

#[cfg(test)]
mod test {

	use anyhow::Result;
	use plonky2::{
		field::types::Field,
		hash::hash_types::HashOutTarget,
		iop::{
			target::{BoolTarget, Target},
			witness::{PartialWitness, WitnessWrite},
		},
		plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
	};

	use crate::{
		ConfigNative, D, F, ProofNative,
		tree::hasher::{HashOutput, MerkleHash, MerkleHashCircuit, NewFromU64},
	};

	#[test]
	fn hash_2_to_1_circuit() -> Result<()> {
		let config: CircuitConfig = CircuitConfig::standard_recursion_config();
		let mut builder: CircuitBuilder<F, D> = CircuitBuilder::<F, D>::new(config);

		let left: HashOutput = HashOutput::new_from_u64(42);
		let right: HashOutput = HashOutput::new_from_u64(1337);

		let dir_target: BoolTarget = builder.add_virtual_bool_target_safe();
		let left_target: HashOutTarget = builder.add_virtual_hash_public_input();
		let right_target: HashOutTarget = builder.add_virtual_hash_public_input();
		let out_target: HashOutTarget = builder.add_virtual_hash_public_input();
		let have_target: HashOutTarget =
			HashOutput::hash_2_to_1_circuit(&mut builder, left_target, right_target, dir_target);
		builder.connect_hashes(have_target, out_target);
		let data = builder.build::<ConfigNative>();

		for dir in [false, true] {
			let out: HashOutput = HashOutput::hash_2_to_1(&left, &right, dir);
			let mut pw: PartialWitness<F> = PartialWitness::new();
			pw.set_hash_target(left_target, left.as_hash_out())?;
			pw.set_hash_target(right_target, right.as_hash_out())?;
			pw.set_hash_target(out_target, out.as_hash_out())?;
			pw.set_bool_target(dir_target, dir)?;
			let proof = data.prove(pw)?;
			data.verify(proof)?;
		}
		Ok(())
	}

	#[test]
	fn hash_3_to_1_circuit() -> Result<()> {
		let config: CircuitConfig = CircuitConfig::standard_recursion_config();
		let mut builder: CircuitBuilder<F, D> = CircuitBuilder::<F, D>::new(config);

		let next_index: usize = 42;
		let value: HashOutput = HashOutput::new_from_u64(1337);
		let next_value: HashOutput = HashOutput::new_from_u64(432);

		let next_index_t: Target = builder.add_virtual_target();
		let value_t: HashOutTarget = builder.add_virtual_hash_public_input();
		let next_value_t: HashOutTarget = builder.add_virtual_hash_public_input();
		let comm_want_t: HashOutTarget = builder.add_virtual_hash_public_input();
		let comm_have_t: HashOutTarget =
			HashOutput::commit_node_circuit(&mut builder, value_t, next_index_t, next_value_t);
		builder.connect_hashes(comm_have_t, comm_want_t);
		let data = builder.build::<ConfigNative>();

		let out: HashOutput = HashOutput::commit_node(&value, next_index, &next_value);
		let mut pw: PartialWitness<F> = PartialWitness::new();

		pw.set_target(next_index_t, F::from_canonical_u64(next_index as u64))?;
		pw.set_hash_target(value_t, value.as_hash_out())?;
		pw.set_hash_target(next_value_t, next_value.as_hash_out())?;
		pw.set_hash_target(comm_want_t, out.as_hash_out())?;
		let proof: ProofNative = data.prove(pw)?;
		data.verify(proof)?;
		Ok(())
	}
}
