use std::{
	cmp::Ordering,
	fmt::{Debug, Display},
};

use anyhow::Result;
use plonky2::{
	field::{
		extension::Extendable,
		types::{Field, Field64},
	},
	hash::{
		hash_types::{HashOut, HashOutTarget, RichField},
		hashing::PlonkyPermutation,
		poseidon::{PoseidonHash, PoseidonPermutation},
	},
	iop::{
		target::{BoolTarget, Target},
		witness::{PartialWitness, WitnessWrite},
	},
	plonk::{circuit_builder::CircuitBuilder, config::{AlgebraicHasher, Hasher}},
};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::F;

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

// ---------------------------------------------------------------------------
// MerkleHashTarget<N> — const-generic circuit hash target
// ---------------------------------------------------------------------------

/// Circuit-level hash target with a compile-time element count.
///
/// - Poseidon: `MerkleHashTarget<4>` (maps 1:1 to plonky2's `HashOutTarget`)
/// - Keccak-256: `MerkleHashTarget<8>` (one u32 word per element, no packing)
#[derive(Clone, Copy, Debug)]
pub struct MerkleHashTarget<const N: usize> {
	pub elements: [Target; N],
}

impl<const N: usize> MerkleHashTarget<N> {
	/// Allocate N virtual targets.
	pub fn add_virtual<F: RichField + Extendable<D>, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
	) -> Self {
		Self {
			elements: core::array::from_fn(|_| builder.add_virtual_target()),
		}
	}

	/// Allocate N virtual targets and register them as public inputs.
	pub fn add_virtual_public_input<F: RichField + Extendable<D>, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
	) -> Self {
		Self {
			elements: core::array::from_fn(|_| builder.add_virtual_public_input()),
		}
	}

	/// Connect two hash targets element-wise (equality constraint).
	pub fn connect<F: RichField + Extendable<D>, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
		a: &Self,
		b: &Self,
	) {
		for i in 0..N {
			builder.connect(a.elements[i], b.elements[i]);
		}
	}

	/// Conditional connect: if `flag == 1`, constrain `a == b`.
	pub fn conditional_connect<F: RichField + Extendable<D>, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
		flag: BoolTarget,
		a: &Self,
		b: &Self,
	) {
		for i in 0..N {
			builder.conditional_assert_eq(flag.target, a.elements[i], b.elements[i]);
		}
	}

	/// Per-element select: if `dir == 1` pick `a`, else pick `b`.
	pub fn select<F: RichField + Extendable<D>, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
		dir: BoolTarget,
		a: &Self,
		b: &Self,
	) -> Self {
		Self {
			elements: core::array::from_fn(|i| builder.select(dir, a.elements[i], b.elements[i])),
		}
	}

	/// Set witness values from a field-element array.
	pub fn set_witness<F: Field>(
		pw: &mut PartialWitness<F>,
		target: &Self,
		values: &[F; N],
	) -> Result<()> {
		for (i, &val) in values.iter().enumerate().take(N) {
			pw.set_target(target.elements[i], val)?;
		}
		Ok(())
	}
}

/// Conversion helpers for the 4-element case (plonky2 `HashOutTarget`).
impl MerkleHashTarget<4> {
	pub fn from_hash_out_target(h: HashOutTarget) -> Self {
		Self {
			elements: h.elements,
		}
	}

	pub fn to_hash_out_target(&self) -> HashOutTarget {
		HashOutTarget {
			elements: self.elements,
		}
	}
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

pub trait MerkleHashCircuit<F: Field, const D: usize>: MerkleHash {
	/// Circuit-level hash target type.
	/// Poseidon: `MerkleHashTarget<4>`. Keccak: `MerkleHashTarget<8>`.
	type HashTarget: Copy + Clone + Debug;

	/// Return the field elements of a native digest as a slice.
	/// Used to bridge native proof values into witness-setting helpers.
	fn digest_elements(d: &Self::Digest) -> &[F];

	/// Access the underlying `[Target]` slice of a hash target.
	fn hash_target_elements(t: &Self::HashTarget) -> &[Target];

	/// Allocate virtual targets for one hash.
	fn add_virtual_hash(builder: &mut CircuitBuilder<F, D>) -> Self::HashTarget
	where
		F: RichField + Extendable<D>;

	/// Allocate virtual targets for one hash and register them as public inputs.
	fn add_virtual_hash_public_input(builder: &mut CircuitBuilder<F, D>) -> Self::HashTarget
	where
		F: RichField + Extendable<D>;

	/// Create a constant hash target from a native digest value.
	fn constant_hash(builder: &mut CircuitBuilder<F, D>, value: &Self::Digest) -> Self::HashTarget
	where
		F: RichField + Extendable<D>;

	/// Connect two hash targets element-wise (equality constraint).
	fn connect_hashes(
		builder: &mut CircuitBuilder<F, D>,
		a: &Self::HashTarget,
		b: &Self::HashTarget,
	) where
		F: RichField + Extendable<D>;

	/// Per-element select: if `dir == 1` pick `a`, else pick `b`.
	fn select_hash(
		builder: &mut CircuitBuilder<F, D>,
		dir: BoolTarget,
		a: &Self::HashTarget,
		b: &Self::HashTarget,
	) -> Self::HashTarget
	where
		F: RichField + Extendable<D>;

	/// Set witness values for a hash target from a native digest.
	fn set_hash_witness(
		pw: &mut PartialWitness<F>,
		target: &Self::HashTarget,
		value: &Self::Digest,
	) -> Result<()>;

	fn hash_2_to_1_circuit(
		builder: &mut CircuitBuilder<F, D>,
		cur: Self::HashTarget,
		sib: Self::HashTarget,
		dir: BoolTarget,
	) -> Self::HashTarget
	where
		F: RichField + Extendable<D>;

	fn hash_root_circuit(
		builder: &mut CircuitBuilder<F, D>,
		num_leaves: Target,
		left: Self::HashTarget,
		right: Self::HashTarget,
	) -> Self::HashTarget
	where
		F: RichField + Extendable<D>;

	fn commit_node_circuit(
		builder: &mut CircuitBuilder<F, D>,
		value: Self::HashTarget,
		next_index: Target,
		next_value: Self::HashTarget,
	) -> Self::HashTarget
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
			F::from_canonical_u64(num_leaves as u64),
			left.0[0],
			left.0[1],
			left.0[2],
			left.0[3],
			right.0[0],
			right.0[1],
			right.0[2],
			right.0[3],
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
	type HashTarget = MerkleHashTarget<4>;

	fn digest_elements(d: &Self::Digest) -> &[F] {
		&d.0
	}

	fn hash_target_elements(t: &Self::HashTarget) -> &[Target] {
		&t.elements
	}

	fn add_virtual_hash(builder: &mut CircuitBuilder<F, 2>) -> Self::HashTarget {
		MerkleHashTarget::<4>::add_virtual(builder)
	}

	fn add_virtual_hash_public_input(builder: &mut CircuitBuilder<F, 2>) -> Self::HashTarget {
		MerkleHashTarget::<4>::add_virtual_public_input(builder)
	}

	fn constant_hash(builder: &mut CircuitBuilder<F, 2>, value: &Self::Digest) -> Self::HashTarget {
		MerkleHashTarget::from_hash_out_target(builder.constant_hash(value.as_hash_out()))
	}

	fn connect_hashes(
		builder: &mut CircuitBuilder<F, 2>,
		a: &Self::HashTarget,
		b: &Self::HashTarget,
	) {
		MerkleHashTarget::connect(builder, a, b);
	}

	fn select_hash(
		builder: &mut CircuitBuilder<F, 2>,
		dir: BoolTarget,
		a: &Self::HashTarget,
		b: &Self::HashTarget,
	) -> Self::HashTarget {
		MerkleHashTarget::select(builder, dir, a, b)
	}

	fn set_hash_witness(
		pw: &mut PartialWitness<F>,
		target: &Self::HashTarget,
		value: &Self::Digest,
	) -> Result<()> {
		MerkleHashTarget::set_witness(pw, target, &value.0)
	}

	fn hash_2_to_1_circuit(
		builder: &mut CircuitBuilder<F, 2>,
		cur: Self::HashTarget,
		sib: Self::HashTarget,
		dir: BoolTarget,
	) -> Self::HashTarget {
		let zero = builder.zero();
		let perm_inputs = PoseidonPermutation::new(
			cur.elements
				.iter()
				.chain(sib.elements.iter())
				.copied()
				.chain(core::iter::repeat(zero)),
		);
		let perm_output = PoseidonHash::permute_swapped(perm_inputs, dir, builder);
		let output = perm_output.squeeze();
		MerkleHashTarget {
			elements: core::array::from_fn(|i| output[i]),
		}
	}

	fn hash_root_circuit(
		builder: &mut CircuitBuilder<F, 2>,
		num_leaves: Target,
		left: Self::HashTarget,
		right: Self::HashTarget,
	) -> Self::HashTarget {
		let out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![
			num_leaves,
			left.elements[0],
			left.elements[1],
			left.elements[2],
			left.elements[3],
			right.elements[0],
			right.elements[1],
			right.elements[2],
			right.elements[3],
		]);
		MerkleHashTarget::from_hash_out_target(out)
	}

	fn commit_node_circuit(
		builder: &mut CircuitBuilder<F, 2>,
		value: Self::HashTarget,
		next_index: Target,
		next_value: Self::HashTarget,
	) -> Self::HashTarget {
		let out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![
			next_index,
			value.elements[0],
			value.elements[1],
			value.elements[2],
			value.elements[3],
			next_value.elements[0],
			next_value.elements[1],
			next_value.elements[2],
			next_value.elements[3],
		]);
		MerkleHashTarget::from_hash_out_target(out)
	}
}

#[cfg(test)]
mod test {

	use anyhow::Result;
	use plonky2::{
		field::types::Field,
		iop::{
			target::Target,
			witness::{PartialWitness, WitnessWrite},
		},
		plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig},
	};

	use crate::{
		ConfigNative, D, F, ProofNative,
		hasher::{HashOutput, MerkleHash, MerkleHashCircuit, NewFromU64},
	};

	#[test]
	fn hash_2_to_1_circuit() -> Result<()> {
		let config: CircuitConfig = CircuitConfig::standard_recursion_config();
		let mut builder: CircuitBuilder<F, D> = CircuitBuilder::<F, D>::new(config);

		let left: HashOutput = HashOutput::new_from_u64(42);
		let right: HashOutput = HashOutput::new_from_u64(1337);

		let dir_target = builder.add_virtual_bool_target_safe();
		let left_target = HashOutput::add_virtual_hash(&mut builder);
		let right_target = HashOutput::add_virtual_hash(&mut builder);
		let out_target = HashOutput::add_virtual_hash(&mut builder);
		let have_target =
			HashOutput::hash_2_to_1_circuit(&mut builder, left_target, right_target, dir_target);
		HashOutput::connect_hashes(&mut builder, &have_target, &out_target);
		let data = builder.build::<ConfigNative>();

		for dir in [false, true] {
			let out: HashOutput = HashOutput::hash_2_to_1(&left, &right, dir);
			let mut pw: PartialWitness<F> = PartialWitness::new();
			HashOutput::set_hash_witness(&mut pw, &left_target, &left)?;
			HashOutput::set_hash_witness(&mut pw, &right_target, &right)?;
			HashOutput::set_hash_witness(&mut pw, &out_target, &out)?;
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
		let value_t = HashOutput::add_virtual_hash(&mut builder);
		let next_value_t = HashOutput::add_virtual_hash(&mut builder);
		let comm_want_t = HashOutput::add_virtual_hash(&mut builder);
		let comm_have_t =
			HashOutput::commit_node_circuit(&mut builder, value_t, next_index_t, next_value_t);
		HashOutput::connect_hashes(&mut builder, &comm_have_t, &comm_want_t);
		let data = builder.build::<ConfigNative>();

		let out: HashOutput = HashOutput::commit_node(&value, next_index, &next_value);
		let mut pw: PartialWitness<F> = PartialWitness::new();

		pw.set_target(next_index_t, F::from_canonical_u64(next_index as u64))?;
		HashOutput::set_hash_witness(&mut pw, &value_t, &value)?;
		HashOutput::set_hash_witness(&mut pw, &next_value_t, &next_value)?;
		HashOutput::set_hash_witness(&mut pw, &comm_want_t, &out)?;
		let proof: ProofNative = data.prove(pw)?;
		data.verify(proof)?;
		Ok(())
	}
}
