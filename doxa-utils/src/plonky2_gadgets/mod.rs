pub mod keccak256;
pub mod u32;

use std::marker::PhantomData;

use plonky2::{
	field::extension::Extendable,
	hash::hash_types::RichField,
	iop::target::Target,
	plonk::{
		circuit_builder::CircuitBuilder,
		config::{AlgebraicHasher, GenericConfig},
	},
};

use crate::{
	hasher::{CommitmentPreimage, DataCommitment},
	plonky2_gadgets::{
		keccak256::{
			builder::BuilderKeccak256 as _, field_decompose::decompose_field_to_u32_pair,
			utils::keccak256_field_elements_native,
		},
		u32::gadgets::add_u8_range_check_lookup_table,
	},
};

/// Keccak-256-based data commitment.
///
/// Computes `keccak256(preimage)` where each target is treated as a
/// Goldilocks field element encoded in big-endian 8-byte form (high
/// 32-bit word followed by low 32-bit word).
/// Registers the 8-word (256-bit) digest as public inputs
/// (8 targets, each holding a `u32` value).
///
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
