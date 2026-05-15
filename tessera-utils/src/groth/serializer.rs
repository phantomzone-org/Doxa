//! Custom [`WitnessGeneratorSerializer`] for the Tessera native circuit.
//!
//! The native plonky2 circuit uses 10 custom witness generators from the
//! Keccak-256 / SHA-256 / u32 gadgets that are not included in plonky2's
//! [`DefaultGeneratorSerializer`].  This module provides
//! [`TesseraGeneratorSerializer`] which covers all 24 standard generators
//! plus the 10 custom ones, enabling full round-trip serialization of the
//! native circuit data with [`CircuitData::to_bytes`] / `from_bytes`.

// The impl_generator_serializer! macro expands to calls of these two helper macros.
use plonky2::{
	gadgets::{
		arithmetic::EqualityGenerator,
		arithmetic_extension::QuotientGeneratorExtension,
		range_check::LowHighGenerator,
		split_base::BaseSumGenerator,
		split_join::{SplitGenerator, WireSplitGenerator},
	},
	gates::{
		arithmetic_base::ArithmeticBaseGenerator,
		arithmetic_extension::ArithmeticExtensionGenerator, base_sum::BaseSplitGenerator,
		coset_interpolation::InterpolationGenerator, exponentiation::ExponentiationGenerator,
		lookup::LookupGenerator, lookup_table::LookupTableGenerator,
		multiplication_extension::MulExtensionGenerator, poseidon::PoseidonGenerator,
		poseidon_mds::PoseidonMdsGenerator, random_access::RandomAccessGenerator,
		reducing::ReducingGenerator,
		reducing_extension::ReducingGenerator as ReducingExtensionGenerator,
	},
	iop::generator::{
		ConstantGenerator, CopyGenerator, NonzeroTestGenerator, RandomValueGenerator,
	},
	recursion::dummy_circuit::DummyProofGenerator,
	util::serialization::WitnessGeneratorSerializer,
};
#[allow(unused_imports)]
use plonky2::{get_generator_tag_impl, read_generator_impl};

use crate::plonky2_gadgets::{
	keccak256::field_decompose::{CanonicalCheckGenerator, FieldDecompositionGenerator},
	keccak256::generators::{
		single_generator::Keccak256SingleGenerator,
		stark_proof_generator::Keccak256StarkProofGenerator,
	},
	u32::gadgets::{
		// defined directly in gadgets/mod.rs
		ByteDecompositionGenerator,
		ChunkDecompositionGenerator,
		LimbByteDecompositionGenerator,
		U16LimbDecompositionGenerator,
		// pub(crate) in submodules — not re-exported by `pub use arithmetic::*`
		arithmetic::U32WrappingAddGenerator,
		rotation::SplitLowHighGenerator,
	},
};
use crate::{ConfigNative, F};

const D: usize = 2;

/// A [`WitnessGeneratorSerializer`] that covers both the 24 default plonky2
/// generators and the 10 custom generators used by Tessera's Keccak-256 /
/// SHA-256 / u32 gadgets.
///
/// Use this in place of [`DefaultGeneratorSerializer`] when serializing or
/// deserializing the native circuit data (`CircuitDataNative`).
#[derive(Debug, Default)]
pub struct TesseraGeneratorSerializer;

impl WitnessGeneratorSerializer<F, D> for TesseraGeneratorSerializer {
	plonky2::impl_generator_serializer! {
		TesseraGeneratorSerializer,
		// --- 24 standard plonky2 generators (mirrors DefaultGeneratorSerializer) ---
		ArithmeticBaseGenerator<F, D>,
		ArithmeticExtensionGenerator<F, D>,
		BaseSplitGenerator<2>,
		BaseSumGenerator<2>,
		ConstantGenerator<F>,
		CopyGenerator,
		DummyProofGenerator<F, ConfigNative, D>,
		EqualityGenerator,
		ExponentiationGenerator<F, D>,
		InterpolationGenerator<F, D>,
		LookupGenerator,
		LookupTableGenerator,
		LowHighGenerator,
		MulExtensionGenerator<F, D>,
		NonzeroTestGenerator,
		PoseidonGenerator<F, D>,
		PoseidonMdsGenerator<D>,
		QuotientGeneratorExtension<D>,
		RandomAccessGenerator<F, D>,
		RandomValueGenerator,
		ReducingGenerator<D>,
		ReducingExtensionGenerator<D>,
		SplitGenerator,
		WireSplitGenerator,
		// --- 10 custom Tessera generators (Keccak-256 / SHA-256 / u32 gadgets) ---
		ByteDecompositionGenerator,
		ChunkDecompositionGenerator,
		U16LimbDecompositionGenerator,
		LimbByteDecompositionGenerator,
		U32WrappingAddGenerator,
		SplitLowHighGenerator,
		FieldDecompositionGenerator,
		CanonicalCheckGenerator,
		Keccak256SingleGenerator,
		Keccak256StarkProofGenerator<F, ConfigNative, D>
	}
}
