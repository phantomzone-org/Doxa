use plonky2::{get_gate_tag_impl, read_gate_impl};

use super::signature::{CompressionGate, DoubleAdd4x};

/// A [`GateSerializer`] that supports all default plonky2 gates plus the
/// custom gates defined in this module (`DoubleAdd4x` and `CompressionGate`).
#[derive(Debug)]
pub struct TesseraGateSerializer;

impl<
	F: plonky2::hash::hash_types::RichField + plonky2_field::extension::Extendable<D>,
	const D: usize,
> plonky2::util::serialization::GateSerializer<F, D> for TesseraGateSerializer
{
	plonky2::impl_gate_serializer! {
		TesseraGateSerializer,
		plonky2::gates::arithmetic_base::ArithmeticGate,
		plonky2::gates::arithmetic_extension::ArithmeticExtensionGate<D>,
		plonky2::gates::base_sum::BaseSumGate<2>,
		plonky2::gates::constant::ConstantGate,
		plonky2::gates::coset_interpolation::CosetInterpolationGate<F, D>,
		plonky2::gates::exponentiation::ExponentiationGate<F, D>,
		plonky2::gates::lookup::LookupGate,
		plonky2::gates::lookup_table::LookupTableGate,
		plonky2::gates::multiplication_extension::MulExtensionGate<D>,
		plonky2::gates::noop::NoopGate,
		plonky2::gates::poseidon_mds::PoseidonMdsGate<F, D>,
		plonky2::gates::poseidon::PoseidonGate<F, D>,
		plonky2::gates::public_input::PublicInputGate,
		plonky2::gates::random_access::RandomAccessGate<F, D>,
		plonky2::gates::reducing_extension::ReducingExtensionGate<D>,
		plonky2::gates::reducing::ReducingGate<D>,
		DoubleAdd4x,
		CompressionGate
	}
}
