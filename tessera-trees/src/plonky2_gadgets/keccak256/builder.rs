use plonky2::{
	field::extension::Extendable,
	hash::hash_types::RichField,
	iop::generator::{SimpleGenerator as _, WitnessGeneratorRef},
	plonk::{
		circuit_builder::CircuitBuilder,
		config::{AlgebraicHasher, GenericConfig},
	},
};

use crate::plonky2_gadgets::keccak256::{
	U32Target,
	generators::{
		single_generator::Keccak256SingleGenerator,
		stark_proof_generator::Keccak256StarkProofGenerator,
	},
};

pub trait BuilderKeccak256<F: RichField + Extendable<D>, const D: usize> {
	fn keccak256<C: GenericConfig<D, F = F> + 'static>(
		&mut self,
		input: &[U32Target],
	) -> [U32Target; 8]
	where
		<C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>;
}

impl<F: RichField + Extendable<D>, const D: usize> BuilderKeccak256<F, D> for CircuitBuilder<F, D> {
	/// Computes the keccak256 hash according to the Solidity specification.
	/// Both input and output are in big-endian format.
	/// NOTICE: It is necessary to additionally constrain each limb of the input
	/// to be 32 bits.
	fn keccak256<C: GenericConfig<D, F = F> + 'static>(
		&mut self,
		input: &[U32Target],
	) -> [U32Target; 8]
	where
		<C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
	{
		let output: [U32Target; 8] = [(); 8].map(|_| self.add_virtual_target());

		let single_generator = Keccak256SingleGenerator {
			input: input.to_vec(),
			output,
		};
		self.add_generators(vec![WitnessGeneratorRef::new(single_generator.adapter())]);

		let stark_generator =
			Keccak256StarkProofGenerator::<F, C, D>::new(self, vec![input.to_vec()]);
		for (x, y) in output.iter().zip(stark_generator.outputs[0].iter()) {
			self.connect(*x, *y);
		}
		self.add_generators(vec![WitnessGeneratorRef::new(stark_generator.adapter())]);

		output
	}
}

#[cfg(test)]
mod tests {
	use plonky2::{
		field::types::Field,
		iop::witness::{PartialWitness, WitnessWrite},
		plonk::{
			circuit_builder::CircuitBuilder,
			circuit_data::CircuitConfig,
			config::{GenericConfig, PoseidonGoldilocksConfig},
		},
	};
	use rand::RngExt;

	use crate::plonky2_gadgets::keccak256::{
		builder::BuilderKeccak256 as _, utils::solidity_keccak256,
	};

	#[test]
	fn keccak_builder() {
		let num_inputs = 10;
		let inputs_random_len_range = 10..=10;
		const D: usize = 2;
		type C = PoseidonGoldilocksConfig;
		type F = <C as GenericConfig<D>>::F;
		let mut rng = rand::rng();
		let inputs: Vec<Vec<u32>> = (0..num_inputs)
			.map(|_| {
				let random_len = rng.random_range(inputs_random_len_range.clone());
				(0..random_len)
					.map(|_| rng.random::<u32>())
					.collect::<Vec<_>>()
			})
			.collect::<Vec<_>>();
		let expected_outputs = inputs
			.iter()
			.map(|input| solidity_keccak256(input))
			.collect::<Vec<_>>();
		let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::default());
		let inputs_t: Vec<Vec<plonky2::iop::target::Target>> = inputs
			.iter()
			.map(|input| {
				input
					.iter()
					.map(|_| builder.add_virtual_target())
					.collect::<Vec<_>>()
			})
			.collect::<Vec<_>>();
		let outputs_t: Vec<[plonky2::iop::target::Target; 8]> = inputs_t
			.iter()
			.map(|input_t| builder.keccak256::<C>(input_t))
			.collect::<Vec<_>>();
		let mut pw = PartialWitness::new();
		for (input_t, input) in inputs_t.iter().zip(inputs.iter()) {
			for (t, w) in input_t.iter().zip(input.iter()) {
				pw.set_target(*t, F::from_canonical_u32(*w)).unwrap();
			}
		}
		for (ouput_t, output) in outputs_t.iter().zip(expected_outputs.iter()) {
			for (t, w) in ouput_t.iter().zip(output.iter()) {
				pw.set_target(*t, F::from_canonical_u32(*w)).unwrap();
			}
		}
		let circuit = builder.build::<C>();
		circuit.prove(pw).unwrap();
	}
}
