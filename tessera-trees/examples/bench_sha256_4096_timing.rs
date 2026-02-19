use std::time::Instant;

use anyhow::Result;
use log::{Level, LevelFilter};
use plonky2::{
	field::types::{Field, PrimeField64},
	iop::witness::{PartialWitness, WitnessWrite},
	plonk::{
		circuit_builder::CircuitBuilder,
		circuit_data::CircuitConfig,
		config::{GenericConfig, PoseidonGoldilocksConfig},
		prover::prove,
	},
	util::timing::TimingTree,
};
use sha2::{Digest, Sha256};
use tessera_trees::plonky2_gadgets::{
	sha256::{CircuitBuilderSha256, Sha256Luts},
	u32::{CircuitBuilderU32, U32Target},
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

fn pad_sha256_blocks(msg: &[u8]) -> Vec<[u32; 16]> {
	let bit_len = (msg.len() as u64) * 8;
	let mut data = msg.to_vec();
	data.push(0x80);
	while (data.len() + 8) % 64 != 0 {
		data.push(0);
	}
	data.extend_from_slice(&bit_len.to_be_bytes());

	data.chunks_exact(64)
		.map(|chunk| {
			let mut block = [0u32; 16];
			for (i, w) in block.iter_mut().enumerate() {
				let start = 4 * i;
				*w = u32::from_be_bytes(chunk[start..start + 4].try_into().unwrap());
			}
			block
		})
		.collect()
}

fn main() -> Result<()> {
	let mut logger = env_logger::Builder::from_default_env();
	logger.filter_level(LevelFilter::Debug);
	let _ = logger.try_init();
	let input_bytes: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
	let blocks = pad_sha256_blocks(&input_bytes);

	let expected_bytes = Sha256::digest(&input_bytes);
	let expected_words: [u32; 8] = core::array::from_fn(|i| {
		u32::from_be_bytes(expected_bytes[4 * i..4 * i + 4].try_into().unwrap())
	});

	let t_build = Instant::now();
	let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
	let luts = Sha256Luts::new(&mut builder, 8);

	let block_targets: Vec<[U32Target; 16]> = (0..blocks.len())
		.map(|_| core::array::from_fn(|_| builder.add_virtual_u32_target()))
		.collect();

	for block in &block_targets {
		for &word in block {
			builder.decompose_u32_to_bytes(word, luts.byte_range_lut);
		}
	}

	let hash = builder.sha256(&block_targets, &luts);
	for word in hash {
		builder.register_public_input(word.0);
	}

	let data = builder.build::<C>();
	let build_time = t_build.elapsed();

	let mut pw = PartialWitness::new();
	for (block_t, block) in block_targets.iter().zip(blocks.iter()) {
		for (t, w) in block_t.iter().zip(block.iter()) {
			pw.set_target(t.0, F::from_canonical_u32(*w))?;
		}
	}

	let mut timing = TimingTree::new("sha256_4096_prove", Level::Debug);
	let t_prove = Instant::now();
	let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
	let prove_time = t_prove.elapsed();
	timing.print();

	let t_verify = Instant::now();
	data.verify(proof.clone())?;
	let verify_time = t_verify.elapsed();

	for (i, exp) in expected_words.iter().enumerate() {
		let got = proof.public_inputs[i].to_canonical_u64() as u32;
		assert_eq!(got, *exp, "digest word {} mismatch", i);
	}

	println!("input bytes: {}", input_bytes.len());
	println!("blocks: {}", blocks.len());
	println!("build:   {:.3?}", build_time);
	println!("prove:   {:.3?}", prove_time);
	println!("verify:  {:.3?}", verify_time);
	println!("proof bytes: {}", proof.to_bytes().len());

	Ok(())
}
