use plonky2::hash::hash_types::RichField;
use tiny_keccak::keccakf;

pub(crate) const BLOCK_SIZE: usize = 136 / 4;

/// Computes the keccak256 hash according to the Solidity specification.
/// Both input and output are in big-endian format.
pub fn solidity_keccak256(input: &[u32]) -> [u32; 8] {
	let input = input
		.iter()
		.map(|v| u32::from_le_bytes(v.to_be_bytes()))
		.collect::<Vec<_>>();
	let result = keccak256(input);

	result.output.map(|v| u32::from_be_bytes(v.to_le_bytes()))
}

/// Computes Keccak-256 of field elements outside the circuit.
///
/// Each element is encoded as its canonical big-endian 8-byte representation
/// (identical to the encoding used by `sha256_field_elements_native`).
/// Returns the 8-word digest in big-endian word order.
///
/// The output matches `keccak256(abi.encodePacked(fields))` in Solidity
/// when each field element maps to one `uint64` big-endian word.
pub fn keccak256_field_elements_native<F: RichField>(input: &[F]) -> [u32; 8] {
	let mut u32_words = Vec::with_capacity(input.len() * 2);
	for &elem in input {
		let val = elem.to_canonical_u64();
		u32_words.push((val >> 32) as u32); // high 32 bits
		u32_words.push(val as u32); // low 32 bits
	}
	solidity_keccak256(&u32_words)
}

/// Same as `solidity_keccak256` but with perm IOs.
pub(crate) fn solidity_keccak256_with_perm_io(
	input: &[u32],
) -> ([u32; 8], Vec<Vec<u32>>, Vec<Vec<u32>>) {
	let input = input
		.iter()
		.map(|v| u32::from_le_bytes(v.to_be_bytes()))
		.collect::<Vec<_>>();
	let result = keccak256(input);
	let output = result.output.map(|v| u32::from_be_bytes(v.to_le_bytes()));
	(output, result.perm_inputs, result.perm_outputs)
}

pub(crate) struct Keccak256Result<T: Copy + Clone + Default> {
	pub(crate) output: [T; 8],
	pub(crate) perm_inputs: Vec<Vec<T>>,
	pub(crate) perm_outputs: Vec<Vec<T>>,
}

fn keccak256(input: Vec<u32>) -> Keccak256Result<u32> {
	let mut perm_inputs = vec![];
	let mut perm_outputs = vec![];
	let num_blocks = input.len() / BLOCK_SIZE + 1;
	let mut padded = vec![0u32; BLOCK_SIZE * num_blocks];
	padded[0..input.len()].copy_from_slice(&input);
	padded[input.len()] = 0x01;
	*padded.last_mut().unwrap() ^= 0x80 << 24;
	let mut state = [0u32; 50];
	for i in 0..num_blocks {
		for j in 0..BLOCK_SIZE {
			state[j] ^= padded[i * BLOCK_SIZE + j];
		}
		let output = keccakf_u32(state);
		perm_inputs.push(state.to_vec());
		perm_outputs.push(output.to_vec());
		state = output;
	}
	Keccak256Result {
		output: state[0..8].try_into().unwrap(),
		perm_inputs,
		perm_outputs,
	}
}

/// Apply keccakf to an array of u32s. Treat input and output as little endian.
fn keccakf_u32(input: [u32; 50]) -> [u32; 50] {
	let mut state = input
		.chunks(2)
		.map(|chunk| chunk[0] as u64 + ((chunk[1] as u64) << 32))
		.collect::<Vec<_>>()
		.try_into()
		.unwrap();
	keccakf(&mut state);
	let output = state
		.iter()
		.flat_map(|&x| vec![x as u32, (x >> 32) as u32])
		.collect::<Vec<_>>();
	output.try_into().unwrap()
}
