/// Generates test vectors for a Solidity Poseidon Goldilocks compression function.
///
/// The compression function matches plonky2's `compress`:
///   state[0..4]  = left  (4 Goldilocks elements)
///   state[4..8]  = right (4 Goldilocks elements)
///   state[8..12] = 0
///   Apply Poseidon permutation
///   output = state[0..4]
///
/// Each u256 packs 4 field elements in little-limb order:
///   u256 = el[0] | (el[1] << 64) | (el[2] << 128) | (el[3] << 192)
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::{
	field::types::{Field, Field64, PrimeField64},
	hash::{hash_types::HashOut, hashing::compress, poseidon::PoseidonPermutation},
};

type F = GoldilocksField;

/// Pack 4 Goldilocks field elements into a u256 hex string (little-limb order).
fn pack_u256(elements: &[F; 4]) -> String {
	let mut bytes = [0u8; 32];
	for (i, &el) in elements.iter().enumerate() {
		let val = el.to_canonical_u64();
		bytes[i * 8..(i + 1) * 8].copy_from_slice(&val.to_le_bytes());
	}
	// Reverse to get big-endian for hex display (Solidity convention)
	bytes.reverse();
	format!("0x{}", hex::encode(bytes))
}

fn run_test_case(name: &str, left: HashOut<F>, right: HashOut<F>) {
	let output = compress::<F, PoseidonPermutation<F>>(left, right);

	println!("// Test case: {}", name);
	println!(
		"// left  elements: [{:#018x}, {:#018x}, {:#018x}, {:#018x}]",
		left.elements[0].to_canonical_u64(),
		left.elements[1].to_canonical_u64(),
		left.elements[2].to_canonical_u64(),
		left.elements[3].to_canonical_u64()
	);
	println!(
		"// right elements: [{:#018x}, {:#018x}, {:#018x}, {:#018x}]",
		right.elements[0].to_canonical_u64(),
		right.elements[1].to_canonical_u64(),
		right.elements[2].to_canonical_u64(),
		right.elements[3].to_canonical_u64()
	);
	println!(
		"// out   elements: [{:#018x}, {:#018x}, {:#018x}, {:#018x}]",
		output.elements[0].to_canonical_u64(),
		output.elements[1].to_canonical_u64(),
		output.elements[2].to_canonical_u64(),
		output.elements[3].to_canonical_u64()
	);

	let left_u256 = pack_u256(&left.elements);
	let right_u256 = pack_u256(&right.elements);
	let output_u256 = pack_u256(&output.elements);

	println!("bytes32 left  = {};", left_u256);
	println!("bytes32 right = {};", right_u256);
	println!("bytes32 out   = {};", output_u256);
	println!();
}

fn main() {
	let p = GoldilocksField::ORDER;
	println!("// Goldilocks prime p = {:#018x}", p);
	println!("// p = 2^64 - 2^32 + 1 = {}", p);
	println!();

	// Test case 1: all zeros
	run_test_case(
		"all zeros",
		HashOut {
			elements: [F::ZERO; 4],
		},
		HashOut {
			elements: [F::ZERO; 4],
		},
	);

	// Test case 2: sequential small values
	run_test_case(
		"sequential 0..7",
		HashOut {
			elements: [
				F::from_canonical_u64(0),
				F::from_canonical_u64(1),
				F::from_canonical_u64(2),
				F::from_canonical_u64(3),
			],
		},
		HashOut {
			elements: [
				F::from_canonical_u64(4),
				F::from_canonical_u64(5),
				F::from_canonical_u64(6),
				F::from_canonical_u64(7),
			],
		},
	);

	// Test case 3: max values (p-1)
	let p_minus_1 = p - 1;
	run_test_case(
		"all p-1 (max field element)",
		HashOut {
			elements: [F::from_canonical_u64(p_minus_1); 4],
		},
		HashOut {
			elements: [F::from_canonical_u64(p_minus_1); 4],
		},
	);

	// Test case 4: large random-looking values
	run_test_case(
		"large random values",
		HashOut {
			elements: [
				F::from_canonical_u64(0x8ccbbbea4fe5d2b7),
				F::from_canonical_u64(0xc2af59ee9ec49970),
				F::from_canonical_u64(0x90f7e1a9e658446a),
				F::from_canonical_u64(0xdcc0630a3ab8b1b8),
			],
		},
		HashOut {
			elements: [
				F::from_canonical_u64(0x7ff8256bca20588c),
				F::from_canonical_u64(0x5d99a7ca0c44ecfb),
				F::from_canonical_u64(0x48452b17a70fbee3),
				F::from_canonical_u64(0xeb09d654690b6c88),
			],
		},
	);
}
