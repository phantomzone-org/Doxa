use std::{array, sync::Arc};

use itertools::{Itertools, izip};
use plonky2::{
	hash::{
		hash_types::{HashOutTarget, NUM_HASH_OUT_ELTS, RichField},
		hashing::PlonkyPermutation,
		poseidon::{Poseidon, PoseidonHash, PoseidonPermutation},
	},
	iop::target::{BoolTarget, Target},
	plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use plonky2_field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field};

use crate::{
	DS_NULLIFIER_KEY, DS_PUBLIC_IDENTIFIER, NOTE_BATCH,
	p2::signature::{LocalPointEw, LocalQuinticExtension, PubkeyTarget, schnorr_verify_gadget},
};

// TODO: every related to main pool config tree

#[derive(Clone, Copy)]
struct SubpoolIdTarget(Target);

#[derive(Clone, Copy)]
struct PublicIdentifierTaregt(HashOutTarget);

#[derive(Clone, Copy)]
struct ConsumeCondTarget {
	subpool_id: SubpoolIdTarget,
	public_identifier: PublicIdentifierTaregt,
}

#[derive(Clone, Copy)]
struct RejectCondTarget {
	subpool_id: SubpoolIdTarget,
	public_identifier: PublicIdentifierTaregt,
}

#[derive(Clone, Copy)]
struct AccountTarget {
	private_identifier: [Target; 2],
	nonce: Target,
	subpool_id: Target,
	balance: [Target; 8],
	auth: PubkeyTarget<Target>,
}

struct AccCommitmentTarget(HashOutTarget);

struct NoteNullifierTarget(HashOutTarget);

#[derive(Clone, Copy)]
struct BalanceTarget([Target; 8]);

#[derive(Clone, Copy)]
struct NoteTarget {
	identifier: [Target; 2],
	amount: BalanceTarget,
	spend_cond: ConsumeCondTarget,
	reject_cond: RejectCondTarget,
}

struct PositionedNoteTargetWithProof {
	note: NoteTarget,
	position: Target,
}

struct NoteCommitmentTarget(HashOutTarget);

struct TxHashTarget(HashOutTarget);

impl AccountTarget {
	fn virtual_target<F: RichField + Extendable<D> + Poseidon, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
	) -> Self {
		Self {
			private_identifier: builder.add_virtual_target_arr(),
			nonce: builder.add_virtual_target(),
			subpool_id: builder.add_virtual_public_input(),
			balance: builder.add_virtual_target_arr(),
			auth: PubkeyTarget(LocalQuinticExtension(builder.add_virtual_target_arr())),
		}
	}
}

impl ConsumeCondTarget {
	fn virtual_target<F: RichField + Extendable<D> + Poseidon, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
	) -> Self {
		let subpool_id = SubpoolIdTarget(builder.add_virtual_target());
		let public_identifier = PublicIdentifierTaregt(builder.add_virtual_hash());

		Self {
			subpool_id,
			public_identifier,
		}
	}
}

impl RejectCondTarget {
	fn virtual_target<F: RichField + Extendable<D> + Poseidon, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
	) -> Self {
		let subpool_id = SubpoolIdTarget(builder.add_virtual_target());
		let public_identifier = PublicIdentifierTaregt(builder.add_virtual_hash());

		Self {
			subpool_id,
			public_identifier,
		}
	}
}

impl NoteTarget {
	fn virtual_target<F: RichField + Extendable<D> + Poseidon, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
	) -> Self {
		let identifier = builder.add_virtual_target_arr();
		let amount = BalanceTarget(builder.add_virtual_target_arr());
		let spend_cond = ConsumeCondTarget::virtual_target(builder);
		let reject_cond = RejectCondTarget::virtual_target(builder);

		NoteTarget {
			identifier,
			amount,
			spend_cond,
			reject_cond,
		}
	}
}

fn note_comm_gadget<F: RichField + Extendable<D> + Poseidon, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
	note: NoteTarget,
) -> NoteCommitmentTarget {
	todo!()
}

fn note_nulllifer_gadget<F: RichField + Extendable<D> + Poseidon, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
	nc: NoteCommitmentTarget,
	private_identifier: [Target; 2],
	ds_nullifier_key: Target,
) -> NoteNullifierTarget {
	let mut input0 = vec![ds_nullifier_key];
	input0.extend(private_identifier);
	let nk = builder.hash_n_to_hash_no_pad::<PoseidonHash>(input0);

	let mut input1 = nk.elements.to_vec();
	input1.extend(nc.0.elements);
	let nullifier = builder.hash_n_to_hash_no_pad::<PoseidonHash>(input1);

	NoteNullifierTarget(nullifier)
}

fn tx_hash_gadget<F: RichField + Extendable<D> + Poseidon, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
	inote_nulls: [NoteNullifierTarget; NOTE_BATCH],
) -> TxHashTarget {
	// Start with the 8 leaves.
	let mut level: Vec<HashOutTarget> = inote_nulls.iter().map(|n| n.0).collect();

	// Reduce by pairing adjacent nodes until one root remains.
	while level.len() > 1 {
		level = level
			.chunks_exact(2)
			.map(|pair| {
				let input: Vec<Target> = pair[0]
					.elements
					.iter()
					.chain(pair[1].elements.iter())
					.copied()
					.collect();
				builder.hash_n_to_hash_no_pad::<PoseidonHash>(input)
			})
			.collect();
	}

	TxHashTarget(level[0])
}

fn tx_circuit<F: RichField + Extendable<D> + Poseidon, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
	acc_point_offset: LocalPointEw<F>,
) {
	// Mint constants
	let ds_nullifier_key = builder.constant(F::from_canonical_u64(DS_NULLIFIER_KEY));
	let ds_public_identifier = builder.constant(F::from_canonical_u64(DS_PUBLIC_IDENTIFIER));

	let accin = AccountTarget::virtual_target(builder);
	let public_identifier = {
		let mut input = vec![ds_public_identifier];
		input.extend(accin.private_identifier);
		let pubid = builder.hash_n_to_hash_no_pad::<PoseidonHash>(input);
		PublicIdentifierTaregt(pubid)
	};

	let inotes: [NoteTarget; NOTE_BATCH] =
		core::array::from_fn(|_| NoteTarget::virtual_target(builder));
	let inote_active_sels: [BoolTarget; NOTE_BATCH] =
		array::from_fn(|_| builder.add_virtual_bool_target_safe());
	let nct_root = builder.add_virtual_hash();

	let inote_merkle_proofs: [MerkleTargets; NOTE_BATCH] =
		array::from_fn(|i| merkle_verify_gadget(builder, nct_root, inote_active_sels[i]));
	let inotes_comm = inotes.map(|n| note_comm_gadget(builder, n));

	// connect note commitment with leaf of merkle proofs
	for (proof, comm) in izip!(inote_merkle_proofs.iter(), inotes_comm.iter()) {
		for i in 0..NUM_HASH_OUT_ELTS {
			builder.connect(proof.leaf[i], comm.0.elements[i]);
		}
	}

	let inote_nulls = inotes_comm
		.map(|nc| note_nulllifer_gadget(builder, nc, accin.private_identifier, ds_nullifier_key));

	// connect inote spend condition with account
	inotes.iter().for_each(|note| {
		builder.connect_array(
			note.spend_cond.public_identifier.0.elements,
			public_identifier.0.elements,
		);
		builder.connect(note.spend_cond.subpool_id.0, accin.subpool_id);
	});

	// Validate auth from the user
	let tx_hash = tx_hash_gadget(builder, inote_nulls);
	let auth_schnorr_target = schnorr_verify_gadget(builder, tx_hash.0, accin.auth);

	// TODO: set inote_nulls are PIs
}

pub fn acc_comm_gadget<F: RichField + Extendable<D> + Poseidon, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
	account: AccountTarget,
	public_identifier: PublicIdentifierTaregt,
) -> AccCommitmentTarget {
	let inode0: [Target; 3] = [
		account.private_identifier[0],
		account.private_identifier[1],
		account.nonce,
	];
	let node0 = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inode0.to_vec());

	let mut inode1 = account.balance.to_vec();
	inode1.extend(account.auth.0.0);
	let node1 = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inode1);

	let mut inode2 = public_identifier.0.elements.to_vec();
	inode2.push(account.subpool_id);
	let node2 = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inode2);

	let node3 = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
		node0
			.elements
			.into_iter()
			.chain(node1.elements.into_iter())
			.collect(),
	);

	let acc_comm = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
		node3
			.elements
			.into_iter()
			.chain(node2.elements.into_iter())
			.collect(),
	);

	AccCommitmentTarget(acc_comm)
}

pub struct MerkleTargets {
	pub leaf: [Target; 4],
	pub siblings: [[Target; 4]; 32],
	pub bits: [Target; 32],
	pub computed_root: [Target; 4],
}

/// Builds a depth-32 Merkle path verification gadget using the existing
/// PoseidonGate.
///
/// Each of the 32 levels adds one `PoseidonGate` via
/// `PoseidonHash::permute_swapped`. The gate's built-in SWAP wire handles
/// left/right child ordering: when `bit=0` the node is the left child, when
/// `bit=1` the node is the right child.
///
/// After all 32 levels, if `selector=1` the computed root is constrained to
/// equal `expected_root`; if `selector=0` no equality is enforced.
pub fn merkle_verify_gadget<F: RichField + Extendable<D> + Poseidon, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
	expected_root: HashOutTarget,
	selector: BoolTarget,
) -> MerkleTargets {
	let leaf: [Target; 4] = core::array::from_fn(|_| builder.add_virtual_target());

	let mut current: [Target; 4] = leaf;
	let mut siblings: [[Target; 4]; 32] = [[builder.zero(); 4]; 32];
	let mut bits: [Target; 32] = [builder.zero(); 32];

	for level in 0..32 {
		let sibling: [Target; 4] = core::array::from_fn(|_| builder.add_virtual_target());
		let bit = builder.add_virtual_bool_target_safe();

		// Build the 12-element Poseidon input:
		//   [current[0..4] || sibling[0..4] || zero[0..4]]
		// PoseidonGate SWAP will swap the first 4 with the next 4 when bit=1,
		// so the permutation always receives [left || right || zeros].
		let zero = builder.zero();
		let perm_inputs = PoseidonPermutation::new(
			current
				.iter()
				.chain(sibling.iter())
				.copied()
				.chain(core::iter::repeat(zero).take(4)),
		);

		let perm_output = PoseidonHash::permute_swapped(perm_inputs, bit, builder);
		let output = perm_output.squeeze();

		let parent: [Target; 4] = core::array::from_fn(|i| output[i]);

		siblings[level] = sibling;
		bits[level] = bit.target;
		current = parent;
	}

	let computed_root = current;

	// Selector-gated root equality: selector * (computed_root[i] -
	// expected_root[i]) = 0
	for i in 0..4 {
		let diff = builder.sub(computed_root[i], expected_root.elements[i]);
		let product = builder.mul(selector.target, diff);
		builder.assert_zero(product);
	}

	MerkleTargets {
		leaf,
		siblings,
		bits,
		computed_root,
	}
}

#[cfg(test)]
mod tests {
	use plonky2::{
		hash::{hash_types::HashOut, poseidon::PoseidonHash},
		iop::witness::{PartialWitness, WitnessWrite},
		plonk::{
			circuit_data::CircuitConfig,
			config::{GenericConfig, PoseidonGoldilocksConfig},
		},
	};
	use plonky2_field::{goldilocks_field::GoldilocksField, types::Field};

	use super::*;

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = <C as GenericConfig<D>>::F;

	/// Build a depth-32 Merkle tree from a leaf and return the root along with
	/// the sibling and bit arrays for the path at index 0 (all bits = 0 means
	/// the target leaf is always the left child at every level).
	fn build_merkle_path(leaf: HashOut<F>) -> (HashOut<F>, [HashOut<F>; 32], [bool; 32]) {
		// All siblings are a fixed non-zero hash so the tree is non-trivial.
		let sibling_val = HashOut {
			elements: [
				GoldilocksField::from_canonical_u64(0xdeadbeef),
				GoldilocksField::from_canonical_u64(0xcafebabe),
				GoldilocksField::from_canonical_u64(0x12345678),
				GoldilocksField::from_canonical_u64(0xabcdef01),
			],
		};

		// Index 0 → all bits = 0 (leaf is always the left child).
		let bits = [false; 32];
		let siblings = [sibling_val; 32];

		let mut current = leaf;
		for i in 0..32 {
			// bit=0 means current is left child
			current = <PoseidonHash as plonky2::plonk::config::Hasher<F>>::two_to_one(
				current,
				siblings[i],
			);
		}

		(current, siblings, bits)
	}

	#[test]
	fn test_merkle_gadget_valid() {
		let leaf_elements = [
			GoldilocksField::from_canonical_u64(1),
			GoldilocksField::from_canonical_u64(2),
			GoldilocksField::from_canonical_u64(3),
			GoldilocksField::from_canonical_u64(4),
		];
		let leaf = HashOut {
			elements: leaf_elements,
		};

		let (root, siblings, bits) = build_merkle_path(leaf);

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let expected_root_targets = builder.add_virtual_hash();
		let selector = builder.add_virtual_bool_target_safe();
		let targets = merkle_verify_gadget::<F, D>(&mut builder, expected_root_targets, selector);

		let data = builder.build::<C>();

		let mut pw = PartialWitness::new();

		// Set leaf
		for i in 0..4 {
			pw.set_target(targets.leaf[i], leaf_elements[i]).unwrap();
		}
		// Set siblings and bits
		for level in 0..32 {
			for i in 0..4 {
				pw.set_target(targets.siblings[level][i], siblings[level].elements[i])
					.unwrap();
			}
			pw.set_bool_target(BoolTarget::new_unsafe(targets.bits[level]), bits[level])
				.unwrap();
		}
		// Set expected root = computed root
		for i in 0..4 {
			pw.set_target(expected_root_targets.elements[i], root.elements[i])
				.unwrap();
		}
		pw.set_bool_target(selector, true).unwrap();

		let proof = data.prove(pw).expect("prove failed");
		data.verify(proof).expect("verify failed");
	}

	#[test]
	fn test_merkle_gadget_selector_off() {
		let leaf_elements = [
			GoldilocksField::from_canonical_u64(1),
			GoldilocksField::from_canonical_u64(2),
			GoldilocksField::from_canonical_u64(3),
			GoldilocksField::from_canonical_u64(4),
		];
		let leaf = HashOut {
			elements: leaf_elements,
		};
		let (_, siblings, bits) = build_merkle_path(leaf);

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let expected_root_targets = builder.add_virtual_hash();
		let selector = builder.add_virtual_bool_target_safe();
		let targets = merkle_verify_gadget::<F, D>(&mut builder, expected_root_targets, selector);

		let data = builder.build::<C>();
		let mut pw = PartialWitness::new();

		for i in 0..4 {
			pw.set_target(targets.leaf[i], leaf_elements[i]).unwrap();
		}
		for level in 0..32 {
			for i in 0..4 {
				pw.set_target(targets.siblings[level][i], siblings[level].elements[i])
					.unwrap();
			}
			pw.set_bool_target(BoolTarget::new_unsafe(targets.bits[level]), bits[level])
				.unwrap();
		}

		// Wrong expected root — but selector = 0, so no equality is enforced.
		let wrong_root = [
			GoldilocksField::from_canonical_u64(0xbad),
			GoldilocksField::from_canonical_u64(0xbad),
			GoldilocksField::from_canonical_u64(0xbad),
			GoldilocksField::from_canonical_u64(0xbad),
		];
		for i in 0..4 {
			pw.set_target(expected_root_targets.elements[i], wrong_root[i])
				.unwrap();
		}
		pw.set_bool_target(selector, false).unwrap();

		let proof = data.prove(pw).expect("prove failed");
		data.verify(proof).expect("verify failed");
	}

	#[test]
	fn test_merkle_gadget_wrong_root_selector_on() {
		let leaf_elements = [
			GoldilocksField::from_canonical_u64(1),
			GoldilocksField::from_canonical_u64(2),
			GoldilocksField::from_canonical_u64(3),
			GoldilocksField::from_canonical_u64(4),
		];
		let leaf = HashOut {
			elements: leaf_elements,
		};
		let (_, siblings, bits) = build_merkle_path(leaf);

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let expected_root_targets = builder.add_virtual_hash();
		let selector = builder.add_virtual_bool_target_safe();
		let targets = merkle_verify_gadget::<F, D>(&mut builder, expected_root_targets, selector);

		let data = builder.build::<C>();
		let mut pw = PartialWitness::new();

		for i in 0..4 {
			pw.set_target(targets.leaf[i], leaf_elements[i]).unwrap();
		}
		for level in 0..32 {
			for i in 0..4 {
				pw.set_target(targets.siblings[level][i], siblings[level].elements[i])
					.unwrap();
			}
			pw.set_bool_target(BoolTarget::new_unsafe(targets.bits[level]), bits[level])
				.unwrap();
		}

		// Wrong expected root with selector = 1 — must fail.
		let wrong_root = [
			GoldilocksField::from_canonical_u64(0xbad),
			GoldilocksField::from_canonical_u64(0xbad),
			GoldilocksField::from_canonical_u64(0xbad),
			GoldilocksField::from_canonical_u64(0xbad),
		];
		for i in 0..4 {
			pw.set_target(expected_root_targets.elements[i], wrong_root[i])
				.unwrap();
		}
		pw.set_bool_target(selector, true).unwrap();

		assert!(
			data.prove(pw).is_err(),
			"Expected proof to fail with wrong root and selector=1"
		);
	}
}
