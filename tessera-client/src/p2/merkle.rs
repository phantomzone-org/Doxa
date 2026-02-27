use std::{
	array,
	hash::{BuildHasherDefault, Hash},
	sync::Arc,
};

use itertools::{Itertools, izip};
use plonky2::{
	hash::{
		hash_types::{HashOutTarget, NUM_HASH_OUT_ELTS, RichField},
		hashing::PlonkyPermutation,
		poseidon::{Poseidon, PoseidonHash, PoseidonPermutation},
	},
	iop::{
		generator::{GeneratedValues, SimpleGenerator},
		target::{BoolTarget, Target},
		witness::{PartitionWitness, Witness, WitnessWrite},
	},
	plonk::{
		circuit_builder::CircuitBuilder, circuit_data::CommonCircuitData, config::AlgebraicHasher,
	},
	util::serialization::{Buffer, IoResult, Read as _, Write as _},
};
use plonky2_field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field};
use rand::seq::index::IndexVecIntoIter;
use tessera_trees::{
	plonky2_gadgets::u32::gadgets::{
		CircuitBuilderU32, CircuitBuilderU32Arithmetic, U32Target, add_u8_range_check_lookup_table,
	},
	tree::HASH_SIZE,
};

use crate::{
	ACC_AST_DEPTH, ACT_DEPTH, AST_DEFAULT_LEAF, DS_ACC_AST, DS_NULLIFIER_KEY, DS_PUBLIC_IDENTIFIER,
	NCT_DEPTH, NOTE_BATCH,
	p2::{
		signature::{
			LocalPointEw, LocalQuinticExtension, PubkeyTarget, conditional_schnorr_verify_gadget,
		},
		u256::{CircuitBuilderU256, U256Target},
	},
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
	private_identifier: PrivateIdentifierTarget,
	nonce: Target,
	subpool_id: Target,
	acc_ast_root: HashOutTarget,
	auth: PubkeyTarget<Target>,
}

struct AccCommitmentTarget(HashOutTarget);

struct NoteNullifierTarget(HashOutTarget);

#[derive(Clone, Copy)]
struct BalanceTarget([Target; 8]);

#[derive(Clone, Copy)]
struct NoteTarget {
	identifier: [Target; 2],
	amount: U256Target,
	spend_cond: ConsumeCondTarget,
	reject_cond: RejectCondTarget,
}

#[derive(Clone, Copy)]
struct DummyNoteTarget([Target; 4]);

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
			acc_ast_root: builder.add_virtual_target_arr(),
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
		let amount = builder.add_virtual_u256_target();
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

#[derive(Clone, Copy)]
struct AccountNullifierTarget(HashOutTarget);
#[derive(Clone, Copy)]
struct AccountCommitmentTarget(HashOutTarget);

#[derive(Clone, Copy)]
struct NullifierKeyTarget(HashOutTarget);
#[derive(Clone, Copy)]
struct PrivateIdentifierTarget([Target; 2]);

struct ActMerkleTarget(MerkleTargets<ACT_DEPTH>);
struct ActRootTarget(HashOutTarget);
struct NctRootTarget(HashOutTarget);

#[derive(Clone, Copy)]
struct DummyAccountTarget([Target; 4]);

#[derive(Clone, Copy)]
struct DummyAccountCommitment(HashOutTarget);
#[derive(Clone, Copy)]
struct DummyAccountNullifier(HashOutTarget);

pub trait LocalCB {
	fn add_virtual_dummy_note_target(&mut self) -> DummyNoteTarget;

	fn derive_account_commitment(&mut self, acc: AccountTarget) -> AccountCommitmentTarget;
	fn derive_account_nullifier(
		&mut self,
		acc: AccountCommitmentTarget,
		pos: Target,
		nk: NullifierKeyTarget,
	) -> AccountNullifierTarget;
	fn derive_dummy_account_commitment(
		&mut self,
		dacc: DummyAccountTarget,
	) -> DummyAccountCommitment;
	fn derive_dummy_account_nullifier(&mut self, dacc: DummyAccountTarget)
	-> DummyAccountNullifier;
	fn conditionally_assert_account_commitment_exists_in_act(
		&mut self,
		acc_comm: AccountCommitmentTarget,
		act_root: ActRootTarget,
		condition: BoolTarget,
	) -> ActMerkleTarget;

	fn derive_note_commitment(&mut self, note: NoteTarget) -> NoteCommitmentTarget;
	fn derive_note_nullifier(
		&mut self,
		nc: NoteCommitmentTarget,
		pos: Target,
		nk: NullifierKeyTarget,
	) -> NoteNullifierTarget;
	fn derive_dummy_note_nullifier(&mut self, dnote: DummyNoteTarget) -> NoteNullifierTarget;
	fn derive_dummy_note_commitment(&mut self, dnote: DummyNoteTarget) -> NoteCommitmentTarget;

	fn derive_nullifier_key(&mut self, priv_id: PrivateIdentifierTarget) -> NullifierKeyTarget;

	fn derive_tx_hash(
		&mut self,
		inote_nulls: [NoteNullifierTarget; NOTE_BATCH],
		onote_comms: [NoteCommitmentTarget; NOTE_BATCH],
		accin_null: AccountNullifierTarget,
		accout_comm: AccountCommitmentTarget,
	);
}

fn double_hash<F: RichField + Extendable<D>, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
	input: [Target; HASH_SIZE],
) -> HashOutTarget {
	let input = input.to_vec();
	let out0 = builder.hash_n_to_hash_no_pad::<PoseidonHash>(input);
	let out1 = builder.hash_n_to_hash_no_pad::<PoseidonHash>(out0.elements.to_vec());
	out1
}

impl<F: RichField + Extendable<D>, const D: usize> LocalCB for CircuitBuilder<F, D> {
	fn add_virtual_dummy_note_target(&mut self) -> DummyNoteTarget {
		todo!()
	}

	fn derive_account_commitment(&mut self, acc: AccountTarget) -> AccountCommitmentTarget {
		todo!()
	}

	fn conditionally_assert_account_commitment_exists_in_act(
		&mut self,
		acc_comm: AccountCommitmentTarget,
		act_root: ActRootTarget,
		condition: BoolTarget,
	) -> ActMerkleTarget {
		let merkletargets = merkle_verify_gadget::<F, D, ACT_DEPTH>(self, act_root.0, condition);

		// leaf is acc_comm
		izip!(merkletargets.leaf, acc_comm.0.elements).for_each(|(l, r)| {
			self.connect(l, r);
		});

		// root is acc_root
		izip!(merkletargets.computed_root, act_root.0.elements).for_each(|(l, r)| {
			self.connect(l, r);
		});

		ActMerkleTarget(merkletargets)
	}

	fn derive_account_nullifier(
		&mut self,
		acc: AccountCommitmentTarget,
		pos: Target,
		nk: NullifierKeyTarget,
	) -> AccountNullifierTarget {
		todo!()
	}

	fn derive_dummy_account_commitment(
		&mut self,
		dacc: DummyAccountTarget,
	) -> DummyAccountCommitment {
		DummyAccountCommitment(double_hash(self, dacc.0))
	}

	fn derive_dummy_account_nullifier(
		&mut self,
		dacc: DummyAccountTarget,
	) -> DummyAccountNullifier {
		DummyAccountNullifier(double_hash(self, dacc.0))
	}

	fn derive_note_commitment(&mut self, note: NoteTarget) -> NoteCommitmentTarget {
		todo!()
	}

	fn derive_note_nullifier(
		&mut self,
		nc: NoteCommitmentTarget,
		pos: Target,
		nk: NullifierKeyTarget,
	) -> NoteNullifierTarget {
		let mut input = nc.0.elements.to_vec();
		input.push(pos);
		input.extend_from_slice(nk.0.elements.as_ref());
		let nullifier = self.hash_n_to_hash_no_pad::<PoseidonHash>(input);
		NoteNullifierTarget(nullifier)
	}

	fn derive_nullifier_key(&mut self, priv_id: PrivateIdentifierTarget) -> NullifierKeyTarget {
		let mut input = vec![self.constant(F::from_canonical_u64(DS_NULLIFIER_KEY))];
		input.extend(priv_id.0);
		NullifierKeyTarget(self.hash_n_to_hash_no_pad::<PoseidonHash>(input))
	}

	fn derive_dummy_note_nullifier(&mut self, dnote: DummyNoteTarget) -> NoteNullifierTarget {
		NoteNullifierTarget(double_hash(self, dnote.0))
	}

	fn derive_dummy_note_commitment(&mut self, dnote: DummyNoteTarget) -> NoteCommitmentTarget {
		NoteCommitmentTarget(double_hash(self, dnote.0))
	}

	fn derive_tx_hash(
		&mut self,
		inote_nulls: [NoteNullifierTarget; NOTE_BATCH],
		onote_comms: [NoteCommitmentTarget; NOTE_BATCH],
		accin_null: AccountNullifierTarget,
		accout_comm: AccountCommitmentTarget,
	) {
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
					self.hash_n_to_hash_no_pad::<PoseidonHash>(input)
				})
				.collect();
		}

		todo!()
	}
}

#[derive(Debug, Clone, Copy)]
struct AssetIdTarget(pub Target);
struct AstMerkleTargets(MerkleTargets<ACC_AST_DEPTH>);

fn assert_asset_amt_or_default_in_ast<F: RichField + Extendable<D> + Poseidon, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
	asset_id: AssetIdTarget,
	amt: U256Target,
	acc: AccountTarget,
	selector: BoolTarget,
) -> AstMerkleTargets {
	let merkletargets =
		merkle_verify_gadget::<F, D, ACC_AST_DEPTH>(builder, acc.acc_ast_root, selector);

	// derive asset leaf
	let leaf = {
		let mut inputs: [Target; 10] = builder.add_virtual_target_arr();
		inputs[0] = builder.constant(F::from_canonical_u64(DS_ACC_AST));
		inputs[1] = asset_id.0;
		inputs[2..].copy_from_slice(amt.0.map(|t| t.0).as_slice());
		builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs.to_vec())
	};
	let default_leaf: [Target; HASH_SIZE] =
		array::from_fn(|i| builder.constant(F::from_canonical_u64(AST_DEFAULT_LEAF[i])));
	let exists_or_default: [Target; HASH_SIZE] =
		array::from_fn(|i| builder._if(selector, leaf.elements[i], default_leaf[i]));
	izip!(merkletargets.leaf.iter(), exists_or_default.iter()).for_each(|(a, b)| {
		builder.connect(*a, *b);
	});

	AstMerkleTargets(merkletargets)
}

fn assert_asset_amt_in_ast<F: RichField + Extendable<D> + Poseidon, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
	asset_id: AssetIdTarget,
	amt: U256Target,
	acc: AccountTarget,
) -> AstMerkleTargets {
	let tr = builder._true();
	let merkletargets = merkle_verify_gadget::<F, D, ACC_AST_DEPTH>(builder, acc.acc_ast_root, tr);

	// derive asset leaf
	let leaf = {
		let mut inputs: [Target; 10] = builder.add_virtual_target_arr();
		inputs[0] = builder.constant(F::from_canonical_u64(DS_ACC_AST));
		inputs[1] = asset_id.0;
		inputs[2..].copy_from_slice(amt.0.map(|t| t.0).as_slice());
		builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs.to_vec())
	};
	izip!(merkletargets.leaf.iter(), leaf.elements.iter()).for_each(|(a, b)| {
		builder.connect(*a, *b);
	});

	AstMerkleTargets(merkletargets)
}

fn tx_circuit<F: RichField + Extendable<D> + Poseidon, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
	acc_point_offset: LocalPointEw<F>,
) {
	// Mint constants
	let ds_nullifier_key = builder.constant(F::from_canonical_u64(DS_NULLIFIER_KEY));
	let ds_public_identifier = builder.constant(F::from_canonical_u64(DS_PUBLIC_IDENTIFIER));

	let zero = builder.zero();
	let tr = builder._true();

	let is_rjct = builder.add_virtual_bool_target_safe();

	let act_root = ActRootTarget(builder.add_virtual_hash());
	let nct_root = NctRootTarget(builder.add_virtual_hash());

	let asset_id = AssetIdTarget(builder.add_virtual_target());
	let accin_amt = builder.add_virtual_u256_target();
	let asset_exists_in_accin = builder.add_virtual_bool_target_safe();
	let accout_amt = builder.add_virtual_u256_target();

	let is_accin_fresh = builder.add_virtual_bool_target_safe();
	let accin = AccountTarget::virtual_target(builder);
	let accout = AccountTarget::virtual_target(builder);
	let public_identifier = {
		let mut input = vec![ds_public_identifier];
		input.extend(accin.private_identifier.0);
		let pubid = builder.hash_n_to_hash_no_pad::<PoseidonHash>(input);
		PublicIdentifierTaregt(pubid)
	};
	let nk = builder.derive_nullifier_key(accin.private_identifier);

	// Check AccIn commitment exists in the ACT
	let accin_comm = builder.derive_account_commitment(accin);
	let accin_pos = builder.add_virtual_target();
	let accin_merkletrgts = builder.conditionally_assert_account_commitment_exists_in_act(
		accin_comm,
		act_root,
		is_accin_fresh,
	);

	// AccIn nullifier
	let accin_null = builder.derive_account_nullifier(accin_comm, accin_pos, nk);

	// Dummy Acc commitment, nullifier
	let daccin = DummyAccountTarget(builder.add_virtual_target_arr());
	let daccout = DummyAccountTarget(builder.add_virtual_target_arr());

	// TODO: assert account is fresh
	//
	// AccountFresh
	// if account is fresh, then what things need to be chcked:
	//  - all values of the account are set to default
	//  - one should only be allowed to update the configuration of the account
	//  - if acc_fresh, then it's a new type of tx
	//
	// PrivateTrafer
	//      - for each inote:
	//          - Comm(inote) exists in NCT
	//          - Null(inote) is derived correctly
	//          - inote.spend_cond = AccIn
	//      - for each dinote:
	//          - Comm(dinote) is derived correctly
	//      - for each onote:
	//          - Comm(onote) is derived correctly
	//      - accin.amt + sum(inote) == accout.amt + sum(onote)
	//      - approval signature
	//      - if [onote].len > 0: user spend sig
	//      - if [inote].len > 0 && [onote].len == 0: consume sig
	//      - accin.public_identifier exists in MainCofigTree root
	//
	//

	// there exist no valid meklre path for any asset,amount if account is asserted to be
	// fresh. Because for a fresh account, AST root is asserted to be a default value, with no valid
	// merkle path for any asset,amount pair. Therefore, no need to check
	//  if is_fresh, accin_amt == 0

	// frocibly set amtin to be zero if asset_exists_in_accin is set to false
	let accin_amt = U256Target(array::from_fn(|i| {
		U32Target(builder._if(asset_exists_in_accin, accin_amt.0[i].0, zero))
	}));

	let accin_ast_merkletrgts = assert_asset_amt_or_default_in_ast(
		builder,
		asset_id,
		accin_amt,
		accin,
		asset_exists_in_accin,
	);
	let accout_ast_merkletrgts = assert_asset_amt_in_ast(builder, asset_id, accout_amt, accout);

	// assert that merkle path of AST proof in accin equals accout
	for i in 0..ACC_AST_DEPTH {
		builder.connect_array(
			accin_ast_merkletrgts.0.siblings[i],
			accout_ast_merkletrgts.0.siblings[i],
		);
		builder.connect(
			accin_ast_merkletrgts.0.bits[i],
			accout_ast_merkletrgts.0.bits[i],
		);
	}

	// TODO: all notes must have the same asset id
	let inotes: [NoteTarget; NOTE_BATCH] =
		core::array::from_fn(|_| NoteTarget::virtual_target(builder));
	let inotes_pos: [Target; NOTE_BATCH] = core::array::from_fn(|_| builder.add_virtual_target());
	let inote_isactive: [BoolTarget; NOTE_BATCH] =
		array::from_fn(|_| builder.add_virtual_bool_target_safe());
	let dinotes: [DummyNoteTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_dummy_note_target());

	let onotes: [NoteTarget; NOTE_BATCH] =
		core::array::from_fn(|_| NoteTarget::virtual_target(builder));
	let onote_isactive: [BoolTarget; NOTE_BATCH] =
		array::from_fn(|_| builder.add_virtual_bool_target_safe());
	let donotes: [DummyNoteTarget; NOTE_BATCH] =
		core::array::from_fn(|_| builder.add_virtual_dummy_note_target());

	// Note comms and they exist in NCT
	let inotes_comm = inotes.map(|n| builder.derive_note_commitment(n));
	let nct_root = builder.add_virtual_hash();
	let inote_merkle_proofs: [MerkleTargets<NCT_DEPTH>; NOTE_BATCH] =
		array::from_fn(|i| merkle_verify_gadget(builder, nct_root, inote_isactive[i]));

	// connect note commitment with leaf of merkle proofs
	for (proof, comm) in izip!(inote_merkle_proofs.iter(), inotes_comm.iter()) {
		for i in 0..HASH_SIZE {
			builder.connect(proof.leaf[i], comm.0.elements[i]);

			// root is NCT root
			builder.connect(proof.computed_root[i], nct_root.elements[i]);
		}
	}

	// note nullifiers
	let inote_nulls = inotes_comm
		.into_iter()
		.enumerate()
		.map(|(index, nc)| builder.derive_note_nullifier(nc, inotes_pos[index], nk))
		.collect_array()
		.unwrap();

	// dummy input note nullifier
	let dinote_nulls = dinotes.map(|dn| builder.derive_dummy_note_nullifier(dn));

	// output note comms
	let onote_comms = onotes.map(|n| builder.derive_note_commitment(n));
	let donote_comms = donotes.map(|dn| builder.derive_dummy_note_commitment(dn));

	// AccIn.amt + Sum([INote.amt]) == AccOut.amt + Sum([ONote.amt])
	let inote_amts: [U256Target; NOTE_BATCH] = array::from_fn(|i| {
		U256Target(array::from_fn(|j| {
			U32Target(builder._if(inote_isactive[i], inotes[i].amount.0[j].0, zero))
		}))
	});
	let onote_amts: [U256Target; NOTE_BATCH] = array::from_fn(|i| {
		U256Target(array::from_fn(|j| {
			U32Target(builder._if(onote_isactive[i], onotes[i].amount.0[j].0, zero))
		}))
	});

	let u8rngchk_lut = add_u8_range_check_lookup_table(builder);
	let accinamt_sum_inoteamts = builder.u256_addition_chain(&accin_amt, &inote_amts, u8rngchk_lut);
	let accoutamt_sum_onoteamts =
		builder.u256_addition_chain(&accout_amt, &onote_amts, u8rngchk_lut);
	builder.connect_u256(&accinamt_sum_inoteamts, &accoutamt_sum_onoteamts);

	// connect inote spend condition with account
	inotes.iter().for_each(|note| {
		builder.connect_array(
			note.spend_cond.public_identifier.0.elements,
			public_identifier.0.elements,
		);
		builder.connect(note.spend_cond.subpool_id.0, accin.subpool_id);
	});

	// derive tx hash
	// select valid inote nullifiers, onote commitments as per respective active selectors
	let act_inotenulls = array::from_fn(|i| {
		NoteNullifierTarget(HashOutTarget {
			elements: array::from_fn(|j| {
				builder._if(
					inote_isactive[i],
					inote_nulls[i].0.elements[j],
					dinote_nulls[i].0.elements[j],
				)
			}),
		})
	});
	let act_onotecomms = array::from_fn(|i| {
		NoteCommitmentTarget(HashOutTarget {
			elements: array::from_fn(|j| {
				builder._if(
					onote_isactive[i],
					onote_comms[i].0.elements[j],
					donote_comms[i].0.elements[j],
				)
			}),
		})
	});
	let tx_hash = builder.derive_tx_hash(act_inotenulls, act_onotecomms, accin_null, accout_comm);

	// Validate auth from the user for spend
	let mut is_user_val_req = onote_isactive[0];
	for sel in onote_isactive.iter().take(1) {
		is_user_val_req = builder.or(*sel, is_user_val_req);
	}
	let user_val_sig_target =
		conditional_schnorr_verify_gadget(builder, tx_hash.0, accin.auth, is_user_val_req);

	// Validate auth from the delegate consume authority
	let mut consume_sig_req = inote_isactive[0];
	for sel in inote_isactive.iter().skip(1) {
		consume_sig_req = builder.or(*sel, consume_sig_req);
	}
	consume_sig_req = builder.and(builder.not(is_user_val_req), consume_sig_req);
	let consume_sig_target =
		conditional_schnorr_verify_gadget(builder, tx_hash.0, accin.auth, consume_sig_req);

	// Validate auth from the subpool owner
	let approval_sig_target = conditional_schnorr_verify_gadget(builder, tx_hash.0, accin.auth, tr);

	// let
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

	let mut inode1 = account.acc_ast_root.to_vec();
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

pub struct MerkleTargets<const DEPTH: usize> {
	pub leaf: [Target; HASH_SIZE],
	pub siblings: [[Target; HASH_SIZE]; DEPTH],
	pub bits: [Target; DEPTH],
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
pub fn merkle_verify_gadget<
	F: RichField + Extendable<D> + Poseidon,
	const D: usize,
	const DEPTH: usize,
>(
	builder: &mut CircuitBuilder<F, D>,
	expected_root: HashOutTarget,
	selector: BoolTarget,
) -> MerkleTargets<DEPTH> {
	let leaf: [Target; HASH_SIZE] = core::array::from_fn(|_| builder.add_virtual_target());

	let mut current: [Target; HASH_SIZE] = leaf;
	let mut siblings: [[Target; HASH_SIZE]; DEPTH] = [[builder.zero(); 4]; DEPTH];
	let mut bits: [Target; DEPTH] = [builder.zero(); DEPTH];

	for level in 0..DEPTH {
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

		let parent: [Target; HASH_SIZE] = core::array::from_fn(|i| output[i]);

		siblings[level] = sibling;
		bits[level] = bit.target;
		current = parent;
	}

	let computed_root = current;

	// Selector-gated root equality: selector * (computed_root[i] -
	// expected_root[i]) = 0
	for i in 0..HASH_SIZE {
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
		let targets =
			merkle_verify_gadget::<F, D, 32>(&mut builder, expected_root_targets, selector);

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
		let targets =
			merkle_verify_gadget::<F, D, 32>(&mut builder, expected_root_targets, selector);

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
		let targets =
			merkle_verify_gadget::<F, D, 32>(&mut builder, expected_root_targets, selector);

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
