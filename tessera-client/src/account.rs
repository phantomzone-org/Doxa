use std::{hash::Hash, marker::PhantomData};

use plonky2::{
	gadgets::arithmetic_extension::QuotientGeneratorExtension, hash::poseidon::PoseidonHash,
	plonk::config::Hasher,
};
use plonky2_field::types::{Field, Field64, PrimeField64};
use primitive_types::U256;
use rand::{CryptoRng, Rng, RngExt};
use tessera_trees::{
	F,
	tree::{HASH_SIZE, hasher::HashOutput},
};

use crate::{
	ACC_AST_DEPTH, AST_DEFAULT_LEAF, DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER,
	DEFAULT_SPEND_AUTH_PK, DS_ACC_AST, DS_NULLIFIER_KEY, DS_PUBLIC_IDENTIFIER, NOTE_BATCH,
	NoteCommitment, NoteNullifier,
	commitment::Commitment,
	ecgfp5::CompressedPoint,
	schnorr::{CompressedPublicKey, PublicKey},
	tree::{GenericNode, Leaf, MerkleTree},
};

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct AccountCommitment(HashOutput);

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct AccountNullifier(HashOutput);

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct NullifierKey(pub [F; 4]);

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
pub struct PrivateIdentifier(pub [F; 2]);

impl PrivateIdentifier {
	fn sample<R: CryptoRng + Rng>(rng: &mut R) -> PrivateIdentifier {
		let arr = core::array::from_fn(|_| F::from_canonical_u64(rng.random_range(0..F::ORDER)));
		PrivateIdentifier(arr)
	}
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct PublicIdentifier(pub HashOutput);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SubpoolId(pub F);

#[derive(Debug, Clone)]
pub struct Nonce(pub F);

#[derive(Debug, Clone, Default)]
pub struct SpendAuth {
	pub spend_pk: Option<CompressedPublicKey<F>>,
}

#[derive(Debug, Clone)]
pub struct ConsumeAuth {
	/// If false, consume is delegated to subpool owner
	/// If true, consume requires signature from self.pk
	pub config: bool,
	/// None only when self.config == 1.
	pub pk: Option<CompressedPublicKey<F>>,
}

impl Default for ConsumeAuth {
	fn default() -> Self {
		Self {
			config: false,
			pk: None,
		}
	}
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct AccountStateTreeLeaf {
	pub asset_id: F,
	pub amount: U256,
}

impl Leaf for AccountStateTreeLeaf {
	type Node = GenericNode<Self>;

	fn empty() -> Self::Node {
		GenericNode {
			inner: HashOutput(AST_DEFAULT_LEAF.map(F::from_canonical_u64)),
			_phantom: PhantomData,
		}
	}
}

impl From<AccountStateTreeLeaf> for GenericNode<AccountStateTreeLeaf> {
	fn from(value: AccountStateTreeLeaf) -> Self {
		// input = [DS_ACC_AST, asset_id, limb0, limb1, ..., limb7]
		// limb_i is the i-th 32-bit limb of `amount`, least-significant first.
		// U256.0 is [u64; 4] in little-endian word order.
		let mut input = [F::ZERO; 1 + 1 + 8];
		input[0] = F::from_canonical_u64(DS_ACC_AST);
		input[1] = value.asset_id;
		for (i, word) in value.amount.0.iter().enumerate() {
			input[1 + i * 2] = F::from_canonical_u32(*word as u32);
			input[1 + i * 2 + 1] = F::from_canonical_u32((*word >> 32) as u32);
		}
		Self::from(HashOutput(
			<PoseidonHash as Hasher<F>>::hash_no_pad(&input).elements,
		))
	}
}

#[derive(Clone, Debug)]
pub struct StandardAccount {
	pub private_identifier: PrivateIdentifier,
	pub subpool_id: SubpoolId,
	pub balance: U256,
	pub nonce: Nonce,
	pub spend_auth: SpendAuth,
	pub consume_auth: ConsumeAuth,
	pub ast: MerkleTree<ACC_AST_DEPTH, GenericNode<AccountStateTreeLeaf>>,
}

impl StandardAccount {
	pub fn sample<R: CryptoRng + Rng>(rng: &mut R, subpool_id: SubpoolId) -> Self {
		let private_identifier = PrivateIdentifier::sample(rng);
		StandardAccount {
			private_identifier,
			subpool_id,
			balance: U256::zero(),
			nonce: Nonce(F::ZERO),
			spend_auth: SpendAuth::default(),
			consume_auth: ConsumeAuth::default(),
			ast: MerkleTree::new(),
		}
	}

	pub fn public_id(&self) -> PublicIdentifier {
		let mut input = [F::ZERO; 3];
		input[0] = F::from_canonical_u64(DS_PUBLIC_IDENTIFIER);
		input[1..].copy_from_slice(self.private_identifier.0.as_slice());
		let pubid = <PoseidonHash as Hasher<F>>::hash_no_pad(input.as_slice()).elements;
		PublicIdentifier(pubid.into())
	}

	pub fn nk(&self) -> NullifierKey {
		let mut input = [F::ZERO; 3];
		input[0] = F::from_canonical_u64(DS_NULLIFIER_KEY);
		input[1..].copy_from_slice(self.private_identifier.0.as_slice());
		let nk = <PoseidonHash as Hasher<F>>::hash_no_pad(input.as_ref()).elements;
		NullifierKey(nk.into())
	}

	pub fn commitment(&self) -> AccountCommitment {
		let mut inp = Vec::with_capacity(19);
		inp.extend_from_slice(&self.private_identifier.0);
		inp.push(self.subpool_id.0);
		inp.extend_from_slice(&self.ast.root().0);
		inp.push(self.nonce.0);

		if let Some(spend_pk) = self.spend_auth.spend_pk {
			inp.extend_from_slice(&spend_pk.0.w.0);
		} else {
			inp.extend_from_slice(&DEFAULT_SPEND_AUTH_PK.map(F::from_canonical_u64));
		}

		if self.consume_auth.config {
			inp.push(F::ONE);
			inp.extend(self.consume_auth.pk.unwrap().0.w.0);
		} else {
			inp.push(F::ZERO);
			inp.extend(DEFAULT_ACC_COMM_CONSUME_PK_PLACEHOLDER.map(F::from_canonical_u64));
		};

		AccountCommitment(HashOutput(
			<PoseidonHash as Hasher<F>>::hash_no_pad(&inp).elements,
		))
	}

	pub fn nullifier(&self, pos: Option<u64>) -> AccountNullifier {
		if self.is_fresh() {
			self.fresh_acc_nullifier()
		} else {
			assert!(pos.is_some());
			self.old_acc_nullifier(pos.unwrap())
		}
	}

	pub fn is_fresh(&self) -> bool {
		self.nonce.0 == F::ZERO
			&& self.spend_auth.spend_pk.is_none()
			&& !self.consume_auth.config
			&& self.consume_auth.pk.is_none()
			&& self.ast.size() == 0
	}

	fn fresh_acc_nullifier(&self) -> AccountNullifier {
		let mut inp = Vec::with_capacity(4 + 4);
		inp.extend(self.commitment().0.0);
		inp.extend(self.nk().0);

		AccountNullifier(HashOutput(
			<PoseidonHash as Hasher<F>>::hash_no_pad(&inp).elements,
		))
	}

	fn old_acc_nullifier(&self, pos: u64) -> AccountNullifier {
		let pos = F::from_canonical_u64(pos);

		let mut inp = Vec::with_capacity(4 + 1 + 4);
		inp.extend(self.commitment().0.0);
		inp.push(pos);
		inp.extend(self.nk().0);

		AccountNullifier(HashOutput(
			<PoseidonHash as Hasher<F>>::hash_no_pad(&inp).elements,
		))
	}
}

pub fn derive_tx_hash(
	accin_null: AccountNullifier,
	accout_comm: AccountCommitment,
	inotes_null: [NoteNullifier; NOTE_BATCH],
	onotes_comm: [NoteCommitment; NOTE_BATCH],
) -> [F; 4] {
	use plonky2::plonk::config::Hasher;
	let mut inp = Vec::with_capacity(4 + 4 + 4 * crate::NOTE_BATCH + 4 * crate::NOTE_BATCH);
	inp.extend_from_slice(&accin_null.0.0);
	inp.extend_from_slice(&accout_comm.0.0);
	for n in &inotes_null {
		inp.extend(n.0.0);
	}
	for c in &onotes_comm {
		inp.extend(c.0.0);
	}
	<PoseidonHash as Hasher<F>>::hash_no_pad(&inp).elements
}

/// Compute the actual root of the default empty Account State Tree (depth `ACC_AST_DEPTH`,
/// all leaves = `AST_DEFAULT_LEAF`)
pub(crate) fn ast_default_root() -> [u64; HASH_SIZE] {
	use plonky2::{
		hash::{hash_types::HashOut, poseidon::PoseidonHash},
		plonk::config::Hasher,
	};
	use plonky2_field::types::Field;

	let mut cur: [F; HASH_SIZE] = AST_DEFAULT_LEAF.map(F::from_canonical_u64);
	for _ in 0..ACC_AST_DEPTH {
		let r = <PoseidonHash as Hasher<F>>::two_to_one(
			HashOut {
				elements: cur,
			},
			HashOut {
				elements: cur,
			},
		);
		cur = r.elements;
	}
	cur.map(|f| f.to_canonical_u64())
}

/// Siblings for the index-0 path through the empty default AST (depth ACC_AST_DEPTH).
/// At every level the sibling equals the current node (all nodes identical in an empty tree).
/// Bits are all false (current is always the left child).
pub(crate) fn default_ast_siblings() -> [[F; 4]; crate::ACC_AST_DEPTH] {
	use plonky2::{hash::hash_types::HashOut, plonk::config::Hasher};
	let mut cur = crate::AST_DEFAULT_LEAF.map(F::from_canonical_u64);
	core::array::from_fn(|_| {
		let sib = cur;
		let next = <PoseidonHash as Hasher<F>>::two_to_one(
			HashOut {
				elements: cur,
			},
			HashOut {
				elements: cur,
			},
		);
		cur = next.elements;
		sib
	})
}

#[cfg(test)]
mod tests {
	use std::array;

	use rand::rng;
	use tessera_trees::tree::CommitmentTree;

	use super::*;
	use crate::{
		NOTE_BATCH,
		note::{PositionedStandardNode, RecipientCond, SenderCond, StandardNote},
	};

	impl StandardAccount {
		#[allow(dead_code)]
		fn set_auth(&mut self, auth: SpendAuth) {
			self.spend_auth = auth;
		}
	}

	#[test]
	fn testtest() {
		let mut tree = CommitmentTree::<HashOutput>::new(32);

		let mut rng = rng();
		let sbpoolid = SubpoolId(F::ONE);
		let [acc0, acc1] = array::from_fn(|_| StandardAccount::sample(&mut rng, sbpoolid));
		let notes: [StandardNote; NOTE_BATCH] = array::from_fn(|i| {
			StandardNote::sample_with(
				RecipientCond::from_acc(&acc0),
				SenderCond::from_acc(&acc1),
				U256::from(i),
			)
		});
		let ncs = notes.map(|n| n.commitment());
		let pnotes = ncs.iter().enumerate().map(|(i, nc)| {
			// tree.insert(nc.as_field_hash()).unwrap();
			PositionedStandardNode::from_note(notes[i], F::from_canonical_usize(i))
		});

		// let mrklpaths = pnotes.map(|pn| tree.)
	}
}
