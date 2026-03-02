use std::{collections::HashMap, hash::Hash, marker::PhantomData};

use plonky2::{hash::poseidon::PoseidonHash, plonk::config::Hasher};
use plonky2_field::types::Field;
use tessera_trees::{
	F,
	tree::{HASH_SIZE, hasher::HashOutput},
};

// #[derive(Clone, Debug, PartialEq, Eq)]
// pub(crate) struct Node(pub(crate) HashOutput);

pub trait Leaf {
	type Node;
	fn empty() -> Self::Node;
}

pub trait Node: Sized + From<HashOutput> {
	type Leaf: Leaf<Node = Self> + Into<Self>;

	fn inner(&self) -> HashOutput;

	fn compress_two(lhs: &Self, rhs: &Self) -> Self {
		// Use two_to_one so the native hash matches the circuit's PoseidonPermutation gadget.
		use plonky2::hash::hash_types::HashOut;
		let left = HashOut { elements: lhs.inner().0 };
		let right = HashOut { elements: rhs.inner().0 };
		let result = <PoseidonHash as Hasher<F>>::two_to_one(left, right);
		Self::from(HashOutput(result.elements))
	}
}

#[derive(Debug, Clone)]
pub struct GenericNode<L> {
	pub(crate) inner: HashOutput,
	pub(crate) _phantom: PhantomData<L>,
}

impl<L> From<HashOutput> for GenericNode<L> {
	fn from(value: HashOutput) -> Self {
		Self {
			inner: value,
			_phantom: PhantomData,
		}
	}
}

impl<L: Leaf<Node = GenericNode<L>> + Into<GenericNode<L>>> Node for GenericNode<L> {
	type Leaf = L;

	fn inner(&self) -> HashOutput {
		self.inner
	}
}

/// Direction in the Merkle path (indicates position of sibling)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
	/// Sibling is on the left (current node is right child)
	Left,
	/// Sibling is on the right (current node is left child)
	Right,
}

/// A single step in a Merkle proof
#[derive(Clone, Debug)]
pub struct MerkleProofStep<NType: Node> {
	/// The sibling hash at this level
	pub sibling: NType,
	/// Whether the sibling is on the left or right
	pub direction: Direction,
}

/// A complete Merkle proof for a leaf
#[derive(Clone, Debug)]
pub struct MerkleProof<Ntype: Node> {
	/// The leaf being proven
	pub leaf: Ntype::Leaf,
	/// The index of the leaf in the tree
	pub _leaf_index: usize,
	/// The path from leaf to root
	pub path: Vec<MerkleProofStep<Ntype>>,
	/// The root hash
	pub root: HashOutput,
}

impl<Ntype: Node> MerkleProof<Ntype>
where
	Ntype::Leaf: Clone,
{
	/// Verify the Merkle proof
	pub fn verify(&self) -> bool {
		let mut current_node: Ntype = self.leaf.clone().into();

		for step in &self.path {
			current_node = match step.direction {
				// Sibling is on the left, so hash(sibling, current)
				Direction::Left => Ntype::compress_two(&step.sibling, &current_node),
				// Sibling is on the right, so hash(current, sibling)
				Direction::Right => Ntype::compress_two(&current_node, &step.sibling),
			};
		}

		current_node.inner() == self.root
	}

	pub(crate) fn extract_root(&self) -> HashOutput {
		self.root
	}
}

#[derive(Clone, Debug)]
pub struct MerkleTree<const DEPTH: usize, NType: Node> {
	root: HashOutput,
	leaf_index_map: HashMap<NType::Leaf, usize>,
	tree: Vec<Vec<NType>>,
	next_index: usize,
}

impl<const D: usize, NType: Node + Clone> MerkleTree<D, NType>
where
	NType::Leaf: Hash + Eq + Clone,
{
	pub(crate) fn new() -> Self {
		let depth = D;
		let mut curr_nodes = NType::Leaf::empty();
		let mut curr_len = 1 << depth;
		let mut tree = vec![];
		while curr_len > 0 {
			tree.push(vec![curr_nodes.clone(); curr_len]);
			curr_nodes = NType::compress_two(&curr_nodes, &curr_nodes);
			curr_len >>= 1;
		}
		let root = tree[depth][0].clone();
		Self {
			root: root.inner(),
			leaf_index_map: HashMap::default(),
			tree,
			next_index: 0,
		}
	}

	pub fn next_index(&self) -> usize {
		self.next_index
	}

	pub fn root(&self) -> HashOutput {
		self.root
	}

	/// Get the number of leaves currently inserted
	pub fn size(&self) -> usize {
		self.next_index
	}

	/// Get the maximum capacity of the tree
	pub fn capacity(&self) -> usize {
		1 << D
	}

	/// Check if the tree is full
	pub fn is_full(&self) -> bool {
		self.next_index >= self.capacity()
	}

	pub fn insert(&mut self, leaf: NType::Leaf) {
		assert!(!self.is_full(), "Capacity reached");

		let index = self.next_index;
		self.leaf_index_map.insert(leaf.clone(), index);
		self.next_index += 1;

		self.set_leaf(index, leaf);
	}

	pub fn batch_insert(&mut self, leaves: Vec<NType::Leaf>) {
		for id in leaves.into_iter() {
			self.insert(id);
		}
	}

	pub fn set_leaf(&mut self, at_index: usize, to_leaf: NType::Leaf) {
		self.leaf_index_map.insert(to_leaf.clone(), at_index);
		let node: NType = to_leaf.into();
		let mut index = at_index;

		self.tree[0][index] = node;
		index = index >> 1;
		for i in 0..D {
			let left_child = &self.tree[i][index << 1];
			let right_child = &self.tree[i][(index << 1) + 1];

			self.tree[i + 1][index] = NType::compress_two(left_child, right_child);
			index >>= 1;
		}
		self.root = self.tree[D][0].inner();
	}

	pub fn merkle_proof(&self, leaf: NType::Leaf) -> Option<MerkleProof<NType>> {
		let index = self.leaf_index_map.get(&leaf);

		if index.is_none() {
			return None;
		}

		let mut current_index = *index.unwrap();
		let mut path = vec![];
		for level in 0..D {
			let (sibling_index, direction) = if current_index % 2 == 0 {
				// Current is left child, sibling is on the right
				(current_index + 1, Direction::Right)
			} else {
				// Current is right child, sibling is on the left
				(current_index - 1, Direction::Left)
			};

			let sibling_hash = self.tree[level][sibling_index].clone();

			path.push(MerkleProofStep {
				sibling: sibling_hash,
				direction,
			});

			current_index /= 2;
		}

		Some(MerkleProof {
			leaf,
			_leaf_index: *index.unwrap(),
			path,
			root: self.root,
		})
	}

	pub fn verify(&self, proof: &MerkleProof<NType>) -> bool {
		self.root == proof.root && (proof.verify())
	}
}
