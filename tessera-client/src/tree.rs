use std::{collections::HashMap, fmt, fmt::Debug, hash::Hash, marker::PhantomData};

use plonky2::{
	hash::poseidon::PoseidonHash,
	plonk::{config::Hasher, proof},
};
use tessera_trees::{
	F,
	tree::{HASH_SIZE, hasher::HashOutput},
};

// #[derive(Clone, Debug, PartialEq, Eq)]
// pub(crate) struct Node(pub(crate) HashOutput);

pub(crate) struct CommitmentTreeMerkleProof<const DEPTH: usize> {
	pub(crate) path: Vec<HashOutput>,
	pub(crate) num_leaves: usize,
	pub(crate) pos: usize,
}

impl<const DEPTH: usize> CommitmentTreeMerkleProof<DEPTH> {
	pub(crate) fn new(path: Vec<HashOutput>, pos: usize, num_leaves: usize) -> Self {
		assert!(path.len() == DEPTH);
		Self {
			path,
			num_leaves,
			pos,
		}
	}

	pub(crate) fn extract_siblings_bits(&self) -> ([[F; HASH_SIZE]; DEPTH], [bool; DEPTH]) {
		let siblings: [[F; 4]; DEPTH] = core::array::from_fn(|i| self.path[i].0);
		let bits: [bool; DEPTH] = core::array::from_fn(|j| (self.pos >> j) & 1 == 1);
		(siblings, bits)
	}
}

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
		let left = HashOut {
			elements: lhs.inner().0,
		};
		let right = HashOut {
			elements: rhs.inner().0,
		};
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

/// The leaf value stored in a [`MerkleProof`].
///
/// `Actual` holds a real leaf that was inserted into the tree.
/// `Empty` indicates that the slot at the proven index has never been written,
/// so the bottom node is the tree's canonical empty node (`NType::Leaf::empty()`).
#[derive(Clone, Debug)]
pub enum MerkleLeaf<NType: Node> {
	Actual(NType::Leaf),
	Empty,
}

/// A complete Merkle proof for a leaf
pub struct MerkleProof<Ntype: Node, const DEPTH: usize> {
	/// The leaf being proven
	pub leaf: MerkleLeaf<Ntype>,
	/// The index of the leaf in the tree
	pub leaf_index: usize,
	/// The path from leaf to root
	pub path: [MerkleProofStep<Ntype>; DEPTH],
	/// The root hash
	pub root: HashOutput,
}

impl<Ntype: Node, const DEPTH: usize> Clone for MerkleProof<Ntype, DEPTH>
where
	MerkleLeaf<Ntype>: Clone,
	MerkleProofStep<Ntype>: Clone,
{
	fn clone(&self) -> Self {
		Self {
			leaf: self.leaf.clone(),
			leaf_index: self.leaf_index,
			path: self.path.clone(),
			root: self.root,
		}
	}
}

impl<Ntype: Node, const DEPTH: usize> fmt::Debug for MerkleProof<Ntype, DEPTH>
where
	MerkleLeaf<Ntype>: fmt::Debug,
	MerkleProofStep<Ntype>: fmt::Debug,
{
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("MerkleProof")
			.field("leaf", &self.leaf)
			.field("leaf_index", &self.leaf_index)
			.field("path", &self.path)
			.field("root", &self.root)
			.finish()
	}
}

impl<Ntype: Node, const DEPTH: usize> MerkleProof<Ntype, DEPTH>
where
	Ntype::Leaf: Clone,
{
	/// Verify the Merkle proof
	pub fn verify(&self) -> bool {
		let mut current_node: Ntype = match &self.leaf {
			MerkleLeaf::Actual(leaf) => leaf.clone().into(),
			MerkleLeaf::Empty => Ntype::Leaf::empty(),
		};

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

	/// Extract siblings and direction bits from a native MerkleProof.
	/// Direction::Left  (sibling on left, current is right child) → bit = true
	/// Direction::Right (sibling on right, current is left child) → bit = false
	pub(crate) fn extract_siblings_bits(&self) -> ([[F; HASH_SIZE]; DEPTH], [bool; DEPTH]) {
		let siblings: [[F; 4]; DEPTH] = core::array::from_fn(|i| self.path[i].sibling.inner().0);
		let bits: [bool; DEPTH] =
			core::array::from_fn(|i| self.path[i].direction == crate::tree::Direction::Left);
		(siblings, bits)
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

impl<const DEPTH: usize, NType: Node + Clone + Debug> MerkleTree<DEPTH, NType>
where
	NType::Leaf: Hash + Eq + Clone + Debug,
{
	pub(crate) fn new() -> Self {
		let depth = DEPTH;
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
		1 << DEPTH
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
		for i in 0..DEPTH {
			let left_child = &self.tree[i][index << 1];
			let right_child = &self.tree[i][(index << 1) + 1];

			self.tree[i + 1][index] = NType::compress_two(left_child, right_child);
			index >>= 1;
		}
		self.root = self.tree[DEPTH][0].inner();
	}

	pub fn merkle_proof(&self, leaf: NType::Leaf) -> Option<MerkleProof<NType, DEPTH>> {
		let index = self.leaf_index_map.get(&leaf);

		if index.is_none() {
			return None;
		}

		let mut current_index = *index.unwrap();
		let mut path = vec![];
		for level in 0..DEPTH {
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
			leaf: MerkleLeaf::Actual(leaf),
			leaf_index: *index.unwrap(),
			path: path.try_into().unwrap(),
			root: self.root,
		})
	}

	/// Return a [`MerkleProof`] for an arbitrary `index`, regardless of whether a leaf
	/// has been inserted there.  If no leaf exists at `index`, the proof uses
	/// [`MerkleLeaf::Empty`] as the bottom node (i.e. `NType::Leaf::empty()`).
	pub fn merkle_proof_at(&self, index: usize) -> MerkleProof<NType, DEPTH> {
		let mut current_index = index;
		let mut path = vec![];
		for level in 0..DEPTH {
			let (sibling_index, direction) = if current_index % 2 == 0 {
				(current_index + 1, Direction::Right)
			} else {
				(current_index - 1, Direction::Left)
			};

			let sibling_hash = self.tree[level][sibling_index].clone();
			path.push(MerkleProofStep {
				sibling: sibling_hash,
				direction,
			});

			current_index /= 2;
		}

		let leaf = self
			.leaf_index_map
			.iter()
			.find(|(_, i)| i == &&index)
			.map(|(l, _)| MerkleLeaf::Actual(l.clone()))
			.unwrap_or(MerkleLeaf::Empty);

		MerkleProof {
			leaf,
			leaf_index: index,
			path: path.try_into().unwrap(),
			root: self.root,
		}
	}

	pub fn verify(&self, proof: &MerkleProof<NType, DEPTH>) -> bool {
		self.root == proof.root && (proof.verify())
	}
}
