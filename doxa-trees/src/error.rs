use core::fmt;

use anyhow::Result;

#[derive(Debug)]
pub enum MerkleTreeError {
	FullTree(),
	InvalidProof,
	InvalidBatch(alloc::string::String),
	NotFoundError(alloc::string::String),
	OrderingError,
	EmptyMerkleTreeError,
	IndexError(alloc::string::String),
	InvalidFormatError(alloc::string::String),
	MerkleProofError,
	NonMembershipProofError(alloc::string::String),
	UpdateProofError(alloc::string::String),
	RootMismatch,
	LeafHashMismatch(usize),
	LeafDataInvalid(alloc::string::String),
	LayerMismatch(usize),
	DepthMismatch(alloc::string::String),
}

impl fmt::Display for MerkleTreeError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			MerkleTreeError::LeafDataInvalid(x) => write!(f, "LeafDataInvalid: {x}"),
			MerkleTreeError::InvalidBatch(x) => write!(f, "InvalidBatch: {x}"),
			MerkleTreeError::InvalidProof => write!(f, "invalid proof"),
			MerkleTreeError::FullTree() => write!(f, "tree is full"),
			MerkleTreeError::LeafHashMismatch(x) => write!(f, "LeafHashMismatch: {x}"),
			MerkleTreeError::LayerMismatch(x) => write!(f, "LayerMismatch: {x}"),
			MerkleTreeError::RootMismatch => write!(f, "root mismatch"),
			MerkleTreeError::UpdateProofError(s) => write!(f, "{}", s),
			MerkleTreeError::NonMembershipProofError(s) => write!(f, "{}", s),
			MerkleTreeError::NotFoundError(s) => write!(f, "{} not found", s),
			MerkleTreeError::OrderingError => write!(f, "Failed to order merkle tree nodes"),
			MerkleTreeError::EmptyMerkleTreeError => write!(f, "The Merkle tree is empty"),
			MerkleTreeError::IndexError(s) => {
				write!(f, "Failed to retrieve the node at index {}", s)
			},
			MerkleTreeError::InvalidFormatError(s) => write!(f, "Invalid format error: {}", s),
			MerkleTreeError::MerkleProofError => write!(f, "Failed to generate Merkle proof"),
			MerkleTreeError::DepthMismatch(s) => write!(f, "Depth mismatch: {}", s),
		}
	}
}

pub type MerkleTreeResult<T> = Result<T>;
