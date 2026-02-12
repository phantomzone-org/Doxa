mod tree;
pub use tree::*;

const PENDING_DEPOSIT_BATCH_SIZE: usize = 128;
const PENDING_DEPOSIT_TREE_DEPTH: usize = 32;
