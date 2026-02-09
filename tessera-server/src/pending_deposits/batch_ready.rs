use tessera_trees::tree::hasher::Hash;

use crate::pending_deposits::PendingDepositsBatch;



pub struct PendingDepositsBatchReady {
    pub batch: PendingDepositsBatch,
    pub new_root: Hash, 
}