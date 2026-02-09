use anyhow::{Ok, Result, anyhow};
use serde::{Deserialize, Serialize};
use tessera_trees::tree::hasher::Hash;

use crate::pending_deposits::PendingDeposit;


const BATCH_SIZE: usize = 128;


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingDepositsBatch {
	pub deposits: Vec<PendingDeposit>,
}

impl PendingDepositsBatch {
	pub fn new() -> Self {
		Self {
			deposits: Vec::with_capacity(BATCH_SIZE),
		}
	}

	pub fn add_deposit(&mut self, deposit: PendingDeposit) -> Result<()> {
        if self.deposits.len() >= BATCH_SIZE {
            return Err(anyhow!("Batch is full"));
        }
		self.deposits.push(deposit);
        Ok(())
	}

    pub fn leaves(&self) -> Vec<Hash> {
        self.deposits.iter().map(|d| d.hash()).collect()
    }
}
