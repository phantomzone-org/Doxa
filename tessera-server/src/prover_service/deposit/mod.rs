pub mod aggregator;
mod batch;
mod mock_aggregator;
mod validation;

pub use aggregator::DepositAggregator;
pub use batch::{Deposit, DepositBatch, FinalizedDepositBatchValidation};
pub use mock_aggregator::MockDepositAggregator;
pub(super) use validation::{log_deposit_rejection, validate_deposit};
