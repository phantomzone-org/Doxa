#[cfg(feature = "groth")]
mod aggregator;
mod batch;

#[cfg(feature = "groth")]
pub use aggregator::*;
pub use batch::*;
use tessera_client::NOTE_BATCH;

pub const NOTES_PER_SLOT: usize = 2 * (NOTE_BATCH + 1);
