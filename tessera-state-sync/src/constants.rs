// Batch parsing constants (must match TesseraContract.sol)

pub const PRIV_TX_BATCH_SIZE: usize = 64;
pub const NOTE_BATCH: usize = 7;
pub const BRIDGE_TX_HALF_SIZE: usize = 256;
pub const BATCH_SUBTREE_DEPTH: usize = 9;

// TX batch preimage layout
pub const TX_HEADER_SIZE: usize = 96;
pub const TX_SLOT_SIZE: usize = 520;
pub const TX_ACCIN_NULL_OFF: usize = 8;
pub const TX_ACCOUT_COMM_OFF: usize = 40;
pub const TX_NOTE_IN_OFF: usize = 72;
pub const TX_NOTE_OUT_OFF: usize = 296;

// Bridge TX batch preimage layout
pub const W_SLOT_SIZE: usize = 616;
pub const D_SLOT_SIZE: usize = 216;
pub const D_SECTION_OFF: usize = TX_HEADER_SIZE + BRIDGE_TX_HALF_SIZE * W_SLOT_SIZE;
pub const W_ACCIN_NULL_OFF: usize = 8;
pub const W_ACCOUT_COMM_OFF: usize = 40;
pub const D_ACCIN_NULL_OFF: usize = 8;
pub const D_ACCOUT_COMM_OFF: usize = 40;
pub const D_NOTE_COMM_OFF: usize = 72;

// Total preimage lengths
pub const TX_PREIMAGE_LEN: usize = TX_HEADER_SIZE + PRIV_TX_BATCH_SIZE * TX_SLOT_SIZE;
pub const BRIDGE_TX_PREIMAGE_LEN: usize = D_SECTION_OFF + BRIDGE_TX_HALF_SIZE * D_SLOT_SIZE;

/// Maximum block range per `eth_getLogs` call.
pub const LOG_FETCH_CHUNK_BLOCKS: u64 = 1_000;

// Compile-time assertions to catch drift
const _: () = assert!(D_SECTION_OFF == TX_HEADER_SIZE + BRIDGE_TX_HALF_SIZE * W_SLOT_SIZE);
const _: () = assert!(TX_PREIMAGE_LEN == TX_HEADER_SIZE + PRIV_TX_BATCH_SIZE * TX_SLOT_SIZE);
const _: () = assert!(BRIDGE_TX_PREIMAGE_LEN == D_SECTION_OFF + BRIDGE_TX_HALF_SIZE * D_SLOT_SIZE);