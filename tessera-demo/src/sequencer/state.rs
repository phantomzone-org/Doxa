use std::{
	collections::{BTreeSet, HashMap},
	sync::Arc,
	time::{Duration, Instant},
};

use alloy::{network::EthereumWallet, primitives::{Address, B256, U256}};
use tessera_server::sequencer::BatchBuilder;
use tessera_trees::MerkleTree;
use tessera_utils::hasher::HashOutput;
use tokio::sync::Mutex;

pub(crate) struct SequencerState {
	pub rollup_addr: Address,
	pub token_addr: Address,
	pub operator: Address,
	pub confirmed_root: U256,
	pub confirmed_root_history: BTreeSet<U256>,
	pub tx_batch_builder: Option<BatchBuilder>,
	pub tx_batch_pending_since: Option<Instant>,
	pub deposit_queue: Vec<B256>,
	pub deposit_batch_pending_since: Option<Instant>,
	pub prove_delay: Duration,
	/// Local Poseidon Merkle tree mirroring the on-chain commitment tree.
	/// Leaves are inserted in batch after each proven batch.
	pub local_tree: MerkleTree<HashOutput>,
	/// Per-subpool queues of forwarded notes awaiting pickup by operators.
	pub note_pool: HashMap<u64, Vec<ForwardedNote>>,
}

/// A note forwarded from one subpool operator to another via the sequencer.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct ForwardedNote {
	pub identifier: String,
	pub asset_id: String,
	pub amount: String,
	pub recipient_address: String,
	pub sender_address: String,
}

pub(crate) type SharedState = Arc<Mutex<SequencerState>>;

/// Concrete provider type produced by `ProviderBuilder::new().wallet(w).connect_http(url)`.
pub(crate) type DemoProvider = alloy::providers::fillers::FillProvider<
	alloy::providers::fillers::JoinFill<
		alloy::providers::fillers::JoinFill<
			alloy::providers::Identity,
			alloy::providers::fillers::JoinFill<
				alloy::providers::fillers::GasFiller,
				alloy::providers::fillers::JoinFill<
					alloy::providers::fillers::BlobGasFiller,
					alloy::providers::fillers::JoinFill<
						alloy::providers::fillers::NonceFiller,
						alloy::providers::fillers::ChainIdFiller,
					>,
				>,
			>,
		>,
		alloy::providers::fillers::WalletFiller<EthereumWallet>,
	>,
	alloy::providers::RootProvider,
>;

pub(crate) type AppState = (SharedState, Arc<DemoProvider>);
