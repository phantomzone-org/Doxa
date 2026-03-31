//! Integration tests for [`StateService`].
//!
//! Each test deploys the `TesseraContract` on a local Anvil node backed by
//! the `AcceptAllVerifier` stub, so proofs are accepted unconditionally and
//! no cryptographic artifacts are needed.
//!
//! # What is tested
//!
//! - Genesis sync: StateService started *after* batches are already on-chain
//!   replicates them correctly into its local flat tree.
//! - Incremental sync: StateService polls and picks up batches proven *while*
//!   it is running.
//! - Leaf-index lookups: note and account commitments map to the expected
//!   zero-based positions.
//! - Merkle proofs: siblings returned by the service satisfy
//!   [`MerkleProof::verify`].
//! - Unknown commitment: returns `Ok(None)`, not an error.

#[macro_use]
mod common;

use std::time::Duration;

use alloy::{
    network::EthereumWallet,
    node_bindings::{Anvil, AnvilInstance},
    primitives::{Address, B256, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol_types::SolValue,
};
use tessera_e2e::contract_bytecodes::{
    ACCEPT_ALL_BYTECODE, POSEIDON_BYTECODE, ROLLUP_BYTECODE, TOKEN_BYTECODE,
};
use tessera_server::{
    contract::{self, ITesseraRollupV2},
    state_service::{StateService, StateServiceConfig, StateServiceHandle},
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

mod helpers {
    use super::*;

    // -----------------------------------------------------------------------
    // Test context
    // -----------------------------------------------------------------------

    /// Holds all resources for a single test run.
    ///
    /// The [`AnvilInstance`] must remain alive for the duration of the test; it
    /// is dropped (killing the Anvil process) when `TestCtx` goes out of scope.
    pub struct TestCtx {
        /// Keeps the Anvil process alive. Must not be dropped early.
        pub _anvil: AnvilInstance,
        /// JSON-RPC URL of the local Anvil node.
        pub url: String,
        /// Hex-encoded private key of the operator (Anvil account 0).
        pub operator_key: String,
        /// Deployed `TesseraContract` address.
        pub rollup_addr: Address,
        /// Deployed `ToyUSDT` token address.
        pub token_addr: Address,
    }

    // -----------------------------------------------------------------------
    // Setup
    // -----------------------------------------------------------------------

    /// Spawn Anvil and deploy the full contract stack backed by
    /// `AcceptAllVerifier`. Returns the test context and a concrete provider.
    pub async fn setup_impl() -> (TestCtx, impl Provider + Clone) {
        let anvil = Anvil::new().try_spawn().expect("anvil spawn");
        let url = anvil.endpoint_url().to_string();

        let operator_key_bytes = anvil.keys()[0].to_bytes();
        let operator_key = format!("0x{}", hex::encode(operator_key_bytes));

        let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(anvil.endpoint_url());

        let verifier_addr =
            common::deploy_no_args(&provider, ACCEPT_ALL_BYTECODE).await;
        let poseidon_addr =
            common::deploy_no_args(&provider, POSEIDON_BYTECODE).await;
        let token_addr = common::deploy_no_args(&provider, TOKEN_BYTECODE).await;

        let operator = provider
            .get_accounts()
            .await
            .expect("eth_accounts")[0];

        // Pool config root = B256::ZERO for all tests.
        let constructor_args = (
            verifier_addr, // txVerifier  — AcceptAll
            verifier_addr, // depositVerifier — AcceptAll
            poseidon_addr,
            operator,
            token_addr,
            B256::ZERO, // poolConfigRoot
            U256::from(32_u64), // treeDepth
        )
            .abi_encode();

        let rollup_addr =
            common::deploy_with_args(&provider, ROLLUP_BYTECODE, constructor_args)
                .await;

        let ctx = TestCtx {
            _anvil: anvil,
            url: url.clone(),
            operator_key,
            rollup_addr,
            token_addr,
        };
        (ctx, provider)
    }

    // -----------------------------------------------------------------------
    // Commitment encoding helpers
    // -----------------------------------------------------------------------

    /// Build a valid Goldilocks U256 commitment from a small integer.
    ///
    /// `U256::from(n)` has limbs `[n, 0, 0, 0]`, all strictly less than
    /// `GOLDILOCKS_PRIME` for any `n ≤ u32::MAX`, so it is a valid Goldilocks
    /// hash representation.
    pub fn gl_commitment(n: u64) -> U256 {
        assert!(
            n < contract::GOLDILOCKS_PRIME,
            "n must be a valid Goldilocks element"
        );
        U256::from(n)
    }

    /// Convert an on-chain `uint256` commitment (LE-packed Goldilocks) to the
    /// `[u8; 32]` key that the [`StateService`] stores in its leaf-index map.
    ///
    /// This is the inverse of [`contract::bytes32_be_to_u256_le`]: each of the
    /// four 64-bit Goldilocks limbs is serialised as 8 bytes big-endian.
    pub fn commitment_bytes(v: U256) -> [u8; 32] {
        let h = contract::u256_le_to_hash(v)
            .expect("commitment_bytes: not a valid Goldilocks hash");
        contract::hash_to_bytes32(&h).0
    }

    // -----------------------------------------------------------------------
    // Proof stub
    // -----------------------------------------------------------------------

    /// Return an all-zero [`ITesseraRollupV2::Proof`].
    ///
    /// The `AcceptAllVerifier` ignores the proof contents, so any value works.
    pub fn zero_proof() -> ITesseraRollupV2::Proof {
        ITesseraRollupV2::Proof {
            proof: [U256::ZERO; 8],
            commitments: [U256::ZERO; 2],
            commitmentPok: [U256::ZERO; 2],
        }
    }

    // -----------------------------------------------------------------------
    // TX batch helpers
    // -----------------------------------------------------------------------

    /// Submit and prove a transaction batch on-chain.
    ///
    /// Uses the current on-chain root as `batch.root` and `B256::ZERO` as
    /// `mainPoolConfigRoot` (matching the deployment).  The
    /// `batchPoseidonRoot` is set to `U256::from(batch_idx + 1)` to ensure
    /// every batch produces a unique `piCommitment`.
    ///
    /// Leaves inserted into the local flat tree will be, in order:
    /// `nc[0], nc[1], …, nc[n-1], ac[0], ac[1], …, ac[m-1]`.
    pub async fn submit_and_prove_tx_batch<P: Provider + Clone>(
        provider: &P,
        rollup_addr: Address,
        nc: &[U256],
        ac: &[U256],
        nn: &[U256],
        an: &[U256],
        batch_idx: u64,
    ) {
        let rollup =
            ITesseraRollupV2::ITesseraRollupV2Instance::new(rollup_addr, provider);

        let current_root = rollup
            .currentRoot()
            .call()
            .await
            .expect("currentRoot");

        let batch_poseidon_root = U256::from(batch_idx + 1);

        let batch = ITesseraRollupV2::TransactionBatch {
            root: current_root,
            mainPoolConfigRoot: B256::ZERO,
            noteCommitments: nc.to_vec(),
            accountCommitments: ac.to_vec(),
            noteNullifiers: nn.to_vec(),
            accountNullifiers: an.to_vec(),
            batchPoseidonRoot: batch_poseidon_root,
            confirmed: false,
        };

        let submit_receipt = rollup
            .submitTransactionBatch(batch)
            .send()
            .await
            .expect("submitTransactionBatch send")
            .get_receipt()
            .await
            .expect("submitTransactionBatch receipt");

        let pi_commitment = decode_tx_submitted_pi(&submit_receipt);

        rollup
            .proveTransactionBatch(pi_commitment, zero_proof())
            .send()
            .await
            .expect("proveTransactionBatch send")
            .get_receipt()
            .await
            .expect("proveTransactionBatch receipt");
    }

    /// Submit and prove a deposit batch on-chain.
    ///
    /// Each `dnc` entry must first be registered with `depositAndRegister`
    /// (which requires ERC-20 approval). This helper mints tokens, approves,
    /// and registers all commitments before submitting the batch.
    ///
    /// Leaves inserted into the local flat tree will be `dnc[0], dnc[1], …`
    /// in order.
    pub async fn register_and_prove_deposit_batch<P: Provider + Clone>(
        provider: &P,
        rollup_addr: Address,
        token_addr: Address,
        dnc: &[B256],
        batch_idx: u64,
    ) {
        let rollup =
            ITesseraRollupV2::ITesseraRollupV2Instance::new(rollup_addr, provider);

        // Mint and approve enough tokens for the deposits.
        let operator = provider
            .get_accounts()
            .await
            .expect("eth_accounts")[0];
        let token = ITesseraRollupV2IToyUSDT::new(token_addr, provider);
        let total_amount = U256::from(dnc.len() as u64 * 1_000_000_u64);
        token
            .mint(operator, total_amount)
            .send()
            .await
            .expect("token mint send")
            .get_receipt()
            .await
            .expect("token mint receipt");
        token
            .approve(rollup_addr, total_amount)
            .send()
            .await
            .expect("token approve send")
            .get_receipt()
            .await
            .expect("token approve receipt");

        // Register each note commitment as a Pending deposit.
        for nc in dnc {
            rollup
                .depositAndRegister(*nc, U256::from(1_000_000_u64))
                .send()
                .await
                .expect("depositAndRegister send")
                .get_receipt()
                .await
                .expect("depositAndRegister receipt");
        }

        let current_root = rollup
            .currentRoot()
            .call()
            .await
            .expect("currentRoot");

        let batch_poseidon_root = U256::from(1000 + batch_idx + 1);

        let batch = ITesseraRollupV2::DepositBatch {
            root: current_root,
            mainPoolConfigRoot: B256::ZERO,
            depositNoteCommitments: dnc.to_vec(),
            batchPoseidonRoot: batch_poseidon_root,
            confirmed: false,
        };

        let submit_receipt = rollup
            .submitDepositBatch(batch)
            .send()
            .await
            .expect("submitDepositBatch send")
            .get_receipt()
            .await
            .expect("submitDepositBatch receipt");

        let pi_commitment = decode_deposit_submitted_pi(&submit_receipt);

        rollup
            .proveDepositBatch(pi_commitment, zero_proof())
            .send()
            .await
            .expect("proveDepositBatch send")
            .get_receipt()
            .await
            .expect("proveDepositBatch receipt");
    }

    // -----------------------------------------------------------------------
    // Event decoding helpers
    // -----------------------------------------------------------------------

    /// Extract the `piCommitment` from a `TransactionBatchSubmitted` receipt.
    fn decode_tx_submitted_pi(
        receipt: &alloy::rpc::types::TransactionReceipt,
    ) -> B256 {
        receipt
            .inner
            .logs()
            .iter()
            .find_map(|log| {
                log.log_decode::<ITesseraRollupV2::TransactionBatchSubmitted>()
                    .ok()
                    .map(|d| d.inner.piCommitment)
            })
            .expect("TransactionBatchSubmitted event not found in receipt")
    }

    /// Extract the `piCommitment` from a `DepositBatchSubmitted` receipt.
    fn decode_deposit_submitted_pi(
        receipt: &alloy::rpc::types::TransactionReceipt,
    ) -> B256 {
        receipt
            .inner
            .logs()
            .iter()
            .find_map(|log| {
                log.log_decode::<ITesseraRollupV2::DepositBatchSubmitted>()
                    .ok()
                    .map(|d| d.inner.piCommitment)
            })
            .expect("DepositBatchSubmitted event not found in receipt")
    }

    // -----------------------------------------------------------------------
    // StateService lifecycle
    // -----------------------------------------------------------------------

    /// Spawn a [`StateService`] in a background task and return its handle.
    ///
    /// `poll_interval_secs` is set to `1` so the service picks up new blocks
    /// quickly in tests.
    pub fn start_state_service(
        url: String,
        rollup_addr: Address,
    ) -> (tokio::task::JoinHandle<()>, StateServiceHandle) {
        let config = StateServiceConfig {
            rpc_url: url,
            bridge_address: rollup_addr,
            chain_id: 31337,
            poll_interval_secs: 1,
            log_chunk_blocks: 1_000,
        };
        let (mut svc, handle) = StateService::new(config);
        let jh = tokio::spawn(async move {
            if let Err(e) = svc.run().await {
                eprintln!("StateService error: {e}");
            }
        });
        (jh, handle)
    }

    // -----------------------------------------------------------------------
    // Synchronisation helpers
    // -----------------------------------------------------------------------

    /// Block until the StateService has indexed `commitment`, or panic on
    /// timeout.
    ///
    /// Polls every 100 ms up to `timeout` (default: 10 s).
    pub async fn wait_for_commitment(
        handle: &StateServiceHandle,
        commitment: [u8; 32],
        timeout: Duration,
    ) {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match handle.get_leaf_index(commitment).await {
                Ok(Some(_)) => return,
                Ok(None) => {}
                Err(e) => panic!("wait_for_commitment: service error: {e}"),
            }
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "wait_for_commitment: timed out after {timeout:?}; \
                     commitment {commitment:?} not indexed"
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Default wait timeout for sync assertions (10 seconds).
    pub const SYNC_TIMEOUT: Duration = Duration::from_secs(10);
}

// ---------------------------------------------------------------------------
// Minimal ERC-20 interface for minting and approving inside tests
// ---------------------------------------------------------------------------

alloy::sol! {
    #[sol(rpc)]
    interface ITesseraRollupV2IToyUSDT {
        function mint(address to, uint256 amount) external;
        function approve(address spender, uint256 amount) external returns (bool);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// StateService started on an empty chain completes initial sync without error
/// and returns `Ok(None)` for any unknown commitment.
#[tokio::test]
async fn genesis_sync_empty_chain() {
    let (ctx, _provider) = helpers::setup_impl().await;
    let (_jh, handle) = helpers::start_state_service(ctx.url.clone(), ctx.rollup_addr);

    // Give the service time to complete its initial sync.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Any arbitrary bytes32 must return None on an empty chain.
    let result = handle.get_leaf_index([1u8; 32]).await.expect("get_leaf_index failed");
    assert_eq!(result, None, "empty chain: expected None");
}

/// A single TX batch proven before the StateService starts is replayed
/// correctly during genesis sync.
///
/// Leaf order: `nc[0], nc[1], ac[0]`.
#[tokio::test]
async fn genesis_sync_single_tx_batch() {
    let (ctx, provider) = helpers::setup_impl().await;

    let nc = [helpers::gl_commitment(1), helpers::gl_commitment(2)];
    let ac = [helpers::gl_commitment(3)];
    let nn = [helpers::gl_commitment(100)];
    let an = [helpers::gl_commitment(101)];

    helpers::submit_and_prove_tx_batch(&provider, ctx.rollup_addr, &nc, &ac, &nn, &an, 0).await;

    let (_jh, handle) = helpers::start_state_service(ctx.url.clone(), ctx.rollup_addr);
    helpers::wait_for_commitment(
        &handle,
        helpers::commitment_bytes(ac[0]),
        helpers::SYNC_TIMEOUT,
    )
    .await;

    // Leaves are note commitments first, then account commitments.
    assert_eq!(
        handle.get_leaf_index(helpers::commitment_bytes(nc[0])).await.expect("lookup nc[0]"),
        Some(0),
        "nc[0] should be at index 0"
    );
    assert_eq!(
        handle.get_leaf_index(helpers::commitment_bytes(nc[1])).await.expect("lookup nc[1]"),
        Some(1),
        "nc[1] should be at index 1"
    );
    assert_eq!(
        handle.get_leaf_index(helpers::commitment_bytes(ac[0])).await.expect("lookup ac[0]"),
        Some(2),
        "ac[0] should be at index 2"
    );

    // Nullifiers are NOT leaves.
    assert_eq!(
        handle.get_leaf_index(helpers::commitment_bytes(nn[0])).await.expect("lookup nn[0]"),
        None,
        "nullifiers must not appear as leaves"
    );
    assert_eq!(
        handle.get_leaf_index(helpers::commitment_bytes(an[0])).await.expect("lookup an[0]"),
        None,
        "account nullifiers must not appear as leaves"
    );
}

/// A single deposit batch proven before the StateService starts is replayed
/// correctly during genesis sync.
///
/// Deposit note commitments are raw `bytes32`; their leaf indices start at 0.
#[tokio::test]
async fn genesis_sync_single_deposit_batch() {
    let (ctx, provider) = helpers::setup_impl().await;

    let dnc: Vec<B256> = vec![B256::from([1u8; 32]), B256::from([2u8; 32])];

    helpers::register_and_prove_deposit_batch(
        &provider,
        ctx.rollup_addr,
        ctx.token_addr,
        &dnc,
        0,
    )
    .await;

    let (_jh, handle) = helpers::start_state_service(ctx.url.clone(), ctx.rollup_addr);
    helpers::wait_for_commitment(&handle, *dnc[1], helpers::SYNC_TIMEOUT).await;

    assert_eq!(
        handle.get_leaf_index(*dnc[0]).await.expect("lookup dnc[0]"),
        Some(0),
        "dnc[0] should be at index 0"
    );
    assert_eq!(
        handle.get_leaf_index(*dnc[1]).await.expect("lookup dnc[1]"),
        Some(1),
        "dnc[1] should be at index 1"
    );
}

/// Two TX batches and one deposit batch proven in interleaved order before
/// startup are replayed in the correct leaf-index order.
///
/// Expected flat-tree layout:
/// ```text
/// idx 0: nc[0] from tx_batch_0
/// idx 1: nc[1] from tx_batch_0
/// idx 2: ac[0] from tx_batch_0
/// idx 3: dnc[0] from deposit_batch
/// idx 4: nc[0] from tx_batch_1
/// idx 5: nc[1] from tx_batch_1
/// idx 6: ac[0] from tx_batch_1
/// ```
#[tokio::test]
async fn genesis_sync_multiple_mixed_batches() {
    let (ctx, provider) = helpers::setup_impl().await;

    // TX batch 0
    helpers::submit_and_prove_tx_batch(
        &provider,
        ctx.rollup_addr,
        &[helpers::gl_commitment(1), helpers::gl_commitment(2)],
        &[helpers::gl_commitment(3)],
        &[helpers::gl_commitment(100)],
        &[helpers::gl_commitment(101)],
        0,
    )
    .await;

    // Deposit batch (leafIndex = 1 in the global on-chain IMT)
    let dnc = vec![B256::from([0xAAu8; 32])];
    helpers::register_and_prove_deposit_batch(
        &provider,
        ctx.rollup_addr,
        ctx.token_addr,
        &dnc,
        1,
    )
    .await;

    // TX batch 1 (leafIndex = 2)
    helpers::submit_and_prove_tx_batch(
        &provider,
        ctx.rollup_addr,
        &[helpers::gl_commitment(4), helpers::gl_commitment(5)],
        &[helpers::gl_commitment(6)],
        &[helpers::gl_commitment(200)],
        &[helpers::gl_commitment(201)],
        2,
    )
    .await;

    let (_jh, handle) = helpers::start_state_service(ctx.url.clone(), ctx.rollup_addr);
    // Wait for the last leaf in the sequence.
    helpers::wait_for_commitment(
        &handle,
        helpers::commitment_bytes(helpers::gl_commitment(6)),
        helpers::SYNC_TIMEOUT,
    )
    .await;

    // TX batch 0 leaves
    assert_eq!(handle.get_leaf_index(helpers::commitment_bytes(helpers::gl_commitment(1))).await.unwrap(), Some(0));
    assert_eq!(handle.get_leaf_index(helpers::commitment_bytes(helpers::gl_commitment(2))).await.unwrap(), Some(1));
    assert_eq!(handle.get_leaf_index(helpers::commitment_bytes(helpers::gl_commitment(3))).await.unwrap(), Some(2));
    // Deposit leaf
    assert_eq!(handle.get_leaf_index(*dnc[0]).await.unwrap(), Some(3));
    // TX batch 1 leaves
    assert_eq!(handle.get_leaf_index(helpers::commitment_bytes(helpers::gl_commitment(4))).await.unwrap(), Some(4));
    assert_eq!(handle.get_leaf_index(helpers::commitment_bytes(helpers::gl_commitment(5))).await.unwrap(), Some(5));
    assert_eq!(handle.get_leaf_index(helpers::commitment_bytes(helpers::gl_commitment(6))).await.unwrap(), Some(6));
}

/// A batch proven *after* the StateService has started is detected by the
/// polling loop within the poll interval.
#[tokio::test]
async fn incremental_sync_new_batch() {
    let (ctx, provider) = helpers::setup_impl().await;

    // One batch exists before the service starts.
    helpers::submit_and_prove_tx_batch(
        &provider,
        ctx.rollup_addr,
        &[helpers::gl_commitment(1)],
        &[helpers::gl_commitment(2)],
        &[],
        &[],
        0,
    )
    .await;

    let (_jh, handle) = helpers::start_state_service(ctx.url.clone(), ctx.rollup_addr);
    // Wait for the initial sync to incorporate the first batch.
    helpers::wait_for_commitment(
        &handle,
        helpers::commitment_bytes(helpers::gl_commitment(2)),
        helpers::SYNC_TIMEOUT,
    )
    .await;

    // Submit a second batch while the service is running.
    helpers::submit_and_prove_tx_batch(
        &provider,
        ctx.rollup_addr,
        &[helpers::gl_commitment(3)],
        &[helpers::gl_commitment(4)],
        &[],
        &[],
        1,
    )
    .await;

    // The polling loop (1 s interval) should pick it up within 10 s.
    helpers::wait_for_commitment(
        &handle,
        helpers::commitment_bytes(helpers::gl_commitment(4)),
        helpers::SYNC_TIMEOUT,
    )
    .await;

    assert_eq!(handle.get_leaf_index(helpers::commitment_bytes(helpers::gl_commitment(1))).await.unwrap(), Some(0));
    assert_eq!(handle.get_leaf_index(helpers::commitment_bytes(helpers::gl_commitment(2))).await.unwrap(), Some(1));
    assert_eq!(handle.get_leaf_index(helpers::commitment_bytes(helpers::gl_commitment(3))).await.unwrap(), Some(2));
    assert_eq!(handle.get_leaf_index(helpers::commitment_bytes(helpers::gl_commitment(4))).await.unwrap(), Some(3));
}

/// The Merkle proof returned by [`StateServiceHandle::get_siblings`] for a
/// leaf in a synced tree satisfies [`MerkleProof::verify`].
#[tokio::test]
async fn get_siblings_verifiable() {
    let (ctx, provider) = helpers::setup_impl().await;

    let nc = [
        helpers::gl_commitment(10),
        helpers::gl_commitment(11),
        helpers::gl_commitment(12),
    ];
    let ac = [helpers::gl_commitment(13)];

    helpers::submit_and_prove_tx_batch(&provider, ctx.rollup_addr, &nc, &ac, &[], &[], 0).await;

    let (_jh, handle) = helpers::start_state_service(ctx.url.clone(), ctx.rollup_addr);
    helpers::wait_for_commitment(
        &handle,
        helpers::commitment_bytes(ac[0]),
        helpers::SYNC_TIMEOUT,
    )
    .await;

    // Request the Merkle proof for nc[1] (leaf index 1).
    let proof = handle
        .get_siblings(helpers::commitment_bytes(nc[1]))
        .await
        .expect("get_siblings failed");

    assert_eq!(proof.pos, 1, "pos should be 1");
    assert_eq!(proof.num_leaves, 4, "tree should have 4 leaves");
    assert!(
        proof.verify(),
        "Merkle proof did not verify: leaf={:?}, root={:?}",
        proof.leaf,
        proof.root
    );
}

/// [`StateServiceHandle::get_siblings`] for a leaf in a two-batch tree also
/// produces a valid proof, exercising cross-subtree sibling paths.
#[tokio::test]
async fn get_siblings_cross_batch_verifiable() {
    let (ctx, provider) = helpers::setup_impl().await;

    // Batch 0: 2 leaves
    helpers::submit_and_prove_tx_batch(
        &provider,
        ctx.rollup_addr,
        &[helpers::gl_commitment(20)],
        &[helpers::gl_commitment(21)],
        &[],
        &[],
        0,
    )
    .await;

    // Batch 1: 2 more leaves
    helpers::submit_and_prove_tx_batch(
        &provider,
        ctx.rollup_addr,
        &[helpers::gl_commitment(22)],
        &[helpers::gl_commitment(23)],
        &[],
        &[],
        1,
    )
    .await;

    let (_jh, handle) = helpers::start_state_service(ctx.url.clone(), ctx.rollup_addr);
    helpers::wait_for_commitment(
        &handle,
        helpers::commitment_bytes(helpers::gl_commitment(23)),
        helpers::SYNC_TIMEOUT,
    )
    .await;

    // Verify proofs for all four leaves.
    for (expected_idx, commitment) in [
        helpers::gl_commitment(20),
        helpers::gl_commitment(21),
        helpers::gl_commitment(22),
        helpers::gl_commitment(23),
    ]
    .iter()
    .enumerate()
    {
        let proof = handle
            .get_siblings(helpers::commitment_bytes(*commitment))
            .await
            .expect("get_siblings failed");

        assert_eq!(proof.pos, expected_idx, "unexpected leaf position");
        assert!(
            proof.verify(),
            "proof verification failed for leaf at index {expected_idx}"
        );
    }
}

/// Querying a commitment that was never inserted returns `Ok(None)`.
#[tokio::test]
async fn unknown_commitment_returns_none() {
    let (ctx, provider) = helpers::setup_impl().await;

    helpers::submit_and_prove_tx_batch(
        &provider,
        ctx.rollup_addr,
        &[helpers::gl_commitment(1)],
        &[helpers::gl_commitment(2)],
        &[],
        &[],
        0,
    )
    .await;

    let (_jh, handle) = helpers::start_state_service(ctx.url.clone(), ctx.rollup_addr);
    helpers::wait_for_commitment(
        &handle,
        helpers::commitment_bytes(helpers::gl_commitment(2)),
        helpers::SYNC_TIMEOUT,
    )
    .await;

    // A commitment with value 99 was never submitted.
    assert_eq!(
        handle
            .get_leaf_index(helpers::commitment_bytes(helpers::gl_commitment(99)))
            .await
            .expect("lookup gl_commitment(99)"),
        None,
        "unseen commitment must return None"
    );
    // All-zero bytes were never submitted.
    assert_eq!(
        handle.get_leaf_index([0u8; 32]).await.expect("lookup zero bytes"),
        None,
        "zero bytes must return None"
    );
}
