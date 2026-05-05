mod common;
use common::*;
use alloy::primitives::{B256, U256};
use plonky2_field::types::Field;
use tessera_state_sync::{
    StateSyncService,
    api::{
        get_batch_status, get_commitment_merkle_path, get_deposits,
        get_nullifier_status, get_subpool_full_proof,
        BatchQuery, CommitmentQuery, DepositsQuery, NullifierQuery, SubpoolQuery,
    },
    constants::{TX_HEADER_SIZE, TX_ACCIN_NULL_OFF, TX_ACCOUT_COMM_OFF, W_ACCIN_NULL_OFF},
    contract::{
        bytes32_to_hash, hash_to_bytes32, hash_to_u256_le, preimage_bytes32_to_raw,
        ITesseraRollupV2,
    },
    state::DepositStatus,
};
use tessera_utils::{hasher::HashOutput, F};
use axum::extract::{Query, State};
use tessera_utils::hasher::MerkleHash;

// ---------------------------------------------------------------------------
// Named constants for GL byte widths
// ---------------------------------------------------------------------------

/// Bytes for a single GL-preimage encoded bytes32 (4 GL field elements × 8 bytes each).
const GL_B32_BYTES: usize = 32;
/// Bytes for a single GL field element (lo_u32_BE4 ++ hi_u32_BE4).
const GL_FIELD_BYTES: usize = 8;

// ---------------------------------------------------------------------------
// StateMirrorExpectation builder
// ---------------------------------------------------------------------------

#[derive(Default)]
struct StateMirrorExpectation {
    pending_tx_pis:       Vec<[u8; 32]>,
    confirmed_tx_pis:     Vec<[u8; 32]>,
    pending_bridge_pis:   Vec<[u8; 32]>,
    confirmed_bridge_pis: Vec<[u8; 32]>,
    state_tree_leaves:    Option<usize>,
    pending_nullifiers:   Vec<HashOutput>,
    confirmed_nullifiers: Vec<HashOutput>,
    /// (note_commitment_bytes, expected_status)
    deposits:             Vec<([u8; 32], DepositStatus)>,
    /// (subpool_id, expected_root)
    subpool_roots:        Vec<(u64, HashOutput)>,
}

impl StateMirrorExpectation {
    fn new() -> Self { Self::default() }
    fn pending_tx_pis(mut self, v: Vec<[u8;32]>) -> Self { self.pending_tx_pis = v; self }
    fn confirmed_tx_pis(mut self, v: Vec<[u8;32]>) -> Self { self.confirmed_tx_pis = v; self }
    fn pending_bridge_pis(mut self, v: Vec<[u8;32]>) -> Self { self.pending_bridge_pis = v; self }
    fn confirmed_bridge_pis(mut self, v: Vec<[u8;32]>) -> Self { self.confirmed_bridge_pis = v; self }
    fn state_tree_leaves(mut self, n: usize) -> Self { self.state_tree_leaves = Some(n); self }
    fn pending_nullifiers(mut self, v: Vec<HashOutput>) -> Self { self.pending_nullifiers = v; self }
    fn confirmed_nullifiers(mut self, v: Vec<HashOutput>) -> Self { self.confirmed_nullifiers = v; self }
    fn deposits(mut self, v: Vec<([u8;32], DepositStatus)>) -> Self { self.deposits = v; self }
    fn subpool_roots(mut self, v: Vec<(u64, HashOutput)>) -> Self { self.subpool_roots = v; self }

    fn assert(&self, service: &tessera_state_sync::StateSyncService) {
        service.with_state(|s| {
            for pi in &self.pending_tx_pis {
                assert!(s.pending_tx_batches.contains_key(pi),
                    "expected pending tx pi {:?} not found", pi);
            }
            for pi in &self.confirmed_tx_pis {
                assert!(s.confirmed_tx_batches.contains(pi),
                    "expected confirmed tx pi {:?} not found", pi);
            }
            for pi in &self.pending_bridge_pis {
                assert!(s.pending_bridge_tx_batches.contains_key(pi),
                    "expected pending bridge pi {:?} not found", pi);
            }
            for pi in &self.confirmed_bridge_pis {
                assert!(s.confirmed_bridge_tx_batches.contains(pi),
                    "expected confirmed bridge pi {:?} not found", pi);
            }
            if let Some(n) = self.state_tree_leaves {
                assert_eq!(s.state_tree.num_leaves(), n, "state_tree leaf count mismatch");
            }
            for null in &self.pending_nullifiers {
                assert!(s.pending_nullifiers.contains_key(null),
                    "expected pending nullifier {:?} not found", null);
            }
            for null in &self.confirmed_nullifiers {
                assert!(s.confirmed_nullifiers.contains(null),
                    "expected confirmed nullifier {:?} not found", null);
            }
            for (nc, expected_status) in &self.deposits {
                let rec = s.deposits.get(nc)
                    .unwrap_or_else(|| panic!("deposit not found: {:?}", nc));
                assert_eq!(&rec.status, expected_status,
                    "deposit status mismatch for {:?}", nc);
            }
            for (id, expected_root) in &self.subpool_roots {
                let actual = s.subpool_roots.get(id).copied()
                    .unwrap_or_else(|| panic!("subpool {} not found in subpool_roots", id));
                assert_eq!(actual, *expected_root,
                    "subpool_root mismatch for id={}", id);
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Test 1: Empty chain sync
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_empty_chain_sync() {
    let (env, provider) = setup_env().await;
    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    StateMirrorExpectation::new()
        .state_tree_leaves(0)
        .assert(&service);
    assert!(service.with_state(|s| s.confirmed_tx_batches.is_empty()));
    assert!(service.with_state(|s| s.confirmed_bridge_tx_batches.is_empty()));
    assert!(service.with_state(|s| s.deposits.is_empty()));
}

// ---------------------------------------------------------------------------
// Test 2: TX batch submitted but not proven (pending)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tx_batch_submitted_pending() {
    let (env, provider) = setup_env().await;
    submit_tx_batch(&provider, env.rollup, tx_preimage()).await;

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    let pi: [u8; 32] = *alloy::primitives::keccak256(tx_preimage());

    StateMirrorExpectation::new()
        .pending_tx_pis(vec![pi])
        .assert(&service);
    assert!(service.with_state(|s| s.confirmed_tx_batches.is_empty()));

    // Verify API also reports pending
    let pi_hex = format!("0x{}", hex::encode(pi));
    let resp = get_batch_status(
        Query(BatchQuery { pi_commitment: pi_hex, kind: "tx".to_string() }),
        State(service),
    )
    .await
    .unwrap();
    assert_eq!(resp.0["status"], "pending");
}

// ---------------------------------------------------------------------------
// Test 3: TX batch proven and confirmed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tx_batch_proven_confirmed() {
    let (env, provider) = setup_env().await;
    submit_tx_batch(&provider, env.rollup, tx_preimage()).await;
    prove_tx_batch(&provider, env.rollup, tx_preimage()).await;

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    let pi: [u8; 32] = *alloy::primitives::keccak256(tx_preimage());

    StateMirrorExpectation::new()
        .confirmed_tx_pis(vec![pi])
        .state_tree_leaves(1)
        .assert(&service);
    assert!(!service.with_state(|s| s.pending_tx_batches.contains_key(&pi)));

    // batch_root key derivation: the first 32 bytes of the preimage are batchPoseidonRoot
    // in GL-preimage encoding; preimage_bytes32_to_raw converts to raw bytes32.
    let gl_bytes: [u8; GL_B32_BYTES] = tx_preimage()[0..GL_B32_BYTES].try_into().unwrap();
    let batch_root_raw = preimage_bytes32_to_raw(&B256::from(gl_bytes));
    assert_eq!(
        service.with_state(|s| s.batch_root_to_leaf_index.get(&batch_root_raw).copied()),
        Some(0)
    );
}

// ---------------------------------------------------------------------------
// Test 4: Bridge batch proven and confirmed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_bridge_batch_proven_confirmed() {
    let (env, provider) = setup_env().await;
    submit_bridge_batch(&provider, env.rollup, bridge_preimage()).await;
    prove_bridge_batch(&provider, env.rollup, bridge_preimage()).await;

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    let pi: [u8; 32] = *alloy::primitives::keccak256(bridge_preimage());

    StateMirrorExpectation::new()
        .confirmed_bridge_pis(vec![pi])
        .state_tree_leaves(1)
        .assert(&service);
}

// ---------------------------------------------------------------------------
// Test 5: Multiple TX batches sequential
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_multiple_tx_batches_sequential() {
    let preimage_a = patch_tx_slot_is_real(tx_preimage(), 0);
    let preimage_b = patch_tx_slot_is_real(tx_preimage(), 1);
    assert_ne!(
        alloy::primitives::keccak256(&preimage_a),
        alloy::primitives::keccak256(&preimage_b)
    );

    let (env, provider) = setup_env().await;
    submit_tx_batch(&provider, env.rollup, &preimage_a).await;
    prove_tx_batch(&provider, env.rollup, &preimage_a).await;
    submit_tx_batch(&provider, env.rollup, &preimage_b).await;
    prove_tx_batch(&provider, env.rollup, &preimage_b).await;

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    StateMirrorExpectation::new()
        .state_tree_leaves(2)
        .assert(&service);
}

// ---------------------------------------------------------------------------
// Test 6: poll_sync incremental
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_poll_sync_incremental() {
    let preimage_a = patch_tx_slot_is_real(tx_preimage(), 0);
    let preimage_b = patch_tx_slot_is_real(tx_preimage(), 1);

    let (env, provider) = setup_env().await;
    submit_tx_batch(&provider, env.rollup, &preimage_a).await;
    prove_tx_batch(&provider, env.rollup, &preimage_a).await;

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    StateMirrorExpectation::new()
        .state_tree_leaves(1)
        .assert(&service);

    submit_tx_batch(&provider, env.rollup, &preimage_b).await;
    prove_tx_batch(&provider, env.rollup, &preimage_b).await;

    service.poll_sync(&provider, env.rollup, 1000).await.unwrap();

    StateMirrorExpectation::new()
        .state_tree_leaves(2)
        .assert(&service);
}

// ---------------------------------------------------------------------------
// Test 7: Nullifier tracked
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_nullifier_tracked() {
    let patched = patch_tx_slot_is_real(tx_preimage(), 0);
    let (env, provider) = setup_env().await;
    submit_tx_batch(&provider, env.rollup, &patched).await;
    prove_tx_batch(&provider, env.rollup, &patched).await;

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    // Read the account-input nullifier from slot 0 in the preimage.
    let null_gl: [u8; GL_B32_BYTES] = patched
        [TX_HEADER_SIZE + TX_ACCIN_NULL_OFF..TX_HEADER_SIZE + TX_ACCIN_NULL_OFF + GL_B32_BYTES]
        .try_into()
        .unwrap();
    let null_raw = preimage_bytes32_to_raw(&B256::from(null_gl));
    let expected_null = bytes32_to_hash(&B256::from(null_raw)).unwrap();

    StateMirrorExpectation::new()
        .confirmed_nullifiers(vec![expected_null])
        .assert(&service);
}

// ---------------------------------------------------------------------------
// Test 8: Subpool owner assigned sync
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_subpool_owner_assigned_sync() {
    let (env, provider) = setup_env().await;

    ITesseraRollupV2::new(env.rollup, &provider)
        .assignSubpoolOwner(1u64, env.operator)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    StateMirrorExpectation::new()
        .subpool_roots(vec![(1u64, HashOutput::ZERO)])
        .assert(&service);
    assert_eq!(service.with_state(|s| s.next_expected_subpool_id), 2);
    assert!(service.with_state(|s| s.pending_subpool_assignments.is_empty()));
}

// ---------------------------------------------------------------------------
// Test 9: Subpool root updated sync
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_subpool_root_updated_sync() {
    let (env, provider) = setup_env().await;

    ITesseraRollupV2::new(env.rollup, &provider)
        .assignSubpoolOwner(1u64, env.operator)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    // Build siblings for subpool 1 at zero root
    let siblings: Vec<U256> = service.with_state(|s| {
        use tessera_client::SubpoolId;
        let proof = s
            .config_tree
            .subpool_proof(SubpoolId(F::from_canonical_u64(1)), HashOutput::ZERO)
            .unwrap();
        proof.siblings.iter().map(hash_to_u256_le).collect()
    });

    let new_root = HashOutput([F::ONE, F::ZERO, F::ZERO, F::ZERO]);

    ITesseraRollupV2::new(env.rollup, &provider)
        .updateSubpoolRoot(1u64, hash_to_u256_le(&new_root), siblings)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    service.poll_sync(&provider, env.rollup, 1000).await.unwrap();

    StateMirrorExpectation::new()
        .subpool_roots(vec![(1u64, new_root)])
        .assert(&service);

    // Check that local config_tree root matches on-chain mainPoolConfigRoot
    let onchain_root = ITesseraRollupV2::new(env.rollup, &provider)
        .mainPoolConfigRoot()
        .call()
        .await
        .unwrap();
    let local_root = service.with_state(|s| hash_to_u256_le(&s.config_tree.root()));
    assert_eq!(onchain_root, local_root);
}

// ---------------------------------------------------------------------------
// Test 10: Sequential subpool assignment (replaces out-of-order test)
// ---------------------------------------------------------------------------

/// Assigns subpools 1, 2, 3 sequentially and verifies sync tracks all of them.
/// The buffering code in sync_config_tree stays as defense-in-depth but is only
/// reachable via synthetic events, not from this contract.
#[tokio::test]
async fn test_subpool_owner_assigned_sequential() {
    let (env, provider) = setup_env().await;

    for id in 1u64..=3 {
        ITesseraRollupV2::new(env.rollup, &provider)
            .assignSubpoolOwner(id, env.operator)
            .send().await.unwrap().get_receipt().await.unwrap();
    }

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await.unwrap();

    StateMirrorExpectation::new()
        .subpool_roots(vec![
            (1, HashOutput::ZERO),
            (2, HashOutput::ZERO),
            (3, HashOutput::ZERO),
        ])
        .assert(&service);

    assert_eq!(service.with_state(|s| s.next_expected_subpool_id), 4);

    // Confirm config_tree root matches on-chain mainPoolConfigRoot
    let onchain_root = ITesseraRollupV2::new(env.rollup, &provider)
        .mainPoolConfigRoot().call().await.unwrap();
    let local_root = service.with_state(|s| hash_to_u256_le(&s.config_tree.root()));
    assert_eq!(onchain_root, local_root);
}

// ---------------------------------------------------------------------------
// Test 11: Deposit available sync
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_deposit_available_sync() {
    let (env, provider) = setup_env().await;

    // Register asset 1 → token
    ITesseraRollupV2::new(env.rollup, &provider)
        .registerAsset(U256::from(1u64), env.token)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // Mint tokens for depositor and approve
    let (depositor_addr, dep_provider) = depositor_provider(&env);
    mint_and_approve(
        env.token,
        env.rollup,
        depositor_addr,
        U256::from(1000u64),
        &provider,
        &dep_provider,
    )
    .await;

    // Deposit
    let note_commitment = B256::from([1u8; 32]);
    ITesseraRollupV2::new(env.rollup, &dep_provider)
        .depositAndRegister(note_commitment, U256::from(1u64), U256::from(1000u64))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    assert!(service.with_state(|s| s.deposits.contains_key(&note_commitment.0)));
    let rec = service.with_state(|s| s.deposits.get(&note_commitment.0).cloned().unwrap());
    assert_eq!(rec.status, DepositStatus::Pending);
    assert_eq!(rec.value, U256::from(1000u64));
    assert_eq!(rec.recipient, depositor_addr);
    assert_eq!(rec.asset_id, U256::from(1u64));
}

// ---------------------------------------------------------------------------
// Test 12: Deposit validated via bridge batch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_deposit_validated_via_bridge_batch() {
    let (env, provider) = setup_env().await;

    // Register asset 1 → token
    ITesseraRollupV2::new(env.rollup, &provider)
        .registerAsset(U256::from(1u64), env.token)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let (depositor_addr, dep_provider) = depositor_provider(&env);
    mint_and_approve(
        env.token,
        env.rollup,
        depositor_addr,
        U256::from(1000u64),
        &provider,
        &dep_provider,
    )
    .await;

    let note_comm_raw = random_gl_b32();
    let note_commitment = B256::from(note_comm_raw);
    ITesseraRollupV2::new(env.rollup, &dep_provider)
        .depositAndRegister(note_commitment, U256::from(1u64), U256::from(1000u64))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // Patch bridge preimage to include this deposit in slot 0
    let patched = patch_bridge_deposit_slot(
        bridge_preimage(),
        0,
        note_comm_raw,
        depositor_addr,
        U256::from(1000u64),
        1u64,
    );
    submit_bridge_batch(&provider, env.rollup, &patched).await;
    prove_bridge_batch(&provider, env.rollup, &patched).await;

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    StateMirrorExpectation::new()
        .deposits(vec![(note_comm_raw, DepositStatus::Validated)])
        .assert(&service);
}

// ---------------------------------------------------------------------------
// Test 13: Deposit withdrawn sync
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_deposit_withdrawn_sync() {
    let (env, provider) = setup_env().await;

    // Register asset 1 → token
    ITesseraRollupV2::new(env.rollup, &provider)
        .registerAsset(U256::from(1u64), env.token)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let (depositor_addr, dep_provider) = depositor_provider(&env);
    mint_and_approve(
        env.token,
        env.rollup,
        depositor_addr,
        U256::from(1000u64),
        &provider,
        &dep_provider,
    )
    .await;

    let note_comm_raw = random_gl_b32();
    let note_commitment = B256::from(note_comm_raw);
    ITesseraRollupV2::new(env.rollup, &dep_provider)
        .depositAndRegister(note_commitment, U256::from(1u64), U256::from(1000u64))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // Sync to confirm deposit is in Pending state
    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    StateMirrorExpectation::new()
        .deposits(vec![(note_comm_raw, DepositStatus::Pending)])
        .assert(&service);

    // Withdraw the Pending deposit (withdrawalDelay=0, only the depositor can withdraw)
    // Note: withdrawPendingDeposit only works on Pending deposits.
    ITesseraRollupV2::new(env.rollup, &dep_provider)
        .withdrawPendingDeposit(note_commitment)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    service.poll_sync(&provider, env.rollup, 1000).await.unwrap();

    StateMirrorExpectation::new()
        .deposits(vec![(note_comm_raw, DepositStatus::Withdrawn)])
        .assert(&service);
}

// ---------------------------------------------------------------------------
// Test 14: API commitment not found
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_api_commitment_not_found() {
    let (env, provider) = setup_env().await;
    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    let resp = get_commitment_merkle_path(
        Query(CommitmentQuery { commitment: format!("0x{}", "00".repeat(32)) }),
        State(service),
    )
    .await
    .unwrap();
    assert_eq!(resp.0["status"], "not_found");
}

// ---------------------------------------------------------------------------
// Test 15: API commitment pending
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_api_commitment_pending() {
    let (env, provider) = setup_env().await;
    submit_tx_batch(&provider, env.rollup, tx_preimage()).await;
    // No prove — batch stays pending

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    // The account-output commitment for slot 0 is at offset TX_HEADER_SIZE + TX_ACCOUT_COMM_OFF
    let comm_gl: [u8; GL_B32_BYTES] = tx_preimage()
        [TX_HEADER_SIZE + TX_ACCOUT_COMM_OFF..TX_HEADER_SIZE + TX_ACCOUT_COMM_OFF + GL_B32_BYTES]
        .try_into()
        .unwrap();
    let comm_raw = preimage_bytes32_to_raw(&B256::from(comm_gl));
    let comm_hash = bytes32_to_hash(&B256::from(comm_raw)).unwrap();
    let comm_hex = format!("0x{}", hex::encode(hash_to_bytes32(&comm_hash)));

    let resp = get_commitment_merkle_path(
        Query(CommitmentQuery { commitment: comm_hex }),
        State(service),
    )
    .await
    .unwrap();
    assert_eq!(resp.0["status"], "pending");
}

// ---------------------------------------------------------------------------
// Test 16: API commitment confirmed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_api_commitment_confirmed() {
    let (env, provider) = setup_env().await;
    submit_tx_batch(&provider, env.rollup, tx_preimage()).await;
    prove_tx_batch(&provider, env.rollup, tx_preimage()).await;

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    let comm_gl: [u8; GL_B32_BYTES] = tx_preimage()
        [TX_HEADER_SIZE + TX_ACCOUT_COMM_OFF..TX_HEADER_SIZE + TX_ACCOUT_COMM_OFF + GL_B32_BYTES]
        .try_into()
        .unwrap();
    let comm_raw = preimage_bytes32_to_raw(&B256::from(comm_gl));
    let comm_hash = bytes32_to_hash(&B256::from(comm_raw)).unwrap();
    let comm_hex = format!("0x{}", hex::encode(hash_to_bytes32(&comm_hash)));

    let resp = get_commitment_merkle_path(
        Query(CommitmentQuery { commitment: comm_hex }),
        State(service),
    )
    .await
    .unwrap();
    assert_eq!(resp.0["status"], "confirmed");
    assert!(!resp.0["batch_subtree_path"].is_null());
    assert!(!resp.0["state_tree_path"].is_null());
}

// ---------------------------------------------------------------------------
// Test 17: API nullifier not found
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_api_nullifier_not_found() {
    let (env, provider) = setup_env().await;
    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    let resp = get_nullifier_status(
        Query(NullifierQuery { nullifier: format!("0x{}", "00".repeat(32)) }),
        State(service),
    )
    .await
    .unwrap();
    assert_eq!(resp.0["status"], "not_found");
}

// ---------------------------------------------------------------------------
// Test 18: API nullifier pending
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_api_nullifier_pending() {
    let patched = patch_tx_slot_is_real(tx_preimage(), 0);
    let (env, provider) = setup_env().await;
    submit_tx_batch(&provider, env.rollup, &patched).await;
    // No prove — nullifier stays pending

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    // Extract nullifier from patched preimage
    let null_gl: [u8; GL_B32_BYTES] = patched
        [TX_HEADER_SIZE + TX_ACCIN_NULL_OFF..TX_HEADER_SIZE + TX_ACCIN_NULL_OFF + GL_B32_BYTES]
        .try_into()
        .unwrap();
    let null_raw = preimage_bytes32_to_raw(&B256::from(null_gl));
    let null_hash = bytes32_to_hash(&B256::from(null_raw)).unwrap();
    let nullifier_hex = format!("0x{}", hex::encode(hash_to_bytes32(&null_hash)));

    StateMirrorExpectation::new()
        .pending_nullifiers(vec![null_hash])
        .assert(&service);

    let resp = get_nullifier_status(
        Query(NullifierQuery { nullifier: nullifier_hex }),
        State(service),
    )
    .await
    .unwrap();
    assert_eq!(resp.0["status"], "pending");
}

// ---------------------------------------------------------------------------
// Test 19: API nullifier confirmed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_api_nullifier_confirmed() {
    let patched = patch_tx_slot_is_real(tx_preimage(), 0);
    let (env, provider) = setup_env().await;
    submit_tx_batch(&provider, env.rollup, &patched).await;
    prove_tx_batch(&provider, env.rollup, &patched).await;

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    // Extract nullifier from patched preimage
    let null_gl: [u8; GL_B32_BYTES] = patched
        [TX_HEADER_SIZE + TX_ACCIN_NULL_OFF..TX_HEADER_SIZE + TX_ACCIN_NULL_OFF + GL_B32_BYTES]
        .try_into()
        .unwrap();
    let null_raw = preimage_bytes32_to_raw(&B256::from(null_gl));
    let null_hash = bytes32_to_hash(&B256::from(null_raw)).unwrap();
    let nullifier_hex = format!("0x{}", hex::encode(hash_to_bytes32(&null_hash)));

    StateMirrorExpectation::new()
        .confirmed_nullifiers(vec![null_hash])
        .assert(&service);

    let resp = get_nullifier_status(
        Query(NullifierQuery { nullifier: nullifier_hex }),
        State(service),
    )
    .await
    .unwrap();
    assert_eq!(resp.0["status"], "confirmed");
}

// ---------------------------------------------------------------------------
// Test 20: API subpool not found
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_api_subpool_not_found() {
    let (env, provider) = setup_env().await;
    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    let result = get_subpool_full_proof(
        Query(SubpoolQuery { subpool_id: 1 }),
        State(service),
    )
    .await;
    assert!(result.is_err());
    use axum::http::StatusCode;
    assert_eq!(result.unwrap_err(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Test 21: API subpool full proof
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_api_subpool_full_proof() {
    let (env, provider) = setup_env().await;

    ITesseraRollupV2::new(env.rollup, &provider)
        .assignSubpoolOwner(1u64, env.operator)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    StateMirrorExpectation::new()
        .subpool_roots(vec![(1u64, HashOutput::ZERO)])
        .assert(&service);

    let result = get_subpool_full_proof(
        Query(SubpoolQuery { subpool_id: 1 }),
        State(service),
    )
    .await;
    let json = result.unwrap().0;
    assert_eq!(json["subpool_id"], 1u64);
    assert_eq!(json["siblings"].as_array().unwrap().len(), 20); // MAIN_POOL_CONFIG_DEPTH = 20
}

// ---------------------------------------------------------------------------
// Test 22: API batch status not found
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_api_batch_status_not_found() {
    let (env, provider) = setup_env().await;
    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    let resp = get_batch_status(
        Query(BatchQuery {
            pi_commitment: format!("0x{}", "00".repeat(32)),
            kind: "tx".to_string(),
        }),
        State(service),
    )
    .await
    .unwrap();
    assert_eq!(resp.0["status"], "not_found");
}

// ---------------------------------------------------------------------------
// Test 23: API batch status pending
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_api_batch_status_pending() {
    let (env, provider) = setup_env().await;
    submit_tx_batch(&provider, env.rollup, tx_preimage()).await;
    // No prove — batch stays pending

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    let pi: [u8; 32] = *alloy::primitives::keccak256(tx_preimage());

    StateMirrorExpectation::new()
        .pending_tx_pis(vec![pi])
        .assert(&service);

    let pi_hex = format!("0x{}", hex::encode(pi));
    let resp = get_batch_status(
        Query(BatchQuery { pi_commitment: pi_hex, kind: "tx".to_string() }),
        State(service),
    )
    .await
    .unwrap();
    assert_eq!(resp.0["status"], "pending");
}

// ---------------------------------------------------------------------------
// Test 24: API batch status confirmed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_api_batch_status_confirmed() {
    let (env, provider) = setup_env().await;
    submit_tx_batch(&provider, env.rollup, tx_preimage()).await;
    prove_tx_batch(&provider, env.rollup, tx_preimage()).await;

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    let pi: [u8; 32] = *alloy::primitives::keccak256(tx_preimage());

    StateMirrorExpectation::new()
        .confirmed_tx_pis(vec![pi])
        .state_tree_leaves(1)
        .assert(&service);

    let pi_hex = format!("0x{}", hex::encode(pi));
    let resp = get_batch_status(
        Query(BatchQuery { pi_commitment: pi_hex, kind: "tx".to_string() }),
        State(service),
    )
    .await
    .unwrap();
    assert_eq!(resp.0["status"], "confirmed");
}

// ---------------------------------------------------------------------------
// Test 25: API deposits empty
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_api_deposits_empty() {
    let (env, provider) = setup_env().await;
    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    let resp = get_deposits(
        Query(DepositsQuery { from_block: None }),
        State(service),
    )
    .await
    .unwrap();
    assert_eq!(resp.0.as_array().unwrap().len(), 0);
}

// ---------------------------------------------------------------------------
// Test 26: API deposits with data
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_api_deposits_with_data() {
    let (env, provider) = setup_env().await;

    // Register asset 1 → token
    ITesseraRollupV2::new(env.rollup, &provider)
        .registerAsset(U256::from(1u64), env.token)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let (depositor_addr, dep_provider) = depositor_provider(&env);
    mint_and_approve(
        env.token,
        env.rollup,
        depositor_addr,
        U256::from(1000u64),
        &provider,
        &dep_provider,
    )
    .await;

    let note_comm_raw = random_gl_b32();
    let note_commitment = B256::from(note_comm_raw);
    ITesseraRollupV2::new(env.rollup, &dep_provider)
        .depositAndRegister(note_commitment, U256::from(1u64), U256::from(1000u64))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    StateMirrorExpectation::new()
        .deposits(vec![(note_comm_raw, DepositStatus::Pending)])
        .assert(&service);

    let resp = get_deposits(
        Query(DepositsQuery { from_block: None }),
        State(service),
    )
    .await
    .unwrap();
    let arr = resp.0.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["status"], "Pending");
    assert_eq!(arr[0]["asset_id"], "1");
}

// ---------------------------------------------------------------------------
// Test 27: API bridge batch status (pending → confirmed)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_api_bridge_batch_status() {
    let (env, provider) = setup_env().await;
    submit_bridge_batch(&provider, env.rollup, bridge_preimage()).await;

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    let pi: [u8; 32] = *alloy::primitives::keccak256(bridge_preimage());
    let pi_hex = format!("0x{}", hex::encode(pi));

    StateMirrorExpectation::new()
        .pending_bridge_pis(vec![pi])
        .assert(&service);

    // Should be pending before prove
    let resp = get_batch_status(
        Query(BatchQuery { pi_commitment: pi_hex.clone(), kind: "bridge".to_string() }),
        State(service.clone()),
    )
    .await
    .unwrap();
    assert_eq!(resp.0["status"], "pending");

    // Prove the batch
    prove_bridge_batch(&provider, env.rollup, bridge_preimage()).await;
    service.poll_sync(&provider, env.rollup, 1000).await.unwrap();

    StateMirrorExpectation::new()
        .confirmed_bridge_pis(vec![pi])
        .state_tree_leaves(1)
        .assert(&service);

    // Should now be confirmed
    let resp = get_batch_status(
        Query(BatchQuery { pi_commitment: pi_hex, kind: "bridge".to_string() }),
        State(service),
    )
    .await
    .unwrap();
    assert_eq!(resp.0["status"], "confirmed");
}

// ---------------------------------------------------------------------------
// Test 28: API get_deposits with from_block filter
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_api_get_deposits_from_block() {
    let (env, provider) = setup_env().await;

    // Register asset 1 → token
    ITesseraRollupV2::new(env.rollup, &provider)
        .registerAsset(U256::from(1u64), env.token)
        .send().await.unwrap().get_receipt().await.unwrap();

    let (depositor_addr, dep_provider) = depositor_provider(&env);
    mint_and_approve(env.token, env.rollup, depositor_addr, U256::from(1000u64), &provider, &dep_provider).await;

    // Two random GL-encoded note commitments
    let nc1 = random_gl_b32();
    let nc2 = random_gl_b32();

    // First deposit — capture block from receipt
    let receipt1 = ITesseraRollupV2::new(env.rollup, &dep_provider)
        .depositAndRegister(B256::from(nc1), U256::from(1u64), U256::from(500u64))
        .send().await.unwrap().get_receipt().await.unwrap();
    let first_deposit_block = receipt1.block_number.unwrap();

    // Second deposit — Anvil mines one block per tx, so this will be in a later block
    ITesseraRollupV2::new(env.rollup, &dep_provider)
        .depositAndRegister(B256::from(nc2), U256::from(1u64), U256::from(500u64))
        .send().await.unwrap().get_receipt().await.unwrap();

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    // from_block = first_deposit_block + 1 should return only nc2
    let resp = get_deposits(
        Query(DepositsQuery { from_block: Some(first_deposit_block + 1) }),
        State(service.clone()),
    )
    .await
    .unwrap();
    let arr = resp.0.as_array().unwrap();
    assert_eq!(arr.len(), 1);

    // from_block = 0 should return both deposits
    let resp_all = get_deposits(
        Query(DepositsQuery { from_block: Some(0) }),
        State(service),
    )
    .await
    .unwrap();
    assert_eq!(resp_all.0.as_array().unwrap().len(), 2);
}

// ---------------------------------------------------------------------------
// Test 29: Bridge batch — real withdrawal, fake deposit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_bridge_batch_real_withdraw_fake_deposit() {
    let (env, provider) = setup_env().await;

    let patched = patch_bridge_withdraw_slot(bridge_preimage(), 0);
    submit_bridge_batch(&provider, env.rollup, &patched).await;
    prove_bridge_batch(&provider, env.rollup, &patched).await;

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    let pi: [u8; 32] = *alloy::primitives::keccak256(&patched);

    // Extract the withdrawal nullifier from the patched preimage
    let null_gl: [u8; GL_B32_BYTES] = patched
        [TX_HEADER_SIZE + W_ACCIN_NULL_OFF..TX_HEADER_SIZE + W_ACCIN_NULL_OFF + GL_B32_BYTES]
        .try_into()
        .unwrap();
    let null_raw = preimage_bytes32_to_raw(&B256::from(null_gl));
    let withdraw_nullifier = bytes32_to_hash(&B256::from(null_raw)).unwrap();

    StateMirrorExpectation::new()
        .state_tree_leaves(1)
        .confirmed_bridge_pis(vec![pi])
        .confirmed_nullifiers(vec![withdraw_nullifier])
        .assert(&service);
}

// ---------------------------------------------------------------------------
// Test 30: Bridge batch — fake withdrawal, real deposit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_bridge_batch_fake_withdraw_real_deposit() {
    let (env, provider) = setup_env().await;

    // Register asset 1 → token
    ITesseraRollupV2::new(env.rollup, &provider)
        .registerAsset(U256::from(1u64), env.token)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let (depositor_addr, dep_provider) = depositor_provider(&env);
    mint_and_approve(
        env.token,
        env.rollup,
        depositor_addr,
        U256::from(1000u64),
        &provider,
        &dep_provider,
    )
    .await;

    let note_comm_raw = random_gl_b32();
    ITesseraRollupV2::new(env.rollup, &dep_provider)
        .depositAndRegister(B256::from(note_comm_raw), U256::from(1u64), U256::from(500u64))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let patched = patch_bridge_deposit_slot(
        bridge_preimage(),
        0,
        note_comm_raw,
        depositor_addr,
        U256::from(500u64),
        1u64,
    );
    submit_bridge_batch(&provider, env.rollup, &patched).await;
    prove_bridge_batch(&provider, env.rollup, &patched).await;

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    let pi: [u8; 32] = *alloy::primitives::keccak256(&patched);

    StateMirrorExpectation::new()
        .state_tree_leaves(1)
        .confirmed_bridge_pis(vec![pi])
        .deposits(vec![(note_comm_raw, DepositStatus::Validated)])
        .assert(&service);
}

// ---------------------------------------------------------------------------
// Test 31: Bridge batch — real withdrawal, real deposit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_bridge_batch_real_withdraw_real_deposit() {
    let (env, provider) = setup_env().await;

    // Register asset 1 → token
    ITesseraRollupV2::new(env.rollup, &provider)
        .registerAsset(U256::from(1u64), env.token)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let (depositor_addr, dep_provider) = depositor_provider(&env);
    mint_and_approve(
        env.token,
        env.rollup,
        depositor_addr,
        U256::from(1000u64),
        &provider,
        &dep_provider,
    )
    .await;

    let note_comm_raw = random_gl_b32();
    ITesseraRollupV2::new(env.rollup, &dep_provider)
        .depositAndRegister(B256::from(note_comm_raw), U256::from(1u64), U256::from(1000u64))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // Apply both patches sequentially: first withdrawal (slot 0), then deposit (slot 0)
    let patched = patch_bridge_withdraw_slot(bridge_preimage(), 0);
    let patched = patch_bridge_deposit_slot(
        &patched,
        0,
        note_comm_raw,
        depositor_addr,
        U256::from(1000u64),
        1u64,
    );
    submit_bridge_batch(&provider, env.rollup, &patched).await;
    prove_bridge_batch(&provider, env.rollup, &patched).await;

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    let pi: [u8; 32] = *alloy::primitives::keccak256(&patched);

    // Extract the withdrawal nullifier from the patched preimage
    let null_gl: [u8; GL_B32_BYTES] = patched
        [TX_HEADER_SIZE + W_ACCIN_NULL_OFF..TX_HEADER_SIZE + W_ACCIN_NULL_OFF + GL_B32_BYTES]
        .try_into()
        .unwrap();
    let null_raw = preimage_bytes32_to_raw(&B256::from(null_gl));
    let withdraw_nullifier = bytes32_to_hash(&B256::from(null_raw)).unwrap();

    StateMirrorExpectation::new()
        .state_tree_leaves(1)
        .confirmed_bridge_pis(vec![pi])
        .confirmed_nullifiers(vec![withdraw_nullifier])
        .deposits(vec![(note_comm_raw, DepositStatus::Validated)])
        .assert(&service);
}
