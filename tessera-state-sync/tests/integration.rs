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
    constants::{TX_HEADER_SIZE, TX_ACCIN_NULL_OFF, TX_ACCOUT_COMM_OFF},
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
// Test 1: Empty chain sync
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_empty_chain_sync() {
    let (env, provider) = setup_env().await;
    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    assert_eq!(service.with_state(|s| s.state_tree.num_leaves()), 0);
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
    assert!(service.with_state(|s| s.pending_tx_batches.contains_key(&pi)));
    assert!(service.with_state(|s| s.confirmed_tx_batches.is_empty()));
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
    assert!(service.with_state(|s| s.confirmed_tx_batches.contains(&pi)));
    assert_eq!(service.with_state(|s| s.state_tree.num_leaves()), 1);
    assert!(!service.with_state(|s| s.pending_tx_batches.contains_key(&pi)));

    // batch_root key derivation: the first 32 bytes of the preimage are batchPoseidonRoot
    // in GL-preimage encoding; preimage_bytes32_to_raw converts to raw bytes32.
    let gl_bytes: [u8; 32] = tx_preimage()[0..32].try_into().unwrap();
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
    assert!(service.with_state(|s| s.confirmed_bridge_tx_batches.contains(&pi)));
    assert_eq!(service.with_state(|s| s.state_tree.num_leaves()), 1);
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

    assert_eq!(service.with_state(|s| s.state_tree.num_leaves()), 2);
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
    assert_eq!(service.with_state(|s| s.state_tree.num_leaves()), 1);

    submit_tx_batch(&provider, env.rollup, &preimage_b).await;
    prove_tx_batch(&provider, env.rollup, &preimage_b).await;

    service.poll_sync(&provider, env.rollup, 1000).await.unwrap();
    assert_eq!(service.with_state(|s| s.state_tree.num_leaves()), 2);
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
    let null_gl: [u8; 32] = patched
        [TX_HEADER_SIZE + TX_ACCIN_NULL_OFF..TX_HEADER_SIZE + TX_ACCIN_NULL_OFF + 32]
        .try_into()
        .unwrap();
    let null_raw = preimage_bytes32_to_raw(&B256::from(null_gl));
    let expected_null = bytes32_to_hash(&B256::from(null_raw)).unwrap();

    assert!(service.with_state(|s| s.confirmed_nullifiers.contains(&expected_null)));
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

    assert!(service.with_state(|s| s.subpool_roots.contains_key(&1u64)));
    assert_eq!(
        service.with_state(|s| s.subpool_roots.get(&1u64).copied()),
        Some(HashOutput::ZERO)
    );
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

    // Check local state
    assert_eq!(
        service.with_state(|s| s.subpool_roots.get(&1u64).copied()),
        Some(new_root)
    );

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
// Test 10: Out-of-order subpool assignment
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_out_of_order_subpool_assignment() {
    let (env, provider) = setup_env().await;

    // Assign subpool 2 BEFORE subpool 1
    ITesseraRollupV2::new(env.rollup, &provider)
        .assignSubpoolOwner(2u64, env.operator)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000)
        .await
        .unwrap();

    // Subpool 2 should be buffered as pending
    assert!(service.with_state(|s| s.pending_subpool_assignments.contains_key(&2u64)));
    assert!(!service.with_state(|s| s.subpool_roots.contains_key(&2u64)));
    assert_eq!(service.with_state(|s| s.next_expected_subpool_id), 1u64);

    // Now assign subpool 1
    ITesseraRollupV2::new(env.rollup, &provider)
        .assignSubpoolOwner(1u64, env.operator)
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    service.poll_sync(&provider, env.rollup, 1000).await.unwrap();

    assert!(service.with_state(|s| s.subpool_roots.contains_key(&1u64)));
    assert!(service.with_state(|s| s.subpool_roots.contains_key(&2u64)));
    assert!(service.with_state(|s| s.pending_subpool_assignments.is_empty()));
    assert_eq!(service.with_state(|s| s.next_expected_subpool_id), 3u64);
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

    let note_comm_raw = [2u8; 32];
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
    let rec = service.with_state(|s| s.deposits.get(&note_comm_raw).cloned().unwrap());
    assert_eq!(rec.status, DepositStatus::Validated);
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

    let note_comm_raw = [3u8; 32];
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
    let rec = service.with_state(|s| s.deposits.get(&note_comm_raw).cloned().unwrap());
    assert_eq!(rec.status, DepositStatus::Pending);

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
    let rec = service.with_state(|s| s.deposits.get(&note_comm_raw).cloned().unwrap());
    assert_eq!(rec.status, DepositStatus::Withdrawn);
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
    let comm_gl: [u8; 32] = tx_preimage()
        [TX_HEADER_SIZE + TX_ACCOUT_COMM_OFF..TX_HEADER_SIZE + TX_ACCOUT_COMM_OFF + 32]
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

    let comm_gl: [u8; 32] = tx_preimage()
        [TX_HEADER_SIZE + TX_ACCOUT_COMM_OFF..TX_HEADER_SIZE + TX_ACCOUT_COMM_OFF + 32]
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
    let null_gl: [u8; 32] = patched
        [TX_HEADER_SIZE + TX_ACCIN_NULL_OFF..TX_HEADER_SIZE + TX_ACCIN_NULL_OFF + 32]
        .try_into()
        .unwrap();
    let null_raw = preimage_bytes32_to_raw(&B256::from(null_gl));
    let null_hash = bytes32_to_hash(&B256::from(null_raw)).unwrap();
    let nullifier_hex = format!("0x{}", hex::encode(hash_to_bytes32(&null_hash)));

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
    let null_gl: [u8; 32] = patched
        [TX_HEADER_SIZE + TX_ACCIN_NULL_OFF..TX_HEADER_SIZE + TX_ACCIN_NULL_OFF + 32]
        .try_into()
        .unwrap();
    let null_raw = preimage_bytes32_to_raw(&B256::from(null_gl));
    let null_hash = bytes32_to_hash(&B256::from(null_raw)).unwrap();
    let nullifier_hex = format!("0x{}", hex::encode(hash_to_bytes32(&null_hash)));

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

    let pi_hex = format!("0x{}", hex::encode(alloy::primitives::keccak256(tx_preimage())));
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

    let pi_hex = format!("0x{}", hex::encode(alloy::primitives::keccak256(tx_preimage())));
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

    let note_commitment = B256::from([4u8; 32]);
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
