mod common;
use common::*;
use alloy::primitives::{B256, U256};
use alloy::providers::Provider;
use plonky2_field::types::Field;
use std::collections::HashSet;
use tessera_state_sync::{
    StateSyncService,
    api::{
        get_batch_status, get_commitment_merkle_path, get_deposits,
        get_nullifier_status, get_subpool_full_proof,
        BatchQuery, CommitmentQuery, DepositsQuery, NullifierQuery, SubpoolQuery,
    },
    constants::{
        TX_HEADER_SIZE, TX_SLOT_SIZE, NOTE_BATCH,
        TX_ACCIN_NULL_OFF, TX_ACCOUT_COMM_OFF, TX_NOTE_IN_OFF, TX_NOTE_OUT_OFF,
        W_SLOT_SIZE, W_ACCIN_NULL_OFF,
    },
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
// File-local helper: extract a HashOutput from a preimage at GL-encoded bytes32 at offset `off`.
// ---------------------------------------------------------------------------

/// Extract a HashOutput from a preimage at GL-encoded bytes32 at offset `off`.
fn extract_hash_from_preimage(preimage: &[u8], off: usize) -> HashOutput {
    let gl: [u8; 32] = preimage[off..off + 32].try_into().unwrap();
    let raw = preimage_bytes32_to_raw(&B256::from(gl));
    bytes32_to_hash(&B256::from(raw)).unwrap()
}

// ---------------------------------------------------------------------------
// StateMirrorExpectation builder
// ---------------------------------------------------------------------------

#[derive(Default)]
struct StateMirrorExpectation {
    // Batch tracking — None=skip, Some(v)=exact set match
    pending_tx_pis:       Option<Vec<[u8; 32]>>,
    confirmed_tx_pis:     Option<Vec<[u8; 32]>>,
    pending_bridge_pis:   Option<Vec<[u8; 32]>>,
    confirmed_bridge_pis: Option<Vec<[u8; 32]>>,

    // State tree
    state_tree_leaves: Option<usize>,

    // Specific map entries to check (presence + value, not exhaustive)
    batch_root_to_leaf_index: Vec<([u8; 32], usize)>,
    commitment_to_batch:      Vec<(HashOutput, [u8; 32], usize, bool)>,
    confirmed_roots_contains: Vec<HashOutput>,
    pi_to_batch_root:         Vec<([u8; 32], HashOutput)>,
    confirmed_batch_subtrees: Vec<([u8; 32], HashOutput)>, // (pi, expected subtree root)

    // pending_batch_leaves must be empty?
    pending_batch_leaves_empty: Option<bool>,

    // Nullifiers — None=skip, Some(v)=exact set
    pending_nullifiers:   Option<Vec<HashOutput>>,
    confirmed_nullifiers: Option<Vec<HashOutput>>,

    // Deposits — None=skip, Some(v)=check entries; if empty also check is_empty
    deposits: Option<Vec<([u8; 32], DepositStatus)>>,

    // Subpools — None=skip, Some(v)=exact map (length + all entries)
    subpool_roots: Option<Vec<(u64, HashOutput)>>,
    next_expected_subpool_id: Option<u64>,
    pending_subpool_assignments_empty: Option<bool>,

    // Sync state
    last_synced_block: Option<u64>,
}

impl StateMirrorExpectation {
    fn new() -> Self { Self::default() }

    fn pending_tx_pis(mut self, v: Vec<[u8; 32]>) -> Self { self.pending_tx_pis = Some(v); self }
    fn confirmed_tx_pis(mut self, v: Vec<[u8; 32]>) -> Self { self.confirmed_tx_pis = Some(v); self }
    fn pending_bridge_pis(mut self, v: Vec<[u8; 32]>) -> Self { self.pending_bridge_pis = Some(v); self }
    fn confirmed_bridge_pis(mut self, v: Vec<[u8; 32]>) -> Self { self.confirmed_bridge_pis = Some(v); self }
    fn state_tree_leaves(mut self, n: usize) -> Self { self.state_tree_leaves = Some(n); self }
    fn pending_nullifiers(mut self, v: Vec<HashOutput>) -> Self { self.pending_nullifiers = Some(v); self }
    fn confirmed_nullifiers(mut self, v: Vec<HashOutput>) -> Self { self.confirmed_nullifiers = Some(v); self }
    fn deposits(mut self, v: Vec<([u8; 32], DepositStatus)>) -> Self { self.deposits = Some(v); self }
    fn subpool_roots(mut self, v: Vec<(u64, HashOutput)>) -> Self { self.subpool_roots = Some(v); self }
    fn next_expected_subpool_id(mut self, n: u64) -> Self { self.next_expected_subpool_id = Some(n); self }
    fn pending_batch_leaves_empty(mut self) -> Self { self.pending_batch_leaves_empty = Some(true); self }
    fn pending_subpool_assignments_empty(mut self) -> Self { self.pending_subpool_assignments_empty = Some(true); self }
    fn last_synced_block(mut self, n: u64) -> Self { self.last_synced_block = Some(n); self }
    fn batch_root_at_index(mut self, raw: [u8; 32], idx: usize) -> Self {
        self.batch_root_to_leaf_index.push((raw, idx)); self
    }
    fn commitment_in_batch(mut self, c: HashOutput, pi: [u8; 32], sub_idx: usize, conf: bool) -> Self {
        self.commitment_to_batch.push((c, pi, sub_idx, conf)); self
    }
    fn confirmed_root_contains(mut self, r: HashOutput) -> Self {
        self.confirmed_roots_contains.push(r); self
    }
    fn pi_maps_to_batch_root(mut self, pi: [u8; 32], r: HashOutput) -> Self {
        self.pi_to_batch_root.push((pi, r)); self
    }
    fn confirmed_subtree_for(mut self, pi: [u8; 32], expected_root: HashOutput) -> Self {
        self.confirmed_batch_subtrees.push((pi, expected_root)); self
    }

    fn assert(&self, service: &tessera_state_sync::StateSyncService) {
        service.with_state(|s| {
            // Batch tracking — exact set match
            if let Some(v) = &self.pending_tx_pis {
                let actual: HashSet<[u8; 32]> = s.pending_tx_batches.keys().copied().collect();
                let expected: HashSet<[u8; 32]> = v.iter().copied().collect();
                assert_eq!(actual, expected, "pending_tx_pis mismatch");
            }
            if let Some(v) = &self.confirmed_tx_pis {
                let expected: HashSet<[u8; 32]> = v.iter().copied().collect();
                assert_eq!(s.confirmed_tx_batches, expected, "confirmed_tx_pis mismatch");
            }
            if let Some(v) = &self.pending_bridge_pis {
                let actual: HashSet<[u8; 32]> = s.pending_bridge_tx_batches.keys().copied().collect();
                let expected: HashSet<[u8; 32]> = v.iter().copied().collect();
                assert_eq!(actual, expected, "pending_bridge_pis mismatch");
            }
            if let Some(v) = &self.confirmed_bridge_pis {
                let expected: HashSet<[u8; 32]> = v.iter().copied().collect();
                assert_eq!(s.confirmed_bridge_tx_batches, expected, "confirmed_bridge_pis mismatch");
            }

            // State tree
            if let Some(n) = self.state_tree_leaves {
                assert_eq!(s.state_tree.num_leaves(), n, "state_tree leaf count mismatch");
            }

            // Specific map entries
            for (raw, idx) in &self.batch_root_to_leaf_index {
                assert_eq!(
                    s.batch_root_to_leaf_index.get(raw).copied(),
                    Some(*idx),
                    "batch_root_to_leaf_index mismatch for {:?}", raw
                );
            }
            for (comm, pi, sub_idx, conf) in &self.commitment_to_batch {
                let loc = s.commitment_to_batch.get(comm)
                    .unwrap_or_else(|| panic!("commitment {:?} not found in commitment_to_batch", comm));
                assert_eq!(loc.pi_commitment, *pi,
                    "commitment pi_commitment mismatch for {:?}", comm);
                assert_eq!(loc.subtree_leaf_index, *sub_idx,
                    "commitment subtree_leaf_index mismatch for {:?}", comm);
                assert_eq!(loc.confirmed, *conf,
                    "commitment confirmed mismatch for {:?}", comm);
            }
            for r in &self.confirmed_roots_contains {
                assert!(s.confirmed_roots.contains(r),
                    "confirmed_roots does not contain {:?}", r);
            }
            if let Some(true) = self.pending_batch_leaves_empty {
                assert!(s.pending_batch_leaves.is_empty(),
                    "expected pending_batch_leaves to be empty");
            }
            for (pi, expected_root) in &self.confirmed_batch_subtrees {
                let subtree = s.confirmed_batch_subtrees.get(pi)
                    .unwrap_or_else(|| panic!("no confirmed subtree for pi {:?}", pi));
                assert_eq!(subtree.root(), *expected_root,
                    "confirmed subtree root mismatch for pi {:?}", pi);
            }
            for (pi, r) in &self.pi_to_batch_root {
                assert_eq!(
                    s.pi_to_batch_root.get(pi).copied(),
                    Some(*r),
                    "pi_to_batch_root mismatch for pi {:?}", pi
                );
            }

            // Nullifiers — exact set
            if let Some(v) = &self.pending_nullifiers {
                let actual: HashSet<HashOutput> = s.pending_nullifiers.keys().copied().collect();
                let expected: HashSet<HashOutput> = v.iter().copied().collect();
                assert_eq!(actual, expected, "pending_nullifiers mismatch");
            }
            if let Some(v) = &self.confirmed_nullifiers {
                let expected: HashSet<HashOutput> = v.iter().copied().collect();
                assert_eq!(s.confirmed_nullifiers, expected, "confirmed_nullifiers mismatch");
            }

            // Deposits
            if let Some(v) = &self.deposits {
                if v.is_empty() {
                    assert!(s.deposits.is_empty(), "expected deposits to be empty");
                } else {
                    for (nc, expected_status) in v {
                        let rec = s.deposits.get(nc)
                            .unwrap_or_else(|| panic!("deposit not found: {:?}", nc));
                        assert_eq!(&rec.status, expected_status,
                            "deposit status mismatch for {:?}", nc);
                    }
                }
            }

            // Subpools — exact map
            if let Some(v) = &self.subpool_roots {
                assert_eq!(s.subpool_roots.len(), v.len(),
                    "subpool_roots length mismatch: actual={}, expected={}", s.subpool_roots.len(), v.len());
                for (id, expected_root) in v {
                    let actual = s.subpool_roots.get(id).copied()
                        .unwrap_or_else(|| panic!("subpool {} not found", id));
                    assert_eq!(actual, *expected_root, "subpool_root mismatch for id={}", id);
                }
            }
            if let Some(n) = self.next_expected_subpool_id {
                assert_eq!(s.next_expected_subpool_id, n, "next_expected_subpool_id mismatch");
            }
            if let Some(true) = self.pending_subpool_assignments_empty {
                assert!(s.pending_subpool_assignments.is_empty(),
                    "expected pending_subpool_assignments to be empty");
            }

            // Sync state
            if let Some(n) = self.last_synced_block {
                assert_eq!(s.last_synced_block, n, "last_synced_block mismatch");
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
    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000).await.unwrap();

    StateMirrorExpectation::new()
        .pending_tx_pis(vec![])
        .confirmed_tx_pis(vec![])
        .pending_bridge_pis(vec![])
        .confirmed_bridge_pis(vec![])
        .state_tree_leaves(0)
        .pending_nullifiers(vec![])
        .confirmed_nullifiers(vec![])
        .deposits(vec![])
        .subpool_roots(vec![])
        .next_expected_subpool_id(1)
        .pending_subpool_assignments_empty()
        .pending_batch_leaves_empty()
        .assert(&service);
}

// ---------------------------------------------------------------------------
// Test 2: Poll sync incremental (exhaustive two-TX-batch test)
// Replaces: test_tx_batch_submitted_pending, test_tx_batch_proven_confirmed,
//           test_multiple_tx_batches_sequential, test_nullifier_tracked
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_poll_sync_incremental() {
    // Build two TX preimages with distinct batch roots AND distinct output commitments
    let preimage_a = patch_batch_root_gl(&patch_tx_slot_is_real(tx_preimage(), 0), 1u64);
    let preimage_b = patch_batch_root_gl(&patch_tx_slot_is_real(tx_preimage(), 1), 2u64);

    // Compute PIs
    let pi_a: [u8; 32] = *alloy::primitives::keccak256(&preimage_a);
    let pi_b: [u8; 32] = *alloy::primitives::keccak256(&preimage_b);

    // Compute batch roots (GL-decoded first 32 bytes of each preimage)
    let batch_root_a_gl: [u8; 32] = preimage_a[0..32].try_into().unwrap();
    let batch_root_a_raw = preimage_bytes32_to_raw(&B256::from(batch_root_a_gl));
    let batch_root_a = bytes32_to_hash(&B256::from(batch_root_a_raw)).unwrap();

    let batch_root_b_gl: [u8; 32] = preimage_b[0..32].try_into().unwrap();
    let batch_root_b_raw = preimage_bytes32_to_raw(&B256::from(batch_root_b_gl));
    let batch_root_b = bytes32_to_hash(&B256::from(batch_root_b_raw)).unwrap();

    // Subtree roots (computed from the full preimage, same logic as sync service)
    let subtree_root_a = batch_subtree_root_from_tx_preimage(&preimage_a);
    let subtree_root_b = batch_subtree_root_from_tx_preimage(&preimage_b);

    // Extract real-slot commitments for slot 0 (from preimage_a)
    let acc_comm_a = extract_hash_from_preimage(&preimage_a, TX_HEADER_SIZE + 0 * TX_SLOT_SIZE + TX_ACCOUT_COMM_OFF);
    let note_comm_a: Vec<HashOutput> = (0..NOTE_BATCH)
        .map(|j| extract_hash_from_preimage(&preimage_a, TX_HEADER_SIZE + 0 * TX_SLOT_SIZE + TX_NOTE_OUT_OFF + j * 32))
        .collect();

    // Extract real-slot commitments for slot 1 (from preimage_b)
    let acc_comm_b = extract_hash_from_preimage(&preimage_b, TX_HEADER_SIZE + 1 * TX_SLOT_SIZE + TX_ACCOUT_COMM_OFF);
    let note_comm_b: Vec<HashOutput> = (0..NOTE_BATCH)
        .map(|j| extract_hash_from_preimage(&preimage_b, TX_HEADER_SIZE + 1 * TX_SLOT_SIZE + TX_NOTE_OUT_OFF + j * 32))
        .collect();

    // Extract nullifiers for slot 0 (from preimage_a)
    let acc_null_a = extract_hash_from_preimage(&preimage_a, TX_HEADER_SIZE + 0 * TX_SLOT_SIZE + TX_ACCIN_NULL_OFF);
    let note_null_a: Vec<HashOutput> = (0..NOTE_BATCH)
        .map(|j| extract_hash_from_preimage(&preimage_a, TX_HEADER_SIZE + 0 * TX_SLOT_SIZE + TX_NOTE_IN_OFF + j * 32))
        .collect();

    // Extract nullifiers for slot 1 (from preimage_b)
    let acc_null_b = extract_hash_from_preimage(&preimage_b, TX_HEADER_SIZE + 1 * TX_SLOT_SIZE + TX_ACCIN_NULL_OFF);
    let note_null_b: Vec<HashOutput> = (0..NOTE_BATCH)
        .map(|j| extract_hash_from_preimage(&preimage_b, TX_HEADER_SIZE + 1 * TX_SLOT_SIZE + TX_NOTE_IN_OFF + j * 32))
        .collect();

    let all_nulls_a: Vec<HashOutput> = std::iter::once(acc_null_a).chain(note_null_a.iter().copied()).collect();
    let all_nulls_b: Vec<HashOutput> = std::iter::once(acc_null_b).chain(note_null_b.iter().copied()).collect();
    let all_nulls: Vec<HashOutput> = all_nulls_a.iter().copied().chain(all_nulls_b.iter().copied()).collect();

    let (env, provider) = setup_env().await;

    // === Phase 1: Batch A only ===
    submit_tx_batch(&provider, env.rollup, &preimage_a).await;
    prove_tx_batch(&provider, env.rollup, &preimage_a).await;

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000).await.unwrap();

    // Build commitment_in_batch entries for slot 0 (all confirmed=true, pi=pi_a)
    // Slot 0: accOutComm at subtree index 0, noteOutComm[j] at subtree index 1+j
    let exp = StateMirrorExpectation::new()
        .pending_tx_pis(vec![])
        .confirmed_tx_pis(vec![pi_a])
        .pending_bridge_pis(vec![])
        .confirmed_bridge_pis(vec![])
        .state_tree_leaves(1)
        .batch_root_at_index(batch_root_a_raw, 0)
        .pi_maps_to_batch_root(pi_a, batch_root_a)
        .confirmed_subtree_for(pi_a, subtree_root_a)
        .pending_batch_leaves_empty()
        .confirmed_nullifiers(all_nulls_a.clone())
        .pending_nullifiers(vec![])
        .deposits(vec![])
        .subpool_roots(vec![])
        .next_expected_subpool_id(1)
        .pending_subpool_assignments_empty()
        .commitment_in_batch(acc_comm_a, pi_a, 0, true);
    let exp = note_comm_a.iter().enumerate().fold(exp, |e, (j, &nc)| e.commitment_in_batch(nc, pi_a, 1 + j, true));
    exp.assert(&service);

    // === Phase 2: Add Batch B ===
    submit_tx_batch(&provider, env.rollup, &preimage_b).await;
    prove_tx_batch(&provider, env.rollup, &preimage_b).await;
    service.poll_sync(&provider, env.rollup, 1000).await.unwrap();

    let final_state_root = service.with_state(|s| s.state_tree.root());
    let latest_block: u64 = provider.get_block_number().await.unwrap();

    let exp = StateMirrorExpectation::new()
        .pending_tx_pis(vec![])
        .confirmed_tx_pis(vec![pi_a, pi_b])
        .pending_bridge_pis(vec![])
        .confirmed_bridge_pis(vec![])
        .state_tree_leaves(2)
        .batch_root_at_index(batch_root_a_raw, 0)
        .batch_root_at_index(batch_root_b_raw, 1)
        .pi_maps_to_batch_root(pi_a, batch_root_a)
        .pi_maps_to_batch_root(pi_b, batch_root_b)
        .confirmed_subtree_for(pi_a, subtree_root_a)
        .confirmed_subtree_for(pi_b, subtree_root_b)
        .pending_batch_leaves_empty()
        .confirmed_nullifiers(all_nulls)
        .pending_nullifiers(vec![])
        .confirmed_root_contains(final_state_root)
        .deposits(vec![])
        .subpool_roots(vec![])
        .next_expected_subpool_id(1)
        .pending_subpool_assignments_empty()
        .last_synced_block(latest_block)
        // Slot 0 commitments (in pi_a, indices 0..7)
        .commitment_in_batch(acc_comm_a, pi_a, 0, true);
    let exp = note_comm_a.iter().enumerate().fold(exp, |e, (j, &nc)| e.commitment_in_batch(nc, pi_a, 1 + j, true));
    // Slot 1 commitments (in pi_b, indices 8..15)
    let exp = exp.commitment_in_batch(acc_comm_b, pi_b, 8, true);
    let exp = note_comm_b.iter().enumerate().fold(exp, |e, (j, &nc)| e.commitment_in_batch(nc, pi_b, 9 + j, true));
    exp.assert(&service);
}

// ---------------------------------------------------------------------------
// Test 3: Bridge batch scenarios
// Replaces: test_bridge_batch_proven_confirmed, test_bridge_batch_real_withdraw_fake_deposit,
//           test_bridge_batch_fake_withdraw_real_deposit, test_bridge_batch_real_withdraw_real_deposit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_bridge_batch_scenarios() {
    let (env, provider) = setup_env().await;

    // Register asset 1
    ITesseraRollupV2::new(env.rollup, &provider)
        .registerAsset(U256::from(1u64), env.token)
        .send().await.unwrap().get_receipt().await.unwrap();

    let (depositor_addr, dep_provider) = depositor_provider(&env);
    mint_and_approve(env.token, env.rollup, depositor_addr, U256::from(1000u64), &provider, &dep_provider).await;

    // Deposit a note commitment
    let nc = random_gl_b32();
    ITesseraRollupV2::new(env.rollup, &dep_provider)
        .depositAndRegister(B256::from(nc), U256::from(1u64), U256::from(1000u64))
        .send().await.unwrap().get_receipt().await.unwrap();

    // Batch 1: bridge_preimage() base (withdrawal slot 0 real), unique batch root GL(10)
    let preimage_1 = patch_batch_root_gl(bridge_preimage(), 10u64);
    submit_bridge_batch(&provider, env.rollup, &preimage_1).await;
    prove_bridge_batch(&provider, env.rollup, &preimage_1).await;

    // Batch 2: real withdrawal slot 0, unique batch root GL(11)
    let preimage_2 = patch_batch_root_gl(&patch_bridge_withdraw_slot(bridge_preimage(), 0), 11u64);
    let withdraw_null = extract_hash_from_preimage(&preimage_2, TX_HEADER_SIZE + 0 * W_SLOT_SIZE + W_ACCIN_NULL_OFF);
    // bridge_preimage() has withdrawal slot 0 is_real=true; batches 1 and 3 confirm this null
    let orig_w_null = extract_hash_from_preimage(&preimage_1, TX_HEADER_SIZE + 0 * W_SLOT_SIZE + W_ACCIN_NULL_OFF);
    submit_bridge_batch(&provider, env.rollup, &preimage_2).await;
    prove_bridge_batch(&provider, env.rollup, &preimage_2).await;

    // Batch 3: real deposit slot 0, unique batch root GL(12)
    let preimage_3 = patch_batch_root_gl(
        &patch_bridge_deposit_slot(bridge_preimage(), 0, nc, depositor_addr, U256::from(1000u64), 1u64),
        12u64,
    );
    submit_bridge_batch(&provider, env.rollup, &preimage_3).await;
    prove_bridge_batch(&provider, env.rollup, &preimage_3).await;

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000).await.unwrap();

    let pi_1: [u8; 32] = *alloy::primitives::keccak256(&preimage_1);
    let pi_2: [u8; 32] = *alloy::primitives::keccak256(&preimage_2);
    let pi_3: [u8; 32] = *alloy::primitives::keccak256(&preimage_3);

    StateMirrorExpectation::new()
        .pending_bridge_pis(vec![])
        .confirmed_bridge_pis(vec![pi_1, pi_2, pi_3])
        .pending_tx_pis(vec![])
        .confirmed_tx_pis(vec![])
        .state_tree_leaves(3)
        .confirmed_nullifiers(vec![orig_w_null, withdraw_null])
        .pending_nullifiers(vec![])
        .deposits(vec![(nc, DepositStatus::Validated)])
        .subpool_roots(vec![])
        .next_expected_subpool_id(1)
        .pending_subpool_assignments_empty()
        .assert(&service);
}

// ---------------------------------------------------------------------------
// Test 4: Randomized batch ordering
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_randomized_batch_ordering() {
    use rand::RngExt;
    let mut rng = rand::rng();

    // which_batch[i]=true → TX, false → bridge
    let which_batch: [bool; 8] = std::array::from_fn(|_| rng.random::<bool>());

    // is_proven: all true, 3 random distinct indices set to false
    let mut is_proven = [true; 8usize];
    let mut pending_indices = std::collections::HashSet::new();
    while pending_indices.len() < 3 {
        pending_indices.insert((random_gl_u64() % 8) as usize);
    }
    for i in pending_indices {
        is_proven[i] = false;
    }

    // Build 8 distinct preimages
    let preimages: Vec<Vec<u8>> = (0..8)
        .map(|i| {
            if which_batch[i] {
                patch_batch_root_gl(&patch_tx_slot_is_real(tx_preimage(), i), (i as u64) + 1)
            } else {
                patch_batch_root_gl(&patch_bridge_withdraw_slot(bridge_preimage(), i), (i as u64) + 100)
            }
        })
        .collect();

    let pis: Vec<[u8; 32]> = preimages.iter().map(|p| *alloy::primitives::keccak256(p)).collect();

    let (env, provider) = setup_env().await;

    // First half: submit i=0..4, then prove those with is_proven[i]
    for i in 0..4 {
        if which_batch[i] {
            submit_tx_batch(&provider, env.rollup, &preimages[i]).await;
        } else {
            submit_bridge_batch(&provider, env.rollup, &preimages[i]).await;
        }
    }
    for i in 0..4 {
        if is_proven[i] {
            if which_batch[i] {
                prove_tx_batch(&provider, env.rollup, &preimages[i]).await;
            } else {
                prove_bridge_batch(&provider, env.rollup, &preimages[i]).await;
            }
        }
    }

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000).await.unwrap();

    // Second half: submit i=4..8, then prove those with is_proven[i]
    for i in 4..8 {
        if which_batch[i] {
            submit_tx_batch(&provider, env.rollup, &preimages[i]).await;
        } else {
            submit_bridge_batch(&provider, env.rollup, &preimages[i]).await;
        }
    }
    for i in 4..8 {
        if is_proven[i] {
            if which_batch[i] {
                prove_tx_batch(&provider, env.rollup, &preimages[i]).await;
            } else {
                prove_bridge_batch(&provider, env.rollup, &preimages[i]).await;
            }
        }
    }

    service.poll_sync(&provider, env.rollup, 1000).await.unwrap();

    // Compute expected batch PI sets
    let confirmed_tx: Vec<[u8; 32]> = (0..8usize).filter(|&i| which_batch[i] && is_proven[i]).map(|i| pis[i]).collect();
    let confirmed_br: Vec<[u8; 32]> = (0..8usize).filter(|&i| !which_batch[i] && is_proven[i]).map(|i| pis[i]).collect();
    let pending_tx: Vec<[u8; 32]>   = (0..8usize).filter(|&i| which_batch[i] && !is_proven[i]).map(|i| pis[i]).collect();
    let pending_br: Vec<[u8; 32]>   = (0..8usize).filter(|&i| !which_batch[i] && !is_proven[i]).map(|i| pis[i]).collect();
    let total_proven = is_proven.iter().filter(|&&p| p).count();

    // Compute expected nullifier sets
    let mut confirmed_nulls: Vec<HashOutput> = Vec::new();
    let mut pending_nulls: Vec<HashOutput>   = Vec::new();
    for i in 0..8 {
        let nullifiers: Vec<HashOutput> = if which_batch[i] {
            // TX batch i: 1 acc_null + 7 note_nulls
            let mut v = vec![extract_hash_from_preimage(&preimages[i], TX_HEADER_SIZE + i * TX_SLOT_SIZE + TX_ACCIN_NULL_OFF)];
            for j in 0..NOTE_BATCH {
                v.push(extract_hash_from_preimage(&preimages[i], TX_HEADER_SIZE + i * TX_SLOT_SIZE + TX_NOTE_IN_OFF + j * 32));
            }
            v
        } else {
            // Bridge batch i: 1 withdrawal acc_null
            vec![extract_hash_from_preimage(&preimages[i], TX_HEADER_SIZE + i * W_SLOT_SIZE + W_ACCIN_NULL_OFF)]
        };
        if is_proven[i] {
            confirmed_nulls.extend_from_slice(&nullifiers);
        } else {
            pending_nulls.extend_from_slice(&nullifiers);
        }
    }

    StateMirrorExpectation::new()
        .confirmed_tx_pis(confirmed_tx)
        .confirmed_bridge_pis(confirmed_br)
        .pending_tx_pis(pending_tx)
        .pending_bridge_pis(pending_br)
        .state_tree_leaves(total_proven)
        .confirmed_nullifiers(confirmed_nulls)
        .pending_nullifiers(pending_nulls)
        .assert(&service);
}

// ---------------------------------------------------------------------------
// Test 5: Subpool lifecycle
// Combines: test_subpool_owner_assigned_sync + test_subpool_root_updated_sync
//           + test_subpool_owner_assigned_sequential
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_subpool_lifecycle() {
    let (env, provider) = setup_env().await;

    // Initial sync: empty subpool state
    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000).await.unwrap();
    StateMirrorExpectation::new()
        .subpool_roots(vec![])
        .next_expected_subpool_id(1)
        .pending_subpool_assignments_empty()
        .assert(&service);

    // Assign subpools 1, 2, 3 sequentially
    for id in 1u64..=3 {
        ITesseraRollupV2::new(env.rollup, &provider)
            .assignSubpoolOwner(id, env.operator)
            .send().await.unwrap().get_receipt().await.unwrap();
    }

    service.poll_sync(&provider, env.rollup, 1000).await.unwrap();

    StateMirrorExpectation::new()
        .subpool_roots(vec![(1, HashOutput::ZERO), (2, HashOutput::ZERO), (3, HashOutput::ZERO)])
        .next_expected_subpool_id(4)
        .pending_subpool_assignments_empty()
        .assert(&service);

    // Verify config_tree root matches on-chain
    let onchain_root = ITesseraRollupV2::new(env.rollup, &provider).mainPoolConfigRoot().call().await.unwrap();
    let local_root = service.with_state(|s| hash_to_u256_le(&s.config_tree.root()));
    assert_eq!(onchain_root, local_root);

    // Update subpool 2 root
    let new_root = HashOutput([F::ONE, F::ZERO, F::ZERO, F::ZERO]);
    let siblings: Vec<U256> = service.with_state(|s| {
        use tessera_client::SubpoolId;
        let proof = s.config_tree.subpool_proof(SubpoolId(F::from_canonical_u64(2)), HashOutput::ZERO).unwrap();
        proof.siblings.iter().map(hash_to_u256_le).collect()
    });

    ITesseraRollupV2::new(env.rollup, &provider)
        .updateSubpoolRoot(2u64, hash_to_u256_le(&new_root), siblings)
        .send().await.unwrap().get_receipt().await.unwrap();

    service.poll_sync(&provider, env.rollup, 1000).await.unwrap();

    StateMirrorExpectation::new()
        .subpool_roots(vec![(1, HashOutput::ZERO), (2, new_root), (3, HashOutput::ZERO)])
        .next_expected_subpool_id(4)
        .pending_subpool_assignments_empty()
        .assert(&service);

    // Verify config_tree root matches on-chain again
    let onchain_root = ITesseraRollupV2::new(env.rollup, &provider).mainPoolConfigRoot().call().await.unwrap();
    let local_root = service.with_state(|s| hash_to_u256_le(&s.config_tree.root()));
    assert_eq!(onchain_root, local_root);
}

// ---------------------------------------------------------------------------
// Test 6: Deposit lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_deposit_lifecycle() {
    let (env, provider) = setup_env().await;

    ITesseraRollupV2::new(env.rollup, &provider)
        .registerAsset(U256::from(1u64), env.token)
        .send().await.unwrap().get_receipt().await.unwrap();

    let (depositor_addr, dep_provider) = depositor_provider(&env);
    mint_and_approve(env.token, env.rollup, depositor_addr, U256::from(1000u64), &provider, &dep_provider).await;

    let nc = random_gl_b32();
    ITesseraRollupV2::new(env.rollup, &dep_provider)
        .depositAndRegister(B256::from(nc), U256::from(1u64), U256::from(1000u64))
        .send().await.unwrap().get_receipt().await.unwrap();

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000).await.unwrap();
    StateMirrorExpectation::new()
        .deposits(vec![(nc, DepositStatus::Pending)])
        .assert(&service);

    // Withdraw the deposit
    ITesseraRollupV2::new(env.rollup, &dep_provider)
        .withdrawPendingDeposit(B256::from(nc))
        .send().await.unwrap().get_receipt().await.unwrap();

    service.poll_sync(&provider, env.rollup, 1000).await.unwrap();

    StateMirrorExpectation::new()
        .deposits(vec![(nc, DepositStatus::Withdrawn)])
        .assert(&service);
}

// ---------------------------------------------------------------------------
// Test 7: Deposit validated via bridge batch
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
// Test 8: API commitment queries
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_api_commitment_queries() {
    let (env, provider) = setup_env().await;
    submit_tx_batch(&provider, env.rollup, tx_preimage()).await;

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000).await.unwrap();

    // Extract the account-output commitment for slot 0
    let comm_gl: [u8; 32] = tx_preimage()[TX_HEADER_SIZE + TX_ACCOUT_COMM_OFF..TX_HEADER_SIZE + TX_ACCOUT_COMM_OFF + 32].try_into().unwrap();
    let comm_raw = preimage_bytes32_to_raw(&B256::from(comm_gl));
    let comm_hash = bytes32_to_hash(&B256::from(comm_raw)).unwrap();
    let comm_hex = format!("0x{}", hex::encode(hash_to_bytes32(&comm_hash)));

    // Not found: random commitment
    let resp = get_commitment_merkle_path(
        Query(CommitmentQuery { commitment: format!("0x{}", "00".repeat(32)) }),
        State(service.clone()),
    ).await.unwrap();
    assert_eq!(resp.0["status"], "not_found");

    // Pending: batch submitted but not proven
    let resp = get_commitment_merkle_path(
        Query(CommitmentQuery { commitment: comm_hex.clone() }),
        State(service.clone()),
    ).await.unwrap();
    assert_eq!(resp.0["status"], "pending");

    // Prove and re-sync
    prove_tx_batch(&provider, env.rollup, tx_preimage()).await;
    service.poll_sync(&provider, env.rollup, 1000).await.unwrap();

    // Confirmed: batch proven
    let resp = get_commitment_merkle_path(
        Query(CommitmentQuery { commitment: comm_hex }),
        State(service),
    ).await.unwrap();
    assert_eq!(resp.0["status"], "confirmed");
    assert!(!resp.0["batch_subtree_path"].is_null());
    assert!(!resp.0["state_tree_path"].is_null());
}

// ---------------------------------------------------------------------------
// Test 9: API nullifier queries
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_api_nullifier_queries() {
    let patched = patch_tx_slot_is_real(tx_preimage(), 0);
    let (env, provider) = setup_env().await;
    submit_tx_batch(&provider, env.rollup, &patched).await;

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000).await.unwrap();

    let null_gl: [u8; 32] = patched[TX_HEADER_SIZE + TX_ACCIN_NULL_OFF..TX_HEADER_SIZE + TX_ACCIN_NULL_OFF + 32].try_into().unwrap();
    let null_raw = preimage_bytes32_to_raw(&B256::from(null_gl));
    let null_hash = bytes32_to_hash(&B256::from(null_raw)).unwrap();
    let nullifier_hex = format!("0x{}", hex::encode(hash_to_bytes32(&null_hash)));

    // Not found
    let resp = get_nullifier_status(
        Query(NullifierQuery { nullifier: format!("0x{}", "00".repeat(32)) }),
        State(service.clone()),
    ).await.unwrap();
    assert_eq!(resp.0["status"], "not_found");

    // Pending
    let resp = get_nullifier_status(
        Query(NullifierQuery { nullifier: nullifier_hex.clone() }),
        State(service.clone()),
    ).await.unwrap();
    assert_eq!(resp.0["status"], "pending");

    // Prove and poll
    prove_tx_batch(&provider, env.rollup, &patched).await;
    service.poll_sync(&provider, env.rollup, 1000).await.unwrap();

    // Confirmed
    let resp = get_nullifier_status(
        Query(NullifierQuery { nullifier: nullifier_hex }),
        State(service),
    ).await.unwrap();
    assert_eq!(resp.0["status"], "confirmed");
}

// ---------------------------------------------------------------------------
// Test 10: API batch status queries
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_api_batch_status_queries() {
    let (env, provider) = setup_env().await;

    let service_empty = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000).await.unwrap();

    // Not found
    let resp = get_batch_status(
        Query(BatchQuery { pi_commitment: format!("0x{}", "00".repeat(32)), kind: "tx".to_string() }),
        State(service_empty),
    ).await.unwrap();
    assert_eq!(resp.0["status"], "not_found");

    // Submit batch → pending
    submit_tx_batch(&provider, env.rollup, tx_preimage()).await;
    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000).await.unwrap();
    let pi: [u8; 32] = *alloy::primitives::keccak256(tx_preimage());
    let pi_hex = format!("0x{}", hex::encode(pi));

    let resp = get_batch_status(
        Query(BatchQuery { pi_commitment: pi_hex.clone(), kind: "tx".to_string() }),
        State(service.clone()),
    ).await.unwrap();
    assert_eq!(resp.0["status"], "pending");

    // Prove → confirmed
    prove_tx_batch(&provider, env.rollup, tx_preimage()).await;
    service.poll_sync(&provider, env.rollup, 1000).await.unwrap();

    let resp = get_batch_status(
        Query(BatchQuery { pi_commitment: pi_hex, kind: "tx".to_string() }),
        State(service),
    ).await.unwrap();
    assert_eq!(resp.0["status"], "confirmed");
}

// ---------------------------------------------------------------------------
// Test 11: API bridge batch status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_api_bridge_batch_status() {
    let (env, provider) = setup_env().await;

    let pi: [u8; 32] = *alloy::primitives::keccak256(bridge_preimage());
    let pi_hex = format!("0x{}", hex::encode(pi));

    // Submit only → check pending (service consumed here, no clone)
    submit_bridge_batch(&provider, env.rollup, bridge_preimage()).await;
    let service_pending = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000).await.unwrap();
    let resp = get_batch_status(
        Query(BatchQuery { pi_commitment: pi_hex.clone(), kind: "bridge".to_string() }),
        State(service_pending),
    ).await.unwrap();
    assert_eq!(resp.0["status"], "pending");

    // Prove → check confirmed (fresh service, no clone)
    prove_bridge_batch(&provider, env.rollup, bridge_preimage()).await;
    let service_confirmed = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000).await.unwrap();
    let resp = get_batch_status(
        Query(BatchQuery { pi_commitment: pi_hex, kind: "bridge".to_string() }),
        State(service_confirmed),
    ).await.unwrap();
    assert_eq!(resp.0["status"], "confirmed");
}

// ---------------------------------------------------------------------------
// Test 12: API deposits
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_api_deposits() {
    let (env, provider) = setup_env().await;

    ITesseraRollupV2::new(env.rollup, &provider)
        .registerAsset(U256::from(1u64), env.token)
        .send().await.unwrap().get_receipt().await.unwrap();

    let (depositor_addr, dep_provider) = depositor_provider(&env);
    mint_and_approve(env.token, env.rollup, depositor_addr, U256::from(1000u64), &provider, &dep_provider).await;

    let nc1 = random_gl_b32();
    let nc2 = random_gl_b32();

    // First deposit
    let receipt1 = ITesseraRollupV2::new(env.rollup, &dep_provider)
        .depositAndRegister(B256::from(nc1), U256::from(1u64), U256::from(500u64))
        .send().await.unwrap().get_receipt().await.unwrap();
    let block1 = receipt1.block_number.unwrap();

    // Second deposit (next block)
    ITesseraRollupV2::new(env.rollup, &dep_provider)
        .depositAndRegister(B256::from(nc2), U256::from(1u64), U256::from(500u64))
        .send().await.unwrap().get_receipt().await.unwrap();

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000).await.unwrap();

    // All deposits
    let resp = get_deposits(Query(DepositsQuery { from_block: None }), State(service.clone())).await.unwrap();
    assert_eq!(resp.0.as_array().unwrap().len(), 2);

    // from_block = block1+1 → only nc2
    let resp = get_deposits(Query(DepositsQuery { from_block: Some(block1 + 1) }), State(service.clone())).await.unwrap();
    assert_eq!(resp.0.as_array().unwrap().len(), 1);

    // from_block = 0 → both
    let resp = get_deposits(Query(DepositsQuery { from_block: Some(0) }), State(service)).await.unwrap();
    assert_eq!(resp.0.as_array().unwrap().len(), 2);
}

// ---------------------------------------------------------------------------
// Test 13: API subpool
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_api_subpool() {
    let (env, provider) = setup_env().await;

    let service = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000).await.unwrap();

    // Not found
    let result = get_subpool_full_proof(Query(SubpoolQuery { subpool_id: 1 }), State(service)).await;
    use axum::http::StatusCode;
    assert_eq!(result.unwrap_err(), StatusCode::NOT_FOUND);

    // Assign subpool 1 and sync
    ITesseraRollupV2::new(env.rollup, &provider)
        .assignSubpoolOwner(1u64, env.operator)
        .send().await.unwrap().get_receipt().await.unwrap();

    let service2 = StateSyncService::sync_from_genesis(&provider, env.rollup, 1000).await.unwrap();
    let result = get_subpool_full_proof(Query(SubpoolQuery { subpool_id: 1 }), State(service2)).await;
    let json = result.unwrap().0;
    assert_eq!(json["subpool_id"], 1u64);
    assert_eq!(json["siblings"].as_array().unwrap().len(), 20);
}
