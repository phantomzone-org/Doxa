# 14 — Streaming Aggregation Pipeline with Distributed Proving

## Context

The current `GenericAggregator::aggregate()` proves all `arity^depth` leaf proofs
sequentially, one level at a time.  Benchmarks on a single machine:

| Config | Seq. wall time | Theoretical min (critical path) |
|---|---|---|
| 2^7 (128 leaves) | 37.5 s | 7.9 s |
| 4^4 (256 leaves) | ~41 s | 8.4 s |

The gap is closed by two complementary techniques:

1. **Streaming dispatch** — an internal tree node starts proving as soon as its
   `arity` children are available, without waiting for all siblings at the same
   level to complete.

2. **Distributed proving** — node proving tasks are dispatched (push) to a pool
   of workers that can be local threads or remote HTTP provers.  The pool uses
   *least-inflight* selection: work always goes to the worker with the fewest
   outstanding tasks.

---

## Architecture overview

```
[Coordinator — AssociatedInputAggregatorService]
        │
        ├─ AggregationSession (tokio actor, tessera-server)
        │     state: Vec<Vec<NodeState>>
        │     channel: PipelineMsg (LeafProof | NodeProven | NodeFailed)
        │
        ├─ NodeProverPool (tessera-server)
        │     ├─ LocalAsyncNodeProver  → spawn_blocking → LocalNodeProver
        │     ├─ RemoteNodeProver("http://agg-1:8092") → POST /prove-node
        │     └─ RemoteNodeProver("http://agg-2:8092") → POST /prove-node
        │
        └─ AggregationInputHandle  ← leaf proofs arrive here

[aggregation_prover binary — stateless, one per cluster node]
        POST /prove-node: deserialise children → prove → return proof bytes
```

`tessera-trees` remains **sync / no-tokio**.  All async orchestration lives in
`tessera-server`.

---

## Node addressing

For a tree of `arity` and `depth`:

| Concept | Formula |
|---|---|
| Nodes at level `l` | `arity^(depth - 1 - l)` |
| Level 0 parent of leaf `i` | `i / arity` |
| Position within that node | `i % arity` |
| Parent of node `(l, j)` | level `l+1`, index `j / arity`, position `j % arity` |

---

## Step-by-step implementation

### Step 1 — Public accessors on `GenericAggregator`

**File:** `tessera-trees/src/proof_aggregation/generic.rs`

Add three methods to the *generic* `impl` block (not the monomorphised one):

```
fn config(&self) -> &GenericAggregatorConfig

fn level_circuit(&self, level: usize) -> Result<&LevelCircuit<F, C, D>>
    // Returns Err if level >= self.levels.len()

fn inner_verifier_for_level(&self, level: usize) -> &VerifierOnlyCircuitData<C, D>
    // level == 0  →  &self.leaf_verifier
    // level  > 0  →  &self.levels[level - 1].circuit_data.verifier_only
    // Panics if level >= self.levels.len() (caller's responsibility)
```

**Why:** downstream code in `tessera-server` (different crate) needs to read
these to build `PartialWitness` objects for node proving.  The existing
`leaf_common()` getter stays as-is.

**Tests to add** (in `generic.rs` test module):

| Test | What it checks |
|---|---|
| `test_config_accessor` | `config()` returns the same arity/depth/reducer used at construction |
| `test_level_circuit_valid` | `level_circuit(0)` and `level_circuit(depth-1)` return `Ok` |
| `test_level_circuit_oob` | `level_circuit(depth)` returns `Err` |
| `test_inner_verifier_level0` | matches `leaf_verifier` by address / equality |
| `test_inner_verifier_level1` | matches `levels[0].circuit_data.verifier_only` |

---

### Step 2 — `NodeProver` trait and `LocalNodeProver`

**New file:** `tessera-trees/src/proof_aggregation/node_prover.rs`

```
pub trait NodeProver<F, C, const D>: Send + Sync
where F: RichField + Extendable<D>, C: GenericConfig<D, F=F>
{
    /// Blocking — intended to be called from spawn_blocking.
    fn prove_node_blocking(
        &self,
        level:    usize,
        node_idx: usize,            // used only for logging/tracing
        children: Vec<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>>;
}

pub struct LocalNodeProver<F, C, const D> {
    aggregator: Arc<GenericAggregator<F, C, D>>,
}

impl LocalNodeProver { pub fn new(aggregator: Arc<GenericAggregator<...>>) -> Self }

impl NodeProver for LocalNodeProver {
    fn prove_node_blocking(&self, level, node_idx, children) -> Result<Proof> {
        let level_circuit   = self.aggregator.level_circuit(level)?;
        let inner_verifier  = self.aggregator.inner_verifier_for_level(level);
        let mut pw = PartialWitness::new();
        pw.set_verifier_data_target(&level_circuit.verifier_target, inner_verifier)?;
        for (i, child) in children.iter().enumerate() {
            pw.set_proof_with_pis_target(&level_circuit.proof_targets[i], child)?;
        }
        level_circuit.circuit_data.prove(pw)
    }
}
```

**Update** `tessera-trees/src/proof_aggregation/mod.rs`:

```
pub mod node_prover;
pub use node_prover::{LocalNodeProver, NodeProver};
```

**Tests to add** (in `node_prover.rs` test module — or a dedicated integration
file under `tessera-trees/tests/`):

| Test | What it checks |
|---|---|
| `test_local_prover_level0_arity2` | Build leaf circuit; prove 2 leaves; wrap in `Arc<GenericAggregator>`; call `prove_node_blocking(level=0, node_idx=0, children)`; verify resulting proof with `aggregator.level_circuit(0).circuit_data.verify()` |
| `test_local_prover_wrong_child_count` | Pass 3 children when arity=2; expect `Err` (plonky2 target count mismatch) |

---

### Step 3 — HTTP protocol types

**File:** `tessera-server/src/aggregation_pipeline/types.rs`  (new file)

```
/// Sent by coordinator to a remote aggregation prover.
#[derive(Serialize, Deserialize)]
pub struct ProveNodeRequest {
    pub level:    usize,
    pub node_idx: usize,
    /// Hex-encoded `ProofWithPublicInputs::to_bytes()` for each child,
    /// in order (index 0 = position 0 within the node).
    pub children: Vec<String>,
}

/// Returned by a remote aggregation prover.
#[derive(Serialize, Deserialize)]
pub struct ProveNodeResponse {
    /// Hex-encoded `ProofWithPublicInputs::to_bytes()` of the proven node.
    pub proof: String,
}
```

These types are the only shared serialization contract between coordinator and
workers.  They carry no circuit data — workers load their own artifacts.

**No tests needed** for the types themselves; they are covered by the round-trip
tests in Step 6.

---

### Step 4 — `NodeProverPool` and `RemoteNodeProver`

**New file:** `tessera-server/src/aggregation_pipeline/pool.rs`

```
/// Async counterpart to NodeProver; drives remote or local proving.
#[async_trait]
pub trait AsyncNodeProver<F, C, const D>: Send + Sync {
    async fn prove_node(
        &self,
        level:    usize,
        node_idx: usize,
        children: Vec<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>>;
    fn inflight(&self) -> usize;   // current in-flight count
}

/// Wraps a LocalNodeProver for async use via spawn_blocking.
pub struct LocalAsyncNodeProver<F, C, const D> {
    inner:    Arc<LocalNodeProver<F, C, D>>,
    inflight: AtomicUsize,
}

impl AsyncNodeProver for LocalAsyncNodeProver {
    async fn prove_node(&self, level, node_idx, children) -> Result<Proof> {
        self.inflight.fetch_add(1, SeqCst);
        let inner = self.inner.clone();
        let result = spawn_blocking(move || inner.prove_node_blocking(level, node_idx, children))
            .await?;
        self.inflight.fetch_sub(1, SeqCst);
        result
    }
    fn inflight(&self) -> usize { self.inflight.load(Relaxed) }
}

/// Sends proving work to a remote aggregation_prover service.
pub struct RemoteNodeProver<F, C, const D> {
    client:     reqwest::Client,
    base_url:   String,
    aggregator: Arc<GenericAggregator<F, C, D>>,   // for proof (de)serialisation
    inflight:   AtomicUsize,
    timeout:    Duration,
}

impl AsyncNodeProver for RemoteNodeProver {
    async fn prove_node(&self, level, node_idx, children) -> Result<Proof> {
        // 1. Serialise children: proof.to_bytes() → hex
        // 2. POST self.base_url + "/prove-node"
        // 3. Deserialise response: hex → from_bytes(level_circuit(level).common)
        self.inflight.fetch_add(1, SeqCst);
        let req = build_request(level, node_idx, children);
        let resp = self.client.post(url).json(&req).timeout(self.timeout).send().await;
        self.inflight.fetch_sub(1, SeqCst);
        deserialise_response(resp?, level, &self.aggregator)
    }
    fn inflight(&self) -> usize { self.inflight.load(Relaxed) }
}

/// Dispatches node-prove tasks to the least-inflight worker.
/// Falls back to the next-least worker on failure (up to pool.len() retries).
pub struct NodeProverPool<F, C, const D> {
    provers: Vec<Arc<dyn AsyncNodeProver<F, C, D>>>,
}

impl NodeProverPool {
    pub fn new(provers: Vec<Arc<dyn AsyncNodeProver<F, C, D>>>) -> Self
    pub async fn prove_node(
        &self,
        level:    usize,
        node_idx: usize,
        children: Vec<ProofWithPublicInputs<F, C, D>>,
    ) -> Result<ProofWithPublicInputs<F, C, D>>
    // Selection: provers.iter().min_by_key(|p| p.inflight())
    // Retry: on Err, try next-least-inflight; after all provers exhausted → Err
}
```

**Child deserialisation on remote path:**

```
level == 0  →  use aggregator.leaf_common() as CommonCircuitData
level  > 0  →  use aggregator.level_circuit(level - 1)?.circuit_data.common
```

**Tests to add:**

| Test | What it checks |
|---|---|
| `test_pool_least_inflight_empty_pool` | Empty pool returns Err immediately |
| `test_pool_dispatch_to_lowest` | Three mock provers with inflight counts 2, 0, 1; dispatch goes to index 1 |
| `test_pool_retry_on_failure` | First prover always returns Err; second succeeds; pool returns Ok |
| `test_pool_all_fail` | All provers return Err; pool returns Err |
| `test_remote_prover_serialise_roundtrip` | Build a real proof; serialise to hex; deserialise; verify it matches original `public_inputs` |

For mock provers: define a `MockAsyncNodeProver { inflight: AtomicUsize, result: fn() -> Result<Proof> }` in a `#[cfg(test)]` block.

---

### Step 5 — `AggregationSession` actor

**New file:** `tessera-server/src/aggregation_pipeline/session.rs`

#### Internal types

```
struct NodeState<F, C, const D> {
    children: Vec<Option<ProofWithPublicInputs<F, C, D>>>,
    filled:   usize,
}

impl NodeState {
    fn new(arity: usize) -> Self
    fn insert(&mut self, pos: usize, proof: Proof) -> Result<()>  // Err on duplicate pos
    fn is_full(&self) -> bool { self.filled == self.children.len() }
    fn drain_children(&mut self) -> Vec<Proof>  // takes all children out
}

enum PipelineMsg<F, C, const D> {
    LeafProof  { leaf_idx: usize, proof: ProofWithPublicInputs<F, C, D> },
    NodeProven { level: usize, node_idx: usize, proof: ProofWithPublicInputs<F, C, D> },
    NodeFailed { level: usize, node_idx: usize, error: anyhow::Error },
}
```

#### Public types

```
/// Clonable handle for submitting leaf proofs.
pub struct AggregationInputHandle<F, C, const D> {
    tx:          mpsc::Sender<PipelineMsg<F, C, D>>,
    n_leaves:    usize,   // arity^depth — for out-of-bounds check
    leaf_common: Arc<CommonCircuitData<F, D>>,
}

impl AggregationInputHandle {
    /// Submit the deserialized proof for slot `leaf_idx`.
    pub async fn submit(
        &self,
        leaf_idx: usize,
        proof: ProofWithPublicInputs<F, C, D>,
    ) -> Result<()>

    /// Convenience: deserialise from bytes and submit.
    pub async fn submit_bytes(&self, leaf_idx: usize, bytes: Vec<u8>) -> Result<()>
}

/// Future that resolves to the root proof (or Err if the session failed/was dropped).
pub struct AggregationRootFuture<F, C, const D>(oneshot::Receiver<Result<...>>);

impl Future for AggregationRootFuture { type Output = Result<ProofWithPublicInputs<F, C, D>>; }
```

#### Session constructor

```
pub fn start_aggregation_session<F, C, const D>(
    aggregator: Arc<GenericAggregator<F, C, D>>,
    pool:       Arc<NodeProverPool<F, C, D>>,
) -> (AggregationInputHandle<F, C, D>, AggregationRootFuture<F, C, D>)
```

Internally:

1. Creates `mpsc::channel::<PipelineMsg>(arity^depth)` (bounded — backpressure).
2. Creates `oneshot::channel::<Result<Proof>>`.
3. Initialises `tree: Vec<Vec<NodeState>>`:
   - `depth` levels; level `l` has `arity^(depth-1-l)` nodes, each with `arity` slots.
4. Spawns the actor task via `tokio::spawn`.
5. Returns `(AggregationInputHandle { tx, n_leaves, leaf_common }, AggregationRootFuture(rx))`.

#### Actor loop

```
loop {
    match actor_rx.recv().await {
        None => {
            // All senders dropped (handle + all proving tasks) without a root proof.
            // Session was abandoned before completion.
            let _ = root_tx.send(Err(anyhow!("session abandoned before root proof")));
            return;
        }

        Some(LeafProof { leaf_idx, proof }) => {
            let node_idx = leaf_idx / arity;
            let pos      = leaf_idx % arity;
            tree[0][node_idx].insert(pos, proof)?;   // Err → send to root_tx and return
            if tree[0][node_idx].is_full() {
                dispatch(pool, actor_tx.clone(), 0, node_idx,
                         tree[0][node_idx].drain_children());
            }
        }

        Some(NodeProven { level, node_idx, proof }) => {
            if level == depth - 1 {
                let _ = root_tx.send(Ok(proof));
                return;                              // actor exits; remaining sends fail silently
            }
            let parent_level = level + 1;
            let parent_idx   = node_idx / arity;
            let pos          = node_idx % arity;
            tree[parent_level][parent_idx].insert(pos, proof)?;
            if tree[parent_level][parent_idx].is_full() {
                dispatch(pool, actor_tx.clone(), parent_level, parent_idx,
                         tree[parent_level][parent_idx].drain_children());
            }
        }

        Some(NodeFailed { level, node_idx, error }) => {
            let _ = root_tx.send(Err(anyhow!("node ({level},{node_idx}) failed: {error}")));
            return;
        }
    }
}
```

`dispatch` is a free `async fn` (called with `tokio::spawn`):

```
async fn dispatch<F, C, const D>(
    pool:     Arc<NodeProverPool<F, C, D>>,
    actor_tx: mpsc::Sender<PipelineMsg<F, C, D>>,
    level:    usize,
    node_idx: usize,
    children: Vec<ProofWithPublicInputs<F, C, D>>,
) {
    tokio::spawn(async move {
        match pool.prove_node(level, node_idx, children).await {
            Ok(proof) => { let _ = actor_tx.send(NodeProven { level, node_idx, proof }).await; }
            Err(e)    => { let _ = actor_tx.send(NodeFailed { level, node_idx, error: e }).await; }
        }
    });
}
```

**Edge cases:**
- `leaf_idx >= n_leaves`: `insert` on `tree[0]` will panic or return Err; validate in `submit()` before sending.
- Duplicate `leaf_idx`: `NodeState::insert` returns `Err("duplicate position")` → actor sends to `root_tx` and exits.
- Depth == 1: the single level is both level-0 and root; `NodeProven { level=0 }` triggers the `level == depth-1` branch immediately.

**Tests to add:**

| Test | What it checks |
|---|---|
| `test_node_state_fill_and_drain` | Insert `arity` proofs one at a time; verify `is_full()` flips at correct point; `drain_children()` returns all and leaves slots empty |
| `test_node_state_duplicate_insert` | Insert same `pos` twice; expect `Err` |
| `test_session_arity2_depth1` | 2 leaf proofs → root, using `LocalAsyncNodeProver`; verify `AggregationRootFuture` resolves with a proof that passes `aggregator.verify_root()` |
| `test_session_arity2_depth2` | 4 leaf proofs → root |
| `test_session_arity2_depth3` | 8 leaf proofs; submit in random order; verify root |
| `test_session_out_of_order_submit` | Submit leaf 3 before leaf 0; verify root still arrives |
| `test_session_duplicate_leaf_idx` | Submit same `leaf_idx` twice; verify root future resolves to `Err` |
| `test_session_oob_leaf_idx` | `submit(leaf_idx = n_leaves)` returns `Err` |
| `test_session_handle_dropped_early` | Drop handle after 1 of 4 proofs; verify root future resolves to `Err` containing "abandoned" |
| `test_session_node_failure_propagates` | Mock pool returns `Err` on first dispatch; verify root future carries the error |

For tests that need a real `GenericAggregator`, use `arity=2, depth=1` (fastest to build).  Gate
heavier tests (`depth=2`, `depth=3`) under `#[ignore]` so `cargo test` stays fast.

---

### Step 6 — `aggregation_prover` binary

**New file:** `tessera-server/src/bin/aggregation_prover.rs`

Axum HTTP server with a single route: `POST /prove-node`.

#### Handler

```
async fn prove_node_handler(
    State(state): State<AppState>,
    Json(req):    Json<ProveNodeRequest>,
) -> Result<Json<ProveNodeResponse>, StatusCode> {

    let agg = state.aggregator.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<ProveNodeResponse> {

        // 1. Determine CommonCircuitData for child deserialisation.
        let child_common = if req.level == 0 {
            agg.leaf_common().clone()
        } else {
            agg.level_circuit(req.level - 1)?.circuit_data.common.clone()
        };

        // 2. Deserialise children.
        let children = req.children
            .iter()
            .map(|hex| {
                let bytes = hex::decode(hex)?;
                ProofNative::from_bytes(bytes, &child_common)
                    .map_err(|e| anyhow!("child deserialisation failed: {e:?}"))
            })
            .collect::<Result<Vec<_>>>()?;

        // 3. Prove using LocalNodeProver.
        let local = LocalNodeProver::new(agg.clone());
        let proof = local.prove_node_blocking(req.level, req.node_idx, children)?;

        // 4. Serialise result.
        Ok(ProveNodeResponse { proof: hex::encode(proof.to_bytes()) })
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .map_err(|e| { error!("{e}"); StatusCode::INTERNAL_SERVER_ERROR })?;

    Ok(Json(result))
}
```

#### AppState

```
#[derive(Clone)]
struct AppState {
    aggregator: Arc<GenericAggregator<F, ConfigNative, D>>,
}
```

#### `main`

```
#[tokio::main]
async fn main() -> Result<()> {
    let config  = AggregatorProverConfig::from_env()?;
    let agg     = GenericAggregator::<F, ConfigNative, D>::from_artifacts(&config.artifacts_path)?;
    let state   = AppState { aggregator: Arc::new(agg) };
    let app     = Router::new()
        .route("/prove-node", post(prove_node_handler))
        .with_state(state);
    let listener = TcpListener::bind(&config.api_bind_addr).await?;
    info!(addr = %config.api_bind_addr, "aggregation prover listening");
    axum::serve(listener, app).await?;
    Ok(())
}
```

#### New config type in `tessera-server/src/config.rs`

```
pub struct AggregatorProverConfig {
    pub artifacts_path: PathBuf,    // TESSERA_AGGREGATOR_ARTIFACTS_PATH (required)
    pub api_bind_addr:  String,     // TESSERA_AGGREGATION_PROVER_ADDR (default 0.0.0.0:8092)
}
```

**Tests to add** (in `tests/aggregation_prover_integration.rs` or in-binary):

| Test | What it checks |
|---|---|
| `test_prove_node_handler_level0` | Spin up `axum::Router` in-process using `axum_test` or `tower::ServiceExt`; send a real `ProveNodeRequest` for level 0; verify response deserialises and passes circuit verification |
| `test_prove_node_handler_bad_hex` | Send malformed hex in children; expect 500 |
| `test_prove_node_handler_wrong_level` | Send `level = 99`; expect 500 (level out of range) |

These tests run against a real `GenericAggregator` artifact; gate under `#[ignore]` if artifacts
are not present, or use `arity=2, depth=1` built in the test itself.

---

### Step 7 — Config updates for coordinator

**File:** `tessera-server/src/config.rs`

Add two fields to `ProverConfig`:

```
/// Comma-separated list of remote aggregation prover base URLs.
/// When empty (default) the coordinator uses only a local prover.
/// Set via TESSERA_AGGREGATION_PROVER_URLS.
pub aggregation_prover_urls: Vec<String>,

/// Per-request HTTP timeout for remote aggregation provers (seconds).
/// Set via TESSERA_AGGREGATION_PROVER_TIMEOUT_SECS (default 300).
pub aggregation_prover_timeout_secs: u64,
```

Parsing:

```
let aggregation_prover_urls: Vec<String> = std::env::var("TESSERA_AGGREGATION_PROVER_URLS")
    .unwrap_or_default()
    .split(',')
    .map(str::trim)
    .filter(|s| !s.is_empty())
    .map(String::from)
    .collect();
```

**No new tests** — covered by existing config unit tests; extend them to verify new field defaults.

---

### Step 8 — Wire `AggregationSession` into `prover.rs`

This step replaces the synchronous `aggregate_bytes` call in
`AssociatedInputAggregatorService` with the streaming session.

#### Changes to `AssociatedInputAggregatorService`

```
pub struct AssociatedInputAggregatorService {
    aggregator: Arc<GenericAggregator<F, ConfigNative, D>>,
    pool:       Arc<NodeProverPool<F, ConfigNative, D>>,
}

impl AssociatedInputAggregatorService {
    pub fn from_artifacts_and_pool(
        path: &Path,
        pool: Arc<NodeProverPool<F, ConfigNative, D>>,
    ) -> Result<Self>

    /// Submit all leaf proof bytes to a streaming session, await the root proof.
    pub async fn aggregate_bytes(&self, proof_bytes: &[Vec<u8>]) -> Result<ProofNative> {
        let (handle, root_fut) = start_aggregation_session(
            self.aggregator.clone(),
            self.pool.clone(),
        );
        for (i, bytes) in proof_bytes.iter().enumerate() {
            handle.submit_bytes(i, bytes.clone()).await?;
        }
        drop(handle);
        root_fut.await
    }
}
```

#### Changes to `ProverRuntime`

- `aggregator: Option<AssociatedInputAggregatorService>` stays as-is (type is updated above).
- `verify_and_aggregate_associated_input_proofs` becomes `async fn`; callers inside
  `prove_request` must be updated accordingly.

#### Changes to `ProverRuntime::init`

```
pub async fn init(
    ...
    aggregator_artifacts_path: Option<PathBuf>,
    aggregation_prover_urls:   Vec<String>,
    aggregation_prover_timeout_secs: u64,
) -> Result<Self> {
    let pool = build_pool(
        aggregator_artifacts_path.as_deref(),
        &aggregation_prover_urls,
        Duration::from_secs(aggregation_prover_timeout_secs),
    )?;
    let aggregator = aggregator_artifacts_path
        .map(|p| AssociatedInputAggregatorService::from_artifacts_and_pool(&p, pool.clone()))
        .transpose()?;
    ...
}
```

`build_pool` constructs:
1. A `LocalAsyncNodeProver` (always present — the fallback).
2. One `RemoteNodeProver` per URL in `aggregation_prover_urls`.
3. Returns `Arc<NodeProverPool>` containing all of them.

#### Changes to `prover_thread`

The existing `prover_thread` is sync (blocking recv loop).  `prove_request` now
needs an async context for `verify_and_aggregate_associated_input_proofs`.

Two options — **choose Option A** for minimal diff:

**Option A (recommended):** Keep `prover_thread` blocking; add a per-request
one-shot tokio runtime for the async aggregation call:

```
// Inside prove_request, where aggregation is called:
let agg_result = tokio::runtime::Handle::current()
    .block_on(Self::verify_and_aggregate_associated_input_proofs_async(&self.aggregator, ...));
```

This works because the prover already runs on a `spawn_blocking` thread which has
access to `Handle::current()` from the outer `#[tokio::main]` runtime.

**Option B:** Convert `prover_thread` to an async task.  Larger diff; deferred
to a follow-up refactor.

#### Changes to `tessera-server/src/bin/prover.rs`

Pass the two new config fields to `ProverRuntime::init`:

```
let runtime = ProverRuntime::init(
    config.plonky2_data_path,
    config.groth16_artifacts_path,
    config.nullifier_plonky2_data_path,
    config.nullifier_groth16_artifacts_path,
    config.batch_size,
    config.aggregator_artifacts_path,
    config.aggregation_prover_urls,          // new
    config.aggregation_prover_timeout_secs,  // new
)?;
```

**Tests to add** (extend existing `prover.rs` tests):

| Test | What it checks |
|---|---|
| `test_aggregate_bytes_local_only` | Build `AssociatedInputAggregatorService` with local-only pool; call `aggregate_bytes` with 2 real proofs (arity=2, depth=1); verify returned root proof |
| `test_aggregate_bytes_all_dummy` | All `[0x01]` inputs → returns stub zero `SolidityProof` as before |
| `test_aggregate_bytes_mixed_dummy_real` | One real, one dummy → `Err` |
| `test_aggregate_bytes_real_no_aggregator` | `aggregator = None`; real proofs → `Err` |

---

### Step 9 — `tessera-server/src/aggregation_pipeline/mod.rs`

Wire the module tree:

```
// tessera-server/src/aggregation_pipeline/mod.rs
mod pool;
mod session;
pub mod types;

pub use pool::{AsyncNodeProver, LocalAsyncNodeProver, NodeProverPool, RemoteNodeProver};
pub use session::{start_aggregation_session, AggregationInputHandle, AggregationRootFuture};
pub use types::{ProveNodeRequest, ProveNodeResponse};
```

Add to `tessera-server/src/lib.rs`:

```
pub mod aggregation_pipeline;
```

---

## Full file map

| File | Status | Change |
|---|---|---|
| `tessera-trees/src/proof_aggregation/generic.rs` | Modify | Add `config()`, `level_circuit()`, `inner_verifier_for_level()` |
| `tessera-trees/src/proof_aggregation/node_prover.rs` | **New** | `NodeProver` trait + `LocalNodeProver` |
| `tessera-trees/src/proof_aggregation/mod.rs` | Modify | `pub mod node_prover` + re-exports |
| `tessera-server/src/aggregation_pipeline/mod.rs` | **New** | Module root + re-exports |
| `tessera-server/src/aggregation_pipeline/session.rs` | **New** | `NodeState`, `PipelineMsg`, `AggregationInputHandle`, `AggregationRootFuture`, `start_aggregation_session`, actor loop |
| `tessera-server/src/aggregation_pipeline/pool.rs` | **New** | `AsyncNodeProver` trait, `LocalAsyncNodeProver`, `RemoteNodeProver`, `NodeProverPool` |
| `tessera-server/src/aggregation_pipeline/types.rs` | **New** | `ProveNodeRequest`, `ProveNodeResponse` |
| `tessera-server/src/bin/aggregation_prover.rs` | **New** | Standalone aggregation prover HTTP server |
| `tessera-server/src/config.rs` | Modify | Add `AggregatorProverConfig`; add 2 fields to `ProverConfig` |
| `tessera-server/src/prover.rs` | Modify | `AssociatedInputAggregatorService` → Arc + pool; `aggregate_bytes` → async; `init` takes 2 new args |
| `tessera-server/src/bin/prover.rs` | Modify | Pass 2 new config fields to `init` |
| `tessera-server/src/lib.rs` | Modify | `pub mod aggregation_pipeline` |

---

## Complete test matrix

### tessera-trees (unit, all fast)

| File | Test |
|---|---|
| `generic.rs` | `test_config_accessor`, `test_level_circuit_valid`, `test_level_circuit_oob`, `test_inner_verifier_level0`, `test_inner_verifier_level1` |
| `node_prover.rs` | `test_local_prover_level0_arity2`, `test_local_prover_wrong_child_count` |

### tessera-server (unit)

| File | Test |
|---|---|
| `session.rs` | `test_node_state_fill_and_drain`, `test_node_state_duplicate_insert`, `test_session_arity2_depth1`, `test_session_arity2_depth2`, `test_session_arity2_depth3` (#[ignore]), `test_session_out_of_order_submit`, `test_session_duplicate_leaf_idx`, `test_session_oob_leaf_idx`, `test_session_handle_dropped_early`, `test_session_node_failure_propagates` |
| `pool.rs` | `test_pool_least_inflight_empty_pool`, `test_pool_dispatch_to_lowest`, `test_pool_retry_on_failure`, `test_pool_all_fail`, `test_remote_prover_serialise_roundtrip` |
| `prover.rs` | `test_aggregate_bytes_local_only`, `test_aggregate_bytes_all_dummy`, `test_aggregate_bytes_mixed_dummy_real`, `test_aggregate_bytes_real_no_aggregator` |

### tessera-server (integration, `#[ignore]` by default)

| File | Test | Requires |
|---|---|---|
| `aggregation_pipeline/pool.rs` | `test_remote_node_prover_http_roundtrip` | in-process axum test server |
| `bin/aggregation_prover.rs` | `test_prove_node_handler_level0`, `test_prove_node_handler_bad_hex`, `test_prove_node_handler_wrong_level` | arity=2,depth=1 artifacts built in test |
| `prover.rs` | `test_full_session_with_remote_prover` | in-process axum aggregation_prover |

---

## Build order

Each step below must compile and pass its tests before the next begins.

```
Step 1  cargo test -p tessera-trees -- proof_aggregation::generic
Step 2  cargo test -p tessera-trees -- proof_aggregation::node_prover
Step 3  cargo check -p tessera-server   (types compile)
Step 4  cargo test -p tessera-server -- aggregation_pipeline::pool
Step 5  cargo test -p tessera-server -- aggregation_pipeline::session
Step 6  cargo build --bin aggregation_prover
        cargo test -p tessera-server -- aggregation_prover   [integration, #[ignore] gate]
Step 7  cargo check -p tessera-server   (config compiles)
Step 8  cargo test -p tessera-server -- prover
Step 9  cargo clippy -p tessera-trees -p tessera-server && cargo fmt
```

---

## Open questions (resolved in design sessions, recorded here for reference)

| Question | Decision |
|---|---|
| Global vs per-level in-flight tracking | Global — simpler; level-aware routing adds complexity without measurable benefit given the 6 s root bottleneck |
| Round-robin vs least-inflight | Least-inflight — handles varying network latency and prover load without coordination |
| Level affinity (reserve capacity for root) | Deferred to v2 — root is a single node and always finds a free prover before deadline |
| `prover_thread` sync vs async | Keep sync (Option A) — `Handle::current().block_on(...)` bridges async aggregation from blocking thread; full conversion deferred |
| Separate `aggregation_prover` binary vs extending existing `prover` | Separate — allows independent scaling of aggregation work vs Groth16 work; keeps existing prover startup unaffected |
