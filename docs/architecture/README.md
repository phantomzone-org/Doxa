# Tessera Architecture Documentation

This folder contains auto-generated architecture diagrams and analysis for the Tessera ZK-rollup system.

## Contents

| File | Description |
|---|---|
| [01-component-inventory.md](01-component-inventory.md) | Full component table with entry points, interfaces, and source files |
| [02-system-overview.md](02-system-overview.md) | High-level system overview diagram (Mermaid) |
| [03-workflow-index.md](03-workflow-index.md) | Index of all major workflows |
| [04-w1-deposit-registration.md](04-w1-deposit-registration.md) | W1: Deposit & Registration flow |
| [05-w2-consume-batch-prove-finalize.md](05-w2-consume-batch-prove-finalize.md) | W2: Main pipeline — consume request through on-chain finalization |
| [06-w3-private-transaction.md](06-w3-private-transaction.md) | W3: Private transaction multi-tree fan-out |
| [07-w4-withdrawal.md](07-w4-withdrawal.md) | W4: Pending deposit withdrawal |
| [08-w5-sequencer-recovery.md](08-w5-sequencer-recovery.md) | W5: Sequencer recovery from chain |
| [09-w6-prover-pipeline.md](09-w6-prover-pipeline.md) | W6: Prover proof generation pipeline |
| [10-concurrency-model.md](10-concurrency-model.md) | Concurrency, orchestration, and the batch state machine |
| [11-assumptions-and-gaps.md](11-assumptions-and-gaps.md) | Known assumptions, stubs, and gaps |

## Rendering

All diagrams use [Mermaid](https://mermaid.js.org/) syntax. They render natively on GitHub and in VS Code with the Mermaid extension.
