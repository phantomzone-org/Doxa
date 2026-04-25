# tessera-server Agent Notes

1. Keep `src/aggregator_service/**` and the setup binaries inside this crate unless the repo owners explicitly request otherwise. They are still used by local artifact tooling.
2. All prover and aggregator tests (even the `#[ignore]` ones) are important for correctness. Do not delete or move them unless instructed.
3. Go FFI scaffolding has been removed from tessera-server. Groth16/BN128 bindings now live in `tessera-utils`, so never reintroduce local Go shims here.
