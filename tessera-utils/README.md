# tessera-utils

Shared primitives for the Tessera workspace: Plonky2/STARK gadgets, a Keccak-256 in-circuit implementation, Groth16 wrapping via Go FFI, and common type aliases.

## System dependencies

These must be installed before building:

| Dependency | Reason | Install |
|---|---|---|
| **Go** ≥ 1.24 | Compiles `ffi/main.go` into `libgo.a` (Groth16 prover/verifier via gnark) | `sudo apt-get install golang-go` or [go.dev/dl](https://go.dev/dl/) |
| **libclang** | Required by `bindgen` to generate Rust FFI bindings from `libgo.h` at build time | `sudo apt-get install libclang-dev` |
| **clang** / **gcc** | C toolchain for linking the Go-produced C archive | usually pre-installed; `sudo apt-get install build-essential` |

## Build

The `build.rs` script runs automatically during `cargo build`:

1. Compiles `ffi/main.go` with `go build -buildmode=c-archive`, producing `libgo.a` and `libgo.h` in Cargo's `OUT_DIR`.
2. Runs `bindgen` against `libgo.h` to emit `bindings.rs`.
3. Links the resulting static archive via `cargo:rustc-link-lib=static=go`.

## Go module

The FFI layer lives in `ffi/main.go` and is part of the `plonky2-wrapper` Go module (`go.mod`). Direct Go dependencies:

| Package | Version | Purpose |
|---|---|---|
| `github.com/consensys/gnark` | 0.14.0 | Groth16 prover and verifier over BN254 |
| `github.com/consensys/gnark-crypto` | 0.19.2 | BN254 elliptic curve arithmetic |
| `github.com/succinctlabs/gnark-plonky2-verifier` | fork by arnaucube | Plonky2 verifier circuit inside gnark |
| `golang.org/x/crypto` | 0.47.0 | SHA-3 / Keccak primitives |

## Rust crate structure

| Module | Contents |
|---|---|
| `groth` | `Groth16Wrapper` and `BN128Wrapper` — FFI calls into the Go library; Poseidon-BN128 config and serializer |
| `plonky2_gadgets` | In-circuit Keccak-256 (STARK-based) and u32 arithmetic/bitwise/rotation gadgets |
| `hasher` | Native (out-of-circuit) Keccak-256 helper |
