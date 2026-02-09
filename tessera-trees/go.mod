module plonky2-wrapper

go 1.24.4

require (
	github.com/consensys/gnark v0.14.0
	github.com/consensys/gnark-crypto v0.19.2
	github.com/succinctlabs/gnark-plonky2-verifier v0.1.0
	golang.org/x/crypto v0.47.0
)

require (
	github.com/bits-and-blooms/bitset v1.24.4 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/google/pprof v0.0.0-20250820193118-f64d9cf942d6 // indirect
	github.com/ingonyama-zk/icicle-gnark/v3 v3.2.2 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/ronanh/intcomp v1.1.1 // indirect
	github.com/rs/zerolog v1.34.0 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/exp v0.0.0-20250819193227-8b4c13bb791b // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// replace gnark-plonky2-verifier by the fork that updates it to be compatible
// with latest plonky2 version
replace github.com/succinctlabs/gnark-plonky2-verifier => github.com/arnaucube/gnark-plonky2-verifier v0.0.0-20251003081055-02979848ab6d
