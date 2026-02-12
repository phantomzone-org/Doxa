package pod2onchain

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"
	"golang.org/x/crypto/sha3"
)

func checkErr(err error, msg ...string) {
	if err != nil {
		fmt.Println(err, msg)
		os.Exit(1)
	}
}

func infof(format string, args ...any) {
	fmt.Printf(format, args...)
}

func debugEnabled() bool {
	return os.Getenv("TESSERA_DEBUG") == "1"
}

func debugf(format string, args ...any) {
	if debugEnabled() {
		fmt.Printf(format, args...)
	}
}

func R1csCircuit(proofWithPis variables.ProofWithPublicInputs, verifierOnlyCircuitData variables.VerifierOnlyCircuitData, commonCircuitData types.CommonCircuitData, outputsPath string) constraint.ConstraintSystem {
	infof("building r1cs (output: %s)\n", outputsPath)
	circuit := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	var p *profile.Profile
	p = profile.Start()

	var builder frontend.NewBuilder
	builder = r1cs.NewBuilder

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	checkErr(err, "error in building circuit")

	p.Stop()
	p.Top()
	debugf("r1cs.GetNbCoefficients(): %d\n", r1cs.GetNbCoefficients())
	debugf("r1cs.GetNbConstraints(): %d\n", r1cs.GetNbConstraints())
	debugf("r1cs.GetNbSecretVariables(): %d\n", r1cs.GetNbSecretVariables())
	debugf("r1cs.GetNbPublicVariables(): %d\n", r1cs.GetNbPublicVariables())
	debugf("r1cs.GetNbInternalVariables(): %d\n", r1cs.GetNbInternalVariables())

	// store r1cs into a file
	fR1CS, err := os.Create(filepath.Join(outputsPath, "r1cs"))
	checkErr(err)
	r1cs.WriteTo(fR1CS)
	fR1CS.Close()

	return r1cs
}

func TrustedSetup(r1cs constraint.ConstraintSystem, outputsPath string) (groth16.ProvingKey, groth16.VerifyingKey) {
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	var err error

	infof("running groth16 trusted setup (output: %s)\n", outputsPath)
	pk, vk, err = groth16.Setup(r1cs)
	checkErr(err)

	fPK, err := os.Create(filepath.Join(outputsPath, "proving.key"))
	checkErr(err)
	pk.WriteTo(fPK)
	fPK.Close()

	if vk != nil {
		fVK, err := os.Create(filepath.Join(outputsPath, "verifying.key"))
		checkErr(err)
		vk.WriteTo(fVK)
		fVK.Close()
	}

	// write solidity smart contract into a file
	fSolidity, err := os.Create(filepath.Join(outputsPath, "Verifier.sol"))
	checkErr(err)
	// use keccak256 (ethereum version) as hashtofield
	err = vk.ExportSolidity(fSolidity, solidity.WithHashToFieldFunction(sha3.NewLegacyKeccak256()))
	checkErr(err)
	fSolidity.Close()

	infof("trusted setup complete (pk/vk/r1cs/verifier written)\n")
	return pk, vk
}

func CheckR1CS(r1cs constraint.ConstraintSystem, proofWithPis variables.ProofWithPublicInputs, verifierOnlyCircuitData variables.VerifierOnlyCircuitData, commonCircuitData types.CommonCircuitData) {
	var err error

	assignment := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	// must not error with big int test engine
	err = test.IsSolved(&assignment, &assignment, ecc.BN254.ScalarField(), test.WithNoSmallFieldCompatibility())
	checkErr(err)

	// parse assignment
	validWitness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	checkErr(err)

	err = r1cs.IsSolved(validWitness)
	checkErr(err)
}

func Groth16Proof(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey, proofWithPis variables.ProofWithPublicInputs, verifierOnlyCircuitData variables.VerifierOnlyCircuitData, commonCircuitData types.CommonCircuitData) (groth16.Proof, witness.Witness, error) {
	var err error

	assignment := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	infof("generating groth16 witness\n")
	start := time.Now()
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, err
	}

	infof("creating groth16 proof\n")
	start = time.Now()
	proof, err := groth16.Prove(r1cs, pk, witness, backend.WithProverHashToFieldFunction(sha3.NewLegacyKeccak256()))
	if err != nil {
		return nil, nil, err
	}
	debugf("[DBG] proof gen %dms\n", time.Since(start).Milliseconds())

	witnessPublic, err := witness.Public()
	if err != nil {
		return nil, nil, err
	}

	return proof, witnessPublic, nil
}

func Groth16ProofStore(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey, proofWithPis variables.ProofWithPublicInputs, verifierOnlyCircuitData variables.VerifierOnlyCircuitData, commonCircuitData types.CommonCircuitData, outputsPath string, solidityCheck bool) {
	var err error

	infof("generating groth16 proof (output: %s)\n", outputsPath)
	assignment := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	infof("generating witness\n")
	start := time.Now()
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	checkErr(err)

	// store witness in a file
	fWitness, err := os.Create(filepath.Join(outputsPath, "witness"))
	checkErr(err)
	witness.WriteTo(fWitness)
	fWitness.Close()

	// get the public witness (public inputs)
	witnessPublic, err := witness.Public()
	checkErr(err)

	// store witnessPublic in a file
	fWitnessPublic, err := os.Create(filepath.Join(outputsPath, "witness.public"))
	checkErr(err)
	witnessPublic.WriteTo(fWitnessPublic)
	fWitnessPublic.Close()
	debugf("[DBG] witness gen %dms\n", time.Since(start).Milliseconds())

	infof("creating proof\n")
	start = time.Now()
	proof, err := groth16.Prove(r1cs, pk, witness, backend.WithProverHashToFieldFunction(sha3.NewLegacyKeccak256()))
	checkErr(err)
	debugf("[DBG] proof gen %dms\n", time.Since(start).Milliseconds())
	fProof, err := os.Create(filepath.Join(outputsPath, "proof.proof"))
	checkErr(err)
	proof.WriteTo(fProof)
	fProof.Close()

	if vk == nil {
		panic("vk is nil")
	}

	infof("verifying proof\n")
	err = groth16.Verify(proof, vk, witnessPublic, backend.WithVerifierHashToFieldFunction(sha3.NewLegacyKeccak256()))
	checkErr(err)

	const fpSize = 4 * 8
	var buf bytes.Buffer
	proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	// convert public inputs
	inputBytes, err := witnessPublic.MarshalBinary()
	checkErr(err)

	nbInputs := len(inputBytes) / fr.Bytes
	var input []*big.Int
	for i := 0; i < nbInputs; i++ {
		var e fr.Element
		e.SetBytes(inputBytes[fr.Bytes*i : fr.Bytes*(i+1)])
		input = append(input, new(big.Int))
		e.BigInt(input[i])
	}
	debugf("[solidity] inputs %v\n", input)

	// solidity contract inputs
	var proofSol [8]*big.Int
	for i := 0; i < 8; i++ {
		proofSol[i] = new(big.Int).SetBytes(proofBytes[fpSize*i : fpSize*(i+1)])
	}
	debugf("[solidity] proof %v\n", proof)

	// prepare commitments
	commitmentsBI := new(big.Int).SetBytes(proofBytes[fpSize*8 : fpSize*8+4])
	commitmentCount := int(commitmentsBI.Int64())

	commitments := []*big.Int{}
	var commitmentPok [2]*big.Int

	// commitments
	for i := 0; i < 2*commitmentCount; i++ {
		commitments = append(commitments, new(big.Int).SetBytes(proofBytes[fpSize*8+4+i*fpSize:fpSize*8+4+(i+1)*fpSize]))
	}
	debugf("[solidity] commitments %v\n", commitments)

	// commitmentPok
	commitmentPok[0] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize : fpSize*8+4+2*commitmentCount*fpSize+fpSize])
	commitmentPok[1] = new(big.Int).SetBytes(proofBytes[fpSize*8+4+2*commitmentCount*fpSize+fpSize : fpSize*8+4+2*commitmentCount*fpSize+2*fpSize])
	debugf("[solidity] commitmentPok %v\n", commitmentPok)

	// check that the proof can be verified in the Solidity smart contract
	// through gnark-solidity-checker
	if solidityCheck {
		if _vk, ok := vk.(solidity.VerifyingKey); ok {
			infof("verifying proof in solidity checker\n")
			SolidityVerification(_vk, proof, witnessPublic, outputsPath, []solidity.ExportOption{solidity.WithHashToFieldFunction(sha3.NewLegacyKeccak256())})
		}
	}
}

// function from gnark/test/assert_solidity.go
func SolidityVerification(vk solidity.VerifyingKey,
	proof any,
	validPublicWitness witness.Witness,
	outputsPath string,
	opts []solidity.ExportOption,
) {
	// make dir
	_ = os.Mkdir(filepath.Join(outputsPath, "solidity"), os.ModePerm)

	// export solidity contract
	fSolidity, err := os.Create(filepath.Join(outputsPath, "solidity/gnark_verifier.sol"))
	checkErr(err)

	err = vk.ExportSolidity(fSolidity, opts...)
	checkErr(err)

	err = fSolidity.Close()
	checkErr(err)

	// generate assets
	// gnark-solidity-checker generate --dir tmpdir --solidity contract_g16.sol
	cmd := exec.Command("gnark-solidity-checker", "generate", "--dir", outputsPath+"/solidity", "--solidity", "gnark_verifier.sol")
	debugf("running %s\n", cmd.String())
	out, err := cmd.CombinedOutput()
	checkErr(err, string(out))

	// len(vk.K) - 1 == len(publicWitness) + len(commitments)
	numOfCommitments := vk.NbPublicWitness() - len(validPublicWitness.Vector().(fr_bn254.Vector))

	checkerOpts := []string{"verify"}
	checkerOpts = append(checkerOpts, "--groth16")

	// proof to hex
	_proof, ok := proof.(interface{ MarshalSolidity() []byte })
	if !ok {
		panic("proof does not implement MarshalSolidity()")
	}

	proofStr := hex.EncodeToString(_proof.MarshalSolidity())

	if numOfCommitments > 0 {
		checkerOpts = append(checkerOpts, "--commitment", strconv.Itoa(numOfCommitments))
	}

	// public witness to hex
	bPublicWitness, err := validPublicWitness.MarshalBinary()
	checkErr(err)
	// first 4 bytes -> nbPublic
	// next 4 bytes -> nbSecret
	// next 4 bytes -> nb elements in the vector (== nbPublic + nbSecret)
	bPublicWitness = bPublicWitness[12:]
	publicWitnessStr := hex.EncodeToString(bPublicWitness)

	checkerOpts = append(checkerOpts, "--dir", filepath.Join(outputsPath, "solidity"))
	checkerOpts = append(checkerOpts, "--nb-public-inputs", strconv.Itoa(len(validPublicWitness.Vector().(fr_bn254.Vector))))
	checkerOpts = append(checkerOpts, "--proof", proofStr)
	checkerOpts = append(checkerOpts, "--public-inputs", publicWitnessStr)

	// verify proof
	// gnark-solidity-checker verify --dir tmdir --groth16 --nb-public-inputs 1 --proof 1234 --public-inputs dead
	cmd = exec.Command("gnark-solidity-checker", checkerOpts...)
	debugf("running %s\n", cmd.String())
	out, err = cmd.CombinedOutput()
	checkErr(err, string(out))

}

// SolidityProofJSON is the JSON envelope that mirrors the argument layout of
// the generated verifier's verifyProof function:
//
//	function verifyProof(
//	    uint256[8]   calldata proof,
//	    uint256[2*N] calldata commitments,
//	    uint256[2]   calldata commitmentPok,
//	    uint256[M]   calldata input
//	)
//
// Every element is a 0x-prefixed, zero-padded 64-hex-char uint256 literal,
// ready to paste into a Foundry/Hardhat test or feed to an ABI encoder.
type SolidityProofJSON struct {
	Proof         []string `json:"proof"`
	Commitments   []string `json:"commitments"`
	CommitmentPok []string `json:"commitmentPok"`
	PublicInputs  []string `json:"publicInputs"`
}

// FormatSolidityJSON converts the two raw byte blobs that come out of a
// Groth16 proving round into a pretty-printed JSON object.
//
// proofRawBytes  – output of groth16.Proof.WriteRawTo.  Layout:
//
//	[8 × 32 bytes]          proof points A, B, C in EIP-197 order
//	[4 bytes]               commitmentCount  (endianness auto-detected)
//	[2×count × 32 bytes]    commitment G1 points (X, Y per point)
//	[2 × 32 bytes]          commitmentPok G1 point  (X, Y)
//
// witnessPublicBytes – output of witness.WriteTo for the public witness;
//
//	round-tripped back via witness.ReadFrom (same as Groth16Verify).
func FormatSolidityJSON(proofRawBytes []byte, witnessPublicBytes []byte) (string, error) {
	const fpSize = 4 * 8 // 32 bytes per BN254 base-field element

	if len(proofRawBytes) < 8*fpSize+4 {
		return "", fmt.Errorf("proof bytes too short: %d", len(proofRawBytes))
	}

	// ── proof points (8 uint256) ─────────────────────────────────
	proofHex := make([]string, 8)
	for i := 0; i < 8; i++ {
		proofHex[i] = "0x" + hex.EncodeToString(proofRawBytes[fpSize*i:fpSize*(i+1)])
	}

	// ── commitmentCount (auto-detect endianness, mirrors Rust parser) ─
	countBytes := proofRawBytes[8*fpSize : 8*fpSize+4]
	countBE := binary.BigEndian.Uint32(countBytes)
	countLE := binary.LittleEndian.Uint32(countBytes)
	remaining := len(proofRawBytes) - (8*fpSize + 4)
	fits := func(c uint32) bool { return remaining >= int(2*c+2)*fpSize }

	var commitmentCount uint32
	switch {
	case fits(countBE):
		commitmentCount = countBE
	case fits(countLE):
		commitmentCount = countLE
	default:
		return "", fmt.Errorf("cannot decode commitmentCount: BE=%d LE=%d remaining=%d",
			countBE, countLE, remaining)
	}
	debugf("(go) [FormatSolidityJSON] commitmentCount = %d\n", commitmentCount)

	offset := 8*fpSize + 4

	// ── commitments (2 uint256 per G1 point) ─────────────────────
	commitments := make([]string, 0, 2*commitmentCount)
	for i := uint32(0); i < 2*commitmentCount; i++ {
		commitments = append(commitments, "0x"+hex.EncodeToString(proofRawBytes[offset:offset+fpSize]))
		offset += fpSize
	}

	// ── commitmentPok (1 G1 point = 2 uint256) ───────────────────
	if offset+2*fpSize > len(proofRawBytes) {
		return "", fmt.Errorf("proof bytes too short for commitmentPok: need %d, have %d",
			offset+2*fpSize, len(proofRawBytes))
	}
	commitmentPok := []string{
		"0x" + hex.EncodeToString(proofRawBytes[offset:offset+fpSize]),
		"0x" + hex.EncodeToString(proofRawBytes[offset+fpSize:offset+2*fpSize]),
	}

	// ── public inputs (round-trip through gnark witness) ─────────
	witnessPublic, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return "", fmt.Errorf("witness.New: %w", err)
	}
	if _, err := witnessPublic.ReadFrom(bytes.NewBuffer(witnessPublicBytes)); err != nil {
		return "", fmt.Errorf("witness.ReadFrom: %w", err)
	}

	vec, ok := witnessPublic.Vector().(fr_bn254.Vector)
	if !ok {
		return "", fmt.Errorf("witness vector type assertion to fr.Vector failed")
	}

	publicInputs := make([]string, len(vec))
	for i := range vec {
		bi := new(big.Int)
		vec[i].BigInt(bi)
		publicInputs[i] = fmt.Sprintf("0x%064x", bi)
	}

	// ── JSON ──────────────────────────────────────────────────────
	jsonBytes, err := json.MarshalIndent(SolidityProofJSON{
		Proof:         proofHex,
		Commitments:   commitments,
		CommitmentPok: commitmentPok,
		PublicInputs:  publicInputs,
	}, "", "  ")
	if err != nil {
		return "", fmt.Errorf("json.MarshalIndent: %w", err)
	}
	return string(jsonBytes), nil
}
