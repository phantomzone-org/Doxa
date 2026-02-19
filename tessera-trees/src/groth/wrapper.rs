//! This file offers methods for the Groth16 proofs which internally call the Go
//! methods through FFI.

use std::{
	ffi::{CStr, CString, c_char, c_int, c_uchar},
	fs,
	io::Write,
	path::Path,
};

use anyhow::{Result, anyhow};
use plonky2::{
	iop::witness::{PartialWitness, WitnessWrite},
	plonk::{
		circuit_builder::CircuitBuilder,
		circuit_data::{CircuitConfig, VerifierCircuitTarget},
		proof::ProofWithPublicInputsTarget,
	},
	util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use serde::Serialize;

use super::serializer::TesseraGeneratorSerializer;
use crate::{
	CircuitDataBN128, CircuitDataNative, ConfigBN128, ConfigNative, F, ProofBN128, ProofNative,
};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

const PROVING_KEY_PATH: &str = "proving.key";
const VERIFYING_KEY_PATH: &str = "verifying.key";
const R1CS_PATH: &str = "r1cs";
const VERIFIER_DATA_PATH: &str = "verifier_only_circuit_data.json";
const COMMON_DATA_PATH: &str = "common_circuit_data.json";
const PROOF_WITH_PI: &str = "proof_with_public_inputs.json";
const NATIVE_CIRCUIT_DATA_PATH: &str = "native_circuit_data.bin";
const BN128_CIRCUIT_DATA_PATH: &str = "bn128_circuit_data.bin";

pub struct Groth16Wrapper {}

impl Groth16Wrapper {
	#[inline]
	fn debug_enabled() -> bool {
		std::env::var("TESSERA_DEBUG")
			.map(|v| v == "1")
			.unwrap_or(false)
	}

	#[inline]
	fn debug_log(msg: &str) {
		if Self::debug_enabled() {
			println!("{msg}");
		}
	}

	#[inline]
	fn info_log(msg: &str) {
		println!("{msg}");
	}

	/// computes the Groth16 trusted setup. Method only for tests, do not use in
	/// production.
	pub fn trusted_setup(input_path: &Path, output_path: &Path) -> String {
		Self::info_log("groth16 trusted setup (ffi) starting");
		let input_path = CString::new(input_path.to_str().expect("path is valid UTF-8")).unwrap();
		let output_path = CString::new(output_path.to_str().expect("path is valid UTF-8")).unwrap();

		unsafe {
			let cstr = CStr::from_ptr(TrustedSetup(
				input_path.as_ptr() as *mut c_char,
				output_path.as_ptr() as *mut c_char,
			));
			let s = String::from_utf8_lossy(cstr.to_bytes()).to_string();
			GoFree(cstr.as_ptr() as *mut c_uchar);
			Self::info_log("groth16 trusted setup (ffi) completed");
			s
		}
	}

	/// Loads into memory the
	///   - Groth16's R1CS, ProvingKey and VerifierKey
	///   - Plonky2's VerifierOnlyCircuitData, CommonCircuitData
	///
	/// so that they can be used by later calls to `groth16_prove` and `groth16_verify`.
	pub fn init(input_path: &Path, output_path: &Path) -> Result<String> {
		Self::info_log("groth16 init (ffi) starting");
		// check that the trusted setup & r1cs files exist
		let pk_path = output_path.join(PROVING_KEY_PATH);
		let vk_path = output_path.join(VERIFYING_KEY_PATH);
		let r1cs_path = output_path.join(R1CS_PATH);
		if !pk_path.exists() || !vk_path.exists() || !r1cs_path.exists() {
			return Err(anyhow!(
				"not found: pk, vk, r1cs. Path:\n  pk: {:?}\n  vk: {:?},\n  r1cs: {:?}",
				pk_path,
				vk_path,
				r1cs_path
			));
		}

		let input_path = CString::new(input_path.to_str().expect("path is valid UTF-8")).unwrap();
		let output_path = CString::new(output_path.to_str().expect("path is valid UTF-8")).unwrap();

		unsafe {
			let cstr = CStr::from_ptr(Init(
				input_path.as_ptr() as *mut c_char,
				output_path.as_ptr() as *mut c_char,
			));
			let s = String::from_utf8_lossy(cstr.to_bytes()).to_string();
			GoFree(cstr.as_ptr() as *mut c_uchar);
			Self::info_log("groth16 init (ffi) completed");
			if s.starts_with("error:") {
				return Err(anyhow!(s));
			}
			Ok(s)
		}
	}

	/// Loads into memory the
	pub fn load_vk(path: &Path) -> Result<String> {
		// check that the trusted setup & r1cs files exist
		let vk_path = path.join(VERIFYING_KEY_PATH);
		if !vk_path.exists() {
			return Err(anyhow!("not found: vk. Path: vk: {:?}", vk_path,));
		}

		let path = CString::new(path.to_str().expect("path is valid UTF-8")).unwrap();

		unsafe {
			let cstr = CStr::from_ptr(LoadVk(path.as_ptr() as *mut c_char));
			let s = String::from_utf8_lossy(cstr.to_bytes()).to_string();
			GoFree(cstr.as_ptr() as *mut c_uchar);
			Ok(s)
		}
	}

	pub fn check_init() -> String {
		Self::info_log("groth16 check_init (ffi) starting");
		unsafe {
			let cstr = CStr::from_ptr(CheckInit());
			let s = String::from_utf8_lossy(cstr.to_bytes()).to_string();
			GoFree(cstr.as_ptr() as *mut c_uchar);
			Self::info_log("groth16 check_init (ffi) completed");
			s
		}
	}

	/// compute a Groth16 proof out of the given Plonky2's ProofWithPublicInputs
	pub fn prove(proof_with_pis: ProofBN128) -> Result<(Vec<u8>, Vec<u8>)> {
		Self::info_log("groth16 prove (ffi) starting");
		let json: String = serde_json::to_string_pretty(&proof_with_pis)?;
		let input: Vec<u8> = json.into_bytes();
		let input_len = c_int::try_from(input.len()).map_err(|_| {
			anyhow!(
				"proof JSON too large for FFI ({}B > c_int::MAX)",
				input.len()
			)
		})?;
		let mut proof_out_len: c_int = 0;
		let mut wit_out_len: c_int = 0;
		let res = unsafe {
			Groth16Proof(
				input.as_ptr() as *mut u8,
				input_len,
				&mut proof_out_len as *mut c_int,
				&mut wit_out_len as *mut c_int,
			)
		};
		let (proof_out_ptr, wit_out_ptr) = (res.r0, res.r1);

		let proof_bytes: Vec<u8> = if proof_out_len > 0 && !proof_out_ptr.is_null() {
			let slice =
				unsafe { std::slice::from_raw_parts(proof_out_ptr, proof_out_len as usize) };
			let vec = slice.to_vec();
			unsafe { GoFree(proof_out_ptr) };
			vec
		} else {
			let go_err = unsafe { Self::go_last_error() };
			return Err(anyhow!("groth16_prove failed: {go_err}"));
		};
		let pub_inp_bytes: Vec<u8> = if wit_out_len > 0 && !wit_out_ptr.is_null() {
			let slice = unsafe { std::slice::from_raw_parts(wit_out_ptr, wit_out_len as usize) };
			let vec = slice.to_vec();
			unsafe { GoFree(wit_out_ptr) };
			vec
		} else {
			let go_err = unsafe { Self::go_last_error() };
			return Err(anyhow!("groth16_prove failed: {go_err}"));
		};
		Self::info_log("groth16 prove (ffi) completed");
		Ok((proof_bytes, pub_inp_bytes))
	}

	unsafe fn go_last_error() -> String {
		let ptr = unsafe { LastError() };
		if ptr.is_null() {
			return "<no error (LastError returned null)>".to_string();
		}
		let cstr = unsafe { CStr::from_ptr(ptr) };
		let s = String::from_utf8_lossy(cstr.to_bytes()).to_string();
		unsafe { GoFree(ptr as *mut c_uchar) };
		if s.is_empty() {
			"<no error (empty)>".to_string()
		} else {
			s
		}
	}

	/// verify the given Groth16 proof with the given public inputs
	pub fn verify(proof: Vec<u8>, public_inputs: Vec<u8>) -> Result<()> {
		Self::info_log("groth16 verify (ffi) starting");
		let proof_len = c_int::try_from(proof.len())
			.map_err(|_| anyhow!("proof too large for FFI ({}B > c_int::MAX)", proof.len()))?;
		let pub_inp_len = c_int::try_from(public_inputs.len()).map_err(|_| {
			anyhow!(
				"public inputs too large for FFI ({}B > c_int::MAX)",
				public_inputs.len()
			)
		})?;
		let res_string = unsafe {
			let ptr = Groth16Verify(
				proof.as_ptr() as *mut u8,
				proof_len,
				public_inputs.as_ptr() as *mut u8,
				pub_inp_len,
			);

			let cstr = CStr::from_ptr(ptr);
			let s = String::from_utf8_lossy(cstr.to_bytes()).to_string();
			GoFree(cstr.as_ptr() as *mut c_uchar);
			s
		};
		if res_string != "ok" {
			return Err(anyhow!(res_string));
		}
		Self::info_log("groth16 verify (ffi) ok");
		Ok(())
	}

	/// Formats the raw proof and public-input byte blobs returned by
	/// [`prove`] as a JSON object compatible with the generated Solidity
	/// verifier contract.
	///
	/// The JSON layout mirrors `verifyProof`'s calldata:
	/// ```json
	/// {
	///   "proof":          ["0x…", …],   // uint256[8]  – A, B, C (EIP-197)
	///   "commitments":    ["0x…", …],   // uint256[2]  – Pedersen commitment
	///   "commitmentPok":  ["0x…", …],   // uint256[2]  – proof of knowledge
	///   "publicInputs":   ["0x…", …]    // uint256[N]  – public witness
	/// }
	/// ```
	///
	/// Parsing and field-element conversion happen in Go (where the gnark
	/// types live); this method is a thin FFI bridge.
	pub fn proof_to_solidity_json(proof_bytes: &[u8], pub_inp_bytes: &[u8]) -> Result<String> {
		Self::info_log("groth16 format solidity json (ffi) starting");
		let proof_len = c_int::try_from(proof_bytes.len()).map_err(|_| {
			anyhow!(
				"proof bytes too large for FFI ({}B > c_int::MAX)",
				proof_bytes.len()
			)
		})?;
		let pub_inp_len = c_int::try_from(pub_inp_bytes.len()).map_err(|_| {
			anyhow!(
				"public input bytes too large for FFI ({}B > c_int::MAX)",
				pub_inp_bytes.len()
			)
		})?;
		unsafe {
			let ptr = Groth16FormatJSON(
				proof_bytes.as_ptr() as *mut u8,
				proof_len,
				pub_inp_bytes.as_ptr() as *mut u8,
				pub_inp_len,
			);
			let cstr = CStr::from_ptr(ptr);
			let s = String::from_utf8_lossy(cstr.to_bytes()).to_string();
			GoFree(cstr.as_ptr() as *mut c_uchar);
			if !s.starts_with('{') {
				return Err(anyhow!(s));
			}
			Self::info_log("groth16 format solidity json (ffi) completed");
			Ok(s)
		}
	}

	/// gets as input the public inputs vector (output from
	/// `prepare_public_inputs`), and encodes it as a byte-array compatible with
	/// Gnark encoding
	#[cfg(test)]
	pub fn encode_public_inputs_gnark(pub_inp: Vec<crate::F>) -> Vec<u8> {
		// encode it as big-endian bytes compatible with Gnark:
		//   0..4: num public inputs
		//   4..8: num secret inputs (0 in the case of only public inputs))
		//   8..12: num of elements in the vector (which is the num of public inputs)
		//   12..n: public inputs encoded as big-endian bytes
		let mut pub_inp_bytes = Vec::new();
		let n = pub_inp.len() as u32;
		pub_inp_bytes.extend_from_slice(&n.to_be_bytes());
		pub_inp_bytes.extend_from_slice(&0u32.to_be_bytes());
		pub_inp_bytes.extend_from_slice(&n.to_be_bytes());
		for e in pub_inp {
			let b = e.0.to_be_bytes();
			let padding = vec![0u8; 24];
			let b_256 = [padding, b.to_vec()].concat();
			pub_inp_bytes.extend_from_slice(&b_256);
		}
		pub_inp_bytes
	}
}

pub struct BN128Wrapper {
	circuit_data_bn128: CircuitDataBN128,
	circuit_data: CircuitDataNative,
	proof_with_pis_bn128: ProofBN128,
	proof_with_pis_target: ProofWithPublicInputsTarget<2>,
	verifier_target: VerifierCircuitTarget,
}

impl BN128Wrapper {
	/// Instantiate a new [BN128Wrapper] from a provided [CircuitData].
	/// This helper is used to wrap a proof with standard configuration [C]
	/// into a proof with configuration [PoseidonBN128GoldilocksConfig] which
	/// is accepted by the [Groth16Wrapper].
	///
	/// Unfortunately, for now, we need a concrete proof over [C] to instantiate the [BN128Wrapper].
	pub fn new(circuit_data: CircuitDataNative, proof_with_pis: ProofNative) -> Result<Self> {
		let config: CircuitConfig = CircuitConfig::standard_recursion_config();

		let mut builder = CircuitBuilder::new(config);

		let proof_with_pis_target = builder.add_virtual_proof_with_pis(&circuit_data.common);

		let verifier_circuit_target = builder.constant_verifier_data(&circuit_data.verifier_only);

		builder.verify_proof::<ConfigNative>(
			&proof_with_pis_target,
			&verifier_circuit_target,
			&circuit_data.common,
		);

		builder.register_public_inputs(&proof_with_pis_target.public_inputs);

		let circuit_data_bn128 = builder.build::<ConfigBN128>();

		let mut pw = PartialWitness::new();
		pw.set_verifier_data_target(&verifier_circuit_target, &circuit_data.verifier_only)?;
		pw.set_proof_with_pis_target(&proof_with_pis_target, &proof_with_pis)?;
		let verifier_circuit_data = circuit_data_bn128.verifier_data();
		let proof_with_pis_bn128 = circuit_data_bn128.prove(pw)?;

		verifier_circuit_data.verify(proof_with_pis_bn128.clone())?; // sanity check: verify proof
		Groth16Wrapper::info_log("BN128Wrapper initialized");

		Ok(Self {
			circuit_data_bn128,
			circuit_data,
			proof_with_pis_bn128,
			proof_with_pis_target,
			verifier_target: verifier_circuit_target,
		})
	}

	/// Wraps a proof with standard configuration [ConfigNative] into a proof with configuration
	/// [PoseidonBN128GoldilocksConfig].
	pub fn wrap_proof_to_bn128(&self, proof_with_pis: ProofNative) -> Result<ProofBN128> {
		let mut pw = PartialWitness::new();
		pw.set_verifier_data_target(&self.verifier_target, &self.circuit_data.verifier_only)?;
		pw.set_proof_with_pis_target(&self.proof_with_pis_target, &proof_with_pis)?;
		let verifier_circuit_data = self.circuit_data_bn128.verifier_data();
		let proof = self.circuit_data_bn128.prove(pw)?;
		verifier_circuit_data.verify(proof.clone())?; // sanity check: verify proof
		Groth16Wrapper::info_log("BN128Wrapper::wrap_proof_to_bn128 ok");
		Ok(proof)
	}

	/// Store the necessary data for the [Groth16Wrapper].
	pub fn store_circuit_data_bn128(&self, path: &Path) -> Result<()> {
		store(
			&path.join(COMMON_DATA_PATH),
			&self.circuit_data_bn128.common,
		)?;
		store(
			&path.join(VERIFIER_DATA_PATH),
			&self.circuit_data_bn128.verifier_only,
		)?;
		store(&path.join(PROOF_WITH_PI), &self.proof_with_pis_bn128)?;
		Groth16Wrapper::info_log("BN128Wrapper::store_circuit_data_bn128 ok");
		Ok(())
	}

	/// Store a wrapped proof.
	pub fn store_proof_bn128(path: &Path, data: &ProofBN128) -> Result<()> {
		store(&path.join(VERIFIER_DATA_PATH), data)?;
		Groth16Wrapper::info_log("BN128Wrapper::store_proof_bn128 ok");
		Ok(())
	}

	/// Returns `true` if the full binary circuit artifacts needed by
	/// [`BN128Wrapper::from_artifacts`] are present in `path`.
	pub fn has_full_artifacts(path: &Path) -> bool {
		path.join(NATIVE_CIRCUIT_DATA_PATH).is_file()
			&& path.join(BN128_CIRCUIT_DATA_PATH).is_file()
			&& path.join(PROOF_WITH_PI).is_file()
	}

	/// Store the full circuit data (native + BN128) as binary files alongside
	/// the existing JSON files used by the Go R1CS compiler.
	///
	/// Call this during artifact generation so that [`BN128Wrapper::from_artifacts`]
	/// can reconstruct the wrapper without re-deriving the circuit or generating a new proof.
	pub fn store_full_circuit_data(&self, path: &Path) -> Result<()> {
		// Existing JSON files required by the Go R1CS compiler.
		self.store_circuit_data_bn128(path)?;

		let gate_ser = DefaultGateSerializer;

		let native_bytes = self
			.circuit_data
			.to_bytes(&gate_ser, &TesseraGeneratorSerializer)
			.map_err(|_| {
				anyhow!(
					"serialize native circuit failed (plonky2 IoError — no inner detail available). \
				 TesseraGeneratorSerializer covers all 24 standard generators plus the 10 custom \
				 Keccak-256 / SHA-256 / u32 generators. If a new custom generator was added to the circuit, \
				 register it in tessera-trees/src/groth/serializer.rs."
				)
			})?;
		fs::write(path.join(NATIVE_CIRCUIT_DATA_PATH), native_bytes)?;

		// The BN128 circuit's generators all operate over GoldilocksField; they do not
		// use PoseidonBN128Hash (which is not AlgebraicHasher), so ConfigNative's serializer
		// handles them correctly.
		let bn128_bytes = self
			.circuit_data_bn128
			.to_bytes(&gate_ser, &DefaultGeneratorSerializer::<ConfigNative, 2>::default())
			.map_err(|_| anyhow!(
				"serialize BN128 circuit failed (plonky2 IoError — no inner detail available). \
				 Most likely cause: a gate or witness-generator type used by the BN128 recursion \
				 circuit is not registered in DefaultGateSerializer / DefaultGeneratorSerializer<ConfigNative>. \
				 Note: PoseidonBN128Hash is intentionally excluded (not AlgebraicHasher); \
				 if a generator that depends on it was added, a custom serializer is required."
			))?;
		fs::write(path.join(BN128_CIRCUIT_DATA_PATH), bn128_bytes)?;

		Ok(())
	}

	/// Reconstruct a [`BN128Wrapper`] from pre-generated artifacts without
	/// re-deriving the circuit or generating a new proof.
	///
	/// Loads `circuit_data` (native) and `circuit_data_bn128` (BN128, including
	/// the proving key) from binary files, then cheaply rebuilds the circuit
	/// targets by replaying the deterministic builder operations.
	pub fn from_artifacts(path: &Path) -> Result<Self> {
		let gate_ser = DefaultGateSerializer;

		let native_bytes = fs::read(path.join(NATIVE_CIRCUIT_DATA_PATH))?;
		let circuit_data =
			CircuitDataNative::from_bytes(&native_bytes, &gate_ser, &TesseraGeneratorSerializer)
				.map_err(|_| {
					anyhow!(
						"deserialize native circuit from '{}' failed (plonky2 IoError — no inner detail available). \
			 Possible causes: (1) the binary was produced by a different plonky2 revision; \
			 (2) the file is truncated or corrupt; \
			 (3) a generator type present at serialization time is missing from TesseraGeneratorSerializer. \
			 Delete the artifacts directory and re-run pending_deposit_artifacts.",
						path.join(NATIVE_CIRCUIT_DATA_PATH).display()
					)
				})?;

		let bn128_bytes = fs::read(path.join(BN128_CIRCUIT_DATA_PATH))?;
		let circuit_data_bn128 = CircuitDataBN128::from_bytes(
			&bn128_bytes,
			&gate_ser,
			&DefaultGeneratorSerializer::<ConfigNative, 2>::default(),
		)
		.map_err(|_| {
			anyhow!(
				"deserialize BN128 circuit from '{}' failed (plonky2 IoError — no inner detail available). \
			 Possible causes: (1) the binary was produced by a different plonky2 revision; \
			 (2) the file is truncated or corrupt; \
			 (3) a gate/generator type present at serialization time is not registered here. \
			 Delete the artifacts directory and re-run pending_deposit_artifacts.",
				path.join(BN128_CIRCUIT_DATA_PATH).display()
			)
		})?;

		let proof_with_pis_bn128: ProofBN128 =
			serde_json::from_str(&fs::read_to_string(path.join(PROOF_WITH_PI))?)?;

		// Rebuild the circuit targets cheaply. The four builder operations below are
		// deterministic: given the same `circuit_data.common` / `verifier_only`, plonky2's
		// sequential wire allocator always produces the same target indices. No `build()` or
		// `prove()` call is needed; the builder is dropped immediately after obtaining the
		// targets.
		let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
		let proof_with_pis_target = builder.add_virtual_proof_with_pis(&circuit_data.common);
		let verifier_circuit_target = builder.constant_verifier_data(&circuit_data.verifier_only);
		builder.verify_proof::<ConfigNative>(
			&proof_with_pis_target,
			&verifier_circuit_target,
			&circuit_data.common,
		);
		builder.register_public_inputs(&proof_with_pis_target.public_inputs);

		Ok(Self {
			circuit_data_bn128,
			circuit_data,
			proof_with_pis_bn128,
			proof_with_pis_target,
			verifier_target: verifier_circuit_target,
		})
	}
}

fn store<T>(path: &Path, data: &T) -> Result<()>
where
	T: ?Sized + Serialize,
{
	let json: String = serde_json::to_string_pretty(data)?;
	let mut file: fs::File = fs::File::create(path)?;
	file.write_all(&json.into_bytes())?;
	Ok(())
}
