/// Convert a raw bridge revert error into a human-readable string.
///
/// Attempts to extract and decode a Solidity custom-error selector from the
/// error display string.  Falls back to the raw string if no recognised selector
/// is found.
///
/// Decoding strategy (in priority order):
/// 1. Extract revert data bytes from patterns like `data: "0x…"`.
/// 2. Use the first 4 bytes as the selector, or fall back to a 4-byte selector extracted from a
///    `"custom error 0x…"` pattern in the string.
/// 3. Look up the selector in [`decode_bridge_custom_error`]; if found, format any ABI-encoded
///    arguments.
///
/// # Parameters
/// - `err`: any display-formatted error (typically from `alloy`'s transport layer).
///
/// # Returns
/// A human-readable error string such as `"InvalidProof()"` or
/// `"NoteNotFound(bytes32): 0xdeadbeef…"`.
pub(super) fn humanize_bridge_revert(err: &impl std::fmt::Display) -> String {
	let s = err.to_string();
	let Some(data) = extract_revert_data(&s) else {
		if let Some(sel) = extract_custom_error_selector(&s) {
			if let Some(msg) = decode_bridge_custom_error(&sel, &[]) {
				return format!("{msg} (no revert data)");
			}
		}
		return s;
	};

	let selector: [u8; 4] = if data.len() >= 4 {
		[data[0], data[1], data[2], data[3]]
	} else if let Some(sel) = extract_custom_error_selector(&s) {
		sel
	} else {
		return s;
	};

	match decode_bridge_custom_error(&selector, &data) {
		Some(msg) => msg,
		None => s,
	}
}

/// Extract a 4-byte custom-error selector from the pattern `"custom error 0x<8 hex digits>"`.
///
/// Returns `None` if the pattern is absent or the hex decode fails.
fn extract_custom_error_selector(s: &str) -> Option<[u8; 4]> {
	let needle = "custom error 0x";
	let idx = s.find(needle)?;
	let hex_start = idx + needle.len();
	let hex_end = hex_start + 8;
	if s.len() < hex_end {
		return None;
	}
	let bytes = hex::decode(&s[hex_start..hex_end]).ok()?;
	bytes.as_slice().try_into().ok()
}

/// Extract the ABI-encoded revert payload bytes from an error string.
///
/// Searches for any of the needle patterns that `alloy`'s transport layer uses
/// to embed hex-encoded revert data (`"data: \"0x…\""`, `"data:\"0x…"`, etc.).
/// Returns the decoded bytes, or `None` if no pattern matches or the hex is empty.
fn extract_revert_data(s: &str) -> Option<Vec<u8>> {
	let needles = ["data: \"0x", "data:\"0x", "data: 0x", "data:\" 0x"];
	for needle in needles {
		if let Some(idx) = s.find(needle) {
			let start = idx + needle.len();
			let rest = &s[start..];
			let end = rest
				.find('"')
				.or_else(|| rest.find(' '))
				.unwrap_or(rest.len());
			let hex_str = &rest[..end].trim_matches('"');
			let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
			if hex_str.is_empty() {
				return None;
			}
			return hex::decode(hex_str).ok();
		}
	}
	None
}

/// Decode a known `DepositsRollupBridge` custom-error selector into a human-readable string.
///
/// Selectors are the first 4 bytes of `keccak256(errorSignature)` as produced by the
/// Solidity compiler.  If ABI-encoded arguments follow (e.g. `bytes32` for `NoteNotFound`),
/// they are appended in a readable format.
///
/// Returns `None` for unknown selectors (caller falls back to the raw error string).
///
/// # Parameters
/// - `selector`: 4-byte error selector.
/// - `data`: full revert payload (including the 4-byte selector prefix if present; ABI arguments
///   start at byte 4).
fn decode_bridge_custom_error(selector: &[u8; 4], data: &[u8]) -> Option<String> {
	// Selectors computed via `cast sig "ErrorName(argTypes)"`.
	const NOT_OPERATOR: [u8; 4] = [0x7c, 0x21, 0x4f, 0x04];
	const PAUSED: [u8; 4] = [0xda, 0x82, 0x93, 0x39];
	const INVALID_PROOF: [u8; 4] = [0x09, 0xbd, 0xe3, 0x39];
	// keccak256("ProofVerificationFailed(bytes32,uint256[8])") = 0x5ab88774
	const PROOF_VERIFICATION_FAILED: [u8; 4] = [0x5a, 0xb8, 0x87, 0x74];
	const NOTE_NOT_FOUND: [u8; 4] = [0x70, 0x82, 0x97, 0xd2];
	const INVALID_DEPOSIT_STATE: [u8; 4] = [0xc4, 0xe1, 0x4b, 0x16];
	const DUPLICATE_NOTE: [u8; 4] = [0x59, 0x5a, 0x0e, 0x08];
	const INVALID_BATCH_SIZE: [u8; 4] = [0x78, 0x62, 0xe9, 0x59];
	const INVALID_BATCH_LENGTH: [u8; 4] = [0xcc, 0x58, 0x2f, 0xc5];
	const INVALID_MONITORED_TOKEN: [u8; 4] = [0xb0, 0x63, 0x6a, 0xce];
	const INVALID_AMOUNT: [u8; 4] = [0x2c, 0x52, 0x11, 0xc6];
	const NO_TOKEN_RECEIVED: [u8; 4] = [0x4b, 0xf4, 0x79, 0x0a];
	const NOT_DEPOSIT_RECIPIENT: [u8; 4] = [0x63, 0xba, 0x28, 0x3e];
	const TOKEN_TRANSFER_FAILED: [u8; 4] = [0x04, 0x5c, 0x4b, 0x02];
	const ZERO_ADDRESS: [u8; 4] = [0xd9, 0x2e, 0x23, 0x3d];
	// cast sig "InvalidinputsProof()" → 0xf9d080e4
	const INVALID_INPUTS_PROOF: [u8; 4] = [0xf9, 0xd0, 0x80, 0xe4];
	const PENDING_QUEUE_FULL: [u8; 4] = [0xce, 0xe3, 0x27, 0x22];
	const SLOT_CONFLICT: [u8; 4] = [0xb0, 0x69, 0xd3, 0xa3];
	const UNKNOWN_BATCH: [u8; 4] = [0x43, 0x92, 0xee, 0x6a];
	const ALREADY_CONFIRMED: [u8; 4] = [0xc7, 0x28, 0x1d, 0xfa];
	const INPUTS_PROOF_ALREADY_CONFIRMED: [u8; 4] = [0x4c, 0x2d, 0xc5, 0xf4];
	const INVALID_TREE_INDEX: [u8; 4] = [0xc3, 0x3a, 0x4e, 0x44];

	let name = match *selector {
		NOT_OPERATOR => "NotOperator()",
		PAUSED => "PausedErr()",
		INVALID_PROOF => "InvalidProof()",
		PROOF_VERIFICATION_FAILED => "ProofVerificationFailed(bytes32,uint256[8])",
		NOTE_NOT_FOUND => "NoteNotFound(bytes32)",
		INVALID_DEPOSIT_STATE => "InvalidDepositState(bytes32)",
		DUPLICATE_NOTE => "DuplicateNoteCommitment(bytes32)",
		INVALID_BATCH_SIZE => "InvalidBatchSize()",
		INVALID_BATCH_LENGTH => "InvalidBatchLength(uint256,uint256)",
		INVALID_MONITORED_TOKEN => "InvalidMonitoredToken()",
		INVALID_AMOUNT => "InvalidAmount()",
		NO_TOKEN_RECEIVED => "NoTokenReceived()",
		NOT_DEPOSIT_RECIPIENT => "NotDepositRecipient()",
		TOKEN_TRANSFER_FAILED => "TokenTransferFailed()",
		ZERO_ADDRESS => "ZeroAddress()",
		INVALID_INPUTS_PROOF => "InvalidinputsProof()",
		PENDING_QUEUE_FULL => "PendingQueueFull()",
		SLOT_CONFLICT => "SlotConflict(uint256)",
		UNKNOWN_BATCH => "UnknownBatch(uint256)",
		ALREADY_CONFIRMED => "AlreadyConfirmed(uint256,uint8)",
		INPUTS_PROOF_ALREADY_CONFIRMED => "InputsProofAlreadyConfirmed(uint256)",
		INVALID_TREE_INDEX => "InvalidTreeIndex(uint8)",
		_ => return None,
	};

	if data.len() < 4 + 32 {
		return Some(name.to_string());
	}

	match *selector {
		PROOF_VERIFICATION_FAILED => {
			// Layout: selector[4] | superPiCommitment[32] | pubInputs[8 × 32]
			// Minimum: 4 + 32 = 36 bytes (commitment only)
			let commitment = hex::encode(&data[4..36]);
			if data.len() < 4 + 32 + 8 * 32 {
				return Some(format!(
					"{name}: on_chain_commitment=0x{commitment} (pubInputs truncated)"
				));
			}
			let mut words = [0u32; 8];
			for (i, w) in words.iter_mut().enumerate() {
				let start = 4 + 32 + i * 32;
				// Each pubInput is a uint256; the u32 value sits in the last 4 bytes of the 32-byte
				// slot.
				*w =
					u32::from_be_bytes(data[start + 28..start + 32].try_into().unwrap_or([0u8; 4]));
			}
			let inputs_hex: Vec<String> = words.iter().map(|w| format!("{w:#010x}")).collect();
			Some(format!(
				"{name}: on_chain_commitment=0x{commitment}, pubInputs=[{}]",
				inputs_hex.join(", ")
			))
		},
		NOTE_NOT_FOUND | INVALID_DEPOSIT_STATE | DUPLICATE_NOTE => {
			let arg = &data[4..36];
			Some(format!("{name}: 0x{}", hex::encode(arg)))
		},
		INVALID_BATCH_LENGTH | SLOT_CONFLICT | UNKNOWN_BATCH | INPUTS_PROOF_ALREADY_CONFIRMED => {
			let a = alloy::primitives::U256::from_be_slice(&data[4..36]);
			if data.len() < 4 + 64 {
				return Some(format!("{name}: {a}"));
			}
			let b = alloy::primitives::U256::from_be_slice(&data[36..68]);
			Some(format!("{name}: {a}, {b}"))
		},
		ALREADY_CONFIRMED => {
			let a = alloy::primitives::U256::from_be_slice(&data[4..36]);
			if data.len() < 4 + 64 {
				return Some(format!("{name}: batch_id={a}"));
			}
			let b = alloy::primitives::U256::from_be_slice(&data[36..68]);
			Some(format!("{name}: batch_id={a}, tree_index={b}"))
		},
		INVALID_TREE_INDEX => {
			let b = data[4 + 31]; // uint8 is right-padded in a 32-byte slot
			Some(format!("{name}: {b}"))
		},
		_ => Some(name.to_string()),
	}
}
