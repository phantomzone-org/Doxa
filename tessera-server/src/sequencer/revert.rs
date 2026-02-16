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

pub(super) fn is_note_not_found_revert(err: &impl std::fmt::Display) -> bool {
	const NOTE_NOT_FOUND: [u8; 4] = [0x70, 0x82, 0x97, 0xd2];
	let s = err.to_string();
	if let Some(data) = extract_revert_data(&s) {
		return data.len() >= 4 && data[..4] == NOTE_NOT_FOUND;
	}
	extract_custom_error_selector(&s) == Some(NOTE_NOT_FOUND)
}

fn extract_custom_error_selector(s: &str) -> Option<[u8; 4]> {
	let needle = "custom error 0x";
	let idx = s.find(needle)?;
	let hex_start = idx + needle.len();
	let hex_end = hex_start + 8;
	if s.len() < hex_end {
		return None;
	}
	let bytes = hex::decode(&s[hex_start..hex_end]).ok()?;
	Some(bytes.as_slice().try_into().ok()?)
}

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

fn decode_bridge_custom_error(selector: &[u8; 4], data: &[u8]) -> Option<String> {
	const NOT_OPERATOR: [u8; 4] = [0x7c, 0x21, 0x4f, 0x04];
	const NOT_TRUSTED_SOURCE: [u8; 4] = [0x4c, 0x9e, 0xc4, 0xbb];
	const PAUSED: [u8; 4] = [0xda, 0x82, 0x93, 0x39];
	const INVALID_PROOF: [u8; 4] = [0x09, 0xbd, 0xe3, 0x39];
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
	const INSUFFICIENT_TRACKED_BALANCE: [u8; 4] = [0xf0, 0x92, 0xaa, 0xce];
	const ZERO_ADDRESS: [u8; 4] = [0xd9, 0x2e, 0x23, 0x3d];
	const LOADED_BATCH_NOT_FOUND: [u8; 4] = [0x6c, 0xc9, 0xe0, 0x4f];
	const INVALID_AGG_INPUT_PROOF: [u8; 4] = [0x13, 0xa2, 0x9f, 0xa2];

	let name = match *selector {
		NOT_OPERATOR => "NotOperator()",
		NOT_TRUSTED_SOURCE => "NotTrustedSource()",
		PAUSED => "PausedErr()",
		INVALID_PROOF => "InvalidProof()",
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
		INSUFFICIENT_TRACKED_BALANCE => "InsufficientTrackedBalance(uint256,uint256)",
		ZERO_ADDRESS => "ZeroAddress()",
		LOADED_BATCH_NOT_FOUND => "LoadedBatchNotFound(bytes32)",
		INVALID_AGG_INPUT_PROOF => "InvalidAggregatedInputProof()",
		_ => return None,
	};

	if data.len() < 4 + 32 {
		return Some(name.to_string());
	}

	match *selector {
		NOTE_NOT_FOUND | INVALID_DEPOSIT_STATE | DUPLICATE_NOTE | LOADED_BATCH_NOT_FOUND => {
			let arg = &data[4..36];
			Some(format!("{name}: 0x{}", hex::encode(arg)))
		},
		INVALID_BATCH_LENGTH | INSUFFICIENT_TRACKED_BALANCE => {
			if data.len() < 4 + 64 {
				return Some(name.to_string());
			}
			let a = alloy::primitives::U256::from_be_slice(&data[4..36]);
			let b = alloy::primitives::U256::from_be_slice(&data[36..68]);
			Some(format!("{name}: a={a} b={b}"))
		},
		_ => Some(name.to_string()),
	}
}
