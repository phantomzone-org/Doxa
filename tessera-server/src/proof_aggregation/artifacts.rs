//! Shared artifact helpers and circuit utilities for proof aggregation.

/// Current manifest format version.  Increment when the on-disk layout changes.
pub(super) const MANIFEST_VERSION: u32 = 1;

pub(super) const MANIFEST_PATH: &str = "manifest.json";
pub(super) const LEAF_COMMON_PATH: &str = "leaf_common.bin";
pub(super) const LEAF_VERIFIER_PATH: &str = "leaf_verifier.bin";

/// Returns the file name for the serialized circuit data at aggregation level `i`.
pub(super) fn level_circuit_path(i: usize) -> String {
	format!("level_{i}_circuit_data.bin")
}
