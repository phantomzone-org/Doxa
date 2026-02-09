//! SHA-256 circuit gadget for Plonky2.
//!
//! Implements the full SHA-256 compression function and multi-block
//! hashing as an extension trait on [`CircuitBuilder`], composing the
//! U32 primitives from [`crate::plonky2_gadgets::u32`].
//!
//! # Usage
//!
//! ```ignore
//! let luts = Sha256Luts::new(&mut builder);
//! let input: [U32Target; 16] = ...;
//! let hash = builder.sha256_single_block(input, &luts);
//! ```

pub mod circuit;
pub mod constants;

pub use circuit::*;
pub use constants::*;

use plonky2::{
	field::extension::Extendable,
	hash::hash_types::RichField,
	plonk::circuit_builder::CircuitBuilder,
};

use crate::plonky2_gadgets::u32::{
	add_and_lookup_table, add_u8_range_check_lookup_table, add_xor_lookup_table, U32Target,
};

/// Bundles the three lookup-table indices needed by SHA256 sub-operations.
///
/// Created once per circuit via [`Sha256Luts::new`].  Passed by reference
/// to all SHA256 circuit-building methods.
#[derive(Clone, Copy, Debug)]
pub struct Sha256Luts {
	pub range_lut: usize,
	pub xor_lut: usize,
	pub and_lut: usize,
}

impl Sha256Luts {
	/// Registers all three lookup tables required by SHA256 and returns
	/// their bundled indices.
	///
	/// Call this exactly once per circuit.
	pub fn new<F: RichField + Extendable<D>, const D: usize>(
		builder: &mut CircuitBuilder<F, D>,
	) -> Self {
		Self {
			range_lut: add_u8_range_check_lookup_table(builder),
			xor_lut: add_xor_lookup_table(builder),
			and_lut: add_and_lookup_table(builder),
		}
	}
}

/// The 8-word output of a SHA-256 hash.
///
/// Each element is a [`U32Target`] representing one 32-bit word of the
/// 256-bit digest, in big-endian word order: `[H0, H1, ..., H7]`.
pub type Sha256Target = [U32Target; 8];
