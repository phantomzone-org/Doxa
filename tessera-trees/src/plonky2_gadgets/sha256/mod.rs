//! SHA-256 circuit gadget for Plonky2.
//!
//! Implements the full SHA-256 compression function and multi-block
//! hashing as an extension trait on [`CircuitBuilder`], composing the
//! U32 primitives from [`crate::plonky2_gadgets::u32`].
//!
//! # Usage
//!
//! ```ignore
//! let luts = Sha256Luts::new(&mut builder, 8);
//! let input: [U32Target; 16] = ...;
//! let hash = builder.sha256_single_block(input, &luts);
//! ```

pub mod circuit;
pub mod constants;

pub use circuit::*;
pub use constants::*;

use crate::plonky2_gadgets::u32::{BitwiseLuts, U32Target};

/// Type alias: SHA-256 lookup tables are [`BitwiseLuts`] parameterized
/// by chunk bit-width.
pub type Sha256Luts = BitwiseLuts;

/// The 8-word output of a SHA-256 hash.
///
/// Each element is a [`U32Target`] representing one 32-bit word of the
/// 256-bit digest, in big-endian word order: `[H0, H1, ..., H7]`.
pub type Sha256Target = [U32Target; 8];
