#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

extern crate alloc;
mod merkle_proof;
#[allow(clippy::module_inception)]
mod tree;
pub(crate) mod verification;

pub mod error;
pub use merkle_proof::*;
pub use tree::*;
