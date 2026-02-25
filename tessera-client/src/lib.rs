#![allow(clippy::all)]
#![allow(warnings)]
pub(crate) mod account;
pub(crate) mod commitment;
pub(crate) mod ecgfp5;
pub(crate) mod note;
pub(crate) mod p2;
pub(crate) mod schnorr;

pub const DS_NULLIFIER_KEY: u64 = 12;
pub const DS_PUBLIC_IDENTIFIER: u64 = 13;

pub const NOTE_BATCH: usize = 8;

pub use account::*;
pub use note::*;
