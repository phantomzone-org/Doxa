use plonky2_field::types::Field;
use tessera_client::PrivateIdentifier;
use tessera_utils::F;

/// Deserialize 8 bytes (u64 LE) back to a Goldilocks field element.
pub fn bytes_to_f(b: &[u8; 8]) -> F {
    F::from_canonical_u64(u64::from_le_bytes(*b))
}

/// Deserialize 16 bytes into a `PrivateIdentifier`.
pub fn bytes_to_private_id(b: &[u8; 16]) -> PrivateIdentifier {
    PrivateIdentifier([
        bytes_to_f(b[..8].try_into().unwrap()),
        bytes_to_f(b[8..].try_into().unwrap()),
    ])
}
