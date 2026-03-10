use plonky2_field::types::Field;
use primitive_types::H160;

/// H160 is repr as 20 u8 elements in LE. Map it to 5 F els, with limb size 32 bits
pub(crate) fn map_h160_to_f<F: Field>(v: &H160) -> [F; 5] {
	core::array::from_fn(|i| {
		let v32 = u32::from_le_bytes([v.0[4 * i], v.0[4 * i + 1], v.0[4 * i + 2], v.0[4 * i + 3]]);
		F::from_canonical_u32(v32)
	})
}
