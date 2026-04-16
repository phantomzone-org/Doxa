use std::{
	mem::zeroed,
	ops::{Add, Mul, Neg},
};

use plonky2::hash::hashing::hash_n_to_m_no_pad;
use plonky2_field::{
	extension::Extendable,
	goldilocks_field::GoldilocksField,
	types::{Field, PrimeField64},
};
use rand::RngExt;
use tessera_utils::F;

use crate::ecgfp5::{CompressedPoint, Legendre, PointEw};

/// A scalar (integer modulo the prime group order n).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scalar(pub [u64; 5]);

// TODO: ack Thomas Pornin

impl Scalar {
	pub const BITS: usize = 319;
	// The modulus itself, stored in a Scalar structure (which
	// contravenes to the rules of a Scalar; this constant MUST NOT leak
	// outside the API).
	const N: Self = Self([
		0xE80FD996948BFFE1,
		0xE8885C39D724A09C,
		0x7FFFFFE6CFB80639,
		0x7FFFFFF100000016,
		0x7FFFFFFD80000007,
	]);
	// -1/N[0] mod 2^64
	const N0I: u64 = 0xD78BEF72057B7BDF;
	pub const ONE: Self = Self([1, 0, 0, 0, 0]);
	// 2^640 mod n.
	const R2: Self = Self([
		0xA01001DCE33DC739,
		0x6C3228D33F62ACCF,
		0xD1D796CC91CF8525,
		0xAADFFF5D1574C1D8,
		0x4ACA13B28CA251F5,
	]);
	// 2^632 mod n.
	const T632: Self = Self([
		0x2B0266F317CA91B3,
		0xEC1D26528E984773,
		0x8651D7865E12DB94,
		0xDA2ADFF5941574D0,
		0x53CACA12110CA256,
	]);
	// Group order n is slightly below 2^319. We store values over five
	// 64-bit limbs.
	pub const ZERO: Self = Self([0, 0, 0, 0, 0]);

	pub(crate) fn to_bit_arr(self) -> [bool; Self::BITS] {
		let mut bits = [false; Self::BITS];
		for (i, b) in bits.iter_mut().enumerate() {
			let limb = i / 64;
			let bit = i % 64;
			*b = (self.0[limb] >> bit) & 1 == 1;
		}
		bits
	}

	fn add_inner(self, a: Self) -> Self {
		let mut r = Self::ZERO;
		let mut c: u64 = 0;
		for i in 0..5 {
			let z = (self.0[i] as u128)
				.wrapping_add(a.0[i] as u128)
				.wrapping_add(c as u128);
			r.0[i] = z as u64;
			c = (z >> 64) as u64;
		}
		r
	}

	fn sub_inner(self, a: Self) -> (Self, u64) {
		let mut r = Self::ZERO;
		let mut c: u64 = 0;
		for i in 0..5 {
			let z = (self.0[i] as u128)
				.wrapping_sub(a.0[i] as u128)
				.wrapping_sub(c as u128);
			r.0[i] = z as u64;
			c = ((z >> 64) as u64) & 1;
		}
		// c == 1 if overflow otherwise 0
		(r, c)
	}

	pub(crate) fn add_mod(self, a: Self) -> Self {
		let t = self.add_inner(a);
		let (w, cc) = t.sub_inner(Self::N);
		if cc == 0 { w } else { t }
	}

	fn sub_mod(self, a: Self) -> Self {
		let (t, cc) = self.sub_inner(a);
		if cc == 0 { t } else { t.add_inner(Self::N) }
	}

	pub(crate) fn neg_mod(self) -> Self {
		Self::ZERO.sub_mod(self)
	}

	/// Montgomery multiplication: returns (self*rhs)/2^320 mod n.
	fn montymul(self, rhs: Self) -> Self {
		let mut r = Self::ZERO;
		for i in 0..5 {
			let m = rhs.0[i];
			let f = self.0[0]
				.wrapping_mul(m)
				.wrapping_add(r.0[0])
				.wrapping_mul(Self::N0I);
			let mut cc1: u64 = 0;
			let mut cc2: u64 = 0;
			for j in 0..5 {
				let mut z = (self.0[j] as u128)
					.wrapping_mul(m as u128)
					.wrapping_add(r.0[j] as u128)
					.wrapping_add(cc1 as u128);
				cc1 = (z >> 64) as u64;
				z = (f as u128)
					.wrapping_mul(Self::N.0[j] as u128)
					.wrapping_add((z as u64) as u128)
					.wrapping_add(cc2 as u128);
				cc2 = (z >> 64) as u64;
				if j > 0 {
					r.0[j - 1] = z as u64;
				}
			}
			r.0[4] = cc1.wrapping_add(cc2);
		}
		let (r2, cc) = r.sub_inner(Self::N);
		if cc == 0 { r2 } else { r }
	}

	pub(crate) fn mul_mod(self, rhs: Self) -> Self {
		self.montymul(Self::R2).montymul(rhs)
	}

	/// Sample a uniformly random scalar in `[0, N)`.
	pub fn sample<R: rand::Rng>(rng: &mut R) -> Self {
		let mut bytes = [0u8; 40];
		rng.fill(&mut bytes);
		Self::decode_reduce(&bytes)
	}

	/// Decode the provided byte slice into a scalar. The bytes are
	/// interpreted into an integer in little-endian unsigned convention.
	/// All slice bytes are read. Returns `Some(scalar)` if the decoded
	/// integer is lower than the group order, `None` otherwise.
	pub fn decode(buf: &[u8]) -> Option<Self> {
		let n = buf.len();
		let mut r = Self::ZERO;
		let mut extra: u8 = 0;
		for (i, b) in buf.iter().enumerate().take(n) {
			if i < 40 {
				r.0[i >> 3] |= (*b as u64).wrapping_shl(((i as u32) & 7) << 3);
			} else {
				extra |= b;
			}
		}

		// If input buffer is at most 39 bytes then the result is
		// necessarily in range; we can skip the reduction tests.
		if n <= 39 {
			return Some(r);
		}

		// Output is valid iff extra == 0 and the value is lower than n
		// (checked via overflow flag from sub_inner).
		let (_, c) = r.sub_inner(Self::N);
		let valid = c & ((extra as u64).wrapping_add(0xFF) >> 8).wrapping_sub(1);
		if valid != 0 { Some(r) } else { None }
	}

	/// Decode the provided byte slice into a scalar. The bytes are
	/// interpreted into an integer in little-endian unsigned convention.
	/// All slice bytes are read, and the value is REDUCED modulo n. This
	/// function never fails; it accepts arbitrary input values.
	pub fn decode_reduce(buf: &[u8]) -> Self {
		// We inject the value by chunks of 312 bits, in high-to-low
		// order. We multiply by 2^312 the intermediate result, which
		// is equivalent to performing a Montgomery multiplication
		// by 2^632 mod n.

		// If buffer length is at most 39 bytes, then the plain decode()
		// function works.
		let n = buf.len();
		if n <= 39 {
			return Self::decode(buf).unwrap();
		}

		// We can now assume that we have at least 40 bytes of input.

		// Compute k as a multiple of 39 such that n-39 <= k < n. Since
		// n >= 40, this implies that k >= 1. We decode the top chunk
		// (which has length _at most_ 39 bytes) into acc.
		let mut k = ((n - 1) / 39) * 39;
		let mut acc = Self::decode(&buf[k..n]).unwrap();
		while k > 0 {
			k -= 39;
			let b = Self::decode(&buf[k..k + 39]).unwrap();
			acc = acc.montymul(Self::T632).add(b);
		}
		acc
	}

	/// Reduce 5 Goldilocks field elements (320 bits) to scalar < N.
	/// Circuit-friendly: just a conditional subtraction.
	pub(crate) fn from_hash(elements: [GoldilocksField; 5]) -> Self {
		let mut h = elements.map(|e| e.to_canonical_u64());
		// drop 2 bits of last GL element, resulting in a value 318 (< N) bit value.
		h[4] <<= 2;
		h[4] >>= 2;
		Self(h)
	}
}

impl Add for Scalar {
	type Output = Self;

	fn add(self, rhs: Self) -> Self {
		self.add_mod(rhs)
	}
}

impl Mul for Scalar {
	type Output = Self;

	fn mul(self, rhs: Self) -> Self {
		self.mul_mod(rhs)
	}
}

impl Neg for Scalar {
	type Output = Self;

	fn neg(self) -> Self {
		self.neg_mod()
	}
}

/// A private key for Schnorr signatures.
///
/// This is a scalar value that must be kept secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrivateKey(Scalar);

impl PrivateKey {
	/// Create a new private key from a scalar.
	pub fn new(scalar: Scalar) -> Self {
		Self(scalar)
	}

	/// Get the underlying scalar value.
	pub fn as_scalar(&self) -> Scalar {
		self.0
	}

	/// Decode a byte slice into a private key, reducing modulo N.
	pub fn decode_reduce(buf: &[u8]) -> Self {
		Self(Scalar::decode_reduce(buf))
	}

	/// Sample a uniformly random private key.
	pub fn sample<R: rand::Rng>(rng: &mut R) -> Self {
		Self(Scalar::sample(rng))
	}

	/// Derive the corresponding public key.
	pub fn public_key<F: Extendable<5>>(&self) -> PublicKey<F> {
		PublicKey(PointEw::generator().scalar_mul(&self.0))
	}

	// Encode the private key as 40 bytes.
	// pub fn to_bytes(&self) -> [u8; 40] {
	//     self.0.encode()
	// }

	// Decode a private key from 40 bytes.
	// Returns `None` if the encoding is invalid or represents zero.
	// pub fn from_bytes(bytes: &[u8; 40]) -> Option<Self> {
	//     Scalar::decode(bytes).filter(|s| s.iszero() == 0).map(Self)
	// }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct CompressedPublicKey<F: Extendable<5>>(pub(crate) CompressedPoint<F>);

impl<F: PrimeField64 + Legendre + Extendable<5>> From<PublicKey<F>> for CompressedPublicKey<F> {
	fn from(value: PublicKey<F>) -> Self {
		CompressedPublicKey(value.0.encode())
	}
}

impl<F: PrimeField64 + Extendable<5>> CompressedPublicKey<F> {
	/// Serialize to 40 bytes: 5 × u64 little-endian.
	/// Mirrors the r-half encoding in `Signature::encode`.
	pub fn encode(&self) -> [u8; 40] {
		let mut out = [0u8; 40];
		for (i, f) in self.0.w.0.iter().enumerate() {
			out[i * 8..i * 8 + 8].copy_from_slice(&f.to_canonical_u64().to_le_bytes());
		}
		out
	}

	/// Deserialize from 40 bytes (inverse of `encode`).
	pub fn decode(bytes: &[u8; 40]) -> Self {
		let mut v = [0u64; 5];
		for i in 0..5 {
			v[i] = u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
		}
		CompressedPublicKey(CompressedPoint::from(v))
	}
}

/// A public key for Schnorr signatures.
///
/// This is a point on the curve that corresponds to a private key.
#[derive(Clone, Copy, Debug)]
pub struct PublicKey<F: Extendable<5>>(PointEw<F>);

impl<F: Extendable<5>> PublicKey<F> {
	/// Create a new public key from a curve point.
	pub fn new(point: PointEw<F>) -> Self {
		Self(point)
	}

	/// Get the underlying curve point.
	pub fn as_point(&self) -> PointEw<F> {
		self.0
	}
}

pub struct Signature {
	pub(crate) r: PointEw<GoldilocksField>,
	pub(crate) s: Scalar,
}

impl Signature {
	pub(crate) const ZERO: Self = Self {
		r: PointEw::NEUTRAL,
		s: Scalar::ZERO,
	};

	/// Serialize to 80 bytes: 40 bytes for `r` (5 × u64 LE) + 40 bytes for `s` (5 × u64 LE).
	pub fn encode(&self) -> [u8; 80] {
		let mut out = [0u8; 80];
		for (i, f) in self.r.encode().w.0.iter().enumerate() {
			out[i * 8..i * 8 + 8].copy_from_slice(&f.to_canonical_u64().to_le_bytes());
		}
		for (i, limb) in self.s.0.iter().enumerate() {
			out[40 + i * 8..40 + i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
		}
		out
	}
}

fn poseidon_hash_to_scalar(hash_input: &[GoldilocksField]) -> Scalar {
	use plonky2::{hash::poseidon::PoseidonHash, plonk::config::Hasher};
	let mut out = [GoldilocksField::ZERO; 5];
	out.copy_from_slice(
		hash_n_to_m_no_pad::<_, <PoseidonHash as Hasher<GoldilocksField>>::Permutation>(
			hash_input, 5,
		)
		.as_slice(),
	);
	Scalar::from_hash(out)
}

pub(crate) fn schnorr_challenge(
	cr: &CompressedPoint<F>,
	cq: &CompressedPoint<F>,
	m: &[F],
) -> Scalar {
	let mut h: Vec<F> = cr.w.0.to_vec();
	h.extend_from_slice(&cq.w.0);
	h.extend_from_slice(m);
	poseidon_hash_to_scalar(&h)
}

/// Sign: R = k*G, e = H(R || Q || m), s = k + d*-e
pub fn schnorr_sign(privkey: &PrivateKey, message: &[GoldilocksField], k: Scalar) -> Signature {
	let g = PointEw::generator();
	let r = g.scalar_mul(&k);

	let r_encoded = r.encode();
	let q_encoded = privkey.public_key().as_point().encode();

	let e = schnorr_challenge(&r_encoded, &q_encoded, message);

	let s = k + privkey.0 * -e;

	Signature {
		r,
		s,
	}
}

/// Verify: s*G + e*Q == R
pub(crate) fn schnorr_verify(
	pubkey: &PublicKey<GoldilocksField>,
	message: &[GoldilocksField],
	sig: &Signature,
) -> bool {
	let r_encoded = sig.r.encode();
	let q_encoded = pubkey.0.encode();

	let e = schnorr_challenge(&r_encoded, &q_encoded, message);

	let g = PointEw::generator();
	let sg = g.scalar_mul(&sig.s);
	let eq = pubkey.0.scalar_mul(&(e));
	let result = sg.add(&eq);

	result.encode() == sig.r.encode()
}

#[cfg(test)]
mod tests {
	use rand::SeedableRng;
	use rand_chacha::ChaCha8Rng;

	use super::*;

	type F = GoldilocksField;

	#[test]
	fn test_schnorr_sign_verify() {
		// Private key d (a random scalar < N)
		let mut rng = ChaCha8Rng::seed_from_u64(42);
		let d = Scalar::sample(&mut rng);

		// Public key Q = d*G
		let privkey = PrivateKey::new(d);
		let pubkey = privkey.public_key();
		assert!(!pubkey.0.at_inf);

		// Message
		let message: Vec<GoldilocksField> = (1..=10)
			.map(|i| GoldilocksField::from_canonical_u64(i))
			.collect();

		// Nonce k
		let k = Scalar::sample(&mut rng);

		// Sign
		let sig = schnorr_sign(&privkey, &message, k);
		assert!(!sig.r.at_inf, "R should not be at infinity");

		// Verify: correct message should pass
		assert!(
			schnorr_verify(&pubkey, &message, &sig),
			"valid signature should verify"
		);

		// Verify: wrong message should fail
		let wrong_message: Vec<GoldilocksField> = (11..=20)
			.map(|i| GoldilocksField::from_canonical_u64(i))
			.collect();
		assert!(
			!schnorr_verify(&pubkey, &wrong_message, &sig),
			"wrong message should not verify"
		);

		// Verify: wrong public key should fail
		let wrong_pubkey = PublicKey(pubkey.0.double());
		assert!(
			!schnorr_verify(&wrong_pubkey, &message, &sig),
			"wrong pubkey should not verify"
		);
	}
}
