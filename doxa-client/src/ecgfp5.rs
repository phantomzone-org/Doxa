use std::{
	hash::Hash,
	ops::{Mul, Neg},
};

use plonky2_field::{
	extension::{Extendable, FieldExtension, Frobenius, quintic::QuinticExtension},
	goldilocks_field::GoldilocksField,
	ops::Square,
	types::{Field, PrimeField, PrimeField64},
};

use crate::{DEFAULT_SPEND_AUTH_PK, schnorr::Scalar};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CompressedPoint<F: Extendable<5>> {
	pub(crate) w: QuinticExtension<F>,
}

impl<F: Field + Extendable<5>> From<[u64; 5]> for CompressedPoint<F> {
	fn from(v: [u64; 5]) -> Self {
		Self {
			w: QuinticExtension::from_basefield_array([
				F::from_canonical_u64(v[0]),
				F::from_canonical_u64(v[1]),
				F::from_canonical_u64(v[2]),
				F::from_canonical_u64(v[3]),
				F::from_canonical_u64(v[4]),
			]),
		}
	}
}

impl<F: PrimeField64 + Extendable<5>> Hash for CompressedPoint<F> {
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		for f in &self.w.0 {
			f.to_canonical_u64().hash(state);
		}
	}
}

pub(crate) const GENERATOR: [[u64; 5]; 2] = [
	[
		11712523173042564207,
		14090224426659529053,
		13197813503519687414,
		16280770174934269299,
		15998333998318935536,
	],
	[
		14639054205878357578,
		17426078571020221072,
		2548978194165003307,
		8663895577921260088,
		9793640284382595140,
	],
];

pub(crate) const ECGFP5_A: [u64; 5] = [2, 0, 0, 0, 0];

// a/3 = 2/3 mod p = 6148914689804861441
pub(crate) const ECGFP5_A_DIV_3: [u64; 5] = [6148914689804861441, 0, 0, 0, 0];

pub(crate) const ECGFP5_B: [u64; 5] = [0, 263, 0, 0, 0];

// 4bz
pub(crate) const ECGFP5_4BZ: [u64; 5] = [0, 263 * 4, 0, 0, 0];

// A = (3b-a^2) / 3 = b - a^2/3 = 263z - 4/3
// -4/3 mod p = 6148914689804861439
pub(crate) const ECGFP5_CAP_A: [u64; 5] = [6148914689804861439, 263, 0, 0, 0];

// B = a(2a^2 - 9b) / 27 = 16/27 - (2/3)263z
// = 15713893096167979237 + 6148914689804861265z
pub(crate) const ECGFP5_CAP_B: [u64; 5] = [15713893096167979237, 6148914689804861265, 0, 0, 0];

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct PointEw<F: Extendable<5>> {
	pub(crate) x: QuinticExtension<F>,
	pub(crate) y: QuinticExtension<F>,
	pub(crate) at_inf: bool,
}

impl<F: Extendable<5>> From<[[u64; 5]; 2]> for PointEw<F> {
	fn from(value: [[u64; 5]; 2]) -> Self {
		let p = PointEw::<F> {
			x: QuinticExtension::from_basefield_array([
				F::from_canonical_u64(value[0][0]),
				F::from_canonical_u64(value[0][1]),
				F::from_canonical_u64(value[0][2]),
				F::from_canonical_u64(value[0][3]),
				F::from_canonical_u64(value[0][4]),
			]),
			y: QuinticExtension::from_basefield_array([
				F::from_canonical_u64(value[1][0]),
				F::from_canonical_u64(value[1][1]),
				F::from_canonical_u64(value[1][2]),
				F::from_canonical_u64(value[1][3]),
				F::from_canonical_u64(value[1][4]),
			]),
			at_inf: false,
		};
		assert!(p.is_on_curve());
		p
	}
}

impl<F: Extendable<5>> PointEw<F> {
	// define netural
	pub(crate) const NEUTRAL: PointEw<F> = PointEw {
		x: QuinticExtension::<F>::ZERO,
		y: QuinticExtension::<F>::ZERO,
		at_inf: true,
	};

	fn a() -> QuinticExtension<F> {
		QuinticExtension::from_basefield_array(ECGFP5_A.map(F::from_canonical_u64))
	}

	pub(crate) fn adiv3() -> QuinticExtension<F> {
		QuinticExtension::from_basefield_array(ECGFP5_A_DIV_3.map(F::from_canonical_u64))
	}

	fn b() -> QuinticExtension<F> {
		QuinticExtension::from_basefield_array(ECGFP5_B.map(F::from_canonical_u64))
	}

	fn b4mul() -> QuinticExtension<F> {
		QuinticExtension::from_basefield_array(ECGFP5_4BZ.map(F::from_canonical_u64))
	}

	// A = (3b-a^2) / 3 = b - a^2/3 = 263z - 4/3
	// -4/3 mod p = 6148914689804861439
	fn cap_a() -> QuinticExtension<F> {
		QuinticExtension::from_basefield_array(ECGFP5_CAP_A.map(F::from_canonical_u64))
	}

	// B = a(2a^2 - 9b) / 27 = 16/27 - (2/3)263z
	// = 15713893096167979237 + 6148914689804861265z
	fn cap_b() -> QuinticExtension<F> {
		QuinticExtension::from_basefield_array(ECGFP5_CAP_B.map(F::from_canonical_u64))
	}

	pub(crate) fn generator() -> Self {
		PointEw::<F> {
			x: QuinticExtension::from_basefield_array(GENERATOR[0].map(F::from_canonical_u64)),
			y: QuinticExtension::from_basefield_array(GENERATOR[1].map(F::from_canonical_u64)),
			at_inf: false,
		}
	}

	/// Incomplete addition. Assumes self.x != rhs.x.
	fn add_incomplete(&self, rhs: &PointEw<F>) -> Self {
		let lambda = (rhs.y - self.y) / (rhs.x - self.x);
		let x3 = lambda * lambda - self.x - rhs.x;
		let y3 = lambda * (self.x - x3) - self.y;

		Self {
			x: x3,
			y: y3,
			at_inf: false,
		}
	}

	pub(crate) fn add(&self, rhs: &PointEw<F>) -> Self {
		if self.at_inf {
			return *rhs;
		}
		if rhs.at_inf {
			return *self;
		}
		if self.x == rhs.x {
			if self.y == rhs.y {
				return self.double();
			}

			return Self {
				x: Self::scalar(0),
				y: Self::scalar(0),
				at_inf: true,
			};
		}
		self.add_incomplete(rhs)
	}

	// Returns tangent from self |-> rhs
	pub(crate) fn tangent(&self, rhs: &Self) -> QuinticExtension<F> {
		// self.x must ne rhs.x
		assert!(self.x.ne(&rhs.x));

		(rhs.y - self.y) / (rhs.x - self.x)
	}

	pub(crate) fn double(&self) -> Self {
		// Tangent slope: λ = (3x² + A) / (2y)
		let x_sq = self.x * self.x;
		let num = x_sq * Self::scalar(3) + Self::cap_a();
		let den = self.y * Self::scalar(2);
		let lambda = num / den;

		let x3 = lambda * lambda - self.x - self.x;
		let w3 = lambda * (self.x - x3) - self.y;

		Self {
			x: x3,
			y: w3,
			at_inf: false,
		}
	}

	pub(crate) fn is_on_curve(&self) -> bool {
		self.y.square() == ((self.x.square() * self.x) + Self::cap_a() * self.x + Self::cap_b())
	}

	fn scalar(c: u64) -> QuinticExtension<F> {
		QuinticExtension::from_basefield_array([
			F::from_canonical_u64(c),
			F::ZERO,
			F::ZERO,
			F::ZERO,
			F::ZERO,
		])
	}

	pub(crate) fn scalar_mul(&self, s: &Scalar) -> Self {
		if self.at_inf {
			return Self::NEUTRAL;
		}
		let bits = s.to_bit_arr();
		let mut top = Scalar::BITS;
		while top > 0 && !bits[top - 1] {
			top -= 1;
		}
		if top == 0 {
			return Self::NEUTRAL;
		}
		let mut acc = *self;
		for i in (0..top - 1).rev() {
			acc = acc.double();
			if bits[i] {
				acc = acc.add(self);
			}
		}
		acc
	}
}

impl<F: PrimeField64 + Legendre + Extendable<5>> PointEw<F> {
	pub(crate) fn encode(&self) -> CompressedPoint<F> {
		if self.at_inf {
			return CompressedPoint {
				w: QuinticExtension::<F>::ZERO,
			};
		}

		let w = self.y / (Self::adiv3() - self.x);
		CompressedPoint {
			w,
		}
	}

	pub(crate) fn decode(w: CompressedPoint<F>) -> Option<Self> {
		let w = w.w;

		if w.is_zero() {
			return Some(Self {
				x: QuinticExtension::<F>::ZERO,
				y: QuinticExtension::<F>::ZERO,
				at_inf: true,
			});
		}

		let e = w.square() - Self::a();
		let delta = e.square() - Self::b4mul();
		// point at inf is handled with w = 0 before. If delta is not a sqaure, then w
		// is invalid.
		delta.sqrt().map(|r| {
			let half: F = F::from_canonical_u64(F::ORDER.div_ceil(2));

			let x1 = <QuinticExtension<F> as FieldExtension<5>>::scalar_mul(&(e + r), half);
			let x2 = <QuinticExtension<F> as FieldExtension<5>>::scalar_mul(&(e - r), half);
			let x = if x1.legendre() == LegendreSymbol::ONE {
				// x1 is QR
				x1
			} else {
				x2
			};

			let y = (-w) * x;

			Self {
				x: x + Self::adiv3(),
				y,
				at_inf: false,
			}
		})
	}
}

impl<F: Extendable<5>> Neg for PointEw<F> {
	type Output = Self;

	fn neg(self) -> Self::Output {
		PointEw {
			x: self.x,
			y: self.y.neg(),
			at_inf: false,
		}
	}
}

fn repeated_square<F: Square>(v: F, n: usize) -> F {
	let mut x1 = v.square();
	(1..n).for_each(|_| {
		x1 = x1.square();
	});
	x1
}

pub trait Sqrt: Sized {
	fn sqrt(&self) -> Option<Self>;
}

impl<F: Extendable<5> + PrimeField> Sqrt for QuinticExtension<F> {
	fn sqrt(&self) -> Option<Self> {
		let mut t = *self;
		let mut y = t;

		// === x^((p+1) / 2) ===

		t *= y.square(); // t = x^3
		y = t;

		y = repeated_square(y, 2);
		t *= y; // t = x^(2^4-1)

		y = t;
		y = repeated_square(y, 4);
		t *= y; // t = x^(2^8-1)

		y = t;
		y = repeated_square(y, 8);
		t *= y; // t = x^(2^16-1)

		y = t;
		y = repeated_square(y, 16);
		t *= y; // t = x^(2^32-1)

		t = repeated_square(t, 31); // t = x^(2^63 - 2^32)
		t *= *self; // x^((p+1)/2)

		// === x^((r-1) / 2) ===

		y = t;
		y = y.repeated_frobenius(2);
		t *= y;
		t = t.frobenius(); // x^((r-1) / 2)

		// === x^r ===

		y = t.square();
		y = *self * y;
		let a: [F; 5] = y.to_basefield_array();
		let a = a[0]; // TODO: x^r \in GFp. Therefore mul in GFp5 can be optimised

		// === sqrt(x^r) / x^((r-1) / 2) ===
		a.sqrt().map(|sqrta| {
			// TODO: Next we need to multiple `t` an element in GFp5 with `a` a goldilocks
			// element. `t` is a degree 4 polynomial whereas `a` is a constant polynomial in
			// GFp5. Multiplication can be handled with simple scalar mnultiplication.
			// However, p2 does not support such a method. Hence, we convert `a` to an
			// element in GFp5 and then multiply. This is not optimal and should be optmised
			// later.
			// let a = QuinticExtension::from_basefield(a);
			t = t.inverse();
			t = <QuinticExtension<F> as FieldExtension<5>>::scalar_mul(&t, sqrta);
			t
		})
	}
}

#[derive(PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum LegendreSymbol {
	ZERO,
	ONE,
	NEGONE, // -1
}

impl From<u64> for LegendreSymbol {
	fn from(value: u64) -> Self {
		if value == 0 {
			return Self::ZERO;
		} else if value == 1 {
			return Self::ONE;
		}
		// TODO: assert that value is indeed p-1
		Self::NEGONE
	}
}

pub trait Legendre {
	fn legendre(&self) -> LegendreSymbol;
}

impl Legendre for GoldilocksField {
	fn legendre(&self) -> LegendreSymbol {
		// (p-1)/2 = 0x7FFFFFFF80000000
		let x = *self;
		let x2 = x * x.square();
		let x4 = x2 * repeated_square(x2, 2);
		let x8 = x4 * repeated_square(x4, 4);
		let x16 = x8 * repeated_square(x8, 8);
		let x32 = x16 * repeated_square(x16, 16);
		let symbol = repeated_square(x32, 31);
		symbol.to_canonical_u64().into()
	}
}

impl<F> Legendre for QuinticExtension<F>
where
	F: PrimeField64 + Legendre + Extendable<5>,
{
	fn legendre(&self) -> LegendreSymbol {
		let x0 = self.frobenius();
		let x1 = x0.frobenius();
		let x2 = x0 * x1;
		let x3 = x2.repeated_frobenius(2);
		let x4 = x2 * x3;
		let x = self.mul(x4);
		// TODO: the result `x` is guaranteed to have only the constant coefficient.
		// Therefore, the multiplication operation can be restricted to
		// `ext_5_add_prods0`, which is cheaper than a single multiplication in GFp5.
		let x: [F; 5] = x.to_basefield_array();
		assert!(
			(x[1].to_canonical_u64()
				| x[2].to_canonical_u64()
				| x[3].to_canonical_u64()
				| x[4].to_canonical_u64())
				== 0
		);
		x[0].legendre()
	}
}

#[cfg(test)]
mod tests {
	use rand::{RngExt, rng};

	use super::*;

	type F = GoldilocksField;
	type CP = CompressedPoint<F>;

	impl<F: Extendable<5>> PointEw<F> {
		pub(crate) fn as_arr(&self) -> [QuinticExtension<F>; 2] {
			[self.x, self.y]
		}
	}

	#[test]
	fn test_decode_encode_roundtrip() {
		// Test vectors from Pornin's reference (same as ecgfp5-p2 tests).
		let w0: CP = [0, 0, 0, 0, 0].into();
		let w1: CP = [
			12539254003028696409,
			15524144070600887654,
			15092036948424041984,
			11398871370327264211,
			10958391180505708567,
		]
		.into();
		let w2: CP = [
			11001943240060308920,
			17075173755187928434,
			3940989555384655766,
			15017795574860011099,
			5548543797011402287,
		]
		.into();
		let w3: CP = [
			246872606398642312,
			4900963247917836450,
			7327006728177203977,
			13945036888436667069,
			3062018119121328861,
		]
		.into();
		let w4: CP = [
			8058035104653144162,
			16041715455419993830,
			7448530016070824199,
			11253639182222911208,
			6228757819849640866,
		]
		.into();
		let w5: CP = [
			10523134687509281194,
			11148711503117769087,
			9056499921957594891,
			13016664454465495026,
			16494247923890248266,
		]
		.into();
		let w6: CP = [
			12173306542237620,
			6587231965341539782,
			17027985748515888117,
			17194831817613584995,
			10056734072351459010,
		]
		.into();
		let w7: CP = [
			9420857400785992333,
			4695934009314206363,
			14471922162341187302,
			13395190104221781928,
			16359223219913018041,
		]
		.into();

		// w0 decodes to point-at-infinity
		let p0 = PointEw::decode(w0.clone()).expect("w0 should decode");
		assert!(p0.at_inf, "P0 should be at infinity");
		assert_eq!(p0.encode(), w0, "encode(P0) != w0");

		// w1..w7 should all decode and round-trip
		for (i, w) in [w1, w2, w3, w4, w5, w6, w7].iter().enumerate() {
			let p =
				PointEw::decode(w.clone()).unwrap_or_else(|| panic!("w{} should decode", i + 1));
			assert!(!p.at_inf, "P{} should not be at infinity", i + 1);
			assert_eq!(
				p.encode(),
				*w,
				"encode/decode roundtrip failed for w{}",
				i + 1
			);
		}
	}

	#[test]
	fn test_decode_invalid() {
		// These values should NOT decode successfully.
		let bww: [CP; 6] = [
			[
				13557832913345268708,
				15669280705791538619,
				8534654657267986396,
				12533218303838131749,
				5058070698878426028,
			]
			.into(),
			[
				135036726621282077,
				17283229938160287622,
				13113167081889323961,
				1653240450380825271,
				520025869628727862,
			]
			.into(),
			[
				6727960962624180771,
				17240764188796091916,
				3954717247028503753,
				1002781561619501488,
				4295357288570643789,
			]
			.into(),
			[
				4578929270179684956,
				3866930513245945042,
				7662265318638150701,
				9503686272550423634,
				12241691520798116285,
			]
			.into(),
			[
				16890297404904119082,
				6169724643582733633,
				9725973298012340311,
				5977049210035183790,
				11379332130141664883,
			]
			.into(),
			[
				13777379982711219130,
				14715168412651470168,
				17942199593791635585,
				6188824164976547520,
				15461469634034461986,
			]
			.into(),
		];

		for (i, bw) in bww.into_iter().enumerate() {
			assert!(
				PointEw::decode(bw).is_none(),
				"invalid value {} was decoded",
				i
			);
		}
	}

	#[test]
	fn test_point_addition_and_doubling() {
		let w1: CP = [
			12539254003028696409,
			15524144070600887654,
			15092036948424041984,
			11398871370327264211,
			10958391180505708567,
		]
		.into();
		let w2: CP = [
			11001943240060308920,
			17075173755187928434,
			3940989555384655766,
			15017795574860011099,
			5548543797011402287,
		]
		.into();
		let w3: CP = [
			246872606398642312,
			4900963247917836450,
			7327006728177203977,
			13945036888436667069,
			3062018119121328861,
		]
		.into();
		let w4: CP = [
			8058035104653144162,
			16041715455419993830,
			7448530016070824199,
			11253639182222911208,
			6228757819849640866,
		]
		.into();
		let w5: CP = [
			10523134687509281194,
			11148711503117769087,
			9056499921957594891,
			13016664454465495026,
			16494247923890248266,
		]
		.into();
		let w6: CP = [
			12173306542237620,
			6587231965341539782,
			17027985748515888117,
			17194831817613584995,
			10056734072351459010,
		]
		.into();
		let w7: CP = [
			9420857400785992333,
			4695934009314206363,
			14471922162341187302,
			13395190104221781928,
			16359223219913018041,
		]
		.into();

		let p1 = PointEw::decode(w1).unwrap();
		let p2 = PointEw::decode(w2).unwrap();
		let p4 = PointEw::decode(w4.clone()).unwrap();
		let p5 = PointEw::decode(w5.clone()).unwrap();

		// P3 = P1 + P2
		assert_eq!(p1.add(&p2).encode(), w3, "P1 + P2 != P3");

		// P4 = 2*P1 (doubling)
		assert_eq!(p1.double().encode(), w4, "2*P1 != P4");

		// P4 = P1 + P1 (addition of same point)
		assert_eq!(p1.add(&p1).encode(), w4, "P1 + P1 != P4");

		// P5 = 2*P2
		assert_eq!(p2.double().encode(), w5, "2*P2 != P5");

		// P5 = P2 + P2
		assert_eq!(p2.add(&p2).encode(), w5, "P2 + P2 != P5");

		// P6 = 2*P1 + P2 = P4 + P2
		assert_eq!(p4.add(&p2).encode(), w6, "P4 + P2 != P6");

		// P7 = P1 + 2*P2 = P5 + P1
		assert_eq!(p5.add(&p1).encode(), w7, "P5 + P1 != P7");
	}

	#[test]
	fn test_neutral_element() {
		let w0: CP = [0, 0, 0, 0, 0].into();
		let w1: CP = [
			12539254003028696409,
			15524144070600887654,
			15092036948424041984,
			11398871370327264211,
			10958391180505708567,
		]
		.into();

		let p0 = PointEw::<F>::NEUTRAL;
		let p1 = PointEw::decode(w1.clone()).unwrap();

		// P1 + O = P1
		assert_eq!(p1.add(&p0).encode(), w1, "P1 + O != P1");

		// O + P1 = P1
		assert_eq!(p0.add(&p1).encode(), w1, "O + P1 != P1");

		// O + O = O
		assert_eq!(p0.add(&p0).encode(), w0, "O + O != O");
	}

	#[test]
	fn test_scalar_mul() {
		// From Pornin's reference: P2 = e * P1
		let w1: CP = [
			12539254003028696409,
			15524144070600887654,
			15092036948424041984,
			11398871370327264211,
			10958391180505708567,
		]
		.into();
		let w2: CP = [
			11001943240060308920,
			17075173755187928434,
			3940989555384655766,
			15017795574860011099,
			5548543797011402287,
		]
		.into();

		let p1 = PointEw::decode(w1).unwrap();

		// e = 841809598287430541331763924924406256080383779033370172527955679319982746101779529382447999363236
		let e = Scalar([
			5400142491657709732,
			15846706413025839610,
			1661266468596303141,
			17577886881415715269,
			7270009582106593884,
		]);

		assert_eq!(p1.scalar_mul(&e).encode(), w2, "e * P1 != P2");
	}

	#[test]
	fn test_scalar_mul_zero() {
		let w1: CP = [
			12539254003028696409,
			15524144070600887654,
			15092036948424041984,
			11398871370327264211,
			10958391180505708567,
		]
		.into();
		let p1 = PointEw::decode(w1).unwrap();

		// 0 * P1 = O
		let result = p1.scalar_mul(&Scalar::ZERO);
		assert!(result.at_inf, "0 * P1 should be point at infinity");
	}

	#[test]
	fn test_scalar_mul_one() {
		let w1: CP = [
			12539254003028696409,
			15524144070600887654,
			15092036948424041984,
			11398871370327264211,
			10958391180505708567,
		]
		.into();
		let p1 = PointEw::decode(w1.clone()).unwrap();

		// 1 * P1 = P1
		assert_eq!(p1.scalar_mul(&Scalar::ONE).encode(), w1, "1 * P1 != P1");
	}

	#[test]
	fn test_scalar_mul_small() {
		let w1: CP = [
			12539254003028696409,
			15524144070600887654,
			15092036948424041984,
			11398871370327264211,
			10958391180505708567,
		]
		.into();
		let w4: CP = [
			8058035104653144162,
			16041715455419993830,
			7448530016070824199,
			11253639182222911208,
			6228757819849640866,
		]
		.into();

		let p1 = PointEw::decode(w1).unwrap();

		// 2 * P1 = P4 (doubling)
		assert_eq!(
			p1.scalar_mul(&Scalar([2, 0, 0, 0, 0])).encode(),
			w4,
			"2 * P1 != P4"
		);
	}

	#[test]
	fn test_scalar_mul_neutral() {
		// e * O = O for any scalar
		let neutral = PointEw::<F>::NEUTRAL;
		let e = Scalar([
			5400142491657709732,
			15846706413025839610,
			1661266468596303141,
			17577886881415715269,
			7270009582106593884,
		]);
		let result = neutral.scalar_mul(&e);
		assert!(result.at_inf, "e * O should be point at infinity");
	}

	#[test]
	fn test_is_on_curve() {
		let mut rng = rng();
		let g = PointEw::<F>::generator();

		// Random valid points: k*G is always on the curve.
		for _ in 0..20 {
			let limbs: [u64; 5] = rng.random();
			let scalar = Scalar(limbs);
			let p = g.scalar_mul(&scalar);
			if !p.at_inf {
				assert!(p.is_on_curve(), "k*G must be on the curve");
			}
		}

		// The generator itself must be on the curve.
		assert!(g.is_on_curve(), "generator must be on the curve");

		// A point with a corrupted y-coordinate must NOT be on the curve.
		let bad = PointEw::<F> {
			x: g.x,
			y: g.y + PointEw::<F>::scalar(1),
			at_inf: false,
		};
		assert!(
			!bad.is_on_curve(),
			"corrupted point must not be on the curve"
		);
	}
}
