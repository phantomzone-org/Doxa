use std::{
	array,
	fmt::Debug,
	ops::{Add, Mul, Neg, Sub},
};

use anyhow::Result;
use itertools::{Itertools, izip};
use plonky2::{
	gates::gate::Gate,
	hash::hash_types::{HashOutTarget, RichField},
	iop::{
		generator::SimpleGenerator,
		target::{BoolTarget, Target},
		witness::{PartialWitness, WitnessWrite},
	},
	plonk::circuit_data::{CircuitConfig, CommonCircuitData},
	util::serialization::{IoResult, Read, Write},
};
use plonky2_field::{
	extension::{Extendable, FieldExtension as _, quintic::QuinticExtension},
	types::Field,
};

use crate::{
	ecgfp5::{CompressedPoint, GENERATOR, Legendre, PointEw},
	plonky2_gadgets::set_gfp5,
	schnorr::Scalar,
};

/// [x,y] coordinates of the offset point O added to the accumulator at the
/// start of the chain
pub const OFFSET: [[u64; 5]; 2] = [
	[
		2626390539619063455,
		3069873143820007175,
		16481805966921623903,
		2169403494164322467,
		15849876939764656634,
	],
	[
		8052493994140007067,
		12476750341447220703,
		7297584762312352412,
		4456043296886321460,
		17416054515469523789,
	],
];

/// [x,y] coordinates of -2^319 * O (the offset point) added to the
/// accumulator at the end of the chain
pub const OFFSET_NEG_319: [[u64; 5]; 2] = [
	[
		4290739547668160462,
		4414444320864360104,
		13341412719882091143,
		6277196213122332219,
		5576063673169056362,
	],
	[
		31345035390588453,
		16142908491486898889,
		1937863704661416826,
		5598663702127262288,
		17388813215359868465,
	],
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LocalQuinticExtension<F>(pub(crate) [F; 5]);

impl<F: Extendable<5>> From<QuinticExtension<F>> for LocalQuinticExtension<F> {
	fn from(value: QuinticExtension<F>) -> Self {
		Self(value.0)
	}
}

impl<F: Extendable<5>> From<CompressedPoint<F>> for LocalQuinticExtension<F> {
	fn from(value: CompressedPoint<F>) -> Self {
		value.w.into()
	}
}

impl<F: Field> LocalQuinticExtension<F> {
	fn lift<const D: usize>(self) -> LocalQuinticExtension<F::Extension>
	where
		F: Extendable<D>,
	{
		LocalQuinticExtension(self.0.map(|v| <F as Extendable<D>>::Extension::from(v)))
	}
}

impl<F: Field> LocalQuinticExtension<F> {
	const ONE: Self = Self([F::ONE, F::ZERO, F::ZERO, F::ZERO, F::ZERO]);
	const ZERO: Self = Self([F::ZERO; 5]);

	/// W = 3 for the Goldilocks quintic extension (x^5 - 3 is irreducible).
	fn w() -> F {
		F::from_canonical_u64(3)
	}

	fn square(&self) -> Self {
		let [a0, a1, a2, a3, a4] = self.0;
		let w = Self::w();
		let double_w = w.double();

		let c0 = a0.square() + double_w * (a1 * a4 + a2 * a3);
		let double_a0 = a0.double();
		let c1 = double_a0 * a1 + double_w * a2 * a4 + w * a3 * a3;
		let c2 = double_a0 * a2 + a1 * a1 + double_w * a4 * a3;
		let double_a1 = a1.double();
		let c3 = double_a0 * a3 + double_a1 * a2 + w * a4 * a4;
		let c4 = double_a0 * a4 + double_a1 * a3 + a2 * a2;

		Self([c0, c1, c2, c3, c4])
	}

	fn double(&self) -> Self {
		let [a0, a1, a2, a3, a4] = self.0;
		Self([a0 + a0, a1 + a1, a2 + a2, a3 + a3, a4 + a4])
	}

	// TODO: move constants from here. They don't belong here
	fn adiv3() -> LocalQuinticExtension<F> {
		// a/3 = 2/3 mod p = 6148914689804861441
		LocalQuinticExtension([
			F::from_canonical_u64(6148914689804861441),
			F::ZERO,
			F::ZERO,
			F::ZERO,
			F::ZERO,
		])
	}

	// Capital A of weistrass curve eq.
	fn cap_a() -> LocalQuinticExtension<F> {
		LocalQuinticExtension([
			F::from_canonical_u64(6148914689804861439),
			F::from_canonical_u64(263),
			F::ZERO,
			F::ZERO,
			F::ZERO,
		])
	}

	// Capital B of wistrass curve eq.
	fn cap_b() -> LocalQuinticExtension<F> {
		LocalQuinticExtension([
			F::from_canonical_u64(15713893096167979237),
			F::from_canonical_u64(6148914689804861265),
			F::ZERO,
			F::ZERO,
			F::ZERO,
		])
	}

	fn assert_equal(x: Self, y: Self) -> Vec<F> {
		izip!(x.0.into_iter(), y.0.into_iter())
			.map(|(x0, y0)| x0 - y0)
			.collect()
	}

	// Returns constraints polynomials for Po = P1 + P2
	//
	// Constriants:
	// (xo + x1 + x2) * (x2 - x1)^2 == (y2 - y1)^2 // degree 3
	// (yo + y1) * (x2 - x1) == (y2 - y1) * (x1 - xo) // degree 2
	fn add_two_points(x1: Self, y1: Self, x2: Self, y2: Self, xo: Self, yo: Self) -> Vec<F> {
		let mut constraints = vec![];
		let x2x1 = x2 - x1;
		let y2y1 = y2 - y1;
		constraints.extend(Self::assert_equal(
			(xo + x1 + x2) * x2x1.square(),
			y2y1.square(),
		));
		constraints.extend(Self::assert_equal((yo + y1) * x2x1, y2y1 * (x1 - xo)));
		constraints
	}

	// lmabda * (x2-x1) == y2-y1
	//
	// xi = lambda^2 - x1- x2 // degree = 2
	// yi = lambda (x1 - xi) - y1 // degree = 3
	//
	// (xo + xi + x3) (xi - x3)^2 == (yi - y3)^2 // degree = 6
	// (yo + y3) * (xi - x3) == (yi - y3) * (x3 - xo) // degree = 4
	fn add_three_points(
		x1: Self,
		y1: Self,
		x2: Self,
		y2: Self,
		x3: Self,
		y3: Self,
		lambda: Self,
		xo: Self,
		yo: Self,
	) -> Vec<F> {
		let mut constraints = vec![];
		let xi = lambda.square() - x1 - x2;
		let yi = (lambda * (x1 - xi)) - y1;
		let yiy3 = yi - y3;
		let xix3 = xi - x3;
		constraints.extend(Self::assert_equal(lambda * (x2 - x1), y2 - y1));
		constraints.extend(Self::assert_equal(
			(xo + xi + x3) * xix3.square(),
			yiy3.square(),
		));
		constraints.extend(Self::assert_equal((yo + y3) * xix3, yiy3 * (x3 - xo)));
		constraints
	}

	// Returns constraints for
	//      AccOut = AccIn + b0 x P1 + b1 x P2
	// where `x` op is intepreted as selection with bi as the selector bit
	fn double_acc_chain(
		accix: Self,
		acciy: Self,
		p1x: Self,
		p1y: Self,
		p2x: Self,
		p2y: Self,
		accox: Self,
		accoy: Self,
		lambda: Self,
		b0: F,
		b1: F,
	) -> Vec<F> {
		let mut constraints = vec![];
		let one = F::ONE;
		constraints.push((one - b0) * b0);
		constraints.push((one - b1) * b1);
		let s0 = (one - b0) * (one - b1);
		let s1 = b0 * (one - b1);
		let s2 = (one - b0) * b1;
		let s3 = b0 * b1;
		// case=0, AccOut = AccIn
		for i in 0..5 {
			constraints.push(s0 * (accix.0[i] - accox.0[i]));
			constraints.push(s0 * (acciy.0[i] - accoy.0[i]));
		}
		// case=1, AccOut = AccOut + P1
		//
		// AccIn = (x1,y1)
		// AccOut = (xo, yo)
		// P1 = (x2, y2)
		constraints.extend(
			Self::add_two_points(accix, acciy, p1x, p1y, accox, accoy)
				.into_iter()
				.map(|c| s1 * c),
		);
		// case=2, AccOut = AccIn + P2
		constraints.extend(
			Self::add_two_points(accix, acciy, p2x, p2y, accox, accoy)
				.into_iter()
				.map(|c| s2 * c),
		);
		// case=3, AccOut = AccIn + P1 + P2
		constraints.extend(
			Self::add_three_points(accix, acciy, p1x, p1y, p2x, p2y, lambda, accox, accoy)
				.into_iter()
				.map(|c| s3 * c),
		);
		constraints
	}

	fn p2_doubleof_p1(p1x: Self, p1y: Self, p2x: Self, p2y: Self) -> Vec<F> {
		let mut constraints = vec![];
		let three = F::from_canonical_u64(3);
		let two = F::TWO;
		let lambda_num = p1x.square() * three + LocalQuinticExtension::cap_a();
		let lambda_denom = p1y * two;
		constraints.extend(Self::assert_equal(
			(p2x + p1x + p1x) * lambda_denom.square(),
			lambda_num.square(),
		));
		let lambda_num_sq = lambda_num.square();
		let lambda_denom_sq = lambda_denom.square();
		let lambda_denom_cube = lambda_denom_sq * lambda_denom;
		constraints.extend(Self::assert_equal(
			(p2y + p1y) * lambda_denom_cube,
			(p1x * lambda_num * lambda_denom_sq * three) - lambda_num_sq * lambda_num,
		));
		constraints
	}
}

impl<F: Field> Add for LocalQuinticExtension<F> {
	type Output = Self;

	fn add(self, rhs: Self) -> Self {
		Self([
			self.0[0] + rhs.0[0],
			self.0[1] + rhs.0[1],
			self.0[2] + rhs.0[2],
			self.0[3] + rhs.0[3],
			self.0[4] + rhs.0[4],
		])
	}
}

impl<F: Field> Sub for LocalQuinticExtension<F> {
	type Output = Self;

	fn sub(self, rhs: Self) -> Self {
		Self([
			self.0[0] - rhs.0[0],
			self.0[1] - rhs.0[1],
			self.0[2] - rhs.0[2],
			self.0[3] - rhs.0[3],
			self.0[4] - rhs.0[4],
		])
	}
}

impl<F: Field> Mul for LocalQuinticExtension<F> {
	type Output = Self;

	fn mul(self, rhs: Self) -> Self {
		let [a0, a1, a2, a3, a4] = self.0;
		let [b0, b1, b2, b3, b4] = rhs.0;
		let w = Self::w();

		let c0 = a0 * b0 + w * (a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1);
		let c1 = a0 * b1 + a1 * b0 + w * (a2 * b4 + a3 * b3 + a4 * b2);
		let c2 = a0 * b2 + a1 * b1 + a2 * b0 + w * (a3 * b4 + a4 * b3);
		let c3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + w * a4 * b4;
		let c4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

		Self([c0, c1, c2, c3, c4])
	}
}

impl<F: Field> Mul<F> for LocalQuinticExtension<F> {
	type Output = Self;

	fn mul(self, rhs: F) -> Self::Output {
		Self([
			self.0[0] * rhs,
			self.0[1] * rhs,
			self.0[2] * rhs,
			self.0[3] * rhs,
			self.0[4] * rhs,
		])
	}
}

impl<F: Field> Neg for LocalQuinticExtension<F> {
	type Output = Self;

	fn neg(self) -> Self {
		Self([-self.0[0], -self.0[1], -self.0[2], -self.0[3], -self.0[4]])
	}
}

impl<F: Default> Default for LocalQuinticExtension<F> {
	fn default() -> Self {
		Self([
			F::default(),
			F::default(),
			F::default(),
			F::default(),
			F::default(),
		])
	}
}

// ---------------------------------------------------------------------------
// Circuit-level (ExtensionTarget) helpers for eval_unfiltered_circuit
// ---------------------------------------------------------------------------

/// A GFp5 element represented as 5 `ExtensionTarget<D>` components in a
/// circuit.  Mirrors `LocalQuinticExtension<F>` but for recursive constraint
/// generation.
#[derive(Clone, Copy)]
struct QET<const D: usize>([plonky2::iop::ext_target::ExtensionTarget<D>; 5]);

impl<const D: usize> QET<D> {
	fn add<F: RichField + Extendable<D>>(
		self,
		rhs: Self,
		b: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
	) -> Self {
		Self(array::from_fn(|i| b.add_extension(self.0[i], rhs.0[i])))
	}

	fn sub<F: RichField + Extendable<D>>(
		self,
		rhs: Self,
		b: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
	) -> Self {
		Self(array::from_fn(|i| b.sub_extension(self.0[i], rhs.0[i])))
	}

	/// GFp5 multiplication (W = 3, x^5 - 3 irreducible).
	fn mul<F: RichField + Extendable<D>>(
		self,
		rhs: Self,
		bldr: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
	) -> Self {
		let [a0, a1, a2, a3, a4] = self.0;
		let [b0, b1, b2, b3, b4] = rhs.0;
		// w = 3
		let w = bldr.constant_extension(F::Extension::from_basefield(F::from_canonical_u64(3)));
		// r_i = sum_{j} a_j * c_{(i-j) mod 5}  + w * ...  (standard quintic multiply)
		// Written out explicitly to avoid dependencies:
		let c0 = {
			let t0 = bldr.mul_extension(a0, b0);
			let t1 = bldr.mul_extension(a1, b4);
			let t2 = bldr.mul_extension(a2, b3);
			let t3 = bldr.mul_extension(a3, b2);
			let t4 = bldr.mul_extension(a4, b1);
			let inner = bldr.add_many_extension([t1, t2, t3, t4]);
			let w_inner = bldr.mul_extension(w, inner);
			bldr.add_extension(t0, w_inner)
		};
		let c1 = {
			let t0 = bldr.mul_extension(a0, b1);
			let t1 = bldr.mul_extension(a1, b0);
			let t2 = bldr.mul_extension(a2, b4);
			let t3 = bldr.mul_extension(a3, b3);
			let t4 = bldr.mul_extension(a4, b2);
			let inner = bldr.add_many_extension([t2, t3, t4]);
			let w_inner = bldr.mul_extension(w, inner);
			bldr.add_many_extension([t0, t1, w_inner])
		};
		let c2 = {
			let t0 = bldr.mul_extension(a0, b2);
			let t1 = bldr.mul_extension(a1, b1);
			let t2 = bldr.mul_extension(a2, b0);
			let t3 = bldr.mul_extension(a3, b4);
			let t4 = bldr.mul_extension(a4, b3);
			let inner = bldr.add_extension(t3, t4);
			let w_inner = bldr.mul_extension(w, inner);
			bldr.add_many_extension([t0, t1, t2, w_inner])
		};
		let c3 = {
			let t0 = bldr.mul_extension(a0, b3);
			let t1 = bldr.mul_extension(a1, b2);
			let t2 = bldr.mul_extension(a2, b1);
			let t3 = bldr.mul_extension(a3, b0);
			let t4 = bldr.mul_extension(a4, b4);
			let w_t4 = bldr.mul_extension(w, t4);
			bldr.add_many_extension([t0, t1, t2, t3, w_t4])
		};
		let c4 = {
			let t0 = bldr.mul_extension(a0, b4);
			let t1 = bldr.mul_extension(a1, b3);
			let t2 = bldr.mul_extension(a2, b2);
			let t3 = bldr.mul_extension(a3, b1);
			let t4 = bldr.mul_extension(a4, b0);
			bldr.add_many_extension([t0, t1, t2, t3, t4])
		};
		Self([c0, c1, c2, c3, c4])
	}

	fn square<F: RichField + Extendable<D>>(
		self,
		b: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
	) -> Self {
		self.clone().mul(self, b)
	}

	fn mul_basef<F: RichField + Extendable<D>>(
		self,
		scalar: F,
		b: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
	) -> Self {
		let s = b.constant_extension(F::Extension::from_basefield(scalar));
		Self(array::from_fn(|i| b.mul_extension(self.0[i], s)))
	}

	fn assert_equal<F: RichField + Extendable<D>>(
		x: QET<D>,
		y: QET<D>,
		b: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
	) -> Vec<plonky2::iop::ext_target::ExtensionTarget<D>> {
		(0..5).map(|i| b.sub_extension(x.0[i], y.0[i])).collect()
	}

	fn add_two_points<F: RichField + Extendable<D>>(
		x1: QET<D>,
		y1: QET<D>,
		x2: QET<D>,
		y2: QET<D>,
		xo: QET<D>,
		yo: QET<D>,
		b: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
	) -> Vec<plonky2::iop::ext_target::ExtensionTarget<D>> {
		let mut c = vec![];
		let x2x1 = x2.sub(x1, b);
		let y2y1 = y2.sub(y1, b);
		// (xo + x1 + x2) * (x2-x1)^2 == (y2-y1)^2
		let lhs = (xo.add(x1, b).add(x2, b)).mul(x2x1.square(b), b);
		let rhs = y2y1.square(b);
		c.extend(QET::assert_equal(lhs, rhs, b));
		// (yo + y1) * (x2-x1) == (y2-y1) * (x1-xo)
		let lhs2 = (yo.add(y1, b)).mul(x2x1, b);
		let rhs2 = y2y1.mul(x1.sub(xo, b), b);
		c.extend(QET::assert_equal(lhs2, rhs2, b));
		c
	}

	fn add_three_points<F: RichField + Extendable<D>>(
		x1: QET<D>,
		y1: QET<D>,
		x2: QET<D>,
		y2: QET<D>,
		x3: QET<D>,
		y3: QET<D>,
		lambda: QET<D>,
		xo: QET<D>,
		yo: QET<D>,
		b: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
	) -> Vec<plonky2::iop::ext_target::ExtensionTarget<D>> {
		let mut c = vec![];
		let xi = (lambda.square(b).sub(x1, b)).sub(x2, b);
		let yi = (lambda.mul(x1.sub(xi, b), b)).sub(y1, b);
		let yiy3 = yi.sub(y3, b);
		let xix3 = xi.sub(x3, b);
		// lambda * (x2-x1) == y2-y1
		c.extend(QET::assert_equal(
			lambda.mul(x2.sub(x1, b), b),
			y2.sub(y1, b),
			b,
		));
		// (xo + xi + x3) * (xi-x3)^2 == (yi-y3)^2
		c.extend(QET::assert_equal(
			((xo.add(xi, b)).add(x3, b)).mul(xix3.square(b), b),
			yiy3.square(b),
			b,
		));
		// (yo + y3) * (xi-x3) == (yi-y3) * (x3-xo)
		c.extend(QET::assert_equal(
			(yo.add(y3, b)).mul(xix3, b),
			yiy3.mul(x3.sub(xo, b), b),
			b,
		));
		c
	}

	fn double_acc_chain<F: RichField + Extendable<D>>(
		accix: QET<D>,
		acciy: QET<D>,
		p1x: QET<D>,
		p1y: QET<D>,
		p2x: QET<D>,
		p2y: QET<D>,
		accox: QET<D>,
		accoy: QET<D>,
		lambda: QET<D>,
		b0: plonky2::iop::ext_target::ExtensionTarget<D>,
		b1: plonky2::iop::ext_target::ExtensionTarget<D>,
		b: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
	) -> Vec<plonky2::iop::ext_target::ExtensionTarget<D>> {
		use plonky2::iop::ext_target::ExtensionTarget;
		let mut c: Vec<ExtensionTarget<D>> = vec![];
		let one = b.one_extension();

		// b0, b1 are bits
		let nb0 = b.sub_extension(one, b0);
		let nb1 = b.sub_extension(one, b1);
		c.push(b.mul_extension(nb0, b0));
		c.push(b.mul_extension(nb1, b1));

		let s0 = b.mul_extension(nb0, nb1);
		let s1 = b.mul_extension(b0, nb1);
		let s2 = b.mul_extension(nb0, b1);
		let s3 = b.mul_extension(b0, b1);

		// case=0: AccOut = AccIn
		for i in 0..5 {
			let diff_x = b.sub_extension(accix.0[i], accox.0[i]);
			let diff_y = b.sub_extension(acciy.0[i], accoy.0[i]);
			c.push(b.mul_extension(s0, diff_x));
			c.push(b.mul_extension(s0, diff_y));
		}
		// case=1: AccOut = AccIn + P1
		for con in QET::add_two_points(accix, acciy, p1x, p1y, accox, accoy, b) {
			c.push(b.mul_extension(s1, con));
		}
		// case=2: AccOut = AccIn + P2
		for con in QET::add_two_points(accix, acciy, p2x, p2y, accox, accoy, b) {
			c.push(b.mul_extension(s2, con));
		}
		// case=3: AccOut = AccIn + P1 + P2
		for con in QET::add_three_points(accix, acciy, p1x, p1y, p2x, p2y, lambda, accox, accoy, b)
		{
			c.push(b.mul_extension(s3, con));
		}
		c
	}

	fn p2_doubleof_p1<F: RichField + Extendable<D>>(
		p1x: QET<D>,
		p1y: QET<D>,
		p2x: QET<D>,
		p2y: QET<D>,
		b: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
	) -> Vec<plonky2::iop::ext_target::ExtensionTarget<D>> {
		let mut c = vec![];
		let three = F::from_canonical_u64(3);
		let two = F::TWO;

		let cap_a = QET(array::from_fn(|k| {
			b.constant_extension(F::Extension::from_basefield(
				LocalQuinticExtension::<F>::cap_a().0[k],
			))
		}));

		// lambda_num = 3 * p1x^2 + A
		let lambda_num = p1x.square(b).mul_basef(three, b).add(cap_a, b);
		// lambda_denom = 2 * p1y
		let lambda_denom = p1y.mul_basef(two, b);

		// (p2x + 2*p1x) * lambda_denom^2 == lambda_num^2
		let lhs = p2x
			.add(p1x.mul_basef(two, b), b)
			.mul(lambda_denom.square(b), b);
		let rhs = lambda_num.square(b);
		c.extend(QET::assert_equal(lhs, rhs, b));

		// (p2y + p1y) * lambda_denom^3 == 3*p1x*lambda_num*lambda_denom^2 -
		// lambda_num^3
		let ld2 = lambda_denom.square(b);
		let ld3 = ld2.mul(lambda_denom, b);
		let ln2 = lambda_num.square(b);
		let ln3 = ln2.mul(lambda_num, b);
		let lhs2 = p2y.add(p1y, b).mul(ld3, b);
		let rhs2 = p1x
			.mul(lambda_num, b)
			.mul(ld2, b)
			.mul_basef(three, b)
			.sub(ln3, b);
		c.extend(QET::assert_equal(lhs2, rhs2, b));
		c
	}
}

#[derive(Debug)]
pub(super) struct DoubleAdd4x {}

impl DoubleAdd4x {
	const DOUBLE_ACC_CHAIN_CONSTRAINT_COUNT: usize = 47;
	const DOUBLE_ACC_CHAIN_COUNT: usize = 4;
	const DOUBLING_CONSTRAINT_COUNT: usize = 2 * 5;
	const DOUBLING_COUNT: usize = 4;
	const POINT_SIZE: usize = 10;
	const SP_WIRE_OFFSET: usize = 30;

	fn new() -> Self {
		Self {}
	}
}

impl<F: RichField + Extendable<D>, const D: usize> Gate<F, D> for DoubleAdd4x {
	fn id(&self) -> String {
		format!("{self:?}")
	}

	fn num_wires(&self) -> usize {
		130
	}

	fn num_constants(&self) -> usize {
		0
	}

	fn num_constraints(&self) -> usize {
		(Self::DOUBLE_ACC_CHAIN_CONSTRAINT_COUNT * Self::DOUBLE_ACC_CHAIN_COUNT)
			+ (Self::DOUBLING_CONSTRAINT_COUNT * Self::DOUBLING_COUNT)
			+ 1 + 10
	}

	fn degree(&self) -> usize {
		// TODO: why this does not fail even when degree is set to 7
		8
	}

	fn generators(
		&self,
		row: usize,
		_local_constants: &[F],
	) -> Vec<plonky2::iop::generator::WitnessGeneratorRef<F, D>> {
		vec![plonky2::iop::generator::WitnessGeneratorRef::new(
			DoubleAdd4xGenerator {
				row,
			}
			.adapter(),
		)]
	}

	fn deserialize(
		_src: &mut plonky2::util::serialization::Buffer,
		_common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
	) -> plonky2::util::serialization::IoResult<Self>
	where
		Self: Sized,
	{
		Ok(Self {})
	}

	fn serialize(
		&self,
		_dst: &mut Vec<u8>,
		_common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
	) -> plonky2::util::serialization::IoResult<()> {
		Ok(())
	}

	fn eval_unfiltered(
		&self,
		vars: plonky2::plonk::vars::EvaluationVars<F, D>,
	) -> Vec<F::Extension> {
		let mut constraints = vec![];

		let gx = LocalQuinticExtension(array::from_fn(|i| {
			<F as Extendable<D>>::Extension::from_canonical_u64(GENERATOR[0][i])
		}));
		let gy = LocalQuinticExtension(array::from_fn(|i| {
			<F as Extendable<D>>::Extension::from_canonical_u64(GENERATOR[1][i])
		}));

		// 2^319 * -O (O = Offset point)
		let noffx = LocalQuinticExtension(array::from_fn(|i| {
			<F as Extendable<D>>::Extension::from_canonical_u64(OFFSET_NEG_319[0][i])
		}));
		let noffy = LocalQuinticExtension(array::from_fn(|i| {
			<F as Extendable<D>>::Extension::from_canonical_u64(OFFSET_NEG_319[1][i])
		}));

		// Wire layout (routable wires first for copy constraints):
		let px = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[i]));
		let py = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[5 + i]));
		let accinx = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[10 + i]));
		let acciny = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[15 + i]));
		let acco4x = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[20 + i]));
		let acco4y = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[25 + i]));
		let [sp0, sp1, sp2, sp3, _] = array::from_fn(|i| vars.local_wires[30 + i]);
		let [sg0, sg1, sg2, sg3, lgs] = array::from_fn(|i| vars.local_wires[35 + i]);
		let acco1x = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[40 + i]));
		let acco1y = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[45 + i]));
		let acco2x = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[50 + i]));
		let acco2y = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[55 + i]));
		let acco3x = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[60 + i]));
		let acco3y = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[65 + i]));
		let accdblinx = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[70 + i]));
		let accdbliny = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[75 + i]));
		let accdblo1x = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[80 + i]));
		let accdblo1y = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[85 + i]));
		let accdblo2x = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[90 + i]));
		let accdblo2y = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[95 + i]));
		let accdblo3x = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[100 + i]));
		let accdblo3y = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[105 + i]));
		let lambda1 = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[110 + i]));
		let lambda2 = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[115 + i]));
		let lambda3 = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[120 + i]));
		let lambda4 = LocalQuinticExtension(array::from_fn(|i| vars.local_wires[125 + i]));

		// AccInDbl2 = 2*AccIn
		constraints.extend(LocalQuinticExtension::p2_doubleof_p1(
			accinx, acciny, accdblinx, accdbliny,
		));
		// AccDblO1 = 2*AccO1
		constraints.extend(LocalQuinticExtension::p2_doubleof_p1(
			acco1x, acco1y, accdblo1x, accdblo1y,
		));
		constraints.extend(LocalQuinticExtension::p2_doubleof_p1(
			acco2x, acco2y, accdblo2x, accdblo2y,
		));
		// If lgs == 0, then accdblo3 = 2acco3 otherwise accdblo3 = acco3
		let nlgs = <F as Extendable<D>>::Extension::ONE - lgs;
		constraints.push(lgs * nlgs);
		constraints.extend(
			LocalQuinticExtension::p2_doubleof_p1(acco3x, acco3y, accdblo3x, accdblo3y)
				.into_iter()
				.map(|c| nlgs * c),
		);
		constraints.extend(
			LocalQuinticExtension::assert_equal(acco3x, accdblo3x)
				.into_iter()
				.chain(LocalQuinticExtension::assert_equal(acco3y, accdblo3y))
				.map(|c| lgs * c),
		);

		// AccO1 = AccDblIn + sp0 * P + sg0 G
		constraints.extend(LocalQuinticExtension::double_acc_chain(
			accdblinx, accdbliny, px, py, gx, gy, acco1x, acco1y, lambda1, sp0, sg0,
		));
		// AccO2 = AccDblO1 + sp1 * P + sg1 G
		constraints.extend(LocalQuinticExtension::double_acc_chain(
			accdblo1x, accdblo1y, px, py, gx, gy, acco2x, acco2y, lambda2, sp1, sg1,
		));
		constraints.extend(LocalQuinticExtension::double_acc_chain(
			accdblo2x, accdblo2y, px, py, gx, gy, acco3x, acco3y, lambda3, sp2, sg2,
		));

		// If lgs == 0 {
		//      p2 = g
		// }else{
		//      p2 = 2^319 * -O
		// }
		// Note: if lgs == 1 (i.e. last gate), always set sg3 = 1 and sp3 = 0. This is
		// ok, since scalar is only 319 bits
		let p2x = LocalQuinticExtension(array::from_fn(|i| nlgs * gx.0[i] + lgs * noffx.0[i]));
		let p2y = LocalQuinticExtension(array::from_fn(|i| nlgs * gy.0[i] + lgs * noffy.0[i]));
		constraints.extend(LocalQuinticExtension::double_acc_chain(
			accdblo3x, accdblo3y, px, py, p2x, p2y, acco4x, acco4y, lambda4, sp3, sg3,
		));

		constraints
	}

	fn eval_unfiltered_circuit(
		&self,
		builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
		vars: plonky2::plonk::vars::EvaluationTargets<D>,
	) -> Vec<plonky2::iop::ext_target::ExtensionTarget<D>> {
		let w = vars.local_wires;
		let qet = |base: usize| QET(array::from_fn(|i| w[base + i]));

		let gx = QET(array::from_fn(|i| {
			builder.constant_extension(<F as Extendable<D>>::Extension::from_canonical_u64(
				GENERATOR[0][i],
			))
		}));
		let gy = QET(array::from_fn(|i| {
			builder.constant_extension(<F as Extendable<D>>::Extension::from_canonical_u64(
				GENERATOR[1][i],
			))
		}));

		let noffx = QET(array::from_fn(|i| {
			builder.constant_extension(<F as Extendable<D>>::Extension::from_canonical_u64(
				OFFSET_NEG_319[0][i],
			))
		}));
		let noffy = QET(array::from_fn(|i| {
			builder.constant_extension(<F as Extendable<D>>::Extension::from_canonical_u64(
				OFFSET_NEG_319[1][i],
			))
		}));

		let px = qet(0);
		let py = qet(5);
		let accinx = qet(10);
		let acciny = qet(15);
		let acco4x = qet(20);
		let acco4y = qet(25);
		let [sp0, sp1, sp2, sp3, _]: [_; 5] = array::from_fn(|i| w[30 + i]);
		let [sg0, sg1, sg2, sg3, lgs]: [_; 5] = array::from_fn(|i| w[35 + i]);
		let acco1x = qet(40);
		let acco1y = qet(45);
		let acco2x = qet(50);
		let acco2y = qet(55);
		let acco3x = qet(60);
		let acco3y = qet(65);
		let accdblinx = qet(70);
		let accdbliny = qet(75);
		let accdblo1x = qet(80);
		let accdblo1y = qet(85);
		let accdblo2x = qet(90);
		let accdblo2y = qet(95);
		let accdblo3x = qet(100);
		let accdblo3y = qet(105);
		let lambda1 = qet(110);
		let lambda2 = qet(115);
		let lambda3 = qet(120);
		let lambda4 = qet(125);

		let mut constraints = vec![];

		constraints.extend(QET::p2_doubleof_p1(
			accinx, acciny, accdblinx, accdbliny, builder,
		));
		constraints.extend(QET::p2_doubleof_p1(
			acco1x, acco1y, accdblo1x, accdblo1y, builder,
		));
		constraints.extend(QET::p2_doubleof_p1(
			acco2x, acco2y, accdblo2x, accdblo2y, builder,
		));
		let one = builder.one_extension();
		let nlgs = builder.sub_extension(one, lgs);
		constraints.push(builder.mul_extension(nlgs, lgs));
		constraints.extend(
			QET::p2_doubleof_p1(acco3x, acco3y, accdblo3x, accdblo3y, builder)
				.into_iter()
				.map(|c| builder.mul_extension(c, nlgs)),
		);
		constraints.extend(
			QET::assert_equal(acco3x, accdblo3x, builder)
				.into_iter()
				.chain(QET::assert_equal(acco3y, accdblo3y, builder))
				.map(|c| builder.mul_extension(c, lgs)),
		);

		// AccO1 = AccDblIn + sp0 * P + sg0 G
		constraints.extend(QET::double_acc_chain(
			accdblinx, accdbliny, px, py, gx, gy, acco1x, acco1y, lambda1, sp0, sg0, builder,
		));
		// AccO2 = AccDblO1 + sp1 * P + sg1 G
		constraints.extend(QET::double_acc_chain(
			accdblo1x, accdblo1y, px, py, gx, gy, acco2x, acco2y, lambda2, sp1, sg1, builder,
		));
		constraints.extend(QET::double_acc_chain(
			accdblo2x, accdblo2y, px, py, gx, gy, acco3x, acco3y, lambda3, sp2, sg2, builder,
		));

		let p2x = QET(array::from_fn(|i| {
			let v0 = builder.mul_extension(nlgs, gx.0[i]);
			let v1 = builder.mul_extension(lgs, noffx.0[i]);
			builder.add_extension(v0, v1)
		}));
		let p2y = QET(array::from_fn(|i| {
			let v0 = builder.mul_extension(nlgs, gy.0[i]);
			let v1 = builder.mul_extension(lgs, noffy.0[i]);
			builder.add_extension(v0, v1)
		}));
		constraints.extend(QET::double_acc_chain(
			accdblo3x, accdblo3y, px, py, p2x, p2y, acco4x, acco4y, lambda4, sp3, sg3, builder,
		));

		constraints
	}
}

#[derive(Clone, Debug, Default)]
pub struct DoubleAdd4xGenerator {
	row: usize,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D> for DoubleAdd4xGenerator {
	fn id(&self) -> String {
		format!("{self:?}")
	}

	fn dependencies(&self) -> Vec<Target> {
		let mut deps: Vec<Target> = (0..34).map(|i| Target::wire(self.row, i)).collect();
		deps.extend((35..130).map(|i| Target::wire(self.row, i)));
		deps
	}

	fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
		dst.write_usize(self.row)
	}

	fn deserialize(
		src: &mut plonky2::util::serialization::Buffer,
		_common_data: &CommonCircuitData<F, D>,
	) -> IoResult<Self>
	where
		Self: Sized,
	{
		let row = src.read_usize()?;
		Ok(Self {
			row,
		})
	}

	fn run_once(
		&self,
		_witness: &plonky2::iop::witness::PartitionWitness<F>,
		_out_buffer: &mut plonky2::iop::generator::GeneratedValues<F>,
	) -> Result<()> {
		Ok(())
	}
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct LocalPointEw {
	pub(crate) x: LocalQuinticExtension<Target>,
	pub(crate) y: LocalQuinticExtension<Target>,
}

/// All witness targets for a single DoubleAdd4x instance.
#[derive(Clone)]
pub(crate) struct DoubleAdd4xTargets {
	pub(crate) p: LocalPointEw,
	pub(crate) accin: LocalPointEw,
	pub(crate) acco4: LocalPointEw,
	pub(crate) sp: [Target; 4],
	pub(crate) sg: [Target; 4],
	// last gate selector
	pub(crate) lgs: Target,
	pub(crate) acco1: LocalPointEw,
	pub(crate) acco2: LocalPointEw,
	pub(crate) acco3: LocalPointEw,
	pub(crate) accdblin: LocalPointEw,
	pub(crate) accdblo1: LocalPointEw,
	pub(crate) accdblo2: LocalPointEw,
	pub(crate) accdblo3: LocalPointEw,
	pub(crate) lambda1: LocalQuinticExtension<Target>,
	pub(crate) lambda2: LocalQuinticExtension<Target>,
	pub(crate) lambda3: LocalQuinticExtension<Target>,
	pub(crate) lambda4: LocalQuinticExtension<Target>,
}

impl DoubleAdd4xTargets {
	/// Build targets for all wires of a SigGate1 at the given circuit row.
	pub(crate) fn from_row(row: usize) -> Self {
		let point = |base: usize| LocalPointEw {
			x: LocalQuinticExtension(array::from_fn(|j| Target::wire(row, base + j))),
			y: LocalQuinticExtension(array::from_fn(|j| Target::wire(row, base + 5 + j))),
		};
		DoubleAdd4xTargets {
			p: point(0),
			accin: point(10),
			acco4: point(20),
			sp: array::from_fn(|j| Target::wire(row, 30 + j)),
			sg: array::from_fn(|j| Target::wire(row, 35 + j)),
			lgs: Target::wire(row, 39),
			acco1: point(40),
			acco2: point(50),
			acco3: point(60),
			accdblin: point(70),
			accdblo1: point(80),
			accdblo2: point(90),
			accdblo3: point(100),
			lambda1: LocalQuinticExtension(array::from_fn(|j| Target::wire(row, 110 + j))),
			lambda2: LocalQuinticExtension(array::from_fn(|j| Target::wire(row, 115 + j))),
			lambda3: LocalQuinticExtension(array::from_fn(|j| Target::wire(row, 120 + j))),
			lambda4: LocalQuinticExtension(array::from_fn(|j| Target::wire(row, 125 + j))),
		}
	}
}

#[derive(Debug, Clone, Copy)]
/// Checks w is compressed Point(x,y) and Point(x,y) is on the ecgfp5 curve. Check is applied when
/// selector is set to 1.
///
/// Accomodates `num_ops` instances in a row
pub(super) struct CompressionGate {
	num_ops: usize,
}

impl CompressionGate {
	fn new_from_config(config: &CircuitConfig) -> Self {
		let wires_per_op = 15;
		Self {
			num_ops: config.num_routed_wires / wires_per_op,
		}
	}

	fn wire_ith_w_offset(i: usize) -> usize {
		i * 16
	}

	fn wire_ith_x_offset(i: usize) -> usize {
		i * 16 + 5
	}

	fn wire_ith_y_offset(i: usize) -> usize {
		i * 16 + 10
	}

	fn wire_ith_isactive_offset(i: usize) -> usize {
		i * 16 + 15
	}
}

impl<F: RichField + Extendable<D>, const D: usize> Gate<F, D> for CompressionGate {
	fn id(&self) -> String {
		format!("{self:?}")
	}

	fn num_wires(&self) -> usize {
		self.num_ops * 15
	}

	fn num_constants(&self) -> usize {
		0
	}

	fn num_constraints(&self) -> usize {
		5 * (2 * self.num_ops)
	}

	fn degree(&self) -> usize {
		3
	}

	fn generators(
		&self,
		row: usize,
		_local_constants: &[F],
	) -> Vec<plonky2::iop::generator::WitnessGeneratorRef<F, D>> {
		(0..self.num_ops)
			.map(|i| {
				plonky2::iop::generator::WitnessGeneratorRef::new(
					CompressionGateGenerator {
						row,
						i,
					}
					.adapter(),
				)
			})
			.collect_vec()
	}

	fn deserialize(
		src: &mut plonky2::util::serialization::Buffer,
		_common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
	) -> plonky2::util::serialization::IoResult<Self>
	where
		Self: Sized,
	{
		let num_ops = src.read_usize()?;
		Ok(Self {
			num_ops,
		})
	}

	fn serialize(
		&self,
		dst: &mut Vec<u8>,
		_common_data: &plonky2::plonk::circuit_data::CommonCircuitData<F, D>,
	) -> plonky2::util::serialization::IoResult<()> {
		dst.write_usize(self.num_ops)
	}

	fn eval_unfiltered(
		&self,
		vars: plonky2::plonk::vars::EvaluationVars<F, D>,
	) -> Vec<F::Extension> {
		let mut constraints = vec![];

		let adiv3 = LocalQuinticExtension::adiv3();
		let capa = LocalQuinticExtension::cap_a();
		let capb = LocalQuinticExtension::cap_b();

		for j in 0..self.num_ops {
			let isactive = vars.local_wires[Self::wire_ith_isactive_offset(j)];
			let w = LocalQuinticExtension(array::from_fn(|i| {
				vars.local_wires[Self::wire_ith_w_offset(j) + i]
			}));
			let x = LocalQuinticExtension(array::from_fn(|i| {
				vars.local_wires[Self::wire_ith_x_offset(j) + i]
			}));
			let y = LocalQuinticExtension(array::from_fn(|i| {
				vars.local_wires[Self::wire_ith_y_offset(j) + i]
			}));

			// compression constraint
			constraints.extend(LocalQuinticExtension::assert_equal(w * (adiv3 - x), y));
			// is on curve constraint
			constraints.extend(LocalQuinticExtension::assert_equal(
				x.square() * x + (capa * x + capb) * isactive,
				y.square(),
			));
		}

		constraints
	}

	fn eval_unfiltered_circuit(
		&self,
		builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
		vars: plonky2::plonk::vars::EvaluationTargets<D>,
	) -> Vec<plonky2::iop::ext_target::ExtensionTarget<D>> {
		let mut c = vec![];

		let adiv3f = LocalQuinticExtension::adiv3();
		let adiv3 = QET(array::from_fn(|i| builder.constant_extension(adiv3f.0[i])));
		let capaf = LocalQuinticExtension::cap_a();
		let capa = QET(array::from_fn(|i| builder.constant_extension(capaf.0[i])));
		let capbf = LocalQuinticExtension::cap_b();
		let capb = QET(array::from_fn(|i| builder.constant_extension(capbf.0[i])));

		for j in 0..self.num_ops {
			let isactv = vars.local_wires[Self::wire_ith_isactive_offset(j)];
			let w = QET(array::from_fn(|i| {
				vars.local_wires[Self::wire_ith_w_offset(j) + i]
			}));
			let x = QET(array::from_fn(|i| {
				vars.local_wires[Self::wire_ith_x_offset(j) + i]
			}));
			let y = QET(array::from_fn(|i| {
				vars.local_wires[Self::wire_ith_y_offset(j) + i]
			}));

			c.extend(QET::assert_equal(
				w.mul(adiv3.sub(x, builder), builder),
				y,
				builder,
			));
			let x3 = x.square(builder).mul(x, builder);
			let capax = capa.mul(x, builder);
			let capax_capb = QET((capax.add(capb, builder))
				.0
				.map(|v| builder.mul_extension(isactv, v)));
			c.extend(QET::assert_equal(
				x3.add(capax_capb, builder),
				y.square(builder),
				builder,
			));
		}

		c
	}
}

#[derive(Clone, Debug, Default)]
pub struct CompressionGateGenerator {
	row: usize,
	i: usize,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
	for CompressionGateGenerator
{
	fn id(&self) -> String {
		format!("{self:?}")
	}

	fn dependencies(&self) -> Vec<Target> {
		(CompressionGate::wire_ith_w_offset(self.i)..CompressionGate::wire_ith_w_offset(self.i) + 5)
			.chain(
				CompressionGate::wire_ith_x_offset(self.i)
					..CompressionGate::wire_ith_x_offset(self.i) + 5,
			)
			.chain(
				CompressionGate::wire_ith_y_offset(self.i)
					..CompressionGate::wire_ith_y_offset(self.i) + 5,
			)
			.map(|i| Target::wire(self.row, i))
			.collect_vec()
	}

	fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
		dst.write_usize(self.row)?;
		dst.write_usize(self.i)
	}

	fn deserialize(
		src: &mut plonky2::util::serialization::Buffer,
		_common_data: &CommonCircuitData<F, D>,
	) -> IoResult<Self>
	where
		Self: Sized,
	{
		let row = src.read_usize()?;
		let i = src.read_usize()?;
		Ok(Self {
			row,
			i,
		})
	}

	fn run_once(
		&self,
		_witness: &plonky2::iop::witness::PartitionWitness<F>,
		_out_buffer: &mut plonky2::iop::generator::GeneratedValues<F>,
	) -> Result<()> {
		Ok(())
	}
}

#[derive(Clone)]
pub(crate) struct SchnorrTargets {
	/// Compressed R
	pub(crate) cr: [Target; 5],
	/// Per-gate targets for each of the 80 DoubleAdd4x instances
	pub(crate) da4x: Box<[DoubleAdd4xTargets; 80]>,
}

#[derive(Clone, Copy)]
// TODO: why this is abstract over F, when F always equals Target
pub(crate) struct PubkeyTarget(pub(crate) LocalQuinticExtension<Target>);

impl PubkeyTarget {
	pub(crate) fn set_witness<F: Field + Extendable<5>>(
		&self,
		pw: &mut PartialWitness<F>,
		cpk: &crate::schnorr::CompressedPublicKey<F>,
	) {
		for (t, v) in self.0.0.iter().zip(cpk.0.w.0.iter()) {
			pw.set_target(*t, *v).unwrap();
		}
	}
}

/// Build a Schnorr signature verification circuit.
///
/// Verifies `R = sG + eQ` where `e = DropTop2Bits(H(w_R || w_Q || m))`.
pub(crate) fn conditional_schnorr_verify_gadget<F: RichField + Extendable<D>, const D: usize>(
	builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
	message: HashOutTarget,
	pubkey: PubkeyTarget,
	apply_check: BoolTarget,
) -> SchnorrTargets {
	use plonky2::{hash::poseidon::PoseidonHash, iop::target::BoolTarget};

	// Q point
	let qx: [Target; 5] = array::from_fn(|_| builder.add_virtual_target());
	let qy: [Target; 5] = array::from_fn(|_| builder.add_virtual_target());

	// Add 80 DoubleAdd4x gates
	let mut da4x_rows = [usize::default(); 80];
	for i in 0..80 {
		let gate = DoubleAdd4x::new();
		da4x_rows[i] = builder.add_gate(gate, vec![]);
	}

	// Build per-gate targets from wire offsets (matching eval_unfiltered layout).
	let sig_gates: Box<[DoubleAdd4xTargets; 80]> = Box::new(array::from_fn(|i| {
		DoubleAdd4xTargets::from_row(da4x_rows[i])
	}));

	{
		for i in 0..80 - 1 {
			// AccO4[i] == AccIn[i+1]
			for j in 0..5 {
				builder.connect(sig_gates[i].acco4.x.0[j], sig_gates[i + 1].accin.x.0[j]);
				builder.connect(sig_gates[i].acco4.y.0[j], sig_gates[i + 1].accin.y.0[j]);
			}
		}

		// P == Q
		for i in 0..80 {
			for j in 0..5 {
				builder.connect(sig_gates[i].p.x.0[j], qx[j]);
				builder.connect(sig_gates[i].p.y.0[j], qy[j]);
			}
		}

		// Set AccIn of 0^th DoubleAdd4x to acc OFFSET point
		for j in 0..5 {
			let cx = builder.constant(F::from_canonical_u64(OFFSET[0][j]));
			let cy = builder.constant(F::from_canonical_u64(OFFSET[1][j]));
			builder.connect(cx, sig_gates[0].accin.x.0[j]);
			builder.connect(cy, sig_gates[0].accin.y.0[j]);
		}
	}

	// R point: AccOut4
	let rx: [Target; 5] = array::from_fn(|i| sig_gates[79].acco4.x.0[i]);
	let ry: [Target; 5] = array::from_fn(|i| sig_gates[79].acco4.y.0[i]);

	// Compression and curve check //
	let cg_kind = CompressionGate::new_from_config(&builder.config);

	// check cr is indeed compressed R = (rx, ry)
	// check R is indeed a point on the curve
	let (cg_r_row, cg_r_pos) = builder.find_slot(cg_kind, &vec![], &vec![]);
	let acvtr = Target::wire(
		cg_r_row,
		CompressionGate::wire_ith_isactive_offset(cg_r_pos),
	);
	builder.assert_one(acvtr);
	let cr: [Target; 5] = array::from_fn(|i| {
		Target::wire(cg_r_row, CompressionGate::wire_ith_w_offset(cg_r_pos) + i)
	});
	for i in 0..5 {
		builder.connect(
			rx[i],
			Target::wire(cg_r_row, CompressionGate::wire_ith_x_offset(cg_r_pos) + i),
		);

		builder.connect(
			ry[i],
			Target::wire(cg_r_row, CompressionGate::wire_ith_y_offset(cg_r_pos) + i),
		);
	}

	// check cq is compressed point Q
	let (cg_q_row, cg_q_pos) = builder.find_slot(cg_kind, &vec![], &vec![]);
	let acvtq = Target::wire(
		cg_q_row,
		CompressionGate::wire_ith_isactive_offset(cg_q_pos),
	);
	builder.assert_one(acvtq);
	let cq: [Target; 5] = array::from_fn(|i| {
		Target::wire(cg_q_row, CompressionGate::wire_ith_w_offset(cg_q_pos) + i)
	});
	for i in 0..5 {
		builder.connect(
			qx[i],
			Target::wire(cg_q_row, CompressionGate::wire_ith_x_offset(cg_q_pos) + i),
		);

		builder.connect(
			qy[i],
			Target::wire(cg_q_row, CompressionGate::wire_ith_y_offset(cg_q_pos) + i),
		);
	}
	// cq must equal compressed public key
	builder.connect_array(cq, pubkey.0.0);

	// Poseidon hash of w_R || w_Q || m //
	let mut hash_input = Vec::with_capacity(14);
	hash_input.extend_from_slice(&cr);
	hash_input.extend_from_slice(&cq);
	hash_input.extend_from_slice(&message.elements);

	// 14 inputs, 5 outputs => 2 Poseidon permutations
	let e_hash: Vec<Target> = builder.hash_n_to_m_no_pad::<PoseidonHash>(hash_input, 5);

	// e' == e equivalence check (with top 2 bits dropped)

	// Reconstruct each 64-bit limb from the bits and connect to e_hash.
	//
	// Note: Can the prover really do something by setting sp3, sg3 at row 79 to
	// anything other than 0,1 resp.? Don't think so, since prover does not constrol
	// P, G, and OFFSET
	let mut all_e_bits: Vec<Target> = (1..320)
		.map(|i| {
			Target::wire(
				da4x_rows[79 - (i / 4)],
				DoubleAdd4x::SP_WIRE_OFFSET + 3 - (i % 4),
			)
		})
		.collect();
	// TODO: we don't check e[318] == 0 as it's expect from our hash to scalar map.
	// Should be check?
	all_e_bits.push(builder.zero());

	// TODO: how does the thing below compare with a custom gate to check e == e'?
	let two_pow_32 = builder.constant(F::from_canonical_u64(1u64 << 32));
	for k in 0..5 {
		let start = 64 * k;
		let lo_bits = all_e_bits[start..start + 32]
			.iter()
			.map(|&t| BoolTarget::new_unsafe(t));
		let hi_bits = all_e_bits[start + 32..start + 32 + 32]
			.iter()
			.map(|&t| BoolTarget::new_unsafe(t));
		let lo = builder.le_sum(lo_bits);
		let hi = builder.le_sum(hi_bits);
		let reconstructed = builder.mul_add(two_pow_32, hi, lo);

		if k < 4 {
			builder.conditional_assert_eq(apply_check.target, reconstructed, e_hash[k]);
		} else {
			// Limb 4: e_hash[4] may have top 2 bits set.
			// Constrain (e_hash[4] - reconstructed) * (e_hash[4] - reconstructed
			// - 2^62)         //         * (e_hash[4] - reconstructed - 2^63) *
			// (e_hash[4] - reconstructed -         //           3*2^62) = 0
			let diff = builder.sub(e_hash[4], reconstructed);
			let c1 = builder.constant(F::from_canonical_u64(1u64 << 62));
			let c2 = builder.constant(F::from_canonical_u64(1u64 << 63));
			let c3 = builder.constant(F::from_canonical_u64(3u64 << 62));
			let d0 = diff;
			let d1 = builder.sub(diff, c1);
			let d2 = builder.sub(diff, c2);
			let d3 = builder.sub(diff, c3);
			let p01 = builder.mul(d0, d1);
			let p23 = builder.mul(d2, d3);
			let product = builder.mul(p01, p23);
			// hack to print total rows occupied by the gadget
			// match product {
			//     Target::Wire(w) => {
			//         dbg!(w.row);
			//     }
			//     _ => {}
			// }
			let cond = builder.mul(apply_check.target, product);
			builder.assert_zero(cond);
		}
	}

	SchnorrTargets {
		cr,
		da4x: sig_gates,
	}
}

struct DoubleAdd4xGateWitness<F: RichField + Extendable<5>> {
	accdblin: PointEw<F>,
	acco1: PointEw<F>,
	accdblo1: PointEw<F>,
	acco2: PointEw<F>,
	accdblo2: PointEw<F>,
	acco3: PointEw<F>,
	accdblo3: PointEw<F>,
	acco4: PointEw<F>,
	lambda1: QuinticExtension<F>,
	lambda2: QuinticExtension<F>,
	lambda3: QuinticExtension<F>,
	lambda4: QuinticExtension<F>,
}

fn compute_gate_witness<F: RichField + Extendable<5>>(
	sp: [F; 4],
	sg: [F; 4],
	p: PointEw<F>,
	accin: PointEw<F>,
	is_last: bool,
) -> DoubleAdd4xGateWitness<F> {
	let g = PointEw::generator();
	let neg_off = PointEw::from(OFFSET_NEG_319);
	if is_last {
		assert!(sp[3] == F::ZERO && sg[3] == F::ONE);
	}

	let step = |acc: PointEw<F>,
	            spi: F,
	            sgi: F,
	            index: usize|
	 -> (PointEw<F>, PointEw<F>, QuinticExtension<F>) {
		let accdbl = if is_last && index == 3 {
			acc
		} else {
			acc.double()
		};
		let p2 = if is_last && index == 3 { neg_off } else { g };
		let lambda = accdbl.tangent(&p);

		let acco = match (spi.is_one(), sgi.is_one()) {
			(false, false) => accdbl,
			(true, false) => accdbl.add(&p),
			(false, true) => accdbl.add(&p2),
			(true, true) => accdbl.add(&p).add(&p2),
		};

		(accdbl, acco, lambda)
	};

	let (accdbl, acco1, lambda1) = step(accin, sp[0], sg[0], 0);
	let (accdblo1, acco2, lambda2) = step(acco1, sp[1], sg[1], 1);
	let (accdblo2, acco3, lambda3) = step(acco2, sp[2], sg[2], 2);
	let (accdblo3, acco4, lambda4) = step(acco3, sp[3], sg[3], 3);

	DoubleAdd4xGateWitness {
		accdblin: accdbl,
		acco1,
		accdblo1,
		acco2,
		accdblo2,
		acco3,
		accdblo3,
		acco4,
		lambda1,
		lambda2,
		lambda3,
		lambda4,
	}
}

pub(crate) fn set_schnorr_witness<F: RichField + Legendre + Extendable<5>>(
	pw: &mut PartialWitness<F>,
	targets: &SchnorrTargets,
	q: PointEw<F>,
	cr: CompressedPoint<F>,
	e: Scalar,
	s: Scalar,
) {
	set_gfp5(pw, targets.cr, cr.w.0);

	let mut e_bits = e.to_bit_arr();
	let mut s_bits = s.to_bit_arr();
	e_bits.reverse();
	s_bits.reverse();

	let mut accin: PointEw<F> = OFFSET.into();
	for gate_idx in 0..80usize {
		let gate_targets = &targets.da4x[gate_idx];

		let sp: [F; 4] = array::from_fn(|k| {
			let bit_idx = 4 * gate_idx + k;
			if bit_idx < 319 {
				if e_bits[bit_idx] { F::ONE } else { F::ZERO }
			} else {
				F::ZERO
			}
		});
		let sg: [F; 4] = array::from_fn(|k| {
			let bit_idx = 4 * gate_idx + k;
			if bit_idx < 319 {
				if s_bits[bit_idx] { F::ONE } else { F::ZERO }
			} else {
				F::ONE
			}
		});

		let w = compute_gate_witness(sp, sg, q, accin, gate_idx == 79);
		set_dbladd4x_gate_witness(pw, gate_targets, q, accin, sp, sg, gate_idx == 79, &w);
		accin = w.acco4;
	}
	assert_eq!(accin.encode(), cr);
}

fn set_dbladd4x_gate_witness<F: RichField + Extendable<5>>(
	pw: &mut PartialWitness<F>,
	t: &DoubleAdd4xTargets,
	p: PointEw<F>,
	accin: PointEw<F>,
	sp: [F; 4],
	sg: [F; 4],
	lgs: bool,
	w: &DoubleAdd4xGateWitness<F>,
) {
	let lgs = if lgs { F::ONE } else { F::ZERO };
	set_gfp5(pw, t.p.x.0, p.x.0);
	set_gfp5(pw, t.p.y.0, p.y.0);
	set_gfp5(pw, t.accin.x.0, accin.x.0);
	set_gfp5(pw, t.accin.y.0, accin.y.0);
	set_gfp5(pw, t.acco4.x.0, w.acco4.x.0);
	set_gfp5(pw, t.acco4.y.0, w.acco4.y.0);
	izip!(t.sp.iter(), sp.iter()).for_each(|(&tgt, &v)| pw.set_target(tgt, v).unwrap());
	izip!(t.sg.iter(), sg.iter()).for_each(|(&tgt, &v)| pw.set_target(tgt, v).unwrap());
	pw.set_target(t.lgs, lgs).unwrap();
	set_gfp5(pw, t.acco1.x.0, w.acco1.x.0);
	set_gfp5(pw, t.acco1.y.0, w.acco1.y.0);
	set_gfp5(pw, t.acco2.x.0, w.acco2.x.0);
	set_gfp5(pw, t.acco2.y.0, w.acco2.y.0);
	set_gfp5(pw, t.acco3.x.0, w.acco3.x.0);
	set_gfp5(pw, t.acco3.y.0, w.acco3.y.0);
	set_gfp5(pw, t.accdblin.x.0, w.accdblin.x.0);
	set_gfp5(pw, t.accdblin.y.0, w.accdblin.y.0);
	set_gfp5(pw, t.accdblo1.x.0, w.accdblo1.x.0);
	set_gfp5(pw, t.accdblo1.y.0, w.accdblo1.y.0);
	set_gfp5(pw, t.accdblo2.x.0, w.accdblo2.x.0);
	set_gfp5(pw, t.accdblo2.y.0, w.accdblo2.y.0);
	set_gfp5(pw, t.accdblo3.x.0, w.accdblo3.x.0);
	set_gfp5(pw, t.accdblo3.y.0, w.accdblo3.y.0);
	set_gfp5(pw, t.lambda1.0, w.lambda1.0);
	set_gfp5(pw, t.lambda2.0, w.lambda2.0);
	set_gfp5(pw, t.lambda3.0, w.lambda3.0);
	set_gfp5(pw, t.lambda4.0, w.lambda4.0);
}

#[cfg(test)]
mod tests {
	use plonky2::{
		gates::gate_testing::{test_eval_fns, test_low_degree},
		hash::{hashing::hash_n_to_m_no_pad, poseidon::PoseidonHash},
		iop::witness::PartialWitness,
		plonk::{
			circuit_builder::CircuitBuilder,
			circuit_data::CircuitConfig,
			config::{GenericConfig, Hasher, PoseidonGoldilocksConfig},
		},
	};
	use plonky2_field::goldilocks_field::GoldilocksField;
	use rand::{RngExt, rng};

	use super::*;
	use crate::{
		ecgfp5::{CompressedPoint, PointEw},
		plonky2_gadgets::tests::print_common_data,
		schnorr::{PrivateKey, Scalar, schnorr_sign},
		time,
	};

	const D: usize = 2;
	type C = PoseidonGoldilocksConfig;
	type F = <C as GenericConfig<D>>::F;

	#[test]
	fn doubleadd4x_low_degree() {
		test_low_degree::<GoldilocksField, _, 2>(DoubleAdd4x::new());
	}

	#[test]
	fn doubleadd4x_eval_fns() {
		test_eval_fns::<GoldilocksField, C, _, D>(DoubleAdd4x::new())
			.expect("DoubleAdd4x eval_fns failed");
	}

	#[test]
	fn compressiongate_eval_fns() {
		test_eval_fns::<GoldilocksField, C, _, D>(CompressionGate::new_from_config(
			&CircuitConfig::standard_recursion_config(),
		))
		.expect("CompressionGate eval_fns failed");
	}

	#[test]
	fn test_compression_gate() {
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);

		let cg_kind = CompressionGate::new_from_config(&builder.config);
		let (cg_row, cg_pos) = builder.find_slot(cg_kind, &vec![], &vec![]);
		let cp: [Target; 5] = array::from_fn(|i| {
			Target::wire(cg_row, CompressionGate::wire_ith_w_offset(cg_pos) + i)
		});
		let px: [Target; 5] = array::from_fn(|i| {
			Target::wire(cg_row, CompressionGate::wire_ith_x_offset(cg_pos) + i)
		});
		let py: [Target; 5] = array::from_fn(|i| {
			Target::wire(cg_row, CompressionGate::wire_ith_y_offset(cg_pos) + i)
		});
		let actv0 = Target::wire(cg_row, CompressionGate::wire_ith_isactive_offset(0));
		builder.assert_one(actv0);
		let data = builder.build::<C>();

		// k*G
		let k = Scalar::from_raw([
			12539254003028696409,
			15524144070600887654,
			15092036948424041984,
			11398871370327264211,
			958391180505708567,
		]);
		let p = PointEw::generator().scalar_mul(&k);
		assert!(p.is_on_curve());

		let mut pw = PartialWitness::new();
		set_gfp5(&mut pw, cp, p.encode().w.0);
		set_gfp5(&mut pw, px, p.x.0);
		set_gfp5(&mut pw, py, p.y.0);
		pw.set_target(actv0, F::ONE).unwrap();

		let proof = data.prove(pw).expect("proof generation failed");
		data.verify(proof).expect("verification failed");
	}

	/// Helper to build and prove a single DoubleAdd4x gate with given selector bits for
	/// fixed P
	fn prove_single_gate(sp: [GoldilocksField; 4], sg: [GoldilocksField; 4]) {
		const D: usize = 2;
		type C = PoseidonGoldilocksConfig;
		type F = <C as GenericConfig<D>>::F;

		let w0: CompressedPoint<F> = [
			12539254003028696409,
			15524144070600887654,
			15092036948424041984,
			11398871370327264211,
			10958391180505708567,
		]
		.into();

		let p1 = PointEw::decode(w0).unwrap();
		let offset: CompressedPoint<F> = [
			11001943240060308920,
			17075173755187928434,
			3940989555384655766,
			15017795574860011099,
			5548543797011402287,
		]
		.into();
		let accin = PointEw::decode(offset).unwrap();
		let w = compute_gate_witness(sp, sg, p1, accin, false);

		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let row = builder.add_gate(DoubleAdd4x::new(), vec![]);
		let gate_targets = DoubleAdd4xTargets::from_row(row);
		let data = builder.build::<C>();

		let mut pw = PartialWitness::new();
		set_dbladd4x_gate_witness(&mut pw, &gate_targets, p1, accin, sp, sg, false, &w);

		let proof = data.prove(pw).expect("proof generation failed");
		data.verify(proof).expect("verification failed");
	}

	#[test]
	fn doubleadd4x_prove_multi_random() {
		type F = GoldilocksField;
		let mut rng = rng();
		for _ in 0..10 {
			let sp: [F; 4] = array::from_fn(|_| F::from_canonical_u64(rng.random_bool(0.5) as u64));
			let sg: [F; 4] = array::from_fn(|_| F::from_canonical_u64(rng.random_bool(0.5) as u64));
			prove_single_gate(sp, sg);
		}
	}

	#[test]
	fn doubleadd4x_prove_case0() {
		type F = GoldilocksField;
		prove_single_gate([F::ZERO; 4], [F::ZERO; 4]);
	}

	#[test]
	fn doubleadd4x_prove_case1() {
		type F = GoldilocksField;
		prove_single_gate([F::ONE, F::ZERO, F::ZERO, F::ZERO], [F::ZERO; 4]);
	}

	#[test]
	fn doubleadd4x_recursive_verify() {
		// Build and prove the inner circuit (single SigGate1, all-zero selectors).
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config.clone());
		let row = builder.add_gate(DoubleAdd4x::new(), vec![]);
		let gate_targets = DoubleAdd4xTargets::from_row(row);
		let inner_data = time!("inner build", builder.build::<C>());
		print_common_data(&inner_data.common, "inner common data");

		let w0: CompressedPoint<F> = [
			12539254003028696409,
			15524144070600887654,
			15092036948424041984,
			11398871370327264211,
			10958391180505708567,
		]
		.into();
		let p1 = PointEw::decode(w0).unwrap();
		let accin: PointEw<_> = OFFSET.into();
		let sp = [F::ONE; 4];
		let sg = [F::ZERO; 4];
		let w = compute_gate_witness(sp, sg, p1, accin, false);

		let mut inner_pw = PartialWitness::new();
		set_dbladd4x_gate_witness(&mut inner_pw, &gate_targets, p1, accin, sp, sg, false, &w);
		let inner_proof = time!(
			"inner prove",
			inner_data.prove(inner_pw).expect("inner proof failed")
		);
		time!(
			"inner verify",
			inner_data
				.verify(inner_proof.clone())
				.expect("inner verify failed")
		);

		// Build the outer (recursive) circuit that verifies the inner proof.
		let mut rec_builder =
			CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
		let proof_target = rec_builder.add_virtual_proof_with_pis(&inner_data.common);
		let verifier_target =
			rec_builder.add_virtual_verifier_data(inner_data.common.config.fri_config.cap_height);
		rec_builder.verify_proof::<C>(&proof_target, &verifier_target, &inner_data.common);
		let rec_data = time!("rec build", rec_builder.build::<C>());
		print_common_data(&rec_data.common, "rec common data");

		// Set the recursive witness.
		let mut rec_pw = PartialWitness::new();
		rec_pw
			.set_proof_with_pis_target(&proof_target, &inner_proof)
			.unwrap();
		rec_pw
			.set_cap_target(
				&verifier_target.constants_sigmas_cap,
				&inner_data.verifier_only.constants_sigmas_cap,
			)
			.unwrap();
		rec_pw
			.set_hash_target(
				verifier_target.circuit_digest,
				inner_data.verifier_only.circuit_digest,
			)
			.unwrap();

		let rec_proof = time!(
			"rec prove",
			rec_data.prove(rec_pw).expect("recursive proof failed")
		);
		time!(
			"rec verify",
			rec_data.verify(rec_proof).expect("recursive verify failed")
		);
	}

	#[test]
	fn test_schnorr_verify_gadget() {
		// Generate keys and sign
		let d = Scalar::from_raw([
			5400142491657709732,
			15846706413025839610,
			1661266468596303141,
			17577886881415715269,
			7270009582106593884,
		]);
		let privkey = PrivateKey::new(d);
		let pubkey = privkey.public_key::<F>();
		let q = pubkey.as_point();

		let message: [F; 4] = [
			F::from_canonical_u64(1),
			F::from_canonical_u64(2),
			F::from_canonical_u64(3),
			F::from_canonical_u64(4),
		];

		let k = Scalar::from_raw([
			12539254003028696409,
			15524144070600887654,
			15092036948424041984,
			11398871370327264211,
			958391180505708567,
		]);
		let sig = schnorr_sign(&privkey, &message, k);
		let r = sig.r;
		let s = sig.s;

		// Compute e from hash (same as schnorr_sign does)
		let cr = r.encode();
		let cq = q.encode();
		let mut hash_input = Vec::new();
		hash_input.extend_from_slice(&cr.w.0);
		hash_input.extend_from_slice(&cq.w.0);
		hash_input.extend_from_slice(&message);

		let hash_out =
			hash_n_to_m_no_pad::<F, <PoseidonHash as Hasher<F>>::Permutation>(&hash_input, 5);

		let e = Scalar::from_hash([
			hash_out[0],
			hash_out[1],
			hash_out[2],
			hash_out[3],
			hash_out[4],
		]);

		// Verify natively: sG + eQ = R
		let g = PointEw::<F>::generator();
		let sg = g.scalar_mul(&s);
		let eq = q.scalar_mul(&e);
		let result = sg.add(&eq);
		assert_eq!(result.encode(), r.encode(), "native verification failed");

		// Build inner circuit
		let config = CircuitConfig::standard_recursion_config();
		// print_circuit_config(&config, "inner verifier config");
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let tr = builder._true();
		let message_target = builder.add_virtual_hash();
		let pubkey_target = PubkeyTarget(LocalQuinticExtension(builder.add_virtual_target_arr()));
		let targets =
			conditional_schnorr_verify_gadget(&mut builder, message_target, pubkey_target, tr);
		let inner_data = time!("inner build", builder.build::<C>());
		print_common_data(&inner_data.common, "inner common data");

		//  Set witness
		let mut pw = PartialWitness::new();
		{
			// Set pubkey Q and R
			set_gfp5(&mut pw, pubkey_target.0.0, cq.w.0);
			set_gfp5(&mut pw, targets.cr, cr.w.0);

			// Set message
			for j in 0..4 {
				pw.set_target(message_target.elements[j], message[j])
					.unwrap();
			}

			set_schnorr_witness(&mut pw, &targets, q, cr, e, s);
			// println!("for R w = {:?}, x = {:?}, y = {:?}", r.encode().w, r.x, r.y,);
		}

		// Inner prove and verify
		let inner_proof = time!(
			"inner prove",
			inner_data.prove(pw).expect("inner proof generation failed")
		);
		time!(
			"inner verify",
			inner_data
				.verify(inner_proof.clone())
				.expect("inner verification failed")
		);

		// Build the outer (recursive) circuit that verifies the inner proof.
		let mut rec_builder =
			CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
		let proof_target = rec_builder.add_virtual_proof_with_pis(&inner_data.common);
		let verifier_target =
			rec_builder.add_virtual_verifier_data(inner_data.common.config.fri_config.cap_height);
		rec_builder.verify_proof::<C>(&proof_target, &verifier_target, &inner_data.common);
		let rec_data = time!("rec build", rec_builder.build::<C>());
		print_common_data(&rec_data.common, "rec common data");

		// Set the recursive witness.
		let mut rec_pw = PartialWitness::new();
		rec_pw
			.set_proof_with_pis_target(&proof_target, &inner_proof)
			.unwrap();
		rec_pw
			.set_cap_target(
				&verifier_target.constants_sigmas_cap,
				&inner_data.verifier_only.constants_sigmas_cap,
			)
			.unwrap();
		rec_pw
			.set_hash_target(
				verifier_target.circuit_digest,
				inner_data.verifier_only.circuit_digest,
			)
			.unwrap();

		let rec_proof = time!(
			"rec prove",
			rec_data.prove(rec_pw).expect("recursive proof failed")
		);
		time!(
			"rec verify",
			rec_data.verify(rec_proof).expect("recursive verify failed")
		);
	}

	/// Demonstrates that `conditional_schnorr_verify_gadget` with `apply_check = false` accepts
	/// an arbitrary (fake) signature.  We pick e, s freely, compute R = s·G + e·Q so that the
	/// EC arithmetic in the DoubleAdd4x gates is satisfied, then prove without the hash check.
	#[test]
	fn test_conditional_schnorr_verify_apply_check_false() {
		use plonky2_field::types::Field;

		const D: usize = 2;
		type C = PoseidonGoldilocksConfig;
		type F = <C as GenericConfig<D>>::F;

		// Use a known private key to get a valid curve point Q.
		let d = Scalar::from_raw([
			5400142491657709732,
			15846706413025839610,
			1661266468596303141,
			17577886881415715269,
			7270009582106593884,
		]);
		let privkey = PrivateKey::new(d);
		let pubkey = privkey.public_key::<F>();
		let q = pubkey.as_point();
		let cq = q.encode();

		// Arbitrary scalars — NOT derived from hashing any message.
		let e = Scalar::from_raw([42, 0, 0, 0, 0]);
		let s = Scalar::from_raw([7, 0, 0, 0, 0]);

		// Compute R = s·G + e·Q natively.  This is exactly what the 80 DoubleAdd4x
		// gates evaluate, so the EC-arithmetic witness will be consistent.
		let g = PointEw::<F>::generator();
		let sg = g.scalar_mul(&s);
		let eq = q.scalar_mul(&e);
		let r = sg.add(&eq);
		let cr = r.encode();

		// Build circuit with a virtual apply_check target.
		let config = CircuitConfig::standard_recursion_config();
		let mut builder = CircuitBuilder::<F, D>::new(config);
		let apply_check = builder.add_virtual_bool_target_safe();
		let message_target = builder.add_virtual_hash();
		let pubkey_target = PubkeyTarget(LocalQuinticExtension(builder.add_virtual_target_arr()));
		let targets = conditional_schnorr_verify_gadget(
			&mut builder,
			message_target,
			pubkey_target,
			apply_check,
		);
		let data = builder.build::<C>();

		// Fill witness.
		let mut pw = PartialWitness::new();

		// Disable the hash check.
		pw.set_bool_target(apply_check, false).unwrap();

		// Public key Q and compressed R.
		set_gfp5(&mut pw, pubkey_target.0.0, cq.w.0);
		set_gfp5(&mut pw, targets.cr, cr.w.0);

		// Message can be anything: it will not be hash-checked.
		for j in 0..4 {
			pw.set_target(message_target.elements[j], F::TWO).unwrap();
		}

		// Fill the 80 DoubleAdd4x gate witnesses.  Internally this verifies that the
		// accumulated EC result encodes to `cr`, so R = s·G + e·Q must hold natively.
		set_schnorr_witness(&mut pw, &targets, q, cr, e, s);

		let proof = data
			.prove(pw)
			.expect("proof must succeed: apply_check=false skips hash check");
		data.verify(proof).expect("verification failed");
	}

	fn generate_offset_neg_319() {
		let p = PointEw::<GoldilocksField>::from(OFFSET);

		let mut p319 = p;
		for _ in 0..319 {
			p319 = p319.double();
		}

		println!("2^319*P = {:?}", -p319);
	}
}
