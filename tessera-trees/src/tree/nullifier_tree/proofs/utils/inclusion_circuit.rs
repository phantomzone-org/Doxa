use anyhow::Result;
#[cfg(test)]
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::{
	field::{
		extension::Extendable,
		types::{Field, PrimeField64},
	},
	hash::hash_types::RichField,
	iop::{
		target::{BoolTarget, Target},
		witness::{PartialWitness, WitnessWrite},
	},
	plonk::circuit_builder::CircuitBuilder,
};

#[cfg(test)]
use crate::tree::hasher::{HASH_SIZE, MerkleHash, ToHashOut};
#[cfg(test)]
pub struct IndexRangeCheckTarget {
	pub a: Vec<HashOutTarget>,
	pub x: Vec<HashOutTarget>,
	pub b: Vec<HashOutTarget>,
	pub u: Vec<Vec<Target>>,
	pub v: Vec<Vec<Target>>,
	pub c_ax: Vec<Vec<BoolTarget>>,
	pub c_xb: Vec<Vec<BoolTarget>>,
}

#[cfg(test)]
impl IndexRangeCheckTarget {
	pub fn new<F, const D: usize>(builder: &mut CircuitBuilder<F, D>, batch: usize) -> Self
	where
		F: Field + RichField + Extendable<D>,
	{
		let a: Vec<HashOutTarget> = (0..batch).map(|_| builder.add_virtual_hash()).collect();

		let x: Vec<HashOutTarget> = (0..batch).map(|_| builder.add_virtual_hash()).collect();

		let b: Vec<HashOutTarget> = (0..batch).map(|_| builder.add_virtual_hash()).collect();

		let u = (0..batch)
			.map(|_| {
				(0..2 * HASH_SIZE)
					.map(|_| builder.add_virtual_target())
					.collect()
			})
			.collect();

		let v = (0..batch)
			.map(|_| {
				(0..2 * HASH_SIZE)
					.map(|_| builder.add_virtual_target())
					.collect()
			})
			.collect();

		let c_ax = (0..batch)
			.map(|_| {
				(0..2 * HASH_SIZE - 1)
					.map(|_| builder.add_virtual_bool_target_safe())
					.collect()
			})
			.collect();

		let c_xb = (0..batch)
			.map(|_| {
				(0..2 * HASH_SIZE - 1)
					.map(|_| builder.add_virtual_bool_target_safe())
					.collect()
			})
			.collect();

		Self {
			a,
			x,
			b,
			u,
			v,
			c_ax,
			c_xb,
		}
	}

	fn batch(&self) -> usize {
		self.x.len()
	}

	pub fn connect<F, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>)
	where
		F: Field + RichField + Extendable<D>,
	{
		let batch = self.batch();
		for i in 0..batch {
			inclusion(
				builder,
				&self.a[i].elements,
				&self.x[i].elements,
				&self.b[i].elements,
				&self.u[i],
				&self.v[i],
				&self.c_ax[i],
				&self.c_xb[i],
			);
		}
	}

	pub fn set<H, F, const D: usize>(
		&self,
		pw: &mut PartialWitness<F>,
		a: Vec<H::Digest>,
		x: Vec<H::Digest>,
		b: Vec<H::Digest>,
	) -> Result<()>
	where
		H: MerkleHash,
		H::Digest: ToHashOut<F>,
		F: Field + PrimeField64,
	{
		let batch: usize = self.batch();

		for i in 0..batch {
			pw.set_hash_target(self.a[i], a[i].to_hash_out())?;
			pw.set_hash_target(self.x[i], x[i].to_hash_out())?;
			pw.set_hash_target(self.b[i], b[i].to_hash_out())?;

			populate_inclusion_witness(
				pw,
				&a[i].to_hash_out().elements,
				&x[i].to_hash_out().elements,
				&b[i].to_hash_out().elements,
				&self.u[i],
				&self.v[i],
				&self.c_ax[i],
				&self.c_xb[i],
			)?;
		}

		Ok(())
	}
}

#[allow(clippy::too_many_arguments)]
pub fn inclusion<F: Field + RichField + Extendable<D>, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
	a: &[Target], // MSB-first, field limbs
	x: &[Target],
	b: &[Target],
	u: &[Target],
	v: &[Target],
	c_ax: &[BoolTarget],
	c_xb: &[BoolTarget],
) {
	assert_eq!(a.len(), x.len());
	assert_eq!(x.len(), b.len());

	// 1. Decompose + flatten into radix 2^32
	let a_flat: Vec<Target> = split_and_flatten(builder, a);
	let x_flat: Vec<Target> = split_and_flatten(builder, x);
	let b_flat: Vec<Target> = split_and_flatten(builder, b);

	// 2. Enforce strict inclusion in radix 2^32
	enforce_strict_inclusion_radix(builder, &a_flat, &x_flat, &b_flat, u, v, c_ax, c_xb, 32)
}

/// Splits each field limb into two 32-bit sub-limbs and flattens the result.
///
/// Input:
///   - `limbs`: big integer represented as field elements, MSB-first
///
/// Output:
///   - big integer represented in radix 2^32, MSB-first
fn split_and_flatten<
	F: Field + RichField + Extendable<D>, // Required Plonky2 field bounds
	const D: usize,                       // Extension degree
>(
	builder: &mut CircuitBuilder<F, D>, // Circuit builder
	limbs: &[Target],                   // Input big integer (field limbs), MSB-first
) -> Vec<Target> {
	// Allocate output vector:
	// each field limb becomes two 32-bit sub-limbs
	let mut out = Vec::with_capacity(limbs.len() * 2);

	// Iterate over each field limb
	for &x in limbs {
		builder.range_check(x, 64);

		// Decompose x as:
		//   x = lo + 2^32 * hi
		//
		// Enforced constraints:
		//   lo < 2^32
		//   hi < 2^32
		//
		// PRECONDITION:
		//   x has already been range-checked to 64 bits
		let (lo, hi) = builder.split_low_high(x, 32, 64);

		// Push sub-limbs in MSB-first order:
		// hi is more significant than lo
		out.push(hi);
		out.push(lo);
	}

	// Return the flattened radix-2^32 representation
	out
}

/// Populate witnesses for the strict inclusion gadget:
///   a < x < b
///
/// Inputs:
/// - a, x, b: field elements, MSB-first
/// - u, v: slack targets (flattened, radix 2^32, MSB-first)
/// - c_ax, c_xb: carry targets (length = flattened_len - 1)
///
/// This function computes:
///   x = a + 1 + u
///   b = x + 1 + v
#[allow(clippy::too_many_arguments)]
pub fn populate_inclusion_witness<F: Field + PrimeField64>(
	pw: &mut PartialWitness<F>,
	a: &[F], // MSB-first field limbs
	x: &[F],
	b: &[F],
	u: &[Target],
	v: &[Target],
	c_ax: &[BoolTarget],
	c_xb: &[BoolTarget],
) -> Result<()> {
	assert_eq!(a.len(), x.len());
	assert_eq!(x.len(), b.len());

	let base: u64 = 1u64 << 32;
	let n_field = a.len();

	// -------- flatten field limbs into radix-2^32 (LE) --------

	let mut a_flat: Vec<u64> = Vec::with_capacity(2 * n_field);
	let mut x_flat: Vec<u64> = Vec::with_capacity(2 * n_field);
	let mut b_flat: Vec<u64> = Vec::with_capacity(2 * n_field);

	for i in 0..n_field {
		let ai: u64 = a[i].to_canonical_u64();
		let xi: u64 = x[i].to_canonical_u64();
		let bi: u64 = b[i].to_canonical_u64();

		a_flat.push(ai >> 32);
		a_flat.push(ai & 0xffff_ffff);

		x_flat.push(xi >> 32);
		x_flat.push(xi & 0xffff_ffff);

		b_flat.push(bi >> 32);
		b_flat.push(bi & 0xffff_ffff);
	}

	let n: usize = a_flat.len();
	assert_eq!(u.len(), n);
	assert_eq!(v.len(), n);
	assert_eq!(c_ax.len(), n - 1);
	assert_eq!(c_xb.len(), n - 1);

	// -------- helper: compute (out = left + 1 + slack) --------

	fn compute_slack_and_carry(
		left: &[u64], // MSB-first
		out: &[u64],  // MSB-first
		base: u64,
	) -> (Vec<u64>, Vec<bool>) {
		let n: usize = left.len();
		let mut slack: Vec<u64> = vec![0u64; n];
		let mut carries: Vec<bool> = vec![false; n - 1];

		let mut borrow: u64 = 1; // accounts for "+1"

		// Iterate from LSB to MSB
		for i in (0..n).rev() {
			let li = left[i];
			let oi = out[i];

			let tmp = oi.wrapping_sub(li);
			let diff = tmp.wrapping_sub(borrow);

			let borrow_out = (oi < li) || (borrow == 1 && oi == li);
			slack[i] = diff & (base - 1);

			// carry from i goes into i-1
			if i > 0 {
				carries[i - 1] = borrow_out;
			}

			borrow = borrow_out as u64;
		}

		// No check on final borrow — circuit enforces it
		(slack, carries)
	}

	// -------- compute u and carries for a + 1 + u = x --------

	let (u_vals, c_ax_vals) = compute_slack_and_carry(&a_flat, &x_flat, base);

	// -------- compute v and carries for x + 1 + v = b --------

	let (v_vals, c_xb_vals) = compute_slack_and_carry(&x_flat, &b_flat, base);

	// -------- assign witnesses --------

	for i in 0..n {
		pw.set_target(u[i], F::from_canonical_u64(u_vals[i]))?;
		pw.set_target(v[i], F::from_canonical_u64(v_vals[i]))?;
	}

	for i in 0..n - 1 {
		pw.set_bool_target(c_ax[i], c_ax_vals[i])?;
		pw.set_bool_target(c_xb[i], c_xb_vals[i])?;
	}

	Ok(())
}

/// Enforces strict inclusion a < x < b for big integers in radix 2^k.
///
/// Semantics enforced:
///   x = a + 1 + u
///   b = x + 1 + v
/// with:
///   u >= 0, v >= 0
///
/// This avoids explicit comparison and proves inclusion via arithmetic.
#[allow(clippy::too_many_arguments)]
fn enforce_strict_inclusion_radix<
	F: Field + RichField + Extendable<D>, // Required Plonky2 field bounds
	const D: usize,                       // Extension degree
>(
	builder: &mut CircuitBuilder<F, D>, // Circuit builder
	a: &[Target],                       // Lower bound, MSB-first, radix 2^k
	x: &[Target],                       // Value being constrained
	b: &[Target],                       // Upper bound
	u: &[Target],                       //   u witnesses x = a + 1 + u
	v: &[Target],                       //   v witnesses b = x + 1 + v
	c_ax: &[BoolTarget],
	c_xb: &[BoolTarget],
	limb_bits: usize, // k such that base = 2^k
) {
	// All three big integers must have identical limb length
	assert_eq!(a.len(), x.len());
	assert_eq!(x.len(), b.len());
	assert_eq!(u.len(), a.len());
	assert_eq!(v.len(), b.len());
	assert_eq!(c_ax.len(), a.len() - 1);
	assert_eq!(c_xb.len(), b.len() - 1);

	// Number of limbs
	let n: usize = a.len();

	// Constant base = 2^k, used for radix arithmetic
	let base: Target = builder.constant(F::from_canonical_u64(1u64 << limb_bits));

	for i in 0..n {
		// Enforce non-negativity and boundedness:
		//   0 <= ui < 2^k
		//   0 <= vi < 2^k
		builder.range_check(u[i], limb_bits);
		builder.range_check(v[i], limb_bits);
	}

	// Enforce big-integer equation:
	//   x = a + u + 1
	//
	// The +1 makes the inequality strict: x > a
	enforce_add_eq(builder, a, u, x, c_ax, base, true);

	// Enforce big-integer equation:
	//   b = x + v + 1
	//
	// The +1 makes the inequality strict: b > x
	enforce_add_eq(builder, x, v, b, c_xb, base, true);
}

fn enforce_add_eq<F: Field + RichField + Extendable<D>, const D: usize>(
	builder: &mut CircuitBuilder<F, D>,
	left: &[Target],        // MSB-first
	right: &[Target],       // MSB-first
	out: &[Target],         // MSB-first
	carries: &[BoolTarget], // length n-1, where carries[j] is carry-out of limb j+1 into j
	base: Target,
	add_one: bool, // add +1 at LSB
) {
	assert_eq!(left.len(), right.len());
	assert_eq!(right.len(), out.len());

	let n: usize = left.len();
	assert_eq!(carries.len(), n - 1);

	let one: Target = builder.one();

	// booleanity for all carries
	for c in carries {
		builder.assert_bool(*c);
	}

	for i in (0..n).rev() {
		// LSB -> MSB
		let mut sum = builder.add(left[i], right[i]);

		// carry_in comes from less significant limb
		if i != n - 1 {
			sum = builder.add(sum, carries[i].target);
		}

		// +1 at LSB (i == n-1)
		if add_one && i == n - 1 {
			sum = builder.add(sum, one);
		}

		let diff = if i == 0 {
			// MSB: no carry-out allowed
			builder.sub(sum, out[i])
		} else {
			// carry_out for limb i is carries[i-1]
			let mul: Target = builder.mul(base, carries[i - 1].target);
			let rhs: Target = builder.add(out[i], mul);
			builder.sub(sum, rhs)
		};

		builder.assert_zero(diff);
	}
}

#[cfg(test)]
mod test {

	use std::time::Instant;

	use anyhow::Result;
	use plonky2::{
		field::{goldilocks_field::GoldilocksField, types::Field},
		iop::witness::PartialWitness,
		plonk::{
			circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
			config::PoseidonGoldilocksConfig,
		},
	};

	use crate::tree::{hasher::Hash, utils::IndexRangeCheckTarget};

	const D: usize = 2;
	pub type C = PoseidonGoldilocksConfig;
	pub type F = GoldilocksField;

	const BATCH: usize = 1024;

	#[test]
	fn inclusion_check() -> Result<()> {
		let a: Vec<Hash> = vec![
			Hash::new([
				F::from_canonical_u64(0),
				F::from_canonical_u64(0),
				F::from_canonical_u64(0),
				F::from_canonical_u64(0),
			]);
			BATCH
		];

		let x: Vec<Hash> = vec![
			Hash::new([
				F::from_canonical_u64(1),
				F::from_canonical_u64(0),
				F::from_canonical_u64(0),
				F::from_canonical_u64(1),
			]);
			BATCH
		];

		let b: Vec<Hash> = vec![
			Hash::new([
				F::from_canonical_u64(1),
				F::from_canonical_u64(0),
				F::from_canonical_u64(0),
				F::from_canonical_u64(3),
			]);
			BATCH
		];

		let config: CircuitConfig = CircuitConfig::standard_recursion_config();
		let mut builder: CircuitBuilder<GoldilocksField, D> = CircuitBuilder::<F, D>::new(config);

		print!("Alloc Targets: ");
		let now: Instant = Instant::now();
		let targets = IndexRangeCheckTarget::new(&mut builder, BATCH);
		println!("{:?}", now.elapsed());

		print!("Connect: ");
		let now: Instant = Instant::now();
		targets.connect::<F, D>(&mut builder);
		println!("{:?}", now.elapsed());

		print!("Set Witnesses: ");
		let mut pw: PartialWitness<GoldilocksField> = PartialWitness::new();
		targets.set::<Hash, F, D>(&mut pw, a, x, b)?;
		println!("{:?}", now.elapsed());

		print!("Build: ");
		let now: Instant = Instant::now();
		let data = builder.build::<C>();
		println!("{:?}", now.elapsed());

		print!("Prove: ");
		let now: Instant = Instant::now();
		let proof = data.prove(pw)?;
		println!("{:?}", now.elapsed());

		println!("proof.pi: {}", proof.public_inputs.len());
		let bytes = proof.to_bytes();
		println!("size: {}KB", bytes.len() >> 10);

		let proof_compressed = data.compress(proof)?;

		let bytes = proof_compressed.to_bytes();
		println!("size compressed: {}KB", bytes.len() >> 10);

		print!("Verify: ");
		let now: Instant = Instant::now();
		let decompressed = data.decompress(proof_compressed)?;
		data.verify(decompressed)?;
		println!("{:?}", now.elapsed());

		Ok(())
	}
}
