// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PoseidonGoldilocks
/// @notice Poseidon hash over Goldilocks (p = 2^64 - 2^32 + 1), width=12, x^7 S-box.
/// @dev Inline-assembly implementation with hardcoded round constants.
///      Full rounds use the packed Goldilocks MDS directly. Partial rounds use
///      Plonky2's fast Goldilocks decomposition with packed per-round immediates.
///      MDS uses 3-packed coefficients (3 row outputs per u256 at bit offsets
///      0/86/172) to cut MUL count from 144 to 48 per round.
contract PoseidonGoldilocks {

    /// @notice Compress two packed Goldilocks HashOut values into one.
    /// @param left  4 Goldilocks elements packed LE: el0 | (el1 << 64) | (el2 << 128) | (el3 << 192)
    /// @param right Same packing
    /// @return digest Packed 4-element hash output
    function compress(uint256 left, uint256 right) public pure returns (uint256 digest) {
        assembly {

            // ── S-box: x → x^7 ──────────────────────────────────
            // After MDS: state < P (canonical via mulmod reduction).
            // After add_rc: state < 2P < 2^65.
            // x² < 2^130, x³ < 2^195 — both fit u256.
            // Use mul (5 gas) instead of mulmod (8 gas) where product fits.
            function sbox7(x) -> r {
                let x2 := mul(x, x)               // < 2^130
                let x3 := mul(x2, x)              // < 2^195
                let x6 := mulmod(x3, x3, 0xFFFFFFFF00000001) // x³*x³ overflows → mulmod
                r := mulmod(x6, x, 0xFFFFFFFF00000001)
            }

            // ── Specialized round 0 ────────────────────────────
            // Capacity lanes start at zero, so their add_rc + sbox outputs are constants.
            function round0(base) {
                let s0 := sbox7(add(mload(base), 0xb585f766f2144405))
                let s1 := sbox7(add(mload(add(base, 0x20)), 0x7746a55f43921ad7))
                let s2 := sbox7(add(mload(add(base, 0x40)), 0xb2fb0d31cee799b4))
                let s3 := sbox7(add(mload(add(base, 0x60)), 0x0f6760a4803427d7))
                let s4 := sbox7(add(mload(add(base, 0x80)), 0xe10d666650f4e012))
                let s5 := sbox7(add(mload(add(base, 0xa0)), 0x8cae14cb07d09bf1))
                let s6 := sbox7(add(mload(add(base, 0xc0)), 0xd438539c95f63e9f))
                let s7 := sbox7(add(mload(add(base, 0xe0)), 0xef781c7ce35b4c3d))
                let mask86 := 0x3fffffffffffffffffffff
                let P := 0xffffffff00000001

                // Group 0: rows 0, 1, 2
                let acc0 := 0x2de8709ead6591bf900000f3e783c9ebb72ce35c00043dca772285e11557b
                acc0 := add(acc0, mul(0x220000000000000000000050000000000000000000019, s0))
                acc0 := add(acc0, mul(0x14000000000000000000004400000000000000000000f, s1))
                acc0 := add(acc0, mul(0x11000000000000000000003c000000000000000000029, s2))
                acc0 := add(acc0, mul(0xf00000000000000000000a4000000000000000000010, s3))
                acc0 := add(acc0, mul(0x290000000000000000000040000000000000000000002, s4))
                acc0 := add(acc0, mul(0x10000000000000000000000800000000000000000001c, s5))
                acc0 := add(acc0, mul(0x2000000000000000000007000000000000000000000d, s6))
                acc0 := add(acc0, mul(0x1c000000000000000000003400000000000000000000d, s7))
                mstore(base, mulmod(and(acc0, mask86), 1, P))
                mstore(add(base, 0x20), mulmod(and(shr(86, acc0), mask86), 1, P))
                mstore(add(base, 0x40), mulmod(shr(172, acc0), 1, P))

                // Group 1: rows 3, 4, 5
                let acc1 := 0x2285b2354583d151d3000078cc0470ed0b0036780003cec47841c824bf60a
                acc1 := add(acc1, mul(0xd000000000000000000009c000000000000000000012, s0))
                acc1 := add(acc1, mul(0x270000000000000000000048000000000000000000022, s1))
                acc1 := add(acc1, mul(0x120000000000000000000088000000000000000000014, s2))
                acc1 := add(acc1, mul(0x220000000000000000000050000000000000000000011, s3))
                acc1 := add(acc1, mul(0x14000000000000000000004400000000000000000000f, s4))
                acc1 := add(acc1, mul(0x11000000000000000000003c000000000000000000029, s5))
                acc1 := add(acc1, mul(0xf00000000000000000000a4000000000000000000010, s6))
                acc1 := add(acc1, mul(0x290000000000000000000040000000000000000000002, s7))
                mstore(add(base, 0x60), mulmod(and(acc1, mask86), 1, P))
                mstore(add(base, 0x80), mulmod(and(shr(86, acc1), mask86), 1, P))
                mstore(add(base, 0xa0), mulmod(shr(172, acc1), 1, P))

                // Group 2: rows 6, 7, 8
                let acc2 := 0x317efcda77b141e6200000a1f5776438dec1de4c0003c2b43a5728125b199
                acc2 := add(acc2, mul(0x2000000000000000000007000000000000000000000d, s0))
                acc2 := add(acc2, mul(0x1c000000000000000000003400000000000000000000d, s1))
                acc2 := add(acc2, mul(0xd0000000000000000000034000000000000000000027, s2))
                acc2 := add(acc2, mul(0xd000000000000000000009c000000000000000000012, s3))
                acc2 := add(acc2, mul(0x270000000000000000000048000000000000000000022, s4))
                acc2 := add(acc2, mul(0x120000000000000000000088000000000000000000014, s5))
                acc2 := add(acc2, mul(0x220000000000000000000050000000000000000000011, s6))
                acc2 := add(acc2, mul(0x14000000000000000000004400000000000000000000f, s7))
                mstore(add(base, 0xc0), mulmod(and(acc2, mask86), 1, P))
                mstore(add(base, 0xe0), mulmod(and(shr(86, acc2), mask86), 1, P))
                mstore(add(base, 0x100), mulmod(shr(172, acc2), 1, P))

                // Group 3: rows 9, 10, 11
                let acc3 := 0x336fc2e08854296c7d0000d8bbffcd44b6c1e2e00003af474e510aa911322
                acc3 := add(acc3, mul(0xf00000000000000000000a4000000000000000000010, s0))
                acc3 := add(acc3, mul(0x290000000000000000000040000000000000000000002, s1))
                acc3 := add(acc3, mul(0x10000000000000000000000800000000000000000001c, s2))
                acc3 := add(acc3, mul(0x2000000000000000000007000000000000000000000d, s3))
                acc3 := add(acc3, mul(0x1c000000000000000000003400000000000000000000d, s4))
                acc3 := add(acc3, mul(0xd0000000000000000000034000000000000000000027, s5))
                acc3 := add(acc3, mul(0xd000000000000000000009c000000000000000000012, s6))
                acc3 := add(acc3, mul(0x270000000000000000000048000000000000000000022, s7))
                mstore(add(base, 0x120), mulmod(and(acc3, mask86), 1, P))
                mstore(add(base, 0x140), mulmod(and(shr(86, acc3), mask86), 1, P))
                mstore(add(base, 0x160), mulmod(shr(172, acc3), 1, P))
            }

            // ── MDS layer (3-packed) ───────────────────────────
            // M = circ(17,15,41,16,2,28,13,13,39,18,34,20) + diag(8,0,...,0)
            // 3 rows packed per u256 at bit offsets 0/86/172
            // 48 MUL + 44 ADD per round instead of 144 MUL + 132 ADD
            function mds(base) {
                let s0 := mload(base)
                let s1 := mload(add(base, 0x20))
                let s2 := mload(add(base, 0x40))
                let s3 := mload(add(base, 0x60))
                let s4 := mload(add(base, 0x80))
                let s5 := mload(add(base, 0xa0))
                let s6 := mload(add(base, 0xc0))
                let s7 := mload(add(base, 0xe0))
                let s8 := mload(add(base, 0x100))
                let s9 := mload(add(base, 0x120))
                let s10 := mload(add(base, 0x140))
                let s11 := mload(add(base, 0x160))

                let mask86 := 0x3fffffffffffffffffffff
                let P := 0xFFFFFFFF00000001

                // Group 0: rows 0, 1, 2
                let acc0 := mul(0x220000000000000000000050000000000000000000019, s0)
                acc0 := add(acc0, mul(0x14000000000000000000004400000000000000000000f, s1))
                acc0 := add(acc0, mul(0x11000000000000000000003c000000000000000000029, s2))
                acc0 := add(acc0, mul(0xf00000000000000000000a4000000000000000000010, s3))
                acc0 := add(acc0, mul(0x290000000000000000000040000000000000000000002, s4))
                acc0 := add(acc0, mul(0x10000000000000000000000800000000000000000001c, s5))
                acc0 := add(acc0, mul(0x2000000000000000000007000000000000000000000d, s6))
                acc0 := add(acc0, mul(0x1c000000000000000000003400000000000000000000d, s7))
                acc0 := add(acc0, mul(0xd0000000000000000000034000000000000000000027, s8))
                acc0 := add(acc0, mul(0xd000000000000000000009c000000000000000000012, s9))
                acc0 := add(acc0, mul(0x270000000000000000000048000000000000000000022, s10))
                acc0 := add(acc0, mul(0x120000000000000000000088000000000000000000014, s11))
                mstore(base, mulmod(and(acc0, mask86), 1, P))
                mstore(add(base, 0x20), mulmod(and(shr(86, acc0), mask86), 1, P))
                mstore(add(base, 0x40), mulmod(shr(172, acc0), 1, P))

                // Group 1: rows 3, 4, 5
                let acc1 := mul(0xd000000000000000000009c000000000000000000012, s0)
                acc1 := add(acc1, mul(0x270000000000000000000048000000000000000000022, s1))
                acc1 := add(acc1, mul(0x120000000000000000000088000000000000000000014, s2))
                acc1 := add(acc1, mul(0x220000000000000000000050000000000000000000011, s3))
                acc1 := add(acc1, mul(0x14000000000000000000004400000000000000000000f, s4))
                acc1 := add(acc1, mul(0x11000000000000000000003c000000000000000000029, s5))
                acc1 := add(acc1, mul(0xf00000000000000000000a4000000000000000000010, s6))
                acc1 := add(acc1, mul(0x290000000000000000000040000000000000000000002, s7))
                acc1 := add(acc1, mul(0x10000000000000000000000800000000000000000001c, s8))
                acc1 := add(acc1, mul(0x2000000000000000000007000000000000000000000d, s9))
                acc1 := add(acc1, mul(0x1c000000000000000000003400000000000000000000d, s10))
                acc1 := add(acc1, mul(0xd0000000000000000000034000000000000000000027, s11))
                mstore(add(base, 0x60), mulmod(and(acc1, mask86), 1, P))
                mstore(add(base, 0x80), mulmod(and(shr(86, acc1), mask86), 1, P))
                mstore(add(base, 0xa0), mulmod(shr(172, acc1), 1, P))

                // Group 2: rows 6, 7, 8
                let acc2 := mul(0x2000000000000000000007000000000000000000000d, s0)
                acc2 := add(acc2, mul(0x1c000000000000000000003400000000000000000000d, s1))
                acc2 := add(acc2, mul(0xd0000000000000000000034000000000000000000027, s2))
                acc2 := add(acc2, mul(0xd000000000000000000009c000000000000000000012, s3))
                acc2 := add(acc2, mul(0x270000000000000000000048000000000000000000022, s4))
                acc2 := add(acc2, mul(0x120000000000000000000088000000000000000000014, s5))
                acc2 := add(acc2, mul(0x220000000000000000000050000000000000000000011, s6))
                acc2 := add(acc2, mul(0x14000000000000000000004400000000000000000000f, s7))
                acc2 := add(acc2, mul(0x11000000000000000000003c000000000000000000029, s8))
                acc2 := add(acc2, mul(0xf00000000000000000000a4000000000000000000010, s9))
                acc2 := add(acc2, mul(0x290000000000000000000040000000000000000000002, s10))
                acc2 := add(acc2, mul(0x10000000000000000000000800000000000000000001c, s11))
                mstore(add(base, 0xc0), mulmod(and(acc2, mask86), 1, P))
                mstore(add(base, 0xe0), mulmod(and(shr(86, acc2), mask86), 1, P))
                mstore(add(base, 0x100), mulmod(shr(172, acc2), 1, P))

                // Group 3: rows 9, 10, 11
                let acc3 := mul(0xf00000000000000000000a4000000000000000000010, s0)
                acc3 := add(acc3, mul(0x290000000000000000000040000000000000000000002, s1))
                acc3 := add(acc3, mul(0x10000000000000000000000800000000000000000001c, s2))
                acc3 := add(acc3, mul(0x2000000000000000000007000000000000000000000d, s3))
                acc3 := add(acc3, mul(0x1c000000000000000000003400000000000000000000d, s4))
                acc3 := add(acc3, mul(0xd0000000000000000000034000000000000000000027, s5))
                acc3 := add(acc3, mul(0xd000000000000000000009c000000000000000000012, s6))
                acc3 := add(acc3, mul(0x270000000000000000000048000000000000000000022, s7))
                acc3 := add(acc3, mul(0x120000000000000000000088000000000000000000014, s8))
                acc3 := add(acc3, mul(0x220000000000000000000050000000000000000000011, s9))
                acc3 := add(acc3, mul(0x14000000000000000000004400000000000000000000f, s10))
                acc3 := add(acc3, mul(0x11000000000000000000003c000000000000000000029, s11))
                mstore(add(base, 0x120), mulmod(and(acc3, mask86), 1, P))
                mstore(add(base, 0x140), mulmod(and(shr(86, acc3), mask86), 1, P))
                mstore(add(base, 0x160), mulmod(shr(172, acc3), 1, P))
            }

            // ── Fast partial-round initializer ──────────────────
            // Transforms state[1..11] once before the 22-round fast path.
            // Lanes 1..11 intentionally stay unreduced through the partial block.
            function mds_partial_init(base) {
                let s1 := mload(add(base, 0x20))
                let s2 := mload(add(base, 0x40))
                let s3 := mload(add(base, 0x60))
                let s4 := mload(add(base, 0x80))
                let s5 := mload(add(base, 0xa0))
                let s6 := mload(add(base, 0xc0))
                let s7 := mload(add(base, 0xe0))
                let s8 := mload(add(base, 0x100))
                let s9 := mload(add(base, 0x120))
                let s10 := mload(add(base, 0x140))
                let s11 := mload(add(base, 0x160))
                {
                    let acc := mul(0x80772dc2645b280b, s1)
                    acc := add(acc, mul(0xe796d293a47a64cb, s2))
                    acc := add(acc, mul(0xdcedab70f40718ba, s3))
                    acc := add(acc, mul(0xf4a437f2888ae909, s4))
                    acc := add(acc, mul(0xf97abba0dffb6c50, s5))
                    acc := add(acc, mul(0x7f8e41e0b0a6cdff, s6))
                    acc := add(acc, mul(0x726af914971c1374, s7))
                    acc := add(acc, mul(0x64dd936da878404d, s8))
                    acc := add(acc, mul(0x85418a9fef8a9890, s9))
                    acc := add(acc, mul(0x156048ee7a738154, s10))
                    acc := add(acc, mul(0xd841e8ef9dde8ba0, s11))
                    mstore(add(base, 0x20), acc)
                }
                {
                    let acc := mul(0xdc927721da922cf8, s1)
                    acc := add(acc, mul(0xb124c33152a2421a, s2))
                    acc := add(acc, mul(0x14a4a64da0b2668f, s3))
                    acc := add(acc, mul(0xc537d44dc2875403, s4))
                    acc := add(acc, mul(0x5e40f0c9bb82aab5, s5))
                    acc := add(acc, mul(0x4b1ba8d40afca97d, s6))
                    acc := add(acc, mul(0x1d7f8a2cce1a9d00, s7))
                    acc := add(acc, mul(0x4db9a2ead2bd7262, s8))
                    acc := add(acc, mul(0xd8a2eb7ef5e707ad, s9))
                    acc := add(acc, mul(0x91f7562377e81df5, s10))
                    acc := add(acc, mul(0x156048ee7a738154, s11))
                    mstore(add(base, 0x40), acc)
                }
                {
                    let acc := mul(0xc1978156516879ad, s1)
                    acc := add(acc, mul(0x0ee5dc0ce131268a, s2))
                    acc := add(acc, mul(0x4715b8e5ab34653b, s3))
                    acc := add(acc, mul(0x7f68007619fd8ba9, s4))
                    acc := add(acc, mul(0x5996a80497e24a6b, s5))
                    acc := add(acc, mul(0x623708f28fca70e8, s6))
                    acc := add(acc, mul(0x18737784700c75cd, s7))
                    acc := add(acc, mul(0xbe2e19f6d07f1a83, s8))
                    acc := add(acc, mul(0xbfe85ababed2d882, s9))
                    acc := add(acc, mul(0xd8a2eb7ef5e707ad, s10))
                    acc := add(acc, mul(0x85418a9fef8a9890, s11))
                    mstore(add(base, 0x60), acc)
                }
                {
                    let acc := mul(0x90e80c591f48b603, s1)
                    acc := add(acc, mul(0xa9032a52f930fae6, s2))
                    acc := add(acc, mul(0x1e8916a99c93a88e, s3))
                    acc := add(acc, mul(0xa4911db6a32612da, s4))
                    acc := add(acc, mul(0x07084430a7307c9a, s5))
                    acc := add(acc, mul(0xbf150dc4914d380f, s6))
                    acc := add(acc, mul(0x7fb45d605dd82838, s7))
                    acc := add(acc, mul(0x02290fe23c20351a, s8))
                    acc := add(acc, mul(0xbe2e19f6d07f1a83, s9))
                    acc := add(acc, mul(0x4db9a2ead2bd7262, s10))
                    acc := add(acc, mul(0x64dd936da878404d, s11))
                    mstore(add(base, 0x80), acc)
                }
                {
                    let acc := mul(0x3a2432625475e3ae, s1)
                    acc := add(acc, mul(0x7e33ca8c814280de, s2))
                    acc := add(acc, mul(0xbba4b5d86b9a3b2c, s3))
                    acc := add(acc, mul(0x2f7e9aade3fdaec1, s4))
                    acc := add(acc, mul(0xad2f570a5b8545aa, s5))
                    acc := add(acc, mul(0xc26a083554767106, s6))
                    acc := add(acc, mul(0x862361aeab0f9b6e, s7))
                    acc := add(acc, mul(0x7fb45d605dd82838, s8))
                    acc := add(acc, mul(0x18737784700c75cd, s9))
                    acc := add(acc, mul(0x1d7f8a2cce1a9d00, s10))
                    acc := add(acc, mul(0x726af914971c1374, s11))
                    mstore(add(base, 0xa0), acc)
                }
                {
                    let acc := mul(0x00a2d4321cca94fe, s1)
                    acc := add(acc, mul(0xad11180f69a8c29e, s2))
                    acc := add(acc, mul(0xe76649f9bd5d5c2e, s3))
                    acc := add(acc, mul(0xe7ffd578da4ea43d, s4))
                    acc := add(acc, mul(0xab7f81fef4274770, s5))
                    acc := add(acc, mul(0x753b8b1126665c22, s6))
                    acc := add(acc, mul(0xc26a083554767106, s7))
                    acc := add(acc, mul(0xbf150dc4914d380f, s8))
                    acc := add(acc, mul(0x623708f28fca70e8, s9))
                    acc := add(acc, mul(0x4b1ba8d40afca97d, s10))
                    acc := add(acc, mul(0x7f8e41e0b0a6cdff, s11))
                    mstore(add(base, 0xc0), acc)
                }
                {
                    let acc := mul(0x77736f524010c932, s1)
                    acc := add(acc, mul(0xc75ac6d5b5a10ff3, s2))
                    acc := add(acc, mul(0xaf8e2518a1ece54d, s3))
                    acc := add(acc, mul(0x43a608e7afa6b5c2, s4))
                    acc := add(acc, mul(0xcb81f535cf98c9e9, s5))
                    acc := add(acc, mul(0xab7f81fef4274770, s6))
                    acc := add(acc, mul(0xad2f570a5b8545aa, s7))
                    acc := add(acc, mul(0x07084430a7307c9a, s8))
                    acc := add(acc, mul(0x5996a80497e24a6b, s9))
                    acc := add(acc, mul(0x5e40f0c9bb82aab5, s10))
                    acc := add(acc, mul(0xf97abba0dffb6c50, s11))
                    mstore(add(base, 0xe0), acc)
                }
                {
                    let acc := mul(0x904d3f2804a36c54, s1)
                    acc := add(acc, mul(0xf0674a8dc5a387ec, s2))
                    acc := add(acc, mul(0xdcda1344cdca873f, s3))
                    acc := add(acc, mul(0xca46546aa99e1575, s4))
                    acc := add(acc, mul(0x43a608e7afa6b5c2, s5))
                    acc := add(acc, mul(0xe7ffd578da4ea43d, s6))
                    acc := add(acc, mul(0x2f7e9aade3fdaec1, s7))
                    acc := add(acc, mul(0xa4911db6a32612da, s8))
                    acc := add(acc, mul(0x7f68007619fd8ba9, s9))
                    acc := add(acc, mul(0xc537d44dc2875403, s10))
                    acc := add(acc, mul(0xf4a437f2888ae909, s11))
                    mstore(add(base, 0x100), acc)
                }
                {
                    let acc := mul(0xbf9b39e28a16f354, s1)
                    acc := add(acc, mul(0xb36d43120eaa5e2b, s2))
                    acc := add(acc, mul(0xcd080204256088e5, s3))
                    acc := add(acc, mul(0xdcda1344cdca873f, s4))
                    acc := add(acc, mul(0xaf8e2518a1ece54d, s5))
                    acc := add(acc, mul(0xe76649f9bd5d5c2e, s6))
                    acc := add(acc, mul(0xbba4b5d86b9a3b2c, s7))
                    acc := add(acc, mul(0x1e8916a99c93a88e, s8))
                    acc := add(acc, mul(0x4715b8e5ab34653b, s9))
                    acc := add(acc, mul(0x14a4a64da0b2668f, s10))
                    acc := add(acc, mul(0xdcedab70f40718ba, s11))
                    mstore(add(base, 0x120), acc)
                }
                {
                    let acc := mul(0x3a1ded54a6cd058b, s1)
                    acc := add(acc, mul(0x6f232aab4b533a25, s2))
                    acc := add(acc, mul(0xb36d43120eaa5e2b, s3))
                    acc := add(acc, mul(0xf0674a8dc5a387ec, s4))
                    acc := add(acc, mul(0xc75ac6d5b5a10ff3, s5))
                    acc := add(acc, mul(0xad11180f69a8c29e, s6))
                    acc := add(acc, mul(0x7e33ca8c814280de, s7))
                    acc := add(acc, mul(0xa9032a52f930fae6, s8))
                    acc := add(acc, mul(0x0ee5dc0ce131268a, s9))
                    acc := add(acc, mul(0xb124c33152a2421a, s10))
                    acc := add(acc, mul(0xe796d293a47a64cb, s11))
                    mstore(add(base, 0x140), acc)
                }
                {
                    let acc := mul(0x42392870da5737cf, s1)
                    acc := add(acc, mul(0x3a1ded54a6cd058b, s2))
                    acc := add(acc, mul(0xbf9b39e28a16f354, s3))
                    acc := add(acc, mul(0x904d3f2804a36c54, s4))
                    acc := add(acc, mul(0x77736f524010c932, s5))
                    acc := add(acc, mul(0x00a2d4321cca94fe, s6))
                    acc := add(acc, mul(0x3a2432625475e3ae, s7))
                    acc := add(acc, mul(0x90e80c591f48b603, s8))
                    acc := add(acc, mul(0xc1978156516879ad, s9))
                    acc := add(acc, mul(0xdc927721da922cf8, s10))
                    acc := add(acc, mul(0x80772dc2645b280b, s11))
                    mstore(add(base, 0x160), acc)
                }
            }

            // ── Fast partial round ──────────────────────────────
            // state[0] is reduced every round for the x^7 S-box.
            // state[1..11] remain lazy and are reduced once before full rounds resume.
            function fast_partial_round(base, rc, v0, v1, v2, w0, w1, w2) {
                let s0 := add(sbox7(mload(base)), rc)
                let d := mul(25, s0)
                let mask64 := 0xFFFFFFFFFFFFFFFF
                let P := 0xFFFFFFFF00000001
                {
                    let si := mload(add(base, 0x20))
                    d := add(d, mul(si, and(w0, mask64)))
                    mstore(add(base, 0x20), add(si, mul(s0, and(v0, mask64))))
                }
                {
                    let si := mload(add(base, 0x40))
                    d := add(d, mul(si, and(shr(64, w0), mask64)))
                    mstore(add(base, 0x40), add(si, mul(s0, and(shr(64, v0), mask64))))
                }
                {
                    let si := mload(add(base, 0x60))
                    d := add(d, mul(si, and(shr(128, w0), mask64)))
                    mstore(add(base, 0x60), add(si, mul(s0, and(shr(128, v0), mask64))))
                }
                {
                    let si := mload(add(base, 0x80))
                    d := add(d, mul(si, and(shr(192, w0), mask64)))
                    mstore(add(base, 0x80), add(si, mul(s0, and(shr(192, v0), mask64))))
                }
                {
                    let si := mload(add(base, 0xa0))
                    d := add(d, mul(si, and(w1, mask64)))
                    mstore(add(base, 0xa0), add(si, mul(s0, and(v1, mask64))))
                }
                {
                    let si := mload(add(base, 0xc0))
                    d := add(d, mul(si, and(shr(64, w1), mask64)))
                    mstore(add(base, 0xc0), add(si, mul(s0, and(shr(64, v1), mask64))))
                }
                {
                    let si := mload(add(base, 0xe0))
                    d := add(d, mul(si, and(shr(128, w1), mask64)))
                    mstore(add(base, 0xe0), add(si, mul(s0, and(shr(128, v1), mask64))))
                }
                {
                    let si := mload(add(base, 0x100))
                    d := add(d, mul(si, and(shr(192, w1), mask64)))
                    mstore(add(base, 0x100), add(si, mul(s0, and(shr(192, v1), mask64))))
                }
                {
                    let si := mload(add(base, 0x120))
                    d := add(d, mul(si, and(w2, mask64)))
                    mstore(add(base, 0x120), add(si, mul(s0, and(v2, mask64))))
                }
                {
                    let si := mload(add(base, 0x140))
                    d := add(d, mul(si, and(shr(64, w2), mask64)))
                    mstore(add(base, 0x140), add(si, mul(s0, and(shr(64, v2), mask64))))
                }
                {
                    let si := mload(add(base, 0x160))
                    d := add(d, mul(si, and(shr(128, w2), mask64)))
                    mstore(add(base, 0x160), add(si, mul(s0, and(shr(128, v2), mask64))))
                }
                mstore(base, mulmod(d, 1, P))
            }

            // ── State setup ──────────────────────────────────────
            let base := mload(0x40)
            let mask := 0xFFFFFFFFFFFFFFFF

            // Unpack left → state[0..3]
            mstore(base,              and(left, mask))
            mstore(add(base, 0x20),   and(shr(64, left), mask))
            mstore(add(base, 0x40),   and(shr(128, left), mask))
            mstore(add(base, 0x60),   shr(192, left))

            // Unpack right → state[4..7]
            mstore(add(base, 0x80),   and(right, mask))
            mstore(add(base, 0xa0),   and(shr(64, right), mask))
            mstore(add(base, 0xc0),   and(shr(128, right), mask))
            mstore(add(base, 0xe0),   shr(192, right))

            // Capacity state[8..11] = 0
            mstore(add(base, 0x100),  0)
            mstore(add(base, 0x120),  0)
            mstore(add(base, 0x140),  0)
            mstore(add(base, 0x160),  0)

            // ── Permutation ──────────────────────────────────────

            // ── Round 0 (full, specialized) ──
            round0(base)

                // ── Round 1 (full) ──
                mstore(base, sbox7(add(mload(base), 0x86287821f722c881)))
                mstore(add(base, 0x20), sbox7(add(mload(add(base, 0x20)), 0x59cd1a8a41c18e55)))
                mstore(add(base, 0x40), sbox7(add(mload(add(base, 0x40)), 0xc3b919ad495dc574)))
                mstore(add(base, 0x60), sbox7(add(mload(add(base, 0x60)), 0xa484c4c5ef6a0781)))
                mstore(add(base, 0x80), sbox7(add(mload(add(base, 0x80)), 0x308bbd23dc5416cc)))
                mstore(add(base, 0xa0), sbox7(add(mload(add(base, 0xa0)), 0x6e4a40c18f30c09c)))
                mstore(add(base, 0xc0), sbox7(add(mload(add(base, 0xc0)), 0x9a2eedb70d8f8cfa)))
                mstore(add(base, 0xe0), sbox7(add(mload(add(base, 0xe0)), 0xe360c6e0ae486f38)))
                mstore(add(base, 0x100), sbox7(add(mload(add(base, 0x100)), 0xd5c7718fbfc647fb)))
                mstore(add(base, 0x120), sbox7(add(mload(add(base, 0x120)), 0xc35eae071903ff0b)))
                mstore(add(base, 0x140), sbox7(add(mload(add(base, 0x140)), 0x849c2656969c4be7)))
                mstore(add(base, 0x160), sbox7(add(mload(add(base, 0x160)), 0xc0572c8c08cbbbad)))
                mds(base)

                // ── Round 2 (full) ──
                mstore(base, sbox7(add(mload(base), 0xe9fa634a21de0082)))
                mstore(add(base, 0x20), sbox7(add(mload(add(base, 0x20)), 0xf56f6d48959a600d)))
                mstore(add(base, 0x40), sbox7(add(mload(add(base, 0x40)), 0xf7d713e806391165)))
                mstore(add(base, 0x60), sbox7(add(mload(add(base, 0x60)), 0x8297132b32825daf)))
                mstore(add(base, 0x80), sbox7(add(mload(add(base, 0x80)), 0xad6805e0e30b2c8a)))
                mstore(add(base, 0xa0), sbox7(add(mload(add(base, 0xa0)), 0xac51d9f5fcf8535e)))
                mstore(add(base, 0xc0), sbox7(add(mload(add(base, 0xc0)), 0x502ad7dc18c2ad87)))
                mstore(add(base, 0xe0), sbox7(add(mload(add(base, 0xe0)), 0x57a1550c110b3041)))
                mstore(add(base, 0x100), sbox7(add(mload(add(base, 0x100)), 0x66bbd30e6ce0e583)))
                mstore(add(base, 0x120), sbox7(add(mload(add(base, 0x120)), 0x0da2abef589d644e)))
                mstore(add(base, 0x140), sbox7(add(mload(add(base, 0x140)), 0xf061274fdb150d61)))
                mstore(add(base, 0x160), sbox7(add(mload(add(base, 0x160)), 0x28b8ec3ae9c29633)))
                mds(base)

                // ── Round 3 (full) ──
                mstore(base, sbox7(add(mload(base), 0x92a756e67e2b9413)))
                mstore(add(base, 0x20), sbox7(add(mload(add(base, 0x20)), 0x70e741ebfee96586)))
                mstore(add(base, 0x40), sbox7(add(mload(add(base, 0x40)), 0x019d5ee2af82ec1c)))
                mstore(add(base, 0x60), sbox7(add(mload(add(base, 0x60)), 0x6f6f2ed772466352)))
                mstore(add(base, 0x80), sbox7(add(mload(add(base, 0x80)), 0x7cf416cfe7e14ca1)))
                mstore(add(base, 0xa0), sbox7(add(mload(add(base, 0xa0)), 0x61df517b86a46439)))
                mstore(add(base, 0xc0), sbox7(add(mload(add(base, 0xc0)), 0x85dc499b11d77b75)))
                mstore(add(base, 0xe0), sbox7(add(mload(add(base, 0xe0)), 0x4b959b48b9c10733)))
                mstore(add(base, 0x100), sbox7(add(mload(add(base, 0x100)), 0xe8be3e5da8043e57)))
                mstore(add(base, 0x120), sbox7(add(mload(add(base, 0x120)), 0xf5c0bc1de6da8699)))
                mstore(add(base, 0x140), sbox7(add(mload(add(base, 0x140)), 0x40b12cbf09ef74bf)))
                mstore(add(base, 0x160), sbox7(add(mload(add(base, 0x160)), 0xa637093ecb2ad631)))
                mds(base)

                // ── Partial rounds (Plonky2 fast path) ──
                // Replace rounds 4..25 with the Goldilocks-specific fast decomposition.
                mstore(base, add(mload(base), 0x3cc3f892184df408))
                mstore(add(base, 0x20), add(mload(add(base, 0x20)), 0xe993fd841e7e97f1))
                mstore(add(base, 0x40), add(mload(add(base, 0x40)), 0xf2831d3575f0f3af))
                mstore(add(base, 0x60), add(mload(add(base, 0x60)), 0xd2500e0a350994ca))
                mstore(add(base, 0x80), add(mload(add(base, 0x80)), 0xc5571f35d7288633))
                mstore(add(base, 0xa0), add(mload(add(base, 0xa0)), 0x91d89c5184109a02))
                mstore(add(base, 0xc0), add(mload(add(base, 0xc0)), 0xf37f925d04e5667b))
                mstore(add(base, 0xe0), add(mload(add(base, 0xe0)), 0x2d6e448371955a69))
                mstore(add(base, 0x100), add(mload(add(base, 0x100)), 0x740ef19ce01398a1))
                mstore(add(base, 0x120), add(mload(add(base, 0x120)), 0x694d24c0752fdf45))
                mstore(add(base, 0x140), add(mload(add(base, 0x140)), 0x60936af96ee2f148))
                mstore(add(base, 0x160), add(mload(add(base, 0x160)), 0xc33448feadc78f0c))
                mds_partial_init(base)

                // Fast partial round 4
                fast_partial_round(base, 0x74cb2e819ae421ab, 0x0ba63a63e94b5ff0d667c2055387940fc6c67cc37a2a2bbd94877900674181c3, 0xabcad82633b7bc9dea0870b47a8caf0e7ff02375ed524bb399460cc41b8f079f, 0x00000000000000003ee8011c2b37f77cfb4515f5e5b0d5393b8d135261052241, 0x887af7d4dd4823282421e5d236704588814e82efcd1725293d999c961b7c63b0, 0x09c4155174a552cc64832009d29bcf57bdc52b2676a4b4aaa5e9c291f6119b27, 0x0000000000000000043b1c289f7bc3acc810936e64982542463f9ee03d290810)

                // Fast partial round 5
                fast_partial_round(base, 0xd2559d2370e7f663, 0x6a065da88d8bfc3cc6b16f7ed4fa1b00a37bf67c6f9865590adef3740e71c726, 0x42433fb6949a629a07a786d9cf0852cf407faac0f02e78d14cabc0916844b46f, 0x00000000000000002bbf0ed7b657acb326cfd58e7b003b55891682a147ce43b0, 0xa667bfa9aa96999d2c68a099b51c9e73d510fe714f39fa10673655aae8be5a8b, 0x5ead03205009714240f9cc8c08f80981f84dde3e6acda1794d67e72f063e2108, 0x00000000000000008a21bcd24a14218a00e18c71963dd1b76591b02092d671bb)

                // Fast partial round 6
                fast_partial_round(base, 0x62bf78acf843d17c, 0x5cfc82216bc1bdca73f260087ad28bece367de32f108e278481ac7746b159c67, 0x3cc51c5d368693ae7bc9e0c57243e62ddb69cd7b4298c45dcaccc870a2663a0e, 0x0000000000000000a752061c4f33b8cf2bd18715cdabbca4366b4e8cc068895b, 0x8e0f68c5dc223b9abe32b32a825596e7e4b5bdb1cc3504ff202800f4addbdc87, 0xaead42a3f445ecbf8b9352ad04bef9e7584d29227aa073ac58022d9e1c256ce3, 0x0000000000000000e8f749470bd7c446da6f61838efa1ffe3c667a1d833a3cca)

                // Fast partial round 7
                fast_partial_round(base, 0xd5ab7b67e14d1fb4, 0x9e77fde2eb315e0d4b39e14ce22abd3c9e18a487f44d2fe4b22d2432b72d5098, 0x8577a815a2ff843f99ec1cd2a4460bfe0c2cb99bf1b6bddbca5e0385fe67014d, 0x00000000000000008f7851650eca21a5eb6c67123eab62cb7d80a6b4fd6518a5, 0xe2ae0f051418112c16e6b8e68b93183045245258aec51cf7c5b85bab9e5b3869, 0xb0be7356254bea2e119265be51812daf6bef71973a8146ed0470e26a0093a65b, 0x00000000000000009e7cd88acf543a5e3c5fe4aeb1fb52ba8584defff7589bd7)

                // Fast partial round 8
                fast_partial_round(base, 0xb9fe2ae6e0969bdc, 0x535e8d6fac0031b2a821855c8c1cf5e59f7d798a3323410c11ba9a1b81718c2a, 0xb53926c27897bf7d4db97d92e58bb831a729353f6e55d354404e7c751b634320, 0x0000000000000000aae4438c877ea8f49565fa41ebd31fd7965040d52fe115c5, 0xd99ddf1fe75085f96696670196b0074facf63d95d8887355179be4bba87f0a8c, 0xc053297389af5d3b15226a8e4cd8d3b6cf48395ee6c54f14c2597881fef0283b, 0x0000000000000000c82f510ecf81f6d00ed3cbcff6fcc5ba2c08893f0d1580e2)

                // Fast partial round 9
                fast_partial_round(base, 0xe33fdf79f92a10e8, 0x9f4310d05d068338c44998e99eae41884edc0918210800e937f4e36af6073c6e, 0x59fa6f8bd91d58baa01920c5ef8b2ebec5b2c1fdc0b508749ec7fe4350680f29, 0x0000000000000000cbb8bbaa3810babfbe86a7a2555ae7758bfc9eb89b515a82, 0x05830a443f86c4ac861cc95ad5c86323500392ed0d43113794b06183acb715cc, 0xbdecf5e0cb9cb2139b77fc8bcd559e2c10b3309838e236fb3b68225874a20a7c, 0x0000000000000000eac6db520bb037087935dd342764a14430276f1221ace5fa)

                // Fast partial round 10
                fast_partial_round(base, 0x0ea2bb4c2b25989b, 0x8283d37c6675b50e82f07007c8b7210688c522b949ace7b1577f9a9e7ee3f9c2, 0x26d7c3d1bc07dae5fed24e206052bc7275c56fb7758317c198b074d9bbac1123, 0x0000000000000000514d4ba49c2b14fe4fe27f9f96615270f88c5e441e28dbb4, 0x55f1523ac6a23ea2c4cbe326d1ad9742622247557e9b53717186a80551025f8f, 0xcd800caef5b72ae308bd488070a3a32be30750b6301c0452a13dfe77a3d52f53, 0x00000000000000006b0731849e200a7fb5b99e6664a0a3ee83329c90f04233ce)

                // Fast partial round 11
                fast_partial_round(base, 0xca9121fbf9d38f06, 0x9a95f6cff5b55c7ece0dc874eaf9b55c0a3630dafb8ae2d7f02a3ac068ee110b, 0x3d4bd48b625a8065daebd3006321052ca0c1cf1251c204ad626d76abfed00c7b, 0x0000000000000000e3260ba93d23540a720574f0501caed37f1e584e071f6ed2, 0x514abd0cf6c7bc863bfb6c3f0e616572382b38cee8ee5375ec3fabc192b01799, 0x738450e42495bc81ad1003c5d28918e7178093843f863d1447521b1361dcc546, 0x0000000000000000057fde2062ae35bf4653fb0685084ef2af947c59af5e4047)

                // Fast partial round 12
                fast_partial_round(base, 0xbdd9b0aa81f58fa4, 0x94178e291145c23151c3c0983d4284e59322ed4c0bc2df01ab1cbd41d8c1e335, 0xdc20ee4b8c4c9a808a52437fecaac06bd427ad96e2b39719fd0f1a973d6b2085, 0x00000000000000000e174929433c55051603fe12613db5b6a2c98e9549da2100, 0x3929624a9def725b7817f3dfff8b4ffa66f3860d7514e7fce376678d843ce55e, 0x85b481e5243f60bf1bc927375febbad7fce2f5d02762a3030126ca37f215a80a, 0x0000000000000000f669de0add9931310811719919351ae82d3c5f42a39c91a0)

                // Fast partial round 13
                fast_partial_round(base, 0x83079fa4ecf20d7e, 0x22365051b78a5b654143cb32d39ac3d9cfff421583896e223d4eab2b8ef5f796, 0x3fc83d3038c86417a44cf1cb33e37165d9dd36fba77522ab6f7fd010d027c9b6, 0x0000000000000000db5eadbbec18de5dce1320f10ab80fe2c4588d418e88d270, 0x31e6a4bdb6a49017f6c705da84d573105b848442237e8a9b7de38bae084da92d, 0x5f5894f4057d755ebac3fa75ee26f2990e4a205459692a1b889489706e5c5c0f, 0x000000000000000004f78fd8c1fdcc5f5e34d8554a6452bab0dc3ecd724bb076)

                // Fast partial round 14
                fast_partial_round(base, 0x650b838edfcc4ad3, 0x19557d34b55551be0fce6f70303f230421cea4aa3d3ed9491183dfce7c454afd, 0xf318c785dc9e0479bad66d423d2ec861a1e920844334f9444c56f689afc5bbc9, 0x0000000000000000e1197454db2e0dd9400ccc9906d66f4599e2032e765ddd81, 0xd5177029fe49516692a29a3675a5d2bedb79ba02704620e94dd19c38779512ea, 0x3301d3362a4ffccbe1c48b26e0d98825251c4a3eb2c5f8fdd32b3298a13330c1, 0x000000000000000060192d883e473feedc05b676564f538a09bb6c88de8cd178)

                // Fast partial round 15
                fast_partial_round(base, 0x77180c88583c76ac, 0xc756f17fb59be595335856bb527b52f4d8af8b9ceb4e11b684d1ecc4d53d2ff1, 0xd7009f0f103be41314fc8b5b3b8091279e9a46b61f2ea942c0654e4ea5553a78, 0x0000000000000000e80a7cde3d4ac526a74e888922085ed73e0ee7b7a9fb4601, 0x0178928152e109aea86e9cf5050724913cb8411e786d3c8e16b9774801ac44a0, 0x4bd545218c59f58dcb97dedecebee9adda20b3be7f53d59f5317b905a6e1ab7b, 0x00000000000000007e5217af969952c287948589e4f243fd77dc8d856c05a44a)

                // Fast partial round 16
                fast_partial_round(base, 0xaf8c20753143a180, 0x217e4f04e5718dc9c7db3817870c5eda9137a5c630bad4b4238aa6daa612186d, 0x3c7835fb85bca2d37bb36ef70b6b9482e3292e7ab770a8bacae814e2817bd99d, 0x0000000000000000eab75ca7c918e4ef61b3915ad7274b20fe2cdf8ee3c25e86, 0x3aace640a3e03990a3c4711b938c02c00b5d420244c9cae3bc58987d06a84e4d, 0x045322b216ec3ec76eacb905beb7e2f88d00b2a7dbed06c7865a0f3249aacd8a, 0x0000000000000000f555f4112b19781f088c5f20df9e5c26eb9de00d594828e6)

                // Fast partial round 17
                fast_partial_round(base, 0xb8ccfe9989a39175, 0xdc9d2e07830ba226fbb1196092bf409cec67881f381a32bfd6e15ffc055e154e, 0x7aebfea95ccdd1c97a5d9bea6ca4910e194fae2974f8b5760698ef3245ff7988, 0x0000000000000000f0dfcbe7653ff787fa65539de65492d8f9bd38a67d5f0e86, 0xfaf322786e2abe8bf1cb02417e23bd8250dcaee0fd27d164a8cedbff1813d3a7, 0x0e7946317a6b4e997d66c4368b3c497b1b18992921a11d85937a4315beb5d9b6, 0x0000000000000000a671690d8095ce823771e82493ab262dbe4430134182978b)

                // Fast partial round 18
                fast_partial_round(base, 0x954a1729f60cc9c5, 0x0ac6fc58b3f0518f0c00ad377a1e26660ad8617bca9e33c80bd87ad390420258, 0x0c8be4920cbd4a540b73630dbb46ca180c210accb117bc210c0cc8a892cc4173, 0x00000000000000000bf50db2f8d6ce310ae790559b0ded810bfe877a21be1690, 0x287bf9177372cf45cb201cf846db4ba3ba1579c7e219b954b035585f6e929d9d, 0xe1e66c991990e2822e166aa6c776ed21d5d0ecfb50bcff99a350e4f61147d0a6, 0x0000000000000000cbabf78f97f95e658aa674b36144d9a9662b329b01e7bb38)

                // Fast partial round 19
                fast_partial_round(base, 0xdeb5b550c4dca53b, 0x000bc792d5c394ef000d1dc8aa81fb26000bd9b3cf49eec8000cf29427ff7c58, 0x000db5ebd48fc0d4000c84128cfed618000d413f12c496c1000d2ae0b2266453, 0x0000000000000000000d10e5b22b11d1000beb0ccc145421000d1b77326dcb90, 0xb9173f13977109a1efe9c6fa4311ad51c8a7aa07c5633533eec24b15a06b53fe, 0xccfc5f7de5c3636a28625def198c33c7ecf623c9cd11881569ce43c9cc94aedc, 0x0000000000000000a868ea113387939fcec0e58c34cb64b1f5e6c40f1621c299)

                // Fast partial round 20
                fast_partial_round(base, 0xf01bb0b00f77011e, 0x00000cde5fd7e04f00000e580cbf696600000cf389ed4bc800000e24c99adad8, 0x00000efb14cac55400000dabe78f6d9800000e7e81a8736100000e63628041b3, 0x000000000000000000000e4690c96af100000d05709f42c100000e5574743b10, 0x9e65309f15943903146bb3c0fe499ac0acfc51de8131458cd8dddbdc5ce4ef45, 0x0dfdc7fd6fc74f66e4626620a75ba276f97817d4ddbf060780d0ad980773aa70, 0x0000000000000000dd8de62487c4092502d55e52a5d44414f464864ad6f2bb93)

                // Fast partial round 21
                fast_partial_round(base, 0xa1ebb404b676afd9, 0x0000000e0d127e2f0000000fa65811e60000000e3006d9480000000f7157bc98, 0x00000010685627540000000eed6461d80000000fd002d9010000000fc18bfe53, 0x00000000000000000000000fa460f6d10000000e3af13ee10000000fa0236f50, 0x2599c5ead81d8fa333f62042e2f80225cbfdcf39869719d4c15acf44759545a3, 0xa1b67f09d4b3ccb8e8d1b2b21b41429c658c80d3df3729b10b306cb6c1d7c8d0, 0x0000000000000000a023d94c56e151c70d593a5e584af47b0e1adf8b84437180)

                // Fast partial round 22
                fast_partial_round(base, 0x860b6e1597a0173e, 0x000000000f848f4f0000000011050f86000000000f56d5880000000011131738, 0x0000000011e2ca9400000000106f2f3800000000114369a100000000111527d3, 0x00000000000000000000000010f625d1000000000fa9f5c100000000110a29f0, 0x92c3c8275e105eeb0ab38c561e8850ffe06dff00ab25b91b49026cc3a4afc5a6, 0xa206f41b12c30415ee61766b889e18f23c0468236ea142f6b65256e546889bd0, 0x00000000000000001ffea9fe85a0b0b1e9633210630cbf1202fe9d756c9f12d1)

                // Fast partial round 23
                fast_partial_round(base, 0x308bb65a036acbce, 0x000000000010cf7f0000000000134a96000000000010b6c8000000000011f718, 0x0000000000132c940000000000117c58000000000013f8a10000000000124d03, 0x00000000000000000000000000128961000000000010a0910000000000134fc0, 0x0b0a6b70915178c3ed446b2315e3efc1f4c77a079a4607d781d1ae8cc50240f3, 0xa2df8c6b8ae0804a65d74e2f43b48d051d4dba0b7ae9cc18b11ff3e089f15d9a, 0x0000000000000000a6b6582c547d0d60c0a26efc7be5669ba4e6f0a8c33348a6)

                // Fast partial round 24
                fast_partial_round(base, 0x1aca78f31c97c876, 0x000000000000131f000000000000114e00000000000017500000000000001300, 0x000000000000182c00000000000012300000000000001371000000000000167b, 0x000000000000000000000000000015c90000000000000f310000000000001368, 0x0bb005236adb9ef2de682d72da0a02d92f8f43734fc906f384afc741f1c13213, 0xcbaf4e5d82856c6052f515f44785cfbc0739a8a3439500105bdf35c10a8b5624, 0x00000000000000001a37905d8450904a8f0fa011a2035fb0ac9ea09074e3e150)

                // Fast partial round 25
                fast_partial_round(base, 0x0000000000000000, 0x0000000000000027000000000000001200000000000000220000000000000014, 0x0000000000000002000000000000001c000000000000000d000000000000000d, 0x0000000000000000000000000000000f00000000000000290000000000000010, 0x9daf69ae1b67e667075a652d9641a9859d19c9dd4eac41333abeb80def61cc85, 0x2f885e584e04aa99f223d1180dbbf3fc50bd769f745c95b1364f71da77920a18, 0x00000000000000000bc051640145b19b09584acaa6e062a0b69a0fa70aea684a)


                // ── Round 26 (full) ──
                mstore(base, sbox7(add(mload(base), 0x475cd3205a3bdcde)))
                mstore(add(base, 0x20), sbox7(add(mulmod(mload(add(base, 0x20)), 1, 0xFFFFFFFF00000001), 0x18a42105c31b7e88)))
                mstore(add(base, 0x40), sbox7(add(mulmod(mload(add(base, 0x40)), 1, 0xFFFFFFFF00000001), 0x023e7414af663068)))
                mstore(add(base, 0x60), sbox7(add(mulmod(mload(add(base, 0x60)), 1, 0xFFFFFFFF00000001), 0x15147108121967d7)))
                mstore(add(base, 0x80), sbox7(add(mulmod(mload(add(base, 0x80)), 1, 0xFFFFFFFF00000001), 0xe4a3dff1d7d6fef9)))
                mstore(add(base, 0xa0), sbox7(add(mulmod(mload(add(base, 0xa0)), 1, 0xFFFFFFFF00000001), 0x01a8d1a588085737)))
                mstore(add(base, 0xc0), sbox7(add(mulmod(mload(add(base, 0xc0)), 1, 0xFFFFFFFF00000001), 0x11b4c74eda62beef)))
                mstore(add(base, 0xe0), sbox7(add(mulmod(mload(add(base, 0xe0)), 1, 0xFFFFFFFF00000001), 0xe587cc0d69a73346)))
                mstore(add(base, 0x100), sbox7(add(mulmod(mload(add(base, 0x100)), 1, 0xFFFFFFFF00000001), 0x1ff7327017aa2a6e)))
                mstore(add(base, 0x120), sbox7(add(mulmod(mload(add(base, 0x120)), 1, 0xFFFFFFFF00000001), 0x594e29c42473d06b)))
                mstore(add(base, 0x140), sbox7(add(mulmod(mload(add(base, 0x140)), 1, 0xFFFFFFFF00000001), 0xf6f31db1899b12d5)))
                mstore(add(base, 0x160), sbox7(add(mulmod(mload(add(base, 0x160)), 1, 0xFFFFFFFF00000001), 0xc02ac5e47312d3ca)))
                mds(base)

                // ── Round 27 (full) ──
                mstore(base, sbox7(add(mload(base), 0xe70201e960cb78b8)))
                mstore(add(base, 0x20), sbox7(add(mload(add(base, 0x20)), 0x6f90ff3b6a65f108)))
                mstore(add(base, 0x40), sbox7(add(mload(add(base, 0x40)), 0x42747a7245e7fa84)))
                mstore(add(base, 0x60), sbox7(add(mload(add(base, 0x60)), 0xd1f507e43ab749b2)))
                mstore(add(base, 0x80), sbox7(add(mload(add(base, 0x80)), 0x1c86d265f15750cd)))
                mstore(add(base, 0xa0), sbox7(add(mload(add(base, 0xa0)), 0x3996ce73dd832c1c)))
                mstore(add(base, 0xc0), sbox7(add(mload(add(base, 0xc0)), 0x8e7fba02983224bd)))
                mstore(add(base, 0xe0), sbox7(add(mload(add(base, 0xe0)), 0xba0dec7103255dd4)))
                mstore(add(base, 0x100), sbox7(add(mload(add(base, 0x100)), 0x9e9cbd781628fc5b)))
                mstore(add(base, 0x120), sbox7(add(mload(add(base, 0x120)), 0xdae8645996edd6a5)))
                mstore(add(base, 0x140), sbox7(add(mload(add(base, 0x140)), 0xdebe0853b1a1d378)))
                mstore(add(base, 0x160), sbox7(add(mload(add(base, 0x160)), 0xa49229d24d014343)))
                mds(base)

                // ── Round 28 (full) ──
                mstore(base, sbox7(add(mload(base), 0x7be5b9ffda905e1c)))
                mstore(add(base, 0x20), sbox7(add(mload(add(base, 0x20)), 0xa3c95eaec244aa30)))
                mstore(add(base, 0x40), sbox7(add(mload(add(base, 0x40)), 0x0230bca8f4df0544)))
                mstore(add(base, 0x60), sbox7(add(mload(add(base, 0x60)), 0x4135c2bebfe148c6)))
                mstore(add(base, 0x80), sbox7(add(mload(add(base, 0x80)), 0x166fc0cc438a3c72)))
                mstore(add(base, 0xa0), sbox7(add(mload(add(base, 0xa0)), 0x3762b59a8ae83efa)))
                mstore(add(base, 0xc0), sbox7(add(mload(add(base, 0xc0)), 0xe8928a4c89114750)))
                mstore(add(base, 0xe0), sbox7(add(mload(add(base, 0xe0)), 0x2a440b51a4945ee5)))
                mstore(add(base, 0x100), sbox7(add(mload(add(base, 0x100)), 0x80cefd2b7d99ff83)))
                mstore(add(base, 0x120), sbox7(add(mload(add(base, 0x120)), 0xbb9879c6e61fd62a)))
                mstore(add(base, 0x140), sbox7(add(mload(add(base, 0x140)), 0x6e7c8f1a84265034)))
                mstore(add(base, 0x160), sbox7(add(mload(add(base, 0x160)), 0x164bb2de1bbeddc8)))
                mds(base)

                // ── Round 29 (full) ──
                mstore(base, sbox7(add(mload(base), 0xf3c12fe54d5c653b)))
                mstore(add(base, 0x20), sbox7(add(mload(add(base, 0x20)), 0x40b9e922ed9771e2)))
                mstore(add(base, 0x40), sbox7(add(mload(add(base, 0x40)), 0x551f5b0fbe7b1840)))
                mstore(add(base, 0x60), sbox7(add(mload(add(base, 0x60)), 0x25032aa7c4cb1811)))
                mstore(add(base, 0x80), sbox7(add(mload(add(base, 0x80)), 0xaaed34074b164346)))
                mstore(add(base, 0xa0), sbox7(add(mload(add(base, 0xa0)), 0x8ffd96bbf9c9c81d)))
                mstore(add(base, 0xc0), sbox7(add(mload(add(base, 0xc0)), 0x70fc91eb5937085c)))
                mstore(add(base, 0xe0), sbox7(add(mload(add(base, 0xe0)), 0x7f795e2a5f915440)))
                mstore(add(base, 0x100), sbox7(add(mload(add(base, 0x100)), 0x4543d9df5476d3cb)))
                mstore(add(base, 0x120), sbox7(add(mload(add(base, 0x120)), 0xf172d73e004fc90d)))
                mstore(add(base, 0x140), sbox7(add(mload(add(base, 0x140)), 0xdfd1c4febcc81238)))
                mstore(add(base, 0x160), sbox7(add(mload(add(base, 0x160)), 0xbc8dfb627fe558fc)))
                mds(base)

            // ── Pack output ──────────────────────────────────────
            // MDS reduction via mulmod(v, 1, P) produces canonical values (< P).
            // No gl_canon step needed.
            digest := or(or(or(
                mload(base),
                shl(64, mload(add(base, 0x20)))),
                shl(128, mload(add(base, 0x40)))),
                shl(192, mload(add(base, 0x60))))
        }
    }
}
