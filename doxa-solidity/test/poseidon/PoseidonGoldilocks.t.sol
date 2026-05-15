// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PoseidonGoldilocks} from "../../src/PoseidonGoldilocks.sol";

contract PoseidonGoldilocksTest is Test {
    PoseidonGoldilocks poseidon;

    function setUp() public {
        poseidon = new PoseidonGoldilocks();
    }

    /// @dev Test vector 1: all zeros → matches plonky2 compress([0,0,0,0], [0,0,0,0])
    function test_compress_zeros() public view {
        uint256 left  = 0x0;
        uint256 right = 0x0;
        uint256 expected = 0xc71603f33a1144ca7953db0ab48808f4c4055e3364a246c33c18a9786cb0b359;
        uint256 result = poseidon.compress(left, right);
        assertEq(result, expected, "compress(zeros) mismatch");
    }

    /// @dev Test vector 2: sequential [0,1,2,3] x [4,5,6,7]
    function test_compress_sequential() public view {
        uint256 left  = 0x0000000000000003000000000000000200000000000000010000000000000000;
        uint256 right = 0x0000000000000007000000000000000600000000000000050000000000000004;
        uint256 expected = 0xc4221df46aa44e4cf624fcbf98c9e7367ec080e2b7f39736eff81bb29a227619;
        uint256 result = poseidon.compress(left, right);
        assertEq(result, expected, "compress(sequential) mismatch");
    }

    /// @dev Test vector 3: all (p-1) elements
    function test_compress_max() public view {
        uint256 P_MINUS_1 = 0xFFFFFFFF00000000;
        uint256 left  = P_MINUS_1 | (P_MINUS_1 << 64) | (P_MINUS_1 << 128) | (P_MINUS_1 << 192);
        uint256 right = left;
        uint256 expected = 0x284dc652ec4da28df022f6e7464a2385794ba7d81197cb29dfd14cb3a924a57f;
        uint256 result = poseidon.compress(left, right);
        assertEq(result, expected, "compress(max) mismatch");
    }

    /// @dev Test vector 4: large random values from plonky2 test suite
    function test_compress_random() public view {
        uint256 left  = 0xdcc0630a3ab8b1b890f7e1a9e658446ac2af59ee9ec499708ccbbbea4fe5d2b7;
        uint256 right = 0xeb09d654690b6c8848452b17a70fbee35d99a7ca0c44ecfb7ff8256bca20588c;
        uint256 expected = 0x580f10f419a35ad14953718928462cd7c0c854a5893755dc1da1634603812793;
        uint256 result = poseidon.compress(left, right);
        assertEq(result, expected, "compress(random) mismatch");
    }

    /// @dev Smoke-test: compress output elements are all < P
    function test_compress_output_canonical() public view {
        uint256 P = 0xFFFFFFFF00000001;
        uint256 result = poseidon.compress(42, 99);
        uint256 el0 = result & 0xFFFFFFFFFFFFFFFF;
        uint256 el1 = (result >> 64) & 0xFFFFFFFFFFFFFFFF;
        uint256 el2 = (result >> 128) & 0xFFFFFFFFFFFFFFFF;
        uint256 el3 = result >> 192;
        assertTrue(el0 < P, "el0 not canonical");
        assertTrue(el1 < P, "el1 not canonical");
        assertTrue(el2 < P, "el2 not canonical");
        assertTrue(el3 < P, "el3 not canonical");
    }

    /// @dev Gas benchmark (single call)
    function test_compress_gas() public {
        uint256 left  = 0x0000000000000003000000000000000200000000000000010000000000000000;
        uint256 right = 0x0000000000000007000000000000000600000000000000050000000000000004;
        uint256 gasBefore = gasleft();
        poseidon.compress(left, right);
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("compress gas", gasUsed);
    }

    /// @dev Gas benchmark: 64 chained calls (simulates Merkle path)
    function test_compress_gas_64x() public {
        uint256 h = 0x0000000000000003000000000000000200000000000000010000000000000000;
        uint256 sibling = 0x0000000000000007000000000000000600000000000000050000000000000004;
        uint256 gasBefore = gasleft();
        for (uint256 i = 0; i < 64; i++) {
            h = poseidon.compress(h, sibling);
        }
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("64x compress total", gasUsed);
        emit log_named_uint("64x compress avg", gasUsed / 64);
    }
}
