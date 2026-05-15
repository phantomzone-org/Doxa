// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
import {PoseidonGoldilocks} from "../src/PoseidonGoldilocks.sol";
contract TestCompress is Test {
    function test_compress_zero() public {
        PoseidonGoldilocks p = new PoseidonGoldilocks();
        uint256 r = p.compress(0, 0);
        emit log_named_uint("compress(0,0)", r);
        // depth 2
        uint256 r2 = p.compress(r, r);
        emit log_named_uint("compress(r,r)", r2);
    }
}
