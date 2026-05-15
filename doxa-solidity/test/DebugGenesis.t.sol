// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
import {PoseidonGoldilocks} from "../src/PoseidonGoldilocks.sol";
contract DebugGenesis is Test {
    function test_print_genesis() public {
        PoseidonGoldilocks p = new PoseidonGoldilocks();
        uint256 h = 0;
        for (uint256 i = 1; i <= 32; i++) {
            h = p.compress(h, h);
        }
        emit log_named_uint("genesis32", h);
    }
}
