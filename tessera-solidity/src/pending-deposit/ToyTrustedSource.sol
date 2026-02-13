// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {DepositsRollupBridge} from "./DepositsRollupBridge.sol";

interface IERC20TransferFrom {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

/// @notice Toy trusted source that atomically transfers tokens and records deposit.
contract ToyTrustedSource {
    DepositsRollupBridge public immutable BRIDGE;
    IERC20TransferFrom public immutable TOKEN;

    error TransferFailed();

    constructor(address _bridge, address _token) {
        BRIDGE = DepositsRollupBridge(_bridge);
        TOKEN = IERC20TransferFrom(_token);
    }

    /// @notice In one call:
    ///         1) pull tokens from caller into bridge
    ///         2) record a deposit on bridge using note commitment
    function depositAndRecord(bytes32 noteCommitment, uint256 amount) external returns (bytes32) {
        bool ok = TOKEN.transferFrom(msg.sender, address(BRIDGE), amount);
        if (!ok) revert TransferFailed();
        return BRIDGE.recordDeposit(noteCommitment);
    }
}
