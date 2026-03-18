// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {TesseraRollupV2} from "./TesseraRollupV2.sol";

interface IERC20Allowance {
    function allowance(address owner, address spender) external view returns (uint256);
}

interface IERC20Permit {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}

/// @notice Toy user that atomically transfers tokens and records deposit.
contract ToyUser {
    /// @notice Bridge that owns deposit state and escrow.
    TesseraRollupV2 public immutable BRIDGE;
    /// @notice Monitored token used by the bridge.
    IERC20Allowance public immutable TOKEN;

    error InsufficientBridgeAllowance(uint256 current, uint256 required);

    /// @param _bridge Deployed bridge address.
    /// @param _token Monitored token address.
    constructor(address _bridge, address _token) {
        BRIDGE = TesseraRollupV2(_bridge);
        TOKEN = IERC20Allowance(_token);
    }

    /// @notice Returns the spender address users must approve on the ERC20.
    function bridgeSpender() external view returns (address) {
        return address(BRIDGE);
    }

    /// @notice Returns current user allowance granted to bridge.
    function bridgeAllowanceOf(address owner) external view returns (uint256) {
        return TOKEN.allowance(owner, address(BRIDGE));
    }

    /// @notice Delegates deposit creation to bridge for the calling user.
    /// @param noteCommitment Unique note commitment key.
    /// @param amount Max amount requested by user for bridge `transferFrom`.
    /// @return The created note commitment.
    /// @dev User must approve the bridge token allowance before calling.
    function depositAndRecord(bytes32 noteCommitment, uint256 amount) external returns (bytes32) {
        uint256 currentAllowance = TOKEN.allowance(msg.sender, address(BRIDGE));
        if (currentAllowance < amount) revert InsufficientBridgeAllowance(currentAllowance, amount);
        return BRIDGE.depositAndRegisterFor(noteCommitment, msg.sender, amount);
    }

    /// @notice One-transaction "permit + deposit" flow for tokens that support EIP-2612.
    /// @dev Calls `permit(owner=msg.sender, spender=bridge, value=amount, ...)` then deposits.
    function depositAndRecordWithPermit(
        bytes32 noteCommitment,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bytes32) {
        IERC20Permit(address(TOKEN)).permit(msg.sender, address(BRIDGE), amount, deadline, v, r, s);
        return BRIDGE.depositAndRegisterFor(noteCommitment, msg.sender, amount);
    }
}
