// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Poseidon hash over Goldilocks field — compress two packed HashOut values.
interface IPoseidonGoldilocksIMT {
    function compress(uint256 left, uint256 right) external pure returns (uint256);
}

/// @title IMTLib
/// @notice Library encapsulating the on-chain Poseidon Incremental Merkle Tree (IMT).
///
/// Usage:
///   1. Declare `IMTLib.IMTState public imt;` in your contract.
///   2. Call `imt.init(poseidon, treeDepth)` in your constructor.
///   3. Call `imt.appendLeaf(poseidon, treeDepth, leaf)` to insert leaves.
///
/// The IMTState struct holds all tree state via storage mappings so it can be
/// embedded in a parent contract without any proxy pattern.
library IMTLib {
    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    struct IMTState {
        uint256 leafCount;
        uint256 currentRoot;
        /// level => current left-sibling hash
        mapping(uint256 => uint256) filledSubtrees;
        /// level => zero-hash at that level
        mapping(uint256 => uint256) zeros;
        /// all previously confirmed tree roots
        mapping(uint256 => bool) confirmedRoots;
        /// batchPoseidonRoot => true once its batch is proven
        mapping(uint256 => bool) validatedBatchRoots;
        /// leafIndex => LE-packed GL batchPoseidonRoot
        mapping(uint256 => uint256) leaves;
    }

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    error IMT_TreeFull();

    // -------------------------------------------------------------------------
    // Initialisation
    // -------------------------------------------------------------------------

    /// @notice Builds the zeros chain and seeds filledSubtrees.
    ///         Must be called exactly once from the parent constructor.
    /// @param self       Storage pointer to the IMTState.
    /// @param poseidon   Deployed PoseidonGoldilocks contract.
    /// @param treeDepth  Depth of the Merkle tree (e.g. 20).
    function init(
        IMTState storage self,
        address poseidon,
        uint256 treeDepth
    ) internal {
        // zeros[0] = 0, zeros[i] = compress(zeros[i-1], zeros[i-1])
        self.zeros[0] = 0;
        for (uint256 i = 1; i <= treeDepth; i++) {
            self.zeros[i] = IPoseidonGoldilocksIMT(poseidon).compress(self.zeros[i - 1], self.zeros[i - 1]);
        }

        // Seed filledSubtrees with zero-hash at each level.
        for (uint256 i = 0; i < treeDepth; i++) {
            self.filledSubtrees[i] = self.zeros[i];
        }

        // Genesis root = root of an all-zero tree.
        self.currentRoot = self.zeros[treeDepth];
        self.confirmedRoots[self.currentRoot] = true;
    }

    // -------------------------------------------------------------------------
    // Append
    // -------------------------------------------------------------------------

    /// @notice Standard IMT append. O(treeDepth) Poseidon calls.
    ///         Stores the new root in confirmedRoots and persists the raw leaf.
    /// @param self       Storage pointer to the IMTState.
    /// @param poseidon   Deployed PoseidonGoldilocks contract.
    /// @param treeDepth  Depth of the Merkle tree.
    /// @param leaf       LE-packed GL uint256 leaf value to insert.
    function appendLeaf(
        IMTState storage self,
        address poseidon,
        uint256 treeDepth,
        uint256 leaf
    ) internal {
        if (self.leafCount >= (uint256(1) << treeDepth)) revert IMT_TreeFull();

        self.leaves[self.leafCount] = leaf;
        self.validatedBatchRoots[leaf] = true;

        uint256 node = leaf;
        for (uint256 i = 0; i < treeDepth; i++) {
            if ((self.leafCount >> i) & 1 == 0) {
                // Current node is a left child: cache it and pair with zero sibling.
                self.filledSubtrees[i] = node;
                node = IPoseidonGoldilocksIMT(poseidon).compress(node, self.zeros[i]);
            } else {
                // Current node is a right child: pair with cached left sibling.
                node = IPoseidonGoldilocksIMT(poseidon).compress(self.filledSubtrees[i], node);
            }
        }
        self.leafCount++;
        self.currentRoot = node;
        self.confirmedRoots[node] = true;
    }
}
