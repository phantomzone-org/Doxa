// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Toy ERC20 used for local testing, with an operator allowed to mint.
contract ToyUSDT {
    string public constant name = "USDX";
    string public constant symbol = "USDX";
    uint8 public constant decimals = 6;

    // --- EIP-2612 permit (toy implementation) ---
    bytes32 public immutable DOMAIN_SEPARATOR;
    // keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
    bytes32 public constant PERMIT_TYPEHASH =
        0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;
    mapping(address => uint256) public nonces;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    address public immutable operator;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );

    error InsufficientBalance();
    error InsufficientAllowance();
    error PermitExpired();
    error InvalidPermitSignature();
    error Unauthorized();

    constructor(address _operator) {
        operator = _operator;
        // EIP-712 domain separator for `permit`.
        uint256 chainId = block.chainid;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes(name)),
                keccak256(bytes("1")),
                chainId,
                address(this)
            )
        );
    }

    function mint(address to, uint256 value) external {
        if (msg.sender != operator) revert Unauthorized();
        totalSupply += value;
        balanceOf[to] += value;
        emit Transfer(address(0), to, value);
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    /// @notice Sets `allowance[owner][spender] = value` via EIP-2612 signature.
    /// @dev This enables "approve + action" in a single transaction.
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        if (block.timestamp > deadline) revert PermitExpired();

        uint256 nonce = nonces[owner]++;
        bytes32 domainSep = DOMAIN_SEPARATOR;
        bytes32 structHash;
        assembly {
            let ptr := mload(0x40)
            mstore(
                ptr,
                0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9
            )
            mstore(add(ptr, 0x20), owner)
            mstore(add(ptr, 0x40), spender)
            mstore(add(ptr, 0x60), value)
            mstore(add(ptr, 0x80), nonce)
            mstore(add(ptr, 0xa0), deadline)
            structHash := keccak256(ptr, 0xc0)
        }
        bytes32 digest;
        assembly {
            let ptr := mload(0x40)
            mstore(
                ptr,
                0x1901000000000000000000000000000000000000000000000000000000000000
            )
            mstore(add(ptr, 0x02), domainSep)
            mstore(add(ptr, 0x22), structHash)
            digest := keccak256(ptr, 0x42)
        }

        address recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0) || recovered != owner)
            revert InvalidPermitSignature();

        allowance[owner][spender] = value;
        emit Approval(owner, spender, value);
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 value
    ) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed < value) revert InsufficientAllowance();
        allowance[from][msg.sender] = allowed - value;
        _transfer(from, to, value);
        return true;
    }

    function _transfer(address from, address to, uint256 value) internal {
        if (balanceOf[from] < value) revert InsufficientBalance();
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }
}
