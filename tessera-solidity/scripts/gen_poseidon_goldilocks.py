#!/usr/bin/env python3
"""Generate PoseidonGoldilocks.sol with fully unrolled inline assembly.

Strategy:
- Single assembly block, no Solidity overhead
- Round constants as inline PUSH immediates (no memory array allocation)
- Yul helper functions for sbox7, mds, and the fast partial-round path
- State lives in memory at a fixed base pointer
- Full rounds are unrolled with hardcoded constants
- Partial rounds use Plonky2's fast Goldilocks decomposition with packed immediates
- MDS uses 3-packed coefficients: pack 3 row outputs per u256 at offsets 0/86/172
  to cut MUL count from 144 to 48 per round
"""

from poseidon_goldilocks_fast_partial_constants import (
    FAST_PARTIAL_FIRST_ROUND_CONSTANT,
    FAST_PARTIAL_ROUND_CONSTANTS,
    FAST_PARTIAL_ROUND_INITIAL_MATRIX,
    FAST_PARTIAL_ROUND_VS,
    FAST_PARTIAL_ROUND_W_HATS,
)

# fmt: off
# ALL_ROUND_CONSTANTS from plonky2/src/hash/poseidon.rs (360 u64 values)
RC = [
    0xb585f766f2144405, 0x7746a55f43921ad7, 0xb2fb0d31cee799b4, 0x0f6760a4803427d7,
    0xe10d666650f4e012, 0x8cae14cb07d09bf1, 0xd438539c95f63e9f, 0xef781c7ce35b4c3d,
    0xcdc4a239b0c44426, 0x277fa208bf337bff, 0xe17653a29da578a1, 0xc54302f225db2c76,
    0x86287821f722c881, 0x59cd1a8a41c18e55, 0xc3b919ad495dc574, 0xa484c4c5ef6a0781,
    0x308bbd23dc5416cc, 0x6e4a40c18f30c09c, 0x9a2eedb70d8f8cfa, 0xe360c6e0ae486f38,
    0xd5c7718fbfc647fb, 0xc35eae071903ff0b, 0x849c2656969c4be7, 0xc0572c8c08cbbbad,
    0xe9fa634a21de0082, 0xf56f6d48959a600d, 0xf7d713e806391165, 0x8297132b32825daf,
    0xad6805e0e30b2c8a, 0xac51d9f5fcf8535e, 0x502ad7dc18c2ad87, 0x57a1550c110b3041,
    0x66bbd30e6ce0e583, 0x0da2abef589d644e, 0xf061274fdb150d61, 0x28b8ec3ae9c29633,
    0x92a756e67e2b9413, 0x70e741ebfee96586, 0x019d5ee2af82ec1c, 0x6f6f2ed772466352,
    0x7cf416cfe7e14ca1, 0x61df517b86a46439, 0x85dc499b11d77b75, 0x4b959b48b9c10733,
    0xe8be3e5da8043e57, 0xf5c0bc1de6da8699, 0x40b12cbf09ef74bf, 0xa637093ecb2ad631,
    0x3cc3f892184df408, 0x2e479dc157bf31bb, 0x6f49de07a6234346, 0x213ce7bede378d7b,
    0x5b0431345d4dea83, 0xa2de45780344d6a1, 0x7103aaf94a7bf308, 0x5326fc0d97279301,
    0xa9ceb74fec024747, 0x27f8ec88bb21b1a3, 0xfceb4fda1ded0893, 0xfac6ff1346a41675,
    0x7131aa45268d7d8c, 0x9351036095630f9f, 0xad535b24afc26bfb, 0x4627f5c6993e44be,
    0x645cf794b8f1cc58, 0x241c70ed0af61617, 0xacb8e076647905f1, 0x3737e9db4c4f474d,
    0xe7ea5e33e75fffb6, 0x90dee49fc9bfc23a, 0xd1b1edf76bc09c92, 0x0b65481ba645c602,
    0x99ad1aab0814283b, 0x438a7c91d416ca4d, 0xb60de3bcc5ea751c, 0xc99cab6aef6f58bc,
    0x69a5ed92a72ee4ff, 0x5e7b329c1ed4ad71, 0x5fc0ac0800144885, 0x32db829239774eca,
    0x0ade699c5830f310, 0x7cc5583b10415f21, 0x85df9ed2e166d64f, 0x6604df4fee32bcb1,
    0xeb84f608da56ef48, 0xda608834c40e603d, 0x8f97fe408061f183, 0xa93f485c96f37b89,
    0x6704e8ee8f18d563, 0xcee3e9ac1e072119, 0x510d0e65e2b470c1, 0xf6323f486b9038f0,
    0x0b508cdeffa5ceef, 0xf2417089e4fb3cbd, 0x60e75c2890d15730, 0xa6217d8bf660f29c,
    0x7159cd30c3ac118e, 0x839b4e8fafead540, 0x0d3f3e5e82920adc, 0x8f7d83bddee7bba8,
    0x780f2243ea071d06, 0xeb915845f3de1634, 0xd19e120d26b6f386, 0x016ee53a7e5fecc6,
    0xcb5fd54e7933e477, 0xacb8417879fd449f, 0x9c22190be7f74732, 0x5d693c1ba3ba3621,
    0xdcef0797c2b69ec7, 0x3d639263da827b13, 0xe273fd971bc8d0e7, 0x418f02702d227ed5,
    0x8c25fda3b503038c, 0x2cbaed4daec8c07c, 0x5f58e6afcdd6ddc2, 0x284650ac5e1b0eba,
    0x635b337ee819dab5, 0x9f9a036ed4f2d49f, 0xb93e260cae5c170e, 0xb0a7eae879ddb76d,
    0xd0762cbc8ca6570c, 0x34c6efb812b04bf5, 0x40bf0ab5fa14c112, 0xb6b570fc7c5740d3,
    0x5a27b9002de33454, 0xb1a5b165b6d2b2d2, 0x8722e0ace9d1be22, 0x788ee3b37e5680fb,
    0x14a726661551e284, 0x98b7672f9ef3b419, 0xbb93ae776bb30e3a, 0x28fd3b046380f850,
    0x30a4680593258387, 0x337dc00c61bd9ce1, 0xd5eca244c7a4ff1d, 0x7762638264d279bd,
    0xc1e434bedeefd767, 0x0299351a53b8ec22, 0xb2d456e4ad251b80, 0x3e9ed1fda49cea0b,
    0x2972a92ba450bed8, 0x20216dd77be493de, 0xadffe8cf28449ec6, 0x1c4dbb1c4c27d243,
    0x15a16a8a8322d458, 0x388a128b7fd9a609, 0x2300e5d6baedf0fb, 0x2f63aa8647e15104,
    0xf1c36ce86ecec269, 0x27181125183970c9, 0xe584029370dca96d, 0x4d9bbc3e02f1cfb2,
    0xea35bc29692af6f8, 0x18e21b4beabb4137, 0x1e3b9fc625b554f4, 0x25d64362697828fd,
    0x5a3f1bb1c53a9645, 0xdb7f023869fb8d38, 0xb462065911d4e1fc, 0x49c24ae4437d8030,
    0xd793862c112b0566, 0xaadd1106730d8feb, 0xc43b6e0e97b0d568, 0xe29024c18ee6fca2,
    0x5e50c27535b88c66, 0x10383f20a4ff9a87, 0x38e8ee9d71a45af8, 0xdd5118375bf1a9b9,
    0x775005982d74d7f7, 0x86ab99b4dde6c8b0, 0xb1204f603f51c080, 0xef61ac8470250ecf,
    0x1bbcd90f132c603f, 0x0cd1dabd964db557, 0x11a3ae5beb9d1ec9, 0xf755bfeea585d11d,
    0xa3b83250268ea4d7, 0x516306f4927c93af, 0xddb4ac49c9efa1da, 0x64bb6dec369d4418,
    0xf9cc95c22b4c1fcc, 0x08d37f755f4ae9f6, 0xeec49b613478675b, 0xf143933aed25e0b0,
    0xe4c5dd8255dfc622, 0xe7ad7756f193198e, 0x92c2318b87fff9cb, 0x739c25f8fd73596d,
    0x5636cac9f16dfed0, 0xdd8f909a938e0172, 0xc6401fe115063f5b, 0x8ad97b33f1ac1455,
    0x0c49366bb25e8513, 0x0784d3d2f1698309, 0x530fb67ea1809a81, 0x410492299bb01f49,
    0x139542347424b9ac, 0x9cb0bd5ea1a1115e, 0x02e3f615c38f49a1, 0x985d4f4a9c5291ef,
    0x775b9feafdcd26e7, 0x304265a6384f0f2d, 0x593664c39773012c, 0x4f0a2e5fb028f2ce,
    0xdd611f1000c17442, 0xd8185f9adfea4fd0, 0xef87139ca9a3ab1e, 0x3ba71336c34ee133,
    0x7d3a455d56b70238, 0x660d32e130182684, 0x297a863f48cd1f43, 0x90e0a736a751ebb7,
    0x549f80ce550c4fd3, 0x0f73b2922f38bd64, 0x16bf1f73fb7a9c3f, 0x6d1f5a59005bec17,
    0x02ff876fa5ef97c4, 0xc5cb72a2a51159b0, 0x8470f39d2d5c900e, 0x25abb3f1d39fcb76,
    0x23eb8cc9b372442f, 0xd687ba55c64f6364, 0xda8d9e90fd8ff158, 0xe3cbdc7d2fe45ea7,
    0xb9a8c9b3aee52297, 0xc0d28a5c10960bd3, 0x45d7ac9b68f71a34, 0xeeb76e397069e804,
    0x3d06c8bd1514e2d9, 0x9c9c98207cb10767, 0x65700b51aedfb5ef, 0x911f451539869408,
    0x7ae6849fbc3a0ec6, 0x3bb340eba06afe7e, 0xb46e9d8b682ea65e, 0x8dcf22f9a3b34356,
    0x77bdaeda586257a7, 0xf19e400a5104d20d, 0xc368a348e46d950f, 0x9ef1cd60e679f284,
    0xe89cd854d5d01d33, 0x5cd377dc8bb882a2, 0xa7b0fb7883eee860, 0x7684403ec392950d,
    0x5fa3f06f4fed3b52, 0x8df57ac11bc04831, 0x2db01efa1e1e1897, 0x54846de4aadb9ca2,
    0xba6745385893c784, 0x541d496344d2c75b, 0xe909678474e687fe, 0xdfe89923f6c9c2ff,
    0xece5a71e0cfedc75, 0x5ff98fd5d51fe610, 0x83e8941918964615, 0x5922040b47f150c1,
    0xf97d750e3dd94521, 0x5080d4c2b86f56d7, 0xa7de115b56c78d70, 0x6a9242ac87538194,
    0xf7856ef7f9173e44, 0x2265fc92feb0dc09, 0x17dfc8e4f7ba8a57, 0x9001a64209f21db8,
    0x90004c1371b893c5, 0xb932b7cf752e5545, 0xa0b1df81b6fe59fc, 0x8ef1dd26770af2c2,
    0x0541a4f9cfbeed35, 0x9e61106178bfc530, 0xb3767e80935d8af2, 0x0098d5782065af06,
    0x31d191cd5c1466c7, 0x410fefafa319ac9d, 0xbdf8f242e316c4ab, 0x9e8cd55b57637ed0,
    0xde122bebe9a39368, 0x4d001fd58f002526, 0xca6637000eb4a9f8, 0x2f2339d624f91f78,
    0x6d1a7918c80df518, 0xdf9a4939342308e9, 0xebc2151ee6c8398c, 0x03cc2ba8a1116515,
    0xd341d037e840cf83, 0x387cb5d25af4afcc, 0xbba2515f22909e87, 0x7248fe7705f38e47,
    0x4d61e56a525d225a, 0x262e963c8da05d3d, 0x59e89b094d220ec2, 0x055d5b52b78b9c5e,
    0x82b27eb33514ef99, 0xd30094ca96b7ce7b, 0xcf5cb381cd0a1535, 0xfeed4db6919e5a7c,
    0x41703f53753be59f, 0x5eeea940fcde8b6f, 0x4cd1f1b175100206, 0x4a20358574454ec0,
    0x1478d361dbbf9fac, 0x6f02dc07d141875c, 0x296a202ed8e556a2, 0x2afd67999bf32ee5,
    0x7acfd96efa95491d, 0x6798ba0c0abb2c6d, 0x34c6f57b26c92122, 0x5736e1bad206b5de,
    0x20057d2a0056521b, 0x3dea5bd5d0578bd7, 0x16e50d897d4634ac, 0x29bff3ecb9b7a6e3,
    0x475cd3205a3bdcde, 0x18a42105c31b7e88, 0x023e7414af663068, 0x15147108121967d7,
    0xe4a3dff1d7d6fef9, 0x01a8d1a588085737, 0x11b4c74eda62beef, 0xe587cc0d69a73346,
    0x1ff7327017aa2a6e, 0x594e29c42473d06b, 0xf6f31db1899b12d5, 0xc02ac5e47312d3ca,
    0xe70201e960cb78b8, 0x6f90ff3b6a65f108, 0x42747a7245e7fa84, 0xd1f507e43ab749b2,
    0x1c86d265f15750cd, 0x3996ce73dd832c1c, 0x8e7fba02983224bd, 0xba0dec7103255dd4,
    0x9e9cbd781628fc5b, 0xdae8645996edd6a5, 0xdebe0853b1a1d378, 0xa49229d24d014343,
    0x7be5b9ffda905e1c, 0xa3c95eaec244aa30, 0x0230bca8f4df0544, 0x4135c2bebfe148c6,
    0x166fc0cc438a3c72, 0x3762b59a8ae83efa, 0xe8928a4c89114750, 0x2a440b51a4945ee5,
    0x80cefd2b7d99ff83, 0xbb9879c6e61fd62a, 0x6e7c8f1a84265034, 0x164bb2de1bbeddc8,
    0xf3c12fe54d5c653b, 0x40b9e922ed9771e2, 0x551f5b0fbe7b1840, 0x25032aa7c4cb1811,
    0xaaed34074b164346, 0x8ffd96bbf9c9c81d, 0x70fc91eb5937085c, 0x7f795e2a5f915440,
    0x4543d9df5476d3cb, 0xf172d73e004fc90d, 0xdfd1c4febcc81238, 0xbc8dfb627fe558fc,
]
# fmt: on

assert len(RC) == 360
assert len(FAST_PARTIAL_FIRST_ROUND_CONSTANT) == 12
assert len(FAST_PARTIAL_ROUND_CONSTANTS) == 22
assert len(FAST_PARTIAL_ROUND_VS) == 22
assert len(FAST_PARTIAL_ROUND_W_HATS) == 22
assert len(FAST_PARTIAL_ROUND_INITIAL_MATRIX) == 11

GOLDILOCKS_P = 0xFFFFFFFF00000001

# MDS circulant + diagonal
CIRC = [17, 15, 41, 16, 2, 28, 13, 13, 39, 18, 34, 20]
DIAG = [8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

# 3-packing parameters
LANE_BITS = 86
LANE_MASK = (1 << LANE_BITS) - 1  # 86-bit mask

# Row groups for 3-packing: 12 rows → 4 groups of 3
ROW_GROUPS = [(0, 1, 2), (3, 4, 5), (6, 7, 8), (9, 10, 11)]


def mds_coeff(row, col):
    """M[row][col] = CIRC[(col - row) % 12] + (DIAG[row] if row == col else 0)"""
    return CIRC[(col - row) % 12] + (DIAG[row] if row == col else 0)


def packed_coeff(r1, r2, r3, col):
    """Pack 3 MDS coefficients for rows r1,r2,r3 at column col into one u256.

    Layout: M[r1][col] + M[r2][col] << 86 + M[r3][col] << 172
    """
    c1 = mds_coeff(r1, col)
    c2 = mds_coeff(r2, col)
    c3 = mds_coeff(r3, col)
    return c1 + (c2 << LANE_BITS) + (c3 << (2 * LANE_BITS))


ROUND0_CONST_SBOX = [pow(RC[i], 7, GOLDILOCKS_P) for i in range(8, 12)]


def round0_packed_const_contrib(r1, r2, r3):
    """Packed constant contribution from round-0 capacity lanes 8..11."""
    total = 0
    for col, value in zip(range(8, 12), ROUND0_CONST_SBOX):
        total += packed_coeff(r1, r2, r3, col) * value
    return total


def pack_u64_words(values):
    """Pack up to four u64 constants per word for cheap Yul callsites."""
    packed = []
    for i in range(0, len(values), 4):
        word = 0
        for j, value in enumerate(values[i : i + 4]):
            word |= value << (64 * j)
        packed.append(word)
    return packed


def indent(n):
    return "    " * n


def gen_helpers():
    """Generate Yul helper functions (sbox7).

    gl_reduce replaced by mulmod(v, 1, P) — single 8-gas opcode vs 30-gas
    shift/mask/add chain. mulmod gives canonical output (< P), eliminating
    the need for gl_canon at the end.
    """
    return """\

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
            }"""


def gen_mds_function():
    """Generate the MDS as a Yul function with 3-packed coefficients.

    The function encapsulates all 12 state loads, keeping them within a single
    function scope where the compiler can manage stack depth. The compiler
    decides whether to inline the function based on optimizer_runs.
    """
    mask_hex = f"0x{LANE_MASK:x}"

    lines = []
    lines.append("")
    lines.append("            // ── MDS layer (3-packed) ───────────────────────────")
    lines.append("            // M = circ(17,15,41,16,2,28,13,13,39,18,34,20) + diag(8,0,...,0)")
    lines.append(f"            // 3 rows packed per u256 at bit offsets 0/{LANE_BITS}/{2*LANE_BITS}")
    lines.append("            // 48 MUL + 44 ADD per round instead of 144 MUL + 132 ADD")
    lines.append("            function mds(base) {")

    # Load all 12 state elements
    for i in range(12):
        off = f"0x{i * 0x20:x}" if i > 0 else ""
        base_expr = f"add(base, {off})" if i > 0 else "base"
        lines.append(f"                let s{i} := mload({base_expr})")

    lines.append("")
    lines.append(f"                let mask86 := {mask_hex}")
    lines.append(f"                let P := 0xFFFFFFFF00000001")

    # For each group of 3 rows
    for gi, (r1, r2, r3) in enumerate(ROW_GROUPS):
        lines.append("")
        lines.append(f"                // Group {gi}: rows {r1}, {r2}, {r3}")

        for col in range(12):
            pc = packed_coeff(r1, r2, r3, col)
            pc_hex = f"0x{pc:x}"
            if col == 0:
                lines.append(f"                let acc{gi} := mul({pc_hex}, s{col})")
            else:
                lines.append(f"                acc{gi} := add(acc{gi}, mul({pc_hex}, s{col}))")

        off1 = f"0x{r1 * 0x20:x}" if r1 > 0 else ""
        off2 = f"0x{r2 * 0x20:x}"
        off3 = f"0x{r3 * 0x20:x}"
        base1 = f"add(base, {off1})" if r1 > 0 else "base"
        base2 = f"add(base, {off2})"
        base3 = f"add(base, {off3})"

        # mulmod(v, 1, P) = v mod P — single 8-gas opcode replaces 30-gas gl_reduce
        lines.append(f"                mstore({base1}, mulmod(and(acc{gi}, mask86), 1, P))")
        lines.append(f"                mstore({base2}, mulmod(and(shr({LANE_BITS}, acc{gi}), mask86), 1, P))")
        lines.append(f"                mstore({base3}, mulmod(shr({2 * LANE_BITS}, acc{gi}), 1, P))")

    lines.append("            }")
    return "\n".join(lines)


def gen_round0_function():
    """Generate a specialized round 0 helper.

    Capacity lanes 8..11 start at zero, so their add_rc + sbox outputs are
    constants. Fold those S-box outputs into the first MDS.
    """
    mask_hex = f"0x{LANE_MASK:x}"
    lines = []
    lines.append("")
    lines.append("            // ── Specialized round 0 ────────────────────────────")
    lines.append("            // Capacity lanes start at zero, so their add_rc + sbox outputs are constants.")
    lines.append("            function round0(base) {")
    for i in range(8):
        off = f"0x{i * 0x20:x}" if i > 0 else ""
        base_expr = f"add(base, {off})" if i > 0 else "base"
        lines.append(f"                let s{i} := sbox7(add(mload({base_expr}), 0x{RC[i]:016x}))")
    lines.append(f"                let mask86 := {mask_hex}")
    lines.append(f"                let P := 0x{GOLDILOCKS_P:x}")

    for gi, (r1, r2, r3) in enumerate(ROW_GROUPS):
        lines.append("")
        lines.append(f"                // Group {gi}: rows {r1}, {r2}, {r3}")
        lines.append(f"                let acc{gi} := 0x{round0_packed_const_contrib(r1, r2, r3):x}")
        for col in range(8):
            pc = packed_coeff(r1, r2, r3, col)
            lines.append(f"                acc{gi} := add(acc{gi}, mul(0x{pc:x}, s{col}))")

        off1 = f"0x{r1 * 0x20:x}" if r1 > 0 else ""
        off2 = f"0x{r2 * 0x20:x}"
        off3 = f"0x{r3 * 0x20:x}"
        base1 = f"add(base, {off1})" if r1 > 0 else "base"
        base2 = f"add(base, {off2})"
        base3 = f"add(base, {off3})"
        lines.append(f"                mstore({base1}, mulmod(and(acc{gi}, mask86), 1, P))")
        lines.append(f"                mstore({base2}, mulmod(and(shr({LANE_BITS}, acc{gi}), mask86), 1, P))")
        lines.append(f"                mstore({base3}, mulmod(shr({2 * LANE_BITS}, acc{gi}), 1, P))")

    lines.append("            }")
    return "\n".join(lines)


def gen_mds_partial_init_function():
    """Generate the initial linear transform for fast partial rounds."""
    lines = []
    lines.append("")
    lines.append("            // ── Fast partial-round initializer ──────────────────")
    lines.append("            // Transforms state[1..11] once before the 22-round fast path.")
    lines.append("            // Lanes 1..11 intentionally stay unreduced through the partial block.")
    lines.append("            function mds_partial_init(base) {")

    for i in range(1, 12):
        off = f"0x{i * 0x20:x}"
        lines.append(f"                let s{i} := mload(add(base, {off}))")

    for col in range(11):
        off = f"0x{(col + 1) * 0x20:x}"
        lines.append("                {")
        lines.append(f"                    let acc := mul(0x{FAST_PARTIAL_ROUND_INITIAL_MATRIX[0][col]:016x}, s1)")
        for row in range(1, 11):
            coeff = FAST_PARTIAL_ROUND_INITIAL_MATRIX[row][col]
            lines.append(f"                    acc := add(acc, mul(0x{coeff:016x}, s{row + 1}))")
        lines.append(f"                    mstore(add(base, {off}), acc)")
        lines.append("                }")

    lines.append("            }")
    return "\n".join(lines)


def gen_fast_partial_round_function():
    """Generate one generic fast partial-round helper using packed immediates."""
    lines = []
    lines.append("")
    lines.append("            // ── Fast partial round ──────────────────────────────")
    lines.append("            // state[0] is reduced every round for the x^7 S-box.")
    lines.append("            // state[1..11] remain lazy and are reduced once before full rounds resume.")
    lines.append("            function fast_partial_round(base, rc, v0, v1, v2, w0, w1, w2) {")
    lines.append("                let s0 := add(sbox7(mload(base)), rc)")
    lines.append("                let d := mul(25, s0)")
    lines.append("                let mask64 := 0xFFFFFFFFFFFFFFFF")
    lines.append("                let P := 0xFFFFFFFF00000001")

    for lane in range(1, 12):
        offset = f"0x{lane * 0x20:x}"
        pack_idx = (lane - 1) // 4
        shift = 64 * ((lane - 1) % 4)
        v_word = f"v{pack_idx}"
        w_word = f"w{pack_idx}"
        if shift == 0:
            v_expr = f"and({v_word}, mask64)"
            w_expr = f"and({w_word}, mask64)"
        else:
            v_expr = f"and(shr({shift}, {v_word}), mask64)"
            w_expr = f"and(shr({shift}, {w_word}), mask64)"
        lines.append("                {")
        lines.append(f"                    let si := mload(add(base, {offset}))")
        lines.append(f"                    d := add(d, mul(si, {w_expr}))")
        lines.append(f"                    mstore(add(base, {offset}), add(si, mul(s0, {v_expr})))")
        lines.append("                }")

    lines.append("                mstore(base, mulmod(d, 1, P))")
    lines.append("            }")
    return "\n".join(lines)


def gen_sbox_full_with_rc(round_num, lvl=4, reduce_nonzero_lanes=False):
    """Generate fused full-round add_rc + S-box.

    If reduce_nonzero_lanes is set, lanes 1..11 are canonicalized before the
    constant add. This is used for round 26 to consume the lazy partial lanes
    without paying a dedicated cleanup pass.
    """
    result = []
    p = indent(lvl)
    base = round_num * 12
    for i in range(12):
        rc = RC[base + i]
        off = f"0x{i * 0x20:x}" if i > 0 else ""
        base_expr = f"add(base, {off})" if i > 0 else "base"
        if reduce_nonzero_lanes and i > 0:
            input_expr = f"add(mulmod(mload({base_expr}), 1, 0xFFFFFFFF00000001), 0x{rc:016x})"
        else:
            input_expr = f"add(mload({base_expr}), 0x{rc:016x})"
        result.append(f"{p}mstore({base_expr}, sbox7({input_expr}))")
    return "\n".join(result)


def gen_round(round_num, lvl=4):
    """Generate one full round."""
    p = indent(lvl)
    result = [f"{p}// ── Round {round_num} (full) ──"]
    result.append(gen_sbox_full_with_rc(round_num, lvl, reduce_nonzero_lanes=(round_num == 26)))
    result.append(f"{p}mds(base)")
    return "\n".join(result)


def gen_partial_first_constant_layer(lvl=4):
    """Generate the transformed first constant layer for fast partial rounds."""
    result = []
    p = indent(lvl)
    for i, rc in enumerate(FAST_PARTIAL_FIRST_ROUND_CONSTANT):
        off = f"0x{i * 0x20:x}" if i > 0 else ""
        base_expr = f"add(base, {off})" if i > 0 else "base"
        result.append(f"{p}mstore({base_expr}, add(mload({base_expr}), 0x{rc:016x}))")
    return "\n".join(result)


def gen_fast_partial_round(round_num, lvl=4):
    """Generate one fast partial-round call with packed immediates."""
    packed_vs = pack_u64_words(FAST_PARTIAL_ROUND_VS[round_num])
    packed_ws = pack_u64_words(FAST_PARTIAL_ROUND_W_HATS[round_num])
    assert len(packed_vs) == 3
    assert len(packed_ws) == 3
    p = indent(lvl)
    return (
        f"{p}fast_partial_round("
        f"base, "
        f"0x{FAST_PARTIAL_ROUND_CONSTANTS[round_num]:016x}, "
        f"0x{packed_vs[0]:064x}, 0x{packed_vs[1]:064x}, 0x{packed_vs[2]:064x}, "
        f"0x{packed_ws[0]:064x}, 0x{packed_ws[1]:064x}, 0x{packed_ws[2]:064x}"
        f")"
    )


def gen_partial_round_block(lvl=4):
    """Generate the entire fast partial-round section."""
    p = indent(lvl)
    result = [
        f"{p}// ── Partial rounds (Plonky2 fast path) ──",
        f"{p}// Replace rounds 4..25 with the Goldilocks-specific fast decomposition.",
        gen_partial_first_constant_layer(lvl),
        f"{p}mds_partial_init(base)",
        "",
    ]
    for i in range(22):
        result.append(f"{p}// Fast partial round {4 + i}")
        result.append(gen_fast_partial_round(i, lvl))
        result.append("")
    return "\n".join(result)


def gen_contract():
    """Generate the full Solidity contract."""
    parts = []

    parts.append("""\
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
        assembly {""")

    # Helper functions
    parts.append(gen_helpers())

    # Yul helpers
    parts.append(gen_round0_function())
    parts.append(gen_mds_function())
    parts.append(gen_mds_partial_init_function())
    parts.append(gen_fast_partial_round_function())

    # State setup
    parts.append("""
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
""")

    # First four full rounds
    parts.append("            // ── Round 0 (full, specialized) ──")
    parts.append("            round0(base)")
    parts.append("")
    for r in range(1, 4):
        parts.append(gen_round(r))
        parts.append("")  # blank line between rounds

    # Partial round block
    parts.append(gen_partial_round_block())
    parts.append("")

    # Final four full rounds
    for r in range(26, 30):
        parts.append(gen_round(r))
        parts.append("")

    # Pack output — MDS outputs are already canonical (< P) via mulmod reduction
    parts.append("""\
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
""")

    return "\n".join(parts)


def verify_packed_safety():
    """Verify that 3-packed MDS multiplication is overflow-safe."""
    P = (1 << 64) - (1 << 32) + 1
    max_coeff = max(CIRC) + max(DIAG)
    max_element = 2 * P + (1 << 33)

    max_product = max_coeff * max_element
    print(f"Max single product:    2^{max_product.bit_length() - 1:.1f} (needs < 2^{LANE_BITS})")

    sum_coeffs = sum(mds_coeff(0, c) for c in range(12))
    max_acc = sum_coeffs * max_element
    print(f"Max accumulator/lane:  2^{max_acc.bit_length() - 1:.1f} (needs < 2^{LANE_BITS})")
    print(f"Gap to next lane:      {LANE_BITS - max_acc.bit_length()} bits")

    max_packed = max_coeff + (max_coeff << LANE_BITS) + (max_coeff << (2 * LANE_BITS))
    max_packed_product = max_packed * max_element
    print(f"Max packed*element:    2^{max_packed_product.bit_length() - 1:.1f} (needs < 2^256)")

    max_sum = 12 * max_packed * max_element
    print(f"Max sum of 12 packed:  2^{max_sum.bit_length() - 1:.1f} (needs < 2^256)")

    assert max_acc.bit_length() < LANE_BITS, "Lane overflow!"
    assert max_sum.bit_length() <= 256, "u256 overflow!"
    print("All overflow checks passed ✓")


def verify_fast_partial_safety():
    """Verify that lazy fast partial rounds stay within u256 bounds."""
    P = (1 << 64) - (1 << 32) + 1
    after_first_const = 2 * P

    init_lane_max = []
    for col in range(11):
        total = 0
        for row in range(11):
            total += after_first_const * FAST_PARTIAL_ROUND_INITIAL_MATRIX[row][col]
        init_lane_max.append(total)

    max_init_lane = max(init_lane_max)
    max_v = max(max(row) for row in FAST_PARTIAL_ROUND_VS)
    max_w = max(max(row) for row in FAST_PARTIAL_ROUND_W_HATS)

    lazy_lane_max = max_init_lane + len(FAST_PARTIAL_ROUND_CONSTANTS) * after_first_const * max_v
    d_max = 25 * after_first_const + 11 * lazy_lane_max * max_w

    print(f"Fast partial init lane: 2^{max_init_lane.bit_length() - 1:.1f} (needs < 2^256)")
    print(f"Fast partial lazy lane: 2^{lazy_lane_max.bit_length() - 1:.1f} (needs < 2^256)")
    print(f"Fast partial d sum:     2^{d_max.bit_length() - 1:.1f} (needs < 2^256)")

    assert max_init_lane.bit_length() <= 256, "partial-init overflow!"
    assert lazy_lane_max.bit_length() <= 256, "lazy lane overflow!"
    assert d_max.bit_length() <= 256, "fast partial accumulator overflow!"
    print("Fast partial overflow checks passed ✓")


if __name__ == "__main__":
    import sys
    import os

    # Verify safety before generating
    verify_packed_safety()
    print()
    verify_fast_partial_safety()
    print()

    if len(sys.argv) > 1:
        out_path = sys.argv[1]
    else:
        out_path = os.path.join(os.path.dirname(__file__), "..", "src", "PoseidonGoldilocks.sol")

    code = gen_contract()
    with open(out_path, "w") as f:
        f.write(code)
    print(f"Generated {out_path} ({len(code)} bytes, {code.count(chr(10))} lines)")
