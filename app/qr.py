"""A small QR Code generator — standard library only.

No `qrcode` package is available in this deployment, so the encoder is
implemented here: byte mode, error-correction level M, versions 1–10 (up to
213 bytes, which covers every crypto address we print).

The public entry point is `svg(text)` which returns a self-contained SVG
string — no network, no fonts, no third-party image service.
"""
from __future__ import annotations

from decimal import Decimal, ROUND_DOWN, InvalidOperation

# --- GF(256) arithmetic (primitive polynomial 0x11D) ------------------------

_EXP = [0] * 512
_LOG = [0] * 256


def _init_tables() -> None:
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_init_tables()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("GF(256) division by zero")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def _rs_generator(degree: int) -> list[int]:
    """Generator polynomial for `degree` error-correction codewords."""
    poly = [1]
    for i in range(degree):
        poly = _poly_mul(poly, [1, _EXP[i]])
    return poly


def _poly_mul(a: list[int], b: list[int]) -> list[int]:
    out = [0] * (len(a) + len(b) - 1)
    for i, av in enumerate(a):
        if av == 0:
            continue
        for j, bv in enumerate(b):
            out[i + j] ^= _gf_mul(av, bv)
    return out


def _rs_encode(data: list[int], ec_len: int) -> list[int]:
    """Reed-Solomon error-correction codewords for one block."""
    gen = _rs_generator(ec_len)
    remainder = [0] * ec_len
    for byte in data:
        factor = byte ^ remainder[0]
        remainder = remainder[1:] + [0]
        if factor:
            for i, g in enumerate(gen[1:]):
                remainder[i] ^= _gf_mul(g, factor)
    return remainder


# --- version tables (error-correction level M) ------------------------------

# version -> (ec codewords per block, [block data codeword counts])
VERSIONS: dict[int, tuple[int, list[int]]] = {
    1: (10, [16]),
    2: (16, [28]),
    3: (26, [44]),
    4: (18, [32, 32]),
    5: (24, [43, 43]),
    6: (16, [27, 27, 27, 27]),
    7: (18, [31, 31, 31, 31]),
    8: (22, [38, 38, 39, 39]),
    9: (22, [36, 36, 36, 37, 37]),
    10: (26, [43, 43, 43, 43, 44]),
}

ALIGNMENT_CENTERS: dict[int, list[int]] = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30],
    6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46],
    10: [6, 28, 50],
}

# version -> 18-bit version information (for versions 7 and up)
_VERSION_INFO = {
    7: 0x07C94, 8: 0x085BC, 9: 0x09A99, 10: 0x0A4D3,
}


def _size(version: int) -> int:
    return version * 4 + 17


def _data_capacity(version: int) -> int:
    ec, blocks = VERSIONS[version]
    total_data = sum(blocks)
    count_bits = 8 if version <= 9 else 16
    return total_data - 1 - (count_bits // 8)


def _pick_version(data_len: int) -> int:
    for version in sorted(VERSIONS):
        if data_len <= _data_capacity(version):
            return version
    raise ValueError(f"Data too long for a QR code: {data_len} bytes")


# --- bit stream ------------------------------------------------------------

def _build_codewords(data: bytes, version: int) -> list[int]:
    ec_len, blocks = VERSIONS[version]
    total_data = sum(blocks)
    count_bits = 8 if version <= 9 else 16

    bits: list[int] = []

    def push(value: int, length: int) -> None:
        for i in range(length - 1, -1, -1):
            bits.append((value >> i) & 1)

    push(0b0100, 4)                 # byte mode
    push(len(data), count_bits)     # character count
    for byte in data:
        push(byte, 8)

    # terminator
    capacity = total_data * 8
    push(0, min(4, capacity - len(bits)))

    # pad to a byte boundary
    while len(bits) % 8:
        bits.append(0)

    codewords = [int("".join(str(b) for b in bits[i:i + 8]), 2)
                 for i in range(0, len(bits), 8)]

    # pad codewords
    pads = [0xEC, 0x11]
    i = 0
    while len(codewords) < total_data:
        codewords.append(pads[i % 2])
        i += 1

    # split into blocks, compute ECC, then interleave
    data_blocks: list[list[int]] = []
    ec_blocks: list[list[int]] = []
    pos = 0
    for size in blocks:
        block = codewords[pos:pos + size]
        pos += size
        data_blocks.append(block)
        ec_blocks.append(_rs_encode(block, ec_len))

    out: list[int] = []
    max_data = max(len(b) for b in data_blocks)
    for i in range(max_data):
        for block in data_blocks:
            if i < len(block):
                out.append(block[i])
    max_ec = max(len(b) for b in ec_blocks)
    for i in range(max_ec):
        for block in ec_blocks:
            if i < len(block):
                out.append(block[i])
    return out


# --- matrix construction ----------------------------------------------------

def _new_matrix(version: int) -> list[list[int | None]]:
    size = _size(version)
    return [[None] * size for _ in range(size)]


def _place_finder(m: list[list[int | None]], row: int, col: int) -> None:
    for r in range(-1, 8):
        for c in range(-1, 8):
            rr, cc = row + r, col + c
            if not (0 <= rr < len(m) and 0 <= cc < len(m[rr])):
                continue
            if r in (0, 6) or c in (0, 6):
                m[rr][cc] = 1
            elif 2 <= r <= 4 and 2 <= c <= 4:
                m[rr][cc] = 1
            else:
                m[rr][cc] = 0


def _place_alignment(m: list[list[int | None]], row: int, col: int) -> None:
    for r in range(-2, 3):
        for c in range(-2, 3):
            if max(abs(r), abs(c)) != 1:
                m[row + r][col + c] = 1
            else:
                m[row + r][col + c] = 0


def _setup_function_patterns(m: list[list[int | None]], version: int) -> None:
    size = _size(version)
    _place_finder(m, 0, 0)
    _place_finder(m, 0, size - 7)
    _place_finder(m, size - 7, 0)

    # timing patterns
    for i in range(8, size - 8):
        m[6][i] = 1 if i % 2 == 0 else 0
        m[i][6] = 1 if i % 2 == 0 else 0

    # alignment patterns (skip the ones that collide with the finders)
    centers = ALIGNMENT_CENTERS[version]
    for r in centers:
        for c in centers:
            if (r, c) in ((6, 6), (6, size - 7), (size - 7, 6)):
                continue
            _place_alignment(m, r, c)

    # dark module
    m[size - 8][8] = 1

    # reserve the format-information area (filled in later)
    for i in range(9):
        if m[8][i] is None:
            m[8][i] = 0
        if m[i][8] is None:
            m[i][8] = 0
    for i in range(8):
        if m[8][size - 1 - i] is None:
            m[8][size - 1 - i] = 0
        if m[size - 1 - i][8] is None:
            m[size - 1 - i][8] = 0

    # version information
    if version >= 7:
        bits = _VERSION_INFO[version]
        for i in range(18):
            bit = (bits >> i) & 1
            r, c = i // 3, size - 11 + i % 3
            m[r][c] = bit
            m[c][r] = bit


def _reserved_mask(version: int) -> list[list[bool]]:
    """True where a module holds a function pattern (never data)."""
    size = _size(version)
    m = _new_matrix(version)
    _setup_function_patterns(m, version)
    return [[cell is not None for cell in row] for row in m]


def _place_data(m: list[list[int | None]], codewords: list[int]) -> None:
    size = len(m)
    bits: list[int] = []
    for cw in codewords:
        for i in range(7, -1, -1):
            bits.append((cw >> i) & 1)

    idx = 0
    upward = True
    col = size - 1
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for c in (col, col - 1):
                if m[row][c] is None:
                    if idx < len(bits):
                        m[row][c] = bits[idx]
                        idx += 1
                    else:
                        m[row][c] = 0
        upward = not upward
        col -= 2


_MASK_FUNCS = [
    lambda i, j: (i + j) % 2 == 0,
    lambda i, j: i % 2 == 0,
    lambda i, j: j % 3 == 0,
    lambda i, j: (i + j) % 3 == 0,
    lambda i, j: (i // 2 + j // 3) % 2 == 0,
    lambda i, j: (i * j) % 2 + (i * j) % 3 == 0,
    lambda i, j: ((i * j) % 2 + (i * j) % 3) % 2 == 0,
    lambda i, j: ((i + j) % 2 + (i * j) % 3) % 2 == 0,
]


def _apply_mask(m: list[list[int | None]], reserved: list[list[bool]],
                mask: int) -> list[list[int]]:
    fn = _MASK_FUNCS[mask]
    out: list[list[int]] = []
    for i, row in enumerate(m):
        new_row: list[int] = []
        for j, cell in enumerate(row):
            if cell is None:
                new_row.append(0)
            elif reserved[i][j]:
                new_row.append(int(cell))
            else:
                new_row.append(int(cell) ^ (1 if fn(i, j) else 0))
        out.append(new_row)
    return out


def _format_bits(mask: int) -> int:
    # error-correction level M -> 0b00
    data = (0b00 << 3) | mask
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    bits = ((data << 10) | rem) ^ 0x5412
    return bits


def _place_format(m: list[list[int]], version: int, mask: int) -> None:
    size = len(m)
    bits = _format_bits(mask)
    for i in range(15):
        bit = (bits >> i) & 1
        # around the top-left finder
        if i < 6:
            m[8][i] = bit
        elif i == 6:
            m[8][7] = bit
        elif i == 7:
            m[8][8] = bit
        elif i == 8:
            m[7][8] = bit
        else:
            m[14 - i][8] = bit
        # and the copy near the other two finders.
        # Bits 0-6 sit in the vertical strip beside the bottom-left finder
        # (size-1 down to size-7). Bit 7 onwards go left-to-right beside the
        # top-right finder, starting at column size-8. Using i < 8 for the
        # vertical copy overwrote the mandatory dark module at (size-8, 8)
        # and shifted the second format copy, so wallets could not scan it.
        if i < 7:
            m[size - 1 - i][8] = bit
        else:
            m[8][size - 15 + i] = bit


def _penalty(m: list[list[int]]) -> int:
    size = len(m)
    score = 0

    # rule 1 — runs of five or more
    for i in range(size):
        run_color = m[i][0]
        run_len = 1
        for j in range(1, size):
            if m[i][j] == run_color:
                run_len += 1
            else:
                if run_len >= 5:
                    score += 3 + (run_len - 5)
                run_color = m[i][j]
                run_len = 1
        if run_len >= 5:
            score += 3 + (run_len - 5)
    for j in range(size):
        run_color = m[0][j]
        run_len = 1
        for i in range(1, size):
            if m[i][j] == run_color:
                run_len += 1
            else:
                if run_len >= 5:
                    score += 3 + (run_len - 5)
                run_color = m[i][j]
                run_len = 1
        if run_len >= 5:
            score += 3 + (run_len - 5)

    # rule 2 — 2x2 blocks
    for i in range(size - 1):
        for j in range(size - 1):
            v = m[i][j]
            if v == m[i][j + 1] == m[i + 1][j] == m[i + 1][j + 1]:
                score += 3

    # rule 3 — finder-like patterns
    patterns = ([1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0],
                [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1])
    for i in range(size):
        for j in range(size - 10):
            row = m[i][j:j + 11]
            if row in (patterns[0], patterns[1]):
                score += 40
    for j in range(size):
        for i in range(size - 10):
            col = [m[r][j] for r in range(i, i + 11)]
            if col in (patterns[0], patterns[1]):
                score += 40

    # rule 4 — dark module proportion
    dark = sum(sum(row) for row in m)
    percent = dark * 100 / (size * size)
    score += 10 * int(abs(percent - 50) // 5)
    return score


def make_matrix(text: str) -> list[list[int]]:
    """Build the QR matrix for `text`."""
    data = text.encode("utf-8")
    version = _pick_version(len(data))
    codewords = _build_codewords(data, version)

    base = _new_matrix(version)
    _setup_function_patterns(base, version)
    reserved = [[cell is not None for cell in row] for row in base]
    _place_data(base, codewords)

    best: list[list[int]] | None = None
    best_score = None
    for mask in range(8):
        candidate = _apply_mask(base, reserved, mask)
        _place_format(candidate, version, mask)
        score = _penalty(candidate)
        if best_score is None or score < best_score:
            best = candidate
            best_score = score
    assert best is not None
    return best


# --- rendering --------------------------------------------------------------

def svg(text: str, *, modules: int = 8, quiet: int = 4,
        dark: str = "#000000", light: str = "#ffffff") -> str:
    """Render `text` as a standalone SVG string."""
    m = make_matrix(text)
    size = len(m)
    dim = (size + quiet * 2) * modules

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {dim} {dim}" '
        f'width="{dim}" height="{dim}" role="img" shape-rendering="crispEdges">',
        f'<rect width="{dim}" height="{dim}" fill="{light}"/>',
        '<path fill="%s" d="' % dark,
    ]
    for i, row in enumerate(m):
        for j, cell in enumerate(row):
            if cell:
                x = (j + quiet) * modules
                y = (i + quiet) * modules
                parts.append(f"M{x},{y}h{modules}v{modules}h-{modules}z")
    parts.append('"/></svg>')
    return "".join(parts)



def _amount_number(amount: str | None) -> str | None:
    """Strip a display amount like '0.010000 ETH' down to a plain number."""
    if not amount:
        return None
    token = str(amount).strip().split()[0].replace(",", "")
    if not token or token in {"—", "-", "–"}:
        return None
    try:
        value = Decimal(token)
    except (InvalidOperation, ValueError):
        return None
    if value <= 0:
        return None
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or None


def payment_uri(code: str, address: str, amount: str | None = None) -> str:
    """Wallet-scannable payment URI, with the amount when it is known.

    BTC uses BIP-21 (`bitcoin:<addr>?amount=`), ETH uses EIP-681
    (`ethereum:<addr>@1?value=` in wei). SOL and TRX use a simple
    `solana:` / `tron:` URI with `amount`. Unknown coins fall back to
    the raw address so a QR can still be drawn.
    """
    address = (address or "").strip()
    qty = _amount_number(amount)
    code = (code or "").upper()
    if code == "BTC":
        uri = f"bitcoin:{address}"
        if qty is not None:
            uri += f"?amount={qty}"
        return uri
    if code == "ETH":
        uri = f"ethereum:{address}@1"
        if qty is not None:
            wei = int((Decimal(qty) * (Decimal(10) ** 18)).to_integral_value(
                rounding=ROUND_DOWN))
            if wei > 0:
                uri += f"?value={wei}"
        return uri
    if code == "SOL":
        uri = f"solana:{address}"
        if qty is not None:
            uri += f"?amount={qty}"
        return uri
    if code == "TRX":
        uri = f"tron:{address}"
        if qty is not None:
            uri += f"?amount={qty}"
        return uri
    return address


# --- self-verification ------------------------------------------------------

def read_back(text: str) -> str:
    """Encode `text`, then decode the matrix back to its payload.

    Used by the tests: if the placement, masking and interleaving are wrong,
    this will not reproduce the original string.
    """
    data = text.encode("utf-8")
    version = _pick_version(len(data))
    ec_len, blocks = VERSIONS[version]
    m = make_matrix(text)

    # read the mask from the format information
    bits = 0
    for i in range(15):
        bit = m[8][i] if i < 6 else (m[8][7] if i == 6 else (m[8][8] if i == 7
               else (m[7][8] if i == 8 else m[14 - i][8])))
        bits |= bit << i
    unmasked = bits ^ 0x5412
    mask = (unmasked >> 10) & 0b111

    base = _new_matrix(version)
    _setup_function_patterns(base, version)
    reserved = [[cell is not None for cell in row] for row in base]

    # rebuild the data bitstream from the matrix
    size = len(m)
    fn = _MASK_FUNCS[mask]
    stream: list[int] = []
    col = size - 1
    upward = True
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for c in (col, col - 1):
                if reserved[row][c]:
                    continue
                bit = m[row][c]
                if fn(row, c):
                    bit ^= 1
                stream.append(bit)
        upward = not upward
        col -= 2

    codewords = [int("".join(str(b) for b in stream[i:i + 8]), 2)
                 for i in range(0, len(stream) - 7, 8)]

    # de-interleave
    max_data = max(blocks)
    data_blocks: list[list[int]] = [[] for _ in blocks]
    pos = 0
    for i in range(max_data):
        for b, size_b in enumerate(blocks):
            if i < size_b:
                data_blocks[b].append(codewords[pos])
                pos += 1
    flat: list[int] = []
    for b in data_blocks:
        flat.extend(b)

    count_bits = 8 if version <= 9 else 16
    bits = []
    for cw in flat:
        for i in range(7, -1, -1):
            bits.append((cw >> i) & 1)
    mode = int("".join(str(b) for b in bits[:4]), 2)
    if mode != 0b0100:
        raise ValueError(f"unexpected mode {mode}")
    length = int("".join(str(b) for b in bits[4:4 + count_bits]), 2)
    payload_bits = bits[4 + count_bits: 4 + count_bits + length * 8]
    payload = bytes(int("".join(str(b) for b in payload_bits[i:i + 8]), 2)
                    for i in range(0, len(payload_bits), 8))
    return payload.decode("utf-8")
