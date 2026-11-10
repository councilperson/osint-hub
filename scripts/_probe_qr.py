import io
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
sys.path.insert(0, ".")
from app import qr  # noqa: E402

CASES = [
    "0x3bcC6F90F5fc09FDeAfB4AECF2EA367Ed32E12D4",
    "bc1qpw7n2ck6a6vxc6vm5jhm5tf07kd8430ctt3uyl",
    "32DebfnE2WBVFwVXsiwNEn4DyXHN9moeBLbpcr7W4sEL",
    "TBvY5nkA8viFTAANHPobL4e7Czjadkbs37",
    "HELLO WORLD",
    "https://osint-hub.example/checkout?plan=pro&amount=49",
    "x" * 180,
]

ok = True
for text in CASES:
    version = qr._pick_version(len(text.encode("utf-8")))
    matrix = qr.make_matrix(text)
    back = qr.read_back(text)
    good = back == text
    ok = ok and good
    print("%-5s v%-3d %2dx%-2d  %s" % (
        "PASS" if good else "FAIL", version, len(matrix), len(matrix[0]),
        text[:52]))

# Reed-Solomon syndrome check: a valid codeword evaluates to zero at
# alpha^0 .. alpha^(n-1).
print()
print("RS syndrome check:")
for ec_len in (10, 16, 18, 22, 24, 26):
    data = [0x40, 0xd2, 0x75, 0x47, 0x76, 0x17, 0x32, 0x06,
            0x27, 0x26, 0x96, 0xc6, 0xc6, 0x96, 0x70, 0xec]
    ec = qr._rs_encode(data, ec_len)
    block = data + ec
    # syndrome: evaluate at alpha^i for i in 0..ec_len-1
    bad = 0
    for i in range(ec_len):
        acc = 0
        for coeff in block:
            acc = qr._gf_mul(acc, qr._EXP[i]) ^ coeff
        if acc != 0:
            bad += 1
    print("  ec_len=%-3d syndromes non-zero: %d  %s"
          % (ec_len, bad, "PASS" if bad == 0 else "FAIL"))
    ok = ok and bad == 0

print()
print("ALL PASS" if ok else "FAILURES PRESENT")
