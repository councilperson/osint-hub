"""Decode the order-page QR codes with a real reader.

    pip install -r requirements-dev.txt
    python scripts/_probe_qr.py [address ...]

Renders each address with app.qr (the same code the order page uses) as PNG
and decodes it with zxing-cpp; prints MATCH when the decoded text equals the
address exactly.
"""
from __future__ import annotations

import io
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import zxingcpp  # noqa: E402
from PIL import Image  # noqa: E402

from app import qr  # noqa: E402

DEFAULT = [
    "bc1qpw7n2ck6a6vxc6vm5jhm5tf07kd8430ctt3uyl",
    "0x3bcC6F90F5fc09FDeAfB4AECF2EA367Ed32E12D4",
    "32DebfnE2WBVFwVXsiwNEn4DyXHN9moeBLbpcr7W4sEL",
    "TBvY5nkA8viFTAANHPobL4e7Czjadkbs37",
]


def main(addresses: list[str]) -> int:
    bad = 0
    for addr in addresses:
        img = Image.open(io.BytesIO(qr.png(qr.payload(addr))))
        got = [b.text for b in zxingcpp.read_barcodes(img)]
        ok = got == [addr]
        bad += not ok
        print(("MATCH " if ok else "FAIL  ") + addr + ("" if ok else f"  -> {got}"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or DEFAULT))
