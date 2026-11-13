"""QR codes for the crypto order page, drawn by the `segno` library.

An earlier hand-written encoder produced codes that its own self-test could read
back but real scanners (wallet apps, zxing, OpenCV) could not, so it was replaced
with segno: a pure-Python, ISO/IEC 18004 compliant encoder with no native deps.

The QR holds the PLAIN wallet address only (no `bitcoin:` / `ethereum:` URI and
no amount). That is what wallets such as Exodus show on their own receive
screens, and many wallets/exchanges reject EIP-681 or amount URIs. The amount is
printed as text next to the code instead.
"""
from __future__ import annotations

import io

import segno

QUIET_ZONE = 4          # modules of white border required by the QR spec
DARK = "#000000"
LIGHT = "#ffffff"


def payload(address: str) -> str:
    """What goes inside the QR: the address exactly as configured, trimmed."""
    return (address or "").strip()


def _make(text: str) -> segno.QRCode:
    # error level M, never a Micro QR (many phone scanners can't read those)
    return segno.make_qr(text, error="m", boost_error=False)


def matrix(text: str) -> list[list[int]]:
    """The module matrix (1 = dark) without the quiet zone. Used by tests."""
    return [[1 if cell else 0 for cell in row] for row in _make(text).matrix]


def svg(text: str, *, scale: int = 8, border: int = QUIET_ZONE) -> str:
    """Inline SVG: black modules on an opaque white square with a 4-module
    quiet zone, crisp edges, no XML declaration (safe to drop into HTML)."""
    code = _make(text)
    out = io.BytesIO()
    # omitsize=True makes segno emit a viewBox, so the code scales cleanly when
    # CSS resizes it (without a viewBox the browser crops instead of scaling)
    code.save(out, kind="svg", scale=scale, border=border,
              dark=DARK, light=LIGHT, xmldecl=False, svgns=True,
              svgclass="qr-svg", lineclass=None, omitsize=True,
              title="Wallet address QR code")
    markup = out.getvalue().decode("utf-8")
    width, _ = code.symbol_size(scale=scale, border=border)
    return markup.replace(
        "<svg ", f'<svg width="{width}" height="{width}" '
        'shape-rendering="crispEdges" role="img" ', 1)


def png(text: str, *, scale: int = 10, border: int = QUIET_ZONE) -> bytes:
    """PNG bytes of the same code (for a download link or tests)."""
    out = io.BytesIO()
    _make(text).save(out, kind="png", scale=scale, border=border,
                     dark=DARK, light=LIGHT)
    return out.getvalue()
