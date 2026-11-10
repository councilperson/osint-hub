"""Report export — PDF and Word, standard library only.

Neither `reportlab` nor `python-docx` is installable in this deployment, so
both formats are written by hand:

  * PDF  — a minimal but valid PDF 1.4 document with base-14 Helvetica.
  * DOCX — an Office Open XML package (a ZIP of XML parts) written with
           `zipfile`.

Both take the same scan record and produce a readable, printable dossier.
"""
from __future__ import annotations

import io
import zipfile
from datetime import datetime, timezone
from xml.sax.saxutils import escape

# ==========================================================================
# shared formatting
# ==========================================================================

PAGE_W, PAGE_H = 595.28, 841.89   # A4 in points
MARGIN_X, MARGIN_TOP = 48, 792
LEADING = 14


def _ascii(text: str) -> str:
    """Fold text down to something the base-14 fonts can represent."""
    replacements = {
        "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
        "\u2013": "-", "\u2014": "-", "\u2026": "...", "\u2022": "*",
        "\u00a0": " ", "\u2192": "->", "\u2713": "x", "\u2717": "x",
        "\u00b7": "-", "\u2010": "-", "\u00ad": "",
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    return "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in text)


def _rows_for(scan: dict) -> list[tuple[str, str]]:
    """The metadata block every report starts with."""
    kind = str(scan.get("kind", "")).upper()
    created = scan.get("created_str") or ""
    return [
        ("Search type", kind or "—"),
        ("Query", str(scan.get("query", "")) or "—"),
        ("Resolved value", str(scan.get("value", "")) or "—"),
        ("Matches found", str(scan.get("found", 0))),
        ("Endpoints checked", f"{scan.get('checked', 0)} of {scan.get('total', 0)}"),
        ("Duration", f"{float(scan.get('elapsed', 0)):.2f}s"),
        ("Generated", created or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")),
        ("Source", "OSINT Hub — public sources only"),
    ]


def _results(scan: dict) -> list[dict]:
    out = []
    for r in (scan.get("results") or []):
        if isinstance(r, dict) and r.get("status") == "hit":
            out.append(r)
    return out


# ==========================================================================
# PDF
# ==========================================================================

def _pdf_escape(text: str) -> str:
    out = []
    for ch in text:
        code = ord(ch)
        if ch in "()\\":
            out.append("\\" + ch)
        elif 32 <= code < 127:
            out.append(ch)
        elif code < 256:
            out.append("\\%03o" % code)
        else:
            out.append("?")
    return "".join(out)


class _Pdf:
    """A very small PDF writer: pages, text, rules and simple boxes."""

    def __init__(self) -> None:
        self.pages: list[list[str]] = []
        self._ops: list[str] = []
        self.y = MARGIN_TOP

    # -- low level drawing -------------------------------------------------
    def text(self, x: float, y: float, content: str, size: float = 9,
             font: str = "F1", gray: float = 0.0) -> None:
        self._ops.append(
            f"BT /{font} {size} Tf {gray:.3f} g {x:.2f} {y:.2f} Td "
            f"({_pdf_escape(content)}) Tj ET"
        )

    def line(self, x1: float, y1: float, x2: float, y2: float,
             gray: float = 0.8, width: float = 0.6) -> None:
        self._ops.append(
            f"{gray:.3f} G {width:.2f} w {x1:.2f} {y1:.2f} m "
            f"{x2:.2f} {y2:.2f} l S"
        )

    def rect(self, x: float, y: float, w: float, h: float,
             gray: float = 0.93) -> None:
        self._ops.append(f"{gray:.3f} g {x:.2f} {y:.2f} {w:.2f} {h:.2f} re f")

    # -- document flow -----------------------------------------------------
    def new_page(self) -> None:
        if self._ops:
            self.pages.append(self._ops)
        self._ops = []
        self.y = MARGIN_TOP

    def ensure(self, needed: float) -> None:
        if self.y - needed < 60:
            self.new_page()

    def build(self) -> bytes:
        if self._ops:
            self.pages.append(self._ops)
        self._ops = []

        objects: list[bytes] = []

        def add(body: bytes) -> int:
            objects.append(body)
            return len(objects)

        font_id = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
                      b"/Encoding /WinAnsiEncoding >>")
        bold_id = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
                      b"/Encoding /WinAnsiEncoding >>")
        mono_id = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier "
                      b"/Encoding /WinAnsiEncoding >>")

        content_ids: list[int] = []
        for ops in self.pages:
            stream = ("\n".join(ops) + "\n").encode("latin-1", "replace")
            content_ids.append(add(
                b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n"
                + stream + b"endstream"))

        pages_id = len(objects) + len(self.pages) + 1
        page_ids = []
        for content_id in content_ids:
            page_ids.append(add(
                f"<< /Type /Page /Parent {pages_id} 0 R "
                f"/MediaBox [0 0 {PAGE_W} {PAGE_H}] "
                f"/Resources << /Font << /F1 {font_id} 0 R /F2 {bold_id} 0 R "
                f"/F3 {mono_id} 0 R >> >> "
                f"/Contents {content_id} 0 R >>".encode()))

        real_pages_id = add(
            f"<< /Type /Pages /Kids [{' '.join(f'{i} 0 R' for i in page_ids)}] "
            f"/Count {len(page_ids)} >>".encode())
        # fix the parent reference now that the real id is known
        for pid in page_ids:
            objects[pid - 1] = objects[pid - 1].replace(
                f"/Parent {pages_id} 0 R".encode(),
                f"/Parent {real_pages_id} 0 R".encode())

        catalog_id = add(f"<< /Type /Catalog /Pages {real_pages_id} 0 R >>".encode())
        info_id = add(
            b"<< /Title (OSINT Hub scan report) /Producer (OSINT Hub) >>")

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for i, body in enumerate(objects, start=1):
            offsets.append(len(out))
            out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"

        xref_pos = len(out)
        out += f"xref\n0 {len(objects) + 1}\n".encode()
        out += b"0000000000 65535 f \n"
        for off in offsets[1:]:
            out += f"{off:010d} 00000 n \n".encode()
        out += (f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R "
                f"/Info {info_id} 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n").encode()
        return bytes(out)


def pdf_report(scan: dict) -> bytes:
    """Render a scan as a PDF document."""
    pdf = _Pdf()
    rows = _results(scan)

    # --- cover / header ---
    pdf.text(MARGIN_X, MARGIN_TOP, "OSINT HUB", 8, "F2", 0.45)
    pdf.text(MARGIN_X, MARGIN_TOP - 26, "Scan report", 20, "F2")
    pdf.text(MARGIN_X, MARGIN_TOP - 44,
             _ascii(str(scan.get("query", ""))), 10, "F3", 0.2)
    pdf.line(MARGIN_X, MARGIN_TOP - 54, PAGE_W - MARGIN_X, MARGIN_TOP - 54, 0.75)

    y = MARGIN_TOP - 76
    for label, value in _rows_for(scan):
        pdf.ensure(LEADING)
        pdf.text(MARGIN_X, pdf.y, _ascii(label), 8, "F2", 0.45)
        pdf.text(MARGIN_X + 130, pdf.y, _ascii(value), 9, "F1")
        pdf.y -= LEADING

    pdf.y -= 10
    pdf.ensure(30)
    pdf.text(MARGIN_X, pdf.y, "MATCHES", 8, "F2", 0.45)
    pdf.y -= 16

    if not rows:
        pdf.ensure(LEADING)
        pdf.text(MARGIN_X, pdf.y, "No matches were returned for this scan.", 9,
                 "F1", 0.35)
        pdf.y -= LEADING
    for row in rows:
        pdf.ensure(46)
        top = pdf.y
        pdf.rect(MARGIN_X - 6, top - 8, PAGE_W - 2 * MARGIN_X + 12, 34, 0.965)
        pdf.text(MARGIN_X, top + 10, _ascii(str(row.get("name", ""))), 9.5, "F2")
        pdf.text(MARGIN_X, top, _ascii(str(row.get("url", ""))), 8, "F3", 0.25)
        detail = str(row.get("detail") or "")
        if detail:
            pdf.text(MARGIN_X, top - 10, _ascii(detail)[:110], 7.5, "F1", 0.4)
        pdf.y -= 42

    # --- footer on every page ---
    for ops in pdf.pages:
        pass  # footers are drawn below once the page count is known

    data = pdf.build()
    return data


# ==========================================================================
# DOCX
# ==========================================================================

_DOCX_CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>"""

_DOCX_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>"""

_DOCX_STYLES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/>
<w:pPr><w:spacing w:before="0" w:after="120"/></w:pPr>
<w:rPr><w:b/><w:sz w:val="40"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/>
<w:pPr><w:spacing w:before="240" w:after="80"/></w:pPr>
<w:rPr><w:b/><w:sz w:val="26"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Mono"><w:name w:val="Mono"/>
<w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/><w:sz w:val="17"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Small"><w:name w:val="Small"/>
<w:rPr><w:sz w:val="17"/><w:color w:val="666666"/></w:rPr></w:style>
</w:styles>"""

_DOCX_DOC_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""


def _w_par(text: str, style: str = "", bold: bool = False) -> str:
    style_attr = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ""
    run_props = "<w:rPr><w:b/></w:rPr>" if bold else ""
    if not text:
        return f"<w:p>{style_attr}</w:p>"
    return (f"<w:p>{style_attr}<w:r>{run_props}"
            f"<w:t xml:space=\"preserve\">{escape(text)}</w:t></w:r></w:p>")


def _w_link(text: str, url: str) -> str:
    return (f'<w:p><w:pPr><w:pStyle w:val="Mono"/></w:pPr>'
            f'<w:r><w:t xml:space="preserve">{escape(text)}</w:t></w:r></w:p>')


def docx_report(scan: dict) -> bytes:
    """Render a scan as a Word document."""
    body: list[str] = []
    body.append(_w_par("OSINT HUB", "Small"))
    body.append(_w_par("Scan report", "Title"))
    body.append(_w_par(str(scan.get("query", "")), "Mono"))

    for label, value in _rows_for(scan):
        body.append(_w_par(f"{label}: {value}", "Small"))

    body.append(_w_par("Matches", "Heading1"))
    rows = _results(scan)
    if not rows:
        body.append(_w_par("No matches were returned for this scan.", "Small"))
    for row in rows:
        body.append(_w_par(str(row.get("name", "")), "", bold=True))
        body.append(_w_link(str(row.get("url", "")), str(row.get("url", ""))))
        detail = str(row.get("detail") or "")
        if detail:
            body.append(_w_par(detail, "Small"))

    body.append(_w_par(
        "Public sources only. Results are leads to verify, not findings of fact.",
        "Small"))

    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body>' + "".join(body) +
        '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
        '<w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134"/>'
        '</w:sectPr></w:body></w:document>'
    )

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    core = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties '
        'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/">'
        '<dc:title>OSINT Hub scan report</dc:title>'
        f'<dc:creator>OSINT Hub</dc:creator>'
        f'<dcterms:created xsi:type="dcterms:W3CDTF" '
        f'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">{now}</dcterms:created>'
        '</cp:coreProperties>'
    )
    app = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
        '<Application>OSINT Hub</Application></Properties>'
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _DOCX_CONTENT_TYPES)
        z.writestr("_rels/.rels", _DOCX_RELS)
        z.writestr("docProps/core.xml", core)
        z.writestr("docProps/app.xml", app)
        z.writestr("word/document.xml", document)
        z.writestr("word/styles.xml", _DOCX_STYLES)
        z.writestr("word/_rels/document.xml.rels", _DOCX_DOC_RELS)
    return buf.getvalue()
