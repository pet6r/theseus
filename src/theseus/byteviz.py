"""Byte-level visualization helpers for the Pipeline tab.

Recreates three of the four graphical panels described in Conti, Dean, Sinda,
Sangster, "Visual Reverse Engineering of Binary and Data Files" (VizSEC 2008):

- `byteview_texture`     — Fig 1c, every byte = one pixel, brightness = value
- `byte_presence_texture` — Fig 1b, 256-column matrix of byte-value presence
- `extract_strings`      — Fig 1d, printable ASCII runs with offsets

Pure Python, no DPG dependency. Returns flat RGBA float arrays in `[0, 1]`
ready to hand to `dpg.set_value` on a `mvFormat_Float_rgba` raw texture.
"""

from __future__ import annotations

import array
from typing import Tuple

ByteviewTexture = "array.array[float]"
PresenceTexture = "array.array[float]"
StringEntry = Tuple[int, str]

# Default panel background pixel — slightly lighter than the card bg so
# 0x00 runs render as a visible class instead of a void.
_BG_RGB = (32, 38, 44)


def _byte_color(value_0_255: int) -> Tuple[float, float, float]:
    """Corporate colormap by byte class (white / green / grey / red on black).

    - 0x00          -> medium grey (very common: padding / zeroed structs)
    - 0x01..0x1F    -> muted red ramp  (control bytes / structural)
    - 0x20..0x7E    -> corporate green ramp (printable ASCII)
    - 0x7F..0xFF    -> light grey -> near-white ramp (high bytes / code)

    Brightness within each class scales with value so internal structure
    stays readable. Mirrors the binwalk / Veles binary-class convention but
    with the gui.py corporate palette.
    """
    if value_0_255 == 0:
        return (74 / 255.0, 82 / 255.0, 92 / 255.0)
    if value_0_255 < 0x20:
        # Muted red ramp (201, 48, 48).
        t = 0.45 + 0.55 * (value_0_255 - 1) / (0x1F - 1)
        return (201 / 255.0 * t, 48 / 255.0 * t, 48 / 255.0 * t)
    if value_0_255 < 0x7F:
        # Corporate green ramp (61, 164, 107).
        t = 0.50 + 0.50 * (value_0_255 - 0x20) / (0x7E - 0x20)
        return (61 / 255.0 * t, 164 / 255.0 * t, 107 / 255.0 * t)
    # Light-grey -> near-white ramp for high bytes (200..232 ish).
    t = 0.55 + 0.45 * (value_0_255 - 0x7F) / (0xFF - 0x7F)
    return (200 / 255.0 * t, 207 / 255.0 * t, 213 / 255.0 * t)


def _bg_pixel() -> Tuple[float, float, float, float]:
    return (
        _BG_RGB[0] / 255.0,
        _BG_RGB[1] / 255.0,
        _BG_RGB[2] / 255.0,
        1.0,
    )


def byteview_texture(
    data: bytes,
    *,
    width: int = 256,
    height: int = 256,
    accent_rgb: Tuple[int, int, int] = (203, 166, 247),  # unused, kept for API
) -> Tuple["array.array[float]", int, int]:
    """Render `data` as an RGBA byte plot that fills the full `width x height`.

    Bytes are mapped to pixels by proportional scaling — when the file is
    smaller than `width * height`, each byte stretches across several
    pixels (coarse but image still fills the panel). When the file is
    larger, each pixel samples one of the leading bytes. Uses the 4-class
    `_byte_color` colormap so every byte renders to a visible colour.
    Returns an `array.array('f', ...)`.
    """
    _ = accent_rgb  # legacy kwarg, retained for API compatibility
    n_pixels = width * height
    n_bytes = len(data)
    out = array.array("f", [0.0] * (n_pixels * 4))
    if n_bytes == 0:
        bg = _bg_pixel()
        for i in range(n_pixels):
            j = i * 4
            out[j] = bg[0]
            out[j + 1] = bg[1]
            out[j + 2] = bg[2]
            out[j + 3] = bg[3]
        return out, width, height
    for px in range(n_pixels):
        b_idx = (px * n_bytes) // n_pixels
        if b_idx >= n_bytes:
            b_idx = n_bytes - 1
        r, g, b = _byte_color(data[b_idx])
        j = px * 4
        out[j] = r
        out[j + 1] = g
        out[j + 2] = b
        out[j + 3] = 1.0
    return out, width, height


def byte_presence_texture(
    data: bytes,
    *,
    row_bytes: int = 256,
    rows: int = 170,
    col_replication: int = 4,
    accent_rgb: Tuple[int, int, int] = (61, 164, 107),
) -> Tuple["array.array[float]", int, int]:
    """Each output row K lights the columns whose byte values appear in
    `data[K * row_bytes : (K + 1) * row_bytes]`.

    Output is a `(256 * col_replication) x rows` RGBA float texture. The
    column replication factor (default 4) widens the texture from 256 to
    1024 so DPG's aspect-locked `add_image` renders it wide-and-short
    inside the Pipeline tab without collapsing height.
    """
    width = 256 * col_replication
    out = array.array("f", [0.0] * (width * rows * 4))
    bg = _bg_pixel()
    for k in range(width * rows):
        j = k * 4
        out[j] = bg[0]
        out[j + 1] = bg[1]
        out[j + 2] = bg[2]
        out[j + 3] = bg[3]

    accent_norm = (
        accent_rgb[0] / 255.0,
        accent_rgb[1] / 255.0,
        accent_rgb[2] / 255.0,
    )
    n_rows = min(rows, (len(data) + row_bytes - 1) // row_bytes)
    for row in range(n_rows):
        start = row * row_bytes
        end = min(start + row_bytes, len(data))
        seen = set(data[start:end])
        base = row * width * 4
        for val in seen:
            for rep in range(col_replication):
                col = val * col_replication + rep
                j = base + col * 4
                out[j] = accent_norm[0]
                out[j + 1] = accent_norm[1]
                out[j + 2] = accent_norm[2]
                out[j + 3] = 1.0
    return out, width, rows


def extract_strings(
    data: bytes,
    *,
    min_len: int = 4,
    max_strings: int = 1000,
) -> list[StringEntry]:
    """Classic `strings(1)`: emit (offset, text) on every printable ASCII
    run of length `>= min_len`. Printable = `0x20..0x7E`.
    """
    out: list[StringEntry] = []
    run_start = -1
    run: list[int] = []
    for i, b in enumerate(data):
        if 0x20 <= b <= 0x7E:
            if not run:
                run_start = i
            run.append(b)
        else:
            if len(run) >= min_len:
                out.append((run_start, bytes(run).decode("ascii", errors="replace")))
                if len(out) >= max_strings:
                    return out
            run = []
            run_start = -1
    if len(run) >= min_len:
        out.append((run_start, bytes(run).decode("ascii", errors="replace")))
    return out[:max_strings]
