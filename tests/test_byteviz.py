"""Pure-Python tests for the byteviz module — no DPG runtime needed."""

from __future__ import annotations

from theseus.byteviz import (
    byte_presence_texture,
    byteview_texture,
    extract_strings,
)


def test_byteview_texture_shape_and_colormap():
    data = b"\x00\xff\x40\x10"
    out, w, h = byteview_texture(data, width=2, height=2)
    assert w == 2 and h == 2
    assert len(out) == w * h * 4
    # Byte 0x00 -> medium grey (74, 82, 92) / 255.
    assert abs(out[0] - 74 / 255.0) < 1e-6
    assert abs(out[1] - 82 / 255.0) < 1e-6
    assert abs(out[2] - 92 / 255.0) < 1e-6
    # Byte 0xFF -> high-byte light grey ramp at max (200, 207, 213) / 255.
    assert abs(out[4] - 200 / 255.0) < 1e-6
    assert abs(out[5] - 207 / 255.0) < 1e-6
    assert abs(out[6] - 213 / 255.0) < 1e-6
    # Byte 0x40 sits in the ASCII green class.
    assert out[9] > out[8]   # green channel dominates red
    assert out[9] > out[10]  # green channel dominates blue
    # Byte 0x10 sits in the control-byte red class.
    assert out[12] > out[13]  # red channel dominates green
    # All alphas opaque.
    for i in range(0, len(out), 4):
        assert out[i + 3] == 1.0


def test_byteview_texture_stretches_single_byte_across_all_pixels():
    # 1 byte in a 2x2 grid -> all 4 pixels show that byte's colour, no
    # background padding (texture always fills regardless of file size).
    out, _, _ = byteview_texture(b"\xff", width=2, height=2)
    # All four pixels should be the 0xFF high-byte colour: (200, 207, 213)/255.
    for px in range(4):
        j = px * 4
        assert abs(out[j] - 200 / 255.0) < 1e-6
        assert abs(out[j + 1] - 207 / 255.0) < 1e-6
        assert abs(out[j + 2] - 213 / 255.0) < 1e-6
        assert out[j + 3] == 1.0


def test_byte_presence_only_ascii_lights_cols_32_to_126():
    data = bytes(range(0x20, 0x7F))  # one row of pure printable ASCII
    rep = 4
    out, w, rows = byte_presence_texture(
        data, row_bytes=len(data), rows=1, col_replication=rep,
    )
    assert w == 256 * rep and rows == 1
    bg_g = 38 / 255.0
    # Cols 0..31 (each replicated `rep` times) should be bg.
    for byte_val in range(0, 32):
        for r in range(rep):
            j = (byte_val * rep + r) * 4
            assert out[j + 1] < bg_g + 0.05
    # Cols 32..126 lit (corporate green).
    for byte_val in range(0x20, 0x7F):
        for r in range(rep):
            j = (byte_val * rep + r) * 4
            assert out[j + 1] > 0.5
            assert out[j + 1] > out[j]
    # Byte value 127 is not in the data — should still be bg.
    j = 127 * rep * 4
    assert out[j + 1] < bg_g + 0.05


def test_extract_strings_basic():
    data = b"\x01abcd\x02efghi\x00xx\x00\x00very long printable here\x00"
    s = extract_strings(data, min_len=4)
    assert (1, "abcd") in s
    assert (6, "efghi") in s
    # 'xx' is below min_len, must not appear.
    assert not any(txt == "xx" for _, txt in s)
    assert any(txt.startswith("very long") for _, txt in s)


def test_extract_strings_respects_max_strings():
    # 100 short runs separated by null bytes.
    parts = [b"\x00" + b"ABCD" for _ in range(100)]
    data = b"".join(parts)
    s = extract_strings(data, min_len=4, max_strings=10)
    assert len(s) == 10
