"""Classic hex dump renderer for the Pipeline tab.

Produces a monospaced view of `data` with one row per `bytes_per_line` bytes:

    00000000  4D 5A 90 00 03 00 00 00  04 00 00 00 FF FF 00 00  MZ..............
    00000010  B8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  ........@.......

A small gap separates the two halves of the hex column for readability. Bytes
outside ASCII printable range render as `.` in the right-hand column.
"""

from __future__ import annotations


def hexdump(data: bytes, *, max_bytes: int = 4096, bytes_per_line: int = 16) -> str:
    """Render the first `max_bytes` of `data` as a classic hex dump string."""
    if not data:
        return "(empty)"
    n = min(len(data), max_bytes)
    bpl = bytes_per_line
    half = bpl // 2
    lines: list[str] = []
    for offset in range(0, n, bpl):
        chunk = data[offset:offset + bpl]
        # Pad chunk so the right column lines up on the last row.
        left = chunk[:half]
        right = chunk[half:]
        left_hex = " ".join(f"{b:02X}" for b in left).ljust(half * 3 - 1)
        right_hex = " ".join(f"{b:02X}" for b in right).ljust(half * 3 - 1)
        ascii_part = "".join(
            chr(b) if 0x20 <= b < 0x7F else "." for b in chunk
        )
        lines.append(f"{offset:08X}  {left_hex}  {right_hex}  {ascii_part}")
    if n < len(data):
        remaining = len(data) - n
        lines.append("")
        lines.append(f"... {remaining:,} more bytes  (file size {len(data):,})")
    return "\n".join(lines)


def human_size(n: int) -> str:
    """Format a byte count as a short human-readable string."""
    f = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if f < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(f)} {unit}"
            return f"{f:.1f} {unit}"
        f /= 1024
    return f"{f:.1f} TB"
