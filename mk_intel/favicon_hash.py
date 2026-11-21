"""M.K v2.2 — Shodan Favicon Hash (Pure-Python MMH3) for Infrastructure Pivoting."""

from __future__ import annotations

import base64
import struct


def _mmh3_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python 32-bit MurmurHash3 (signed, matching Shodan's http.favicon.hash)."""
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    h1 = seed
    rounded_end = length & ~3

    for i in range(0, rounded_end, 4):
        k1 = struct.unpack_from("<I", data, i)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    k1 = 0
    tail = length & 3
    if tail == 3:
        k1 ^= data[rounded_end + 2] << 16
    if tail >= 2:
        k1 ^= data[rounded_end + 1] << 8
    if tail >= 1:
        k1 ^= data[rounded_end]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def compute_shodan_favicon_hash(favicon_bytes: bytes) -> int:
    """Compute exact Shodan `http.favicon.hash` value from raw favicon.ico bytes."""
    b64 = base64.encodebytes(favicon_bytes)
    return _mmh3_32(b64)
