"""M.K v2.2 — Perceptual Image Hash (dHash) Matcher for Comparing Profile Avatars Across Platforms."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

try:
    from PIL import Image  # type: ignore

    HAS_PILLOW = True
except ImportError:  # pragma: no cover
    HAS_PILLOW = False


def compute_dhash(image_path: str | Path, hash_size: int = 8) -> Optional[str]:
    """Compute a 64-bit difference hash (dHash) invariant to resizing & light compression."""
    if not HAS_PILLOW:
        return None
    with Image.open(image_path) as img:
        gray = img.convert("L").resize((hash_size + 1, hash_size))
        pixels = list(gray.getdata())
        bits = []
        for row in range(hash_size):
            row_start = row * (hash_size + 1)
            for col in range(hash_size):
                bits.append("1" if pixels[row_start + col] > pixels[row_start + col + 1] else "0")
        return f"{int(''.join(bits), 2):0{hash_size * hash_size // 4}x}"


def hamming_similarity(hash_a: str, hash_b: str) -> float:
    """Return perceptual similarity percentage (0.0 to 100.0) between two hex dHashes."""
    if len(hash_a) != len(hash_b) or not hash_a:
        return 0.0
    int_a = int(hash_a, 16)
    int_b = int(hash_b, 16)
    total_bits = len(hash_a) * 4
    diff_bits = bin(int_a ^ int_b).count("1")
    return round((1.0 - (diff_bits / total_bits)) * 100.0, 2)
