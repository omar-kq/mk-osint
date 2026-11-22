"""M.K v3.0 — True-Color Terminal Image Renderer (Unicode Half-Block '▀' Preview via Pillow + Rich)."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

try:
    from PIL import Image  # type: ignore

    HAS_PILLOW = True
except ImportError:  # pragma: no cover
    HAS_PILLOW = False

try:
    from rich.text import Text

    HAS_RICH = True
except ImportError:  # pragma: no cover
    HAS_RICH = False


def render_image_to_rich_text(
    image_path: str | Path,
    max_width: int = 38,
    max_height: int = 20,
) -> Optional["Text"]:
    """Render any local image as a crisp True-Color RGB preview right inside Kali's terminal."""
    if not HAS_PILLOW or not HAS_RICH:
        return None
    path = Path(image_path)
    if not path.exists() or not path.is_file():
        return None

    try:
        with Image.open(path) as img:
            rgb = img.convert("RGB")
            aspect = rgb.height / max(1, rgb.width)
            target_w = min(max_width, max(8, rgb.width))
            # Each terminal row encodes 2 vertical pixels via upper half-block '▀'
            target_h_px = min(max_height * 2, max(4, int(target_w * aspect)))
            if target_h_px % 2 != 0:
                target_h_px += 1
            resized = rgb.resize((target_w, target_h_px))
            pixels = resized.load()

            canvas = Text()
            for y in range(0, target_h_px, 2):
                for x in range(target_w):
                    r1, g1, b1 = pixels[x, y]
                    r2, g2, b2 = pixels[x, y + 1]
                    canvas.append("▀", style=f"rgb({r1},{g1},{b1}) on rgb({r2},{g2},{b2})")
                canvas.append("\n")
            return canvas
    except Exception:  # noqa: BLE001
        return None
