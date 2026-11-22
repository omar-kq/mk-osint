"""Tests for M.K v3.0 (True-Color Terminal Image Preview, HTML Visual Gallery, Priority Sort, & Timeout Guard)."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from mk_core import __version__
from mk_core.engine import MKEngine
from mk_core.models import OSINTResult, ScanStatus, ScanSummary, TargetType
from mk_report.exporter import ReportExporter
from mk_ui.media_preview import HAS_PILLOW, render_image_to_rich_text


class TestMKv3MediaAndHardening(unittest.TestCase):
    def test_v3_version_and_truecolor_terminal_image_preview(self) -> None:
        self.assertEqual(__version__, "3.0.0")
        if not HAS_PILLOW:
            return
        from PIL import Image

        with tempfile.TemporaryDirectory() as tmp:
            img_path = Path(tmp) / "avatar.png"
            Image.new("RGB", (64, 64), color=(0, 245, 255)).save(img_path)
            rendered = render_image_to_rich_text(img_path, max_width=20, max_height=10)
            self.assertIsNotNone(rendered)
            self.assertIn("▀", rendered.plain)

    def test_html_visual_gallery_embeds_avatars_and_local_images(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            summary = ScanSummary(
                scan_id="v3gallery",
                case_id="CASE-V3",
                target="omar_eg",
                target_type=TargetType.USERNAME,
                started_at="2026-11-22T00:00:00+00:00",
            )
            summary.add_result(
                OSINTResult(
                    module_name="username_mena",
                    source_name="GitHub",
                    target="omar_eg",
                    target_type=TargetType.USERNAME,
                    status=ScanStatus.FOUND,
                    url="https://github.com/omar_eg",
                    extracted_data={
                        "avatar_url": "https://avatars.githubusercontent.com/u/1",
                        "google_lens": "https://lens.google.com/uploadbyurl?url=https%3A%2F%2Favatars.githubusercontent.com%2Fu%2F1",
                        "bio": "مهندس ميكاترونكس",
                    },
                )
            )
            exporter = ReportExporter(out_dir=tmp_path)
            html_file = exporter.export_html(summary)
            content = html_file.read_text(encoding="utf-8")
            self.assertIn("Visual Avatars &amp; Media Gallery", content)
            self.assertIn("avatars.githubusercontent.com", content)
            self.assertIn("Google Lens", content)
            self.assertIn("مهندس ميكاترونكس", content)


if __name__ == "__main__":
    unittest.main()
