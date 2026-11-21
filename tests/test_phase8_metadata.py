"""Offline unit tests for M.K Phase 8 (Image EXIF/GPS & Document Metadata Forensics)."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
import zipfile
from pathlib import Path

from mk_core.engine import MKEngine
from mk_core.models import ScanStatus, TargetType
from mk_modules.media_metadata import HAS_PILLOW, dms_to_decimal


class TestMKPhase8Metadata(unittest.TestCase):
    def test_dms_to_decimal_cairo_coordinates(self) -> None:
        # Cairo ~ 30.0444 N, 31.2357 E
        lat = dms_to_decimal((30, 2, 39.84), "N")
        lon = dms_to_decimal((31, 14, 8.52), "E")
        self.assertAlmostEqual(lat, 30.0444, places=3)
        self.assertAlmostEqual(lon, 31.2357, places=3)

    def test_office_docx_metadata_extraction(self) -> None:
        core_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/">'
            "<dc:creator>Omar Mohamed</dc:creator>"
            "<cp:lastModifiedBy>MK Analyst</cp:lastModifiedBy>"
            "<dc:title>MENA Brief</dc:title>"
            "</cp:coreProperties>"
        )
        with tempfile.TemporaryDirectory() as tmp:
            docx_path = Path(tmp) / "sample.docx"
            with zipfile.ZipFile(docx_path, "w") as zf:
                zf.writestr("docProps/core.xml", core_xml)

            engine = MKEngine()
            summary = asyncio.run(
                engine.scan(str(docx_path), target_type=TargetType.FILE, module_names=["media_metadata"])
            )
            results = summary.results_by_module["media_metadata"]
            office_res = next(r for r in results if r.source_name == "Office Document Metadata")
            self.assertEqual(office_res.status, ScanStatus.FOUND)
            self.assertEqual(office_res.extracted_data["creator"], "Omar Mohamed")

    def test_image_metadata_and_missing_file_error(self) -> None:
        engine = MKEngine()
        missing = asyncio.run(
            engine.scan("/nonexistent/missing.jpg", target_type=TargetType.FILE, module_names=["media_metadata"])
        )
        self.assertEqual(missing.results_by_module["media_metadata"][0].status, ScanStatus.ERROR)

        if HAS_PILLOW:
            from PIL import Image

            with tempfile.TemporaryDirectory() as tmp:
                img_path = Path(tmp) / "test_photo.jpg"
                img = Image.new("RGB", (64, 64), color=(10, 20, 30))
                exif = img.getexif()
                exif[271] = "Canon"
                exif[272] = "EOS R5"
                img.save(img_path, exif=exif)

                summary = asyncio.run(
                    engine.scan(str(img_path), target_type=TargetType.FILE, module_names=["media_metadata"])
                )
                results = summary.results_by_module["media_metadata"]
                exif_res = next(r for r in results if r.source_name.startswith("Image EXIF"))
                self.assertEqual(exif_res.status, ScanStatus.FOUND)
                self.assertEqual(exif_res.extracted_data["Make"], "Canon")
                self.assertEqual(exif_res.extracted_data["Model"], "EOS R5")


if __name__ == "__main__":
    unittest.main()
