"""M.K v2.2 — Deep Image/Document Forensics (Native Kali ExifTool + ELA Photoshop Detector + Pillow/pypdf)."""

from __future__ import annotations

import hashlib
import io
import json
import mimetypes
import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from mk_core.models import ModuleMetadata, OSINTResult, ScanStatus, TargetType
from mk_core.registry import BaseOSINTModule
from mk_intel.avatar_matcher import compute_dhash

try:
    from PIL import ExifTags, Image, ImageChops  # type: ignore

    HAS_PILLOW = True
except ImportError:  # pragma: no cover
    HAS_PILLOW = False

try:
    from pypdf import PdfReader  # type: ignore

    HAS_PYPDF = True
except ImportError:  # pragma: no cover
    HAS_PYPDF = False


IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".webp", ".bmp"}
OFFICE_EXTS = {".docx", ".xlsx", ".pptx"}


def compute_file_hashes(path: Path) -> Dict[str, str]:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(65536):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def _rational_to_float(val: Any) -> float:
    try:
        return float(val)
    except Exception:  # noqa: BLE001
        if isinstance(val, tuple) and len(val) == 2 and val[1]:
            return float(val[0]) / float(val[1])
        return 0.0


def dms_to_decimal(dms: Tuple[Any, Any, Any], ref: str) -> float:
    deg = _rational_to_float(dms[0])
    minutes = _rational_to_float(dms[1])
    seconds = _rational_to_float(dms[2])
    dec = deg + (minutes / 60.0) + (seconds / 3600.0)
    if str(ref).upper() in {"S", "W"}:
        dec = -dec
    return round(dec, 6)


def run_kali_exiftool(path: Path) -> Optional[Dict[str, Any]]:
    """Run Kali's native `exiftool -j -n` if installed; returns parsed metadata dict or None."""
    if shutil.which("exiftool") is None:
        return None
    try:
        proc = subprocess.run(
            ["exiftool", "-j", "-n", str(path)],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            items = json.loads(proc.stdout)
            if isinstance(items, list) and items:
                return items[0]
    except Exception:  # noqa: BLE001
        return None
    return None


def compute_ela_tampering_score(path: Path, quality: int = 90) -> Optional[Dict[str, Any]]:
    """Error Level Analysis (ELA) heuristic to detect potential Photoshop/splicing edits in images."""
    if not HAS_PILLOW:
        return None
    try:
        with Image.open(path) as orig:
            rgb = orig.convert("RGB")
            buf = io.BytesIO()
            rgb.save(buf, "JPEG", quality=quality)
            buf.seek(0)
            with Image.open(buf) as resaved:
                diff = ImageChops.difference(rgb, resaved)
                extrema = diff.getextrema()
                max_diff = max(ch[1] for ch in extrema)
                hist = diff.histogram()
                total_px = rgb.width * rgb.height * 3
                weighted = sum((i % 256) * count for i, count in enumerate(hist))
                mean_diff = round(weighted / max(1, total_px), 3)
                verdict = (
                    "Elevated ELA variance (inspect for possible editing)"
                    if max_diff >= 45 and mean_diff >= 4.0
                    else "Low/Normal ELA variance"
                )
                return {"ela_max_diff": max_diff, "ela_mean_diff": mean_diff, "ela_verdict": verdict}
    except Exception:  # noqa: BLE001
        return None


def extract_image_metadata(path: Path) -> Tuple[Dict[str, Any], Optional[Tuple[float, float]], Optional[str]]:
    if not HAS_PILLOW:
        return {}, None, "Pillow not installed (run pip install -r requirements.txt)"

    meta: Dict[str, Any] = {}
    gps_coords: Optional[Tuple[float, float]] = None

    with Image.open(path) as img:
        meta["format"] = img.format
        meta["mode"] = img.mode
        meta["dimensions"] = f"{img.width}x{img.height}"

        exif_raw = img.getexif()
        if exif_raw:
            for tag_id, value in exif_raw.items():
                tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                if tag_name in {"Make", "Model", "Software", "DateTime", "DateTimeOriginal", "Artist", "Copyright"}:
                    meta[tag_name] = str(value).strip()

            gps_ifd = exif_raw.get_ifd(0x8825) if hasattr(exif_raw, "get_ifd") else None
            if gps_ifd:
                gps_named = {ExifTags.GPSTAGS.get(k, k): v for k, v in gps_ifd.items()}
                if all(k in gps_named for k in ("GPSLatitude", "GPSLatitudeRef", "GPSLongitude", "GPSLongitudeRef")):
                    lat = dms_to_decimal(gps_named["GPSLatitude"], gps_named["GPSLatitudeRef"])
                    lon = dms_to_decimal(gps_named["GPSLongitude"], gps_named["GPSLongitudeRef"])
                    gps_coords = (lat, lon)
                    meta["gps_latitude"] = lat
                    meta["gps_longitude"] = lon

    dhash = compute_dhash(path)
    if dhash:
        meta["perceptual_dhash"] = dhash
    return meta, gps_coords, None


def extract_pdf_metadata(path: Path) -> Tuple[Dict[str, Any], Optional[str]]:
    if not HAS_PYPDF:
        return {}, "pypdf not installed"
    reader = PdfReader(str(path))
    info = reader.metadata or {}
    meta: Dict[str, Any] = {"pages": len(reader.pages)}
    for key in ("/Title", "/Author", "/Subject", "/Creator", "/Producer", "/CreationDate", "/ModDate"):
        val = info.get(key)
        if val:
            meta[key.lstrip("/").lower()] = str(val).strip()
    return meta, None


def extract_office_metadata(path: Path) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    with zipfile.ZipFile(path, "r") as zf:
        for xml_member in ("docProps/core.xml", "docProps/app.xml"):
            if xml_member not in zf.namelist():
                continue
            root = ET.fromstring(zf.read(xml_member))
            for elem in root:
                tag = elem.tag.split("}", 1)[-1]
                text = (elem.text or "").strip()
                if text and tag in {"creator", "lastModifiedBy", "title", "subject", "created", "modified", "Application", "Company"}:
                    meta[tag] = text
    return meta


class MediaMetadataModule(BaseOSINTModule):
    """Deep offline forensics: Kali ExifTool + ELA Photoshop detector + Pillow/pypdf/Office."""

    metadata = ModuleMetadata(
        name="media_metadata",
        display_name="Deep Image/Doc Forensics (ExifTool + ELA + GPS + dHash)",
        version="2.2.0",
        description="Extracts hashes, Kali ExifTool metadata, ELA tampering score, perceptual dHash, GPS maps, and PDF/Office authors.",
        supported_targets=[TargetType.FILE],
        category="forensics",
        requires_network=False,
        passive_only=True,
        enabled_by_default=True,
    )

    async def run(self, target: str, target_type: TargetType) -> List[OSINTResult]:
        path = Path(target).expanduser()
        if not path.exists() or not path.is_file():
            return [
                OSINTResult(
                    module_name=self.metadata.name,
                    source_name="File Existence Check",
                    target=target,
                    target_type=target_type,
                    status=ScanStatus.ERROR,
                    reason="File not found on local filesystem",
                    category="forensics",
                )
            ]

        ext = path.suffix.lower()
        mime_type, _ = mimetypes.guess_type(str(path))
        hashes = compute_file_hashes(path)

        results: List[OSINTResult] = [
            OSINTResult(
                module_name=self.metadata.name,
                source_name="File Fingerprint & Hashes",
                target=path.name,
                target_type=target_type,
                status=ScanStatus.FOUND,
                category="forensics",
                extracted_data={"filename": path.name, "size_bytes": path.stat().st_size, "mime_type": mime_type or "application/octet-stream", **hashes},
            ),
            OSINTResult(
                module_name=self.metadata.name,
                source_name="VirusTotal File Hash Lookup",
                target=path.name,
                target_type=target_type,
                status=ScanStatus.PASSIVE_DORK,
                reason="Passive Hash Intel Portal Ready",
                url=f"https://www.virustotal.com/gui/file/{hashes['sha256']}",
                category="forensics",
            ),
        ]

        # Native Kali ExifTool deep inspection (if installed on system)
        exiftool_data = run_kali_exiftool(path)
        if exiftool_data:
            compact = {k: v for k, v in exiftool_data.items() if k in {
                "Make", "Model", "Software", "CreatorTool", "SerialNumber",
                "CreateDate", "ModifyDate", "GPSLatitude", "GPSLongitude", "Author", "Producer"
            }}
            results.append(
                OSINTResult(
                    module_name=self.metadata.name,
                    source_name="Kali Native ExifTool",
                    target=path.name,
                    target_type=target_type,
                    status=ScanStatus.FOUND,
                    category="forensics",
                    extracted_data=compact or {"exiftool_fields_count": len(exiftool_data)},
                )
            )

        if ext in IMAGE_EXTS:
            img_meta, gps_coords, err = extract_image_metadata(path)
            if err:
                results.append(OSINTResult(self.metadata.name, "Image EXIF Parser", path.name, target_type, ScanStatus.ERROR, reason=err, category="forensics"))
            else:
                ela = compute_ela_tampering_score(path)
                if ela:
                    img_meta.update(ela)
                results.append(OSINTResult(self.metadata.name, "Image EXIF + ELA Tampering + dHash", path.name, target_type, ScanStatus.FOUND, category="forensics", extracted_data=img_meta))
                if gps_coords:
                    lat, lon = gps_coords
                    results.append(
                        OSINTResult(
                            self.metadata.name,
                            "Extracted GPS Location",
                            path.name,
                            target_type,
                            ScanStatus.FOUND,
                            url=f"https://www.google.com/maps?q={lat},{lon}",
                            category="forensics",
                            extracted_data={"latitude": lat, "longitude": lon, "osm_url": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}"},
                        )
                    )
            for label, portal in (
                ("Google Lens Reverse Image", "https://lens.google.com/"),
                ("Yandex Images Reverse Search", "https://yandex.com/images/"),
                ("TinEye Reverse Image", "https://tineye.com/"),
            ):
                results.append(OSINTResult(self.metadata.name, label, path.name, target_type, ScanStatus.PASSIVE_DORK, reason="Upload Image Manually for Reverse Search", url=portal, category="forensics"))

        elif ext == ".pdf":
            pdf_meta, err = extract_pdf_metadata(path)
            results.append(OSINTResult(self.metadata.name, "PDF Document Metadata", path.name, target_type, ScanStatus.ERROR if err else ScanStatus.FOUND, reason=err, category="forensics", extracted_data=pdf_meta))

        elif ext in OFFICE_EXTS:
            try:
                office_meta = extract_office_metadata(path)
                results.append(OSINTResult(self.metadata.name, "Office Document Metadata", path.name, target_type, ScanStatus.FOUND if office_meta else ScanStatus.NOT_FOUND, reason=None if office_meta else "No author/app tags found", category="forensics", extracted_data=office_meta))
            except Exception as exc:  # noqa: BLE001
                results.append(OSINTResult(self.metadata.name, "Office Document Metadata", path.name, target_type, ScanStatus.ERROR, reason=f"Invalid OOXML archive ({type(exc).__name__})", category="forensics"))

        return results
