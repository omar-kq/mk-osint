"""M.K v2.2 — Kali Linux Native OSINT Toolchain Bridge.

Auto-detects installed Kali OSINT binaries (`exiftool`, `whois`, `dig`, `theHarvester`,
`sherlock`, `maigret`, `subfinder`, `amass`, `holehe`, `mat2`) and runs applicable ones
with strict timeout and fault isolation so missing or failing tools never crash M.K.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional

from mk_core.models import ModuleMetadata, OSINTResult, ScanStatus, TargetType
from mk_core.registry import BaseOSINTModule


@dataclass(frozen=True)
class KaliToolSpec:
    binary: str
    apt_package: str
    supported_targets: List[TargetType]
    args_template: List[str]
    description: str


KALI_OSINT_TOOLS: List[KaliToolSpec] = [
    KaliToolSpec("exiftool", "libimage-exiftool-perl", [TargetType.FILE], ["exiftool", "-j", "-n", "{target}"], "Deep image/video/PDF metadata forensics"),
    KaliToolSpec("whois", "whois", [TargetType.DOMAIN, TargetType.IP], ["whois", "{target}"], "Native WHOIS registrar & ASN lookup"),
    KaliToolSpec("dig", "dnsutils", [TargetType.DOMAIN], ["dig", "+short", "ANY", "{target}"], "Native DNS record resolver"),
    KaliToolSpec("theHarvester", "theharvester", [TargetType.DOMAIN], ["theHarvester", "-d", "{target}", "-b", "crtsh,duckduckgo", "-l", "20"], "Passive emails & subdomains harvester"),
    KaliToolSpec("subfinder", "subfinder", [TargetType.DOMAIN], ["subfinder", "-silent", "-d", "{target}"], "Fast passive subdomain discovery"),
    KaliToolSpec("sherlock", "sherlock", [TargetType.USERNAME], ["sherlock", "{target}", "--timeout", "8", "--print-found"], "Global username OSINT database"),
    KaliToolSpec("maigret", "maigret", [TargetType.USERNAME], ["maigret", "{target}", "--timeout", "8", "--no-progressbar"], "Deep username OSINT with profile extraction"),
    KaliToolSpec("holehe", "holehe", [TargetType.EMAIL], ["holehe", "{target}", "--only-used"], "Public email registration footprint check"),
    KaliToolSpec("mat2", "mat2", [TargetType.FILE], ["mat2", "--show", "{target}"], "Metadata inspection across media/docs"),
]


def detect_kali_tools() -> Dict[str, bool]:
    """Return availability map of all supported native Kali OSINT tools."""
    return {spec.binary: shutil.which(spec.binary) is not None for spec in KALI_OSINT_TOOLS}


def _run_tool_sync(cmd: List[str], timeout_s: int = 25) -> tuple[int, str, str]:
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )
    return proc.returncode, proc.stdout[:8192], proc.stderr[:2048]


class KaliToolchainBridgeModule(BaseOSINTModule):
    """Wraps installed native Kali Linux OSINT tools directly inside M.K's pipeline."""

    metadata = ModuleMetadata(
        name="kali_toolchain_bridge",
        display_name="Kali Linux Native OSINT Bridge",
        version="2.2.0",
        description="Auto-detects & orchestrates installed Kali OSINT tools (exiftool, whois, dig, theHarvester, sherlock, maigret, subfinder, holehe, mat2).",
        supported_targets=[TargetType.USERNAME, TargetType.EMAIL, TargetType.DOMAIN, TargetType.IP, TargetType.FILE],
        category="kali_native",
        requires_network=False,
        passive_only=True,
        enabled_by_default=False,  # Run via `-m kali_toolchain_bridge`
    )

    async def run(self, target: str, target_type: TargetType) -> List[OSINTResult]:
        matching = [spec for spec in KALI_OSINT_TOOLS if target_type in spec.supported_targets]
        results: List[OSINTResult] = []

        for spec in matching:
            if shutil.which(spec.binary) is None:
                results.append(
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name=f"Kali:{spec.binary}",
                        target=target,
                        target_type=target_type,
                        status=ScanStatus.NOT_FOUND,
                        reason=f"Not Installed — run: sudo apt install -y {spec.apt_package}",
                        category="kali_native",
                    )
                )
                continue

            cmd = [part.format(target=target) for part in spec.args_template]
            try:
                rc, stdout, stderr = await asyncio.to_thread(_run_tool_sync, cmd, 25)
                if rc == 0 and stdout.strip():
                    results.append(
                        OSINTResult(
                            module_name=self.metadata.name,
                            source_name=f"Kali:{spec.binary}",
                            target=target,
                            target_type=target_type,
                            status=ScanStatus.FOUND,
                            category="kali_native",
                            extracted_data={"output_preview": stdout.strip()[:1200]},
                        )
                    )
                else:
                    results.append(
                        OSINTResult(
                            module_name=self.metadata.name,
                            source_name=f"Kali:{spec.binary}",
                            target=target,
                            target_type=target_type,
                            status=ScanStatus.ERROR if rc != 0 else ScanStatus.NOT_FOUND,
                            reason=stderr.strip()[:160] if rc != 0 else "No output returned",
                            category="kali_native",
                        )
                    )
            except subprocess.TimeoutExpired:
                results.append(
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name=f"Kali:{spec.binary}",
                        target=target,
                        target_type=target_type,
                        status=ScanStatus.ERROR,
                        reason="Tool Timeout (25s Skipped Safely)",
                        category="kali_native",
                    )
                )
            except Exception as exc:  # noqa: BLE001
                results.append(
                    OSINTResult(
                        module_name=self.metadata.name,
                        source_name=f"Kali:{spec.binary}",
                        target=target,
                        target_type=target_type,
                        status=ScanStatus.ERROR,
                        reason=f"Skipped Safely ({type(exc).__name__})",
                        category="kali_native",
                    )
                )

        return results
