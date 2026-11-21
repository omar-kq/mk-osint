"""Cyberpunk Rich-powered Terminal UI with Live 3D Rotating Gear & 7-State Semantic Colors."""

from __future__ import annotations

import asyncio
import sys
from typing import Awaitable, List, TypeVar

from mk_core.models import ScanStatus, ScanSummary
from mk_core.registry import BaseOSINTModule
from mk_ui.banner import GEAR_3D_FRAMES, GEAR_LOGO_3D, build_status_line
from mk_ui.themes import MKTheme, get_theme

try:
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import box

    HAS_RICH = True
except ImportError:  # pragma: no cover
    HAS_RICH = False

T = TypeVar("T")


class MKConsole:
    """Cyberpunk terminal renderer with 7-state semantic status colors and animated 3D gear."""

    def __init__(self, theme_name: str = "cyberpunk_neon") -> None:
        self.theme: MKTheme = get_theme(theme_name)
        self.console = Console() if HAS_RICH else None

    def set_theme(self, theme_name: str) -> None:
        self.theme = get_theme(theme_name)

    def _status_style(self, status: ScanStatus) -> str:
        mapping = {
            ScanStatus.FOUND: self.theme.found,
            ScanStatus.SUSPENDED_OR_DELETED: self.theme.suspended_deleted,
            ScanStatus.NOT_FOUND: self.theme.not_found,
            ScanStatus.BLOCKED: self.theme.blocked,
            ScanStatus.RATE_LIMITED: self.theme.rate_limited,
            ScanStatus.ERROR: self.theme.error,
            ScanStatus.PASSIVE_DORK: self.theme.passive_dork,
        }
        return mapping.get(status, self.theme.muted)

    def show_banner(
        self,
        modules_loaded: int,
        proxy_enabled: bool = False,
        ai_enabled: bool = False,
    ) -> None:
        status_line = build_status_line(
            theme_name=self.theme.name,
            modules_loaded=modules_loaded,
            proxy_enabled=proxy_enabled,
            ai_enabled=ai_enabled,
        )
        if not HAS_RICH or self.console is None:
            print(GEAR_LOGO_3D)
            print(status_line)
            print("=" * 76)
            return

        lines = GEAR_LOGO_3D.strip("\n").splitlines()
        styled = Text()
        palette = self.theme.gear_cycle
        for idx, line in enumerate(lines):
            styled.append(line + "\n", style=palette[idx % len(palette)])

        panel = Panel(
            styled,
            title=f"[{self.theme.secondary}]⚡ ⚙ M.K CYBERPUNK OSINT ENGINE ⚙ ⚡[/]",
            subtitle=f"[{self.theme.accent}]{status_line}[/]",
            border_style=self.theme.border,
            box=box.DOUBLE_EDGE,
            padding=(0, 2),
        )
        self.console.print(panel)

    async def run_with_spinning_gear(
        self,
        coro: Awaitable[T],
        label: str = "Scanning target...",
    ) -> T:
        if not HAS_RICH or self.console is None or not sys.stdout.isatty():
            return await coro

        task = asyncio.create_task(coro)
        frame_idx = 0
        cycle = self.theme.gear_cycle

        with Live(console=self.console, refresh_per_second=10, transient=True) as live:
            while not task.done():
                gear_art = GEAR_3D_FRAMES[frame_idx % len(GEAR_3D_FRAMES)]
                color = cycle[frame_idx % len(cycle)]
                renderable = Panel(
                    Text(f"{gear_art}\n\n⚡ {label}", style=color, justify="center"),
                    title=f"[{self.theme.secondary}]⚙ M.K SCANNING[/]",
                    border_style=color,
                    box=box.HEAVY,
                    width=48,
                )
                live.update(renderable)
                frame_idx += 1
                await asyncio.sleep(0.12)

        return await task

    def show_modules(self, modules: List[BaseOSINTModule]) -> None:
        if not HAS_RICH or self.console is None:
            for mod in modules:
                targets = ", ".join(t.value for t in mod.metadata.supported_targets)
                print(f"- {mod.metadata.name} ({targets}): {mod.metadata.description}")
            return

        table = Table(
            title=f"[{self.theme.primary}]⚙ Loaded M.K Modules ({len(modules)})[/]",
            box=box.ROUNDED,
            border_style=self.theme.border,
            header_style=self.theme.secondary,
        )
        table.add_column("Module", style=self.theme.primary, no_wrap=True)
        table.add_column("Version", style=self.theme.muted, justify="center")
        table.add_column("Targets", style=self.theme.accent)
        table.add_column("Mode", justify="center")
        table.add_column("Description")

        for mod in modules:
            meta = mod.metadata
            targets = ", ".join(t.value for t in meta.supported_targets)
            mode = "Passive" if meta.passive_only else "Active/Hybrid"
            table.add_row(meta.name, meta.version, targets, mode, meta.description)

        self.console.print(table)

    def show_scan_summary(self, summary: ScanSummary) -> None:
        counts = summary.counts_by_status()

        if not HAS_RICH or self.console is None:
            print(f"\nScan {summary.scan_id} | Target: {summary.target} ({summary.target_type.value})")
            for mod_name, results in summary.results_by_module.items():
                print(f"\n--- Module: {mod_name} ({len(results)} items) ---")
                for res in results:
                    print(f"  {res.formatted_status} {res.source_name} -> {res.url or res.extracted_data}")
            print(f"\nCounts: {counts}")
            return

        header = (
            f"[{self.theme.primary}]TARGET:[/] [bold white]{summary.target}[/]  │  "
            f"[{self.theme.primary}]TYPE:[/] [{self.theme.accent}]{summary.target_type.value.upper()}[/]  │  "
            f"[{self.theme.primary}]SCAN ID:[/] {summary.scan_id}\n"
            f"[{self.theme.found}]● FOUND: {counts['FOUND']}[/]  "
            f"[{self.theme.suspended_deleted}]⊘ SUSP/DEL: {counts['SUSPENDED_OR_DELETED']}[/]  "
            f"[{self.theme.blocked}]✖ BLOCKED: {counts['BLOCKED']}[/]  "
            f"[{self.theme.error}]✖ ERR: {counts['ERROR']}[/]  "
            f"[{self.theme.rate_limited}]▲ 429: {counts['RATE_LIMITED']}[/]  "
            f"[{self.theme.passive_dork}]◆ DORK: {counts['PASSIVE_DORK']}[/]  "
            f"[{self.theme.not_found}]○ 404: {counts['NOT_FOUND']}[/]"
        )
        self.console.print(
            Panel(
                header,
                title=f"[{self.theme.secondary}]⚡ ⚙ SCAN TELEMETRY[/]",
                border_style=self.theme.border,
                box=box.HEAVY,
            )
        )

        for mod_name, results in summary.results_by_module.items():
            table = Table(
                title=f"[{self.theme.secondary}]⚙ MODULE: {mod_name.upper()}[/] [{self.theme.muted}]({len(results)} results)[/]",
                box=box.SIMPLE_HEAVY,
                border_style=self.theme.border,
                header_style=self.theme.primary,
                expand=True,
            )
            table.add_column("Status", no_wrap=True)
            table.add_column("Source", style=self.theme.primary, no_wrap=True)
            table.add_column("Category", style=self.theme.muted)
            table.add_column("URL / Extracted Details", overflow="fold")

            for res in results:
                st_style = self._status_style(res.status)
                detail = res.url or ""
                if res.extracted_data:
                    kv = ", ".join(f"{k}: {v}" for k, v in res.extracted_data.items())
                    detail = f"{detail} | {kv}" if detail else kv
                table.add_row(
                    f"[{st_style}]{res.formatted_status}[/]",
                    res.source_name,
                    res.category or "-",
                    detail or "-",
                )
            self.console.print(table)

    def info(self, message: str) -> None:
        if HAS_RICH and self.console:
            self.console.print(f"[{self.theme.primary}]⚙[/] {message}")
        else:
            print(f"[*] {message}")

    def success(self, message: str) -> None:
        if HAS_RICH and self.console:
            self.console.print(f"[{self.theme.found}]✔[/] {message}")
        else:
            print(f"[+] {message}")

    def warn(self, message: str) -> None:
        if HAS_RICH and self.console:
            self.console.print(f"[{self.theme.rate_limited}]▲[/] {message}")
        else:
            print(f"[!] {message}")

    def error(self, message: str) -> None:
        if HAS_RICH and self.console:
            self.console.print(f"[{self.theme.error}]✖[/] {message}")
        else:
            print(f"[x] {message}")
