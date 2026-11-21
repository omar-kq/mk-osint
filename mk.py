#!/usr/bin/env python3
"""M.K v2.1.0 — Cyberpunk 3D-Gear MENA OSINT Framework (Super Multi-Field Scan, CLI, Menu & TUI)."""

from __future__ import annotations

import argparse
import asyncio
import shlex
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from mk_ai.local_rag import LocalRAGProvider
from mk_core import __version__
from mk_core.config import ConfigManager
from mk_core.engine import MKEngine
from mk_core.models import OSINTResult, ScanSummary, TargetType
from mk_db.listener import StorageEventListener
from mk_db.repository import MKDatabase
from mk_intel.batch import BatchQueueScanner, load_targets_file
from mk_intel.correlator import EntityCorrelator
from mk_intel.diff_monitor import ScanDiffMonitor
from mk_report.exporter import ReportExporter
from mk_ui.console import MKConsole
from mk_ui.themes import THEMES
from mk_ui.tui_app import launch_tui


MENU_TEXT = (
    "[1] ⚡ SUPER SEARCH (Multi-Field: Phone + Email + Username + Domain + IP + File + Name)\n"
    "[2] Smart Single Scan (Auto-detect target type)\n"
    "[3] Arabic / Franco Username Permutations\n"
    "[4] Image / PDF / Office Metadata Forensics (File)\n"
    "[5] MENA Bilingual Dorks Generator\n"
    "[6] Case Management (Create / List Cases)\n"
    "[7] Search Saved SQLite Archive (FTS5 Arabic/English)\n"
    "[8] Local AI & Custom Database (Import CSV/JSON/SQLite or Ask)\n"
    "[9] Export Last Scan (HTML / JSON / CSV / Markdown) & Graph\n"
    "[T] Switch Theme / Show Loaded Modules\n"
    "[0] Exit  (or type any direct command like: scan ahmed_eg)"
)

SUPER_FIELDS: List[Tuple[str, str, TargetType]] = [
    ("username", "Username (اليوزر نيم)", TargetType.USERNAME),
    ("email", "Email (الإيميل)", TargetType.EMAIL),
    ("phone", "Phone (رقم التليفون)", TargetType.PHONE),
    ("domain", "Domain (الدومين)", TargetType.DOMAIN),
    ("ip", "IP Address (عنوان الـ IP)", TargetType.IP),
    ("file", "File Path (مسار صورة / PDF / DOCX)", TargetType.FILE),
    ("keyword", "Arabic/English Name (الاسم للتنويعات والـ Dorks)", TargetType.KEYWORD),
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mk",
        description="⚡ ⚙ M.K v2.1.0 — Cyberpunk 3D-Gear MENA OSINT Framework",
    )
    parser.add_argument("-t", "--target", help="Single target (username, email, phone, domain, IP, file, or keyword).")
    parser.add_argument("--type", choices=[t.value for t in TargetType], help="Override auto-detected target type.")
    parser.add_argument("-m", "--modules", nargs="+", help="Run only specific module name(s).")
    parser.add_argument("--super", action="store_true", dest="super_mode", help="Launch Super Multi-Field Search directly.")
    parser.add_argument("--batch", help="Path to .txt or .csv file containing multiple targets.")
    parser.add_argument("--checkpoint", default="data/batch_checkpoint.json", help="Checkpoint file for batch resume.")
    parser.add_argument("--diff", action="store_true", help="Compare current scan against prior SQLite records.")
    parser.add_argument("--case", help="Case title or ID to group scans under in SQLite.")
    parser.add_argument("--proxy", help="Route HTTP requests through proxy/Tor (e.g. socks5h://127.0.0.1:9050).")
    parser.add_argument("--include-gov-edu", action="store_true", help="Enable optional Category 15 passive academic/gov dorks.")
    parser.add_argument("--import-db", help="Import custom CSV/JSON/SQLite/TXT database into local AI index.")
    parser.add_argument("--ai-ask", help="Query local AI / custom database index in Arabic or English.")
    parser.add_argument("--enable-ai", action="store_true", help="Activate LocalRAGProvider during this run.")
    parser.add_argument("--ollama", action="store_true", help="Enable local Ollama LLM synthesis.")
    parser.add_argument("--export", choices=["html", "json", "csv", "md", "all"], help="Export report format after scan.")
    parser.add_argument("--out-dir", default="reports", help="Directory for exported reports.")
    parser.add_argument("--theme", choices=list(THEMES.keys()), help="Select terminal color theme.")
    parser.add_argument("--tui", action="store_true", help="Launch full-screen Textual split-pane TUI dashboard.")
    parser.add_argument("--list-modules", action="store_true", help="List all discovered M.K modules and exit.")
    parser.add_argument("--version", action="version", version=f"⚙ M.K OSINT Framework v{__version__}")
    return parser


def _handle_export(summary: ScanSummary, fmt: str, out_dir: str, ui: MKConsole) -> None:
    exporter = ReportExporter(out_dir=out_dir)
    if fmt == "all":
        for kind, path in exporter.export_all(summary).items():
            ui.success(f"Exported {kind.upper()} report -> {path}")
    elif fmt == "html":
        ui.success(f"Exported HTML report -> {exporter.export_html(summary)}")
    elif fmt == "json":
        ui.success(f"Exported JSON report -> {exporter.export_json(summary)}")
    elif fmt == "csv":
        ui.success(f"Exported CSV report -> {exporter.export_csv(summary)}")
    elif fmt == "md":
        ui.success(f"Exported Markdown report -> {exporter.export_markdown(summary)}")


async def run_super_search(
    engine: MKEngine,
    db: MKDatabase,
    ui: MKConsole,
    inputs: Dict[TargetType, str],
    case_id: Optional[str] = None,
    module_overrides: Optional[Dict[TargetType, List[str]]] = None,
) -> List[ScanSummary]:
    """Execute each provided target field INDEPENDENTLY, isolate results, and correlate at the end."""
    active_items = [(t_type, val.strip()) for t_type, val in inputs.items() if val and val.strip()]
    if not active_items:
        ui.warn("No fields provided for Super Search.")
        return []

    resolved_case_id = case_id or db.create_case(
        title=f"Super Search ({', '.join(v for _, v in active_items[:3])})",
        tags=["super_search"],
    ).case_id

    summaries: List[ScanSummary] = []
    combined_results: List[OSINTResult] = []

    for idx, (t_type, val) in enumerate(active_items, start=1):
        mods = (module_overrides or {}).get(t_type)
        if mods is None and t_type == TargetType.KEYWORD:
            mods = ["username_permutations", "mena_dorks"]

        ui.info(f"⚡ Super Search [{idx}/{len(active_items)}] → Running independent {t_type.value.upper()} scan: {val}")
        summary = await ui.run_with_spinning_gear(
            engine.scan(target=val, target_type=t_type, module_names=mods, case_id=resolved_case_id),
            label=f"Scanning {t_type.value.upper()}: {val}",
        )
        ui.show_scan_summary(summary)
        summaries.append(summary)
        combined_results.extend(summary.all_results())

    # Cross-target correlation across all independently scanned fields
    graph = EntityCorrelator.build_graph(combined_results)
    ui.success(
        f"⚡ Super Search Complete (Case: {resolved_case_id}) — "
        f"{len(summaries)} independent scans | Graph: {len(graph.nodes)} nodes, "
        f"{len(graph.edges)} links, {len(graph.pivots)} cross-target pivot(s)."
    )
    for pivot in graph.pivots:
        ui.success(f"  ↳ {pivot}")

    return summaries


async def interactive_shell(
    engine: MKEngine,
    db: MKDatabase,
    ai_provider: LocalRAGProvider,
    ui: MKConsole,
) -> None:
    """Cyberpunk hybrid shell: Super Multi-Field Search + Numbered Menu [1-9] + Direct Commands."""
    active_case_id: Optional[str] = None
    last_summary: Optional[ScanSummary] = None
    ui.info(f"⚡ CYBERPUNK COMMAND DECK:\n{MENU_TEXT}")

    while True:
        prompt_prefix = f"⚙ M.K [{active_case_id}] ⚡ " if active_case_id else "⚙ M.K ⚡ "
        try:
            raw = input(f"\n{prompt_prefix}").strip()
        except (EOFError, KeyboardInterrupt):
            ui.info("Disconnecting M.K.")
            break

        if not raw:
            continue

        if raw == "0":
            ui.info("Session terminated.")
            break
        if raw == "1":
            ui.info("⚡ SUPER SEARCH — Fill any fields you have (press Enter to skip any field). Each field runs INDEPENDENTLY:")
            collected: Dict[TargetType, str] = {}
            for _, label, t_type in SUPER_FIELDS:
                val = input(f"  [{label}]: ").strip()
                if val:
                    collected[t_type] = val
            summaries = await run_super_search(engine, db, ui, collected, case_id=active_case_id)
            if summaries:
                last_summary = summaries[-1]
            continue
        if raw == "2":
            target = input("  Enter target (username / email / +2010... / domain / IP): ").strip()
            if target:
                last_summary = await ui.run_with_spinning_gear(
                    engine.scan(target=target, case_id=active_case_id),
                    label=f"Scanning {target}",
                )
                ui.show_scan_summary(last_summary)
            continue
        if raw == "3":
            name = input("  Enter Arabic or Latin name/handle: ").strip()
            if name:
                last_summary = await ui.run_with_spinning_gear(
                    engine.scan(target=name, target_type=TargetType.KEYWORD, module_names=["username_permutations"], case_id=active_case_id),
                    label=f"Generating MENA variants for {name}",
                )
                ui.show_scan_summary(last_summary)
            continue
        if raw == "4":
            fpath = input("  Enter local file path (image / PDF / DOCX): ").strip()
            if fpath:
                last_summary = await ui.run_with_spinning_gear(
                    engine.scan(target=fpath, target_type=TargetType.FILE, module_names=["media_metadata"], case_id=active_case_id),
                    label=f"Inspecting metadata: {fpath}",
                )
                ui.show_scan_summary(last_summary)
            continue
        if raw == "5":
            kw = input("  Enter target for MENA Bilingual Dorks: ").strip()
            if kw:
                last_summary = await engine.scan(
                    target=kw, target_type=TargetType.KEYWORD, module_names=["mena_dorks"], case_id=active_case_id
                )
                ui.show_scan_summary(last_summary)
            continue
        if raw == "6":
            sub = input("  Case action ([n]ew / [l]ist): ").strip().lower()
            if sub.startswith("n"):
                title = input("  Case title: ").strip()
                if title:
                    rec = db.create_case(title)
                    active_case_id = rec.case_id
                    ui.success(f"Active case: {rec.case_id} ({rec.title})")
            else:
                for c in db.list_cases():
                    ui.info(f"{c.case_id} | [{c.status}] {c.title}")
            continue
        if raw == "7":
            q = input("  Search SQLite FTS5 archive (Arabic/English): ").strip()
            if q:
                hits = db.search_fts(q, limit=20)
                if not hits:
                    ui.warn("No FTS5 matches found.")
                for h in hits:
                    ui.info(f"{h.formatted_status} [{h.module_name}] {h.source_name}: {h.url or h.extracted_data}")
            continue
        if raw == "8":
            sub = input("  AI action ([i]mport DB / [a]sk question): ").strip().lower()
            if sub.startswith("i"):
                p = input("  Path to CSV / JSON / SQLite file: ").strip()
                if p:
                    cnt = await ai_provider.index_custom_database(p)
                    ui.success(f"Indexed {cnt} records from {p}.")
            else:
                q = input("  Ask local AI / custom DB: ").strip()
                if q:
                    insight = await ai_provider.query_database(q, top_k=6)
                    ui.success(f"Answer (conf={insight.confidence}): {insight.answer}")
            continue
        if raw == "9":
            if not last_summary:
                ui.warn("Run a scan first.")
            else:
                _handle_export(last_summary, "all", "reports", ui)
            continue
        if raw.lower() == "t":
            ui.show_modules(engine.registry.list_all())
            t_choice = input(f"  Switch theme ({', '.join(THEMES.keys())}) or Enter to skip: ").strip()
            if t_choice in THEMES:
                ui.set_theme(t_choice)
                engine.config.set("app.theme", t_choice)
                ui.show_banner(len(engine.registry.list_all()), bool(engine.config.get("opsec.use_proxy")), engine.ai_manager.is_enabled)
            continue

        parts = shlex.split(raw)
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in {"exit", "quit", "q"}:
            ui.info("Session terminated.")
            break
        if cmd in {"help", "menu"}:
            ui.info(f"⚡ CYBERPUNK COMMAND DECK:\n{MENU_TEXT}")
        elif cmd == "modules":
            ui.show_modules(engine.registry.list_all())
        elif cmd == "scan" and args:
            t_type = TargetType(args[1]) if len(args) > 1 and args[1] in {t.value for t in TargetType} else None
            last_summary = await ui.run_with_spinning_gear(
                engine.scan(target=args[0], target_type=t_type, case_id=active_case_id),
                label=f"Scanning {args[0]}",
            )
            ui.show_scan_summary(last_summary)
        elif cmd == "export" and last_summary:
            _handle_export(last_summary, args[0] if args else "all", "reports", ui)
        elif cmd == "graph" and last_summary:
            g = EntityCorrelator.build_graph(last_summary.all_results())
            gfmt = args[0] if args else "mermaid"
            print(g.to_graphviz_dot() if gfmt == "dot" else g.to_json() if gfmt == "json" else g.to_mermaid())
        else:
            ui.warn("Unknown input. Type 1-9, T, or 'menu'.")


async def async_main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config = ConfigManager()
    if args.theme:
        config.set("app.theme", args.theme)
    if args.proxy:
        config.set("opsec.use_proxy", True)
        config.set("opsec.proxy_url", args.proxy)
    if args.include_gov_edu:
        config.set("mena.enable_optional_academic_gov_dorks", True)
    if args.enable_ai or args.ollama:
        config.set("ai.enabled", True)

    engine = MKEngine(config=config)
    data_dir = Path(config.get("app.data_dir", "data"))
    db = MKDatabase(data_dir / "mk_osint.db")
    StorageEventListener(db, engine.events)

    ai_provider = LocalRAGProvider(
        index_db_path=data_dir / "ai_index.db",
        ollama_endpoint=str(config.get("ai.endpoint", "http://127.0.0.1:11434")),
        model_name=str(config.get("ai.model_name", "qwen2.5:3b")),
        use_ollama=bool(args.ollama),
    )
    if config.get("ai.enabled", False):
        engine.ai_manager.set_provider(ai_provider)

    ui = MKConsole(theme_name=config.get("app.theme", "cyberpunk_neon"))

    try:
        if args.tui:
            if launch_tui(engine, db, ai_provider):
                return 0
            ui.warn("Textual is not installed (run: pip install textual). Falling back to Cyberpunk shell.")

        ui.show_banner(
            modules_loaded=len(engine.registry.list_all()),
            proxy_enabled=bool(config.get("opsec.use_proxy", False)),
            ai_enabled=engine.ai_manager.is_enabled,
        )

        if args.list_modules:
            ui.show_modules(engine.registry.list_all())
            return 0

        if args.import_db:
            imported = await ai_provider.index_custom_database(args.import_db)
            ui.success(f"Imported {imported} records from '{args.import_db}' into Local AI index.")
            if not args.ai_ask and not args.target and not args.batch:
                return 0

        if args.ai_ask:
            insight = await ai_provider.query_database(args.ai_ask, top_k=6)
            ui.info(f"AI Query: {args.ai_ask}")
            ui.success(f"Answer: {insight.answer}")
            return 0

        case_id: Optional[str] = None
        if args.case:
            existing = db.get_case(args.case)
            case_id = existing.case_id if existing else db.create_case(args.case).case_id

        if args.super_mode:
            collected: Dict[TargetType, str] = {}
            for _, label, t_type in SUPER_FIELDS:
                val = input(f"  [{label}]: ").strip()
                if val:
                    collected[t_type] = val
            await run_super_search(engine, db, ui, collected, case_id=case_id)
            return 0

        if args.batch:
            items = load_targets_file(args.batch)
            scanner = BatchQueueScanner(engine, checkpoint_path=args.checkpoint)
            summaries, skipped = await ui.run_with_spinning_gear(
                scanner.run_batch(items, module_names=args.modules, case_id=case_id),
                label=f"Batch scanning {len(items)} targets",
            )
            ui.success(f"Batch complete: scanned={len(summaries)}, resumed_skipped={skipped}")
            for sm in summaries:
                ui.show_scan_summary(sm)
                if args.export:
                    _handle_export(sm, args.export, args.out_dir, ui)
            return 0

        if args.target:
            baseline = db.search_fts(args.target, limit=200) if args.diff else []
            explicit_type = TargetType(args.type) if args.type else None
            summary = await ui.run_with_spinning_gear(
                engine.scan(
                    target=args.target,
                    target_type=explicit_type,
                    module_names=args.modules,
                    case_id=case_id,
                ),
                label=f"Scanning {args.target}",
            )
            ui.show_scan_summary(summary)
            if args.diff:
                diff = ScanDiffMonitor.compare(baseline, summary.all_results())
                ui.info(f"Diff vs previous SQLite archive: {diff.summary_dict()}")
            if args.export:
                _handle_export(summary, args.export, args.out_dir, ui)
            return 0

        await interactive_shell(engine, db, ai_provider, ui)
        return 0
    finally:
        ai_provider.close()
        db.close()


def main() -> None:
    sys.exit(asyncio.run(async_main()))


if __name__ == "__main__":
    main()
