"""M.K Phase 15 — Full-Screen Interactive Split-Pane Terminal Dashboard (Textual TUI).

Gracefully falls back to MKConsole's Rich interactive shell if `textual` is not installed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from mk_ai.local_rag import LocalRAGProvider
from mk_core import __app_name__, __version__
from mk_core.engine import MKEngine
from mk_db.repository import MKDatabase
from mk_intel.correlator import EntityCorrelator

try:
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, Vertical
    from textual.widgets import Button, DataTable, Footer, Header, Input, Log, Static, TabbedContent, TabPane

    HAS_TEXTUAL = True
except ImportError:  # pragma: no cover
    HAS_TEXTUAL = False


if HAS_TEXTUAL:

    class MKTUIApp(App):  # type: ignore[misc]
        """Full-screen split-pane M.K v2.0 OSINT Terminal Dashboard."""

        TITLE = f"⚙ {__app_name__} v{__version__} — MENA OSINT Dashboard"
        SUB_TITLE = "Kali Linux • 15 MENA Categories • Local AI Ready"
        CSS = """
        Screen { background: #0b1120; color: #e2e8f0; }
        #top-bar { height: 3; margin: 1 1 0 1; }
        #target-input { width: 1fr; }
        #main-split { height: 1fr; margin: 1; }
        #sidebar { width: 28; border: solid #1e3a8a; padding: 1; background: #111827; }
        #content-area { width: 1fr; border: solid #1e3a8a; padding: 1; background: #0f172a; }
        .section-title { color: #38bdf8; text-style: bold; margin-bottom: 1; }
        """
        BINDINGS = [("q", "quit", "Quit"), ("l", "clear_log", "Clear Log")]

        def __init__(self, engine: MKEngine, db: MKDatabase, ai_provider: LocalRAGProvider) -> None:
            super().__init__()
            self.engine = engine
            self.db = db
            self.ai_provider = ai_provider

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Horizontal(id="top-bar"):
                yield Input(placeholder="Enter target (username / email / +2010... / domain / IP) or AI question...", id="target-input")
                yield Button("⚙ Scan", id="btn-scan", variant="primary")
                yield Button("AI Search", id="btn-ai", variant="success")
            with Horizontal(id="main-split"):
                with Vertical(id="sidebar"):
                    yield Static("⚙ Loaded Modules", classes="section-title")
                    mod_lines = "\n".join(f"• {m.metadata.name}" for m in self.engine.registry.list_all())
                    yield Static(mod_lines or "No modules")
                with Vertical(id="content-area"):
                    with TabbedContent():
                        with TabPane("Scan Results", id="tab-results"):
                            yield DataTable(id="results-table")
                        with TabPane("Correlation Graph", id="tab-graph"):
                            yield Log(id="graph-log")
                        with TabPane("Local AI / Custom DB", id="tab-ai"):
                            yield Log(id="ai-log")
            yield Footer()

        def on_mount(self) -> None:
            table = self.query_one("#results-table", DataTable)
            table.add_columns("Module", "Status", "Source", "Category", "URL / Details")

        async def on_button_pressed(self, event: Button.Pressed) -> None:
            raw = self.query_one("#target-input", Input).value.strip()
            if not raw:
                return
            if event.button.id == "btn-scan":
                summary = await self.engine.scan(raw)
                table = self.query_one("#results-table", DataTable)
                table.clear()
                for res in summary.all_results():
                    detail = res.url or str(res.extracted_data)
                    table.add_row(res.module_name, res.formatted_status, res.source_name, res.category or "-", detail[:120])
                graph = EntityCorrelator.build_graph(summary.all_results())
                glog = self.query_one("#graph-log", Log)
                glog.clear()
                glog.write_line(graph.to_mermaid())
            elif event.button.id == "btn-ai":
                insight = await self.ai_provider.query_database(raw, top_k=8)
                ailog = self.query_one("#ai-log", Log)
                ailog.clear()
                ailog.write_line(f"Query: {raw}\nAnswer: {insight.answer}\n")
                for rec in insight.matched_records:
                    ailog.write_line(f"[{rec['score']}] ({rec['source']}) {rec['text']}")


async def launch_tui(engine: MKEngine, db: MKDatabase, ai_provider: LocalRAGProvider) -> bool:
    """Launch full-screen Textual dashboard if installed; returns False if fallback needed."""
    if not HAS_TEXTUAL:
        return False
    app = MKTUIApp(engine=engine, db=db, ai_provider=ai_provider)
    await app.run_async()
    return True
