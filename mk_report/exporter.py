"""Standalone report exporter (HTML, JSON, CSV, Markdown) with embedded Correlation Graph."""

from __future__ import annotations

import csv
import html
import json
from pathlib import Path
from typing import Dict, List, Optional

from mk_core import __app_name__, __version__
from mk_core.models import ScanStatus, ScanSummary
from mk_intel.correlator import CorrelationGraph, EntityCorrelator


STATUS_BADGE_CSS: Dict[str, str] = {
    ScanStatus.FOUND.value: "#22c55e",
    ScanStatus.NOT_FOUND.value: "#94a3b8",
    ScanStatus.BLOCKED.value: "#f97316",
    ScanStatus.RATE_LIMITED.value: "#eab308",
    ScanStatus.ERROR.value: "#ef4444",
    ScanStatus.PASSIVE_DORK.value: "#38bdf8",
}


class ReportExporter:
    """Exports M.K ScanSummary + CorrelationGraph into HTML, JSON, CSV, and Markdown."""

    def __init__(self, out_dir: str | Path = "reports") -> None:
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def _base_name(self, summary: ScanSummary) -> str:
        safe_target = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in summary.target)
        return f"mk_report_{safe_target[:32]}_{summary.scan_id}"

    def export_all(self, summary: ScanSummary) -> Dict[str, Path]:
        graph = EntityCorrelator.build_graph(summary.all_results())
        return {
            "html": self.export_html(summary, graph),
            "json": self.export_json(summary, graph),
            "csv": self.export_csv(summary),
            "md": self.export_markdown(summary, graph),
        }

    def export_json(
        self,
        summary: ScanSummary,
        graph: Optional[CorrelationGraph] = None,
    ) -> Path:
        graph = graph or EntityCorrelator.build_graph(summary.all_results())
        payload = {
            "framework": __app_name__,
            "version": __version__,
            "scan_id": summary.scan_id,
            "case_id": summary.case_id,
            "target": summary.target,
            "target_type": summary.target_type.value,
            "started_at": summary.started_at,
            "completed_at": summary.completed_at,
            "status_counts": summary.counts_by_status(),
            "results_by_module": {
                mod: [r.to_dict() for r in items]
                for mod, items in summary.results_by_module.items()
            },
            "correlation_graph": graph.to_dict(),
        }
        out_path = self.out_dir / f"{self._base_name(summary)}.json"
        out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return out_path

    def export_csv(self, summary: ScanSummary) -> Path:
        out_path = self.out_dir / f"{self._base_name(summary)}.csv"
        fieldnames = [
            "module_name",
            "source_name",
            "target",
            "target_type",
            "status",
            "reason",
            "formatted_status",
            "category",
            "url",
            "http_status",
            "response_time_ms",
            "extracted_data",
            "timestamp",
        ]
        # UTF-8 with BOM so Arabic characters open cleanly in Excel & LibreOffice
        with out_path.open("w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for res in summary.all_results():
                writer.writerow(
                    {
                        "module_name": res.module_name,
                        "source_name": res.source_name,
                        "target": res.target,
                        "target_type": res.target_type.value,
                        "status": res.status.value,
                        "reason": res.reason or "",
                        "formatted_status": res.formatted_status,
                        "category": res.category or "",
                        "url": res.url or "",
                        "http_status": res.http_status or "",
                        "response_time_ms": res.response_time_ms or "",
                        "extracted_data": json.dumps(res.extracted_data, ensure_ascii=False),
                        "timestamp": res.timestamp,
                    }
                )
        return out_path

    def export_markdown(
        self,
        summary: ScanSummary,
        graph: Optional[CorrelationGraph] = None,
    ) -> Path:
        graph = graph or EntityCorrelator.build_graph(summary.all_results())
        counts = summary.counts_by_status()
        lines: List[str] = [
            f"# ⚙ {__app_name__} OSINT Report — `{summary.target}`",
            "",
            f"- **Scan ID:** `{summary.scan_id}`",
            f"- **Case ID:** `{summary.case_id or 'Standalone'}`",
            f"- **Target Type:** `{summary.target_type.value}`",
            f"- **Timestamp (UTC):** `{summary.started_at}`",
            f"- **Summary:** FOUND={counts['FOUND']} | NOT_FOUND={counts['NOT_FOUND']} | BLOCKED={counts['BLOCKED']} | RATE_LIMITED={counts['RATE_LIMITED']} | ERROR={counts['ERROR']} | PASSIVE_DORK={counts['PASSIVE_DORK']}",
            "",
        ]

        for mod_name, items in summary.results_by_module.items():
            lines.append(f"## ⚙ Module: `{mod_name}` ({len(items)})")
            lines.append("")
            lines.append("| Status | Source | Category | URL / Details |")
            lines.append("| :--- | :--- | :--- | :--- |")
            for res in items:
                url_part = f"[{res.url}]({res.url})" if res.url else ""
                data_part = (
                    json.dumps(res.extracted_data, ensure_ascii=False)
                    if res.extracted_data
                    else ""
                )
                detail = " — ".join(p for p in (url_part, data_part) if p) or "-"
                lines.append(
                    f"| `{res.formatted_status}` | {res.source_name} | {res.category or '-'} | {detail} |"
                )
            lines.append("")

        if graph.edges:
            lines.append("## ⚙ Entity Correlation Graph")
            lines.append("")
            lines.append("```mermaid")
            lines.append(graph.to_mermaid())
            lines.append("```")
            lines.append("")

        out_path = self.out_dir / f"{self._base_name(summary)}.md"
        out_path.write_text("\n".join(lines), encoding="utf-8")
        return out_path

    def export_html(
        self,
        summary: ScanSummary,
        graph: Optional[CorrelationGraph] = None,
    ) -> Path:
        graph = graph or EntityCorrelator.build_graph(summary.all_results())
        counts = summary.counts_by_status()
        esc = html.escape

        module_sections: List[str] = []
        for mod_name, items in summary.results_by_module.items():
            rows_html: List[str] = []
            for res in items:
                color = STATUS_BADGE_CSS.get(res.status.value, "#94a3b8")
                badge = f'<span class="badge" style="border-color:{color};color:{color}">{esc(res.formatted_status)}</span>'
                link_html = (
                    f'<a href="{esc(res.url)}" target="_blank" rel="noopener">{esc(res.url)}</a>'
                    if res.url
                    else ""
                )
                extra_html = (
                    f'<div class="meta">{esc(json.dumps(res.extracted_data, ensure_ascii=False))}</div>'
                    if res.extracted_data
                    else ""
                )
                rows_html.append(
                    f"<tr><td>{badge}</td><td>{esc(res.source_name)}</td>"
                    f"<td>{esc(res.category or '-')}</td><td>{link_html}{extra_html}</td></tr>"
                )
            module_sections.append(
                f"""
                <section class="card">
                    <h2>⚙ Module: {esc(mod_name)} <span class="count">({len(items)})</span></h2>
                    <table>
                        <thead><tr><th>Status</th><th>Source</th><th>Category</th><th>URL &amp; Details</th></tr></thead>
                        <tbody>{''.join(rows_html)}</tbody>
                    </table>
                </section>
                """
            )

        graph_block = (
            f'<section class="card"><h2>⚙ Correlation Graph (Mermaid)</h2>'
            f'<pre class="code">{esc(graph.to_mermaid())}</pre></section>'
            if graph.edges
            else ""
        )

        doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>⚙ {esc(__app_name__)} Report — {esc(summary.target)}</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; background:#0b1120; color:#e2e8f0; margin:0; padding:24px; }}
  .wrap {{ max-width:1180px; margin:0 auto; }}
  header {{ background:#111827; border:1px solid #1e3a8a; border-radius:12px; padding:20px 24px; margin-bottom:20px; }}
  h1 {{ margin:0 0 8px; color:#38bdf8; font-size:24px; }}
  .kpis {{ display:flex; flex-wrap:wrap; gap:10px; margin-top:12px; }}
  .kpi {{ background:#0f172a; border:1px solid #334155; border-radius:8px; padding:8px 14px; font-size:13px; }}
  .card {{ background:#111827; border:1px solid #1f2937; border-radius:12px; padding:18px 20px; margin-bottom:18px; }}
  h2 {{ margin:0 0 12px; color:#c084fc; font-size:18px; }}
  .count {{ color:#94a3b8; font-weight:normal; font-size:14px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #1f2937; vertical-align:top; word-break:break-word; }}
  th {{ color:#38bdf8; background:#0f172a; }}
  .badge {{ display:inline-block; padding:2px 8px; border:1px solid; border-radius:6px; font-family:monospace; font-size:12px; font-weight:600; }}
  a {{ color:#38bdf8; text-decoration:none; }}
  a:hover {{ text-decoration:underline; }}
  .meta {{ color:#94a3b8; font-family:monospace; font-size:12px; margin-top:4px; }}
  .code {{ background:#0f172a; padding:14px; border-radius:8px; overflow-x:auto; color:#a5f3fc; font-size:12px; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>⚙ {esc(__app_name__)} OSINT Intelligence Report — {esc(summary.target)}</h1>
    <div>Scan ID: <code>{esc(summary.scan_id)}</code> | Type: <code>{esc(summary.target_type.value)}</code> | Case: <code>{esc(summary.case_id or 'Standalone')}</code> | UTC: {esc(summary.started_at)}</div>
    <div class="kpis">
      <div class="kpi" style="color:#22c55e">FOUND: {counts['FOUND']}</div>
      <div class="kpi" style="color:#94a3b8">NOT_FOUND: {counts['NOT_FOUND']}</div>
      <div class="kpi" style="color:#f97316">BLOCKED: {counts['BLOCKED']}</div>
      <div class="kpi" style="color:#eab308">RATE_LIMITED: {counts['RATE_LIMITED']}</div>
      <div class="kpi" style="color:#ef4444">ERROR: {counts['ERROR']}</div>
      <div class="kpi" style="color:#38bdf8">PASSIVE_DORK: {counts['PASSIVE_DORK']}</div>
    </div>
  </header>
  {''.join(module_sections)}
  {graph_block}
</div>
</body>
</html>"""

        out_path = self.out_dir / f"{self._base_name(summary)}.html"
        out_path.write_text(doc, encoding="utf-8")
        return out_path
