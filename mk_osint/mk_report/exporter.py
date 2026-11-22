"""M.K v3.0 — Visual Report Exporter (HTML with Visual Avatars/Files Gallery, JSON, CSV, Markdown)."""

from __future__ import annotations

import base64
import csv
import html
import json
from pathlib import Path
from typing import Dict, List, Optional

from mk_core import __app_name__, __version__
from mk_core.models import ScanStatus, ScanSummary, TargetType
from mk_intel.correlator import CorrelationGraph, EntityCorrelator


STATUS_BADGE_CSS: Dict[str, str] = {
    ScanStatus.FOUND.value: "#00ff9f",
    ScanStatus.SUSPENDED_OR_DELETED.value: "#b026ff",
    ScanStatus.NOT_FOUND.value: "#94a3b8",
    ScanStatus.BLOCKED.value: "#ff2a6d",
    ScanStatus.RATE_LIMITED.value: "#fcee0a",
    ScanStatus.ERROR.value: "#ff003c",
    ScanStatus.PASSIVE_DORK.value: "#05d9e8",
}


class ReportExporter:
    """Exports M.K ScanSummary + Visual Media Gallery + CorrelationGraph into HTML, JSON, CSV, and Markdown."""

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

    def export_json(self, summary: ScanSummary, graph: Optional[CorrelationGraph] = None) -> Path:
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
            "module_name", "source_name", "target", "target_type", "status",
            "reason", "formatted_status", "category", "url", "http_status",
            "response_time_ms", "extracted_data", "timestamp",
        ]
        with out_path.open("w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for res in summary.all_results():
                writer.writerow({
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
                })
        return out_path

    def export_markdown(self, summary: ScanSummary, graph: Optional[CorrelationGraph] = None) -> Path:
        graph = graph or EntityCorrelator.build_graph(summary.all_results())
        counts = summary.counts_by_status()
        lines: List[str] = [
            f"# ⚙ {__app_name__} v{__version__} OSINT Report — `{summary.target}`",
            "",
            f"- **Scan ID:** `{summary.scan_id}` | **Case:** `{summary.case_id or 'Standalone'}` | **Type:** `{summary.target_type.value}`",
            f"- **Summary:** FOUND={counts['FOUND']} | SUSP/DEL={counts['SUSPENDED_OR_DELETED']} | BLOCKED={counts['BLOCKED']} | 429={counts['RATE_LIMITED']} | ERROR={counts['ERROR']} | DORK={counts['PASSIVE_DORK']} | 404={counts['NOT_FOUND']}",
            "",
        ]
        for mod_name, items in summary.results_by_module.items():
            lines.append(f"## ⚙ Module: `{mod_name}` ({len(items)})")
            lines.append("")
            lines.append("| Status | Source | Category | URL / Details |")
            lines.append("| :--- | :--- | :--- | :--- |")
            for res in items:
                url_part = f"[{res.url}]({res.url})" if res.url else ""
                data_part = json.dumps(res.extracted_data, ensure_ascii=False) if res.extracted_data else ""
                detail = " — ".join(p for p in (url_part, data_part) if p) or "-"
                lines.append(f"| `{res.formatted_status}` | {res.source_name} | {res.category or '-'} | {detail} |")
            lines.append("")
        if graph.edges:
            lines.extend(["## ⚙ Entity Correlation Graph", "", "```mermaid", graph.to_mermaid(), "```", ""])
        out_path = self.out_dir / f"{self._base_name(summary)}.md"
        out_path.write_text("\n".join(lines), encoding="utf-8")
        return out_path

    @staticmethod
    def _embed_local_image_data_uri(path: Path) -> Optional[str]:
        if not path.exists() or not path.is_file() or path.stat().st_size > 2_500_000:
            return None
        ext = path.suffix.lower().lstrip(".")
        mime = "image/jpeg" if ext in {"jpg", "jpeg"} else f"image/{ext}"
        b64 = base64.b64encode(path.read_bytes()).decode("ascii")
        return f"data:{mime};base64,{b64}"

    def export_html(self, summary: ScanSummary, graph: Optional[CorrelationGraph] = None) -> Path:
        graph = graph or EntityCorrelator.build_graph(summary.all_results())
        counts = summary.counts_by_status()
        esc = html.escape

        # Build Visual Avatars & Scanned Files Gallery
        media_cards: List[str] = []
        if summary.target_type == TargetType.FILE and Path(summary.target).suffix.lower() in {".jpg", ".jpeg", ".png", ".webp"}:
            data_uri = self._embed_local_image_data_uri(Path(summary.target))
            if data_uri:
                media_cards.append(
                    f'<div class="media-card"><img src="{data_uri}" alt="Scanned Image"/>'
                    f'<div class="m-title">Scanned Local Image: {esc(Path(summary.target).name)}</div></div>'
                )

        for res in summary.all_results():
            av = (res.extracted_data or {}).get("avatar_url")
            if av and str(av).startswith("http"):
                gl = (res.extracted_data or {}).get("google_lens") or (res.extracted_data or {}).get("google_lens_url") or ""
                bio = (res.extracted_data or {}).get("bio") or ""
                lens_btn = f'<a class="btn" href="{esc(str(gl))}" target="_blank" rel="noopener">🔍 Google Lens</a>' if gl else ""
                prof_btn = f'<a class="btn" href="{esc(res.url)}" target="_blank" rel="noopener">🔗 Profile</a>' if res.url else ""
                media_cards.append(
                    f'<div class="media-card">'
                    f'<img src="{esc(str(av))}" alt="{esc(res.source_name)}" onerror="this.style.display=\'none\'"/>'
                    f'<div class="m-title">{esc(res.source_name)}</div>'
                    f'<div class="m-bio" dir="auto">{esc(str(bio)[:120])}</div>'
                    f'<div class="m-actions">{prof_btn} {lens_btn}</div></div>'
                )

        gallery_html = (
            f'<section class="card"><h2>🖼 Visual Avatars &amp; Media Gallery ({len(media_cards)})</h2>'
            f'<div class="gallery">{"".join(media_cards)}</div></section>'
            if media_cards
            else ""
        )

        module_sections: List[str] = []
        for mod_name, items in summary.results_by_module.items():
            rows_html: List[str] = []
            for res in items:
                color = STATUS_BADGE_CSS.get(res.status.value, "#94a3b8")
                badge = f'<span class="badge" style="border-color:{color};color:{color}">{esc(res.formatted_status)}</span>'
                link_html = f'<a href="{esc(res.url)}" target="_blank" rel="noopener">{esc(res.url)}</a>' if res.url else ""
                extra_html = f'<div class="meta" dir="auto">{esc(json.dumps(res.extracted_data, ensure_ascii=False))}</div>' if res.extracted_data else ""
                rows_html.append(
                    f"<tr><td>{badge}</td><td>{esc(res.source_name)}</td>"
                    f"<td>{esc(res.category or '-')}</td><td>{link_html}{extra_html}</td></tr>"
                )
            module_sections.append(
                f'<section class="card"><h2>⚙ Module: {esc(mod_name)} <span class="count">({len(items)})</span></h2>'
                f'<table><thead><tr><th>Status</th><th>Source</th><th>Category</th><th>URL &amp; Details</th></tr></thead>'
                f'<tbody>{"".join(rows_html)}</tbody></table></section>'
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
<title>⚙ {esc(__app_name__)} v{esc(__version__)} Report — {esc(summary.target)}</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; background:#070b14; color:#e2e8f0; margin:0; padding:24px; }}
  .wrap {{ max-width:1240px; margin:0 auto; }}
  header {{ background:#0f172a; border:1px solid #ff007f; border-radius:12px; padding:20px 24px; margin-bottom:20px; }}
  h1 {{ margin:0 0 8px; color:#00f5ff; font-size:24px; }}
  .kpis {{ display:flex; flex-wrap:wrap; gap:10px; margin-top:12px; }}
  .kpi {{ background:#090f1d; border:1px solid #334155; border-radius:8px; padding:8px 14px; font-size:13px; font-weight:600; }}
  .card {{ background:#0f172a; border:1px solid #1e293b; border-radius:12px; padding:18px 20px; margin-bottom:18px; }}
  h2 {{ margin:0 0 12px; color:#ff007f; font-size:18px; }}
  .count {{ color:#94a3b8; font-weight:normal; font-size:14px; }}
  .gallery {{ display:grid; grid-template-columns:repeat(auto-fill, minmax(210px, 1fr)); gap:14px; }}
  .media-card {{ background:#090f1d; border:1px solid #1e3a8a; border-radius:10px; padding:12px; text-align:center; }}
  .media-card img {{ width:110px; height:110px; object-fit:cover; border-radius:10px; border:2px solid #00ff9f; margin-bottom:8px; }}
  .m-title {{ font-weight:700; color:#00f5ff; font-size:14px; margin-bottom:4px; }}
  .m-bio {{ color:#cbd5e1; font-size:12px; margin-bottom:8px; min-height:28px; }}
  .btn {{ display:inline-block; background:#1e293b; color:#00f5ff; padding:4px 8px; border-radius:6px; font-size:11px; text-decoration:none; margin:2px; }}
  .btn:hover {{ background:#334155; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #1e293b; vertical-align:top; word-break:break-word; }}
  th {{ color:#00f5ff; background:#090f1d; }}
  .badge {{ display:inline-block; padding:2px 8px; border:1px solid; border-radius:6px; font-family:monospace; font-size:12px; font-weight:600; }}
  a {{ color:#05d9e8; text-decoration:none; }}
  a:hover {{ text-decoration:underline; }}
  .meta {{ color:#94a3b8; font-family:monospace; font-size:12px; margin-top:4px; }}
  .code {{ background:#090f1d; padding:14px; border-radius:8px; overflow-x:auto; color:#a5f3fc; font-size:12px; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>⚡ ⚙ {esc(__app_name__)} v{esc(__version__)} OSINT Report — {esc(summary.target)}</h1>
    <div>Scan ID: <code>{esc(summary.scan_id)}</code> │ Type: <code>{esc(summary.target_type.value)}</code> │ Case: <code>{esc(summary.case_id or 'Standalone')}</code> │ UTC: {esc(summary.started_at)}</div>
    <div class="kpis">
      <div class="kpi" style="color:#00ff9f">● FOUND: {counts['FOUND']}</div>
      <div class="kpi" style="color:#b026ff">⊘ SUSP/DEL: {counts['SUSPENDED_OR_DELETED']}</div>
      <div class="kpi" style="color:#ff2a6d">✖ BLOCKED: {counts['BLOCKED']}</div>
      <div class="kpi" style="color:#fcee0a">▲ 429: {counts['RATE_LIMITED']}</div>
      <div class="kpi" style="color:#ff003c">✖ ERR: {counts['ERROR']}</div>
      <div class="kpi" style="color:#05d9e8">◆ DORK: {counts['PASSIVE_DORK']}</div>
      <div class="kpi" style="color:#94a3b8">○ 404: {counts['NOT_FOUND']}</div>
    </div>
  </header>
  {gallery_html}
  {''.join(module_sections)}
  {graph_block}
</div>
</body>
</html>"""

        out_path = self.out_dir / f"{self._base_name(summary)}.html"
        out_path.write_text(doc, encoding="utf-8")
        return out_path
