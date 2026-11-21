"""M.K Phase 13 — Web Archive (Wayback Machine CDX) & Public Code/Gists OSINT Module."""

from __future__ import annotations

import json
from typing import Any, Dict, List
from urllib.parse import quote_plus

from mk_core.models import ModuleMetadata, OSINTResult, ScanStatus, TargetType
from mk_core.registry import BaseOSINTModule
from mk_net.client import HAS_HTTPX, MKAsyncClient


def parse_wayback_cdx(raw_json: str, limit: int = 15) -> Dict[str, Any]:
    """Parse Wayback Machine CDX JSON rows into first/last timestamps and snapshot URLs."""
    try:
        rows = json.loads(raw_json)
    except Exception:  # noqa: BLE001
        return {"count": 0, "snapshots": []}

    if not isinstance(rows, list) or len(rows) < 2:
        return {"count": 0, "snapshots": []}

    header = rows[0]
    data_rows = rows[1:]
    try:
        ts_idx = header.index("timestamp")
        orig_idx = header.index("original")
    except ValueError:
        return {"count": 0, "snapshots": []}

    snapshots: List[Dict[str, str]] = []
    for row in data_rows[:limit]:
        if len(row) > max(ts_idx, orig_idx):
            ts = str(row[ts_idx])
            orig = str(row[orig_idx])
            snapshots.append(
                {
                    "timestamp": ts,
                    "original": orig,
                    "wayback_url": f"https://web.archive.org/web/{ts}/{orig}",
                }
            )

    return {
        "count": len(data_rows),
        "first_seen": str(data_rows[0][ts_idx]) if data_rows else None,
        "last_seen": str(data_rows[-1][ts_idx]) if data_rows else None,
        "snapshots": snapshots,
    }


def parse_github_repos(raw_json: str, limit: int = 10) -> List[Dict[str, Any]]:
    """Extract concise public repository metadata from GitHub REST API response."""
    try:
        items = json.loads(raw_json)
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(items, list):
        return []

    repos: List[Dict[str, Any]] = []
    for item in items[:limit]:
        if isinstance(item, dict) and item.get("name"):
            repos.append(
                {
                    "name": item.get("name"),
                    "url": item.get("html_url"),
                    "language": item.get("language"),
                    "stars": item.get("stargazers_count", 0),
                    "updated_at": item.get("updated_at"),
                }
            )
    return repos


def parse_github_gists(raw_json: str, limit: int = 10) -> List[Dict[str, Any]]:
    """Extract public Gist metadata from GitHub REST API response."""
    try:
        items = json.loads(raw_json)
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(items, list):
        return []

    gists: List[Dict[str, Any]] = []
    for item in items[:limit]:
        if isinstance(item, dict) and item.get("html_url"):
            files = list((item.get("files") or {}).keys())
            gists.append(
                {
                    "url": item.get("html_url"),
                    "description": (item.get("description") or "")[:120],
                    "files": files[:5],
                    "created_at": item.get("created_at"),
                }
            )
    return gists


class ArchiveCodeOSINTModule(BaseOSINTModule):
    """Passive Web Archive (Wayback CDX) and public GitHub Repos/Gists OSINT."""

    metadata = ModuleMetadata(
        name="archive_code_osint",
        display_name="Web Archive (Wayback CDX) & Public Code OSINT",
        version="1.0.0",
        description="Queries Wayback Machine CDX snapshots for domains and public GitHub repos/gists for usernames, plus passive code/archive dorks.",
        supported_targets=[TargetType.DOMAIN, TargetType.USERNAME, TargetType.EMAIL, TargetType.KEYWORD],
        category="archive_code",
        requires_network=True,
        passive_only=True,
        enabled_by_default=False,  # Run on demand via `-m archive_code_osint`
    )

    def __init__(self, config, offline_only: bool = False) -> None:
        super().__init__(config)
        self.offline_only = offline_only

    async def run(self, target: str, target_type: TargetType) -> List[OSINTResult]:
        clean = target.strip().lstrip("@")
        enc = quote_plus(clean)
        results: List[OSINTResult] = [
            OSINTResult(
                module_name=self.metadata.name,
                source_name="GitHub Public Code Search",
                target=clean,
                target_type=target_type,
                status=ScanStatus.PASSIVE_DORK,
                reason="Passive Code Search Ready",
                url=f"https://github.com/search?q=%22{enc}%22&type=code",
                category="archive_code",
            ),
            OSINTResult(
                module_name=self.metadata.name,
                source_name="Pastebin & Code Snippets Dork",
                target=clean,
                target_type=target_type,
                status=ScanStatus.PASSIVE_DORK,
                reason="Passive Paste Search Ready",
                url=f"https://www.google.com/search?q=(site:pastebin.com+OR+site:gist.github.com+OR+site:gitlab.com/-/snippets)+%22{enc}%22",
                category="archive_code",
            ),
            OSINTResult(
                module_name=self.metadata.name,
                source_name="Archive.today Snapshot Lookup",
                target=clean,
                target_type=target_type,
                status=ScanStatus.PASSIVE_DORK,
                reason="Passive Web Archive Ready",
                url=f"https://archive.today/search/?q={enc}",
                category="archive_code",
            ),
        ]

        if self.offline_only or not HAS_HTTPX:
            return results

        async with MKAsyncClient(self.config) as client:
            if target_type == TargetType.DOMAIN:
                cdx_url = (
                    f"https://web.archive.org/cdx/search/cdx?url={quote_plus(clean)}/*"
                    f"&output=json&fl=timestamp,original&collapse=urlkey&limit=25"
                )
                resp = await client.fetch(cdx_url)
                if resp.error_reason:
                    results.append(
                        OSINTResult(
                            module_name=self.metadata.name,
                            source_name="Wayback Machine CDX API",
                            target=clean,
                            target_type=target_type,
                            status=ScanStatus.ERROR,
                            reason=resp.error_reason,
                            url=cdx_url,
                            category="archive_code",
                        )
                    )
                elif resp.status_code == 200:
                    parsed = parse_wayback_cdx(resp.text)
                    results.append(
                        OSINTResult(
                            module_name=self.metadata.name,
                            source_name="Wayback Machine CDX API",
                            target=clean,
                            target_type=target_type,
                            status=ScanStatus.FOUND if parsed["count"] > 0 else ScanStatus.NOT_FOUND,
                            url=f"https://web.archive.org/web/*/{clean}",
                            category="archive_code",
                            extracted_data=parsed,
                        )
                    )
                else:
                    results.append(
                        OSINTResult(
                            module_name=self.metadata.name,
                            source_name="Wayback Machine CDX API",
                            target=clean,
                            target_type=target_type,
                            status=ScanStatus.RATE_LIMITED if resp.status_code == 429 else ScanStatus.ERROR,
                            reason=f"HTTP {resp.status_code}",
                            category="archive_code",
                        )
                    )

            elif target_type == TargetType.USERNAME:
                gh_headers = {"Accept": "application/vnd.github+json"}
                repos_resp = await client.fetch(
                    f"https://api.github.com/users/{quote_plus(clean)}/repos?sort=updated&per_page=10",
                    extra_headers=gh_headers,
                )
                if repos_resp.status_code == 200:
                    repos = parse_github_repos(repos_resp.text)
                    results.append(
                        OSINTResult(
                            module_name=self.metadata.name,
                            source_name="GitHub Public Repositories",
                            target=clean,
                            target_type=target_type,
                            status=ScanStatus.FOUND if repos else ScanStatus.NOT_FOUND,
                            url=f"https://github.com/{clean}?tab=repositories",
                            category="archive_code",
                            extracted_data={"repo_count": len(repos), "repos": repos},
                        )
                    )
                elif repos_resp.status_code in {403, 429}:
                    results.append(
                        OSINTResult(
                            module_name=self.metadata.name,
                            source_name="GitHub Public Repositories",
                            target=clean,
                            target_type=target_type,
                            status=ScanStatus.RATE_LIMITED,
                            reason=f"GitHub API Limit (HTTP {repos_resp.status_code})",
                            category="archive_code",
                        )
                    )

                gists_resp = await client.fetch(
                    f"https://api.github.com/users/{quote_plus(clean)}/gists?per_page=10",
                    extra_headers=gh_headers,
                )
                if gists_resp.status_code == 200:
                    gists = parse_github_gists(gists_resp.text)
                    results.append(
                        OSINTResult(
                            module_name=self.metadata.name,
                            source_name="GitHub Public Gists",
                            target=clean,
                            target_type=target_type,
                            status=ScanStatus.FOUND if gists else ScanStatus.NOT_FOUND,
                            url=f"https://gist.github.com/{clean}",
                            category="archive_code",
                            extracted_data={"gist_count": len(gists), "gists": gists},
                        )
                    )

        return results
