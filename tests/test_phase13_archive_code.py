"""Offline unit tests for M.K Phase 13 (Wayback CDX & Public Code/Gists OSINT)."""

from __future__ import annotations

import asyncio
import json
import unittest

from mk_core.config import ConfigManager
from mk_core.engine import MKEngine
from mk_core.models import ScanStatus, TargetType
from mk_modules.archive_code_osint import (
    ArchiveCodeOSINTModule,
    parse_github_gists,
    parse_github_repos,
    parse_wayback_cdx,
)


class TestMKPhase13ArchiveCode(unittest.TestCase):
    def test_wayback_cdx_parser(self) -> None:
        raw = json.dumps([
            ["timestamp", "original"],
            ["20210501120000", "https://example.com.eg/"],
            ["20251015093000", "https://example.com.eg/about"],
        ])
        parsed = parse_wayback_cdx(raw)
        self.assertEqual(parsed["count"], 2)
        self.assertEqual(parsed["first_seen"], "20210501120000")
        self.assertEqual(parsed["last_seen"], "20251015093000")
        self.assertIn("web.archive.org/web/20210501120000", parsed["snapshots"][0]["wayback_url"])

    def test_github_repos_and_gists_parsers(self) -> None:
        repos_raw = json.dumps([
            {"name": "mk-osint", "html_url": "https://github.com/omar/mk-osint", "language": "Python", "stargazers_count": 12}
        ])
        gists_raw = json.dumps([
            {"html_url": "https://gist.github.com/omar/123", "description": "MENA notes", "files": {"notes.md": {}}}
        ])
        repos = parse_github_repos(repos_raw)
        gists = parse_github_gists(gists_raw)
        self.assertEqual(repos[0]["name"], "mk-osint")
        self.assertEqual(gists[0]["files"], ["notes.md"])

    def test_offline_archive_module_and_engine_discovery(self) -> None:
        mod = ArchiveCodeOSINTModule(ConfigManager(), offline_only=True)
        res = asyncio.run(mod.run("omar_eg", TargetType.USERNAME))
        self.assertEqual(len(res), 3)
        self.assertTrue(all(r.status == ScanStatus.PASSIVE_DORK for r in res))

        engine = MKEngine()
        self.assertIsNotNone(engine.registry.get("archive_code_osint"))


if __name__ == "__main__":
    unittest.main()
