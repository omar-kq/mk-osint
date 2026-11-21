"""Loads, filters, and validates the 15-category MENA + Global site catalog."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from mk_core.config import ConfigManager
from mk_core.models import SiteCategory
from mk_net.classifier import SiteRule


@dataclass
class SiteCatalog:
    """In-memory catalog of SiteRule definitions grouped by the 15 MENA categories."""

    rules: List[SiteRule]

    def by_category(self) -> Dict[str, List[SiteRule]]:
        grouped: Dict[str, List[SiteRule]] = {}
        for rule in self.rules:
            grouped.setdefault(rule.category, []).append(rule)
        return grouped

    def filter(
        self,
        categories: Optional[Sequence[str]] = None,
        include_optional_academic_gov: bool = False,
        passive_only: bool = False,
    ) -> List[SiteRule]:
        allowed = set(categories) if categories else None
        out: List[SiteRule] = []
        for rule in self.rules:
            if (
                rule.category == SiteCategory.ACADEMIC_PUBLIC_DORKS.value
                and not include_optional_academic_gov
            ):
                continue
            if allowed is not None and rule.category not in allowed:
                continue
            if passive_only and rule.detection_mode != "passive_dork":
                continue
            out.append(rule)
        return out


def load_mena_sites(
    config: Optional[ConfigManager] = None,
    json_path: Optional[Path] = None,
) -> SiteCatalog:
    """Load `mena_sites.json` into validated `SiteRule` objects."""
    path = json_path or (Path(__file__).resolve().parent / "mena_sites.json")
    with path.open("r", encoding="utf-8") as fh:
        raw_items = json.load(fh)

    rules: List[SiteRule] = []
    for item in raw_items:
        rules.append(
            SiteRule(
                name=item["name"],
                url_template=item["url_template"],
                category=item["category"],
                detection_mode=item.get("detection_mode", "status_code"),
                found_codes=item.get("found_codes", [200]),
                not_found_codes=item.get("not_found_codes", [404, 410]),
                found_markers=item.get("found_markers", []),
                not_found_markers=item.get("not_found_markers", []),
                redirect_not_found_substrings=item.get(
                    "redirect_not_found_substrings", []
                ),
            )
        )
    return SiteCatalog(rules=rules)
