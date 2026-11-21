"""Cyberpunk & Hacker-style terminal color themes for M.K v2.2 OSINT Framework.

Semantic color rules (cyberpunk_neon default):
  - FOUND                -> Neon Green   (#00ff9f)
  - SUSPENDED_OR_DELETED -> Neon Purple  (#b026ff)
  - BLOCKED              -> Neon Red     (#ff2a6d)
  - ERROR                -> Crimson Red  (#ff003c)
  - RATE_LIMITED         -> Cyber Yellow (#fcee0a)
  - PASSIVE_DORK         -> Electric Cyan (#05d9e8)
  - NOT_FOUND            -> Dim Slate    (grey54)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass(frozen=True)
class MKTheme:
    """Color palette specification for Rich terminal rendering."""

    name: str
    primary: str
    secondary: str
    accent: str
    gear: str
    border: str
    found: str
    suspended_deleted: str
    not_found: str
    blocked: str
    rate_limited: str
    error: str
    passive_dork: str
    muted: str
    gear_cycle: Tuple[str, ...] = ("bold #00f5ff", "bold #ff007f", "bold #fcee0a", "bold #b026ff")


THEMES: Dict[str, MKTheme] = {
    "cyberpunk_neon": MKTheme(
        name="cyberpunk_neon",
        primary="bold #00f5ff",
        secondary="bold #ff007f",
        accent="bold #fcee0a",
        gear="bold #00f5ff",
        border="#ff007f",
        found="bold #00ff9f",
        suspended_deleted="bold #b026ff",
        not_found="dim grey54",
        blocked="bold #ff2a6d",
        rate_limited="bold #fcee0a",
        error="bold #ff003c",
        passive_dork="bold #05d9e8",
        muted="grey62",
        gear_cycle=("bold #00f5ff", "bold #ff007f", "bold #fcee0a", "bold #00ff9f", "bold #b026ff"),
    ),
    "cyber_gear": MKTheme(
        name="cyber_gear",
        primary="bold bright_cyan",
        secondary="bold bright_magenta",
        accent="bold bright_yellow",
        gear="bold cyan",
        border="bright_blue",
        found="bold bright_green",
        suspended_deleted="bold magenta",
        not_found="dim white",
        blocked="bold bright_red",
        rate_limited="bold yellow",
        error="bold red1",
        passive_dork="bold sky_blue1",
        muted="grey62",
        gear_cycle=("bold bright_cyan", "bold bright_magenta", "bold bright_yellow", "bold bright_green"),
    ),
    "emerald_matrix": MKTheme(
        name="emerald_matrix",
        primary="bold bright_green",
        secondary="bold spring_green2",
        accent="bold bright_cyan",
        gear="bold green3",
        border="green",
        found="bold #00ff9f",
        suspended_deleted="bold magenta",
        not_found="dim grey70",
        blocked="bold #ff2a6d",
        rate_limited="bold yellow",
        error="bold red1",
        passive_dork="bold turquoise2",
        muted="grey58",
        gear_cycle=("bold bright_green", "bold spring_green2", "bold bright_cyan", "bold green3"),
    ),
    "desert_gold": MKTheme(
        name="desert_gold",
        primary="bold gold1",
        secondary="bold dark_orange",
        accent="bold bright_cyan",
        gear="bold yellow3",
        border="dark_goldenrod",
        found="bold green3",
        suspended_deleted="bold medium_purple1",
        not_found="dim grey70",
        blocked="bold bright_red",
        rate_limited="bold gold1",
        error="bold red1",
        passive_dork="bold deep_sky_blue1",
        muted="grey62",
        gear_cycle=("bold gold1", "bold dark_orange", "bold bright_cyan", "bold yellow3"),
    ),
}


def get_theme(name: str) -> MKTheme:
    return THEMES.get(name, THEMES["cyberpunk_neon"])
