"""3D-Shaded Cyberpunk Gear Banner & 4-Frame Animated Rotating Gear for M.K v2.1."""

from __future__ import annotations

from typing import List

from mk_core import __app_name__, __version__

# 3D beveled shading using Unicode shade blocks (░▒▓█)
GEAR_LOGO_3D = r"""
           ░▒▓███▓▒░
       ░▒▓██▀▀   ▀▀██▓▒░      ███╗   ███╗    ██╗  ██╗
     ░▒██▀  ░▒▓█▓▒░  ▀██▒░    ████╗ ████║    ██║ ██╔╝
   ░▒▓██   ▒█▀   ▀█▒   ██▓▒░  ██╔████╔██║    █████╔╝
   ▓███   ▓█  (⚙)  █▓   ███▓  ██║╚██╔╝██║    ██╔═██╗
   ░▒▓██   ▒█▄   ▄█▒   ██▓▒░  ██║ ╚═╝ ██║██╗ ██║  ██╗
     ░▒██▄  ░▒▓█▓▒░  ▄██▒░    ╚═╝     ╚═╝╚═╝ ╚═╝  ╚═╝
       ░▒▓██▄▄   ▄▄██▓▒░      CYBERPUNK MENA OSINT CORE
           ░▒▓███▓▒░          3D ENGINE  •  KALI READY
"""

# Backward compatibility alias
GEAR_LOGO = GEAR_LOGO_3D

# 4-frame rotating 3D gear animation used during live scans
GEAR_3D_FRAMES: List[str] = [
    (
        "      ░▒▓█▓▒░      \n"
        "   ░▓█▀  ▲  ▀█▓░   \n"
        "  ▓█▌  ░(⚙)░  ▐█▓  \n"
        "   ░▓█▄  ▼  ▄█▓░   \n"
        "      ░▒▓█▓▒░      "
    ),
    (
        "    ░▒▓  █  ▓▒░    \n"
        "   ▓█▀ ╲   ╱ ▀█▓   \n"
        "  ░█▌  ▒(⚙)▒  ▐█░  \n"
        "   ▓█▄ ╱   ╲ ▄█▓   \n"
        "    ░▒▓  █  ▓▒░    "
    ),
    (
        "      ▒▓███▓▒      \n"
        "   ▒█▀  ◄─►  ▀█▒   \n"
        "  ██▌  ▓(⚙)▓  ▐██  \n"
        "   ▒█▄  ◄─►  ▄█▒   \n"
        "      ▒▓███▓▒      "
    ),
    (
        "    ▓▒░  █  ░▒▓    \n"
        "   ░█▀ ╱   ╲ ▀█░   \n"
        "  ▒█▌  █(⚙)█  ▐█▒  \n"
        "   ░█▄ ╲   ╱ ▄█░   \n"
        "    ▓▒░  █  ░▒▓    "
    ),
]


def build_status_line(
    theme_name: str,
    modules_loaded: int,
    proxy_enabled: bool,
    ai_enabled: bool,
) -> str:
    """Build a compact Cyberpunk runtime status line displayed under the 3D gear banner."""
    proxy_state = "TOR/PROXY: ACTIVE" if proxy_enabled else "NET: DIRECT"
    ai_state = "AI-RAG: ONLINE" if ai_enabled else "AI-RAG: STANDBY"
    return (
        f"⚙ {__app_name__} v{__version__}  │  "
        f"MODS: {modules_loaded}  │  "
        f"{proxy_state}  │  {ai_state}  │  THEME: {theme_name.upper()}"
    )
