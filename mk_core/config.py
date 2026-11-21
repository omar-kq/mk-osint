"""Configuration manager for M.K OSINT Framework."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


DEFAULT_CONFIG: Dict[str, Any] = {
    "app": {
        "name": "M.K",
        "theme": "cyber_gear",
        "language": "ar_en",
        "max_concurrency": 15,
        "log_level": "INFO",
        "log_dir": "logs",
        "data_dir": "data",
    },
    "opsec": {
        "use_proxy": False,
        "proxy_url": "socks5h://127.0.0.1:9050",
        "timeout_seconds": 12.0,
        "rate_limit_delay_ms": 250,
        "jitter_ms": 150,
        "max_retries": 2,
        "respect_retry_after": True,
    },
    "mena": {
        "default_region": "EG",
        "priority_countries": [
            "EG", "SA", "AE", "KW", "QA", "BH", "OM",
            "JO", "LB", "IQ", "PS", "IL", "MA", "DZ", "TN"
        ],
        "enable_optional_academic_gov_dorks": False,
    },
    "ai": {
        "enabled": False,
        "provider": "null",
        "model_name": "qwen2.5:3b",
        "endpoint": "http://127.0.0.1:11434",
        "vector_db_path": "data/vector_store",
        "auto_index_results": True,
    },
}


class ConfigManager:
    """Loads, merges, validates, and persists M.K configuration."""

    def __init__(self, config_path: Optional[Path] = None) -> None:
        self._root = Path(__file__).resolve().parent.parent
        self.config_path = config_path or (self._root / "config" / "default_config.json")
        self._data: Dict[str, Any] = copy.deepcopy(DEFAULT_CONFIG)
        self.load()

    def load(self) -> None:
        """Load JSON config if present and apply environment variable overrides."""
        if self.config_path.exists():
            with self.config_path.open("r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            self._deep_merge(self._data, loaded)

        # Environment variable overrides (useful for Kali CLI / Docker / CI)
        if env_theme := os.getenv("MK_THEME"):
            self._data["app"]["theme"] = env_theme
        if env_proxy := os.getenv("MK_PROXY"):
            self._data["opsec"]["use_proxy"] = True
            self._data["opsec"]["proxy_url"] = env_proxy
        if os.getenv("MK_AI_ENABLED", "").lower() in {"1", "true", "yes"}:
            self._data["ai"]["enabled"] = True

    def get(self, dotted_key: str, default: Any = None) -> Any:
        """Retrieve a nested setting using dot notation (e.g. 'opsec.timeout_seconds')."""
        current: Any = self._data
        for part in dotted_key.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return default
        return current

    def set(self, dotted_key: str, value: Any) -> None:
        """Set a nested setting in memory using dot notation."""
        parts = dotted_key.split(".")
        current = self._data
        for part in parts[:-1]:
            if part not in current or not isinstance(current[part], dict):
                current[part] = {}
            current = current[part]
        current[parts[-1]] = value

    def save(self, target_path: Optional[Path] = None) -> Path:
        """Persist current settings to JSON."""
        out_path = target_path or self.config_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as fh:
            json.dump(self._data, fh, indent=2, ensure_ascii=False)
        return out_path

    def as_dict(self) -> Dict[str, Any]:
        return copy.deepcopy(self._data)

    @staticmethod
    def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> None:
        for key, value in override.items():
            if isinstance(value, dict) and isinstance(base.get(key), dict):
                ConfigManager._deep_merge(base[key], value)
            else:
                base[key] = value
