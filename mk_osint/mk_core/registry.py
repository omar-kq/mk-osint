"""Base module contract and dynamic plugin loader for M.K.

Any future module added in Phases 4-9 simply subclasses `BaseOSINTModule`
inside `mk_modules/` and is discovered automatically with zero core edits.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional, Type

from mk_core.config import ConfigManager
from mk_core.models import ModuleMetadata, OSINTResult, TargetType


class BaseOSINTModule(ABC):
    """Abstract base class that every M.K intelligence module must implement."""

    metadata: ModuleMetadata

    def __init__(self, config: ConfigManager) -> None:
        self.config = config

    @abstractmethod
    async def run(self, target: str, target_type: TargetType) -> List[OSINTResult]:
        """Execute the module against a target and return standardized OSINTResult items."""

    def supports(self, target_type: TargetType) -> bool:
        return target_type in self.metadata.supported_targets


class PluginRegistry:
    """Auto-discovers and manages M.K OSINT modules."""

    def __init__(self, config: ConfigManager) -> None:
        self.config = config
        self._modules: Dict[str, BaseOSINTModule] = {}

    def register(self, module_cls: Type[BaseOSINTModule]) -> None:
        instance = module_cls(self.config)
        self._modules[instance.metadata.name] = instance

    def discover(self, package_name: str = "mk_modules") -> int:
        """Dynamically import all modules inside `mk_modules/` and register subclasses."""
        loaded_count = 0
        package = importlib.import_module(package_name)
        pkg_paths = getattr(package, "__path__", [])

        for _, mod_name, is_pkg in pkgutil.iter_modules(pkg_paths):
            if mod_name.startswith("_") or is_pkg:
                continue
            full_name = f"{package_name}.{mod_name}"
            imported = importlib.import_module(full_name)
            for _, obj in inspect.getmembers(imported, inspect.isclass):
                if (
                    issubclass(obj, BaseOSINTModule)
                    and obj is not BaseOSINTModule
                    and hasattr(obj, "metadata")
                ):
                    self.register(obj)
                    loaded_count += 1
        return loaded_count

    def get(self, name: str) -> Optional[BaseOSINTModule]:
        return self._modules.get(name)

    def list_all(self) -> List[BaseOSINTModule]:
        return sorted(self._modules.values(), key=lambda m: m.metadata.name)

    def get_for_target(
        self,
        target_type: TargetType,
        selected_names: Optional[List[str]] = None,
    ) -> List[BaseOSINTModule]:
        """Return enabled modules compatible with the requested target type."""
        candidates = self.list_all()
        if selected_names:
            wanted = set(selected_names)
            return [
                m for m in candidates
                if m.metadata.name in wanted and m.supports(target_type)
            ]
        return [
            m for m in candidates
            if m.metadata.enabled_by_default and m.supports(target_type)
        ]
