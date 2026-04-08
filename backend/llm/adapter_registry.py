"""
adapter_registry.py — Maps domain names to LoRA adapter paths.

Handles runtime adapter switching via PEFT's set_adapter().
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from config import DOMAINS, UNIFIED_ADAPTER, ADAPTERS_DIR


class AdapterRegistry:
    """Registry mapping domain IDs to adapter paths."""

    def __init__(self, adapters_dir: str | Path | None = None):
        self.adapters_dir = Path(adapters_dir) if adapters_dir else ADAPTERS_DIR
        self._cache: dict[str, Path] = {}
        self._scan()

    def _scan(self):
        """Scan adapter directory for available adapters."""
        if not self.adapters_dir.exists():
            return

        for entry in self.adapters_dir.iterdir():
            if entry.is_dir():
                # Check for adapter_config.json (PEFT marker)
                if (entry / "adapter_config.json").exists():
                    self._cache[entry.name] = entry
                # Also check subdirectories (e.g., lora-adapter/)
                for sub in entry.iterdir():
                    if sub.is_dir() and (sub / "adapter_config.json").exists():
                        self._cache[entry.name] = sub

    def get_adapter_path(self, domain_id: str) -> Optional[Path]:
        """
        Get the adapter path for a given domain.

        Returns:
            Path to the adapter directory, or None if using base/unified.
        """
        domain = DOMAINS.get(domain_id, {})

        # If domain has a trained expert adapter, try to use it
        if domain.get("has_trained_adapter"):
            adapter_name = domain.get("adapter", "")
            if adapter_name and adapter_name in self._cache:
                return self._cache[adapter_name]

        # Fall back to unified adapter
        if UNIFIED_ADAPTER in self._cache:
            return self._cache[UNIFIED_ADAPTER]

        return None

    def list_available(self) -> dict[str, str]:
        """List all available adapters."""
        return {name: str(path) for name, path in self._cache.items()}

    def get_domain_adapter_info(self) -> list[dict]:
        """Get adapter status for all domains."""
        info = []
        for domain_id, domain in DOMAINS.items():
            adapter_name = domain.get("adapter", "")
            has_adapter = adapter_name in self._cache if adapter_name else False
            info.append({
                "domain_id": domain_id,
                "name": domain["name"],
                "adapter": adapter_name,
                "adapter_available": has_adapter,
                "has_trained_adapter": domain.get("has_trained_adapter", False),
                "using": "expert" if has_adapter else "unified" if UNIFIED_ADAPTER in self._cache else "base",
            })
        return info
