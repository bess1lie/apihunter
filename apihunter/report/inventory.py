from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class InventoryReport:
    """
    Represents an inventory of discovered assets.
    """

    endpoints: list[Any] = field(default_factory=list)
    auth_methods: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
