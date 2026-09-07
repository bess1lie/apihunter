from __future__ import annotations

from apihunter.modules.auth_analyzer import AuthAnalyzer
from apihunter.modules.base import BaseAnalyzer
from apihunter.modules.cors_analyzer import CORSAnalyzer
from apihunter.modules.headers_analyzer import HeadersAnalyzer
from apihunter.modules.idor_analyzer import IDORAnalyzer
from apihunter.modules.info_leak_analyzer import InfoLeakAnalyzer
from apihunter.modules.injection_analyzer import InjectionAnalyzer
from apihunter.modules.rate_limit_analyzer import RateLimitAnalyzer


class AnalyzerRegistry:
    def __init__(self):
        self._analyzers: dict[str, type[BaseAnalyzer]] = {}

    def register(self, name: str, analyzer_cls: type[BaseAnalyzer]):
        self._analyzers[name] = analyzer_cls

    def get_all(self) -> list[type[BaseAnalyzer]]:
        return list(self._analyzers.values())


def get_default_registry() -> AnalyzerRegistry:
    """Production registry — only analyzers with real heuristics.

    Experimental stubs (idor, cors, headers, info_leak, rate_limit,
    injection) are intentionally excluded until implemented.
    Use :func:`get_experimental_registry` to include them.
    """
    registry = AnalyzerRegistry()
    registry.register("auth", AuthAnalyzer)
    return registry


def get_experimental_registry() -> AnalyzerRegistry:
    """Registry including experimental stubs (for testing/roadmap)."""
    registry = get_default_registry()
    registry.register("idor", IDORAnalyzer)
    registry.register("cors", CORSAnalyzer)
    registry.register("headers", HeadersAnalyzer)
    registry.register("info_leak", InfoLeakAnalyzer)
    registry.register("rate_limit", RateLimitAnalyzer)
    registry.register("injection", InjectionAnalyzer)
    return registry
