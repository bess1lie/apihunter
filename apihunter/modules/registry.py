from __future__ import annotations

from apihunter.modules.auth_analyzer import AuthAnalyzer
from apihunter.modules.base import BaseAnalyzer
from apihunter.modules.cors_analyzer import CORSAnalyzer
from apihunter.modules.idor_analyzer import IDORAnalyzer
from apihunter.modules.info_leak_analyzer import InfoLeakAnalyzer
from apihunter.modules.injection_analyzer import InjectionAnalyzer
from apihunter.modules.rate_limit_analyzer import RateLimitAnalyzer
from apihunter.modules.response_headers_analyzer import ResponseHeadersAnalyzer
from apihunter.modules.spec_security_analyzer import SpecSecurityAnalyzer


class AnalyzerRegistry:
    def __init__(self):
        self._analyzers: dict[str, type[BaseAnalyzer]] = {}

    def register(self, name: str, analyzer_cls: type[BaseAnalyzer]):
        self._analyzers[name] = analyzer_cls

    def get_all(self) -> list[type[BaseAnalyzer]]:
        return list(self._analyzers.values())


def get_default_registry() -> AnalyzerRegistry:
    """Production registry — analyzers with real heuristics.

    Passive: auth, spec_security, info_leak.
    HeadersAnalyzer is deprecated alias for SpecSecurityAnalyzer (not double-registered).
    Remaining stubs (idor, cors, rate_limit, injection) stay experimental.
    Use :func:`get_experimental_registry` to include them.
    """
    registry = AnalyzerRegistry()
    registry.register("auth", AuthAnalyzer)
    registry.register("spec_security", SpecSecurityAnalyzer)
    registry.register("info_leak", InfoLeakAnalyzer)
    return registry


def get_experimental_registry() -> AnalyzerRegistry:
    """Registry including experimental/active checks (for testing/roadmap)."""
    registry = get_default_registry()
    registry.register("idor", IDORAnalyzer)
    registry.register("cors", CORSAnalyzer)
    registry.register("rate_limit", RateLimitAnalyzer)
    registry.register("injection", InjectionAnalyzer)
    registry.register("response_headers", ResponseHeadersAnalyzer)
    return registry
