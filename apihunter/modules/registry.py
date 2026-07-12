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
    registry = AnalyzerRegistry()
    registry.register("auth", AuthAnalyzer)
    registry.register("idor", IDORAnalyzer)
    registry.register("cors", CORSAnalyzer)
    registry.register("headers", HeadersAnalyzer)
    registry.register("info_leak", InfoLeakAnalyzer)
    registry.register("rate_limit", RateLimitAnalyzer)
    registry.register("injection", InjectionAnalyzer)
    return registry


def test_registry_registration():
    registry = AnalyzerRegistry()

    class MockAnalyzer(BaseAnalyzer):
        async def analyze(self, spec, scan_run):
            return []

    registry.register("mock", MockAnalyzer)
    assert len(registry.get_all()) == 1
    assert registry.get_all()[0] == MockAnalyzer


def test_default_registry():
    registry = get_default_registry()
    analyzers = registry.get_all()
    assert len(analyzers) == 7
    assert any(a.__name__ == "AuthAnalyzer" for a in analyzers)
    assert any(a.__name__ == "InjectionAnalyzer" for a in analyzers)
