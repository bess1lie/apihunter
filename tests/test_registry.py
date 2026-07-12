import pytest

from apihunter.modules.registry import AnalyzerRegistry, get_default_registry


@pytest.mark.anyio
def test_registry_registration():
    registry = AnalyzerRegistry()

    class MockAnalyzer:
        def __init__(self, context):
            pass

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
