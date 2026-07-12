"""Tests for :class:`apihunter.core.scope.Scope`."""

from __future__ import annotations

from pathlib import Path

import pytest

from apihunter.core.exceptions import ScopeError
from apihunter.core.scope import Scope


class TestScopeFromYaml:
    """Loading scope from YAML files."""

    def test_loads_all_fields(self, tmp_path: Path) -> None:
        """All four keys are parsed from a valid YAML file."""
        yml = tmp_path / "scope.yaml"
        yml.write_text(
            "allow:\n"
            '  - "*.example.com"\n'
            "deny:\n"
            '  - "admin.example.com"\n'
            "targets:\n"
            '  - "https://api.example.com"\n'
            "excluded_extensions:\n"
            "  - png\n"
            "  - jpg\n"
        )
        scope = Scope.from_yaml(yml)
        assert scope.allow == ["*.example.com"]
        assert scope.deny == ["admin.example.com"]
        assert scope.targets == ["https://api.example.com"]
        assert scope.excluded_extensions == ["png", "jpg"]

    def test_empty_yaml_returns_empty_scope(self, tmp_path: Path) -> None:
        """An empty YAML file produces an empty (fail-closed) scope."""
        yml = tmp_path / "empty.yaml"
        yml.write_text("")
        scope = Scope.from_yaml(yml)
        assert scope.allow == []
        assert scope.deny == []
        assert scope.targets == []
        assert scope.excluded_extensions == []

    def test_missing_deny_defaults_to_empty(self, tmp_path: Path) -> None:
        """Omitting the deny key defaults to an empty deny list."""
        yml = tmp_path / "scope.yaml"
        yml.write_text('allow:\n  - "*.example.com"\n')
        scope = Scope.from_yaml(yml)
        assert scope.deny == []

    def test_missing_file_raises_scope_error(self, tmp_path: Path) -> None:
        """A non-existent file raises ScopeError."""
        with pytest.raises(ScopeError, match="not found"):
            Scope.from_yaml(tmp_path / "nonexistent.yaml")

    def test_non_mapping_yaml_raises_scope_error(self, tmp_path: Path) -> None:
        """A YAML file containing a non-mapping (e.g. a list) raises ScopeError."""
        yml = tmp_path / "bad.yaml"
        yml.write_text("- just\n- a\n- list\n")
        with pytest.raises(ScopeError, match="mapping"):
            Scope.from_yaml(yml)


class TestCanScan:
    """Host-level scope decisions via can_scan()."""

    @pytest.mark.parametrize(
        "scope,host,expected",
        [
            # Allow wildcard
            (Scope(allow=["*.example.com"]), "api.example.com", True),
            (Scope(allow=["*.example.com"]), "sub.api.example.com", True),
            # Wildcard does not match bare root
            (Scope(allow=["*.example.com"]), "example.com", False),
            # Allow exact
            (Scope(allow=["example.com"]), "example.com", True),
            (Scope(allow=["example.com"]), "api.example.com", True),
            # Deny overrides allow
            (Scope(allow=["*"], deny=["admin.*"]), "admin.example.com", False),
            (Scope(allow=["*.example.com"], deny=["admin.example.com"]), "admin.example.com", False),
            # Deny only (allow everything not denied)
            (Scope(deny=["bad.com"]), "good.com", True),
            (Scope(deny=["bad.com"]), "bad.com", False),
            # Empty scope = fail closed
            (Scope(), "example.com", False),
            # Targets act as allow when allow is empty
            (Scope(targets=["https://api.example.com"]), "api.example.com", True),
            (Scope(targets=["https://api.example.com"]), "other.com", False),
            # Non-matching allow
            (Scope(allow=["*.example.com"]), "evil.com", False),
        ],
        ids=[
            "wildcard_match",
            "wildcard_deep_sub",
            "wildcard_no_bare",
            "exact_match",
            "exact_subdomain",
            "deny_overrides_wildcard",
            "deny_overrides_specific",
            "deny_only_allows",
            "deny_only_blocks",
            "empty_blocks_all",
            "target_match",
            "target_no_match",
            "allow_no_match",
        ],
    )
    def test_can_scan(self, scope: Scope, host: str, expected: bool) -> None:
        assert scope.can_scan(host) is expected

    def test_case_insensitive(self) -> None:
        """Host matching is case-insensitive."""
        scope = Scope(allow=["*.Example.COM"])
        assert scope.can_scan("API.example.com") is True


class TestIsInScope:
    """URL-level scope decisions via is_in_scope()."""

    def test_url_with_hostname_in_scope(self) -> None:
        scope = Scope(allow=["*.example.com"])
        assert scope.is_in_scope("https://api.example.com/v1/users") is True

    def test_url_with_hostname_out_of_scope(self) -> None:
        scope = Scope(allow=["*.example.com"])
        assert scope.is_in_scope("https://evil.com/v1/users") is False

    def test_url_without_hostname_returns_false(self) -> None:
        scope = Scope(allow=["*.example.com"])
        assert scope.is_in_scope("not-a-url") is False

    def test_url_with_port(self) -> None:
        """Port numbers do not affect hostname matching."""
        scope = Scope(allow=["*.example.com"])
        assert scope.is_in_scope("https://api.example.com:8080/v1") is True


class TestExcludedExtensions:
    """File-extension filtering via is_extension_excluded()."""

    @pytest.mark.parametrize(
        "extensions,url,expected",
        [
            (["png", "jpg", "css", "js"], "https://api.example.com/logo.png", True),
            (["png", "jpg", "css", "js"], "https://api.example.com/photo.jpg", True),
            (["png", "jpg", "css", "js"], "https://api.example.com/style.css", True),
            (["png", "jpg", "css", "js"], "https://api.example.com/app.js", True),
            (["png", "jpg", "css", "js"], "https://api.example.com/api/v1/users", False),
            (["png", "jpg", "css", "js"], "https://api.example.com/data.json", False),
            (["png"], "https://api.example.com/image.png?w=100", True),
            (["png"], "https://api.example.com/image.PNG", False),
            ([], "https://api.example.com/logo.png", False),
        ],
        ids=[
            "png_excluded",
            "jpg_excluded",
            "css_excluded",
            "js_excluded",
            "api_path_not_excluded",
            "json_not_excluded",
            "png_with_query",
            "case_sensitive_ext",
            "empty_list_never_excluded",
        ],
    )
    def test_is_extension_excluded(self, extensions: list[str], url: str, expected: bool) -> None:
        scope = Scope(allow=["*.example.com"], excluded_extensions=extensions)
        assert scope.is_extension_excluded(url) is expected

    def test_extension_in_directory_name_not_matched(self) -> None:
        """A path like /img.png/file should not match .png extension."""
        scope = Scope(excluded_extensions=["png"])
        assert scope.is_extension_excluded("https://example.com/img.png/file") is False


class TestToDict:
    """Serialisation to a plain dict."""

    def test_to_dict_round_trips_all_fields(self) -> None:
        scope = Scope(
            allow=["*.example.com"],
            deny=["admin.example.com"],
            targets=["https://api.example.com"],
            excluded_extensions=["png"],
        )
        d = scope.to_dict()
        assert d["allow"] == ["*.example.com"]
        assert d["deny"] == ["admin.example.com"]
        assert d["targets"] == ["https://api.example.com"]
        assert d["excluded_extensions"] == ["png"]

    def test_to_dict_empty_scope(self) -> None:
        d = Scope().to_dict()
        assert d == {"allow": [], "deny": [], "targets": [], "excluded_extensions": []}


class TestScopeImmutability:
    """Frozen dataclass — fields cannot be mutated."""

    def test_frozen(self) -> None:
        scope = Scope(allow=["*.example.com"])
        with pytest.raises(AttributeError):
            scope.allow = []  # type: ignore[misc]
