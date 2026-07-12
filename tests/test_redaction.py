"""Tests for :func:`apihunter.core.redaction.redact_secret`."""

from __future__ import annotations

import pytest

from apihunter.core.redaction import redact_secret


class TestRedactSecretSchemes:
    """Known auth schemes preserve the scheme name and mask the value."""

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("Bearer eyJhbGciOiJIUzI1", "Bearer ****"),
            ("Basic dXNlcjpwYXNz", "Basic ****"),
            ("ApiKey abc123def456", "ApiKey ****"),
            ("Token mysecret123", "Token ****"),
        ],
    )
    def test_scheme_masked(self, value: str, expected: str) -> None:
        assert redact_secret(value) == expected


class TestRedactSecretHeaders:
    """Header: value format preserves the header name and masks the value."""

    @pytest.mark.parametrize(
        "value,expected_prefix",
        [
            ("Authorization: Bearer eyJhbG", "Authorization:"),
            ("X-Api-Key: my-secret-key-123", "X-Api-Key:"),
            ("X-ApiKey: abc123", "X-ApiKey:"),
        ],
    )
    def test_header_masked(self, value: str, expected_prefix: str) -> None:
        result = redact_secret(value)
        assert result.startswith(expected_prefix)
        assert "****" in result


class TestRedactSecretCookies:
    """Cookie headers mask each key=value pair but preserve attributes."""

    def test_cookie_header_masks_pairs(self) -> None:
        result = redact_secret("Cookie: session=abc123; theme=dark; Path=/; HttpOnly")
        assert "session=****" in result
        assert "theme=****" in result
        assert "Path=/" in result
        assert "HttpOnly" in result

    def test_set_cookie_header_masks_value(self) -> None:
        result = redact_secret("Set-Cookie: token=xyz789; Path=/; Secure; SameSite=Strict")
        assert "token=****" in result
        assert "Path=/" in result
        assert "Secure" in result
        assert "SameSite=Strict" in result

    def test_bare_cookie_pairs(self) -> None:
        """Cookie pairs without a header prefix are also masked."""
        result = redact_secret("session=abc123; theme=dark")
        assert "session=****" in result
        assert "theme=****" in result


class TestRedactSecretJwt:
    """JWT tokens keep the header segment and mask payload + signature."""

    def test_jwt_masked(self) -> None:
        result = redact_secret("eyJhbG.eyJzdWI.eYJhb")
        assert result == "eyJhbG.****.****"


class TestRedactSecretGeneric:
    """Generic secrets use first 3 + **** + last 3."""

    def test_generic_long(self) -> None:
        assert redact_secret("abcdefghijklmnop") == "abc****nop"

    def test_generic_short_masks_all_but_last(self) -> None:
        assert redact_secret("abc") == "****c"

    def test_empty_returns_empty(self) -> None:
        assert redact_secret("") == ""


class TestRedactSecretIdempotency:
    """Applying redact_secret twice must not change the result."""

    @pytest.mark.parametrize(
        "value",
        [
            "Bearer eyJhbGciOiJIUzI1",
            "Basic dXNlcjpwYXNz",
            "ApiKey abc123def456",
            "Token mysecret123",
            "eyJhbG.eyJzdWI.eYJhb",
            "abcdefghijklmnop",
            "abc",
            "Authorization: Bearer eyJhbG",
            "Cookie: session=abc123; Path=/; HttpOnly",
            "Set-Cookie: token=xyz789; Path=/; Secure",
            "X-Api-Key: my-secret-key-123",
            "session=abc123; theme=dark",
        ],
    )
    def test_idempotent(self, value: str) -> None:
        once = redact_secret(value)
        twice = redact_secret(once)
        assert once == twice
