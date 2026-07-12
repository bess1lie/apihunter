"""Universal, idempotent secret redaction.

The :func:`redact_secret` function is used by :class:`apihunter.core.db.Database`
before persisting any credential-bearing field, and can be reused by
report/export/dashboard modules.  It is a **pure function** with no side
effects and no dependency on the database.

Supported formats
-----------------
1.  **Known auth schemes** — ``Bearer <secret>``, ``Basic <secret>``,
    ``ApiKey <secret>``, ``Token <secret>`` → scheme preserved, value
    masked.
2.  **JWT** — three dot-separated segments → header kept, payload and
    signature masked.
3.  **Header: value** — ``Authorization: <secret>``, ``Cookie: <pairs>``,
    ``Set-Cookie: <pair>``, ``X-Api-Key: <secret>`` → header name kept,
    value masked.  Cookies mask each ``key=value`` pair individually.
4.  **Cookie pairs** — ``session=abc; theme=dark`` → each value masked
    independently.
5.  **Generic secret** — ``first 3 + **** + last 3`` for long values,
    ``**** + last char`` for short values.

Idempotency contract
--------------------
Calling ``redact_secret`` on an already-redacted value returns the same
value unchanged.  This lets callers redact defensively (e.g. in multiple
pipeline stages) without producing double-masked garbage.
"""

from __future__ import annotations

import re

_MASK_MARKER = "****"
_KNOWN_SCHEMES = ("bearer", "basic", "apikey", "token")
_HEADER_PREFIXES = ("authorization", "cookie", "set-cookie", "x-api-key", "x-apikey")
_MIN_GENERIC_LENGTH = 8
_COOKIE_PAIR_RE = re.compile(r"([^=;\s]+)=([^;]*)")
_COOKIE_ATTRIBUTES = frozenset(
    {
        "path",
        "domain",
        "max-age",
        "expires",
        "secure",
        "httponly",
        "samesite",
        "partitioned",
        "priority",
    }
)


def redact_secret(value: str) -> str:
    """Return a redacted copy of *value* safe for storage and display.

    The function is idempotent: applying it twice yields the same result
    as applying it once.

    Parameters
    ----------
    value:
        Raw credential string in any supported format.

    Returns
    -------
    str
        Masked representation.  An empty input returns an empty string.
    """
    if not value:
        return ""

    # Idempotency: if the value already contains the mask marker, assume
    # it was redacted by a previous call and return it unchanged.
    if _MASK_MARKER in value:
        return value

    lowered = value.lower()

    # Known auth scheme: "Bearer <secret>", "Basic <secret>", etc.
    for scheme in _KNOWN_SCHEMES:
        prefix = f"{scheme} "
        if lowered.startswith(prefix):
            scheme_part = value[: len(scheme)]
            return f"{scheme_part} {_MASK_MARKER}"

    # Header: value — "Authorization: <secret>", "Cookie: <pairs>", etc.
    if ":" in value:
        header_name, _, header_value = value.partition(":")
        if header_name.strip().lower() in _HEADER_PREFIXES:
            redacted_value = _redact_header_value(header_name.strip(), header_value.strip())
            return f"{header_name.strip()}: {redacted_value}"

    # JWT: three dot-separated segments — keep header, mask the rest.
    if value.count(".") == 2 and "=" not in value:
        header = value.split(".", 1)[0]
        return f"{header}.{_MASK_MARKER}.{_MASK_MARKER}"

    # Cookie pairs without header prefix: "session=abc; theme=dark"
    if _looks_like_cookie_pairs(value):
        return _redact_cookie_pairs(value)

    # Generic secret: first 3 + **** + last 3.
    if len(value) >= _MIN_GENERIC_LENGTH:
        return f"{value[:3]}{_MASK_MARKER}{value[-3:]}"

    # Very short value: mask everything except the last character.
    return f"{_MASK_MARKER}{value[-1:]}" if value else ""


def _redact_header_value(header_name: str, raw_value: str) -> str:
    """Redact the value part of a recognised header.

    Cookie and Set-Cookie headers mask each key=value pair individually.
    Other headers mask the entire value.
    """
    if header_name.lower() in ("cookie", "set-cookie"):
        return _redact_cookie_pairs(raw_value)
    return _MASK_MARKER


def _redact_cookie_pairs(raw: str) -> str:
    """Mask each ``key=value`` pair in a cookie string.

    Standard cookie attributes (``Path``, ``Domain``, ``Secure``,
    ``HttpOnly``, ``SameSite``, etc.) are preserved as-is — they are
    not secrets.
    """

    def _replace_pair(match: re.Match[str]) -> str:
        key = match.group(1)
        if key.lower() in _COOKIE_ATTRIBUTES:
            return match.group(0)
        return f"{key}={_MASK_MARKER}"

    return _COOKIE_PAIR_RE.sub(_replace_pair, raw)


def _looks_like_cookie_pairs(value: str) -> bool:
    """Heuristic: does *value* look like ``key=val; key2=val2``?"""
    return "=" in value and ";" in value and not value.lower().startswith(_HEADER_PREFIXES)
