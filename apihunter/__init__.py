"""apihunter — REST API security testing CLI.

Part of the bug bounty toolkit: bounthunt, gqlhunter, apihunter.
"""

try:
    from importlib.metadata import version as _get_version

    __version__ = _get_version("apihunter-bess1lie")
except Exception:
    __version__ = "1.0.0"

__author__ = "bess1lie"
