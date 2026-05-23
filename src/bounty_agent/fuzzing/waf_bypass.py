"""Encoding variations for fuzzing.

Generates encoded variants of a payload that are commonly documented
in WAF/IDS research material (OWASP, PortSwigger). The intent is
educational: surfacing where a target's input handling is inconsistent
with its filtering layer. Out of scope here: protocol fragmentation,
log evasion, fingerprint manipulation aimed at hiding the source.
"""

from __future__ import annotations

import base64
import urllib.parse


def encoding_variants(payload: str) -> list[str]:
    """Return a deduplicated list of encoded variants of ``payload``.

    The original string is always first. Order is otherwise stable so
    tests can pin behaviour.
    """
    variants: list[str] = [payload]
    seen = {payload}

    candidates: list[str] = [
        payload.upper(),
        payload.lower(),
        urllib.parse.quote(payload, safe=""),
        urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""),
        payload.replace(" ", "+"),
        payload.replace(" ", "/**/"),
        base64.b64encode(payload.encode("utf-8")).decode("ascii"),
        "".join(f"&#{ord(c)};" for c in payload),
    ]

    for variant in candidates:
        if variant not in seen:
            variants.append(variant)
            seen.add(variant)
    return variants


__all__ = ["encoding_variants"]
