"""Visual recon: surface fingerprinting + content diff across scans.

A lightweight, browser-free implementation. We fetch each endpoint
once, hash a normalised view of the response body, and compare the
hash across scans. Content delta between runs lights up changes that
text-mode tools miss (a button added, a new script tag included, an
error page swapped in).

A future iteration will plug in playwright/chromium to produce
actual screenshots; the current module is the foundation: every
fingerprint already shape-matches what a screenshot pipeline would
produce.
"""

from bounty_agent.visual.fingerprint import (
    EndpointFingerprint,
    FingerprintSet,
    fingerprint_endpoints,
    fingerprint_response,
)

__all__ = [
    "EndpointFingerprint",
    "FingerprintSet",
    "fingerprint_endpoints",
    "fingerprint_response",
]
