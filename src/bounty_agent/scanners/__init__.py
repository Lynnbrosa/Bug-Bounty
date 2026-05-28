"""External scanner wrappers (nuclei) and in-process signature scanners."""

from bounty_agent.scanners.cors import CorsProbeScanner
from bounty_agent.scanners.headers import (
    CookieSecurityAuditor,
    CspAuditor,
    SecurityHeadersAuditor,
)
from bounty_agent.scanners.jwt_attack import (
    JwtAttackScanner,
    forge_alg_none,
    strip_signature,
)
from bounty_agent.scanners.nuclei import (
    NucleiConfig,
    NucleiError,
    NucleiNotInstalledError,
    NucleiResult,
    NucleiScanner,
    NucleiTimeoutError,
    parse_nuclei_jsonl,
)
from bounty_agent.scanners.open_redirect import OpenRedirectScanner
from bounty_agent.scanners.sensitive import (
    SensitivePathScanner,
    SensitiveSignature,
)
from bounty_agent.scanners.transport import HttpsEnforcementChecker, Soft404Detector

__all__ = [
    "CookieSecurityAuditor",
    "CorsProbeScanner",
    "CspAuditor",
    "HttpsEnforcementChecker",
    "JwtAttackScanner",
    "NucleiConfig",
    "NucleiError",
    "NucleiNotInstalledError",
    "NucleiResult",
    "NucleiScanner",
    "NucleiTimeoutError",
    "OpenRedirectScanner",
    "SecurityHeadersAuditor",
    "SensitivePathScanner",
    "SensitiveSignature",
    "Soft404Detector",
    "forge_alg_none",
    "parse_nuclei_jsonl",
    "strip_signature",
]
