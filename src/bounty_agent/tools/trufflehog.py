"""trufflehog wrapper (trufflesecurity/trufflehog).

Secret scanning over HTTP responses. trufflehog ships with ~700 regex
detectors for common credentials (AWS, GCP, Azure, GitHub, GitLab,
Stripe, Twilio, Slack, Datadog, ...). Many of them also include a
"verifier" that hits the issuer API to confirm the secret is live;
we leave verification OFF by default to avoid generating traffic to
third parties from a scan.

Use case 1: standalone tool. ``bounty-agent tools run trufflehog
<url>`` fetches the URL and pipes the body through trufflehog.

Use case 2 (future): wire into the sensitive scanner so every fetched
response body is run through trufflehog and matches become findings.
That integration is not done in this commit; we just expose the
wrapper.

The wrapper invokes trufflehog's ``filesystem`` mode over stdin to
keep the surface clean (no need to write a temp file). When the
binary is absent, ``is_available()`` returns False and the registry
falls through.
"""

from __future__ import annotations

import json
from typing import ClassVar

from bounty_agent.core import Finding, FindingSource, Severity
from bounty_agent.tools.base import BaseSubprocessTool, ToolResult


class TruffleHog(BaseSubprocessTool):
    name: ClassVar[str] = "trufflehog"
    description: ClassVar[str] = "Secret scanning (700+ credential detectors)."
    intrusive: ClassVar[bool] = False
    binary: ClassVar[str] = "trufflehog"
    timeout_seconds: ClassVar[int] = 120

    # Pass --no-verification by default so trufflehog doesn't call out
    # to AWS / GitHub / etc. to confirm secrets. Verification can be
    # turned on by a subclass when the operator wants high-confidence
    # findings (with the trade-off of generating outbound traffic).
    verify: ClassVar[bool] = False

    def build_args(self, target: str) -> list[str]:
        # ``target`` is unused for this wrapper because trufflehog reads
        # the body from stdin (the orchestrator pipes the fetched response
        # in). Keep the parameter on the signature to match the
        # Tool protocol.
        del target
        args = [
            "filesystem",
            "--no-update",  # skip the self-update probe on every run
            "--json",
            "/dev/stdin",
        ]
        if not self.verify:
            args.append("--no-verification")
        return args

    def parse_stdout(self, stdout: str, target: str) -> ToolResult:
        """Each line is one detection event (JSON)."""
        items: list[str] = []
        findings: list[Finding] = []
        for raw_line in stdout.splitlines():
            line = raw_line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            detector = str(event.get("DetectorName") or event.get("detector") or "unknown")
            raw = str(event.get("Raw") or event.get("raw") or "")
            verified = bool(event.get("Verified", False))
            if not raw:
                continue
            items.append(detector)
            findings.append(_secret_finding(target, detector, raw, verified))
        return ToolResult(tool=self.name, target=target, items=items, findings=findings)


def _secret_finding(target: str, detector: str, raw: str, verified: bool) -> Finding:
    severity = Severity.CRITICAL if verified else Severity.HIGH
    return Finding(
        url=target,  # type: ignore[arg-type]
        source=FindingSource.MANUAL,
        severity=severity,
        title=f"Exposed credential ({detector})",
        description=(
            "trufflehog matched a credential pattern in the response "
            "body. "
            + (
                "The credential was confirmed live by hitting the issuer API."
                if verified
                else "Not verified against the issuer — manual confirmation required."
            )
        ),
        evidence={
            "detector": detector,
            "verified": verified,
            # Redact the middle of the secret so the report doesn't
            # leak it in plaintext. Show first 4 and last 4 chars only.
            "secret_excerpt": _redact(raw),
            "tool": "trufflehog",
        },
    )


def _redact(secret: str) -> str:
    keep = 4
    if len(secret) <= 2 * keep:
        return "<redacted>"
    return f"{secret[:keep]}...{secret[-keep:]}"


__all__ = ["TruffleHog"]
