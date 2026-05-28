"""subjack wrapper (haccer/subjack).

Subdomain takeover detection. Walks a list of subdomains and checks
whether each one points (via CNAME or A) to a third-party service
that has been deprovisioned but never reclaimed: ``foo.s3.amazonaws.com``
that 404s, ``bar.herokuapp.com`` returning the "No such app" page,
``baz.github.io`` returning the takeover-eligible fingerprint, etc.

These are high-value findings in bug bounty programs ($500-$5000+
typically) because they enable an attacker to host arbitrary content
under the victim's domain. The fix is operational (delete the dangling
CNAME, or claim the third-party service back).

subjack's signature file lives next to the binary and is updated by the
project; our wrapper just parses its JSONL output.
"""

from __future__ import annotations

import json
from typing import ClassVar

from bounty_agent.core import Finding, FindingSource, Severity
from bounty_agent.tools.base import BaseSubprocessTool, ToolResult


class Subjack(BaseSubprocessTool):
    name: ClassVar[str] = "subjack"
    description: ClassVar[str] = "Subdomain takeover detection (dangling CNAMEs)."
    intrusive: ClassVar[bool] = False
    binary: ClassVar[str] = "subjack"
    timeout_seconds: ClassVar[int] = 600

    # Threads / per-request timeout knobs. Conservative defaults.
    threads: ClassVar[int] = 50
    timeout_per_check: ClassVar[int] = 30

    # subjack accepts a single domain via -d, or a wordlist via -w. We use
    # -d so the wrapper signature matches the rest of the tools (one
    # target per invocation). The orchestrator wraps a list of subdomains
    # by calling this tool per-subdomain.
    def build_args(self, target: str) -> list[str]:
        # subjack returns plain JSON-per-line via -ssl -v.
        return [
            "-d",
            target,
            "-t",
            str(self.threads),
            "-timeout",
            str(self.timeout_per_check),
            "-ssl",
            "-v",
        ]

    def parse_stdout(self, stdout: str, target: str) -> ToolResult:
        """Each VULNERABLE line in subjack output becomes a HIGH finding.

        Example output:

            [Vulnerable] foo.example.com -> AWS/S3
            [Not Vulnerable] bar.example.com
            ...
        """
        items: list[str] = []
        findings: list[Finding] = []
        for raw_line in stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("[Vulnerable]"):
                # "[Vulnerable] sub.example.com -> AWS/S3"
                rest = line[len("[Vulnerable]") :].strip()
                parts = rest.split("->")
                subdomain = parts[0].strip()
                service = parts[1].strip() if len(parts) > 1 else "unknown"
                items.append(subdomain)
                findings.append(_takeover_finding(subdomain, service))
            elif line.startswith("{"):
                # Newer subjack versions emit JSONL.
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(payload, dict):
                    continue
                if payload.get("vulnerable"):
                    subdomain = str(payload.get("subdomain") or "")
                    service = str(payload.get("service") or "unknown")
                    if subdomain:
                        items.append(subdomain)
                        findings.append(_takeover_finding(subdomain, service))
        return ToolResult(tool=self.name, target=target, items=items, findings=findings)


def _takeover_finding(subdomain: str, service: str) -> Finding:
    return Finding(
        url=f"https://{subdomain}",  # type: ignore[arg-type]
        source=FindingSource.MANUAL,
        severity=Severity.HIGH,
        title=f"Subdomain takeover candidate ({service})",
        description=(
            "subjack detected a dangling DNS record pointing to a "
            f"deprovisioned {service} resource. An attacker can register "
            "the resource and serve arbitrary content under this "
            "subdomain. Fix: delete the CNAME/A record or reclaim the "
            "third-party resource."
        ),
        evidence={
            "subdomain": subdomain,
            "service": service,
            "tool": "subjack",
        },
    )


__all__ = ["Subjack"]
