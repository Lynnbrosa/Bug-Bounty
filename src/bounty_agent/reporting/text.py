"""Plain text report rendering.

Kept compact and ASCII so it survives copy-pasting into ticketing tools.
"""

from __future__ import annotations

from bounty_agent.core import ScanResult, Severity

_BAR = "=" * 60
_SUB = "-" * 60


def render_text(result: ScanResult) -> str:
    lines = [
        _BAR,
        "BUG BOUNTY SCAN REPORT",
        _BAR,
        f"Target: {result.target}",
        f"Scan id: {result.scan_id}",
        f"Started: {result.started_at.isoformat()}",
    ]
    if result.finished_at:
        lines.append(f"Finished: {result.finished_at.isoformat()}")
    lines.append(_SUB)

    auth = result.authorization
    lines.append(f"Authorization: program={auth.program or '-'}, contact={auth.contact or '-'}")

    waf = result.waf_detection
    if waf.error:
        lines.append(f"WAF detection failed: {waf.error}")
    else:
        lines.append(
            "WAF: "
            f"vendors={', '.join(waf.detected_vendors) or 'none'}, "
            f"likely_protected={'yes' if waf.likely_protected else 'no'}, "
            f"status={waf.status_code}"
        )
    lines.append(_SUB)

    counts = result.counts_by_severity()
    lines.append("Summary:")
    for severity in Severity:
        lines.append(f"  {severity.value:<10} {counts[severity]}")
    lines.append(_SUB)

    if not result.findings:
        lines.append("No findings reported.")
    else:
        lines.append(f"Findings ({len(result.findings)}):")
        for finding in result.findings:
            lines.append("")
            lines.append(f"  [{finding.severity.value.upper()}] {finding.title}")
            lines.append(f"    URL: {finding.url}")
            lines.append(f"    Source: {finding.source.value}")
            if finding.payload:
                lines.append(f"    Payload: {finding.payload}")
            if finding.description:
                lines.append(f"    Description: {finding.description}")

    if result.errors:
        lines.append(_SUB)
        lines.append("Errors:")
        for error in result.errors:
            lines.append(f"  - {error}")

    lines.append(_BAR)
    return "\n".join(lines) + "\n"


__all__ = ["render_text"]
