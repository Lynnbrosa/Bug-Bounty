"""Per-category analyzers for fuzzing responses.

Each analyzer turns a (response, payload, baseline) triple into an
optional :class:`Finding`. This replaces the legacy substring-on-text
heuristic (B12) with category-specific signals.

The goal here is not to be exhaustive: it is to give each category a
dedicated detector that can be replaced or extended in isolation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

import httpx

from bounty_agent.core import Finding, FindingSource, Severity


class Analyzer(Protocol):
    """Interface implemented by every category analyzer."""

    category: str

    def analyze(
        self,
        url: str,
        payload: str,
        response: httpx.Response,
        baseline: httpx.Response | None = None,
    ) -> Finding | None: ...


_ERROR_STATUS = 400


_SQL_ERROR_PATTERNS = re.compile(
    r"|".join(
        re.escape(marker)
        for marker in (
            "you have an error in your sql syntax",
            "warning: mysql_",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "psql: error",
            "ora-00933",
            "ora-01756",
            "sqlite3.operationalerror",
            "sqlstate[",
        )
    ),
    re.IGNORECASE,
)


@dataclass
class SqlInjectionAnalyzer:
    category: str = "sql_injection"

    def analyze(
        self,
        url: str,
        payload: str,
        response: httpx.Response,
        baseline: httpx.Response | None = None,
    ) -> Finding | None:
        body = _safe_text(response)
        match = _SQL_ERROR_PATTERNS.search(body)
        if not match:
            return None
        return Finding(
            url=url,  # type: ignore[arg-type]
            source=FindingSource.FUZZING,
            severity=Severity.HIGH,
            title="Possible SQL injection (error-based)",
            description=(
                "Payload triggered a database error message in the response body. "
                "Manual confirmation required."
            ),
            payload=payload,
            evidence={
                "matched_marker": match.group(0),
                "status_code": response.status_code,
                "baseline_status_code": baseline.status_code if baseline else None,
            },
        )


@dataclass
class ReflectedXssAnalyzer:
    category: str = "xss"

    def analyze(
        self,
        url: str,
        payload: str,
        response: httpx.Response,
        baseline: httpx.Response | None = None,
    ) -> Finding | None:
        body = _safe_text(response)
        if payload not in body:
            return None
        content_type = response.headers.get("content-type", "").lower()
        if "html" not in content_type and "xml" not in content_type:
            return None
        return Finding(
            url=url,  # type: ignore[arg-type]
            source=FindingSource.FUZZING,
            severity=Severity.MEDIUM,
            title="Reflected payload in HTML response",
            description=(
                "The payload was reflected verbatim in an HTML-typed response. "
                "Check whether output encoding is applied."
            ),
            payload=payload,
            evidence={
                "content_type": content_type,
                "status_code": response.status_code,
                "baseline_status_code": baseline.status_code if baseline else None,
            },
        )


@dataclass
class PathTraversalAnalyzer:
    """Looks for canonical files leaking through path traversal payloads."""

    category: str = "path_traversal"

    _MARKERS = (
        re.compile(r"root:[x*]:0:0:", re.IGNORECASE),  # /etc/passwd
        re.compile(r"\[fonts\]", re.IGNORECASE),  # win.ini
        re.compile(r"\[extensions\]", re.IGNORECASE),
    )

    def analyze(
        self,
        url: str,
        payload: str,
        response: httpx.Response,
        baseline: httpx.Response | None = None,
    ) -> Finding | None:
        body = _safe_text(response)
        for pattern in self._MARKERS:
            match = pattern.search(body)
            if match:
                return Finding(
                    url=url,  # type: ignore[arg-type]
                    source=FindingSource.FUZZING,
                    severity=Severity.HIGH,
                    title="Possible path traversal",
                    description=(
                        "Response body contains markers that look like a leaked "
                        "system file. Manual confirmation required."
                    ),
                    payload=payload,
                    evidence={
                        "matched_marker": match.group(0),
                        "status_code": response.status_code,
                        "baseline_status_code": baseline.status_code if baseline else None,
                    },
                )
        return None


@dataclass
class StatusDeltaAnalyzer:
    """Generic last-resort analyzer that flags abrupt status changes.

    Useful in CI to catch behavioural changes between a baseline request
    and a payload-laden request, without claiming a specific class of
    vulnerability.
    """

    category: str = "status_delta"
    severity: Severity = Severity.LOW

    def analyze(
        self,
        url: str,
        payload: str,
        response: httpx.Response,
        baseline: httpx.Response | None = None,
    ) -> Finding | None:
        if baseline is None:
            return None
        if response.status_code == baseline.status_code:
            return None
        if response.status_code < _ERROR_STATUS and baseline.status_code < _ERROR_STATUS:
            return None
        return Finding(
            url=url,  # type: ignore[arg-type]
            source=FindingSource.FUZZING,
            severity=self.severity,
            title="Status code changed under payload",
            description=(
                f"Baseline returned {baseline.status_code}, payload returned "
                f"{response.status_code}. Worth manual review."
            ),
            payload=payload,
            evidence={
                "status_code": response.status_code,
                "baseline_status_code": baseline.status_code,
            },
        )


DEFAULT_ANALYZERS: tuple[Analyzer, ...] = (
    SqlInjectionAnalyzer(),
    ReflectedXssAnalyzer(),
    PathTraversalAnalyzer(),
)


def _safe_text(response: httpx.Response) -> str:
    try:
        return response.text
    except UnicodeDecodeError:
        return ""


__all__ = [
    "DEFAULT_ANALYZERS",
    "Analyzer",
    "PathTraversalAnalyzer",
    "ReflectedXssAnalyzer",
    "SqlInjectionAnalyzer",
    "StatusDeltaAnalyzer",
]
