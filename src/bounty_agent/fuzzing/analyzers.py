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
            # MySQL
            "you have an error in your sql syntax",
            "warning: mysql_",
            "mysql_fetch_array()",
            "mysqlnd",
            # MSSQL
            "unclosed quotation mark after the character string",
            "microsoft odbc",
            "microsoft sql native",
            "incorrect syntax near",
            # PostgreSQL
            "quoted string not properly terminated",
            "psql: error",
            "syntax error at or near",
            "pg::syntaxerror",
            # Oracle
            "ora-00933",
            "ora-01756",
            "ora-00921",
            "oracle error",
            # SQLite (Python wrapper)
            "sqlite3.operationalerror",
            # SQLite (raw error strings emitted by Node/Better-SQLite3/Sequelize)
            "sqlite_error:",
            "sqlite_constraint:",
            "sequelizedatabaseerror",
            "sequelizevalidationerror",
            "sequelizeuniqueconstrainterror",
            # SQLite via better-sqlite3 / node:sqlite
            'sqliteerror: near "',
            "sqliteerror: no such column",
            # PDO / Doctrine
            "sqlstate[",
            "doctrine\\dbal",
            # Generic phrases that strongly imply a DB error surfacing
            # to the user. Lower precision than specific stack markers,
            # but useful when wrappers reformat the error string.
            'syntax error: near "',
            "unrecognized token:",
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
class AuthBypassAnalyzer:
    """Detects successful authentication bypass via injection.

    Heuristic: when a payload is sent to a login-shaped endpoint and the
    response status is 2xx with a recognisable auth artifact (JWT, access
    token, session cookie) in the body, the payload almost certainly
    bypassed authentication. This catches the "SQLi on email field
    returns valid JWT" pattern where the standard SqlInjectionAnalyzer
    sees no error and stays silent.

    The category is shared with ``sql_injection`` so it runs against the
    same payload set as the SQL analyzer; XSS payloads tend not to
    trigger auth bypass and are not exercised here.
    """

    category: str = "sql_injection"

    _AUTH_SUCCESS_STATUS_MAX = 300
    _JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
    _TOKEN_KEY_RE = re.compile(
        r'"(authentication|token|access_token|jwt|session|sessionId)"\s*:\s*"',
        re.IGNORECASE,
    )
    _LOGIN_PATH_RE = re.compile(
        r"/(login|signin|sign-in|auth(?:enticate)?|sessions?)\b",
        re.IGNORECASE,
    )

    def analyze(
        self,
        url: str,
        payload: str,
        response: httpx.Response,
        baseline: httpx.Response | None = None,
    ) -> Finding | None:
        # Only run on login-shaped URLs; otherwise too many false positives
        # (e.g. ordinary search endpoints that return tokenised content).
        if not self._LOGIN_PATH_RE.search(url):
            return None
        if response.status_code >= self._AUTH_SUCCESS_STATUS_MAX:
            return None
        # If the baseline ALSO succeeded, the endpoint just accepts
        # anything; don't claim bypass.
        if baseline is not None and baseline.status_code < self._AUTH_SUCCESS_STATUS_MAX:
            body_baseline = _safe_text(baseline)
            if self._JWT_RE.search(body_baseline) or self._TOKEN_KEY_RE.search(body_baseline):
                return None

        body = _safe_text(response)
        jwt_match = self._JWT_RE.search(body)
        token_match = self._TOKEN_KEY_RE.search(body)
        if not jwt_match and not token_match:
            return None

        if jwt_match:
            marker = jwt_match.group(0)[:40]
        elif token_match:
            marker = token_match.group(1)
        else:
            marker = ""
        return Finding(
            url=url,  # type: ignore[arg-type]
            source=FindingSource.FUZZING,
            severity=Severity.CRITICAL,
            title="Authentication bypass via injection",
            description=(
                "An injection payload sent to a login-shaped endpoint "
                "returned a 2xx with an authentication artifact (JWT, "
                "access token, session id). The baseline request did "
                "not authenticate. Strong indicator of an injection-"
                "based auth bypass; manual confirmation required."
            ),
            payload=payload,
            evidence={
                "matched_marker": marker,
                "status_code": response.status_code,
                "baseline_status_code": baseline.status_code if baseline else None,
                "has_jwt": bool(jwt_match),
            },
        )


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
    AuthBypassAnalyzer(),
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
    "AuthBypassAnalyzer",
    "PathTraversalAnalyzer",
    "ReflectedXssAnalyzer",
    "SqlInjectionAnalyzer",
    "StatusDeltaAnalyzer",
]
