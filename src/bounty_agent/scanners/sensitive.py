"""Signature-based sensitive content scanner.

Some classes of bug never need a payload: the response itself reveals
the problem. Examples:

* ``/.env`` returning ``API_KEY=...``
* ``/metrics`` returning Prometheus exposition format
* ``/.git/HEAD`` returning ``ref: refs/heads/main``
* ``/ftp/package.json.bak`` returning a backup file
* A 200 on a path that ends in ``.bak``/``.swp``/``.orig``

This module GETs each candidate URL once and matches the response
against a curated list of :class:`SensitiveSignature` patterns. Every
match becomes a :class:`Finding` with ``FindingSource.MANUAL`` (the
existing source enum doesn't have a dedicated value; treat these as
operator-style observations).

The check is strictly read-only: no payloads, no fuzzing. It runs as a
sibling of the fuzzer in the orchestrator.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

import httpx

from bounty_agent.core import Finding, FindingSource, ScopePolicy, Severity
from bounty_agent.logging_setup import audit, get_logger

if TYPE_CHECKING:
    from uuid import UUID


logger = get_logger(__name__)


# Named constant for status comparisons (ruff PLR2004).
_HTTP_OK = 200


@dataclass(frozen=True)
class SensitiveSignature:
    """One signature: how to recognise a sensitive response.

    A signature matches when:

    * the URL passes :attr:`url_predicate` (or the predicate is ``None``),
    * the response status is in :attr:`accepted_status` (defaults to
      ``{200}``), and
    * :attr:`body_pattern` matches anywhere in the first
      :attr:`body_window` bytes of the response body (or the pattern is
      ``None``).

    Keeping each rule explicit and small makes it cheap to add more.
    """

    name: str
    title: str
    description: str
    severity: Severity
    body_pattern: re.Pattern[str] | None = None
    url_pattern: re.Pattern[str] | None = None
    accepted_status: frozenset[int] = frozenset({200})
    body_window: int = 4096
    require_non_empty_body: bool = True


# Compile signatures once at import time.
_DEFAULT_SIGNATURES: tuple[SensitiveSignature, ...] = (
    SensitiveSignature(
        name="directory_listing",
        title="Directory listing exposed",
        description=(
            "The server returned an HTML directory index, which exposes "
            "internal file structure to unauthenticated visitors."
        ),
        severity=Severity.HIGH,
        body_pattern=re.compile(r"<title>\s*Index of\s*/|<h1>\s*Index of\s*/", re.IGNORECASE),
    ),
    SensitiveSignature(
        name="git_metadata_exposed",
        title="Git metadata directory exposed",
        description=(
            "A path under .git/ returned data, indicating the repository "
            "metadata is publicly accessible. An attacker can reconstruct "
            "the source tree and history."
        ),
        severity=Severity.HIGH,
        url_pattern=re.compile(r"/\.git/", re.IGNORECASE),
        body_pattern=re.compile(r"ref:\s*refs/heads/|^\x00\x00\x00\x00", re.MULTILINE),
    ),
    SensitiveSignature(
        name="env_file_exposed",
        title="Environment file exposed",
        description=(
            "A .env / config file was served with shell-export-style "
            "key/value pairs, which typically contain credentials and API "
            "keys."
        ),
        severity=Severity.CRITICAL,
        url_pattern=re.compile(r"/\.env(\.|$)|/config/.*\.env", re.IGNORECASE),
        body_pattern=re.compile(
            r"^\s*(API_KEY|SECRET|TOKEN|DB_PASSWORD|JWT_SECRET|AWS_)\w*\s*=",
            re.IGNORECASE | re.MULTILINE,
        ),
    ),
    SensitiveSignature(
        name="package_json_exposed",
        title="Package manifest exposed",
        description=(
            "A package.json (or backup variant) was served publicly. It "
            "discloses dependency versions, internal scripts and "
            "sometimes private repository URLs."
        ),
        severity=Severity.MEDIUM,
        url_pattern=re.compile(r"package\.json(\.|$)|composer\.json|requirements\.txt"),
        body_pattern=re.compile(r'"(dependencies|scripts|devDependencies)"\s*:', re.IGNORECASE),
    ),
    SensitiveSignature(
        name="backup_file_exposed",
        title="Backup file accessible",
        description=(
            "A path with a backup extension (.bak/.swp/.old/.orig/~) "
            "returned content. Backup files often contain unredacted "
            "source code, credentials or stale configs."
        ),
        severity=Severity.HIGH,
        url_pattern=re.compile(r"\.(bak|swp|old|orig|backup|tmp)$|/[^/]+~$", re.IGNORECASE),
    ),
    SensitiveSignature(
        name="prometheus_metrics_exposed",
        title="Prometheus metrics endpoint exposed",
        description=(
            "The /metrics endpoint is publicly readable. It typically "
            "leaks request rates, internal job names, build versions and "
            "occasionally credentials in labels."
        ),
        severity=Severity.MEDIUM,
        body_pattern=re.compile(r"^# HELP \w+|^# TYPE \w+", re.MULTILINE),
    ),
    SensitiveSignature(
        name="stack_trace_exposed",
        title="Server stack trace exposed",
        description=(
            "The response contains a stack trace, leaking framework "
            "internals and file paths to unauthenticated clients."
        ),
        severity=Severity.MEDIUM,
        body_pattern=re.compile(
            r"Traceback \(most recent call last\)|at\s+\w+\.\w+\("
            r"[^)]+\.(java|js|ts|py):\d+\)|"
            r"^\s*at\s+/.*?:\d+:\d+",
            re.MULTILINE,
        ),
        accepted_status=frozenset({200, 500, 502, 503}),
    ),
    SensitiveSignature(
        name="aws_credentials_exposed",
        title="AWS credentials exposed",
        description=("An AWS access key pattern was found in the response body."),
        severity=Severity.CRITICAL,
        body_pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
    ),
    SensitiveSignature(
        name="private_key_exposed",
        title="Private key material exposed",
        description=("The response contains a PEM-encoded private key header."),
        severity=Severity.CRITICAL,
        body_pattern=re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP|PRIVATE) (PRIVATE )?KEY-----"),
    ),
    SensitiveSignature(
        name="swagger_openapi_exposed",
        title="API documentation exposed",
        description=(
            "Swagger/OpenAPI documentation is reachable. Often acceptable "
            "by design but worth confirming with the program."
        ),
        severity=Severity.LOW,
        body_pattern=re.compile(r'"(swagger|openapi)"\s*:\s*"\d'),
    ),
    SensitiveSignature(
        name="ftp_listing_exposed",
        title="Filesystem listing exposed (/ftp)",
        description=(
            "A /ftp-style filesystem listing was served. Commonly seen on "
            "OWASP Juice Shop and similar lab deployments, but also on "
            "real apps that left their static-file router too permissive."
        ),
        severity=Severity.HIGH,
        url_pattern=re.compile(r"/ftp(/|$)", re.IGNORECASE),
        body_pattern=re.compile(
            r'<a\s+href=["\'][^"\']*\.(md|pdf|json|bak|txt|sql|env|pem|key)["\']',
            re.IGNORECASE,
        ),
        body_window=32768,
    ),
    SensitiveSignature(
        name="html_file_listing",
        title="HTML page links to sensitive file extensions",
        description=(
            "An HTML response contains links to files with sensitive "
            "extensions (.bak, .sql, .env, .pem, .key). This often "
            "indicates an accidentally exposed download directory."
        ),
        severity=Severity.MEDIUM,
        body_pattern=re.compile(
            r'<a\s+href=["\'][^"\']*\.(bak|sql|env|pem|key|orig|swp)["\']',
            re.IGNORECASE,
        ),
        body_window=32768,
    ),
    SensitiveSignature(
        name="source_snippet_exposed",
        title="Server source-code snippet exposed",
        description=(
            "An endpoint returned a JSON payload containing source-code "
            "snippets (functions, route handlers). Often points to a "
            "code-review endpoint that should not be public."
        ),
        severity=Severity.MEDIUM,
        url_pattern=re.compile(r"/snippets?/", re.IGNORECASE),
        body_pattern=re.compile(
            r'"snippet"\s*:|function\s+\w+\s*\(|module\.exports\s*=', re.IGNORECASE
        ),
        body_window=16384,
    ),
    SensitiveSignature(
        name="application_version_exposed",
        title="Application version exposed",
        description=(
            "An endpoint discloses the application version. Useful for "
            "an attacker to look up known CVEs for the deployed release."
        ),
        severity=Severity.LOW,
        url_pattern=re.compile(
            r"(application[-_]?version|/version$|/build[-_]?info)", re.IGNORECASE
        ),
        body_pattern=re.compile(r'"version"\s*:\s*"\d|"build"\s*:'),
    ),
    SensitiveSignature(
        name="application_configuration_exposed",
        title="Application configuration exposed",
        description=(
            "An endpoint dumps the application configuration object. "
            "These payloads frequently include URLs, feature flags, "
            "third-party API IDs and occasionally credentials."
        ),
        severity=Severity.MEDIUM,
        url_pattern=re.compile(
            r"(application[-_]?configuration|/configuration$|/config\.json)",
            re.IGNORECASE,
        ),
        body_pattern=re.compile(
            r'"(config|application)"\s*:\s*\{|"frontend"\s*:|"backend"\s*:',
            re.IGNORECASE,
        ),
        body_window=16384,
    ),
    SensitiveSignature(
        name="wp_config_exposed",
        title="WordPress configuration exposed",
        description=(
            "wp-config.php contents were served, which include the "
            "database credentials and secret keys for the WordPress "
            "instance."
        ),
        severity=Severity.CRITICAL,
        body_pattern=re.compile(r"define\(\s*['\"]DB_PASSWORD['\"]"),
    ),
    SensitiveSignature(
        name="application_log_exposed",
        title="Application log exposed",
        description=(
            "A path returned what looks like structured application logs "
            "(timestamps, log levels), which leak operational telemetry "
            "and sometimes usernames or tokens."
        ),
        severity=Severity.LOW,
        url_pattern=re.compile(r"/logs?(/|$)|/support/logs|/admin/logs", re.IGNORECASE),
        body_pattern=re.compile(
            r"\[\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|"
            r'"level"\s*:\s*"(info|warn|error|debug)"',
            re.MULTILINE | re.IGNORECASE,
        ),
    ),
)


class SensitivePathScanner:
    """Scan a batch of URLs against the bundled sensitive-content rules.

    Stateless: a single instance can be reused across scans.
    """

    def __init__(
        self,
        signatures: tuple[SensitiveSignature, ...] = _DEFAULT_SIGNATURES,
        scope: ScopePolicy | None = None,
        request_timeout_seconds: float = 10.0,
    ) -> None:
        self.signatures = signatures
        self.scope = scope
        self.request_timeout_seconds = request_timeout_seconds

    async def scan(
        self,
        client: httpx.AsyncClient,
        urls: list[str],
        scan_id: UUID | None = None,
    ) -> list[Finding]:
        """Run the signature scan against every URL. Returns all findings."""
        findings: list[Finding] = []
        audit(
            "sensitive.scan_started",
            scan_id=str(scan_id) if scan_id else None,
            urls=len(urls),
        )
        for url in urls:
            findings.extend(await self._scan_one(client, url, scan_id))
        audit(
            "sensitive.scan_finished",
            scan_id=str(scan_id) if scan_id else None,
            urls=len(urls),
            findings=len(findings),
        )
        return findings

    async def _scan_one(
        self,
        client: httpx.AsyncClient,
        url: str,
        scan_id: UUID | None,
    ) -> list[Finding]:
        if self.scope is not None:
            self.scope.check(url)
        try:
            response = await client.get(
                url,
                timeout=self.request_timeout_seconds,
                follow_redirects=True,
            )
        except httpx.HTTPError as exc:
            logger.info("sensitive.request_failed", url=url, error=str(exc))
            return []

        body = response.text or ""
        body_window = body[: max(sig.body_window for sig in self.signatures)]
        findings: list[Finding] = []
        # Active probe: when the server blocks a likely-backup file, the
        # 403 itself is information disclosure (the path exists), and many
        # static-file middlewares can be bypassed with a poison null byte
        # (%00) appended to the path. Try it; emit a CRITICAL finding if
        # the bypass exposes content, otherwise a LOW finding for the
        # confirmed existence.
        if response.status_code in (401, 403) and _looks_like_backup_path(url):
            bypass = await self._try_null_byte_bypass(client, url, scan_id)
            if bypass is not None:
                findings.append(bypass)
            else:
                findings.append(_blocked_backup_finding(url, response.status_code))
                audit(
                    "sensitive.blocked_backup",
                    scan_id=str(scan_id) if scan_id else None,
                    url=url,
                    status_code=response.status_code,
                )
        for sig in self.signatures:
            if response.status_code not in sig.accepted_status:
                continue
            if sig.require_non_empty_body and not body:
                continue
            if sig.url_pattern is not None and not sig.url_pattern.search(url):
                continue
            if sig.body_pattern is not None and not sig.body_pattern.search(body_window):
                continue
            findings.append(
                Finding(
                    url=url,  # type: ignore[arg-type]
                    source=FindingSource.MANUAL,
                    severity=sig.severity,
                    title=sig.title,
                    description=sig.description,
                    evidence={
                        "signature": sig.name,
                        "status_code": response.status_code,
                        "content_type": response.headers.get("content-type", ""),
                        "body_excerpt": body_window[:400],
                    },
                )
            )
            audit(
                "sensitive.match",
                scan_id=str(scan_id) if scan_id else None,
                url=url,
                signature=sig.name,
                severity=sig.severity.value,
            )
        return findings

    async def _try_null_byte_bypass(
        self,
        client: httpx.AsyncClient,
        url: str,
        scan_id: UUID | None,
    ) -> Finding | None:
        """Re-request ``url`` with the poison-null-byte suffix.

        Some static-file middlewares (notably the Express ``serve-index``
        chain seen in Juice Shop) only inspect the literal suffix when
        deciding whether to block a request. Appending ``%2500.md`` (the
        double URL-encoded null byte followed by an allowed extension)
        bypasses that check and serves the original file. Worth a single
        retry for every blocked backup-ish path.

        Returns a CRITICAL finding if the bypass yielded a 200 with a
        non-empty body, ``None`` otherwise.
        """
        # We append before any query string to keep the file lookup intact.
        if "?" in url:
            base, _, query = url.partition("?")
            bypass_url = f"{base}%2500.md?{query}"
        else:
            bypass_url = f"{url}%2500.md"

        if self.scope is not None:
            try:
                self.scope.check(bypass_url)
            except Exception:  # pragma: no cover - scope already validated url
                return None

        try:
            response = await client.get(
                bypass_url,
                timeout=self.request_timeout_seconds,
                follow_redirects=True,
            )
        except httpx.HTTPError:
            return None
        if response.status_code != _HTTP_OK or not response.text:
            return None

        audit(
            "sensitive.bypass_success",
            scan_id=str(scan_id) if scan_id else None,
            url=bypass_url,
            origin_url=url,
        )
        return Finding(
            url=bypass_url,  # type: ignore[arg-type]
            source=FindingSource.MANUAL,
            severity=Severity.CRITICAL,
            title="Static-file allowlist bypassed via poison null byte",
            description=(
                "The server returned 403 for the original path but served "
                "the same file when the URL was rewritten with a poison "
                "null byte suffix (%2500.md). This indicates the "
                "extension allowlist is implemented as a suffix check on "
                "the request path rather than on the resolved file."
            ),
            evidence={
                "signature": "null_byte_bypass",
                "status_code": response.status_code,
                "origin_url": url,
                "content_type": response.headers.get("content-type", ""),
                "body_excerpt": response.text[:400],
            },
        )


def _looks_like_backup_path(url: str) -> bool:
    """Cheap heuristic for paths that look like backup or sensitive files."""
    return bool(_BACKUP_SUFFIX_RE.search(url))


def _blocked_backup_finding(url: str, status_code: int) -> Finding:
    return Finding(
        url=url,  # type: ignore[arg-type]
        source=FindingSource.MANUAL,
        severity=Severity.LOW,
        title="Backup-shaped path exists but is access-controlled",
        description=(
            "The server returned an access-denied status for a path that "
            "looks like a backup file. The fact that the path is "
            "specifically blocked (rather than 404) confirms the file "
            "exists in the deployed filesystem; an attacker can now look "
            "for an allowlist bypass."
        ),
        evidence={
            "signature": "blocked_backup",
            "status_code": status_code,
        },
    )


_BACKUP_SUFFIX_RE = re.compile(
    r"\.(bak|swp|old|orig|backup|tmp|gz|tar|zip|rar|sql|sql\.gz)(\?|$)",
    re.IGNORECASE,
)


__all__ = [
    "SensitivePathScanner",
    "SensitiveSignature",
]
