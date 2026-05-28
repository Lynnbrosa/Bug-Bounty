"""Tests for the per-category fuzzing analyzers."""

from __future__ import annotations

import httpx

from bounty_agent.core import Severity
from bounty_agent.fuzzing import (
    AuthBypassAnalyzer,
    PathTraversalAnalyzer,
    ReflectedXssAnalyzer,
    SqlInjectionAnalyzer,
    StatusDeltaAnalyzer,
    TimeBasedSqlInjectionAnalyzer,
)


def _response(
    *,
    status_code: int = 200,
    text: str = "",
    content_type: str = "text/html; charset=utf-8",
    elapsed_seconds: float | None = None,
) -> httpx.Response:
    from datetime import timedelta

    request = httpx.Request("GET", "https://example.com/")
    response = httpx.Response(
        status_code=status_code,
        headers={"content-type": content_type},
        text=text,
        request=request,
    )
    if elapsed_seconds is not None:
        # httpx.Response.elapsed is settable post-construction.
        response.elapsed = timedelta(seconds=elapsed_seconds)
    return response


class TestTimeBasedSqlInjectionAnalyzer:
    def test_slow_response_with_sleep_payload_is_flagged(self) -> None:
        analyzer = TimeBasedSqlInjectionAnalyzer()
        slow = _response(elapsed_seconds=5.2)
        baseline = _response(elapsed_seconds=0.1)
        finding = analyzer.analyze(
            "https://example.com/?id=1",
            payload="1' AND SLEEP(5)--",
            response=slow,
            baseline=baseline,
        )
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert finding.evidence["delta_seconds"] >= 4.0

    def test_fast_response_no_finding(self) -> None:
        analyzer = TimeBasedSqlInjectionAnalyzer()
        fast = _response(elapsed_seconds=0.2)
        baseline = _response(elapsed_seconds=0.1)
        finding = analyzer.analyze(
            "https://example.com/?id=1",
            payload="1' AND SLEEP(5)--",
            response=fast,
            baseline=baseline,
        )
        assert finding is None

    def test_non_time_payload_skipped(self) -> None:
        analyzer = TimeBasedSqlInjectionAnalyzer()
        slow = _response(elapsed_seconds=8.0)
        baseline = _response(elapsed_seconds=0.1)
        # Slow response but the payload has no SLEEP-like fragment.
        # Could be a slow query, not necessarily injectable -> skip.
        finding = analyzer.analyze(
            "https://example.com/?id=1",
            payload="1' OR '1'='1",
            response=slow,
            baseline=baseline,
        )
        assert finding is None

    def test_no_baseline_uses_absolute_floor(self) -> None:
        analyzer = TimeBasedSqlInjectionAnalyzer()
        slow = _response(elapsed_seconds=5.5)
        finding = analyzer.analyze(
            "https://example.com/?id=1",
            payload="1; WAITFOR DELAY '0:0:5'--",
            response=slow,
            baseline=None,
        )
        assert finding is not None

    def test_pg_sleep_signature_matched(self) -> None:
        analyzer = TimeBasedSqlInjectionAnalyzer()
        slow = _response(elapsed_seconds=6.0)
        baseline = _response(elapsed_seconds=0.5)
        finding = analyzer.analyze(
            "https://example.com/?id=1",
            payload="1; SELECT pg_sleep(5);--",
            response=slow,
            baseline=baseline,
        )
        assert finding is not None
        assert "time-based" in finding.title.lower()


class TestSqlInjectionAnalyzer:
    def test_detects_mysql_error(self) -> None:
        analyzer = SqlInjectionAnalyzer()
        response = _response(text="You have an error in your SQL syntax; check the manual.")
        finding = analyzer.analyze(
            "https://example.com/?q=test",
            payload="' OR '1'='1",
            response=response,
        )
        assert finding is not None
        assert finding.severity is Severity.HIGH
        assert "matched_marker" in finding.evidence

    def test_no_match_returns_none(self) -> None:
        analyzer = SqlInjectionAnalyzer()
        response = _response(text="hello world")
        assert analyzer.analyze("https://example.com/", "p", response) is None


class TestReflectedXssAnalyzer:
    def test_reflected_payload_in_html(self) -> None:
        analyzer = ReflectedXssAnalyzer()
        payload = "<script>bounty-agent-probe</script>"
        response = _response(text=f"<html><body>{payload}</body></html>")
        finding = analyzer.analyze("https://example.com/", payload, response)
        assert finding is not None
        assert finding.severity is Severity.MEDIUM

    def test_reflected_payload_in_json_with_dangerous_chars_is_flagged(self) -> None:
        """JSON reflection with HTML-active chars is medium-severity.

        Many SPA frontends pass JSON values through unsafe sinks
        (Angular [innerHTML], React dangerouslySetInnerHTML), so a
        reflected payload that contains '<', '"', etc. is a real XSS
        candidate even in JSON.
        """
        analyzer = ReflectedXssAnalyzer()
        payload = "<script>x</script>"
        response = _response(text=f'{{"echo": "{payload}"}}', content_type="application/json")
        finding = analyzer.analyze("https://example.com/", payload, response)
        assert finding is not None
        assert finding.title.endswith("JSON response")

    def test_inert_reflection_in_json_is_skipped(self) -> None:
        """A JSON echo of a plain string (no dangerous chars) is not XSS."""
        analyzer = ReflectedXssAnalyzer()
        response = _response(text='{"echo": "harmless-string"}', content_type="application/json")
        finding = analyzer.analyze("https://example.com/", "harmless-string", response)
        assert finding is None

    def test_no_reflection_returns_none(self) -> None:
        analyzer = ReflectedXssAnalyzer()
        response = _response(text="<html>nothing here</html>")
        assert analyzer.analyze("https://example.com/", "<script>x</script>", response) is None


class TestPathTraversalAnalyzer:
    def test_detects_passwd_marker(self) -> None:
        analyzer = PathTraversalAnalyzer()
        response = _response(
            text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:",
            content_type="text/plain",
        )
        finding = analyzer.analyze(
            "https://example.com/?file=../etc/passwd", "../etc/passwd", response
        )
        assert finding is not None
        assert finding.severity is Severity.HIGH

    def test_detects_win_ini_marker(self) -> None:
        analyzer = PathTraversalAnalyzer()
        response = _response(text="; for 16-bit app support\n[fonts]\n", content_type="text/plain")
        finding = analyzer.analyze("https://example.com/?file=../win.ini", "../win.ini", response)
        assert finding is not None

    def test_no_marker_returns_none(self) -> None:
        analyzer = PathTraversalAnalyzer()
        response = _response(text="not found", status_code=404)
        assert analyzer.analyze("https://example.com/", "../", response) is None


_JWT_SAMPLE = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9."
    "eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MX19."
    "abcdef1234567890abcdef1234567890"
)


class TestAuthBypassAnalyzer:
    def test_detects_jwt_on_login_path(self) -> None:
        analyzer = AuthBypassAnalyzer()
        response = _response(
            status_code=200,
            text=f'{{"authentication":{{"token":"{_JWT_SAMPLE}"}}}}',
            content_type="application/json",
        )
        baseline = _response(status_code=401, text='{"error":"invalid credentials"}')
        finding = analyzer.analyze(
            "https://example.com/rest/user/login",
            payload="admin@x'--",
            response=response,
            baseline=baseline,
        )
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.evidence["has_jwt"] is True

    def test_ignores_non_login_path(self) -> None:
        analyzer = AuthBypassAnalyzer()
        response = _response(text=f'{{"token":"{_JWT_SAMPLE}"}}')
        finding = analyzer.analyze(
            "https://example.com/api/Products",
            payload="x",
            response=response,
        )
        assert finding is None

    def test_ignores_when_baseline_also_authenticates(self) -> None:
        analyzer = AuthBypassAnalyzer()
        response = _response(text=f'{{"token":"{_JWT_SAMPLE}"}}')
        baseline = _response(text=f'{{"token":"{_JWT_SAMPLE}"}}')
        finding = analyzer.analyze(
            "https://example.com/login",
            payload="x",
            response=response,
            baseline=baseline,
        )
        assert finding is None

    def test_ignores_4xx_response(self) -> None:
        analyzer = AuthBypassAnalyzer()
        response = _response(status_code=401, text=f'{{"token":"{_JWT_SAMPLE}"}}')
        finding = analyzer.analyze(
            "https://example.com/login",
            payload="x",
            response=response,
        )
        assert finding is None


class TestStatusDeltaAnalyzer:
    def test_baseline_required(self) -> None:
        analyzer = StatusDeltaAnalyzer()
        response = _response(status_code=500)
        assert analyzer.analyze("https://example.com/", "p", response, baseline=None) is None

    def test_same_status_no_finding(self) -> None:
        analyzer = StatusDeltaAnalyzer()
        response = _response(status_code=200)
        baseline = _response(status_code=200)
        assert analyzer.analyze("https://example.com/", "p", response, baseline=baseline) is None

    def test_status_jump_to_error_flags(self) -> None:
        analyzer = StatusDeltaAnalyzer()
        response = _response(status_code=500)
        baseline = _response(status_code=200)
        finding = analyzer.analyze("https://example.com/", "p", response, baseline=baseline)
        assert finding is not None
        assert finding.evidence["status_code"] == 500
        assert finding.evidence["baseline_status_code"] == 200
