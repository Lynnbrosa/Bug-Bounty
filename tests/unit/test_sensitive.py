"""Tests for the SensitivePathScanner."""

from __future__ import annotations

import httpx
import pytest
import respx

from bounty_agent.scanners import SensitivePathScanner


@pytest.fixture
def scanner() -> SensitivePathScanner:
    return SensitivePathScanner(request_timeout_seconds=2.0)


class TestSensitivePathScanner:
    async def test_directory_listing_detected(
        self,
        respx_mock: respx.MockRouter,
        scanner: SensitivePathScanner,
    ) -> None:
        respx_mock.get("https://example.com/files/").mock(
            return_value=httpx.Response(200, text="<title>Index of /files</title>")
        )
        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(client, ["https://example.com/files/"])
        assert len(findings) == 1
        assert findings[0].evidence["signature"] == "directory_listing"

    async def test_env_file_detected(
        self,
        respx_mock: respx.MockRouter,
        scanner: SensitivePathScanner,
    ) -> None:
        respx_mock.get("https://example.com/.env").mock(
            return_value=httpx.Response(200, text="API_KEY=ak_live_xxxxxxxxx\nDB_PASSWORD=hunter2")
        )
        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(client, ["https://example.com/.env"])
        names = {f.evidence["signature"] for f in findings}
        assert "env_file_exposed" in names

    async def test_prometheus_metrics_detected(
        self,
        respx_mock: respx.MockRouter,
        scanner: SensitivePathScanner,
    ) -> None:
        prom_text = (
            "# HELP http_requests_total Total HTTP requests\n# TYPE http_requests_total counter\n"
        )
        respx_mock.get("https://example.com/metrics").mock(
            return_value=httpx.Response(200, text=prom_text)
        )
        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(client, ["https://example.com/metrics"])
        names = {f.evidence["signature"] for f in findings}
        assert "prometheus_metrics_exposed" in names

    async def test_aws_key_detected(
        self,
        respx_mock: respx.MockRouter,
        scanner: SensitivePathScanner,
    ) -> None:
        respx_mock.get("https://example.com/dump").mock(
            return_value=httpx.Response(200, text="leak: AKIAIOSFODNN7EXAMPLE rest of the body")
        )
        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(client, ["https://example.com/dump"])
        names = {f.evidence["signature"] for f in findings}
        assert "aws_credentials_exposed" in names

    async def test_clean_response_no_findings(
        self,
        respx_mock: respx.MockRouter,
        scanner: SensitivePathScanner,
    ) -> None:
        respx_mock.get("https://example.com/").mock(
            return_value=httpx.Response(200, text="<html><body>Welcome</body></html>")
        )
        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(client, ["https://example.com/"])
        assert findings == []

    async def test_404_skipped(
        self,
        respx_mock: respx.MockRouter,
        scanner: SensitivePathScanner,
    ) -> None:
        # The signature accepts 200 only. A 404 with a body that would
        # otherwise match should not fire.
        respx_mock.get("https://example.com/.env").mock(
            return_value=httpx.Response(404, text="API_KEY=fake")
        )
        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(client, ["https://example.com/.env"])
        assert findings == []

    async def test_transport_error_swallowed(
        self,
        respx_mock: respx.MockRouter,
        scanner: SensitivePathScanner,
    ) -> None:
        respx_mock.get("https://example.com/dead").mock(side_effect=httpx.ConnectError("boom"))
        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(client, ["https://example.com/dead"])
        assert findings == []

    async def test_backup_file_pattern_detected(
        self,
        respx_mock: respx.MockRouter,
        scanner: SensitivePathScanner,
    ) -> None:
        respx_mock.get("https://example.com/config.yaml.bak").mock(
            return_value=httpx.Response(200, text="database:\n  password: hunter2")
        )
        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(client, ["https://example.com/config.yaml.bak"])
        names = {f.evidence["signature"] for f in findings}
        assert "backup_file_exposed" in names

    async def test_private_key_detected(
        self,
        respx_mock: respx.MockRouter,
        scanner: SensitivePathScanner,
    ) -> None:
        respx_mock.get("https://example.com/keys").mock(
            return_value=httpx.Response(
                200,
                text="-----BEGIN RSA PRIVATE KEY-----\nMIIEvQ...\n-----END RSA PRIVATE KEY-----",
            )
        )
        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(client, ["https://example.com/keys"])
        names = {f.evidence["signature"] for f in findings}
        assert "private_key_exposed" in names

    async def test_blocked_backup_flags_low_finding(
        self,
        respx_mock: respx.MockRouter,
        scanner: SensitivePathScanner,
    ) -> None:
        # 403 on a backup path -> blocked-backup low finding when bypass fails.
        respx_mock.get("https://example.com/secret.sql.bak").mock(
            return_value=httpx.Response(403, text="forbidden")
        )
        respx_mock.get("https://example.com/secret.sql.bak%2500.md").mock(
            return_value=httpx.Response(403, text="forbidden")
        )
        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(client, ["https://example.com/secret.sql.bak"])
        sigs = {f.evidence["signature"] for f in findings}
        assert "blocked_backup" in sigs

    async def test_null_byte_bypass_promotes_to_critical(
        self,
        respx_mock: respx.MockRouter,
        scanner: SensitivePathScanner,
    ) -> None:
        respx_mock.get("https://example.com/secret.sql.bak").mock(
            return_value=httpx.Response(403, text="forbidden")
        )
        respx_mock.get("https://example.com/secret.sql.bak%2500.md").mock(
            return_value=httpx.Response(200, text="-- DROP TABLE users; full dump here --")
        )
        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(client, ["https://example.com/secret.sql.bak"])
        sigs = {f.evidence["signature"] for f in findings}
        assert "null_byte_bypass" in sigs
        # The blocked-backup low finding should NOT also fire when bypass succeeded.
        assert "blocked_backup" not in sigs

    async def test_blocked_non_backup_path_does_not_flag(
        self,
        respx_mock: respx.MockRouter,
        scanner: SensitivePathScanner,
    ) -> None:
        # A 403 on a normal path (not a backup) should NOT generate a finding.
        respx_mock.get("https://example.com/admin").mock(
            return_value=httpx.Response(403, text="forbidden")
        )
        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(client, ["https://example.com/admin"])
        assert findings == []
