"""Tests for the JwtAttackScanner."""

from __future__ import annotations

import base64
import json

import httpx
import respx

from bounty_agent.scanners import JwtAttackScanner, forge_alg_none, strip_signature


def _make_jwt(header: dict, payload: dict, signature: str = "sig") -> str:
    def _b64(d: dict) -> str:
        raw = base64.urlsafe_b64encode(json.dumps(d).encode("utf-8")).rstrip(b"=")
        return raw.decode("ascii")

    return f"{_b64(header)}.{_b64(payload)}.{signature}"


VALID_TOKEN = _make_jwt(
    {"alg": "HS256", "typ": "JWT"},
    {"sub": "alice", "role": "user"},
)


class TestForgeAlgNone:
    def test_replaces_header_and_drops_signature(self) -> None:
        forged = forge_alg_none(VALID_TOKEN)
        assert forged is not None
        header_b64, payload_b64, sig = forged.split(".")
        # Decode the new header.
        pad = "=" * (-len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64 + pad))
        assert header["alg"] == "none"
        # Original payload preserved.
        original_payload = VALID_TOKEN.split(".")[1]
        assert payload_b64 == original_payload
        # No signature.
        assert sig == ""

    def test_rejects_non_jwt(self) -> None:
        assert forge_alg_none("not.a.token") is None
        assert forge_alg_none("only-one-segment") is None


class TestStripSignature:
    def test_keeps_header_and_payload(self) -> None:
        stripped = strip_signature(VALID_TOKEN)
        assert stripped is not None
        parts = stripped.split(".")
        original = VALID_TOKEN.split(".")
        assert parts[0] == original[0]
        assert parts[1] == original[1]
        assert parts[2] == ""

    def test_rejects_non_jwt(self) -> None:
        assert strip_signature("nope") is None


class TestJwtAttackScannerScan:
    async def test_alg_none_accepted_emits_finding(
        self,
        respx_mock: respx.MockRouter,
    ) -> None:
        scanner = JwtAttackScanner(request_timeout_seconds=2.0)
        url = "https://example.com/api/users"

        def _responder(request: httpx.Request) -> httpx.Response:
            auth = request.headers.get("authorization", "")
            if not auth:
                return httpx.Response(401, text="auth required")
            # Accept anything with a bearer (simulating a broken
            # implementation that doesn't validate the signature).
            return httpx.Response(200, text='{"users": ["alice"]}')

        respx_mock.get(url).mock(side_effect=_responder)

        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(client, VALID_TOKEN, [url])
        attacks = {f.evidence["attack"] for f in findings}
        # Both attacks should land on a permissive backend.
        assert "alg_none" in attacks
        assert "strip_sig" in attacks

    async def test_endpoint_not_protected_skipped(
        self,
        respx_mock: respx.MockRouter,
    ) -> None:
        # Baseline returns 200 -> endpoint isn't auth-protected,
        # the scanner should NOT emit any finding.
        scanner = JwtAttackScanner(request_timeout_seconds=2.0)
        respx_mock.get("https://example.com/public").mock(
            return_value=httpx.Response(200, text="anyone can read")
        )
        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(
                client, VALID_TOKEN, ["https://example.com/public"]
            )
        assert findings == []

    async def test_invalid_token_no_findings(
        self,
    ) -> None:
        scanner = JwtAttackScanner(request_timeout_seconds=2.0)
        async with httpx.AsyncClient() as client:
            findings = await scanner.scan(client, "not.a.jwt", ["https://example.com/x"])
        assert findings == []
