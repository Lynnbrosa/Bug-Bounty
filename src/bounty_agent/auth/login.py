"""Login flow + token capture.

The :func:`attempt_login` coroutine performs a single POST/PUT with a
JSON body, then extracts a bearer token from either the response body
(via dotted JSON path) or a regex match. The resulting token is fed
back into the orchestrator so every downstream request includes an
``Authorization: Bearer <token>`` header (or a custom shape).

Why this matters: most modern APIs hide their interesting endpoints
behind auth. Without a logged-in session the agent scans only the
public surface (login, register, robots.txt, error handlers). With
login flow, the agent suddenly sees the entire admin/account surface
and can fuzz it for IDOR, privilege escalation, etc.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from bounty_agent.logging_setup import audit, get_logger

logger = get_logger(__name__)


class LoginError(Exception):
    """Raised when login or token capture fails."""


@dataclass(frozen=True)
class LoginConfig:
    """Recipe for a one-shot login attempt.

    Either :attr:`token_jsonpath` or :attr:`token_regex` must be set
    (not both). The path uses dotted notation (e.g.
    ``authentication.token``); the regex is applied to the raw body
    and the first capture group is the token.
    """

    url: str
    method: str = "POST"
    body: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    token_jsonpath: str | None = None
    token_regex: str | None = None
    # How the token gets injected into subsequent requests. ``{token}``
    # is substituted with the captured value.
    header_name: str = "Authorization"
    header_value_format: str = "Bearer {token}"
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        path = self.token_jsonpath
        regex = self.token_regex
        if (path is None) == (regex is None):
            raise LoginError("LoginConfig requires exactly one of token_jsonpath or token_regex")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LoginConfig:
        """Build from the JSON shape used by the CLI ``--login`` flag."""
        return cls(
            url=str(data["url"]),
            method=str(data.get("method", "POST")),
            body=dict(data.get("body") or {}),
            headers={str(k): str(v) for k, v in (data.get("headers") or {}).items()},
            token_jsonpath=data.get("token_jsonpath"),
            token_regex=data.get("token_regex"),
            header_name=str(data.get("header_name", "Authorization")),
            header_value_format=str(data.get("header_value_format", "Bearer {token}")),
            timeout_seconds=float(data.get("timeout_seconds", 10.0)),
        )


@dataclass(frozen=True)
class LoginResult:
    """Outcome of a successful login."""

    token: str
    header_name: str
    header_value: str
    status_code: int


async def attempt_login(
    client: httpx.AsyncClient,
    config: LoginConfig,
) -> LoginResult:
    """Run the login POST and extract the token. Raise on failure.

    A login is considered successful when the HTTP status is 2xx **and**
    the token can be extracted. Anything else raises :class:`LoginError`.
    """
    audit("auth.login_started", url=config.url, method=config.method)
    request_headers = {"Content-Type": "application/json", **config.headers}
    try:
        response = await client.request(
            config.method.upper(),
            config.url,
            json=config.body,
            headers=request_headers,
            timeout=config.timeout_seconds,
        )
    except httpx.HTTPError as exc:
        audit("auth.login_failed", url=config.url, error=str(exc))
        raise LoginError(f"login request failed: {exc}") from exc

    status_ok_max = 300
    if response.status_code >= status_ok_max:
        audit(
            "auth.login_failed",
            url=config.url,
            status_code=response.status_code,
            body_excerpt=response.text[:200],
        )
        raise LoginError(
            f"login returned {response.status_code} (expected 2xx): {response.text[:200]}"
        )

    token = _extract_token(response, config)
    if not token:
        audit(
            "auth.token_not_found",
            url=config.url,
            jsonpath=config.token_jsonpath,
            regex=config.token_regex,
            body_excerpt=response.text[:200],
        )
        raise LoginError(
            "login succeeded (2xx) but the token could not be extracted. "
            "Check token_jsonpath / token_regex in the login config."
        )

    audit(
        "auth.login_succeeded",
        url=config.url,
        status_code=response.status_code,
        token_excerpt=token[:32],
    )
    header_value = config.header_value_format.format(token=token)
    return LoginResult(
        token=token,
        header_name=config.header_name,
        header_value=header_value,
        status_code=response.status_code,
    )


def _extract_token(response: httpx.Response, config: LoginConfig) -> str | None:
    if config.token_jsonpath:
        try:
            data = response.json()
        except ValueError:
            return None
        return _walk_jsonpath(data, config.token_jsonpath)
    if config.token_regex:
        match = re.search(config.token_regex, response.text)
        if not match:
            return None
        # Prefer the first capture group; fall back to the whole match.
        if match.groups():
            return match.group(1)
        return match.group(0)
    return None


def _walk_jsonpath(data: Any, path: str) -> str | None:  # noqa: ANN401 - JSON traversal
    """Resolve a dotted JSON path. Supports ``a.b.c`` and ``a.b[0].c``.

    Returns the value as a string if it is a primitive, ``None``
    otherwise. Kept intentionally tiny so we don't pull in jsonpath-ng
    for a one-off integration.
    """
    cursor = data
    for raw_part in path.split("."):
        # Handle indexed access like ``items[0]``.
        match = re.match(r"^(\w+)((?:\[\d+\])*)$", raw_part)
        if not match:
            return None
        key, indices = match.group(1), match.group(2)
        if isinstance(cursor, dict):
            if key not in cursor:
                return None
            cursor = cursor[key]
        else:
            return None
        for idx_match in re.finditer(r"\[(\d+)\]", indices):
            idx = int(idx_match.group(1))
            if not isinstance(cursor, list) or idx >= len(cursor):
                return None
            cursor = cursor[idx]
    if isinstance(cursor, (str, int, float, bool)):
        return str(cursor)
    return None


__all__ = ["LoginConfig", "LoginError", "LoginResult", "attempt_login"]
