"""Tests for the login + token-capture flow."""

from __future__ import annotations

import httpx
import pytest
import respx

from bounty_agent.auth import LoginConfig, LoginError, attempt_login


class TestLoginConfigValidation:
    def test_requires_exactly_one_extractor(self) -> None:
        with pytest.raises(LoginError):
            LoginConfig(url="https://e.example/login")
        with pytest.raises(LoginError):
            LoginConfig(
                url="https://e.example/login",
                token_jsonpath="x",
                token_regex="y",
            )
        # OK with just jsonpath:
        LoginConfig(url="https://e.example/login", token_jsonpath="x")
        # OK with just regex:
        LoginConfig(url="https://e.example/login", token_regex="x")


class TestAttemptLogin:
    async def test_extracts_token_via_jsonpath(
        self,
        respx_mock: respx.MockRouter,
    ) -> None:
        respx_mock.post("https://e.example/login").mock(
            return_value=httpx.Response(200, json={"authentication": {"token": "abc.def.ghi"}})
        )
        config = LoginConfig(
            url="https://e.example/login",
            body={"email": "a", "password": "b"},
            token_jsonpath="authentication.token",
        )
        async with httpx.AsyncClient() as client:
            result = await attempt_login(client, config)
        assert result.token == "abc.def.ghi"
        assert result.header_name == "Authorization"
        assert result.header_value == "Bearer abc.def.ghi"

    async def test_extracts_token_via_regex(
        self,
        respx_mock: respx.MockRouter,
    ) -> None:
        respx_mock.post("https://e.example/login").mock(
            return_value=httpx.Response(200, text='{"jwt":"xxx.yyy.zzz"}')
        )
        config = LoginConfig(
            url="https://e.example/login",
            token_regex=r'"jwt":"([^"]+)"',
        )
        async with httpx.AsyncClient() as client:
            result = await attempt_login(client, config)
        assert result.token == "xxx.yyy.zzz"

    async def test_jsonpath_indexed_access(
        self,
        respx_mock: respx.MockRouter,
    ) -> None:
        respx_mock.post("https://e.example/login").mock(
            return_value=httpx.Response(
                200, json={"tokens": [{"value": "first"}, {"value": "second"}]}
            )
        )
        config = LoginConfig(
            url="https://e.example/login",
            token_jsonpath="tokens[1].value",
        )
        async with httpx.AsyncClient() as client:
            result = await attempt_login(client, config)
        assert result.token == "second"

    async def test_failure_on_4xx(
        self,
        respx_mock: respx.MockRouter,
    ) -> None:
        respx_mock.post("https://e.example/login").mock(
            return_value=httpx.Response(401, json={"error": "invalid credentials"})
        )
        config = LoginConfig(
            url="https://e.example/login",
            token_jsonpath="token",
        )
        async with httpx.AsyncClient() as client:
            with pytest.raises(LoginError):
                await attempt_login(client, config)

    async def test_failure_when_token_missing(
        self,
        respx_mock: respx.MockRouter,
    ) -> None:
        respx_mock.post("https://e.example/login").mock(
            return_value=httpx.Response(200, json={"other": "stuff"})
        )
        config = LoginConfig(
            url="https://e.example/login",
            token_jsonpath="token",
        )
        async with httpx.AsyncClient() as client:
            with pytest.raises(LoginError):
                await attempt_login(client, config)

    async def test_custom_header_shape(
        self,
        respx_mock: respx.MockRouter,
    ) -> None:
        respx_mock.post("https://e.example/login").mock(
            return_value=httpx.Response(200, json={"token": "X"})
        )
        config = LoginConfig(
            url="https://e.example/login",
            token_jsonpath="token",
            header_name="X-Api-Key",
            header_value_format="{token}",
        )
        async with httpx.AsyncClient() as client:
            result = await attempt_login(client, config)
        assert result.header_name == "X-Api-Key"
        assert result.header_value == "X"

    async def test_from_dict_round_trip(self) -> None:
        data = {
            "url": "https://e.example/login",
            "body": {"email": "a", "password": "b"},
            "token_jsonpath": "token",
            "headers": {"X-Test": "1"},
        }
        config = LoginConfig.from_dict(data)
        assert config.url == "https://e.example/login"
        assert config.body == {"email": "a", "password": "b"}
        assert config.token_jsonpath == "token"
        assert config.headers == {"X-Test": "1"}
