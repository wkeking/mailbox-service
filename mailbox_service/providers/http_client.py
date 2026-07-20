"""Minimal HTTP JSON client for on-demand mailbox providers (no Session)."""

from __future__ import annotations

from typing import Any, Protocol

import httpx


class ProviderHttpError(RuntimeError):
    """Transport or HTTP status error from an external mailbox API."""


class JsonHttpClient(Protocol):
    def request_json(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        expected_status: tuple[int, ...] = (200, 201, 204),
    ) -> Any: ...


class HttpxJsonHttpClient:
    """httpx-backed JSON client with timeout; verify SSL by default."""

    def __init__(self, *, timeout_seconds: float = 30.0, verify_ssl: bool = True) -> None:
        self._timeout_seconds = float(timeout_seconds)
        self._verify_ssl = verify_ssl

    def request_json(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        expected_status: tuple[int, ...] = (200, 201, 204),
    ) -> Any:
        try:
            response = httpx.request(
                method.upper(),
                url,
                headers=headers,
                params=params,
                json=json_body,
                timeout=self._timeout_seconds,
                verify=self._verify_ssl,
            )
        except httpx.HTTPError as error:
            raise ProviderHttpError(f"HTTP request failed: {method} {url}: {error}") from error
        if response.status_code not in expected_status:
            body_preview = (response.text or "")[:300]
            raise ProviderHttpError(
                f"HTTP {response.status_code} for {method} {url}: {body_preview}"
            )
        if response.status_code == 204 or not (response.content or b"").strip():
            return {}
        content_type = str(response.headers.get("content-type") or "").lower()
        if "application/json" in content_type or response.text[:1] in "{[":
            try:
                return response.json()
            except ValueError as error:
                raise ProviderHttpError(f"invalid JSON from {method} {url}") from error
        return response.text
