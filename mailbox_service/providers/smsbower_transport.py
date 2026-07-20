"""SMSBower HTTP transport using immutable request DTOs (mockable, no Session)."""

from __future__ import annotations

from typing import Any, Protocol

import httpx

from mailbox_service.providers.smsbower_contracts import (
    SmsBowerContractError,
    SmsBowerHttpRequest,
    extract_smsbower_code,
    parse_smsbower_activation,
    smsbower_response_is_pending,
)


class SmsBowerTransportError(RuntimeError):
    """Transport-level SMSBower failure (HTTP, timeout, network)."""

    def __init__(self, message: str, *, is_timeout: bool = False, is_unknown: bool = False) -> None:
        super().__init__(message)
        self.is_timeout = is_timeout
        self.is_unknown = is_unknown


class SmsBowerHttpClientProtocol(Protocol):
    def request(self, prepared: SmsBowerHttpRequest, *, api_key: str) -> Any: ...


class HttpxSmsBowerClient:
    """Real GET transport. Tests inject fakes instead."""

    def __init__(self, *, timeout_seconds: float = 30.0) -> None:
        self._timeout_seconds = timeout_seconds

    def request(self, prepared: SmsBowerHttpRequest, *, api_key: str) -> Any:
        if not api_key:
            raise SmsBowerTransportError("SMSBower api_key is not configured")
        query = {"api_key": api_key}
        for key, value in prepared.params.items():
            if value is None or value == "":
                continue
            query[key] = value
        url = f"{prepared.base_url.rstrip('/')}/{prepared.action}"
        try:
            response = httpx.get(url, params=query, timeout=self._timeout_seconds)
        except httpx.TimeoutException as error:
            raise SmsBowerTransportError(
                f"SMSBower {prepared.action} timeout",
                is_timeout=True,
                is_unknown=True,
            ) from error
        except httpx.HTTPError as error:
            raise SmsBowerTransportError(
                f"SMSBower {prepared.action} network error: {error}",
                is_unknown=True,
            ) from error
        if response.status_code == 429:
            raise SmsBowerTransportError(f"SMSBower {prepared.action} HTTP 429 rate limited")
        if response.status_code >= 400:
            raise SmsBowerTransportError(
                f"SMSBower {prepared.action} HTTP {response.status_code}: {response.text[:200]}"
            )
        text = response.text or ""
        stripped = text.strip()
        if not stripped:
            return ""
        try:
            return response.json()
        except Exception:
            return stripped


class SmsBowerMailTransport:
    """High-level SMSBower operations over a pluggable HTTP client."""

    def __init__(self, http_client: SmsBowerHttpClientProtocol, *, api_key: str) -> None:
        self._http_client = http_client
        self._api_key = api_key

    def get_activation(self, prepared: SmsBowerHttpRequest) -> dict[str, Any]:
        payload = self._http_client.request(prepared, api_key=self._api_key)
        try:
            return parse_smsbower_activation(payload)
        except SmsBowerContractError:
            raise

    def get_code(self, prepared: SmsBowerHttpRequest) -> tuple[str | None, bool]:
        """Return (code_or_none, is_pending)."""
        payload = self._http_client.request(prepared, api_key=self._api_key)
        if smsbower_response_is_pending(payload):
            return None, True
        code = extract_smsbower_code(payload)
        return code, False

    def set_status(self, prepared: SmsBowerHttpRequest) -> str:
        payload = self._http_client.request(prepared, api_key=self._api_key)
        return payload if isinstance(payload, str) else str(payload)
