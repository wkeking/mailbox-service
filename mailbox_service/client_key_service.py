"""Client API Key creation and constant-time authentication."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import hmac
import secrets
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from mailbox_service.models import ClientKey, utc_now


from mailbox_service.providers.catalog import PROVIDER_DEFINITIONS

_PROVIDER_ACQUIRE_SCOPES = frozenset(
    f"providers:{definition.provider_type}:acquire"
    for definition in PROVIDER_DEFINITIONS
    if definition.requires_acquire_scope
)

ALLOWED_CLIENT_KEY_SCOPES = frozenset(
    {
        "leases:acquire",
        "leases:release",
        "tokens:access:read",
        "tokens:refresh:read",
        "tokens:refresh:write",
        "mailboxes:acquire",
        "mailboxes:reacquire",
        "mail:verification-code:read",
        # Explicit provider allowlist scopes (existing keys do not get these by default).
        *_PROVIDER_ACQUIRE_SCOPES,
    }
)


def provider_acquire_scope(provider_type: str) -> str:
    """Return the Client Key scope required to acquire a non-default provider."""
    return f"providers:{provider_type}:acquire"


class ClientKeyAuthenticationError(Exception):
    """Raised when an external API Key is missing, malformed, or inactive."""


class ClientKeyScopeError(Exception):
    """Raised when a valid Client Key lacks a required permission."""


@dataclass(frozen=True)
class ClientPrincipal:
    """Authenticated external caller without any API Key secret material."""

    client_key_id: str
    name: str
    scopes: frozenset[str]

    def require_scope(self, required_scope: str) -> None:
        """Reject an operation that the authenticated Client Key cannot perform."""
        if required_scope not in self.scopes:
            raise ClientKeyScopeError(f"Client Key 缺少权限：{required_scope}")


@dataclass(frozen=True)
class ClientKeyCreationResult:
    """One-time plaintext API Key paired with its persisted metadata."""

    client_key: ClientKey
    api_key: str


class ClientKeyService:
    """Create, disable, list, and authenticate external Client API Keys."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create_client_key(
        self,
        *,
        name: str,
        scopes: list[str],
        expires_at: datetime | None = None,
    ) -> ClientKeyCreationResult:
        """Persist only a digest and return the high-entropy API Key exactly once."""
        normalized_name = name.strip()
        if not normalized_name:
            raise ValueError("Client Key 名称不能为空")

        normalized_scopes = list(dict.fromkeys(scopes))
        unsupported_scopes = set(normalized_scopes) - ALLOWED_CLIENT_KEY_SCOPES
        if unsupported_scopes:
            raise ValueError(f"不支持的 Client Key 权限：{', '.join(sorted(unsupported_scopes))}")
        if not normalized_scopes:
            raise ValueError("Client Key 至少需要一个权限")

        client_key_id = str(uuid.uuid4())
        secret = secrets.token_urlsafe(32)
        client_key = ClientKey(
            id=client_key_id,
            name=normalized_name,
            secret_digest=self._digest_secret(secret),
            scopes=normalized_scopes,
            expires_at=expires_at,
        )
        self._session.add(client_key)
        self._session.flush()
        return ClientKeyCreationResult(
            client_key=client_key,
            api_key=f"mbx_{client_key_id}.{secret}",
        )

    def authenticate(self, api_key: str | None) -> ClientPrincipal:
        """Authenticate one API Key without exposing whether its identifier exists."""
        client_key_id, secret = self._parse_api_key(api_key)
        client_key = self._session.get(ClientKey, client_key_id)
        candidate_digest = self._digest_secret(secret)
        stored_digest = client_key.secret_digest if client_key is not None else "0" * 64
        digest_matches = hmac.compare_digest(stored_digest, candidate_digest)
        current_time = utc_now()
        is_active = client_key is not None and client_key.enabled
        is_expired = bool(
            client_key is not None
            and client_key.expires_at is not None
            and self._is_expired(client_key.expires_at, current_time)
        )
        if not digest_matches or not is_active or is_expired or client_key is None:
            raise ClientKeyAuthenticationError("Client API Key 无效")

        client_key.last_used_at = current_time
        return ClientPrincipal(
            client_key_id=client_key.id,
            name=client_key.name,
            scopes=frozenset(client_key.scopes),
        )

    def disable_client_key(self, client_key_id: str) -> ClientKey:
        """Disable a Client Key and preserve its metadata for auditing."""
        client_key = self._session.get(ClientKey, client_key_id)
        if client_key is None:
            raise LookupError("Client Key 不存在")
        client_key.enabled = False
        client_key.updated_at = utc_now()
        self._session.flush()
        return client_key

    def list_client_keys(self) -> list[ClientKey]:
        """List metadata without ever returning API Key secret material."""
        return list(self._session.scalars(select(ClientKey).order_by(ClientKey.created_at.desc())))

    @staticmethod
    def _digest_secret(secret: str) -> str:
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()

    @staticmethod
    def _parse_api_key(api_key: str | None) -> tuple[str, str]:
        if not api_key or not api_key.startswith("mbx_") or "." not in api_key:
            raise ClientKeyAuthenticationError("Client API Key 无效")
        identifier, secret = api_key.split(".", maxsplit=1)
        client_key_id = identifier.removeprefix("mbx_")
        if not client_key_id or not secret:
            raise ClientKeyAuthenticationError("Client API Key 无效")
        return client_key_id, secret

    @staticmethod
    def _is_expired(expires_at: datetime, current_time: datetime) -> bool:
        comparable_current_time = current_time
        if expires_at.tzinfo is None and current_time.tzinfo is not None:
            comparable_current_time = current_time.replace(tzinfo=None)
        return expires_at <= comparable_current_time
