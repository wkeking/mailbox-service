"""Decode OAuth scope claims from Microsoft access tokens without signature verification."""

from __future__ import annotations

from base64 import urlsafe_b64decode
import json
from typing import Any, Literal

MailAccessChannel = Literal["imap", "graph"]

IMAP_SCOPE_MARKERS = (
    "imap.accessasuser",
    "outlook.office.com",
    "outlook.office365.com",
    "https://outlook.office.com/",
)
GRAPH_SCOPE_MARKERS = (
    "graph.microsoft.com",
    "mail.read",
    "mail.readwrite",
    "mail.readbasic",
    "https://graph.microsoft.com/",
)


def extract_oauth_scopes_from_access_token(access_token: str) -> str | None:
    """Return a space-separated scope string decoded from a JWT access token payload.

    Microsoft user-delegated tokens typically expose scopes in the ``scp`` claim.
    Application permissions may appear in ``roles``. Signature verification is intentionally
    skipped because the token was just obtained from Microsoft's token endpoint or already
    stored as a trusted cache value inside this service.
    """
    if not access_token or access_token.count(".") < 2:
        return None

    payload = _decode_jwt_payload(access_token)
    if payload is None:
        return None

    ordered_scopes: list[str] = []
    scp_claim = payload.get("scp")
    if isinstance(scp_claim, str):
        ordered_scopes.extend(part for part in scp_claim.split() if part)

    roles_claim = payload.get("roles")
    if isinstance(roles_claim, list):
        for role_value in roles_claim:
            if isinstance(role_value, str) and role_value.strip():
                ordered_scopes.append(role_value.strip())

    unique_scopes = list(dict.fromkeys(ordered_scopes))
    if not unique_scopes:
        return None
    return " ".join(unique_scopes)


def _decode_jwt_payload(access_token: str) -> dict[str, Any] | None:
    """Decode the JWT payload segment; return None when the token is not a readable JWT."""
    payload_segment = access_token.split(".", 2)[1]
    padding = "=" * (-len(payload_segment) % 4)
    try:
        payload_bytes = urlsafe_b64decode(payload_segment + padding)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def infer_mail_access_channel_preference(scope: str | None) -> list[MailAccessChannel]:
    """Return preferred probe order based on decoded scope hints.

    Product default prefers IMAP when clues are missing or tied, matching the
    mailbox service's primary XOAUTH2 mail-read path.
    """
    normalized_scope = (scope or "").casefold()
    hints_imap = any(marker in normalized_scope for marker in IMAP_SCOPE_MARKERS)
    hints_graph = any(marker in normalized_scope for marker in GRAPH_SCOPE_MARKERS)

    if hints_imap and not hints_graph:
        return ["imap", "graph"]
    if hints_graph and not hints_imap:
        return ["graph", "imap"]
    return ["imap", "graph"]
