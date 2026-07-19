"""Unit tests for Microsoft access-token scope decoding."""

from __future__ import annotations

from base64 import urlsafe_b64encode
import json

from mailbox_service.access_token_scopes import (
    GRAPH_MAIL_READ_SCOPE,
    cached_token_matches_mail_channel,
    extract_oauth_scopes_from_access_token,
    resolve_oauth_refresh_scope_for_channel,
)


def build_unsigned_jwt(payload: dict) -> str:
    """Build a JWT-shaped token with a JSON payload and dummy signature segment."""
    header_segment = urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8")).rstrip(b"=").decode(
        "ascii"
    )
    payload_segment = urlsafe_b64encode(json.dumps(payload).encode("utf-8")).rstrip(b"=").decode("ascii")
    return f"{header_segment}.{payload_segment}.signature"


def test_extract_scopes_from_scp_claim() -> None:
    """Delegated Microsoft tokens expose space-separated scopes in the scp claim."""
    access_token = build_unsigned_jwt(
        {
            "scp": (
                "https://outlook.office.com/IMAP.AccessAsUser.All "
                "https://outlook.office.com/SMTP.Send offline_access"
            )
        }
    )

    assert extract_oauth_scopes_from_access_token(access_token) == (
        "https://outlook.office.com/IMAP.AccessAsUser.All "
        "https://outlook.office.com/SMTP.Send offline_access"
    )


def test_extract_scopes_merges_scp_and_roles() -> None:
    """Application roles are appended after delegated scopes without duplicates."""
    access_token = build_unsigned_jwt(
        {
            "scp": "Mail.Read offline_access",
            "roles": ["Mail.Read", "User.Read.All"],
        }
    )

    assert extract_oauth_scopes_from_access_token(access_token) == "Mail.Read offline_access User.Read.All"


def test_extract_scopes_returns_none_for_opaque_tokens() -> None:
    """Opaque or non-JWT access tokens cannot be classified from payload claims."""
    assert extract_oauth_scopes_from_access_token("opaque-access-token") is None
    assert extract_oauth_scopes_from_access_token("") is None


def test_infer_mail_access_channel_preference_orders_by_scope_hints() -> None:
    from mailbox_service.access_token_scopes import infer_mail_access_channel_preference

    assert infer_mail_access_channel_preference(
        "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"
    ) == ["imap", "graph"]
    assert infer_mail_access_channel_preference("Mail.Read offline_access") == ["graph", "imap"]
    assert infer_mail_access_channel_preference(None) == ["imap", "graph"]


def test_resolve_oauth_refresh_scope_for_channel() -> None:
    assert resolve_oauth_refresh_scope_for_channel("graph") == GRAPH_MAIL_READ_SCOPE
    assert resolve_oauth_refresh_scope_for_channel("imap") is None
    assert resolve_oauth_refresh_scope_for_channel(None) is None


def test_cached_token_matches_mail_channel_by_audience() -> None:
    graph_scope = "https://graph.microsoft.com/Mail.Read offline_access"
    outlook_scope = (
        "https://outlook.office.com/IMAP.AccessAsUser.All "
        "https://outlook.office.com/Mail.Read"
    )

    assert cached_token_matches_mail_channel(graph_scope, "graph") is True
    assert cached_token_matches_mail_channel(graph_scope, "imap") is False
    assert cached_token_matches_mail_channel(outlook_scope, "imap") is True
    assert cached_token_matches_mail_channel(outlook_scope, "graph") is False
    assert cached_token_matches_mail_channel(None, "imap") is True
    assert cached_token_matches_mail_channel(None, "graph") is False
