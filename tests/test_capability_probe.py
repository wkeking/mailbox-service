"""Unit tests for prefer-by-scope IMAP/Graph capability probing."""

from __future__ import annotations

from base64 import urlsafe_b64encode
import imaplib
import json

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from mailbox_service.access_token_scopes import infer_mail_access_channel_preference
from mailbox_service.capability_probe_service import (
    CapabilityProbeResult,
    ChannelProbeOutcome,
    MailboxCapabilityProbeService,
    ProbeOutcomeKind,
    apply_capability_probe_result,
)
from mailbox_service.config import Settings
from mailbox_service.database import Base
from mailbox_service.models import Mailbox, MailboxCapability
from mailbox_service.proxy_service import MicrosoftTokenResponse
from mailbox_service.security import CredentialCipher
from mailbox_service.token_service import MailboxAccessTokenService


class RecordingImapClient:
    """Test double that records IMAP probe attempts."""

    def __init__(self, outcomes: list[object | Exception]) -> None:
        self.outcomes = outcomes
        self.attempts: list[str] = []

    def connect(self, mailbox: Mailbox, access_token: str):
        self.attempts.append(mailbox.primary_email)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class RecordingGraphClient:
    """Test double that records Graph probe attempts."""

    def __init__(self, outcomes: list[ChannelProbeOutcome]) -> None:
        self.outcomes = outcomes
        self.attempts: list[str] = []

    def probe_messages_access(self, mailbox: Mailbox, access_token: str) -> ChannelProbeOutcome:
        self.attempts.append(mailbox.primary_email)
        return self.outcomes.pop(0)


class FakeMicrosoftOAuthClient:
    def __init__(self, response: MicrosoftTokenResponse) -> None:
        self.response = response
        self.refresh_attempts = 0

    def refresh_access_token(self, mailbox: Mailbox, refresh_token: str) -> MicrosoftTokenResponse:
        self.refresh_attempts += 1
        return self.response


class SuccessfulImapSession:
    def logout(self) -> None:
        return None


def build_unsigned_jwt(payload: dict) -> str:
    header_segment = urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8")).rstrip(b"=").decode(
        "ascii"
    )
    payload_segment = urlsafe_b64encode(json.dumps(payload).encode("utf-8")).rstrip(b"=").decode("ascii")
    return f"{header_segment}.{payload_segment}.signature"


def test_infer_preference_prefers_graph_when_scope_is_graph_only() -> None:
    assert infer_mail_access_channel_preference("Mail.Read offline_access") == ["graph", "imap"]


def test_infer_preference_defaults_to_imap() -> None:
    assert infer_mail_access_channel_preference(None) == ["imap", "graph"]
    assert infer_mail_access_channel_preference("offline_access") == ["imap", "graph"]


def test_probe_stops_on_preferred_imap_success() -> None:
    settings = Settings(database_url="sqlite+pysqlite:///:memory:")
    imap_client = RecordingImapClient([SuccessfulImapSession()])
    graph_client = RecordingGraphClient([])
    service = MailboxCapabilityProbeService(settings, imap_client, graph_client)
    mailbox = Mailbox(
        primary_email="owner@outlook.com",
        scope="https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
    )

    result = service.probe_mailbox_capability(mailbox, "access-token")

    assert result.capability == MailboxCapability.IMAP
    assert result.preferred_channel == "imap"
    assert result.probe_error is None
    assert len(result.outcomes) == 1
    assert graph_client.attempts == []


def test_probe_falls_back_to_graph_after_imap_auth_failure() -> None:
    settings = Settings(database_url="sqlite+pysqlite:///:memory:")
    imap_client = RecordingImapClient([imaplib.IMAP4.error("AUTHENTICATE failed")])
    graph_client = RecordingGraphClient(
        [ChannelProbeOutcome(channel="graph", kind=ProbeOutcomeKind.SUCCESS)]
    )
    service = MailboxCapabilityProbeService(settings, imap_client, graph_client)
    mailbox = Mailbox(primary_email="owner@outlook.com", scope=None)

    result = service.probe_mailbox_capability(mailbox, "access-token")

    assert result.capability == MailboxCapability.GRAPH
    assert [item.channel for item in result.outcomes] == ["imap", "graph"]
    assert result.probe_error is None


def test_probe_marks_unusable_when_both_auth_fail() -> None:
    settings = Settings(database_url="sqlite+pysqlite:///:memory:")
    imap_client = RecordingImapClient([imaplib.IMAP4.error("AUTHENTICATE failed")])
    graph_client = RecordingGraphClient(
        [ChannelProbeOutcome(channel="graph", kind=ProbeOutcomeKind.AUTH_FAILED, error_summary="HTTP 401")]
    )
    service = MailboxCapabilityProbeService(settings, imap_client, graph_client)
    mailbox = Mailbox(primary_email="owner@outlook.com")

    result = service.probe_mailbox_capability(mailbox, "access-token")

    assert result.capability == MailboxCapability.UNUSABLE
    assert result.probe_error is not None
    assert "imap" in result.probe_error
    assert "graph" in result.probe_error


def test_probe_marks_unknown_when_both_transport_fail() -> None:
    settings = Settings(database_url="sqlite+pysqlite:///:memory:")
    imap_client = RecordingImapClient([OSError("connection timed out")])
    graph_client = RecordingGraphClient(
        [
            ChannelProbeOutcome(
                channel="graph",
                kind=ProbeOutcomeKind.TRANSPORT_FAILED,
                error_summary="Graph 代理链路不可用",
            )
        ]
    )
    service = MailboxCapabilityProbeService(settings, imap_client, graph_client)
    mailbox = Mailbox(primary_email="owner@outlook.com")

    result = service.probe_mailbox_capability(mailbox, "access-token")

    assert result.capability == MailboxCapability.UNKNOWN
    assert result.probe_error is not None


def test_probe_marks_unknown_for_imap_runtime_defect_not_unusable() -> None:
    """Programming defects during IMAP connect must not be treated as auth failure."""
    settings = Settings(database_url="sqlite+pysqlite:///:memory:")
    imap_client = RecordingImapClient(
        [AttributeError("property 'file' of 'ProxyIMAP4SSL' object has no setter")]
    )
    graph_client = RecordingGraphClient(
        [ChannelProbeOutcome(channel="graph", kind=ProbeOutcomeKind.AUTH_FAILED, error_summary="HTTP 401")]
    )
    service = MailboxCapabilityProbeService(settings, imap_client, graph_client)
    mailbox = Mailbox(
        primary_email="owner@outlook.com",
        scope="https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
    )

    result = service.probe_mailbox_capability(mailbox, "access-token")

    assert result.capability == MailboxCapability.UNKNOWN
    assert result.outcomes[0].kind == ProbeOutcomeKind.TRANSPORT_FAILED


def test_token_refresh_persists_capability_from_prober() -> None:
    database_engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(database_engine)
    session: Session = sessionmaker(bind=database_engine, expire_on_commit=False)()
    encryption_key = urlsafe_b64encode(b"c" * 32).decode("ascii")
    settings = Settings(
        database_url="sqlite+pysqlite:///:memory:",
        credential_encryption_key=encryption_key,
    )
    cipher = CredentialCipher(encryption_key)
    access_token = build_unsigned_jwt(
        {"scp": "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"}
    )
    oauth_client = FakeMicrosoftOAuthClient(
        MicrosoftTokenResponse(
            access_token=access_token,
            expires_in=3600,
            scope="https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
        )
    )

    class FixedProber:
        def probe_mailbox_capability(self, mailbox: Mailbox, access_token: str) -> CapabilityProbeResult:
            return CapabilityProbeResult(
                capability=MailboxCapability.IMAP,
                preferred_channel="imap",
                probe_error=None,
                outcomes=(ChannelProbeOutcome(channel="imap", kind=ProbeOutcomeKind.SUCCESS),),
            )

    service = MailboxAccessTokenService(
        session,
        settings,
        cipher,
        oauth_client,
        capability_prober=FixedProber(),
    )
    mailbox = Mailbox(
        primary_email="owner@outlook.com",
        client_id="client-id",
        refresh_token_ciphertext=cipher.encrypt("refresh-token"),
    )
    session.add(mailbox)
    session.flush()

    service.ensure_access_token(mailbox.id, force_refresh=True)

    assert mailbox.capability == MailboxCapability.IMAP
    assert mailbox.capability_probed_at is not None
    assert mailbox.capability_probe_error is None
    assert mailbox.scope == "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"


def test_apply_capability_probe_result_writes_error_for_unusable() -> None:
    mailbox = Mailbox(primary_email="owner@outlook.com")
    result = CapabilityProbeResult(
        capability=MailboxCapability.UNUSABLE,
        preferred_channel="imap",
        probe_error="imap:auth;graph:auth",
        outcomes=(),
    )

    apply_capability_probe_result(mailbox, result)

    assert mailbox.capability == MailboxCapability.UNUSABLE
    assert mailbox.capability_probe_error == "imap:auth;graph:auth"
    assert mailbox.capability_probed_at is not None
