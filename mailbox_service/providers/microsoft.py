"""Microsoft adapter: VerificationEvidenceSource only; Token refresh stays in TokenService."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from mailbox_service.providers.ports import (
    InboxMessageEvidence,
    MailboxDraft,
    VerificationAllocationSnapshot,
    VerificationEvidence,
    VerificationQuery,
)
from mailbox_service.proxy_service import MicrosoftIMAPClient
from mailbox_service.verification_code_service import (
    InboxMessageCandidate,
    MicrosoftGraphMailReader,
)


class MicrosoftFourSegmentImportDecoder:
    """Decode classic four-segment Microsoft import lines."""

    def decode(self, content: str) -> list[MailboxDraft]:
        drafts: list[MailboxDraft] = []
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [part.strip() for part in line.split("----")]
            if len(parts) != 4:
                raise ValueError(f"Microsoft import expects 4 segments: {line[:80]}")
            primary_email, mail_password, client_id, refresh_token = parts
            drafts.append(
                MailboxDraft(
                    primary_email=primary_email.lower(),
                    client_id=client_id or None,
                    mail_password=mail_password or None,
                    refresh_token=refresh_token or None,
                    provider_type="microsoft",
                )
            )
        return drafts


class MicrosoftVerificationEvidenceSource:
    """List recent messages via Graph or IMAP using detached access context.

    Graph/IMAP clients still need a mailbox identity for proxy sticky routing.
    We pass a SimpleNamespace with ``id`` and ``primary_email`` only — never an ORM instance.
    """

    def __init__(
        self,
        *,
        graph_reader: MicrosoftGraphMailReader | None = None,
        imap_client: MicrosoftIMAPClient | None = None,
    ) -> None:
        self._graph_reader = graph_reader
        self._imap_client = imap_client

    def fetch_evidence(
        self,
        allocation: VerificationAllocationSnapshot,
        query: VerificationQuery,
    ) -> VerificationEvidence:
        access_token = allocation.access_context.get("access_token")
        if not access_token:
            raise RuntimeError("Microsoft evidence source requires access_token in access_context")
        channel = allocation.access_context.get("channel") or "graph"
        mailbox_handle = SimpleNamespace(
            id=allocation.mailbox_id,
            primary_email=allocation.primary_email,
        )
        since_at = query.newer_than or (datetime.now(timezone.utc) - timedelta(hours=24))
        messages: list[InboxMessageCandidate]
        if channel == "imap":
            if self._imap_client is None:
                raise RuntimeError("IMAP client is not configured")
            # Existing IMAP path lists via connected session inside VerificationCodeService;
            # keep Graph as primary evidence path for Microsoft mail_read.
            if self._graph_reader is None:
                raise RuntimeError("Graph reader is not configured for Microsoft evidence")
            messages = self._graph_reader.list_recent_messages(
                mailbox_handle,
                access_token,
                since_at=since_at,
                max_messages=query.max_messages,
            )
        else:
            if self._graph_reader is None:
                raise RuntimeError("Graph reader is not configured")
            messages = self._graph_reader.list_recent_messages(
                mailbox_handle,
                access_token,
                since_at=since_at,
                max_messages=query.max_messages,
            )
        evidence_messages = tuple(
            InboxMessageEvidence(
                from_address=message.from_address,
                subject=message.subject,
                body_text=message.body_text,
                received_at=message.received_at,
                recipient_addresses=frozenset(message.recipient_addresses or ()),
                channel=message.channel,
            )
            for message in messages
        )
        return VerificationEvidence(messages=evidence_messages, read_method=channel)
