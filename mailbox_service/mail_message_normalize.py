"""Cross-provider message list / field normalization for inbox evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

from mailbox_service.mail_body_sanitize import html_to_visible_text, sanitize_mail_text
from mailbox_service.providers.ports import InboxMessageEvidence

_LIST_CONTAINER_KEYS = (
    "hydra:member",
    "member",
    "items",
    "messages",
    "data",
    "mails",
    "results",
    "emails",
)


@dataclass(frozen=True)
class NormalizedMailMessage:
    """Provider-agnostic message shape before conversion to evidence."""

    message_id: str | None
    from_address: str | None
    from_display: str | None
    subject: str | None
    text: str
    html: str
    received_at: datetime | None
    raw: dict[str, Any]


def extract_message_list(payload: Any) -> list[dict[str, Any]]:
    """Extract a list of message dicts from heterogeneous provider payloads."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in _LIST_CONTAINER_KEYS:
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = value.get("messages") or value.get("items") or value.get("emails")
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, dict)]
    return []


def _first_string(raw: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = raw.get(key)
        if value is None or value == "":
            continue
        if isinstance(value, list):
            value = "\n".join(str(part) for part in value)
        return str(value)
    return ""


def _sender_fields(raw: dict[str, Any]) -> tuple[str, str]:
    sender = (
        raw.get("from")
        or raw.get("fromAddr")
        or raw.get("from_address")
        or raw.get("sender")
        or raw.get("mail_from")
        or raw.get("sendEmail")
        or ""
    )
    if isinstance(sender, dict):
        address = str(sender.get("address") or sender.get("email") or "").strip()
        name = str(sender.get("name") or "").strip()
        display = f"{name} <{address}>".strip() if name and address else (address or name)
        return address, display
    text = str(sender or "").strip()
    return text, text


def parse_received_at(value: Any) -> datetime | None:
    """Parse heterogeneous message timestamps into timezone-aware UTC."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        timestamp = float(value)
        if timestamp > 1_000_000_000_000:
            timestamp = timestamp / 1000.0
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        pass
    try:
        parsed = parsedate_to_datetime(text)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, IndexError):
        return None


def normalize_raw_message(raw: dict[str, Any]) -> NormalizedMailMessage:
    """Map provider-specific keys into a normalized message."""
    from_address, from_display = _sender_fields(raw)
    subject = _first_string(raw, ("subject", "title")) or None
    text = _first_string(
        raw,
        ("text", "textBody", "body_text", "text_content", "intro", "preview", "content", "body"),
    )
    html_value = raw.get("html") or raw.get("htmlBody") or raw.get("body_html") or raw.get("html_content") or ""
    if isinstance(html_value, list):
        html_value = "\n".join(str(part) for part in html_value)
    html = str(html_value or "")
    if not text and html:
        text = html_to_visible_text(html)
    text = sanitize_mail_text(text)
    if html:
        cleaned_html_text = sanitize_mail_text(html_to_visible_text(html))
        if cleaned_html_text and (not text or len(cleaned_html_text) > len(text)):
            if not text:
                text = cleaned_html_text
    message_id = _first_string(raw, ("id", "messageId", "@id", "msgid")) or None
    received_at = parse_received_at(
        raw.get("createdAt")
        or raw.get("created_at")
        or raw.get("receivedAt")
        or raw.get("date")
        or raw.get("time")
        or raw.get("timestamp")
        or raw.get("createTime")
    )
    return NormalizedMailMessage(
        message_id=message_id,
        from_address=from_address or None,
        from_display=from_display or None,
        subject=subject,
        text=text,
        html=html,
        received_at=received_at,
        raw=raw,
    )


def collect_recipient_addresses(raw: dict[str, Any], *, default_recipient: str) -> frozenset[str]:
    """Collect recipient addresses from common provider fields."""
    recipients: set[str] = set()
    if default_recipient.strip():
        recipients.add(default_recipient.strip().lower())
    for key in ("to", "toEmail", "mailTo", "recipient", "recipients"):
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            recipients.add(value.strip().lower())
        elif isinstance(value, list):
            for entry in value:
                if isinstance(entry, str) and entry.strip():
                    recipients.add(entry.strip().lower())
                elif isinstance(entry, dict):
                    email = entry.get("address") or entry.get("email")
                    if email:
                        recipients.add(str(email).strip().lower())
    return frozenset(recipients)


def to_inbox_evidence(
    normalized: NormalizedMailMessage,
    *,
    default_recipient: str,
    raw: dict[str, Any] | None = None,
) -> InboxMessageEvidence:
    """Convert a normalized message into VerificationEvidence input."""
    source = raw if raw is not None else normalized.raw
    return InboxMessageEvidence(
        from_address=normalized.from_address,
        subject=normalized.subject,
        body_text=normalized.text or None,
        received_at=normalized.received_at,
        recipient_addresses=collect_recipient_addresses(source, default_recipient=default_recipient),
        channel=None,
    )


def message_dict_to_evidence(item: dict[str, Any], *, address: str) -> InboxMessageEvidence:
    """One-shot normalize + evidence conversion used by on-demand adapters."""
    normalized = normalize_raw_message(item)
    return to_inbox_evidence(normalized, default_recipient=address, raw=item)
