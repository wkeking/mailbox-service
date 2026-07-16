"""Read inbox messages and extract verification codes for mail_read leases."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email import message_from_bytes
from email.header import decode_header, make_header
from email.message import Message
from email.utils import parsedate_to_datetime
import imaplib
import re
import time
from typing import Literal
from urllib.parse import quote

import httpx

from mailbox_service.models import Mailbox, MailboxCapability, ensure_utc, utc_now
from mailbox_service.proxy_service import (
    EgressProxyService,
    EgressProxyTransportError,
    MicrosoftIMAPClient,
    ResolvedProxy,
)
from mailbox_service.security import summarize_exception
from mailbox_service.token_service import MailboxAccessTokenService

DEFAULT_VERIFICATION_CODE_REGEX = r"\b(\d{4,8})\b"
DEFAULT_SINCE_SECONDS = 180
DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_POLL_INTERVAL_SECONDS = 3
MAX_MESSAGES_PER_SCAN = 30

MailReadChannel = Literal["imap", "graph"]


class VerificationCodeReadError(Exception):
    """Raised when inbox access fails after all configured channels."""


@dataclass(frozen=True)
class InboxMessageCandidate:
    """One inbox message considered for verification-code extraction."""

    from_address: str | None
    subject: str | None
    body_text: str
    received_at: datetime | None
    channel: MailReadChannel


@dataclass(frozen=True)
class VerificationCodeMatch:
    """A verification code extracted from one inbox message."""

    code: str
    matched_from: str | None
    matched_subject: str | None
    message_received_at: datetime | None
    channel: MailReadChannel


@dataclass(frozen=True)
class VerificationCodeLookupResult:
    """Result of a timed verification-code lookup for one lease."""

    found: bool
    code: str | None = None
    matched_from: str | None = None
    matched_subject: str | None = None
    message_received_at: datetime | None = None
    channel: MailReadChannel | None = None
    attempts: int = 0


@dataclass(frozen=True)
class VerificationCodeLookupOptions:
    """Caller-supplied filters for verification-code extraction."""

    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    since_seconds: int = DEFAULT_SINCE_SECONDS
    poll_interval_seconds: int = DEFAULT_POLL_INTERVAL_SECONDS
    from_address: str | None = None
    subject_contains: str | None = None
    body_contains: str | None = None
    code_regex: str = DEFAULT_VERIFICATION_CODE_REGEX


class MicrosoftGraphMailReader:
    """List recent inbox messages through Microsoft Graph with sticky proxy routing."""

    def __init__(self, proxy_service: EgressProxyService, connect_timeout: float, read_timeout: float) -> None:
        self._proxy_service = proxy_service
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout

    def list_recent_messages(
        self,
        mailbox: Mailbox,
        access_token: str,
        *,
        since_at: datetime,
        max_messages: int = MAX_MESSAGES_PER_SCAN,
    ) -> list[InboxMessageCandidate]:
        """Return recent inbox messages newer than ``since_at`` (UTC)."""
        selected_proxy = self._proxy_service.resolve_for_mailbox(mailbox.id)
        try:
            messages = self._list_once(access_token, since_at, max_messages, selected_proxy)
        except EgressProxyTransportError as error:
            if selected_proxy is None:
                raise
            self._proxy_service.record_proxy_failure(selected_proxy.id, error)
            replacement_proxy = self._proxy_service.resolve_for_mailbox(
                mailbox.id,
                excluded_proxy_ids={selected_proxy.id},
                force_rebind=True,
            )
            messages = self._list_once(access_token, since_at, max_messages, replacement_proxy)
            if replacement_proxy is not None:
                self._proxy_service.record_proxy_success(replacement_proxy.id)
            return messages

        if selected_proxy is not None:
            self._proxy_service.record_proxy_success(selected_proxy.id)
        return messages

    def _list_once(
        self,
        access_token: str,
        since_at: datetime,
        max_messages: int,
        selected_proxy: ResolvedProxy | None,
    ) -> list[InboxMessageCandidate]:
        since_filter = ensure_utc(since_at).strftime("%Y-%m-%dT%H:%M:%SZ")
        filter_expression = f"receivedDateTime ge {since_filter}"
        query = (
            f"$filter={quote(filter_expression)}"
            f"&$orderby={quote('receivedDateTime desc')}"
            f"&$top={max_messages}"
            f"&$select={quote('from,subject,body,bodyPreview,receivedDateTime')}"
        )
        request_url = f"https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?{query}"
        proxy_url = selected_proxy.as_httpx_proxy_url() if selected_proxy is not None else None
        timeout = httpx.Timeout(
            connect=self._connect_timeout,
            read=self._read_timeout,
            write=self._read_timeout,
            pool=self._connect_timeout,
        )
        try:
            with httpx.Client(proxy=proxy_url, timeout=timeout) as client:
                response = client.get(
                    request_url,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
        except (httpx.ProxyError, httpx.ConnectTimeout, httpx.ReadTimeout) as error:
            raise EgressProxyTransportError("Graph 代理链路不可用") from error
        except httpx.ConnectError as error:
            if selected_proxy is not None:
                raise EgressProxyTransportError("Graph 代理连接失败") from error
            raise VerificationCodeReadError("无法连接 Microsoft Graph 读取收件箱") from error

        if response.status_code in {401, 403}:
            raise VerificationCodeReadError(f"Graph 鉴权失败，HTTP {response.status_code}")
        if response.status_code >= 400:
            raise VerificationCodeReadError(f"Graph 读取收件箱失败，HTTP {response.status_code}")

        payload = response.json()
        raw_messages = payload.get("value") if isinstance(payload, dict) else None
        if not isinstance(raw_messages, list):
            return []

        candidates: list[InboxMessageCandidate] = []
        for raw_message in raw_messages:
            if not isinstance(raw_message, dict):
                continue
            from_address = _extract_graph_from_address(raw_message.get("from"))
            subject = raw_message.get("subject") if isinstance(raw_message.get("subject"), str) else None
            body_text = _extract_graph_body_text(raw_message)
            received_at = _parse_iso_datetime(raw_message.get("receivedDateTime"))
            candidates.append(
                InboxMessageCandidate(
                    from_address=from_address,
                    subject=subject,
                    body_text=body_text,
                    received_at=received_at,
                    channel="graph",
                )
            )
        return candidates


class VerificationCodeService:
    """Acquire AT for a mailbox and extract verification codes from recent mail."""

    def __init__(
        self,
        access_token_service: MailboxAccessTokenService,
        imap_client: MicrosoftIMAPClient,
        graph_reader: MicrosoftGraphMailReader,
        *,
        sleep_function=time.sleep,
        clock=utc_now,
    ) -> None:
        self._access_token_service = access_token_service
        self._imap_client = imap_client
        self._graph_reader = graph_reader
        self._sleep = sleep_function
        self._clock = clock

    def wait_for_verification_code(
        self,
        mailbox: Mailbox,
        options: VerificationCodeLookupOptions,
    ) -> VerificationCodeLookupResult:
        """Poll inbox until a matching code is found or timeout is reached."""
        try:
            code_pattern = re.compile(options.code_regex)
        except re.error as error:
            raise ValueError(f"验证码正则无效：{error}") from error

        deadline = self._clock() + timedelta(seconds=max(options.timeout_seconds, 0))
        since_at = self._clock() - timedelta(seconds=max(options.since_seconds, 0))
        channels = self._resolve_channel_order(mailbox)
        attempts = 0
        last_error: Exception | None = None

        while True:
            attempts += 1
            access_token_result = self._access_token_service.ensure_access_token(mailbox.id)
            for channel in channels:
                try:
                    messages = self._list_messages(
                        mailbox,
                        access_token_result.access_token,
                        channel=channel,
                        since_at=since_at,
                    )
                except Exception as error:  # noqa: BLE001 - continue alternate channel / retry.
                    last_error = error
                    continue
                match = self._find_code_in_messages(messages, options, code_pattern)
                if match is not None:
                    return VerificationCodeLookupResult(
                        found=True,
                        code=match.code,
                        matched_from=match.matched_from,
                        matched_subject=match.matched_subject,
                        message_received_at=match.message_received_at,
                        channel=match.channel,
                        attempts=attempts,
                    )

            if self._clock() >= deadline:
                break
            remaining_seconds = (deadline - self._clock()).total_seconds()
            sleep_seconds = min(max(options.poll_interval_seconds, 1), max(remaining_seconds, 0))
            if sleep_seconds <= 0:
                break
            self._sleep(sleep_seconds)

        if last_error is not None and attempts == 1:
            raise VerificationCodeReadError(summarize_exception(last_error)) from last_error
        return VerificationCodeLookupResult(found=False, attempts=attempts)

    def _list_messages(
        self,
        mailbox: Mailbox,
        access_token: str,
        *,
        channel: MailReadChannel,
        since_at: datetime,
    ) -> list[InboxMessageCandidate]:
        if channel == "graph":
            return self._graph_reader.list_recent_messages(
                mailbox,
                access_token,
                since_at=since_at,
            )
        return self._list_imap_messages(mailbox, access_token, since_at=since_at)

    def _list_imap_messages(
        self,
        mailbox: Mailbox,
        access_token: str,
        *,
        since_at: datetime,
    ) -> list[InboxMessageCandidate]:
        client = self._imap_client.connect(mailbox, access_token)
        try:
            status_code, _ = client.select("INBOX", readonly=True)
            if status_code != "OK":
                raise VerificationCodeReadError("无法选择 IMAP 收件箱")

            since_date = ensure_utc(since_at).strftime("%d-%b-%Y")
            status_code, search_data = client.search(None, "SINCE", since_date)
            if status_code != "OK" or not search_data or not search_data[0]:
                return []

            message_ids = search_data[0].split()
            selected_ids = message_ids[-MAX_MESSAGES_PER_SCAN:]
            candidates: list[InboxMessageCandidate] = []
            for message_id in reversed(selected_ids):
                status_code, fetch_data = client.fetch(message_id, "(RFC822)")
                if status_code != "OK" or not fetch_data:
                    continue
                raw_bytes = _extract_imap_rfc822_bytes(fetch_data)
                if raw_bytes is None:
                    continue
                email_message = message_from_bytes(raw_bytes)
                from_address = _decode_header_value(email_message.get("From"))
                subject = _decode_header_value(email_message.get("Subject"))
                body_text = _extract_email_body_text(email_message)
                received_at = _parse_email_date(email_message.get("Date"))
                if received_at is not None and ensure_utc(received_at) < ensure_utc(since_at):
                    continue
                candidates.append(
                    InboxMessageCandidate(
                        from_address=from_address,
                        subject=subject,
                        body_text=body_text,
                        received_at=received_at,
                        channel="imap",
                    )
                )
            return candidates
        except imaplib.IMAP4.error as error:
            raise VerificationCodeReadError(summarize_exception(error)) from error
        finally:
            try:
                client.logout()
            except Exception:  # noqa: BLE001 - logout is best-effort.
                pass

    @staticmethod
    def _resolve_channel_order(mailbox: Mailbox) -> list[MailReadChannel]:
        if mailbox.capability == MailboxCapability.IMAP:
            return ["imap"]
        if mailbox.capability == MailboxCapability.GRAPH:
            return ["graph"]
        # Missing / unknown capability: prefer IMAP then Graph.
        return ["imap", "graph"]

    @staticmethod
    def _find_code_in_messages(
        messages: list[InboxMessageCandidate],
        options: VerificationCodeLookupOptions,
        code_pattern: re.Pattern[str],
    ) -> VerificationCodeMatch | None:
        from_filter = (options.from_address or "").strip().lower()
        subject_filter = (options.subject_contains or "").strip().lower()
        body_filter = (options.body_contains or "").strip().lower()

        for message in messages:
            from_value = (message.from_address or "").lower()
            subject_value = (message.subject or "").lower()
            body_value = message.body_text.lower()
            if from_filter and from_filter not in from_value:
                continue
            if subject_filter and subject_filter not in subject_value:
                continue
            if body_filter and body_filter not in body_value:
                continue

            searchable_text = "\n".join(
                part for part in [message.subject or "", message.body_text] if part
            )
            match = code_pattern.search(searchable_text)
            if match is None:
                continue
            code = match.group(1) if match.lastindex else match.group(0)
            return VerificationCodeMatch(
                code=code,
                matched_from=message.from_address,
                matched_subject=message.subject,
                message_received_at=message.received_at,
                channel=message.channel,
            )
        return None


def _extract_graph_from_address(from_payload: object) -> str | None:
    if not isinstance(from_payload, dict):
        return None
    email_address = from_payload.get("emailAddress")
    if not isinstance(email_address, dict):
        return None
    address = email_address.get("address")
    return address if isinstance(address, str) else None


def _extract_graph_body_text(raw_message: dict[str, object]) -> str:
    body = raw_message.get("body")
    if isinstance(body, dict):
        content = body.get("content")
        content_type = body.get("contentType")
        if isinstance(content, str):
            if isinstance(content_type, str) and content_type.lower() == "html":
                return _strip_html(content)
            return content
    preview = raw_message.get("bodyPreview")
    return preview if isinstance(preview, str) else ""


def _extract_imap_rfc822_bytes(fetch_data: list[object]) -> bytes | None:
    for item in fetch_data:
        if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], (bytes, bytearray)):
            return bytes(item[1])
    return None


def _decode_header_value(raw_value: str | None) -> str | None:
    if raw_value is None:
        return None
    try:
        return str(make_header(decode_header(raw_value)))
    except Exception:  # noqa: BLE001 - fall back to raw header text.
        return raw_value


def _extract_email_body_text(email_message: Message) -> str:
    plain_parts: list[str] = []
    html_parts: list[str] = []
    if email_message.is_multipart():
        for part in email_message.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition") or "")
            if "attachment" in disposition.lower():
                continue
            payload = part.get_payload(decode=True)
            if not isinstance(payload, (bytes, bytearray)):
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except LookupError:
                text = payload.decode("utf-8", errors="replace")
            if content_type == "text/plain":
                plain_parts.append(text)
            elif content_type == "text/html":
                html_parts.append(_strip_html(text))
    else:
        payload = email_message.get_payload(decode=True)
        if isinstance(payload, (bytes, bytearray)):
            charset = email_message.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except LookupError:
                text = payload.decode("utf-8", errors="replace")
            if email_message.get_content_type() == "text/html":
                html_parts.append(_strip_html(text))
            else:
                plain_parts.append(text)
    if plain_parts:
        return "\n".join(plain_parts)
    return "\n".join(html_parts)


def _strip_html(value: str) -> str:
    without_tags = re.sub(r"<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", without_tags).strip()


def _parse_email_date(raw_value: str | None) -> datetime | None:
    if not raw_value:
        return None
    try:
        parsed = parsedate_to_datetime(raw_value)
    except (TypeError, ValueError, IndexError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_iso_datetime(raw_value: object) -> datetime | None:
    if not isinstance(raw_value, str) or not raw_value:
        return None
    normalized = raw_value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
