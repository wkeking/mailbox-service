"""Read inbox messages and extract verification codes for mail_read leases."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email import message_from_bytes
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime
import imaplib
import re
import time
from typing import Literal
from urllib.parse import quote

import httpx

from mailbox_service.config import Settings
from mailbox_service.models import Mailbox, MailboxCapability, ensure_utc, utc_now
from mailbox_service.proxy_service import (
    EgressProxyService,
    EgressProxyTransportError,
    MicrosoftIMAPClient,
    ResolvedProxy,
)
from mailbox_service.security import summarize_exception
from mailbox_service.token_service import MailboxAccessTokenService

# Default digit fallback after xAI-style codes. Callers may override via code_regex.
DEFAULT_VERIFICATION_CODE_REGEX = r"\b(\d{4,8})\b"
XAI_SUBJECT_CODE_REGEX = re.compile(r"^([A-Z0-9]{3}-[A-Z0-9]{3})\s+xAI", re.IGNORECASE)
XAI_BODY_CODE_REGEX = re.compile(r"\b([A-Z0-9]{3}-[A-Z0-9]{3})\b", re.IGNORECASE)
DIGIT_KEYWORD_CODE_PATTERNS = (
    re.compile(r"verification\s+code[:\s]+(\d{4,8})", re.IGNORECASE),
    re.compile(r"your\s+code[:\s]+(\d{4,8})", re.IGNORECASE),
    re.compile(r"confirm(?:ation)?\s+code[:\s]+(\d{4,8})", re.IGNORECASE),
    re.compile(r"验证码[：:\s]*(\d{4,8})"),
)
DEFAULT_SINCE_SECONDS = 180
DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_POLL_INTERVAL_SECONDS = 3
MAX_MESSAGES_PER_SCAN = 30
# Expand the lookback slightly so clock skew / mislabeled Date headers do not drop
# fresh verification-code messages. Server INTERNALDATE is preferred over Date.
TIME_FILTER_CLOCK_SKEW_SECONDS = 900
IMAP_FETCH_ITEMS = "(INTERNALDATE RFC822)"
# Consumer mail often lands in Junk; verification codes must still be readable there.
IMAP_SCAN_FOLDERS = ("INBOX", "Junk")
GRAPH_SCAN_FOLDERS = ("inbox", "junkemail")
IMAP_INTERNALDATE_PATTERN = re.compile(
    r'INTERNALDATE\s+"([^"]+)"',
    re.IGNORECASE,
)
RECIPIENT_HEADER_NAMES = (
    "To",
    "Cc",
    "Delivered-To",
    "X-Original-To",
    "X-Envelope-To",
)

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
    recipient_addresses: frozenset[str] = field(default_factory=frozenset)


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
    # When None, after xAI use built-in digit keyword / bare-digit fallbacks.
    # When set, after xAI only this custom pattern is tried.
    code_regex: str | None = None
    # Expected recipient (supports plus alias). Defaults to mailbox.primary_email at call site.
    recipient: str | None = None
    require_recipient_match: bool = True


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
        # Graph timestamps are UTC; still widen the API filter slightly for clock skew.
        filter_since_at = expand_lookback_since_at(since_at)
        since_filter = filter_since_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        filter_expression = f"receivedDateTime ge {since_filter}"
        query = (
            f"$filter={quote(filter_expression)}"
            f"&$orderby={quote('receivedDateTime desc')}"
            f"&$top={max_messages}"
            f"&$select={quote('from,subject,body,bodyPreview,receivedDateTime,toRecipients,ccRecipients')}"
        )
        proxy_url = selected_proxy.as_httpx_proxy_url() if selected_proxy is not None else None
        timeout = httpx.Timeout(
            connect=self._connect_timeout,
            read=self._read_timeout,
            write=self._read_timeout,
            pool=self._connect_timeout,
        )
        candidates: list[InboxMessageCandidate] = []
        folder_scan_summary: dict[str, int] = {}
        # Prefer inbox first, then junk; optional folders may be missing and should not fail the scan.
        for folder_name in GRAPH_SCAN_FOLDERS:
            request_url = (
                f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder_name}/messages?{query}"
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
            if response.status_code == 404 and folder_name != "inbox":
                folder_scan_summary[folder_name] = -1
                continue
            if response.status_code >= 400:
                if folder_name == "inbox":
                    raise VerificationCodeReadError(
                        f"Graph 读取收件箱失败，HTTP {response.status_code}"
                    )
                folder_scan_summary[folder_name] = -1
                continue

            payload = response.json()
            raw_messages = payload.get("value") if isinstance(payload, dict) else None
            if not isinstance(raw_messages, list):
                folder_scan_summary[folder_name] = 0
                continue

            folder_count = 0
            for raw_message in raw_messages:
                if not isinstance(raw_message, dict):
                    continue
                from_address = _extract_graph_from_address(raw_message.get("from"))
                subject = raw_message.get("subject") if isinstance(raw_message.get("subject"), str) else None
                body_text = _extract_graph_body_text(raw_message)
                received_at = _parse_iso_datetime(raw_message.get("receivedDateTime"))
                recipient_addresses = _extract_graph_recipient_addresses(raw_message)
                candidates.append(
                    InboxMessageCandidate(
                        from_address=from_address,
                        subject=subject,
                        body_text=body_text,
                        received_at=received_at,
                        channel="graph",
                        recipient_addresses=recipient_addresses,
                    )
                )
                folder_count += 1
            folder_scan_summary[folder_name] = folder_count

        return candidates


class VerificationCodeService:
    """Acquire AT for a mailbox and extract verification codes from recent mail."""

    def __init__(
        self,
        access_token_service: MailboxAccessTokenService,
        imap_client: MicrosoftIMAPClient | None = None,
        graph_reader: MicrosoftGraphMailReader | None = None,
        *,
        settings: Settings | None = None,
        sleep_function=time.sleep,
        clock=utc_now,
    ) -> None:
        self._access_token_service = access_token_service
        # Test doubles may inject fake clients. Production omits them and opens a short-lived
        # proxy stack per poll so request-scoped sessions never hold locks across sleeps.
        self._imap_client = imap_client
        self._graph_reader = graph_reader
        self._settings = settings
        self._sleep = sleep_function
        self._clock = clock

    def wait_for_verification_code(
        self,
        mailbox: Mailbox,
        options: VerificationCodeLookupOptions,
    ) -> VerificationCodeLookupResult:
        """Poll inbox until a matching code is found or timeout is reached."""
        custom_code_pattern: re.Pattern[str] | None = None
        if options.code_regex:
            try:
                custom_code_pattern = re.compile(options.code_regex)
            except re.error as error:
                raise ValueError(f"验证码正则无效：{error}") from error

        deadline = self._clock() + timedelta(seconds=max(options.timeout_seconds, 0))
        since_at = self._clock() - timedelta(seconds=max(options.since_seconds, 0))
        channels = self._resolve_channel_order(mailbox)
        recipient_filter = _normalize_email_address(
            options.recipient if options.recipient else mailbox.primary_email
        )
        attempts = 0
        last_error: Exception | None = None
        # Track whether any channel scan ever completed. Distinguishes "inbox reachable but no
        # matching code" from "every scan failed", so persistent transport errors are not
        # silently reported as an empty result.
        any_scan_succeeded = False

        while True:
            attempts += 1
            if self._imap_client is not None and self._graph_reader is not None:
                # Unit tests inject fakes and share one in-memory session.
                access_token_result = self._access_token_service.ensure_access_token(mailbox.id)
            else:
                # Production: short-lived session/commit so FOR UPDATE locks are not held across sleeps.
                access_token_result = self._access_token_service.ensure_access_token_in_short_transaction(
                    mailbox.id
                )
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
                any_scan_succeeded = True
                match = self._find_code_in_messages(
                    messages,
                    options,
                    custom_code_pattern=custom_code_pattern,
                    recipient_filter=recipient_filter,
                )
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

        # If no scan ever completed, every attempt hit a transport/auth failure. Surface it as an
        # error instead of masking a persistently unreachable inbox as an empty result.
        if not any_scan_succeeded and last_error is not None:
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
        if self._imap_client is not None and self._graph_reader is not None:
            if channel == "graph":
                return self._graph_reader.list_recent_messages(
                    mailbox,
                    access_token,
                    since_at=since_at,
                )
            return self._list_imap_messages(
                self._imap_client,
                mailbox,
                access_token,
                since_at=since_at,
            )

        if self._settings is None:
            raise RuntimeError("VerificationCodeService 缺少 settings，无法建立短事务邮件读取")

        with self._access_token_service._session_factory() as session:
            proxy_service = EgressProxyService(
                session,
                self._settings,
                self._access_token_service._credential_cipher,
            )
            try:
                if channel == "graph":
                    graph_reader = MicrosoftGraphMailReader(
                        proxy_service,
                        self._settings.proxy_connect_timeout_seconds,
                        self._settings.proxy_read_timeout_seconds,
                    )
                    messages = graph_reader.list_recent_messages(
                        mailbox,
                        access_token,
                        since_at=since_at,
                    )
                else:
                    imap_client = MicrosoftIMAPClient(proxy_service, self._settings)
                    messages = self._list_imap_messages(
                        imap_client,
                        mailbox,
                        access_token,
                        since_at=since_at,
                    )
                session.commit()
                return messages
            except Exception:
                session.rollback()
                raise

    def _list_imap_messages(
        self,
        imap_client: MicrosoftIMAPClient,
        mailbox: Mailbox,
        access_token: str,
        *,
        since_at: datetime,
    ) -> list[InboxMessageCandidate]:
        client = imap_client.connect(mailbox, access_token)
        try:
            candidates: list[InboxMessageCandidate] = []
            folder_scan_summary: dict[str, object] = {}
            inbox_select_succeeded = False
            for folder_name in IMAP_SCAN_FOLDERS:
                status_code, _ = client.select(folder_name, readonly=True)
                if status_code != "OK":
                    folder_scan_summary[folder_name] = {"select": status_code, "kept": 0}
                    if folder_name == "INBOX":
                        raise VerificationCodeReadError("无法选择 IMAP 收件箱")
                    continue
                if folder_name == "INBOX":
                    inbox_select_succeeded = True

                # UID SEARCH ALL then keep the newest N messages; time window is applied locally.
                status_code, search_data = client.uid("search", None, "ALL")
                if status_code != "OK" or not search_data or not search_data[0]:
                    folder_scan_summary[folder_name] = {
                        "select": "OK",
                        "total_uids": 0,
                        "kept": 0,
                    }
                    continue

                message_uids = search_data[0].split()
                selected_uids = message_uids[-MAX_MESSAGES_PER_SCAN:]
                kept_count = 0
                for message_uid in reversed(selected_uids):
                    # Prefer server INTERNALDATE for time filtering; Date headers often lack TZ
                    # or use sender-local wall clocks and falsely fall outside the lookback window.
                    status_code, fetch_data = client.uid("fetch", message_uid, IMAP_FETCH_ITEMS)
                    if status_code != "OK" or not fetch_data:
                        continue
                    raw_bytes = _extract_imap_rfc822_bytes(fetch_data)
                    if raw_bytes is None:
                        continue
                    email_message = message_from_bytes(raw_bytes)
                    from_address = _decode_header_value(email_message.get("From"))
                    subject = _decode_header_value(email_message.get("Subject"))
                    body_text = _extract_email_body_text(email_message)
                    server_received_at = _extract_imap_internaldate(fetch_data)
                    header_received_at = _parse_email_date(email_message.get("Date"))
                    received_at = server_received_at or header_received_at
                    if not is_within_lookback_window(received_at, since_at):
                        continue
                    candidates.append(
                        InboxMessageCandidate(
                            from_address=from_address,
                            subject=subject,
                            body_text=body_text,
                            received_at=received_at,
                            channel="imap",
                            recipient_addresses=_extract_message_recipient_addresses(email_message),
                        )
                    )
                    kept_count += 1
                folder_scan_summary[folder_name] = {
                    "select": "OK",
                    "total_uids": len(message_uids),
                    "scanned": len(selected_uids),
                    "kept": kept_count,
                }

            if not inbox_select_succeeded and not candidates:
                raise VerificationCodeReadError("无法选择 IMAP 收件箱")

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
        *,
        custom_code_pattern: re.Pattern[str] | None,
        recipient_filter: str | None,
    ) -> VerificationCodeMatch | None:
        from_filter = (options.from_address or "").strip().lower()
        subject_filter = (options.subject_contains or "").strip().lower()
        body_filter = (options.body_contains or "").strip().lower()

        for message in messages:
            if options.require_recipient_match:
                if not recipient_filter:
                    continue
                if recipient_filter not in message.recipient_addresses:
                    continue

            from_value = (message.from_address or "").lower()
            subject_value = (message.subject or "").lower()
            body_value = message.body_text.lower()
            if from_filter and from_filter not in from_value:
                continue
            if subject_filter and subject_filter not in subject_value:
                continue
            if body_filter and body_filter not in body_value:
                continue

            code = extract_verification_code(
                message.subject or "",
                message.body_text,
                custom_code_pattern=custom_code_pattern,
            )
            if code is None:
                continue
            return VerificationCodeMatch(
                code=code,
                matched_from=message.from_address,
                matched_subject=message.subject,
                message_received_at=message.received_at,
                channel=message.channel,
            )
        return None


def expand_lookback_since_at(since_at: datetime) -> datetime:
    """Return a slightly older lower bound to tolerate clock skew."""
    return ensure_utc(since_at) - timedelta(seconds=TIME_FILTER_CLOCK_SKEW_SECONDS)


def is_within_lookback_window(received_at: datetime | None, since_at: datetime) -> bool:
    """Return whether a message timestamp should stay in the verification scan window.

    Missing timestamps are kept (better to over-scan recent UIDs than drop a code mail).
    Known timestamps are compared in UTC against ``since_at`` minus a clock-skew buffer.
    """
    if received_at is None:
        return True
    return ensure_utc(received_at) >= expand_lookback_since_at(since_at)


def extract_verification_code(
    subject: str,
    body_text: str,
    *,
    custom_code_pattern: re.Pattern[str] | None = None,
) -> str | None:
    """Extract a code with priority: xAI subject > explicit custom regex > xAI body > digit fallbacks.

    An xAI subject like ``ABC-123 xAI`` is an unambiguous signal and stays first. A
    caller-supplied ``custom_code_pattern`` expresses explicit intent, so it is tried before
    the broad xAI body heuristic (which would otherwise match any ``ABC-123``-shaped token in
    unrelated mail). When a custom pattern is provided, only it is used after the subject check.
    """
    subject_value = subject or ""
    body_value = body_text or ""

    subject_match = XAI_SUBJECT_CODE_REGEX.search(subject_value)
    if subject_match is not None:
        return subject_match.group(1)

    searchable_text = "\n".join(part for part in [subject_value, body_value] if part)

    if custom_code_pattern is not None:
        custom_match = custom_code_pattern.search(searchable_text)
        if custom_match is not None:
            return custom_match.group(1) if custom_match.lastindex else custom_match.group(0)
        return None

    body_xai_match = XAI_BODY_CODE_REGEX.search(searchable_text)
    if body_xai_match is not None:
        return body_xai_match.group(1)

    for keyword_pattern in DIGIT_KEYWORD_CODE_PATTERNS:
        keyword_match = keyword_pattern.search(searchable_text)
        if keyword_match is not None:
            return keyword_match.group(1)

    digit_match = re.search(DEFAULT_VERIFICATION_CODE_REGEX, searchable_text)
    if digit_match is not None:
        return digit_match.group(1)
    return None


def _normalize_email_address(raw_address: str | None) -> str | None:
    if raw_address is None:
        return None
    normalized_value = raw_address.strip().lower()
    if not normalized_value:
        return None
    # Strip display-name form: "Name <user@example.com>"
    if "<" in normalized_value and ">" in normalized_value:
        start_index = normalized_value.rfind("<")
        end_index = normalized_value.rfind(">")
        if start_index < end_index:
            normalized_value = normalized_value[start_index + 1 : end_index].strip()
    return normalized_value or None


def _extract_message_recipient_addresses(email_message: Message) -> frozenset[str]:
    raw_recipients: list[str] = []
    for header_name in RECIPIENT_HEADER_NAMES:
        raw_recipients.extend(email_message.get_all(header_name, []))
    addresses: set[str] = set()
    for _, recipient_address in getaddresses(raw_recipients):
        normalized_address = _normalize_email_address(recipient_address)
        if normalized_address:
            addresses.add(normalized_address)
    return frozenset(addresses)


def _extract_graph_recipient_addresses(raw_message: dict[str, object]) -> frozenset[str]:
    addresses: set[str] = set()
    for field_name in ("toRecipients", "ccRecipients"):
        recipients = raw_message.get(field_name)
        if not isinstance(recipients, list):
            continue
        for recipient in recipients:
            if not isinstance(recipient, dict):
                continue
            email_address = recipient.get("emailAddress")
            if not isinstance(email_address, dict):
                continue
            address = email_address.get("address")
            normalized_address = _normalize_email_address(address if isinstance(address, str) else None)
            if normalized_address:
                addresses.add(normalized_address)
    return frozenset(addresses)


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


def _extract_imap_internaldate(fetch_data: list[object]) -> datetime | None:
    """Parse IMAP INTERNALDATE from a UID FETCH response metadata blob."""
    for item in fetch_data:
        metadata_text = _imap_fetch_metadata_text(item)
        if metadata_text is None:
            continue
        match = IMAP_INTERNALDATE_PATTERN.search(metadata_text)
        if match is None:
            continue
        parsed_internaldate = _parse_imap_internaldate(match.group(1))
        if parsed_internaldate is not None:
            return parsed_internaldate
    return None


def _imap_fetch_metadata_text(fetch_item: object) -> str | None:
    if isinstance(fetch_item, tuple) and fetch_item:
        metadata = fetch_item[0]
    else:
        metadata = fetch_item
    if isinstance(metadata, (bytes, bytearray)):
        return bytes(metadata).decode("utf-8", errors="replace")
    if isinstance(metadata, str):
        return metadata
    return None


def _parse_imap_internaldate(raw_value: str) -> datetime | None:
    """Parse ``DD-Mon-YYYY HH:MM:SS ±HHMM`` INTERNALDATE into aware UTC."""
    cleaned_value = raw_value.strip().strip('"')
    if not cleaned_value:
        return None
    try:
        parsed_value = datetime.strptime(cleaned_value, "%d-%b-%Y %H:%M:%S %z")
    except ValueError:
        return None
    return parsed_value.astimezone(timezone.utc)


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
    """Parse the RFC822 Date header into aware UTC when possible.

    Naive Date values are treated as UTC only as a last-resort fallback. Callers
    should prefer IMAP INTERNALDATE / Graph receivedDateTime when available.
    """
    if not raw_value:
        return None
    try:
        parsed = parsedate_to_datetime(raw_value)
    except (TypeError, ValueError, IndexError, OverflowError):
        return None
    if parsed.tzinfo is None:
        # Sender wall clocks without TZ are untrustworthy; still normalize so the
        # widened lookback window can absorb moderate offsets.
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
