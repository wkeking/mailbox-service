"""Read inbox messages and extract verification codes for mail_read leases."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email import message_from_bytes
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime
import asyncio
import imaplib
import inspect
import logging
import re
import time
from typing import Literal
from urllib.parse import quote

import httpx

from mailbox_service.config import Settings
from mailbox_service.verification_code_matcher import (
    MAX_MESSAGE_BODY_BYTES,
    MAX_REQUEST_BODY_BYTES,
    MAX_SCAN_BODY_BYTES,
    SafeVerificationCodeMatcher,
    VerificationCodePatternOptions,
    VerificationCodePatternType,
    truncate_text_to_byte_budget,
)
from mailbox_service.models import Mailbox, MailboxCapability, ensure_utc, utc_now
from mailbox_service.proxy_service import (
    EgressProxyService,
    EgressProxyTransportError,
    MicrosoftIMAPClient,
    ResolvedProxy,
    describe_proxy_for_log,
)
from mailbox_service.security import (
    summarize_exception,
    summarize_microsoft_error_payload,
    summarize_text,
)
from mailbox_service.token_service import MailboxAccessTokenService

# Prefer uvicorn's error logger so remote-mail diagnostics appear in process stdout / docker logs.
logger = logging.getLogger("uvicorn.error")

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


def _summarize_graph_response_error(response: httpx.Response) -> str:
    """Return a truncated Graph error summary safe for operational logs."""
    try:
        payload = response.json()
    except ValueError:
        body_preview = summarize_text(response.text, maximum_length=200)
        return body_preview or f"empty_body status={response.status_code}"
    microsoft_error = summarize_microsoft_error_payload(payload)
    if microsoft_error:
        return microsoft_error
    return f"unparsed_error status={response.status_code}"


def is_mail_access_auth_failure(error: BaseException) -> bool:
    """Return whether a mail-read failure looks like AT/auth rejection rather than transport.

    Used to decide whether a force-refresh of the access token is worth trying once before
    abandoning the current channel attempt. Walks ``__cause__`` so summarized
    ``VerificationCodeReadError`` wrappers still match the underlying IMAP/Graph failure.
    """
    current: BaseException | None = error
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        if isinstance(current, imaplib.IMAP4.error):
            message = str(current).casefold()
            if any(
                marker in message
                for marker in ("authenticate", "authentication", "auth failed", "login failed")
            ):
                return True
        if isinstance(current, VerificationCodeReadError):
            message = str(current).casefold()
            original_message = str(current)
            if "鉴权" in original_message:
                return True
            if any(
                marker in message
                for marker in (
                    "authenticate",
                    "authentication",
                    "http 401",
                    "http 403",
                    "auth failed",
                    "login failed",
                )
            ):
                return True
        current = current.__cause__ if isinstance(current.__cause__, BaseException) else None
    return False


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
            messages = self._list_once(
                mailbox,
                access_token,
                since_at,
                max_messages,
                selected_proxy,
            )
        except EgressProxyTransportError as error:
            if selected_proxy is None:
                raise
            logger.warning(
                "microsoft_graph_proxy_failover mailbox_id=%s primary_email=%s "
                "failed_proxy=%s error=%s",
                mailbox.id,
                mailbox.primary_email,
                describe_proxy_for_log(selected_proxy),
                summarize_exception(error),
            )
            self._proxy_service.record_proxy_failure(selected_proxy.id, error)
            replacement_proxy = self._proxy_service.resolve_for_mailbox(
                mailbox.id,
                excluded_proxy_ids={selected_proxy.id},
                force_rebind=True,
            )
            try:
                messages = self._list_once(
                    mailbox,
                    access_token,
                    since_at,
                    max_messages,
                    replacement_proxy,
                )
            except Exception as retry_error:
                logger.warning(
                    "microsoft_graph_proxy_failover_failed mailbox_id=%s primary_email=%s "
                    "failed_proxy=%s replacement_proxy=%s error=%s",
                    mailbox.id,
                    mailbox.primary_email,
                    describe_proxy_for_log(selected_proxy),
                    describe_proxy_for_log(replacement_proxy),
                    summarize_exception(retry_error),
                )
                raise
            if replacement_proxy is not None:
                self._proxy_service.record_proxy_success(replacement_proxy.id)
            return messages

        if selected_proxy is not None:
            self._proxy_service.record_proxy_success(selected_proxy.id)
        return messages

    def _list_once(
        self,
        mailbox: Mailbox,
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
        proxy_description = describe_proxy_for_log(selected_proxy)
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
                logger.warning(
                    "microsoft_graph_read_failed mailbox_id=%s primary_email=%s "
                    "proxy=%s folder=%s reason=proxy_chain error=%s",
                    mailbox.id,
                    mailbox.primary_email,
                    proxy_description,
                    folder_name,
                    summarize_exception(error),
                )
                raise EgressProxyTransportError("Graph 代理链路不可用") from error
            except httpx.ConnectError as error:
                if selected_proxy is not None:
                    logger.warning(
                        "microsoft_graph_read_failed mailbox_id=%s primary_email=%s "
                        "proxy=%s folder=%s reason=proxy_connect error=%s",
                        mailbox.id,
                        mailbox.primary_email,
                        proxy_description,
                        folder_name,
                        summarize_exception(error),
                    )
                    raise EgressProxyTransportError("Graph 代理连接失败") from error
                logger.warning(
                    "microsoft_graph_read_failed mailbox_id=%s primary_email=%s "
                    "proxy=%s folder=%s reason=connect error=%s",
                    mailbox.id,
                    mailbox.primary_email,
                    proxy_description,
                    folder_name,
                    summarize_exception(error),
                )
                raise VerificationCodeReadError("无法连接 Microsoft Graph 读取收件箱") from error

            if response.status_code in {401, 403}:
                microsoft_error = _summarize_graph_response_error(response)
                logger.warning(
                    "microsoft_graph_read_failed mailbox_id=%s primary_email=%s "
                    "proxy=%s folder=%s reason=auth http_status=%s microsoft=%s",
                    mailbox.id,
                    mailbox.primary_email,
                    proxy_description,
                    folder_name,
                    response.status_code,
                    microsoft_error,
                )
                raise VerificationCodeReadError(f"Graph 鉴权失败，HTTP {response.status_code}")
            if response.status_code == 404 and folder_name != "inbox":
                folder_scan_summary[folder_name] = -1
                continue
            if response.status_code >= 400:
                microsoft_error = _summarize_graph_response_error(response)
                if folder_name == "inbox":
                    logger.warning(
                        "microsoft_graph_read_failed mailbox_id=%s primary_email=%s "
                        "proxy=%s folder=%s reason=http_status http_status=%s microsoft=%s",
                        mailbox.id,
                        mailbox.primary_email,
                        proxy_description,
                        folder_name,
                        response.status_code,
                        microsoft_error,
                    )
                    raise VerificationCodeReadError(
                        f"Graph 读取收件箱失败，HTTP {response.status_code}"
                    )
                logger.warning(
                    "microsoft_graph_optional_folder_failed mailbox_id=%s primary_email=%s "
                    "proxy=%s folder=%s http_status=%s microsoft=%s",
                    mailbox.id,
                    mailbox.primary_email,
                    proxy_description,
                    folder_name,
                    response.status_code,
                    microsoft_error,
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

    async def wait_for_verification_code(
        self,
        mailbox: Mailbox,
        options: VerificationCodeLookupOptions,
        *,
        authorization_checkpoint=None,
    ) -> VerificationCodeLookupResult:
        """Poll inbox until a matching code is found or timeout is reached (async).

        Production uses ``asyncio.sleep`` when the injected ``sleep_function`` is the default
        ``time.sleep``, so FastAPI async endpoints do not block the event loop on poll waits.
        Tests may inject a sync no-op sleep. ``authorization_checkpoint`` may be sync or async.
        """
        custom_matcher: SafeVerificationCodeMatcher | None = None
        if getattr(options, "code_regex", None):
            custom_matcher = SafeVerificationCodeMatcher.from_deprecated_code_regex(options.code_regex)
        elif getattr(options, "pattern_type", None) is not None:
            custom_matcher = SafeVerificationCodeMatcher.from_options(
                VerificationCodePatternOptions(
                    pattern_type=options.pattern_type,
                    minimum_length=getattr(options, "pattern_minimum_length", None) or 4,
                    maximum_length=getattr(options, "pattern_maximum_length", None) or 8,
                    prefix=getattr(options, "pattern_prefix", None),
                )
            )

        # Provider-aware: SMSBower uses direct getCode; on-demand HTTP providers list messages.
        provider_type = getattr(mailbox, "provider_type", None) or "microsoft"
        if provider_type == "smsbower_gmail":
            return await self._wait_for_smsbower_code(mailbox, options, authorization_checkpoint)
        from mailbox_service.providers.catalog import ON_DEMAND_PROVIDER_TYPES

        if provider_type in ON_DEMAND_PROVIDER_TYPES:
            return await self._wait_for_ondemand_code(
                mailbox, options, authorization_checkpoint, provider_type=provider_type
            )

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
        request_body_bytes_consumed = 0

        while True:
            if authorization_checkpoint is not None:
                await _maybe_await(authorization_checkpoint())
            attempts += 1
            for channel in channels:
                try:
                    messages = self._list_messages_with_auth_refresh(
                        mailbox,
                        channel=channel,
                        since_at=since_at,
                        poll_attempt=attempts,
                    )
                except Exception as error:  # noqa: BLE001 - continue alternate channel / retry.
                    last_error = error
                    logger.warning(
                        "verification_code_scan_attempt_failed mailbox_id=%s primary_email=%s "
                        "channel=%s attempt=%s error=%s",
                        mailbox.id,
                        mailbox.primary_email,
                        channel,
                        attempts,
                        summarize_exception(error),
                    )
                    continue
                any_scan_succeeded = True
                remaining_request_budget = max(0, MAX_REQUEST_BODY_BYTES - request_body_bytes_consumed)
                match, scan_bytes_consumed, request_budget_exhausted = self._find_code_in_messages(
                    messages,
                    options,
                    custom_matcher=custom_matcher,
                    recipient_filter=recipient_filter,
                    remaining_request_budget_bytes=remaining_request_budget,
                )
                request_body_bytes_consumed += scan_bytes_consumed
                if match is not None:
                    if authorization_checkpoint is not None:
                        await _maybe_await(authorization_checkpoint())
                    _persist_last_verification_code(
                        self._access_token_service._session_factory,
                        target_id=mailbox.id,
                        provider_type=provider_type,
                        code=match.code,
                        checked_at=self._clock(),
                    )
                    return VerificationCodeLookupResult(
                        found=True,
                        code=match.code,
                        matched_from=match.matched_from,
                        matched_subject=match.matched_subject,
                        message_received_at=match.message_received_at,
                        channel=match.channel,
                        attempts=attempts,
                    )
                if request_budget_exhausted:
                    logger.warning(
                        "verification_code_request_budget_exhausted mailbox_id=%s primary_email=%s "
                        "consumed_bytes=%s limit_bytes=%s attempts=%s",
                        mailbox.id,
                        mailbox.primary_email,
                        request_body_bytes_consumed,
                        MAX_REQUEST_BODY_BYTES,
                        attempts,
                    )
                    return VerificationCodeLookupResult(found=False, attempts=attempts)

            if self._clock() >= deadline:
                break
            remaining_seconds = (deadline - self._clock()).total_seconds()
            sleep_seconds = min(max(options.poll_interval_seconds, 1), max(remaining_seconds, 0))
            if sleep_seconds <= 0:
                break
            await self._async_sleep(sleep_seconds)

        # If no scan ever completed, every attempt hit a transport/auth failure. Surface it as an
        # error instead of masking a persistently unreachable inbox as an empty result.
        if not any_scan_succeeded and last_error is not None:
            logger.error(
                "verification_code_inbox_unreachable mailbox_id=%s primary_email=%s "
                "channels=%s attempts=%s timeout_seconds=%s last_error=%s",
                mailbox.id,
                mailbox.primary_email,
                ",".join(channels),
                attempts,
                options.timeout_seconds,
                summarize_exception(last_error),
            )
            raise VerificationCodeReadError(summarize_exception(last_error)) from last_error
        return VerificationCodeLookupResult(found=False, attempts=attempts)

    async def _async_sleep(self, sleep_seconds: float) -> None:
        """Prefer asyncio.sleep for default sleep; honor injectable test doubles."""
        if self._sleep is time.sleep:
            await asyncio.sleep(sleep_seconds)
            return
        sleep_result = self._sleep(sleep_seconds)
        await _maybe_await(sleep_result)


    async def _wait_for_smsbower_code(
        self,
        mailbox: Mailbox,
        options: VerificationCodeLookupOptions,
        authorization_checkpoint=None,
    ) -> VerificationCodeLookupResult:
        """Poll SMSBower getCode without Microsoft TokenService."""
        from mailbox_service.models import MailboxProviderResource
        from mailbox_service.providers.smsbower_contracts import (
            build_get_code_request,
            normalize_smsbower_base_url,
        )
        from mailbox_service.providers.smsbower_gmail import SmsBowerUnsupportedFilterError
        from mailbox_service.providers.smsbower_transport import (
            HttpxSmsBowerClient,
            SmsBowerMailTransport,
            SmsBowerTransportError,
        )
        import json

        if any(
            (
                options.from_address,
                options.subject_contains,
                options.body_contains,
                options.recipient,
            )
        ):
            raise SmsBowerUnsupportedFilterError(
                "SMSBower direct-code path does not support message filters"
            )
        if self._settings is None:
            raise RuntimeError("VerificationCodeService 缺少 settings")
        deadline = self._clock() + timedelta(seconds=max(options.timeout_seconds, 0))
        attempts = 0
        while True:
            if authorization_checkpoint is not None:
                await _maybe_await(authorization_checkpoint())
            attempts += 1
            # Reload resource each round; releasing/cooldown must fail closed.
            session_factory = self._access_token_service._session_factory
            with session_factory() as session:
                resource = session.get(MailboxProviderResource, mailbox.id)
                if resource is None or resource.lifecycle_state not in ("claimed",):
                    raise VerificationCodeReadError("SMSBower resource not claimable for verification")
                mail_id = resource.external_resource_id
                secret_blob = resource.encrypted_secret
            if secret_blob:
                try:
                    secret = json.loads(
                        self._access_token_service._credential_cipher.decrypt(secret_blob)
                    )
                    mail_id = secret.get("mail_id") or mail_id
                except Exception:
                    pass
            from mailbox_service.provider_settings_service import ProviderSettingsService

            with session_factory() as settings_session:
                runtime = ProviderSettingsService(
                    settings_session,
                    self._settings,
                    self._access_token_service._credential_cipher,
                ).resolve_smsbower_runtime()
            if not runtime.enabled or not (runtime.api_key or "").strip():
                raise VerificationCodeReadError("SMSBower is not configured")
            transport = SmsBowerMailTransport(
                HttpxSmsBowerClient(timeout_seconds=runtime.request_timeout_seconds),
                api_key=(runtime.api_key or "").strip(),
            )
            prepared = build_get_code_request(
                base_url=normalize_smsbower_base_url(runtime.api_base),
                mail_id=str(mail_id),
            )
            try:
                code, is_pending = transport.get_code(prepared)
            except SmsBowerTransportError as error:
                if self._clock() >= deadline:
                    raise VerificationCodeReadError(str(error)) from error
                code, is_pending = None, True
            if code and not is_pending:
                if authorization_checkpoint is not None:
                    await _maybe_await(authorization_checkpoint())
                _persist_last_verification_code(
                    session_factory,
                    target_id=mailbox.id,
                    provider_type="smsbower_gmail",
                    code=code,
                    checked_at=self._clock(),
                )
                return VerificationCodeLookupResult(
                    found=True,
                    code=code,
                    matched_from=None,
                    matched_subject=None,
                    message_received_at=None,
                    channel=None,
                    attempts=attempts,
                )
            if self._clock() >= deadline:
                break
            remaining_seconds = (deadline - self._clock()).total_seconds()
            sleep_seconds = min(max(options.poll_interval_seconds, 1), max(remaining_seconds, 0))
            if sleep_seconds <= 0:
                break
            await self._async_sleep(sleep_seconds)
        return VerificationCodeLookupResult(found=False, attempts=attempts, channel=None)

    async def _wait_for_ondemand_code(
        self,
        mailbox: Mailbox,
        options: VerificationCodeLookupOptions,
        authorization_checkpoint=None,
        *,
        provider_type: str,
    ) -> VerificationCodeLookupResult:
        """Poll on-demand HTTP providers via VerificationEvidenceSource-style adapters."""
        import json

        from mailbox_service.models import MailboxProviderResource
        from mailbox_service.providers.ondemand_adapters import OnDemandProviderError
        from mailbox_service.providers.ondemand_facade import OnDemandProviderService
        from mailbox_service.providers.ports import (
            VerificationAllocationSnapshot,
            VerificationQuery,
        )

        if self._settings is None:
            raise RuntimeError("VerificationCodeService 缺少 settings")
        session_factory = self._access_token_service._session_factory
        cipher = self._access_token_service._credential_cipher
        service = OnDemandProviderService(
            self._settings,
            credential_cipher=cipher,
            session_factory=session_factory,
        )
        deadline = self._clock() + timedelta(seconds=max(options.timeout_seconds, 0))
        since_at = self._clock() - timedelta(seconds=max(options.since_seconds, 0))
        attempts = 0
        custom_matcher: SafeVerificationCodeMatcher | None = None
        if getattr(options, "code_regex", None):
            custom_matcher = SafeVerificationCodeMatcher.from_deprecated_code_regex(options.code_regex)
        while True:
            if authorization_checkpoint is not None:
                await _maybe_await(authorization_checkpoint())
            attempts += 1
            with session_factory() as session:
                resource = session.get(MailboxProviderResource, mailbox.id)
                if resource is None or resource.lifecycle_state not in ("claimed",):
                    raise VerificationCodeReadError(
                        f"{provider_type} resource not claimable for verification"
                    )
                secret_blob = resource.encrypted_secret
                external_id = resource.external_resource_id
                instance_id = resource.provider_instance_id
            access_context: dict[str, str] = {"external_resource_id": str(external_id or "")}
            if secret_blob:
                try:
                    secret = json.loads(cipher.decrypt(secret_blob))
                    if isinstance(secret, dict):
                        for key, value in secret.items():
                            if value is not None:
                                access_context[str(key)] = str(value)
                except Exception:
                    pass
            allocation = VerificationAllocationSnapshot(
                lease_id="",
                mailbox_id=mailbox.id,
                provider_type=provider_type,
                provider_instance_id=instance_id,
                primary_email=mailbox.primary_email,
                allocated_email=mailbox.primary_email,
                access_context=access_context,
            )
            query = VerificationQuery(
                from_address=options.from_address,
                subject_contains=options.subject_contains,
                body_contains=options.body_contains,
                recipient=options.recipient,
                newer_than=since_at,
                max_messages=MAX_MESSAGES_PER_SCAN,
            )
            try:
                evidence = service.fetch_evidence(allocation, query)
            except OnDemandProviderError as error:
                if self._clock() >= deadline:
                    raise VerificationCodeReadError(str(error)) from error
                evidence = None
            except Exception as error:
                if self._clock() >= deadline:
                    raise VerificationCodeReadError(str(error)) from error
                evidence = None
            if evidence is not None:
                if evidence.direct_code:
                    _persist_last_verification_code(
                        session_factory,
                        target_id=mailbox.id,
                        provider_type=provider_type,
                        code=evidence.direct_code,
                        checked_at=self._clock(),
                    )
                    return VerificationCodeLookupResult(
                        found=True,
                        code=evidence.direct_code,
                        attempts=attempts,
                        channel=None,
                    )
                found_any_check = False
                for message in evidence.messages:
                    body = message.body_text or ""
                    subject = message.subject or ""
                    found_any_check = True
                    code = None
                    if custom_matcher is not None:
                        code = custom_matcher.search(subject, body)
                    else:
                        code = extract_verification_code(subject=subject, body_text=body)
                    if code:
                        _persist_last_verification_code(
                            session_factory,
                            target_id=mailbox.id,
                            provider_type=provider_type,
                            code=code,
                            checked_at=self._clock(),
                        )
                        return VerificationCodeLookupResult(
                            found=True,
                            code=code,
                            matched_from=message.from_address,
                            matched_subject=message.subject,
                            message_received_at=message.received_at,
                            channel=None,
                            attempts=attempts,
                        )
                if found_any_check:
                    _persist_last_verification_code(
                        session_factory,
                        target_id=mailbox.id,
                        provider_type=provider_type,
                        code=None,
                        checked_at=self._clock(),
                    )
            if self._clock() >= deadline:
                break
            remaining_seconds = (deadline - self._clock()).total_seconds()
            sleep_seconds = min(max(options.poll_interval_seconds, 1), max(remaining_seconds, 0))
            if sleep_seconds <= 0:
                break
            await self._async_sleep(sleep_seconds)
        return VerificationCodeLookupResult(found=False, attempts=attempts, channel=None)

    def _list_messages_with_auth_refresh(
        self,
        mailbox: Mailbox,
        *,
        channel: MailReadChannel,
        since_at: datetime,
        poll_attempt: int,
    ) -> list[InboxMessageCandidate]:
        """Load messages, forcing one AT refresh when a cached token is rejected for auth.

        Cached AT can still be within ``access_token_expires_at`` while Microsoft already
        rejects it on IMAP XOAUTH2 or Graph (401/403). In that case re-exchange RT once and
        retry the same channel before the outer poll loop moves on.
        """
        access_token_result = self._ensure_mailbox_access_token(
            mailbox,
            channel=channel,
            force_refresh=False,
        )
        try:
            return self._list_messages(
                mailbox,
                access_token_result.access_token,
                channel=channel,
                since_at=since_at,
            )
        except Exception as error:
            if not is_mail_access_auth_failure(error):
                raise
            logger.warning(
                "verification_code_auth_failed_refreshing_at mailbox_id=%s primary_email=%s "
                "channel=%s poll_attempt=%s used_cached_token=%s error=%s",
                mailbox.id,
                mailbox.primary_email,
                channel,
                poll_attempt,
                str(not access_token_result.refreshed).lower(),
                summarize_exception(error),
            )
            refreshed_access_token_result = self._ensure_mailbox_access_token(
                mailbox,
                channel=channel,
                force_refresh=True,
            )
            return self._list_messages(
                mailbox,
                refreshed_access_token_result.access_token,
                channel=channel,
                since_at=since_at,
            )

    def _ensure_mailbox_access_token(
        self,
        mailbox: Mailbox,
        *,
        channel: MailReadChannel,
        force_refresh: bool,
    ):
        """Return AT for the requested channel; production uses a short-lived DB session."""
        # Each channel needs a matching AT audience: Graph requires Graph-scoped AT,
        # IMAP uses the RT default outlook-family AT.
        if self._imap_client is not None and self._graph_reader is not None:
            # Unit tests inject fakes and share one in-memory session.
            return self._access_token_service.ensure_access_token(
                mailbox.id,
                force_refresh=force_refresh,
                preferred_channel=channel,
            )
        # Production: short-lived session/commit so FOR UPDATE locks are not held across sleeps.
        return self._access_token_service.ensure_access_token_in_short_transaction(
            mailbox.id,
            force_refresh=force_refresh,
            preferred_channel=channel,
        )

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

        # Own short proxy UoW via session_factory so Graph/IMAP network I/O never holds a
        # request-scoped Session / row lock (SEC-03).
        proxy_service = EgressProxyService(
            session_factory=self._access_token_service._session_factory,
            settings=self._settings,
            credential_cipher=self._access_token_service._credential_cipher,
        )
        if channel == "graph":
            graph_reader = MicrosoftGraphMailReader(
                proxy_service,
                self._settings.proxy_connect_timeout_seconds,
                self._settings.proxy_read_timeout_seconds,
            )
            return graph_reader.list_recent_messages(
                mailbox,
                access_token,
                since_at=since_at,
            )
        imap_client = MicrosoftIMAPClient(proxy_service, self._settings)
        return self._list_imap_messages(
            imap_client,
            mailbox,
            access_token,
            since_at=since_at,
        )

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
                        logger.warning(
                            "microsoft_imap_read_failed mailbox_id=%s primary_email=%s "
                            "folder=%s reason=select_failed status=%s",
                            mailbox.id,
                            mailbox.primary_email,
                            folder_name,
                            status_code,
                        )
                        raise VerificationCodeReadError("无法选择 IMAP 收件箱")
                    logger.warning(
                        "microsoft_imap_optional_folder_failed mailbox_id=%s primary_email=%s "
                        "folder=%s reason=select_failed status=%s",
                        mailbox.id,
                        mailbox.primary_email,
                        folder_name,
                        status_code,
                    )
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
                logger.warning(
                    "microsoft_imap_read_failed mailbox_id=%s primary_email=%s "
                    "reason=inbox_unavailable folder_summary=%s",
                    mailbox.id,
                    mailbox.primary_email,
                    folder_scan_summary,
                )
                raise VerificationCodeReadError("无法选择 IMAP 收件箱")

            return candidates
        except imaplib.IMAP4.error as error:
            logger.warning(
                "microsoft_imap_read_failed mailbox_id=%s primary_email=%s "
                "reason=protocol error=%s",
                mailbox.id,
                mailbox.primary_email,
                summarize_exception(error),
            )
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
        custom_matcher: SafeVerificationCodeMatcher | None,
        recipient_filter: str | None,
        remaining_request_budget_bytes: int = MAX_REQUEST_BODY_BYTES,
    ) -> tuple[VerificationCodeMatch | None, int, bool]:
        """Search messages under scan/request body budgets.

        Returns ``(match, bytes_consumed, request_budget_exhausted)``.
        """
        from_filter = (options.from_address or "").strip().lower()
        subject_filter = (options.subject_contains or "").strip().lower()
        body_filter = (options.body_contains or "").strip().lower()

        scan_bytes_consumed = 0
        scan_budget = min(MAX_SCAN_BODY_BYTES, max(0, remaining_request_budget_bytes))
        request_budget_exhausted = remaining_request_budget_bytes <= 0

        for message in messages:
            body_text = truncate_text_to_byte_budget(message.body_text or "", MAX_MESSAGE_BODY_BYTES)
            body_byte_length = len(body_text.encode("utf-8"))
            if scan_bytes_consumed + body_byte_length > scan_budget:
                request_budget_exhausted = (
                    remaining_request_budget_bytes - scan_bytes_consumed
                ) <= body_byte_length or scan_bytes_consumed >= MAX_SCAN_BODY_BYTES
                break
            scan_bytes_consumed += body_byte_length

            if options.require_recipient_match:
                if not recipient_filter:
                    continue
                if recipient_filter not in message.recipient_addresses:
                    continue

            from_value = (message.from_address or "").lower()
            subject_value = (message.subject or "").lower()
            body_value = body_text.lower()
            if from_filter and from_filter not in from_value:
                continue
            if subject_filter and subject_filter not in subject_value:
                continue
            if body_filter and body_filter not in body_value:
                continue

            code = extract_verification_code(
                message.subject or "",
                body_text,
                custom_matcher=custom_matcher,
            )
            if code is None:
                continue
            return (
                VerificationCodeMatch(
                    code=code,
                    matched_from=message.from_address,
                    matched_subject=message.subject,
                    message_received_at=message.received_at,
                    channel=message.channel,
                ),
                scan_bytes_consumed,
                False,
            )
        return None, scan_bytes_consumed, request_budget_exhausted


def _persist_last_verification_code(
    session_factory,
    *,
    target_id: str,
    provider_type: str,
    code: str | None,
    checked_at: datetime,
    message_id: str | None = None,
) -> None:
    """Best-effort write of last verification code cache for Admin/operator views.

    Never logs the plaintext code. Failures are swallowed so verification responses
    are not blocked by cache write issues.
    """
    from mailbox_service.models import MailboxProviderResource
    from mailbox_service.providers.catalog import ON_DEMAND_PROVIDER_TYPES

    try:
        with session_factory() as session:
            if provider_type in ON_DEMAND_PROVIDER_TYPES or provider_type == "smsbower_gmail":
                resource = session.get(MailboxProviderResource, target_id)
                if resource is None:
                    return
                if code is not None:
                    resource.last_verification_code = str(code)[:32]
                    if message_id:
                        resource.last_code_message_id = str(message_id)[:255]
                resource.last_code_checked_at = checked_at
                resource.updated_at = checked_at
            else:
                mailbox = session.get(Mailbox, target_id)
                if mailbox is None:
                    return
                if code is not None:
                    mailbox.last_verification_code = str(code)[:32]
                    if message_id:
                        mailbox.last_code_message_id = str(message_id)[:255]
                mailbox.last_code_checked_at = checked_at
                mailbox.updated_at = checked_at
            session.commit()
    except Exception as error:  # noqa: BLE001 - cache must not break verification
        logger.warning(
            "last_verification_code_persist_failed target_id=%s provider_type=%s error=%s",
            target_id,
            provider_type,
            summarize_exception(error),
        )


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
    custom_matcher: SafeVerificationCodeMatcher | None = None,
    custom_code_pattern: re.Pattern[str] | None = None,
) -> str | None:
    """Extract a code with priority: xAI subject > safe custom matcher > xAI body > digit fallbacks.

    External callers must not supply untrusted Python regex. ``custom_code_pattern`` remains only
    for internal fixed patterns used by legacy tests; production uses SafeVerificationCodeMatcher.
    Body text is sanitized with fixed rules (header strip / HTML / QP) before matching.
    """
    from mailbox_service.mail_body_sanitize import sanitize_mail_text

    subject_value = subject or ""
    body_value = truncate_text_to_byte_budget(
        sanitize_mail_text(body_text or ""),
        MAX_MESSAGE_BODY_BYTES,
    )

    subject_match = XAI_SUBJECT_CODE_REGEX.search(subject_value)
    if subject_match is not None:
        return subject_match.group(1)

    searchable_text = "\n".join(part for part in [subject_value, body_value] if part)

    if custom_matcher is not None:
        return custom_matcher.search(subject_value, body_value)

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


async def _maybe_await(value: object) -> object:
    """Await coroutine/future results; return plain values unchanged."""
    if inspect.isawaitable(value):
        return await value
    return value
