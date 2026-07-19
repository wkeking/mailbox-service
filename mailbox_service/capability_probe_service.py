"""Prefer-by-scope runtime probes for IMAP XOAUTH2 and Microsoft Graph mail access."""

from __future__ import annotations

from dataclasses import dataclass
import enum
import imaplib
import logging
from typing import Protocol

import httpx

from mailbox_service.access_token_scopes import (
    GRAPH_MAIL_READ_SCOPE,
    MailAccessChannel,
    infer_mail_access_channel_preference,
)
from mailbox_service.config import Settings
from mailbox_service.models import Mailbox, MailboxCapability, utc_now
from mailbox_service.proxy_service import (
    EgressProxyService,
    EgressProxyTransportError,
    MicrosoftIMAPClient,
    MicrosoftOAuthError,
    MicrosoftTokenResponse,
    ResolvedProxy,
    describe_proxy_for_log,
)
from mailbox_service.security import (
    summarize_exception,
    summarize_microsoft_error_payload,
    summarize_text,
)

# Prefer uvicorn's error logger so remote-mail diagnostics appear in process stdout / docker logs.
logger = logging.getLogger("uvicorn.error")


class ProbeOutcomeKind(str, enum.Enum):
    """Classification for one channel probe attempt."""

    SUCCESS = "success"
    AUTH_FAILED = "auth_failed"
    TRANSPORT_FAILED = "transport_failed"


@dataclass(frozen=True)
class ChannelProbeOutcome:
    """Result of probing one mail access channel."""

    channel: MailAccessChannel
    kind: ProbeOutcomeKind
    error_summary: str | None = None


@dataclass(frozen=True)
class CapabilityProbeAccessTokenReplacement:
    """Token material that should replace the mailbox cached AT after a Graph re-audience."""

    access_token: str
    expires_in: int
    scope: str | None = None
    rotated_refresh_token: str | None = None


@dataclass(frozen=True)
class CapabilityProbeResult:
    """Aggregated capability decision after prefer-by-scope probing."""

    capability: MailboxCapability
    preferred_channel: MailAccessChannel
    probe_error: str | None
    outcomes: tuple[ChannelProbeOutcome, ...]
    access_token_replacement: CapabilityProbeAccessTokenReplacement | None = None


class MailboxCapabilityProberProtocol(Protocol):
    """Minimal protocol shared by the real prober and test doubles."""

    def probe_mailbox_capability(
        self,
        mailbox: Mailbox,
        access_token: str,
        *,
        refresh_token: str | None = None,
    ) -> CapabilityProbeResult:
        """Probe mail access channels for one mailbox access token."""


class MicrosoftGraphMailProbeClient:
    """Probe Graph mail access with sticky proxy routing and one failover retry."""

    def __init__(self, proxy_service: EgressProxyService, settings: Settings) -> None:
        self._proxy_service = proxy_service
        self._settings = settings

    def probe_messages_access(self, mailbox: Mailbox, access_token: str) -> ChannelProbeOutcome:
        """Return whether GET /me/messages succeeds with the provided access token."""
        selected_proxy = self._proxy_service.resolve_for_mailbox(mailbox.id)
        try:
            outcome = self._probe_once(access_token, selected_proxy)
        except EgressProxyTransportError as error:
            if selected_proxy is None:
                return ChannelProbeOutcome(
                    channel="graph",
                    kind=ProbeOutcomeKind.TRANSPORT_FAILED,
                    error_summary=str(error),
                )
            self._proxy_service.record_proxy_failure(selected_proxy.id, error)
            replacement_proxy = self._proxy_service.resolve_for_mailbox(
                mailbox.id,
                excluded_proxy_ids={selected_proxy.id},
                force_rebind=True,
            )
            try:
                outcome = self._probe_once(access_token, replacement_proxy)
            except EgressProxyTransportError as retry_error:
                return ChannelProbeOutcome(
                    channel="graph",
                    kind=ProbeOutcomeKind.TRANSPORT_FAILED,
                    error_summary=str(retry_error),
                )
            if replacement_proxy is not None and outcome.kind != ProbeOutcomeKind.TRANSPORT_FAILED:
                self._proxy_service.record_proxy_success(replacement_proxy.id)
            return outcome

        if selected_proxy is not None and outcome.kind != ProbeOutcomeKind.TRANSPORT_FAILED:
            self._proxy_service.record_proxy_success(selected_proxy.id)
        return outcome

    def _probe_once(
        self,
        access_token: str,
        selected_proxy: ResolvedProxy | None,
    ) -> ChannelProbeOutcome:
        proxy_url = selected_proxy.as_httpx_proxy_url() if selected_proxy is not None else None
        proxy_description = describe_proxy_for_log(selected_proxy)
        timeout = httpx.Timeout(
            connect=self._settings.proxy_connect_timeout_seconds,
            read=self._settings.proxy_read_timeout_seconds,
            write=self._settings.proxy_read_timeout_seconds,
            pool=self._settings.proxy_connect_timeout_seconds,
        )
        try:
            with httpx.Client(proxy=proxy_url, timeout=timeout) as client:
                response = client.get(
                    self._settings.microsoft_graph_messages_url,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
        except (httpx.ProxyError, httpx.ConnectTimeout, httpx.ReadTimeout) as error:
            logger.warning(
                "microsoft_graph_probe_failed proxy=%s reason=proxy_chain error=%s",
                proxy_description,
                summarize_exception(error),
            )
            raise EgressProxyTransportError("Graph 代理链路不可用") from error
        except httpx.ConnectError as error:
            if selected_proxy is not None:
                logger.warning(
                    "microsoft_graph_probe_failed proxy=%s reason=proxy_connect error=%s",
                    proxy_description,
                    summarize_exception(error),
                )
                raise EgressProxyTransportError("Graph 代理连接失败") from error
            logger.warning(
                "microsoft_graph_probe_failed proxy=%s reason=connect error=%s",
                proxy_description,
                summarize_exception(error),
            )
            return ChannelProbeOutcome(
                channel="graph",
                kind=ProbeOutcomeKind.TRANSPORT_FAILED,
                error_summary="无法连接 Microsoft Graph",
            )

        if response.status_code in {401, 403}:
            microsoft_error = _summarize_graph_probe_error(response)
            logger.warning(
                "microsoft_graph_probe_failed proxy=%s reason=auth http_status=%s microsoft=%s",
                proxy_description,
                response.status_code,
                microsoft_error,
            )
            return ChannelProbeOutcome(
                channel="graph",
                kind=ProbeOutcomeKind.AUTH_FAILED,
                error_summary=f"Graph 鉴权失败，HTTP {response.status_code}",
            )
        if response.status_code >= 400:
            microsoft_error = _summarize_graph_probe_error(response)
            logger.warning(
                "microsoft_graph_probe_failed proxy=%s reason=http_status http_status=%s microsoft=%s",
                proxy_description,
                response.status_code,
                microsoft_error,
            )
            return ChannelProbeOutcome(
                channel="graph",
                kind=ProbeOutcomeKind.AUTH_FAILED,
                error_summary=f"Graph 探测失败，HTTP {response.status_code}",
            )
        return ChannelProbeOutcome(channel="graph", kind=ProbeOutcomeKind.SUCCESS)


class GraphAudienceTokenExchangerProtocol(Protocol):
    """Minimal protocol for exchanging a RT into a Graph-audience access token."""

    def refresh_access_token(
        self,
        mailbox: Mailbox,
        refresh_token: str,
        *,
        scope: str | None = None,
    ) -> MicrosoftTokenResponse:
        """Return a Microsoft token response, optionally scoped to a resource audience."""


class MailboxCapabilityProbeService:
    """Probe IMAP then Graph (or reverse) and persist a conservative capability label."""

    def __init__(
        self,
        settings: Settings,
        imap_client: MicrosoftIMAPClient,
        graph_client: MicrosoftGraphMailProbeClient,
        oauth_client: GraphAudienceTokenExchangerProtocol | None = None,
    ) -> None:
        self._imap_client = imap_client
        self._graph_client = graph_client
        self._oauth_client = oauth_client

    def probe_mailbox_capability(
        self,
        mailbox: Mailbox,
        access_token: str,
        *,
        refresh_token: str | None = None,
    ) -> CapabilityProbeResult:
        """Prefer the channel hinted by scope, stop on first success, otherwise try the alternate.

        When Graph fails with auth against the provided (often outlook-audience) AT and a
        refresh token is available, re-exchange for a Graph-audience AT and probe once more.
        Successful re-audience material is returned so callers can persist it as the cached AT.
        """
        preference = infer_mail_access_channel_preference(mailbox.scope)
        preferred_channel = preference[0]
        outcomes: list[ChannelProbeOutcome] = []
        access_token_replacement: CapabilityProbeAccessTokenReplacement | None = None
        active_access_token = access_token

        for channel in preference:
            if channel == "graph":
                outcome, replacement = self._probe_graph_with_optional_reaudience(
                    mailbox,
                    active_access_token,
                    refresh_token=refresh_token,
                )
                outcomes.append(outcome)
                if replacement is not None:
                    access_token_replacement = replacement
                    active_access_token = replacement.access_token
            else:
                outcome = self._probe_imap(mailbox, active_access_token)
                outcomes.append(outcome)

            if outcome.kind == ProbeOutcomeKind.SUCCESS:
                capability = MailboxCapability.IMAP if channel == "imap" else MailboxCapability.GRAPH
                return CapabilityProbeResult(
                    capability=capability,
                    preferred_channel=preferred_channel,
                    probe_error=None,
                    outcomes=tuple(outcomes),
                    access_token_replacement=access_token_replacement,
                )

        capability, probe_error = self._decide_failure(outcomes)
        return CapabilityProbeResult(
            capability=capability,
            preferred_channel=preferred_channel,
            probe_error=probe_error,
            outcomes=tuple(outcomes),
            access_token_replacement=access_token_replacement,
        )

    def _probe_graph_with_optional_reaudience(
        self,
        mailbox: Mailbox,
        access_token: str,
        *,
        refresh_token: str | None,
    ) -> tuple[ChannelProbeOutcome, CapabilityProbeAccessTokenReplacement | None]:
        """Probe Graph; on auth failure, try one Graph-audience RT exchange when possible."""
        first_outcome = self._graph_client.probe_messages_access(mailbox, access_token)
        if first_outcome.kind != ProbeOutcomeKind.AUTH_FAILED:
            return first_outcome, None
        if self._oauth_client is None or not refresh_token or not mailbox.client_id:
            return first_outcome, None
        if self._scope_already_hints_graph_audience(mailbox.scope):
            # Scope already claims Graph; another re-audience exchange is unlikely to help.
            return first_outcome, None

        try:
            token_response = self._oauth_client.refresh_access_token(
                mailbox,
                refresh_token,
                scope=GRAPH_MAIL_READ_SCOPE,
            )
        except MicrosoftOAuthError as error:
            return (
                ChannelProbeOutcome(
                    channel="graph",
                    kind=ProbeOutcomeKind.AUTH_FAILED,
                    error_summary=(
                        f"{first_outcome.error_summary or 'auth_failed'}；"
                        f"graph_reaudience:{summarize_exception(error)}"
                    ),
                ),
                None,
            )
        except EgressProxyTransportError as error:
            return (
                ChannelProbeOutcome(
                    channel="graph",
                    kind=ProbeOutcomeKind.TRANSPORT_FAILED,
                    error_summary=(
                        f"{first_outcome.error_summary or 'auth_failed'}；"
                        f"graph_reaudience:{str(error)}"
                    ),
                ),
                None,
            )

        replacement = CapabilityProbeAccessTokenReplacement(
            access_token=token_response.access_token,
            expires_in=token_response.expires_in,
            scope=token_response.scope,
            rotated_refresh_token=token_response.rotated_refresh_token,
        )
        second_outcome = self._graph_client.probe_messages_access(mailbox, replacement.access_token)
        if second_outcome.kind == ProbeOutcomeKind.SUCCESS:
            return second_outcome, replacement

        combined_error = "；".join(
            part
            for part in (
                first_outcome.error_summary,
                f"graph_reaudience:{second_outcome.error_summary or second_outcome.kind.value}",
            )
            if part
        )
        return (
            ChannelProbeOutcome(
                channel="graph",
                kind=second_outcome.kind,
                error_summary=combined_error or second_outcome.error_summary,
            ),
            None,
        )

    @staticmethod
    def _scope_already_hints_graph_audience(scope: str | None) -> bool:
        """Return True when the stored scope already looks like a Graph resource token."""
        normalized_scope = (scope or "").casefold()
        return "graph.microsoft.com" in normalized_scope

    def _probe_imap(self, mailbox: Mailbox, access_token: str) -> ChannelProbeOutcome:
        try:
            client = self._imap_client.connect(mailbox, access_token)
        except EgressProxyTransportError as error:
            logger.warning(
                "microsoft_imap_probe_failed mailbox_id=%s primary_email=%s "
                "reason=proxy_transport error=%s",
                mailbox.id,
                mailbox.primary_email,
                summarize_exception(error),
            )
            return ChannelProbeOutcome(
                channel="imap",
                kind=ProbeOutcomeKind.TRANSPORT_FAILED,
                error_summary=str(error),
            )
        except imaplib.IMAP4.error as error:
            logger.warning(
                "microsoft_imap_probe_failed mailbox_id=%s primary_email=%s "
                "reason=auth_or_protocol error=%s",
                mailbox.id,
                mailbox.primary_email,
                summarize_exception(error),
            )
            return ChannelProbeOutcome(
                channel="imap",
                kind=ProbeOutcomeKind.AUTH_FAILED,
                error_summary=summarize_exception(error),
            )
        except OSError as error:
            logger.warning(
                "microsoft_imap_probe_failed mailbox_id=%s primary_email=%s "
                "reason=transport error=%s",
                mailbox.id,
                mailbox.primary_email,
                summarize_exception(error),
            )
            return ChannelProbeOutcome(
                channel="imap",
                kind=ProbeOutcomeKind.TRANSPORT_FAILED,
                error_summary=summarize_exception(error),
            )
        except Exception as error:  # noqa: BLE001 - probe must classify unexpected failures.
            # Programming/runtime defects are not auth failures; keep capability as unknown.
            logger.warning(
                "microsoft_imap_probe_failed mailbox_id=%s primary_email=%s "
                "reason=unexpected error=%s",
                mailbox.id,
                mailbox.primary_email,
                summarize_exception(error),
            )
            return ChannelProbeOutcome(
                channel="imap",
                kind=ProbeOutcomeKind.TRANSPORT_FAILED,
                error_summary=summarize_exception(error),
            )

        try:
            client.logout()
        except Exception:  # noqa: BLE001 - logout failures must not overturn a successful AUTH.
            pass
        return ChannelProbeOutcome(channel="imap", kind=ProbeOutcomeKind.SUCCESS)

    @staticmethod
    def _decide_failure(outcomes: list[ChannelProbeOutcome]) -> tuple[MailboxCapability, str]:
        """Map dual-channel failure into unusable vs unknown with a compact error summary."""
        auth_failures = [item for item in outcomes if item.kind == ProbeOutcomeKind.AUTH_FAILED]
        transport_failures = [item for item in outcomes if item.kind == ProbeOutcomeKind.TRANSPORT_FAILED]

        if len(auth_failures) == len(outcomes) and outcomes:
            summary = "；".join(
                f"{item.channel}:{item.error_summary or 'auth_failed'}" for item in auth_failures
            )
            return MailboxCapability.UNUSABLE, summary[:500]

        if transport_failures and not auth_failures:
            summary = "；".join(
                f"{item.channel}:{item.error_summary or 'transport_failed'}" for item in transport_failures
            )
            return MailboxCapability.UNKNOWN, summary[:500]

        summary_parts = [
            f"{item.channel}:{item.kind.value}:{item.error_summary or 'failed'}" for item in outcomes
        ]
        # Mixed auth + transport means we cannot claim a usable channel; keep unknown for ops retry.
        if auth_failures and transport_failures:
            return MailboxCapability.UNKNOWN, "；".join(summary_parts)[:500]
        return MailboxCapability.UNUSABLE, "；".join(summary_parts)[:500]


def apply_capability_probe_result(mailbox: Mailbox, result: CapabilityProbeResult) -> None:
    """Write probe metadata onto a mailbox row without committing the session."""
    mailbox.capability = result.capability
    mailbox.capability_probed_at = utc_now()
    mailbox.capability_probe_error = result.probe_error
    mailbox.updated_at = mailbox.capability_probed_at


def _summarize_graph_probe_error(response: httpx.Response) -> str:
    """Return a truncated Graph probe error summary safe for operational logs."""
    try:
        payload = response.json()
    except ValueError:
        body_preview = summarize_text(response.text, maximum_length=200)
        return body_preview or f"empty_body status={response.status_code}"
    microsoft_error = summarize_microsoft_error_payload(payload)
    if microsoft_error:
        return microsoft_error
    return f"unparsed_error status={response.status_code}"
