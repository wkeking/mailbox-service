"""Prefer-by-scope runtime probes for IMAP XOAUTH2 and Microsoft Graph mail access."""

from __future__ import annotations

from dataclasses import dataclass
import enum
import imaplib
from typing import Protocol

import httpx

from mailbox_service.access_token_scopes import MailAccessChannel, infer_mail_access_channel_preference
from mailbox_service.config import Settings
from mailbox_service.models import Mailbox, MailboxCapability, utc_now
from mailbox_service.proxy_service import (
    EgressProxyService,
    EgressProxyTransportError,
    MicrosoftIMAPClient,
    ResolvedProxy,
)
from mailbox_service.security import summarize_exception


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
class CapabilityProbeResult:
    """Aggregated capability decision after prefer-by-scope probing."""

    capability: MailboxCapability
    preferred_channel: MailAccessChannel
    probe_error: str | None
    outcomes: tuple[ChannelProbeOutcome, ...]


class MailboxCapabilityProberProtocol(Protocol):
    """Minimal protocol shared by the real prober and test doubles."""

    def probe_mailbox_capability(self, mailbox: Mailbox, access_token: str) -> CapabilityProbeResult:
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
            raise EgressProxyTransportError("Graph 代理链路不可用") from error
        except httpx.ConnectError as error:
            if selected_proxy is not None:
                raise EgressProxyTransportError("Graph 代理连接失败") from error
            return ChannelProbeOutcome(
                channel="graph",
                kind=ProbeOutcomeKind.TRANSPORT_FAILED,
                error_summary="无法连接 Microsoft Graph",
            )

        if response.status_code in {401, 403}:
            return ChannelProbeOutcome(
                channel="graph",
                kind=ProbeOutcomeKind.AUTH_FAILED,
                error_summary=f"Graph 鉴权失败，HTTP {response.status_code}",
            )
        if response.status_code >= 400:
            return ChannelProbeOutcome(
                channel="graph",
                kind=ProbeOutcomeKind.AUTH_FAILED,
                error_summary=f"Graph 探测失败，HTTP {response.status_code}",
            )
        return ChannelProbeOutcome(channel="graph", kind=ProbeOutcomeKind.SUCCESS)


class MailboxCapabilityProbeService:
    """Probe IMAP then Graph (or reverse) and persist a conservative capability label."""

    def __init__(
        self,
        settings: Settings,
        imap_client: MicrosoftIMAPClient,
        graph_client: MicrosoftGraphMailProbeClient,
    ) -> None:
        self._imap_client = imap_client
        self._graph_client = graph_client

    def probe_mailbox_capability(self, mailbox: Mailbox, access_token: str) -> CapabilityProbeResult:
        """Prefer the channel hinted by scope, stop on first success, otherwise try the alternate."""
        preference = infer_mail_access_channel_preference(mailbox.scope)
        preferred_channel = preference[0]
        outcomes: list[ChannelProbeOutcome] = []

        for channel in preference:
            outcome = self._probe_channel(mailbox, access_token, channel)
            outcomes.append(outcome)
            if outcome.kind == ProbeOutcomeKind.SUCCESS:
                capability = MailboxCapability.IMAP if channel == "imap" else MailboxCapability.GRAPH
                return CapabilityProbeResult(
                    capability=capability,
                    preferred_channel=preferred_channel,
                    probe_error=None,
                    outcomes=tuple(outcomes),
                )

        capability, probe_error = self._decide_failure(outcomes)
        return CapabilityProbeResult(
            capability=capability,
            preferred_channel=preferred_channel,
            probe_error=probe_error,
            outcomes=tuple(outcomes),
        )

    def _probe_channel(
        self,
        mailbox: Mailbox,
        access_token: str,
        channel: MailAccessChannel,
    ) -> ChannelProbeOutcome:
        if channel == "graph":
            return self._graph_client.probe_messages_access(mailbox, access_token)
        return self._probe_imap(mailbox, access_token)

    def _probe_imap(self, mailbox: Mailbox, access_token: str) -> ChannelProbeOutcome:
        try:
            client = self._imap_client.connect(mailbox, access_token)
        except EgressProxyTransportError as error:
            return ChannelProbeOutcome(
                channel="imap",
                kind=ProbeOutcomeKind.TRANSPORT_FAILED,
                error_summary=str(error),
            )
        except imaplib.IMAP4.error as error:
            return ChannelProbeOutcome(
                channel="imap",
                kind=ProbeOutcomeKind.AUTH_FAILED,
                error_summary=summarize_exception(error),
            )
        except OSError as error:
            return ChannelProbeOutcome(
                channel="imap",
                kind=ProbeOutcomeKind.TRANSPORT_FAILED,
                error_summary=summarize_exception(error),
            )
        except Exception as error:  # noqa: BLE001 - probe must classify unexpected failures.
            # Programming/runtime defects are not auth failures; keep capability as unknown.
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
