"""Sticky proxy selection, health tracking, and OAuth/IMAP transports."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
import imaplib
import json
import logging
import socket
import ssl
import time
from typing import Any, TypeVar
from urllib.parse import quote

import httpx
import socks
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session, sessionmaker

from mailbox_service.config import Settings
from mailbox_service.models import (
    AuditLog,
    EgressProxy,
    EgressProxyProtocol,
    EgressProxyStatus,
    Mailbox,
    ProxyHealthEvent,
    ProxyPolicy,
    ensure_utc,
    utc_now,
)
from mailbox_service.security import (
    CredentialCipher,
    summarize_exception,
    summarize_microsoft_error_payload,
    summarize_text,
)

# Prefer uvicorn's error logger so remote-mail diagnostics appear in process stdout / docker logs.
logger = logging.getLogger("uvicorn.error")

class NoHealthyEgressProxyError(RuntimeError):
    """Raised when policy forbids direct routing and no usable proxy exists."""

    error_code = "NO_HEALTHY_EGRESS_PROXY"

class EgressProxyTransportError(RuntimeError):
    """A proxy-chain failure that may safely trigger a single failover retry."""

class MicrosoftOAuthError(RuntimeError):
    """A Microsoft token endpoint error unrelated to local proxy health."""

class MicrosoftInvalidGrantError(MicrosoftOAuthError):
    """An unrecoverable refresh-token failure returned by Microsoft."""

@dataclass(frozen=True)
class ResolvedProxy:
    """In-memory connection data. Its representation never includes credentials."""

    id: str
    protocol: EgressProxyProtocol
    host: str
    port: int
    username: str | None = field(repr=False)
    password: str | None = field(repr=False)

    def as_httpx_proxy_url(self) -> str:
        """Build an HTTPX-compatible URL with safely encoded credentials."""
        scheme = "http" if self.protocol == EgressProxyProtocol.HTTP_CONNECT else "socks5"
        credentials = ""
        if self.username is not None:
            encoded_username = quote(self.username, safe="")
            encoded_password = quote(self.password or "", safe="")
            credentials = f"{encoded_username}:{encoded_password}@"
        return f"{scheme}://{credentials}{self.host}:{self.port}"

    def describe_for_log(self) -> str:
        """Return a credential-free proxy identity for operational logs."""
        return f"id={self.id} protocol={self.protocol.value} endpoint={self.host}:{self.port}"


def describe_proxy_for_log(selected_proxy: ResolvedProxy | None) -> str:
    """Format optional sticky proxy context without credentials."""
    if selected_proxy is None:
        return "direct"
    return selected_proxy.describe_for_log()

@dataclass(frozen=True)
class MicrosoftTokenResponse:
    """Sanitized Microsoft token response for internal credential services only."""

    access_token: str = field(repr=False)
    expires_in: int
    rotated_refresh_token: str | None = field(default=None, repr=False)
    scope: str | None = None

@dataclass(frozen=True)
class ProxyObservation:
    """Detached proxy health observation recorded after network I/O."""

    proxy_id: str
    outcome: str
    observed_at: object
    operation_id: str | None = None
    latency_ms: int | None = None
    error_summary: str | None = None
    actor_type: str = "system"
    actor_id: str | None = None


class EgressProxyService:
    """Own proxy lifecycle, sticky mailbox assignments, and health transitions.

    Prefer constructing with ``session_factory`` so resolve/observation each own a
    short Unit of Work. A request-scoped ``session`` remains supported for admin CRUD.
    """

    def __init__(
        self,
        session: Session | None = None,
        settings: Settings | None = None,
        credential_cipher: CredentialCipher | None = None,
        *,
        session_factory: sessionmaker[Session] | None = None,
    ) -> None:
        if settings is None:
            raise TypeError("settings is required")
        if session is None and session_factory is None:
            raise TypeError("session or session_factory is required")
        self._session = session
        self._session_factory = session_factory
        self._settings = settings
        self._credential_cipher = credential_cipher

    def _open_session(self) -> Session:
        if self._session is not None:
            return self._session
        assert self._session_factory is not None
        return self._session_factory()

    def _owns_short_transactions(self) -> bool:
        return self._session_factory is not None and self._session is None

    def ensure_policy(self) -> ProxyPolicy:
        """Load or create the singleton policy using environment defaults."""
        if self._session is None:
            raise RuntimeError("ensure_policy requires an active session")
        policy = self._session.get(ProxyPolicy, 1)
        if policy is not None:
            return policy

        policy = ProxyPolicy(
            id=1,
            enabled=self._settings.proxy_enabled,
            required=self._settings.proxy_required,
            allowed_protocols=[
                EgressProxyProtocol.HTTP_CONNECT.value,
                EgressProxyProtocol.SOCKS5.value,
            ],
            connect_timeout_seconds=int(self._settings.proxy_connect_timeout_seconds),
            read_timeout_seconds=int(self._settings.proxy_read_timeout_seconds),
            failure_threshold=self._settings.proxy_failure_threshold,
            cooldown_seconds=self._settings.proxy_cooldown_seconds,
            switch_minimum_interval_seconds=self._settings.proxy_switch_minimum_interval_seconds,
            allow_direct_development=not self._settings.proxy_required,
        )
        self._session.add(policy)
        self._session.flush()
        return policy

    def resolve_for_mailbox(
        self,
        mailbox_id: str,
        *,
        excluded_proxy_ids: set[str] | frozenset[str] | None = None,
        force_rebind: bool = False,
    ) -> ResolvedProxy | None:
        """Return a sticky healthy proxy or an explicit direct-routing decision.

        When constructed with a session factory, this method owns a short transaction
        that only covers binding selection. Detached ``ResolvedProxy`` is returned so
        callers never hold ORM instances across network I/O.
        """
        excluded = set(excluded_proxy_ids or set())
        if self._owns_short_transactions():
            assert self._session_factory is not None
            with self._session_factory() as session:
                try:
                    resolved = self._resolve_for_mailbox_in_session(
                        session,
                        mailbox_id,
                        excluded_proxy_ids=excluded,
                        force_rebind=force_rebind,
                    )
                    session.commit()
                    return resolved
                except Exception:
                    session.rollback()
                    raise
        assert self._session is not None
        return self._resolve_for_mailbox_in_session(
            self._session,
            mailbox_id,
            excluded_proxy_ids=excluded,
            force_rebind=force_rebind,
        )

    def _resolve_for_mailbox_in_session(
        self,
        session: Session,
        mailbox_id: str,
        *,
        excluded_proxy_ids: set[str],
        force_rebind: bool,
    ) -> ResolvedProxy | None:
        previous_session = self._session
        self._session = session
        try:
            policy = self.ensure_policy()
            if not policy.enabled:
                if policy.required or not policy.allow_direct_development:
                    raise NoHealthyEgressProxyError("代理池已关闭，且当前策略不允许直连")
                return None

            # Sticky reuse: plain read, no FOR UPDATE. Exclusive locks are only needed when
            # rebinding; holding FOR UPDATE on every IMAP/Graph resolve causes 1205 under
            # concurrent verification-code scans (innodb_lock_wait_timeout).
            mailbox = self._load_mailbox_row(mailbox_id, for_update=False)
            current_proxy = self._load_current_proxy(mailbox)
            if (
                not force_rebind
                and current_proxy is not None
                and current_proxy.id not in excluded_proxy_ids
                and self._is_proxy_available(current_proxy, policy)
            ):
                return self._to_resolved_proxy(current_proxy)

            mailbox = self._load_mailbox_row(mailbox_id, for_update=True)
            current_proxy = self._load_current_proxy(mailbox)
            if (
                not force_rebind
                and current_proxy is not None
                and current_proxy.id not in excluded_proxy_ids
                and self._is_proxy_available(current_proxy, policy)
            ):
                # Another writer may have rebound while we decided to reselect; honor sticky.
                return self._to_resolved_proxy(current_proxy)

            selected_proxy = self._select_candidate_with_retry(policy, excluded_proxy_ids)
            if selected_proxy is None:
                if policy.required or not policy.allow_direct_development:
                    raise NoHealthyEgressProxyError("没有可用的全局出口代理")
                self._update_binding(mailbox, None, "direct_routing")
                return None

            self._update_binding(mailbox, selected_proxy, "automatic_failover")
            return self._to_resolved_proxy(selected_proxy)
        finally:
            self._session = previous_session

    def record_proxy_observation(self, observation: ProxyObservation) -> bool:
        """Persist a proxy health observation in an independent short transaction."""
        from datetime import datetime as datetime_type
        import uuid as uuid_module

        observed_at = observation.observed_at
        if not isinstance(observed_at, datetime_type):
            observed_at = utc_now()
        operation_id = observation.operation_id or str(uuid_module.uuid4())

        def _apply(session: Session) -> bool:
            proxy = session.get(EgressProxy, observation.proxy_id, with_for_update=True)
            if proxy is None:
                return False
            if proxy.last_observed_at is not None and ensure_utc(proxy.last_observed_at) > ensure_utc(observed_at):
                return False
            if observation.outcome == "success":
                proxy.status = EgressProxyStatus.HEALTHY
                proxy.consecutive_failure_count = 0
                proxy.cooldown_until = None
                proxy.last_error_summary = None
                proxy.last_success_at = observed_at
            else:
                policy = session.get(ProxyPolicy, 1)
                failure_threshold = (
                    policy.failure_threshold if policy is not None else self._settings.proxy_failure_threshold
                )
                cooldown_seconds = (
                    policy.cooldown_seconds if policy is not None else self._settings.proxy_cooldown_seconds
                )
                proxy.consecutive_failure_count += 1
                proxy.last_failure_at = observed_at
                proxy.last_error_summary = observation.error_summary
                if proxy.consecutive_failure_count >= failure_threshold:
                    proxy.status = EgressProxyStatus.COOLDOWN
                    from datetime import timedelta
                    proxy.cooldown_until = observed_at + timedelta(seconds=cooldown_seconds)
                else:
                    proxy.status = EgressProxyStatus.UNKNOWN
            proxy.last_observed_at = observed_at
            proxy.health_version = int(proxy.health_version or 0) + 1
            session.add(
                ProxyHealthEvent(
                    operation_id=operation_id,
                    proxy_id=proxy.id,
                    outcome=observation.outcome,
                    observed_at=observed_at,
                    latency_ms=observation.latency_ms,
                    error_summary=observation.error_summary,
                )
            )
            session.add(
                AuditLog(
                    actor_type=observation.actor_type,
                    actor_id=observation.actor_id,
                    event_type=f"egress_proxy.{observation.outcome}",
                    target_type="egress_proxy",
                    target_id=proxy.id,
                    operation_id=operation_id,
                    metadata_json={
                        "failure_count": proxy.consecutive_failure_count,
                        "latency_ms": observation.latency_ms,
                    },
                )
            )
            return True

        if self._owns_short_transactions():
            assert self._session_factory is not None
            with self._session_factory() as session:
                try:
                    applied = _apply(session)
                    session.commit()
                    return applied
                except Exception:
                    session.rollback()
                    raise
        assert self._session is not None
        return _apply(self._session)

    def bind_mailbox_to_proxy(
        self,
        mailbox_id: str,
        proxy_id: str | None,
        *,
        reason: str = "manual_rebind",
    ) -> None:
        """Apply an administrator-requested binding after checking availability."""
        mailbox = self._load_locked_mailbox(mailbox_id)
        policy = self.ensure_policy()
        proxy = None
        if proxy_id is not None:
            proxy = self._session.get(EgressProxy, proxy_id)
            if proxy is None:
                raise LookupError("出口代理不存在")
            if not self._is_proxy_available(proxy, policy):
                raise ValueError("出口代理当前不可用")
        elif policy.required:
            raise ValueError("强制代理策略下不允许解除代理绑定")
        self._update_binding(mailbox, proxy, reason)

    def record_proxy_success(self, proxy_id: str) -> None:
        """Clear transient health state after a successful proxied operation."""
        self.record_proxy_observation(
            ProxyObservation(
                proxy_id=proxy_id,
                outcome="success",
                observed_at=utc_now(),
            )
        )

    def record_proxy_failure(self, proxy_id: str, error: Exception) -> None:
        """Track only proxy-chain failures and enter cooldown at the policy threshold."""
        self.record_proxy_observation(
            ProxyObservation(
                proxy_id=proxy_id,
                outcome="failure",
                observed_at=utc_now(),
                error_summary=summarize_exception(error),
            )
        )

    def recover_proxy(self, proxy_id: str) -> EgressProxy:
        """Explicitly clear cooldown after an operator has repaired a proxy."""
        proxy = self._session.get(EgressProxy, proxy_id, with_for_update=True)
        if proxy is None:
            raise LookupError("出口代理不存在")
        proxy.status = EgressProxyStatus.UNKNOWN
        proxy.consecutive_failure_count = 0
        proxy.cooldown_until = None
        proxy.last_error_summary = None
        self._audit("egress_proxy.recovered", "egress_proxy", proxy.id, {})
        return proxy

    def test_proxy_connectivity(self, proxy_id: str) -> None:
        """Perform a bounded proxy handshake without reading any Microsoft response."""
        proxy = self._session.get(EgressProxy, proxy_id)
        if proxy is None:
            raise LookupError("出口代理不存在")

        resolved_proxy = self._to_resolved_proxy(proxy)
        try:
            proxy_socket = self._open_proxy_socket(
                resolved_proxy,
                "login.microsoftonline.com",
                443,
                self.ensure_policy().connect_timeout_seconds,
            )
        except (socks.ProxyError, OSError, TimeoutError) as error:
            logger.warning(
                "egress_proxy_connectivity_failed proxy=%s target=login.microsoftonline.com:443 error=%s",
                resolved_proxy.describe_for_log(),
                summarize_exception(error),
            )
            raise EgressProxyTransportError("代理握手失败") from error
        try:
            proxy_socket.close()
        except OSError:
            pass
        self.record_proxy_success(proxy.id)
        self._audit("egress_proxy.connectivity_tested", "egress_proxy", proxy.id, {"successful": True})

    def _load_locked_mailbox(self, mailbox_id: str) -> Mailbox:
        return self._load_mailbox_row(mailbox_id, for_update=True)

    def _load_mailbox_row(self, mailbox_id: str, *, for_update: bool) -> Mailbox:
        query = select(Mailbox).where(Mailbox.id == mailbox_id)
        if for_update:
            query = query.with_for_update()
        mailbox = self._session.scalar(query)
        if mailbox is None:
            raise LookupError("邮箱不存在")
        return mailbox

    def _load_current_proxy(self, mailbox: Mailbox) -> EgressProxy | None:
        if mailbox.egress_proxy_id is None:
            return None
        return self._session.get(EgressProxy, mailbox.egress_proxy_id)

    def _select_candidate_with_retry(
        self,
        policy: ProxyPolicy,
        excluded_proxy_ids: set[str],
    ) -> EgressProxy | None:
        """Retry brief SKIP LOCKED contention instead of failing the whole mailbox."""
        # Concurrent batch recognition can momentarily lock every healthy proxy row while
        # another worker is still binding. Wait a few short intervals before giving up.
        max_attempts = 8
        for attempt_index in range(max_attempts):
            selected_proxy = self._select_candidate(policy, excluded_proxy_ids)
            if selected_proxy is not None:
                return selected_proxy
            if attempt_index + 1 >= max_attempts:
                break
            # Exponential-ish backoff: 20ms, 40ms, 80ms... capped.
            time.sleep(min(0.02 * (2**attempt_index), 0.25))
        return None

    def _select_candidate(
        self,
        policy: ProxyPolicy,
        excluded_proxy_ids: set[str],
    ) -> EgressProxy | None:
        """Pick one available proxy without monopolizing the rest of the pool.

        MySQL InnoDB can lock more than one index record when ``FOR UPDATE`` is combined
        with ``ORDER BY`` on a secondary index (gap / supremum locks). Loading every
        candidate with ``FOR UPDATE SKIP LOCKED`` is worse: the first concurrent worker
        holds the entire pool until its long OAuth transaction commits, and sibling
        workers immediately observe an empty set → ``NoHealthyEgressProxyError``.

        Strategy: rank candidate IDs without locking, then lock **one primary key at a
        time** with ``SKIP LOCKED`` so each concurrent worker claims a different proxy.
        Callers must commit soon after binding so those row locks are not held across
        multi-second Microsoft network calls.
        """
        now = utc_now()
        bound_mailbox_count = (
            select(func.count(Mailbox.id))
            .where(Mailbox.egress_proxy_id == EgressProxy.id)
            .correlate(EgressProxy)
            .scalar_subquery()
        )
        candidate_proxy_ids = list(
            self._session.scalars(
                select(EgressProxy.id)
                .where(EgressProxy.enabled.is_(True))
                .where(EgressProxy.protocol.in_(policy.allowed_protocols))
                .where(
                    (EgressProxy.status != EgressProxyStatus.COOLDOWN)
                    | (EgressProxy.cooldown_until.is_(None))
                    | (EgressProxy.cooldown_until <= now)
                )
                .where(EgressProxy.id.not_in(excluded_proxy_ids) if excluded_proxy_ids else True)
                .order_by(EgressProxy.priority.asc(), bound_mailbox_count.asc(), EgressProxy.id.asc())
            )
        )

        selected_proxy: EgressProxy | None = None
        for proxy_id in candidate_proxy_ids:
            locked_proxy = self._session.scalar(
                select(EgressProxy)
                .where(EgressProxy.id == proxy_id)
                .with_for_update(skip_locked=True)
            )
            if locked_proxy is None:
                continue
            if not self._is_proxy_available(locked_proxy, policy):
                continue
            selected_proxy = locked_proxy
            break

        if selected_proxy is None:
            return None

        if selected_proxy.status == EgressProxyStatus.COOLDOWN:
            selected_proxy.status = EgressProxyStatus.UNKNOWN
            selected_proxy.cooldown_until = None
        return selected_proxy

    def _is_proxy_available(self, proxy: EgressProxy, policy: ProxyPolicy) -> bool:
        if not proxy.enabled or proxy.protocol.value not in policy.allowed_protocols:
            return False
        if proxy.status != EgressProxyStatus.COOLDOWN:
            return True
        return proxy.cooldown_until is not None and proxy.cooldown_until <= utc_now()

    def _update_binding(
        self,
        mailbox: Mailbox,
        selected_proxy: EgressProxy | None,
        reason: str,
    ) -> None:
        previous_proxy_id = mailbox.egress_proxy_id
        new_proxy_id = selected_proxy.id if selected_proxy is not None else None
        if previous_proxy_id == new_proxy_id:
            return

        current_time = utc_now()
        mailbox.egress_proxy_id = new_proxy_id
        mailbox.proxy_bound_at = current_time if new_proxy_id is not None else None
        mailbox.proxy_last_switch_at = current_time
        self._audit(
            "mailbox.egress_proxy_changed",
            "mailbox",
            mailbox.id,
            {
                "previous_proxy_id": previous_proxy_id,
                "new_proxy_id": new_proxy_id,
                "reason": reason,
            },
        )

    def _to_resolved_proxy(self, proxy: EgressProxy) -> ResolvedProxy:
        username = self._decrypt_optional(proxy.username_ciphertext)
        password = self._decrypt_optional(proxy.password_ciphertext)
        return ResolvedProxy(
            id=proxy.id,
            protocol=proxy.protocol,
            host=proxy.host,
            port=proxy.port,
            username=username,
            password=password,
        )

    def _decrypt_optional(self, ciphertext: str | None) -> str | None:
        if ciphertext is None:
            return None
        if self._credential_cipher is None:
            raise RuntimeError("未配置 credential_encryption_key，无法使用代理凭证")
        return self._credential_cipher.decrypt(ciphertext)

    @staticmethod
    def _open_proxy_socket(
        proxy: ResolvedProxy,
        destination_host: str,
        destination_port: int,
        timeout_seconds: float,
    ) -> socket.socket:
        proxy_type = (
            socks.PROXY_TYPE_HTTP
            if proxy.protocol == EgressProxyProtocol.HTTP_CONNECT
            else socks.PROXY_TYPE_SOCKS5
        )
        return socks.create_connection(
            (destination_host, destination_port),
            timeout=timeout_seconds,
            proxy_type=proxy_type,
            proxy_addr=proxy.host,
            proxy_port=proxy.port,
            proxy_username=proxy.username,
            proxy_password=proxy.password,
            proxy_rdns=proxy.protocol == EgressProxyProtocol.SOCKS5,
        )

    def _audit(
        self,
        event_type: str,
        target_type: str,
        target_id: str | None,
        metadata: dict[str, Any],
    ) -> None:
        self._session.add(
            AuditLog(
                actor_type="system",
                actor_id=None,
                event_type=event_type,
                target_type=target_type,
                target_id=target_id,
                metadata_json=metadata,
            )
        )

OperationResult = TypeVar("OperationResult")

class MicrosoftOAuthClient:
    """Refresh Microsoft tokens with sticky proxy routing and one failover retry."""

    def __init__(self, proxy_service: EgressProxyService, settings: Settings) -> None:
        self._proxy_service = proxy_service
        self._settings = settings

    def refresh_access_token(
        self,
        mailbox: Mailbox,
        refresh_token: str,
        *,
        scope: str | None = None,
    ) -> MicrosoftTokenResponse:
        """Exchange a mailbox refresh token without exposing it in diagnostics.

        When ``scope`` is provided (for example Graph ``Mail.Read``), Microsoft issues an
        access token for that resource audience instead of the RT's default outlook scopes.
        """
        return self._execute_with_proxy_retry(
            mailbox.id,
            lambda selected_proxy: self._request_access_token(
                mailbox,
                refresh_token,
                selected_proxy,
                scope=scope,
            ),
        )

    def _request_access_token(
        self,
        mailbox: Mailbox,
        refresh_token: str,
        selected_proxy: ResolvedProxy | None,
        *,
        scope: str | None = None,
    ) -> MicrosoftTokenResponse:
        proxy_url = selected_proxy.as_httpx_proxy_url() if selected_proxy is not None else None
        proxy_description = describe_proxy_for_log(selected_proxy)
        timeout = httpx.Timeout(
            connect=self._settings.proxy_connect_timeout_seconds,
            read=self._settings.proxy_read_timeout_seconds,
            write=self._settings.proxy_read_timeout_seconds,
            pool=self._settings.proxy_connect_timeout_seconds,
        )
        request_form: dict[str, str] = {
            "grant_type": "refresh_token",
            "client_id": mailbox.client_id or "",
            "refresh_token": refresh_token,
        }
        if scope:
            request_form["scope"] = scope
        try:
            with httpx.Client(proxy=proxy_url, timeout=timeout) as client:
                response = client.post(
                    self._settings.microsoft_token_endpoint,
                    data=request_form,
                )
        except (httpx.ProxyError, httpx.ConnectTimeout, httpx.ReadTimeout) as error:
            logger.warning(
                "microsoft_oauth_transport_failed mailbox_id=%s primary_email=%s "
                "proxy=%s scope=%s reason=proxy_chain error=%s",
                mailbox.id,
                mailbox.primary_email,
                proxy_description,
                scope or "default",
                summarize_exception(error),
            )
            raise EgressProxyTransportError("OAuth 代理链路不可用") from error
        except httpx.ConnectError as error:
            if selected_proxy is not None:
                logger.warning(
                    "microsoft_oauth_transport_failed mailbox_id=%s primary_email=%s "
                    "proxy=%s scope=%s reason=proxy_connect error=%s",
                    mailbox.id,
                    mailbox.primary_email,
                    proxy_description,
                    scope or "default",
                    summarize_exception(error),
                )
                raise EgressProxyTransportError("OAuth 代理连接失败") from error
            logger.warning(
                "microsoft_oauth_request_failed mailbox_id=%s primary_email=%s "
                "proxy=%s scope=%s reason=connect error=%s",
                mailbox.id,
                mailbox.primary_email,
                proxy_description,
                scope or "default",
                summarize_exception(error),
            )
            raise MicrosoftOAuthError("无法连接 Microsoft Token 服务") from error

        if response.status_code >= 400:
            payload = self._safe_json(response)
            microsoft_error = summarize_microsoft_error_payload(payload)
            if payload.get("error") == "invalid_grant":
                logger.warning(
                    "microsoft_oauth_invalid_grant mailbox_id=%s primary_email=%s "
                    "proxy=%s scope=%s http_status=%s microsoft=%s",
                    mailbox.id,
                    mailbox.primary_email,
                    proxy_description,
                    scope or "default",
                    response.status_code,
                    microsoft_error or "error=invalid_grant",
                )
                raise MicrosoftInvalidGrantError("Microsoft 拒绝 refresh token")
            logger.warning(
                "microsoft_oauth_request_failed mailbox_id=%s primary_email=%s "
                "proxy=%s scope=%s reason=http_status http_status=%s microsoft=%s",
                mailbox.id,
                mailbox.primary_email,
                proxy_description,
                scope or "default",
                response.status_code,
                microsoft_error or f"empty_body status={response.status_code}",
            )
            raise MicrosoftOAuthError(f"Microsoft Token 请求失败，HTTP {response.status_code}")
        payload = self._safe_json(response)
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            logger.warning(
                "microsoft_oauth_request_failed mailbox_id=%s primary_email=%s "
                "proxy=%s scope=%s reason=missing_access_token http_status=%s",
                mailbox.id,
                mailbox.primary_email,
                proxy_description,
                scope or "default",
                response.status_code,
            )
            raise MicrosoftOAuthError("Microsoft Token 响应缺少 access_token")
        expires_in = payload.get("expires_in", 0)
        if not isinstance(expires_in, int):
            logger.warning(
                "microsoft_oauth_request_failed mailbox_id=%s primary_email=%s "
                "proxy=%s scope=%s reason=invalid_expires_in http_status=%s",
                mailbox.id,
                mailbox.primary_email,
                proxy_description,
                scope or "default",
                response.status_code,
            )
            raise MicrosoftOAuthError("Microsoft Token 响应包含无效 expires_in")
        rotated_refresh_token = payload.get("refresh_token")
        scope_value = payload.get("scope")
        return MicrosoftTokenResponse(
            access_token=access_token,
            expires_in=expires_in,
            rotated_refresh_token=rotated_refresh_token if isinstance(rotated_refresh_token, str) else None,
            scope=scope_value.strip() if isinstance(scope_value, str) and scope_value.strip() else None,
        )

    def _execute_with_proxy_retry(
        self,
        mailbox_id: str,
        operation: Callable[[ResolvedProxy | None], OperationResult],
    ) -> OperationResult:
        # resolve_for_mailbox owns a short transaction when session_factory is used.
        selected_proxy = self._proxy_service.resolve_for_mailbox(mailbox_id)
        try:
            result = operation(selected_proxy)
        except EgressProxyTransportError as error:
            if selected_proxy is None:
                raise
            logger.warning(
                "microsoft_oauth_proxy_failover mailbox_id=%s failed_proxy=%s error=%s",
                mailbox_id,
                describe_proxy_for_log(selected_proxy),
                summarize_exception(error),
            )
            self._proxy_service.record_proxy_failure(selected_proxy.id, error)
            replacement_proxy = self._proxy_service.resolve_for_mailbox(
                mailbox_id,
                excluded_proxy_ids={selected_proxy.id},
                force_rebind=True,
            )
            try:
                result = operation(replacement_proxy)
            except Exception as retry_error:
                logger.warning(
                    "microsoft_oauth_proxy_failover_failed mailbox_id=%s "
                    "failed_proxy=%s replacement_proxy=%s error=%s",
                    mailbox_id,
                    describe_proxy_for_log(selected_proxy),
                    describe_proxy_for_log(replacement_proxy),
                    summarize_exception(retry_error),
                )
                raise
            if replacement_proxy is not None:
                self._proxy_service.record_proxy_success(replacement_proxy.id)
            return result

        if selected_proxy is not None:
            self._proxy_service.record_proxy_success(selected_proxy.id)
        return result

    @staticmethod
    def _safe_json(response: httpx.Response) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError as error:
            body_preview = summarize_text(response.text, maximum_length=200)
            logger.warning(
                "microsoft_oauth_request_failed reason=non_json_response "
                "http_status=%s body_preview=%s",
                response.status_code,
                body_preview or "<empty>",
            )
            raise MicrosoftOAuthError("Microsoft Token 响应不是 JSON") from error
        return payload if isinstance(payload, dict) else {}

class ProxyIMAP4SSL(imaplib.IMAP4_SSL):
    """IMAP4 SSL client that wraps a pre-connected direct or proxied socket."""

    def __init__(
        self,
        connected_socket: socket.socket,
        server_hostname: str,
        timeout_seconds: float,
    ) -> None:
        self._connected_socket = connected_socket
        self._server_hostname = server_hostname
        self._timeout_seconds = timeout_seconds
        super().__init__(host=server_hostname, port=993, timeout=timeout_seconds)

    def open(self, host: str, port: int, timeout: float | None = None) -> None:
        """Use the prepared socket instead of opening a direct TCP connection.

        CPython versions differ on the makefile handle attribute:

        - Python <= 3.13: ``imaplib`` reads/writes ``self.file``
        - Python 3.14+: ``file`` is a read-only property backed by ``self._file``

        Always populate ``_file``. Also set ``file`` when it is a plain attribute so
        production images on 3.12 do not fall through IMAP4.__getattr__ and raise
        ``Unknown IMAP4 command: 'file'`` during AUTHENTICATE.
        """
        ssl_context = ssl.create_default_context()
        self.sock = ssl_context.wrap_socket(self._connected_socket, server_hostname=self._server_hostname)
        self.sock.settimeout(timeout or self._timeout_seconds)
        makefile_stream = self.sock.makefile("rb")
        self._file = makefile_stream
        file_descriptor = getattr(type(self), "file", None)
        if not isinstance(file_descriptor, property):
            self.file = makefile_stream

class MicrosoftIMAPClient:
    """Open XOAUTH2 IMAP sessions through the same mailbox proxy resolver."""

    def __init__(self, proxy_service: EgressProxyService, settings: Settings) -> None:
        self._proxy_service = proxy_service
        self._settings = settings

    def connect(self, mailbox: Mailbox, access_token: str) -> imaplib.IMAP4_SSL:
        """Connect and authenticate, failing over once only for proxy-chain errors."""
        selected_proxy = self._proxy_service.resolve_for_mailbox(mailbox.id)
        try:
            client = self._connect_once(
                mailbox.id,
                mailbox.primary_email,
                access_token,
                selected_proxy,
            )
        except EgressProxyTransportError as error:
            if selected_proxy is None:
                raise
            logger.warning(
                "microsoft_imap_proxy_failover mailbox_id=%s primary_email=%s "
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
                client = self._connect_once(
                    mailbox.id,
                    mailbox.primary_email,
                    access_token,
                    replacement_proxy,
                )
            except Exception as retry_error:
                logger.warning(
                    "microsoft_imap_proxy_failover_failed mailbox_id=%s primary_email=%s "
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
            return client

        if selected_proxy is not None:
            self._proxy_service.record_proxy_success(selected_proxy.id)
        return client

    def _connect_once(
        self,
        mailbox_id: str,
        primary_email: str,
        access_token: str,
        selected_proxy: ResolvedProxy | None,
    ) -> imaplib.IMAP4_SSL:
        proxy_description = describe_proxy_for_log(selected_proxy)
        imap_target = f"{self._settings.microsoft_imap_host}:{self._settings.microsoft_imap_port}"
        try:
            if selected_proxy is None:
                connected_socket = socket.create_connection(
                    (self._settings.microsoft_imap_host, self._settings.microsoft_imap_port),
                    timeout=self._settings.proxy_connect_timeout_seconds,
                )
            else:
                connected_socket = EgressProxyService._open_proxy_socket(
                    selected_proxy,
                    self._settings.microsoft_imap_host,
                    self._settings.microsoft_imap_port,
                    self._settings.proxy_connect_timeout_seconds,
                )
            client = ProxyIMAP4SSL(
                connected_socket,
                self._settings.microsoft_imap_host,
                self._settings.proxy_read_timeout_seconds,
            )
            authentication_payload = (
                f"user={primary_email}\x01auth=Bearer {access_token}\x01\x01".encode("utf-8")
            )
            client.authenticate("XOAUTH2", lambda _: authentication_payload)
            return client
        except (socks.ProxyError, socket.timeout, TimeoutError) as error:
            logger.warning(
                "microsoft_imap_connect_failed mailbox_id=%s primary_email=%s "
                "proxy=%s target=%s reason=proxy_chain error=%s",
                mailbox_id,
                primary_email,
                proxy_description,
                imap_target,
                summarize_exception(error),
            )
            raise EgressProxyTransportError("IMAP 代理链路不可用") from error
        except imaplib.IMAP4.error as error:
            logger.warning(
                "microsoft_imap_connect_failed mailbox_id=%s primary_email=%s "
                "proxy=%s target=%s reason=auth_or_protocol error=%s",
                mailbox_id,
                primary_email,
                proxy_description,
                imap_target,
                summarize_exception(error),
            )
            raise
        except OSError as error:
            if selected_proxy is not None:
                logger.warning(
                    "microsoft_imap_connect_failed mailbox_id=%s primary_email=%s "
                    "proxy=%s target=%s reason=proxy_connect error=%s",
                    mailbox_id,
                    primary_email,
                    proxy_description,
                    imap_target,
                    summarize_exception(error),
                )
                raise EgressProxyTransportError("IMAP 代理连接失败") from error
            logger.warning(
                "microsoft_imap_connect_failed mailbox_id=%s primary_email=%s "
                "proxy=%s target=%s reason=direct_connect error=%s",
                mailbox_id,
                primary_email,
                proxy_description,
                imap_target,
                summarize_exception(error),
            )
            raise
