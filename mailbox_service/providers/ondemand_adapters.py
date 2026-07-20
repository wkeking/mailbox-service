"""On-demand HTTP mailbox providers (protocol mirrored from chatgpt2api mail_provider.py).

Each adapter implements provision + message fetch without SQLAlchemy Session access.
"""

from __future__ import annotations

import random
import re
import secrets
import string
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable

from mailbox_service.providers.http_client import HttpxJsonHttpClient, JsonHttpClient, ProviderHttpError
from mailbox_service.providers.ports import (
    InboxMessageEvidence,
    OnDemandProvisionRequest,
    OnDemandProvisionResult,
    VerificationAllocationSnapshot,
    VerificationEvidence,
    VerificationQuery,
)


class OnDemandProviderError(RuntimeError):
    """Raised when an on-demand provider cannot provision or read mail."""


def _random_local_part(length: int = 10) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _random_subdomain_label() -> str:
    return _random_local_part(8)


def _next_domain(domains: list[str]) -> str:
    cleaned = [item.strip() for item in domains if str(item).strip()]
    if not cleaned:
        raise OnDemandProviderError("domain list is empty")
    return random.choice(cleaned)


def _parse_received_at(value: Any) -> datetime | None:
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


def _extract_text_html(item: dict[str, Any]) -> tuple[str, str]:
    text = str(
        item.get("text")
        or item.get("text_content")
        or item.get("content")
        or item.get("body")
        or item.get("intro")
        or ""
    )
    html = item.get("html") or item.get("html_content") or item.get("htmlBody") or ""
    if isinstance(html, list):
        html = "".join(str(part) for part in html)
    html_text = str(html or "")
    if not text and html_text:
        text = re.sub(r"<[^>]+>", " ", html_text)
    return text, html_text


def _sender_of(item: dict[str, Any]) -> str:
    sender = item.get("from") or item.get("sender") or item.get("from_address") or item.get("sendEmail") or ""
    if isinstance(sender, dict):
        sender = sender.get("address") or sender.get("email") or sender.get("name") or ""
    return str(sender or "")


def _message_to_evidence(item: dict[str, Any], *, address: str) -> InboxMessageEvidence:
    text, html = _extract_text_html(item)
    body = text or html
    recipients: set[str] = {address.lower()}
    for key in ("to", "toEmail", "mailTo", "recipient"):
        raw = item.get(key)
        if isinstance(raw, str) and raw.strip():
            recipients.add(raw.strip().lower())
        elif isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, str) and entry.strip():
                    recipients.add(entry.strip().lower())
                elif isinstance(entry, dict):
                    email = entry.get("address") or entry.get("email")
                    if email:
                        recipients.add(str(email).strip().lower())
    return InboxMessageEvidence(
        from_address=_sender_of(item) or None,
        subject=str(item.get("subject") or "") or None,
        body_text=body or None,
        received_at=_parse_received_at(
            item.get("createdAt")
            or item.get("created_at")
            or item.get("receivedAt")
            or item.get("date")
            or item.get("timestamp")
            or item.get("createTime")
        ),
        recipient_addresses=frozenset(recipients),
        channel=None,
    )


def _filter_messages(
    messages: list[InboxMessageEvidence],
    query: VerificationQuery,
) -> tuple[InboxMessageEvidence, ...]:
    results: list[InboxMessageEvidence] = []
    for message in messages:
        if query.from_address and (message.from_address or "").lower().find(query.from_address.lower()) < 0:
            continue
        if query.subject_contains and query.subject_contains.lower() not in (message.subject or "").lower():
            continue
        if query.body_contains and query.body_contains.lower() not in (message.body_text or "").lower():
            continue
        if query.recipient:
            recipient = query.recipient.lower()
            if recipient not in message.recipient_addresses and recipient not in (message.body_text or "").lower():
                continue
        if query.newer_than and message.received_at and message.received_at < query.newer_than:
            continue
        results.append(message)
        if len(results) >= max(query.max_messages, 1):
            break
    return tuple(results)


@dataclass(frozen=True)
class OnDemandRuntimeConfig:
    """Resolved non-DB knobs for one on-demand instance (secrets in plaintext for process use only)."""

    provider_type: str
    instance_id: str
    enabled: bool
    values: dict[str, Any]
    secrets: dict[str, str]
    timeout_seconds: float


class ConfigurableOnDemandAdapter:
    """Base for provision + evidence using runtime config and injectable HTTP client."""

    provider_type: str = "unknown"

    def __init__(
        self,
        runtime: OnDemandRuntimeConfig,
        *,
        http_client: JsonHttpClient | None = None,
    ) -> None:
        self._runtime = runtime
        self._http = http_client or HttpxJsonHttpClient(timeout_seconds=runtime.timeout_seconds)

    def _require_secret(self, key: str) -> str:
        value = (self._runtime.secrets.get(key) or "").strip()
        if not value:
            raise OnDemandProviderError(f"{self.provider_type} missing secret: {key}")
        return value

    def _value(self, key: str, default: Any = None) -> Any:
        if key in self._runtime.values and self._runtime.values[key] not in (None, ""):
            return self._runtime.values[key]
        return default

    def _string_list(self, key: str) -> list[str]:
        raw = self._value(key, [])
        if isinstance(raw, str):
            return [part.strip() for part in re.split(r"[\n,]", raw) if part.strip()]
        if isinstance(raw, list):
            return [str(part).strip() for part in raw if str(part).strip()]
        return []

    def provision(self, request: OnDemandProvisionRequest) -> OnDemandProvisionResult:
        raise NotImplementedError

    def fetch_evidence(
        self,
        allocation: VerificationAllocationSnapshot,
        query: VerificationQuery,
    ) -> VerificationEvidence:
        raise NotImplementedError


class CloudflareTempEmailAdapter(ConfigurableOnDemandAdapter):
    provider_type = "cloudflare_temp_email"

    def provision(self, request: OnDemandProvisionRequest) -> OnDemandProvisionResult:
        api_base = str(self._value("api_base") or "").rstrip("/")
        if not api_base:
            raise OnDemandProviderError("cloudflare_temp_email requires api_base")
        admin_password = self._require_secret("admin_password")
        domain = _next_domain(self._string_list("domain"))
        local_part = request.preferred_local_part or _random_local_part()
        data = self._http.request_json(
            "POST",
            f"{api_base}/admin/new_address",
            headers={"Content-Type": "application/json", "x-admin-auth": admin_password},
            json_body={"enablePrefix": True, "name": local_part, "domain": domain},
        )
        if not isinstance(data, dict):
            raise OnDemandProviderError("cloudflare_temp_email invalid create response")
        address = str(data.get("address") or "").strip()
        token = str(data.get("jwt") or "").strip()
        if not address or not token:
            raise OnDemandProviderError("cloudflare_temp_email missing address or jwt")
        return OnDemandProvisionResult(
            address=address.lower(),
            external_resource_id=address.lower(),
            secret_payload={"token": token, "api_base": api_base},
        )

    def fetch_evidence(
        self,
        allocation: VerificationAllocationSnapshot,
        query: VerificationQuery,
    ) -> VerificationEvidence:
        token = allocation.access_context.get("token") or ""
        api_base = (allocation.access_context.get("api_base") or str(self._value("api_base") or "")).rstrip("/")
        if not token or not api_base:
            raise OnDemandProviderError("cloudflare_temp_email missing token/api_base")
        data = self._http.request_json(
            "GET",
            f"{api_base}/api/mails",
            headers={"Authorization": f"Bearer {token}"},
            params={"limit": 20, "offset": 0},
        )
        raw = list(data.get("results") or []) if isinstance(data, dict) else data if isinstance(data, list) else []
        messages = [
            _message_to_evidence(item, address=allocation.primary_email)
            for item in raw
            if isinstance(item, dict)
        ]
        return VerificationEvidence(
            messages=_filter_messages(messages, query),
            read_method="cloudflare_temp_email",
        )


class TempMailLolAdapter(ConfigurableOnDemandAdapter):
    provider_type = "tempmail_lol"

    def provision(self, request: OnDemandProvisionRequest) -> OnDemandProvisionResult:
        api_key = (self._runtime.secrets.get("api_key") or "").strip()
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        payload: dict[str, Any] = {}
        domains = self._string_list("domain")
        if domains:
            domain = random.choice(domains).lower()
            if domain.startswith("*.") and len(domain) > 2:
                payload["domain"] = f"{_random_subdomain_label()}.{domain[2:]}"
                payload["prefix"] = request.preferred_local_part or _random_local_part()
            else:
                payload["domain"] = domain
                if request.preferred_local_part:
                    payload["prefix"] = request.preferred_local_part
        elif request.preferred_local_part:
            payload["prefix"] = request.preferred_local_part
        data = self._http.request_json(
            "POST",
            "https://api.tempmail.lol/v2/inbox/create",
            headers=headers,
            json_body=payload or None,
            expected_status=(200, 201),
        )
        if not isinstance(data, dict):
            raise OnDemandProviderError("tempmail_lol invalid create response")
        address = str(data.get("address") or "").strip().lower()
        token = str(data.get("token") or "").strip()
        if not address or not token:
            raise OnDemandProviderError("tempmail_lol missing address or token")
        return OnDemandProvisionResult(
            address=address,
            external_resource_id=address,
            secret_payload={"token": token},
        )

    def fetch_evidence(
        self,
        allocation: VerificationAllocationSnapshot,
        query: VerificationQuery,
    ) -> VerificationEvidence:
        token = allocation.access_context.get("token") or ""
        headers = {"Accept": "application/json"}
        api_key = (self._runtime.secrets.get("api_key") or "").strip()
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        data = self._http.request_json(
            "GET",
            "https://api.tempmail.lol/v2/inbox",
            headers=headers,
            params={"token": token},
        )
        items = data.get("emails") or data.get("messages") or [] if isinstance(data, dict) else []
        messages = [
            _message_to_evidence(item, address=allocation.primary_email)
            for item in items
            if isinstance(item, dict)
        ]
        return VerificationEvidence(messages=_filter_messages(messages, query), read_method="tempmail_lol")


class DuckMailAdapter(ConfigurableOnDemandAdapter):
    provider_type = "duckmail"

    def provision(self, request: OnDemandProvisionRequest) -> OnDemandProvisionResult:
        api_key = self._require_secret("api_key")
        domain = str(self._value("default_domain") or "duckmail.sbs").strip() or "duckmail.sbs"
        password = "".join(random.choices(string.ascii_letters + string.digits, k=12))
        address = f"{request.preferred_local_part or _random_local_part()}@{domain}".lower()
        payload = {"address": address, "password": password}
        self._http.request_json(
            "POST",
            "https://api.duckmail.sbs/accounts",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json_body=payload,
            expected_status=(200, 201, 204),
        )
        token_data = self._http.request_json(
            "POST",
            "https://api.duckmail.sbs/token",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json_body=payload,
            expected_status=(200, 201),
        )
        token = str((token_data or {}).get("token") or "").strip() if isinstance(token_data, dict) else ""
        if not token:
            raise OnDemandProviderError("duckmail missing token")
        return OnDemandProvisionResult(
            address=address,
            external_resource_id=address,
            secret_payload={"token": token, "password": password},
        )

    def fetch_evidence(
        self,
        allocation: VerificationAllocationSnapshot,
        query: VerificationQuery,
    ) -> VerificationEvidence:
        token = allocation.access_context.get("token") or ""
        data = self._http.request_json(
            "GET",
            "https://api.duckmail.sbs/messages",
            headers={"Authorization": f"Bearer {token}"},
            params={"page": 1},
        )
        items = data if isinstance(data, list) else (data.get("hydra:member") or data.get("member") or data.get("data") or []) if isinstance(data, dict) else []
        messages: list[InboxMessageEvidence] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            message_id = str(item.get("id") or item.get("@id") or "").replace("/messages/", "")
            detail = item
            if message_id:
                try:
                    detail = self._http.request_json(
                        "GET",
                        f"https://api.duckmail.sbs/messages/{message_id}",
                        headers={"Authorization": f"Bearer {token}"},
                    )
                except ProviderHttpError:
                    detail = item
            if isinstance(detail, dict):
                messages.append(_message_to_evidence(detail, address=allocation.primary_email))
        return VerificationEvidence(messages=_filter_messages(messages, query), read_method="duckmail")


class GptMailAdapter(ConfigurableOnDemandAdapter):
    provider_type = "gptmail"

    def provision(self, request: OnDemandProvisionRequest) -> OnDemandProvisionResult:
        api_key = self._require_secret("api_key")
        headers = {"X-API-Key": api_key, "Content-Type": "application/json", "Accept": "application/json"}
        payload = {
            key: value
            for key, value in {
                "prefix": request.preferred_local_part,
                "domain": str(self._value("default_domain") or "").strip() or None,
            }.items()
            if value
        }
        data = self._http.request_json(
            "POST" if payload else "GET",
            "https://mail.chatgpt.org.uk/api/generate-email",
            headers=headers,
            json_body=payload or None,
        )
        payload_data = data["data"] if isinstance(data, dict) and "data" in data else data
        if not isinstance(payload_data, dict):
            raise OnDemandProviderError("gptmail invalid generate response")
        address = str(payload_data.get("email") or "").strip().lower()
        if not address:
            raise OnDemandProviderError("gptmail missing email")
        return OnDemandProvisionResult(
            address=address,
            external_resource_id=address,
            secret_payload={"api_key": api_key},
        )

    def fetch_evidence(
        self,
        allocation: VerificationAllocationSnapshot,
        query: VerificationQuery,
    ) -> VerificationEvidence:
        api_key = allocation.access_context.get("api_key") or self._runtime.secrets.get("api_key") or ""
        headers = {"X-API-Key": api_key, "Accept": "application/json"}
        data = self._http.request_json(
            "GET",
            "https://mail.chatgpt.org.uk/api/emails",
            headers=headers,
            params={"email": allocation.primary_email},
        )
        payload_data = data["data"] if isinstance(data, dict) and "data" in data else data
        emails = payload_data if isinstance(payload_data, list) else (payload_data.get("emails") or []) if isinstance(payload_data, dict) else []
        messages = [
            _message_to_evidence(item, address=allocation.primary_email)
            for item in emails
            if isinstance(item, dict)
        ]
        return VerificationEvidence(messages=_filter_messages(messages, query), read_method="gptmail")


class MoeMailAdapter(ConfigurableOnDemandAdapter):
    provider_type = "moemail"

    def provision(self, request: OnDemandProvisionRequest) -> OnDemandProvisionResult:
        api_base = str(self._value("api_base") or "").rstrip("/")
        api_key = self._require_secret("api_key")
        if not api_base:
            raise OnDemandProviderError("moemail requires api_base")
        domains = self._string_list("domain")
        payload: dict[str, Any] = {
            "name": request.preferred_local_part or _random_local_part(),
            "expiryTime": int(self._value("expiry_time") or 0),
        }
        if domains:
            payload["domain"] = _next_domain(domains)
        data = self._http.request_json(
            "POST",
            f"{api_base}/api/emails/generate",
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            json_body=payload,
            expected_status=(200, 201),
        )
        if not isinstance(data, dict):
            raise OnDemandProviderError("moemail invalid generate response")
        address = str(data.get("email") or "").strip().lower()
        email_id = str(data.get("id") or data.get("email_id") or "").strip()
        if not address or not email_id:
            raise OnDemandProviderError("moemail missing email or id")
        return OnDemandProvisionResult(
            address=address,
            external_resource_id=email_id,
            secret_payload={"email_id": email_id, "api_base": api_base, "api_key": api_key},
        )

    def fetch_evidence(
        self,
        allocation: VerificationAllocationSnapshot,
        query: VerificationQuery,
    ) -> VerificationEvidence:
        email_id = allocation.access_context.get("email_id") or allocation.access_context.get("external_resource_id") or ""
        api_base = (allocation.access_context.get("api_base") or str(self._value("api_base") or "")).rstrip("/")
        api_key = allocation.access_context.get("api_key") or self._runtime.secrets.get("api_key") or ""
        data = self._http.request_json(
            "GET",
            f"{api_base}/api/emails/{email_id}",
            headers={"X-API-Key": api_key},
        )
        items = data.get("messages") if isinstance(data, dict) else []
        messages = [
            _message_to_evidence(item, address=allocation.primary_email)
            for item in (items or [])
            if isinstance(item, dict)
        ]
        return VerificationEvidence(messages=_filter_messages(messages, query), read_method="moemail")


class InbucketAdapter(ConfigurableOnDemandAdapter):
    provider_type = "inbucket"

    def provision(self, request: OnDemandProvisionRequest) -> OnDemandProvisionResult:
        api_base = str(self._value("api_base") or "").rstrip("/")
        if not api_base:
            raise OnDemandProviderError("inbucket requires api_base")
        base_domain = _next_domain(self._string_list("domain"))
        random_sub = bool(self._value("random_subdomain", True))
        domain = f"{_random_subdomain_label()}.{base_domain}" if random_sub else base_domain
        local_part = request.preferred_local_part or _random_local_part()
        address = f"{local_part}@{domain}".lower()
        return OnDemandProvisionResult(
            address=address,
            external_resource_id=local_part,
            secret_payload={"api_base": api_base, "mailbox_name": local_part},
            metadata={"base_domain": base_domain},
        )

    def fetch_evidence(
        self,
        allocation: VerificationAllocationSnapshot,
        query: VerificationQuery,
    ) -> VerificationEvidence:
        api_base = (allocation.access_context.get("api_base") or str(self._value("api_base") or "")).rstrip("/")
        mailbox_name = allocation.access_context.get("mailbox_name") or allocation.primary_email.split("@", 1)[0]
        data = self._http.request_json("GET", f"{api_base}/api/v1/mailbox/{mailbox_name}")
        items = [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []
        messages: list[InboxMessageEvidence] = []
        for item in items[: max(query.max_messages, 1)]:
            message_id = str(item.get("id") or "").strip()
            detail = item
            if message_id:
                try:
                    detail = self._http.request_json(
                        "GET", f"{api_base}/api/v1/mailbox/{mailbox_name}/{message_id}"
                    )
                except ProviderHttpError:
                    detail = item
            if not isinstance(detail, dict):
                continue
            body = detail.get("body") if isinstance(detail.get("body"), dict) else {}
            normalized = {
                "subject": detail.get("subject") or item.get("subject"),
                "from": detail.get("from") or item.get("from"),
                "text": (body or {}).get("text") if isinstance(body, dict) else "",
                "html": (body or {}).get("html") if isinstance(body, dict) else "",
                "date": detail.get("date") or item.get("date"),
            }
            messages.append(_message_to_evidence(normalized, address=allocation.primary_email))
        return VerificationEvidence(messages=_filter_messages(messages, query), read_method="inbucket")


class YydsMailAdapter(ConfigurableOnDemandAdapter):
    provider_type = "yyds_mail"

    def provision(self, request: OnDemandProvisionRequest) -> OnDemandProvisionResult:
        api_base = str(self._value("api_base") or "https://maliapi.215.im/v1").rstrip("/")
        api_key = self._require_secret("api_key")
        payload: dict[str, Any] = {"localPart": request.preferred_local_part or _random_local_part()}
        domains = self._string_list("domain")
        if domains:
            payload["domain"] = _next_domain(domains)
        subdomain = str(self._value("subdomain") or "").strip()
        if subdomain:
            payload["subdomain"] = subdomain
        path = "/accounts/wildcard" if bool(self._value("wildcard")) else "/accounts"
        data = self._http.request_json(
            "POST",
            f"{api_base}{path}",
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
            json_body=payload,
            expected_status=(200, 201),
        )
        body = data.get("data") if isinstance(data, dict) and isinstance(data.get("data"), dict) else data
        if not isinstance(body, dict):
            raise OnDemandProviderError("yyds_mail invalid create response")
        address = str(body.get("address") or body.get("email") or "").strip().lower()
        token = str(
            body.get("token")
            or body.get("temp_token")
            or body.get("tempToken")
            or body.get("access_token")
            or ""
        ).strip()
        if not address or not token:
            raise OnDemandProviderError("yyds_mail missing address or token")
        return OnDemandProvisionResult(
            address=address,
            external_resource_id=str(body.get("id") or address),
            secret_payload={"token": token, "api_base": api_base},
        )

    def fetch_evidence(
        self,
        allocation: VerificationAllocationSnapshot,
        query: VerificationQuery,
    ) -> VerificationEvidence:
        token = allocation.access_context.get("token") or ""
        api_base = (allocation.access_context.get("api_base") or str(self._value("api_base") or "https://maliapi.215.im/v1")).rstrip("/")
        data = self._http.request_json(
            "GET",
            f"{api_base}/messages",
            headers={"Authorization": f"Bearer {token}"},
            params={"address": allocation.primary_email},
        )
        body = data.get("data") if isinstance(data, dict) and "data" in data else data
        items = body if isinstance(body, list) else (body.get("items") or body.get("messages") or []) if isinstance(body, dict) else []
        messages = [
            _message_to_evidence(item, address=allocation.primary_email)
            for item in items
            if isinstance(item, dict)
        ]
        return VerificationEvidence(messages=_filter_messages(messages, query), read_method="yyds_mail")


class CloudMailGenAdapter(ConfigurableOnDemandAdapter):
    provider_type = "cloudmail_gen"

    def _get_admin_token(self) -> str:
        api_base = str(self._value("api_base") or "").rstrip("/")
        admin_email = str(self._value("admin_email") or "").strip()
        admin_password = self._require_secret("admin_password")
        if not api_base or not admin_email:
            raise OnDemandProviderError("cloudmail_gen requires api_base and admin_email")
        data = self._http.request_json(
            "POST",
            f"{api_base}/api/public/genToken",
            headers={"Content-Type": "application/json"},
            json_body={"email": admin_email, "password": admin_password},
        )
        token = ""
        if isinstance(data, dict) and data.get("code") == 200:
            token = str((data.get("data") or {}).get("token") or "").strip()
        if not token:
            raise OnDemandProviderError("cloudmail_gen genToken failed")
        return token

    def provision(self, request: OnDemandProvisionRequest) -> OnDemandProvisionResult:
        api_base = str(self._value("api_base") or "").rstrip("/")
        domains = self._string_list("domain")
        if not domains:
            raise OnDemandProviderError("cloudmail_gen requires domain")
        domain = _next_domain(domains)
        subdomains = self._string_list("subdomain")
        if subdomains:
            domain = f"{random.choice(subdomains)}.{domain}"
        prefix = str(self._value("email_prefix") or "").strip()
        if request.preferred_local_part:
            local_part = request.preferred_local_part
        elif prefix:
            local_part = f"{prefix}_{_random_local_part(6)}"
        else:
            local_part = _random_local_part()
        address = f"{local_part}@{domain}".lower()
        token = self._get_admin_token()
        self._http.request_json(
            "POST",
            f"{api_base}/api/public/addUser",
            headers={"Authorization": token, "Content-Type": "application/json"},
            json_body={"list": [{"email": address}]},
        )
        return OnDemandProvisionResult(
            address=address,
            external_resource_id=address,
            secret_payload={"admin_token": token, "api_base": api_base},
        )

    def fetch_evidence(
        self,
        allocation: VerificationAllocationSnapshot,
        query: VerificationQuery,
    ) -> VerificationEvidence:
        api_base = (allocation.access_context.get("api_base") or str(self._value("api_base") or "")).rstrip("/")
        token = allocation.access_context.get("admin_token") or self._get_admin_token()
        data = self._http.request_json(
            "POST",
            f"{api_base}/api/public/emailList",
            headers={"Authorization": token, "Content-Type": "application/json"},
            json_body={"toEmail": allocation.primary_email, "size": 20, "timeSort": "desc"},
        )
        items = data.get("data") if isinstance(data, dict) else []
        messages = [
            _message_to_evidence(item, address=allocation.primary_email)
            for item in (items or [])
            if isinstance(item, dict)
        ]
        return VerificationEvidence(messages=_filter_messages(messages, query), read_method="cloudmail_gen")


class DdgMailAdapter(ConfigurableOnDemandAdapter):
    """DDG alias creation + Cloudflare-compatible inbox reader."""

    provider_type = "ddg_mail"

    def provision(self, request: OnDemandProvisionRequest) -> OnDemandProvisionResult:
        ddg_token = self._require_secret("ddg_token")
        data = self._http.request_json(
            "POST",
            "https://quack.duckduckgo.com/api/email/addresses",
            headers={
                "Authorization": f"Bearer {ddg_token}",
                "Content-Type": "application/json",
            },
            json_body={},
        )
        if not isinstance(data, dict):
            raise OnDemandProviderError("ddg_mail invalid address response")
        address_part = str(data.get("address") or "").strip()
        if not address_part:
            raise OnDemandProviderError("ddg_mail missing address part")
        address = f"{address_part}@duck.com".lower()
        cf_api_base = str(self._value("api_base") or "").rstrip("/")
        cf_inbox_jwt = (self._runtime.secrets.get("cf_inbox_jwt") or "").strip()
        if not cf_api_base:
            raise OnDemandProviderError("ddg_mail requires CF api_base for inbox reading")
        # Optionally register alias into CF-compatible store when admin password is present.
        admin_password = (self._runtime.secrets.get("admin_password") or "").strip()
        create_path = str(self._value("cf_create_path") or "/api/new_address").strip() or "/api/new_address"
        if admin_password:
            try:
                self._http.request_json(
                    "POST",
                    f"{cf_api_base}{create_path}",
                    headers={"Content-Type": "application/json", "x-admin-auth": admin_password},
                    json_body={"address": address},
                    expected_status=(200, 201, 204),
                )
            except ProviderHttpError:
                # Reader may still work with preconfigured catch-all JWT.
                pass
        secret_payload = {
            "api_base": cf_api_base,
            "messages_path": str(self._value("cf_messages_path") or "/api/mails"),
        }
        if cf_inbox_jwt:
            secret_payload["token"] = cf_inbox_jwt
        if admin_password:
            secret_payload["admin_password"] = admin_password
        cf_api_key = (self._runtime.secrets.get("cf_api_key") or "").strip()
        if cf_api_key:
            secret_payload["cf_api_key"] = cf_api_key
            secret_payload["cf_auth_mode"] = str(self._value("cf_auth_mode") or "none")
        return OnDemandProvisionResult(
            address=address,
            external_resource_id=address,
            secret_payload=secret_payload,
        )

    def fetch_evidence(
        self,
        allocation: VerificationAllocationSnapshot,
        query: VerificationQuery,
    ) -> VerificationEvidence:
        api_base = (allocation.access_context.get("api_base") or str(self._value("api_base") or "")).rstrip("/")
        messages_path = allocation.access_context.get("messages_path") or str(
            self._value("cf_messages_path") or "/api/mails"
        )
        headers: dict[str, str] = {"Accept": "application/json"}
        token = allocation.access_context.get("token") or ""
        if token:
            headers["Authorization"] = f"Bearer {token}"
        cf_api_key = allocation.access_context.get("cf_api_key") or ""
        auth_mode = allocation.access_context.get("cf_auth_mode") or "none"
        params: dict[str, Any] = {"limit": 20, "offset": 0}
        if cf_api_key:
            if auth_mode == "x-api-key":
                headers["X-API-Key"] = cf_api_key
            elif auth_mode == "query-key":
                params["key"] = cf_api_key
            elif auth_mode != "none":
                headers["Authorization"] = f"Bearer {cf_api_key}"
        data = self._http.request_json(
            "GET",
            f"{api_base}{messages_path}",
            headers=headers,
            params=params,
        )
        raw = list(data.get("results") or []) if isinstance(data, dict) else data if isinstance(data, list) else []
        messages = [
            _message_to_evidence(item, address=allocation.primary_email)
            for item in raw
            if isinstance(item, dict)
        ]
        return VerificationEvidence(messages=_filter_messages(messages, query), read_method="ddg_mail")


ADAPTER_FACTORIES: dict[str, Callable[[OnDemandRuntimeConfig, JsonHttpClient | None], ConfigurableOnDemandAdapter]] = {
    "cloudflare_temp_email": lambda runtime, http: CloudflareTempEmailAdapter(runtime, http_client=http),
    "ddg_mail": lambda runtime, http: DdgMailAdapter(runtime, http_client=http),
    "cloudmail_gen": lambda runtime, http: CloudMailGenAdapter(runtime, http_client=http),
    "tempmail_lol": lambda runtime, http: TempMailLolAdapter(runtime, http_client=http),
    "duckmail": lambda runtime, http: DuckMailAdapter(runtime, http_client=http),
    "gptmail": lambda runtime, http: GptMailAdapter(runtime, http_client=http),
    "moemail": lambda runtime, http: MoeMailAdapter(runtime, http_client=http),
    "inbucket": lambda runtime, http: InbucketAdapter(runtime, http_client=http),
    "yyds_mail": lambda runtime, http: YydsMailAdapter(runtime, http_client=http),
}


class OnDemandProviderFacade:
    """Provisioner + evidence source bound to one runtime config."""

    def __init__(
        self,
        runtime: OnDemandRuntimeConfig,
        *,
        http_client: JsonHttpClient | None = None,
    ) -> None:
        factory = ADAPTER_FACTORIES.get(runtime.provider_type)
        if factory is None:
            raise OnDemandProviderError(f"unsupported on-demand provider: {runtime.provider_type}")
        self._adapter = factory(runtime, http_client)
        self.provider_type = runtime.provider_type
        self.instance_id = runtime.instance_id

    def provision(self, request: OnDemandProvisionRequest) -> OnDemandProvisionResult:
        return self._adapter.provision(request)

    def fetch_evidence(
        self,
        allocation: VerificationAllocationSnapshot,
        query: VerificationQuery,
    ) -> VerificationEvidence:
        return self._adapter.fetch_evidence(allocation, query)
