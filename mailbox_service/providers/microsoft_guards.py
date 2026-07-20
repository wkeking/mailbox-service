"""Microsoft-only entry guards for Token, probe, keepalive, and four-segment import paths."""

from __future__ import annotations

from mailbox_service.models import Mailbox
from mailbox_service.providers.registry import DEFAULT_PROVIDER_TYPE, normalize_provider_type


class ProviderNotMicrosoftError(Exception):
    """Raised when a Microsoft-only operation is applied to another provider."""


def require_microsoft_mailbox(mailbox: Mailbox | None, *, operation: str) -> Mailbox:
    """Fail closed unless the mailbox is explicitly Microsoft inventory."""
    if mailbox is None:
        raise ProviderNotMicrosoftError(f"{operation}: mailbox not found")
    provider_type = normalize_provider_type(mailbox.provider_type or DEFAULT_PROVIDER_TYPE)
    if provider_type != DEFAULT_PROVIDER_TYPE:
        raise ProviderNotMicrosoftError(
            f"{operation} is Microsoft-only; mailbox provider_type={provider_type}"
        )
    return mailbox


def is_microsoft_provider(provider_type: str | None) -> bool:
    if not provider_type:
        return True
    return normalize_provider_type(provider_type) == DEFAULT_PROVIDER_TYPE
