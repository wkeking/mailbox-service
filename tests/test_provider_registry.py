"""Unit tests for provider registry and Microsoft import decoder."""

from __future__ import annotations

import pytest

from mailbox_service.providers.builder import build_provider_registry
from mailbox_service.providers.microsoft import MicrosoftFourSegmentImportDecoder
from mailbox_service.providers.registry import ProviderRegistry, normalize_provider_type
from mailbox_service.providers.registry import ProviderDescriptor


def test_normalize_provider_type() -> None:
    assert normalize_provider_type("Microsoft") == "microsoft"
    with pytest.raises(ValueError):
        normalize_provider_type("")
    with pytest.raises(ValueError):
        normalize_provider_type("bad type!")


def test_registry_registers_microsoft_and_rejects_duplicate() -> None:
    registry = build_provider_registry()
    assert "microsoft" in registry.known_types()
    with pytest.raises(ValueError, match="duplicate"):
        registry.register(
            ProviderDescriptor(
                provider_type="microsoft",
                supported_lease_modes=frozenset({"mail_read"}),
            )
        )


def test_unknown_provider_fail_closed() -> None:
    registry = ProviderRegistry()
    with pytest.raises(KeyError):
        registry.get("smsbower_gmail")


def test_microsoft_four_segment_decoder() -> None:
    drafts = MicrosoftFourSegmentImportDecoder().decode(
        "a@example.com----pass----client----rt\n# comment\n"
    )
    assert len(drafts) == 1
    assert drafts[0].primary_email == "a@example.com"
    assert drafts[0].provider_type == "microsoft"
    assert drafts[0].refresh_token == "rt"
