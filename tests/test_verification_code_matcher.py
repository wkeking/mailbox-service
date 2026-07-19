"""Tests for bounded verification-code matchers."""

from __future__ import annotations

import time

import pytest
from pydantic import ValidationError

from mailbox_service.verification_code_matcher import (
    MAX_MESSAGE_BODY_BYTES,
    SafeVerificationCodeMatcher,
    VerificationCodePatternOptions,
    VerificationCodePatternType,
    truncate_text_to_byte_budget,
)
from mailbox_service.schemas import LeaseVerificationCodeRequest


def test_default_digits_match() -> None:
    matcher = SafeVerificationCodeMatcher.from_options(VerificationCodePatternOptions())
    assert matcher.search("Your code", "use 123456 to login") == "123456"


def test_xai_subject_and_body() -> None:
    matcher = SafeVerificationCodeMatcher.from_options(
        VerificationCodePatternOptions(pattern_type=VerificationCodePatternType.XAI)
    )
    assert matcher.search("ABC-123 xAI", "") == "ABC-123"
    assert matcher.search("hello", "code is XYZ-987 for you") == "XYZ-987"


def test_untrusted_regex_is_rejected() -> None:
    with pytest.raises(ValidationError):
        LeaseVerificationCodeRequest(code_regex="(a+)+$")


def test_safe_preset_accepted() -> None:
    request = LeaseVerificationCodeRequest(code_regex=r"\b(\d{4,8})\b")
    assert request.code_regex == r"\b(\d{4,8})\b"


def test_long_body_truncated_quickly() -> None:
    huge = "a" * (2 * 1024 * 1024) + " 424242 "
    started = time.perf_counter()
    truncated = truncate_text_to_byte_budget(huge, MAX_MESSAGE_BODY_BYTES)
    matcher = SafeVerificationCodeMatcher.from_options(VerificationCodePatternOptions())
    _ = matcher.search("subject", truncated)
    elapsed = time.perf_counter() - started
    assert len(truncated.encode("utf-8")) <= MAX_MESSAGE_BODY_BYTES
    assert elapsed < 0.1


def test_scan_and_request_budget_constants() -> None:
    from mailbox_service.verification_code_matcher import MAX_REQUEST_BODY_BYTES, MAX_SCAN_BODY_BYTES

    assert MAX_MESSAGE_BODY_BYTES == 64 * 1024
    assert MAX_SCAN_BODY_BYTES == 512 * 1024
    assert MAX_REQUEST_BODY_BYTES == 1024 * 1024
