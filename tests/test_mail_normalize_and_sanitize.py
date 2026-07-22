"""Unit tests for mail body sanitization and message normalization (P0)."""

from __future__ import annotations

from mailbox_service.mail_body_sanitize import html_to_visible_text, sanitize_mail_text
from mailbox_service.mail_message_normalize import (
    extract_message_list,
    message_dict_to_evidence,
    normalize_raw_message,
)
from mailbox_service.verification_code_service import extract_verification_code


def test_sanitize_strips_rfc822_headers_before_code_extraction() -> None:
    raw = (
        "Received: from mx.example.com\r\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=example.com\r\n"
        "Authentication-Results: mx; dkim=pass\r\n"
        "From: sender@example.com\r\n"
        "Subject: hello\r\n"
        "\r\n"
        "Your verification code is 482913\r\n"
    )
    cleaned = sanitize_mail_text(raw)
    assert "DKIM-Signature" not in cleaned
    assert "482913" in cleaned
    assert extract_verification_code("hello", raw) == "482913"


def test_sanitize_header_noise_does_not_yield_fake_arc_code() -> None:
    # Without sanitization, header tokens can look like codes; body has the real OTP.
    raw = (
        "ARC-Seal: i=1; a=rsa-sha256; t=1; cv=none\r\n"
        "From: a@b.com\r\n"
        "\r\n"
        "验证码：556677\r\n"
    )
    assert extract_verification_code("验证", raw) == "556677"


def test_html_to_visible_text_and_qp_soft_breaks() -> None:
    html = "<html><body><div>Code=3D<span>1234</span>56</div></body></html>"
    # QP entity handled in sanitize path.
    text = sanitize_mail_text(html)
    assert "1234" in text
    assert "<div>" not in text
    assert html_to_visible_text("<script>x</script><b>hi</b>") == "hi"


def test_extract_message_list_supports_multiple_containers() -> None:
    assert len(extract_message_list({"hydra:member": [{"id": "1"}]})) == 1
    assert len(extract_message_list({"messages": [{"id": "2"}]})) == 1
    assert len(extract_message_list({"data": {"items": [{"id": "3"}]}})) == 1
    assert len(extract_message_list([{"id": "4"}])) == 1


def test_normalize_raw_message_aliases() -> None:
    normalized = normalize_raw_message(
        {
            "title": "Your code",
            "fromAddr": {"address": "otp@service.com", "name": "OTP"},
            "textBody": "code 998877",
            "createdAt": "2026-07-22T00:00:00Z",
            "messageId": "mid-1",
        }
    )
    assert normalized.subject == "Your code"
    assert normalized.from_address == "otp@service.com"
    assert "998877" in normalized.text
    assert normalized.message_id == "mid-1"
    assert normalized.received_at is not None


def test_message_dict_to_evidence_includes_recipient() -> None:
    evidence = message_dict_to_evidence(
        {"subject": "s", "text": "body 112233", "from": "a@b.c"},
        address="user@example.com",
    )
    assert "user@example.com" in evidence.recipient_addresses
    assert evidence.subject == "s"
    assert evidence.body_text and "112233" in evidence.body_text
