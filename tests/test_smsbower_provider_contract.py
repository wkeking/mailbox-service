"""Contract tests for SMSBower protocol parsing (no live network)."""

from __future__ import annotations

import pytest

from mailbox_service.providers import smsbower_contracts as contract


def test_source_metadata_frozen() -> None:
    assert contract.SOURCE_COMMIT == "f26f636524ede38ed0361bf8f07f8774455ea67c"
    assert "chatgpt2api" in contract.SOURCE_REPO
    assert contract.SOURCE_PATH.endswith("smsbower_mail.py")


def test_normalize_base_url() -> None:
    assert (
        contract.normalize_smsbower_base_url("https://smsbower.app/api/mail")
        == "https://smsbower.page/api/mail"
    )
    assert contract.normalize_smsbower_base_url("") == contract.SMSBOWER_DEFAULT_BASE_URL


def test_service_code_mapping() -> None:
    for name in ("", "openai", "chatgpt", "oa"):
        assert contract.smsbower_service_code(name) == "dr"
    assert contract.smsbower_service_code("custom") == "custom"


def test_parse_activation_text_and_json() -> None:
    parsed = contract.parse_smsbower_activation("ACCESS:123456789:alice@gmail.com")
    assert parsed["id"] == "123456789"
    assert parsed["email"] == "alice@gmail.com"
    parsed_json = contract.parse_smsbower_activation(
        {"id": "42", "email": "x@gmail.com", "cost": 0.12}
    )
    assert parsed_json["id"] == "42"
    assert parsed_json["cost"] == 0.12
    with pytest.raises(contract.SmsBowerContractError):
        contract.parse_smsbower_activation("NO_BALANCE")


def test_extract_code_and_pending() -> None:
    assert contract.extract_smsbower_code({"code": "123456"}) == "123456"
    assert contract.extract_smsbower_code("STATUS_OK:654321") == "654321"
    assert contract.smsbower_response_is_pending("code has not been received")
    assert not contract.smsbower_response_is_pending("123456")


def test_request_builders() -> None:
    activation = contract.build_get_activation_request(
        base_url=contract.SMSBOWER_DEFAULT_BASE_URL,
        service="openai",
        domain="gmail.com",
        max_price=0.5,
    )
    assert activation.action == "getActivation"
    assert activation.params["service"] == "dr"
    assert activation.params["maxPrice"] == 0.5
    code_request = contract.build_get_code_request(
        base_url=contract.SMSBOWER_DEFAULT_BASE_URL,
        mail_id="99",
    )
    assert code_request.params["mailId"] == "99"
    status_request = contract.build_set_status_request(
        base_url=contract.SMSBOWER_DEFAULT_BASE_URL,
        mail_id="99",
        status=contract.SMSBOWER_STATUS_CLOSE_SUCCESS,
    )
    assert status_request.params["status"] == 3
    assert status_request.params["id"] == "99"
