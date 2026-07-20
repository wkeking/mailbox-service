"""SMSBower Mail API contract (frozen from chatgpt2api source).

Source of truth (Gate 0):
- repo: https://github.com/basketikun/chatgpt2api.git
- path: services/register/smsbower_mail.py
- commit: f26f636524ede38ed0361bf8f07f8774455ea67c
- docs: docs/smsbower-gmail-fission-guide.md
- official ref: https://smsbower.app/cn/api?page=mails
- default base: https://smsbower.page/api/mail

Do not invent parameters. All GET; query always includes api_key.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urlunparse

SMSBOWER_PROVIDER_TYPE = "smsbower_gmail"
SMSBOWER_DEFAULT_INSTANCE_ID = "default"
SMSBOWER_DEFAULT_BASE_URL = "https://smsbower.page/api/mail"
SMSBOWER_DEFAULT_SERVICE = "openai"
SMSBOWER_DEFAULT_DOMAIN = "gmail.com"

# setStatus semantics from chatgpt2api / fission guide
SMSBOWER_STATUS_CLOSE_FAILED = 2
SMSBOWER_STATUS_CLOSE_SUCCESS = 3
SMSBOWER_STATUS_WAIT_NEXT_CODE = 5  # fission only; Phase 1A does not call this

SMSBOWER_PENDING_MARKERS = (
    "code has not been received",
    "try again later",
    "no code",
    "wait_code",
    "waiting",
    "pending",
)

SOURCE_REPO = "https://github.com/basketikun/chatgpt2api.git"
SOURCE_PATH = "services/register/smsbower_mail.py"
SOURCE_COMMIT = "f26f636524ede38ed0361bf8f07f8774455ea67c"


class SmsBowerContractError(RuntimeError):
    """SMSBower response parse or protocol failure."""


def normalize_smsbower_base_url(value: str | None) -> str:
    text = str(value or "").strip()
    if not text:
        return SMSBOWER_DEFAULT_BASE_URL
    if "://" not in text:
        text = "https://" + text
    try:
        parsed = urlparse(text)
    except Exception:
        return SMSBOWER_DEFAULT_BASE_URL
    host = (parsed.hostname or "").lower()
    netloc = parsed.netloc
    if host == "smsbower.app":
        netloc = netloc.replace("smsbower.app", "smsbower.page")
    scheme = parsed.scheme or "https"
    path = (parsed.path or "").rstrip("/")
    normalized = urlunparse((scheme, netloc, path, "", "", ""))
    return normalized or SMSBOWER_DEFAULT_BASE_URL


def smsbower_service_code(service: str | None) -> str:
    text = str(service or "").strip().lower()
    if text in ("", "openai", "chatgpt", "chat-gpt", "oa"):
        return "dr"
    return text


def extract_smsbower_code(payload: Any) -> str | None:
    if payload is None:
        return None
    if isinstance(payload, dict):
        for key in ("code", "otp", "verification_code", "sms", "text", "message"):
            found = extract_smsbower_code(payload.get(key))
            if found:
                return found
        text = json.dumps(payload, ensure_ascii=False)
    else:
        text = str(payload)
    match = re.search(r"(?<!\d)(\d{6})(?!\d)", text)
    return match.group(1) if match else None


def smsbower_response_is_pending(payload: Any) -> bool:
    text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
    lowered = text.lower()
    return any(marker in lowered for marker in SMSBOWER_PENDING_MARKERS)


def parse_smsbower_activation(payload: Any) -> dict[str, Any]:
    """Return {id, email, cost} from getActivation response."""
    activation_id = ""
    email = ""
    cost: float | None = None
    if isinstance(payload, dict):
        for key in ("id", "activation_id", "activationId", "mail_id", "mailId"):
            if payload.get(key):
                activation_id = str(payload.get(key)).strip()
                break
        for key in ("email", "mail", "address", "login"):
            if payload.get(key):
                email = str(payload.get(key)).strip()
                break
        for key in ("cost", "price", "amount", "sum"):
            if payload.get(key) is not None:
                try:
                    cost = float(payload.get(key))
                except Exception:
                    cost = None
                break
    else:
        text = str(payload or "").strip()
        lowered = text.lower()
        if (
            lowered.startswith("no_")
            or "no_balance" in lowered
            or "bad_key" in lowered
            or "no_activation" in lowered
        ):
            raise SmsBowerContractError(f"SMSBower getActivation failed: {text[:200]}")
        parts = text.split(":")
        tokens = [part for part in parts if part]
        email_token = next((part for part in tokens if "@" in part), "")
        id_token = ""
        for part in tokens:
            if part == email_token:
                continue
            if re.fullmatch(r"\d+", part.strip()):
                id_token = part.strip()
                break
        activation_id = id_token
        email = email_token.strip()
    if not activation_id or not email:
        raise SmsBowerContractError(f"SMSBower activation parse failed: {str(payload)[:200]}")
    return {"id": activation_id, "email": email, "cost": cost}


@dataclass(frozen=True)
class SmsBowerHttpRequest:
    action: str
    params: dict[str, Any]
    base_url: str


def build_get_activation_request(
    *,
    base_url: str,
    service: str,
    domain: str,
    max_price: Any = None,
) -> SmsBowerHttpRequest:
    params: dict[str, Any] = {
        "service": smsbower_service_code(service),
        "domain": domain,
    }
    if max_price not in (None, ""):
        params["maxPrice"] = max_price
        params["max_price"] = max_price
    return SmsBowerHttpRequest(
        action="getActivation",
        params=params,
        base_url=normalize_smsbower_base_url(base_url),
    )


def build_get_code_request(*, base_url: str, mail_id: str) -> SmsBowerHttpRequest:
    return SmsBowerHttpRequest(
        action="getCode",
        params={"mailId": mail_id},
        base_url=normalize_smsbower_base_url(base_url),
    )


def build_set_status_request(
    *,
    base_url: str,
    mail_id: str,
    status: int,
) -> SmsBowerHttpRequest:
    return SmsBowerHttpRequest(
        action="setStatus",
        params={"id": mail_id, "mailId": mail_id, "status": status},
        base_url=normalize_smsbower_base_url(base_url),
    )
