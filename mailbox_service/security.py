"""Secret encryption and safe diagnostic helpers."""

from __future__ import annotations

from base64 import urlsafe_b64decode, urlsafe_b64encode
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CredentialCipher:
    """Encrypt credentials with AES-GCM without logging source secret values."""

    def __init__(self, encoded_key: str) -> None:
        self._key = urlsafe_b64decode(encoded_key)
        self._cipher = AESGCM(self._key)

    @property
    def hmac_key(self) -> bytes:
        """Return the raw key bytes used for non-reversible credential fingerprints."""
        return self._key

    def encrypt(self, plaintext: str) -> str:
        """Return an authenticated encrypted value containing a random nonce."""
        nonce = os.urandom(12)
        ciphertext = self._cipher.encrypt(nonce, plaintext.encode("utf-8"), None)
        return urlsafe_b64encode(nonce + ciphertext).decode("ascii")

    def decrypt(self, encrypted_value: str) -> str:
        """Decrypt a value previously returned by :meth:`encrypt`."""
        decoded_value = urlsafe_b64decode(encrypted_value)
        nonce = decoded_value[:12]
        ciphertext = decoded_value[12:]
        return self._cipher.decrypt(nonce, ciphertext, None).decode("utf-8")


def build_proxy_credential_fingerprint(
    username: str | None,
    password: str | None,
    *,
    hmac_key: bytes | None = None,
) -> str:
    """Return a stable fingerprint for proxy-pool identity without storing secrets.

    Proxy pool members often share host and port while differing only by username
    and password. The fingerprint is included in the unique endpoint constraint so
    identical credentials collide while different credentials remain distinct.
    """
    normalized_username = (username or "").strip()
    normalized_password = password or ""
    material = f"{normalized_username}\0{normalized_password}".encode("utf-8")
    if hmac_key is None:
        return hashlib.sha256(b"mailbox-service-proxy-credential\0" + material).hexdigest()
    return hmac.new(hmac_key, material, hashlib.sha256).hexdigest()


def redact_proxy_host(host: str) -> str:
    """Return a useful but non-sensitive proxy address preview for Admin APIs."""
    if len(host) <= 4:
        return "*" * len(host)
    return f"{host[:2]}{'*' * (len(host) - 4)}{host[-2:]}"


def summarize_exception(error: Exception, maximum_length: int = 200) -> str:
    """Provide an exception class summary without serializing request credentials."""
    message = str(error).replace("\n", " ").strip()
    if not message:
        return error.__class__.__name__
    return f"{error.__class__.__name__}: {message[:maximum_length]}"


def summarize_text(value: str | None, maximum_length: int = 300) -> str:
    """Collapse whitespace and truncate free-form remote error text for logs."""
    if value is None:
        return ""
    cleaned = " ".join(value.split()).strip()
    if not cleaned:
        return ""
    if len(cleaned) <= maximum_length:
        return cleaned
    return cleaned[:maximum_length] + "..."


def summarize_microsoft_error_payload(payload: object, *, maximum_length: int = 300) -> str:
    """Extract Microsoft OAuth/Graph error fields without leaking response bodies wholesale."""
    if not isinstance(payload, dict):
        return ""

    oauth_error = payload.get("error")
    if isinstance(oauth_error, str) and oauth_error.strip():
        description = payload.get("error_description")
        description_text = summarize_text(
            description if isinstance(description, str) else None,
            maximum_length=maximum_length,
        )
        if description_text:
            return f"error={oauth_error.strip()} description={description_text}"
        return f"error={oauth_error.strip()}"

    graph_error = payload.get("error")
    if isinstance(graph_error, dict):
        code = graph_error.get("code")
        message = graph_error.get("message")
        code_text = code.strip() if isinstance(code, str) and code.strip() else None
        message_text = summarize_text(
            message if isinstance(message, str) else None,
            maximum_length=maximum_length,
        )
        parts: list[str] = []
        if code_text:
            parts.append(f"code={code_text}")
        if message_text:
            parts.append(f"message={message_text}")
        return " ".join(parts)

    return ""
