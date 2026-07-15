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
