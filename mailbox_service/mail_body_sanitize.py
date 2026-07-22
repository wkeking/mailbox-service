"""Fixed-rule mail body sanitization before verification-code matching.

Rules are intentional and bounded. Callers must not supply untrusted regex.
"""

from __future__ import annotations

import re

_HEADER_LINE_PATTERN = re.compile(
    r"(?im)^(received|return-path|arc-|dkim-|authentication-results|mime-version|"
    r"content-type|message-id|from:|to:|subject:|date:)\b"
)
_SCRIPT_STYLE_PATTERN = re.compile(r"(?is)<(script|style).*?>.*?</\1>")
_HTML_TAG_PATTERN = re.compile(r"(?s)<[^>]+>")
_QP_SOFT_BREAK_PATTERN = re.compile(r"=\r?\n")
_WHITESPACE_PATTERN = re.compile(r"\s+")


def html_to_visible_text(html: str) -> str:
    """Strip script/style blocks and HTML tags, then collapse whitespace."""
    if not html:
        return ""
    text = _SCRIPT_STYLE_PATTERN.sub(" ", html)
    text = _HTML_TAG_PATTERN.sub(" ", text)
    text = _WHITESPACE_PATTERN.sub(" ", text)
    return text.strip()


def sanitize_mail_text(text: str) -> str:
    """Normalize raw provider payloads that may include RFC822 headers or HTML.

    1. If common email headers are present, keep only the body after the first blank line.
    2. Undo quoted-printable soft line breaks and common entities.
    3. If HTML-like, strip tags for code extraction.
    4. Collapse whitespace.
    """
    raw = text or ""
    if not raw:
        return ""

    if _HEADER_LINE_PATTERN.search(raw):
        parts = re.split(r"\r?\n\r?\n", raw, maxsplit=1)
        if len(parts) == 2 and parts[1].strip():
            raw = parts[1]

    raw = _QP_SOFT_BREAK_PATTERN.sub("", raw)
    raw = raw.replace("=3D", "=").replace("=20", " ")

    lower_raw = raw.lower()
    if "<html" in lower_raw or "<body" in lower_raw or "<div" in lower_raw:
        raw = html_to_visible_text(raw)
    else:
        raw = _WHITESPACE_PATTERN.sub(" ", raw).strip()

    return raw.strip()
