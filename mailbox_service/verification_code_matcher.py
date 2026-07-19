"""Bounded, linear-time verification-code matchers without untrusted Python regex."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, model_validator


class VerificationCodePatternType(StrEnum):
    """Server-side pattern families callers may select."""

    DIGITS = "digits"
    ALPHANUMERIC = "alphanumeric"
    XAI = "xai"


# Deprecated code_regex values that map to fixed presets (never executed as Python re).
SAFE_CODE_REGEX_PRESETS: dict[str, VerificationCodePatternType] = {
    r"\b(\d{4,8})\b": VerificationCodePatternType.DIGITS,
    r"\d{4,8}": VerificationCodePatternType.DIGITS,
    "digits": VerificationCodePatternType.DIGITS,
    "alphanumeric": VerificationCodePatternType.ALPHANUMERIC,
    "xai": VerificationCodePatternType.XAI,
    r"\b([A-Z0-9]{3}-[A-Z0-9]{3})\b": VerificationCodePatternType.XAI,
}


class VerificationCodePatternOptions(BaseModel):
    """Bounded pattern options for verification-code extraction."""

    pattern_type: VerificationCodePatternType = VerificationCodePatternType.DIGITS
    minimum_length: int = Field(default=4, ge=4, le=16)
    maximum_length: int = Field(default=8, ge=4, le=16)
    prefix: str | None = Field(default=None, max_length=32)

    @model_validator(mode="after")
    def validate_length_order(self) -> VerificationCodePatternOptions:
        if self.minimum_length > self.maximum_length:
            raise ValueError("minimum_length 不能大于 maximum_length")
        if self.prefix is not None:
            normalized_prefix = self.prefix.strip()
            self.prefix = normalized_prefix or None
        return self


class SafeVerificationCodeMatcher:
    """Linear scan matcher over subject/body with hard character-class bounds."""

    def __init__(self, options: VerificationCodePatternOptions) -> None:
        self._options = options

    @classmethod
    def from_options(cls, options: VerificationCodePatternOptions) -> SafeVerificationCodeMatcher:
        """Build a matcher from validated options."""
        return cls(options)

    @classmethod
    def from_deprecated_code_regex(cls, code_regex: str | None) -> SafeVerificationCodeMatcher | None:
        """Map a deprecated safe preset string to a matcher, or return None when unset."""
        if code_regex is None:
            return None
        normalized = code_regex.strip()
        if not normalized:
            return None
        pattern_type = SAFE_CODE_REGEX_PRESETS.get(normalized)
        if pattern_type is None:
            raise ValueError(
                "code_regex 已废弃且仅接受服务端登记的安全 preset"
                "（digits / alphanumeric / xai / 对应固定模板）"
            )
        return cls(
            VerificationCodePatternOptions(
                pattern_type=pattern_type,
                minimum_length=4 if pattern_type != VerificationCodePatternType.XAI else 7,
                maximum_length=8 if pattern_type != VerificationCodePatternType.XAI else 7,
            )
        )

    def search(self, subject: str, body: str) -> str | None:
        """Return the first matching code or None. Runs in O(n) over the joined text."""
        subject_value = subject or ""
        body_value = body or ""

        if self._options.pattern_type == VerificationCodePatternType.XAI:
            return self._search_xai(subject_value, body_value)

        searchable_text = "\n".join(part for part in [subject_value, body_value] if part)
        if self._options.prefix:
            return self._search_with_prefix(searchable_text, self._options.prefix)
        return self._search_token(searchable_text)

    def _search_xai(self, subject: str, body: str) -> str | None:
        subject_code = self._match_xai_token(subject, require_xai_label=True)
        if subject_code is not None:
            return subject_code
        searchable_text = "\n".join(part for part in [subject, body] if part)
        return self._match_xai_token(searchable_text, require_xai_label=False)

    def _match_xai_token(self, text: str, *, require_xai_label: bool) -> str | None:
        text_length = len(text)
        index = 0
        while index < text_length:
            if not self._is_alphanumeric(text[index]):
                index += 1
                continue
            start_index = index
            while index < text_length and self._is_alphanumeric(text[index]):
                index += 1
            first_segment = text[start_index:index]
            if len(first_segment) != 3:
                continue
            if index >= text_length or text[index] != "-":
                continue
            dash_index = index
            index += 1
            second_start = index
            while index < text_length and self._is_alphanumeric(text[index]):
                index += 1
            second_segment = text[second_start:index]
            if len(second_segment) != 3:
                continue
            if require_xai_label:
                remaining = text[index:].lstrip()
                if not remaining.upper().startswith("XAI"):
                    continue
                boundary_index = len(remaining) - len(remaining.lstrip())
                # Accept "xAI" optionally followed by non-alnum or end.
                label = remaining[:3]
                if label.upper() != "XAI":
                    continue
                if len(remaining) > 3 and self._is_alphanumeric(remaining[3]):
                    continue
            else:
                # Token boundary: not embedded inside a longer alnum run.
                if start_index > 0 and self._is_alphanumeric(text[start_index - 1]):
                    continue
                if index < text_length and self._is_alphanumeric(text[index]):
                    continue
            return f"{first_segment.upper()}-{second_segment.upper()}"
        return None

    def _search_with_prefix(self, text: str, prefix: str) -> str | None:
        prefix_lower = prefix.lower()
        text_lower = text.lower()
        search_from = 0
        while True:
            prefix_index = text_lower.find(prefix_lower, search_from)
            if prefix_index < 0:
                return None
            code_start = prefix_index + len(prefix)
            code = self._read_code_at(text, code_start)
            if code is not None:
                return code
            search_from = prefix_index + 1

    def _search_token(self, text: str) -> str | None:
        text_length = len(text)
        index = 0
        while index < text_length:
            if not self._is_code_char(text[index]):
                index += 1
                continue
            start_index = index
            while index < text_length and self._is_code_char(text[index]):
                index += 1
            token = text[start_index:index]
            if self._options.minimum_length <= len(token) <= self._options.maximum_length:
                if start_index > 0 and self._is_code_char(text[start_index - 1]):
                    continue
                if index < text_length and self._is_code_char(text[index]):
                    continue
                return token
        return None

    def _read_code_at(self, text: str, start_index: int) -> str | None:
        index = start_index
        text_length = len(text)
        while index < text_length and text[index].isspace():
            index += 1
        code_start = index
        while index < text_length and self._is_code_char(text[index]):
            index += 1
        token = text[code_start:index]
        if self._options.minimum_length <= len(token) <= self._options.maximum_length:
            return token
        return None

    def _is_code_char(self, character: str) -> bool:
        if self._options.pattern_type == VerificationCodePatternType.DIGITS:
            return character.isdigit()
        return self._is_alphanumeric(character)

    @staticmethod
    def _is_alphanumeric(character: str) -> bool:
        return ("0" <= character <= "9") or ("A" <= character <= "Z") or ("a" <= character <= "z")


# Hard budgets for mail body scanning (bytes of UTF-8 / character counts used as upper bounds).
MAX_MESSAGE_BODY_BYTES = 64 * 1024
MAX_SCAN_BODY_BYTES = 512 * 1024
MAX_REQUEST_BODY_BYTES = 1024 * 1024


def truncate_text_to_byte_budget(text: str, maximum_bytes: int) -> str:
    """Truncate text so its UTF-8 encoding does not exceed ``maximum_bytes``."""
    if maximum_bytes <= 0:
        return ""
    encoded = text.encode("utf-8")
    if len(encoded) <= maximum_bytes:
        return text
    truncated = encoded[:maximum_bytes]
    # Drop incomplete trailing UTF-8 sequence.
    while truncated and (truncated[-1] & 0xC0) == 0x80:
        truncated = truncated[:-1]
    if truncated and (truncated[-1] & 0xC0) == 0xC0:
        truncated = truncated[:-1]
    return truncated.decode("utf-8", errors="ignore")
