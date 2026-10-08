"""Sanitizer for untrusted GitHub PR text, comments, diffs, and filenames."""

import re
import unicodedata

from pydantic import BaseModel, Field


class UntrustedText(BaseModel):
    """Normalized, delimited container for untrusted external PR content."""

    source: str
    content: str
    sanitized_content: str
    detected_patterns: list[str] = Field(default_factory=list)
    truncated: bool = False


# Bidi control characters and zero-width spaces that could obfuscate text or fool parsers
_DISALLOWED_CODEPOINTS = {
    0x200B,  # Zero-width space
    0x200C,  # Zero-width non-joiner
    0x200D,  # Zero-width joiner
    0x200E,  # Left-to-right mark
    0x200F,  # Right-to-left mark
    0x202A,  # Left-to-right embedding
    0x202B,  # Right-to-left embedding
    0x202C,  # Pop directional formatting
    0x202D,  # Left-to-right override
    0x202E,  # Right-to-left override
    0x2066,  # Left-to-right isolate
    0x2067,  # Right-to-left isolate
    0x2068,  # First strong isolate
    0x2069,  # Pop directional isolate
    0xFEFF,  # Byte order mark / zero-width no-break space
    0x0000,  # Null byte
}


def clean_control_characters(text: str) -> str:
    """Strip dangerous control characters while preserving code whitespace and newlines."""
    cleaned_chars = []
    for ch in text:
        cp = ord(ch)
        if cp in _DISALLOWED_CODEPOINTS:
            continue
        # Allow standard whitespaces: tab (9), newline (10), carriage return (13)
        if cp in (9, 10, 13):
            cleaned_chars.append(ch)
            continue
        # Strip all other ASCII and Unicode control characters (Cc, Cf)
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs"):
            continue
        cleaned_chars.append(ch)
    return "".join(cleaned_chars)


def escape_xml_delimiters(text: str) -> str:
    """Escape attempts to break out of untrusted_input XML isolation delimiters."""
    # Defend against closing tag injections like </untrusted_input>
    escaped = re.sub(
        r"<\s*/\s*untrusted_input\s*>",
        lambda m: m.group(0).replace("<", "&lt;").replace(">", "&gt;"),
        text,
        flags=re.IGNORECASE,
    )
    # Defend against system / instruction tag breakouts
    escaped = re.sub(
        r"<\s*/?\s*(?:system|instructions|developer|prompt)\s*>",
        lambda m: m.group(0).replace("<", "&lt;").replace(">", "&gt;"),
        escaped,
        flags=re.IGNORECASE,
    )
    return escaped


def sanitize_untrusted_text(
    content: str,
    source: str,
    max_chars: int | None = None,
) -> UntrustedText:
    """Sanitize and wrap untrusted content within strict XML isolation delimiters.

    Preserves code indentation, valid strings, comments, and structure while
    neutralizing control-character tricks, XML delimiter breakouts, and memory bombs.
    """
    if content is None:
        content = ""

    truncated = False
    cleaned = clean_control_characters(content)
    cleaned = escape_xml_delimiters(cleaned)

    if max_chars is not None and len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars] + f"\n\n[TRUNCATED: Exceeded safety budget of {max_chars} chars]"
        truncated = True

    # Delimit safely for LLM consumption
    delimited = f'<untrusted_input source="{source}">\n{cleaned}\n</untrusted_input>'

    return UntrustedText(
        source=source,
        content=content,
        sanitized_content=delimited,
        truncated=truncated,
    )
