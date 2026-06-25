from __future__ import annotations

import base64
import re
import unicodedata

_ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\ufeff]")
_NON_TEXT = re.compile(r"[^a-z0-9\s]+")
_WHITESPACE = re.compile(r"\s+")
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
# Runs of single letters separated by spaces/punctuation: "i g n o r e", "i.g.n.o.r.e".
_SPLIT_LETTERS = re.compile(r"\b(?:[a-z][ \t\.\-_*|]){2,}[a-z]\b")
_SEP_CHARS = re.compile(r"[ \t\.\-_*|]")


def normalize_basic(text: str) -> str:
    """Lowercase, fold unicode look-alikes, strip zero-width chars, and collapse
    punctuation/whitespace so spacing tricks match the same as plain text."""
    folded = unicodedata.normalize("NFKC", text)
    folded = _ZERO_WIDTH.sub("", folded).lower()
    folded = _NON_TEXT.sub(" ", folded)
    return _WHITESPACE.sub(" ", folded).strip()


def _join_split_letters(lowered: str) -> str:
    return _SPLIT_LETTERS.sub(lambda m: _SEP_CHARS.sub("", m.group()), lowered)


def _decode_base64_blobs(text: str) -> list[str]:
    decoded: list[str] = []
    for token in _B64_TOKEN.findall(text):
        try:
            raw = base64.b64decode(token, validate=False)
            text_value = raw.decode("utf-8", errors="ignore")
            if text_value and any(c.isalpha() for c in text_value):
                decoded.append(text_value)
        except Exception:
            continue
    return decoded


def normalization_variants(text: str) -> list[str]:
    """Return several normalized views of the text. Patterns are matched against
    all of them, so obfuscation only has to be undone by one variant to be caught."""
    folded = unicodedata.normalize("NFKC", text)
    folded = _ZERO_WIDTH.sub("", folded).lower()

    variants = [
        normalize_basic(text),
        normalize_basic(_join_split_letters(folded)),
    ]
    for decoded in _decode_base64_blobs(text):
        variants.append(normalize_basic(decoded))

    seen: set[str] = set()
    unique: list[str] = []
    for variant in variants:
        if variant and variant not in seen:
            seen.add(variant)
            unique.append(variant)
    return unique
