from __future__ import annotations

import re

from agentguard.security.normalize import normalization_variants

# High-confidence phrases: presence is a strong injection signal.
STRONG_PATTERNS: dict[str, float] = {
    "ignore previous instructions": 0.9,
    "ignore all previous instructions": 0.9,
    "send api key": 0.9,
    "send password": 0.9,
    "reveal secret": 0.85,
    "jailbreak": 0.85,
}

# Low-confidence phrases: suspicious in context but common in benign text, so
# they score low on their own and are further discounted for questions.
WEAK_PATTERNS: dict[str, float] = {
    "system prompt": 0.35,
    "developer message": 0.35,
    "bypass": 0.3,
}

DEFAULT_REGEX_PATTERNS: list[str] = [
    r"\b(?:ignore|disregard|forget|override)\b.{0,40}\b(?:previous|prior|earlier|above|all)\b.{0,40}\b(?:instruction|direction|prompt|rule|message)s?\b",
    r"\breveal\b.{0,40}\b(?:system prompt|secret|secrets|api ?key|password|credential)s?\b",
    r"\b(?:exfiltrate|leak|send|email|post|upload)\b.{0,40}\b(?:api ?key|password|secret|credential|token)s?\b",
    r"\b(?:jailbreak|dan mode|developer mode)\b",
    r"\bact as\b.{0,20}\b(?:unrestricted|no rules|no restrictions|no guardrails)\b",
]
_REGEX_WEIGHT = 0.85

# Backward-compatible flat list of all known phrases.
DEFAULT_PATTERNS: list[str] = list(STRONG_PATTERNS) + list(WEAK_PATTERNS)

_QUESTION_PREFIX = re.compile(r"^(?:what|why|how|who|when|where|which|can|could|is|are|do|does|define|explain)\b")


def _looks_like_question(normalized: str) -> bool:
    return bool(_QUESTION_PREFIX.match(normalized))


def _phrase_in_variants(phrase: str, variants: list[str]) -> bool:
    needle = phrase.replace(" ", " ").strip()
    return any(needle in variant for variant in variants)


def detect_prompt_injection(
    text: str,
    extra_patterns: list[str] | None = None,
    extra_regex: list[str] | None = None,
) -> dict:
    variants = normalization_variants(text)
    primary = variants[0] if variants else ""
    is_question = _looks_like_question(primary)

    matches: list[str] = []
    severity = 0.0

    for phrase, weight in STRONG_PATTERNS.items():
        if _phrase_in_variants(phrase, variants):
            matches.append(phrase)
            severity = max(severity, weight)

    for phrase, weight in WEAK_PATTERNS.items():
        if _phrase_in_variants(phrase, variants):
            matches.append(phrase)
            effective = weight * 0.5 if is_question else weight
            severity = max(severity, effective)

    for phrase in extra_patterns or []:
        if _phrase_in_variants(phrase.lower(), variants):
            matches.append(phrase)
            severity = max(severity, 0.85)

    all_regex = DEFAULT_REGEX_PATTERNS + list(extra_regex or [])
    for pattern in all_regex:
        if any(re.search(pattern, variant) for variant in variants):
            matches.append(pattern)
            severity = max(severity, _REGEX_WEIGHT)

    # If a hit only survived an aggressive normalization variant (not the basic
    # one), the obfuscation itself is a signal — nudge severity up.
    if matches and not _hit_in_basic(matches, primary):
        severity = min(1.0, severity + 0.1)

    return {"detected": severity >= 0.5, "severity": round(severity, 3), "matches": matches}


def _hit_in_basic(matches: list[str], primary: str) -> bool:
    for match in matches:
        if match in primary:
            return True
        try:
            if re.search(match, primary):
                return True
        except re.error:
            continue
    return False
