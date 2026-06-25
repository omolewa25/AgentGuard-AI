import re

REDACTION = "[REDACTED]"

# Ordered so broader patterns run after specific ones.
SECRET_PATTERNS: dict[str, str] = {
    "openai_api_key": r"sk-[A-Za-z0-9]{20,}",
    "aws_access_key_id": r"AKIA[0-9A-Z]{16}",
    "private_key_block": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "bearer_token": r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}",
    "password_assignment": r"(?i)(?:password|passwd|pwd|secret|api[_-]?key)\s*[:=]\s*\S+",
}


def scan_secrets(text: str) -> list[str]:
    return [name for name, pattern in SECRET_PATTERNS.items() if re.search(pattern, text)]


def redact_secrets(text: str) -> tuple[str, list[str]]:
    matches: list[str] = []
    redacted = text
    for name, pattern in SECRET_PATTERNS.items():
        redacted, count = re.subn(pattern, REDACTION, redacted)
        if count:
            matches.append(name)
    return redacted, matches
