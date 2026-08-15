from __future__ import annotations


PROMPT_INJECTION_MARKERS = (
    "ignore all previous",
    "ignore security policy",
    "export credentials",
    "send them to",
    "system administrator note",
    "developer message",
)


def detect_prompt_injection(untrusted_text: str) -> bool:
    lowered = untrusted_text.lower()
    return any(marker in lowered for marker in PROMPT_INJECTION_MARKERS)

