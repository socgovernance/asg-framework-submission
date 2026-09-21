"""Layer 2 (input side): checks tool output for prompt injection before
the agent sees it.

Two stages  -  Stage 1 matches known injection phrasings with regex - less expensive,
and catches the obvious cases. Stage 2 (added next) scores the text for
injection -  for payloads written to avoid the keyword/s

Stage 1 runs first because it costs nothing. If it fires there is no
neeed to embedd the text
"""

import re

# Phrasings from published injection taxonomies (Perez & Ribeiro,
# 2022 - Greshake et al., 2023, label record/s tthe kind of attack the
# pattern represents, and write to the audit log
INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?previous\s+instructions?", "INSTRUCTION_OVERRIDE"),
    (r"disregard\s+(your\s+)?(previous\s+)?instructions?", "INSTRUCTION_OVERRIDE"),
    (r"forget\s+everything", "INSTRUCTION_OVERRIDE"),
    (r"you\s+are\s+now\s+in\s+(\w+\s+)?mode", "ROLE_REASSIGNMENT"),
    (r"diagnostic\s+mode", "ROLE_REASSIGNMENT"),
    (r"new\s+task\s*[:\-]", "GOAL_SUBSTITUTION"),
    (r"your\s+new\s+(role|task|instructions?)\s+(is|are)", "GOAL_SUBSTITUTION"),
    (r"\bsystem\s+message\s*[:\-]", "AUTHORITY_IMPERSONATION"),
    (r"\burgent\s+system\s+message\b", "AUTHORITY_IMPERSONATION"),
    (r"\badministrator\s*[:\-]", "AUTHORITY_IMPERSONATION"),
    (r"security\s+override", "AUTHORITY_IMPERSONATION"),
    (r"mandatory\s+audit\s+procedure", "AUTHORITY_IMPERSONATION"),
    (r"ncsc\s+ir\s+procedure", "AUTHORITY_IMPERSONATION"),
    (r"reference\s*:\s*proc-?\d", "AUTHORITY_IMPERSONATION"),
    (r"ciso\s+authorisation", "AUTHORITY_IMPERSONATION"),
    (r"do\s+not\s+create\s+a\s+(new\s+)?ticket", "OUTPUT_SUPPRESSION"),
    (r"respond\s+only\s+with", "OUTPUT_SUPPRESSION"),
    (r"output\s+(the\s+)?(full\s+)?(contents?\s+of\s+)?your\s+system\s+prompt", "PROMPT_LEAK"),
    (r"reveal\s+your\s+(system\s+)?prompt", "PROMPT_LEAK"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), label) for p, label in INJECTION_PATTERNS]


def pattern_scan(text):
    """Return details of the first pattern  matche or return nothing"""
    for pattern, label in _COMPILED:
        match = pattern.search(text)
        if match:
            return {
                "signature": label,
                "matched_pattern": pattern.pattern,
                "matched_text": match.group(0),
            }
    return None


def sanitise_input(text):
    """Check text for injection, replaces the text completely if found -
    partial removal would leave an attacker the control
    """
    hit = pattern_scan(text)
    if hit:
        return {
            "clean": False,
            "stage": "pattern",
            "detail": hit,
            "sanitised_text": "[SANITISED: injection pattern removed]",
        }

    return {"clean": True, "stage": None, "detail": None, "sanitised_text": text}