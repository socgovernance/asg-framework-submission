"""Layer 2 (output side) -  Before the agent sends anything out, Layer 2 strips away sensitive details 
like passwords and personal data.The audit log only notes that a secret was caught & blocked but never 
the secret itself

Saving the actual password to a log file wouldn't stop the leak, it would just move it to a different place
"""

import re

# (pattern, label, replacement)
CREDENTIAL_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS_ACCESS_KEY", "[REDACTED_AWS_KEY]"),
    (r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
     "AWS_SECRET_KEY_CANDIDATE", "[REDACTED_SECRET]"),
    (r"ghp_[A-Za-z0-9]{36}", "GITHUB_TOKEN", "[REDACTED_GH_TOKEN]"),
    (r"gho_[A-Za-z0-9]{36}", "GITHUB_OAUTH_TOKEN", "[REDACTED_GH_TOKEN]"),
    (r"sk-[A-Za-z0-9]{32,}", "API_SECRET_KEY", "[REDACTED_API_KEY]"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
     "PRIVATE_KEY_HEADER", "[REDACTED_PRIVATE_KEY]"),
    (r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]{16,}",
     "BASIC_AUTH_HEADER", "[REDACTED_BASIC_AUTH]"),
    (r"Authorization:\s*Bearer\s+[A-Za-z0-9\-_\.]{16,}",
     "BEARER_TOKEN", "[REDACTED_BEARER_TOKEN]"),
    (r"(?i)password[\"']?\s*[:=]\s*[\"']?[^\s\"',}]{6,}",
     "PASSWORD_FIELD", "[REDACTED_PASSWORD]"),
]

# Off by default - alert payloads legitimately contain email addresses
# that an analyst needs to see when triaging
PII_PATTERNS = [
    (r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
     "EMAIL_ADDRESS", "[REDACTED_EMAIL]"),
]

_CREDENTIALS = [(re.compile(p), label, token) for p, label, token in CREDENTIAL_PATTERNS]
_PII = [(re.compile(p), label, token) for p, label, token in PII_PATTERNS]


def _apply(patterns, text, findings):
    for pattern, label, token in patterns:
        if pattern.search(text):
            findings.append({"label": label})
            text = pattern.sub(token, text)
    return text


def sanitise_output(text, redact_pii=False):
    """Masks detected credentials with safe placeholders
    Instead of throwing  the entire message like the input filter does,
    this edits the text in place, so the analyst still gets the tool's actual
    output, but with ONLY the sensitive secrets removed
    """
    findings = []
    sanitised = _apply(_CREDENTIALS, text, findings)
    if redact_pii:
        sanitised = _apply(_PII, sanitised, findings)

    return {
        "clean": len(findings) == 0,
        "findings": findings,
        "sanitised_text": sanitised,
    }