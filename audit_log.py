"""
# Layer 3: Audit Trail
# Appends each decision to disk as its own JSON object per line
# Records are append only so nothing gets modified or delete d
# Cryptographic chaining is next -this step just is for the raw logs onto disk

"""

import json
import uuid
from datetime import datetime, timezone


class AuditWriter:
    """Writes policy decisions for a session to a JSONL file
Built as a class (rather than a function) so the instance can track the 
entry counter across multiple tool calls for the duration of the session
    """

    def __init__(self, path="audit.jsonl", manifest_hash="unknown", session_id=None):
        self.path = path
        self.manifest_hash = manifest_hash
        self.session_id = session_id or str(uuid.uuid4())
        self.entry_count = 0

    def append(self, tool_name, params, decision, extra=None):
        self.entry_count += 1

        entry = {
            "entry_number": self.entry_count,
            "session_id": self.session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "manifest_hash": self.manifest_hash,
            "tool_name": tool_name,
            "raw_input": params,
            "outcome": decision.outcome.value,
            "rule_matched": decision.rule_matched,
            "reason": decision.reason,
            "latency_ms": decision.latency_ms,
            # Fixed for every entry - records which regulatory categories
            # this log is intended to satisfy (ONLY EU AI,removed NIST)
            "regulatory_fields": {
                "eu_ai_act_art12_category": "automated_decision_record",
            },
        }

        # to hold optional metadata outside standard log schema,
        # such as  semantic sanitizers similarity score
        if extra:
            entry["extra"] = extra

        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")

        return entry