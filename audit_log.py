"""
# Layer 3: Audit Trail
# Appends each decision to disk as its own JSON object per line
# Records are append only so nothing gets modified or delete d
# Cryptographic chaining is next -this step just is for the raw logs onto disk
# Adding - each record's hash covers  its own content & the hash of the previous record
"""

import json
import uuid
import hashlib
from datetime import datetime, timezone

GENESIS_HASH = "0" * 64


class AuditWriter:
    """Writes policy decisions for a session to a JSONL file
Built as a class (rather than a function) so the instance can track the 
entry counter across multiple tool calls for the duration of the session
    """

    def __init__(self, path="audit.jsonl", manifest_hash="unknown", session_id=None):
        # Because there's no item before the very first entry, we give it a fixed starting hash. This way,
        # every record in the chain follows the exact same format from beginining 
        self.prev_hash = GENESIS_HASH
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
            
        # Linear hash-chaining (Haber & Stornetta, 1991) over a deterministic
        # JSON serialisation - sorted keys and no whitespace, so the same
        # record always produces the same digest
        serialised = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        chain_hash = hashlib.sha256((self.prev_hash + serialised).encode()).hexdigest()

        # Lets think of ths as signing a document-you can't include the signature in the words 
        # we hash only the original data fields first, then attach prev and chain hash
        entry["prev_hash"] = self.prev_hash
        entry["chain_hash"] = chain_hash

        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")
            
        self.prev_hash = chain_hash

        return entry
    
def compute_manifest_hash(manifest):
    """SHA-256 of the manifest, recorded in every audit entry.

    This is what ties a decision to the policy that authorised it - if
    the manifest is edited between runs, the hash in the logs changes
    and the difference is visible.
    """
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()

    