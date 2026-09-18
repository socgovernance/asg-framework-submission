"""Checks wheather an audit log has been tampered with.

Reads the log file sequentially, recalculating each entry's hash using 
its own content and the previous entry's hash. A mismatch indicates that 
the record was altered or an earlier line was removed.

Verification stops at the first error: once the chain is broken, 
subsequent entries cannot be trusted.
"""

import hashlib
import json

GENESIS_HASH = "0" * 64


def _expected_hash(entry, prev_hash):
    """Recalculates the expected SHA-256 hash for a log entry.

    To match  audit_log.py is built
    Strip  existing hash fields ('chain_hash' and 'prev_chain_hash').
    Format the remaining payload as compct JSON with sorted keys
    Prepend the previous entry's hash, then run SHA-256 on combined string
    """
    # Sequential SHA-256 chaining over a deterministic JSON serialisation
    # Chain construction follows Haber and Stornetta (1991) - the secure
    # audit log application follows Schneier and Kelsey (1999)
    body = {k: v for k, v in entry.items() if k not in ("prev_hash", "chain_hash")}
    serialised = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + serialised).encode()).hexdigest()


def verify(path):
    with open(path) as f:
        lines = [line for line in f if line.strip()]

    results = []
    prev_hash = GENESIS_HASH
    break_at = None

    for line in lines:
        entry = json.loads(line)
        expected = _expected_hash(entry, prev_hash)
        ok = entry.get("chain_hash") == expected

        results.append({
            "entry_number": entry.get("entry_number"),
            "tool_name": entry.get("tool_name"),
            "outcome": entry.get("outcome"),
            "ok": ok,
        })

        if not ok:
            break_at = entry.get("entry_number")
            break

        prev_hash = entry["chain_hash"]

    return {
        "path": path,
        "entries": len(lines),
        "verified": len(results),
        "intact": break_at is None,
        "break_at": break_at,
        "results": results,
    }