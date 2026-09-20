""" Test/s for verify chain """

import json
from audit_log import AuditWriter
from policy_engine import evaluate, load_manifest
from verify_chain import verify

MANIFEST = load_manifest("manifest.yaml")
AGENT_ID = MANIFEST["agent_id"]


def write_log(path, n=3):
    w = AuditWriter(path=str(path))
    counts = {}
    for _ in range(n):
        d = evaluate("siem_query", {"query_string": "x"}, MANIFEST, counts, AGENT_ID)
        w.append("siem_query", {"query_string": "x"}, d)


def read_lines(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def rewrite(path, entries):
    with open(path, "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


def test_untouched_log_verifies(tmp_path):
    log = tmp_path / "audit.jsonl"
    write_log(log)
    report = verify(str(log))
    assert report["intact"] is True
    assert report["break_at"] is None


def test_modified_entry_is_detected(tmp_path):
    log = tmp_path / "audit.jsonl"
    write_log(log)
    entries = read_lines(log)
    entries[1]["outcome"] = "PERMIT" if entries[1]["outcome"] == "BLOCK" else "BLOCK"
    rewrite(log, entries)

    report = verify(str(log))
    assert report["intact"] is False
    assert report["break_at"] == 2


def test_deleted_entry_is_detected(tmp_path):
    log = tmp_path / "audit.jsonl"
    write_log(log)
    entries = read_lines(log)
    del entries[1]
    rewrite(log, entries)

    report = verify(str(log))
    assert report["intact"] is False


def test_empty_log_is_intact(tmp_path):
    log = tmp_path / "audit.jsonl"
    log.write_text("")
    assert verify(str(log))["intact"] is True