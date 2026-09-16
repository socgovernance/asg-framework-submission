"""Unit test/s for Audit Logger, integration & decision records
Verifies that policy engines evaluation outcomes - PERMIT/BLOCK decision/s, rule match reasons, sequence numbering - are  
formatted & retained in the append only JSONL log
"""
import json
from audit_log import AuditWriter
from policy_engine import evaluate, load_manifest

MANIFEST = load_manifest("manifest.yaml")


def read_entries(path):
    with open(path) as f:
        return [json.loads(line) for line in f]


def test_permit_is_written(tmp_path):
    log = tmp_path / "audit.jsonl"
    w = AuditWriter(path=str(log))
    d = evaluate("siem_query", {"query_string": "x"}, MANIFEST, {})
    w.append("siem_query", {"query_string": "x"}, d)

    entries = read_entries(log)
    assert len(entries) == 1
    assert entries[0]["outcome"] == "PERMIT"
    assert entries[0]["tool_name"] == "siem_query"


def test_block_records_the_rule(tmp_path):
    log = tmp_path / "audit.jsonl"
    w = AuditWriter(path=str(log))
    d = evaluate("diagnostics_collect", {}, MANIFEST, {})
    w.append("diagnostics_collect", {}, d)

    assert read_entries(log)[0]["rule_matched"] == "TOOL_NOT_PERMITTED"


def test_entries_are_numbered_in_order(tmp_path):
    log = tmp_path / "audit.jsonl"
    w = AuditWriter(path=str(log))
    counts = {}
    for _ in range(3):
        d = evaluate("siem_query", {"query_string": "x"}, MANIFEST, counts)
        w.append("siem_query", {"query_string": "x"}, d)

    assert [e["entry_number"] for e in read_entries(log)] == [1, 2, 3]


def test_extra_fields_are_attached(tmp_path):
    log = tmp_path / "audit.jsonl"
    w = AuditWriter(path=str(log))
    d = evaluate("siem_query", {"query_string": "x"}, MANIFEST, {})
    w.append("siem_query", {"query_string": "x"}, d, extra={"similarity": 0.3038})

    assert read_entries(log)[0]["extra"]["similarity"] == 0.3038