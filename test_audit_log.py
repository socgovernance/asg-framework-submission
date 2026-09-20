"""Unit test/s for Audit Logger, integration & decision records
Verifies that policy engines evaluation outcomes - PERMIT/BLOCK decision/s, rule match reasons, sequence numbering - are  
formatted & retained in the append only JSONL log

Now unit tests for hashchaining
"""
import json
import hashlib

from audit_log import AuditWriter
from policy_engine import evaluate, load_manifest

MANIFEST = load_manifest("manifest.yaml")

AGENT_ID = MANIFEST["agent_id"]


def read_entries(path):
    with open(path) as f:
        return [json.loads(line) for line in f]


def test_permit_is_written(tmp_path):
    log = tmp_path / "audit.jsonl"
    w = AuditWriter(path=str(log))
    d = evaluate("siem_query", {"query_string": "x"}, MANIFEST, {}, AGENT_ID)
    w.append("siem_query", {"query_string": "x"}, d)

    entries = read_entries(log)
    assert len(entries) == 1
    assert entries[0]["outcome"] == "PERMIT"
    assert entries[0]["tool_name"] == "siem_query"


def test_block_records_the_rule(tmp_path):
    log = tmp_path / "audit.jsonl"
    w = AuditWriter(path=str(log))
    d = evaluate("diagnostics_collect", {}, MANIFEST, {}, AGENT_ID)
    w.append("diagnostics_collect", {}, d)

    assert read_entries(log)[0]["rule_matched"] == "TOOL_NOT_PERMITTED"


def test_entries_are_numbered_in_order(tmp_path):
    log = tmp_path / "audit.jsonl"
    w = AuditWriter(path=str(log))
    counts = {}
    for _ in range(3):
        d = evaluate("siem_query", {"query_string": "x"}, MANIFEST, counts, AGENT_ID)
        w.append("siem_query", {"query_string": "x"}, d)

    assert [e["entry_number"] for e in read_entries(log)] == [1, 2, 3]


def test_extra_fields_are_attached(tmp_path):
    log = tmp_path / "audit.jsonl"
    w = AuditWriter(path=str(log))
    d = evaluate("siem_query", {"query_string": "x"}, MANIFEST, {}, AGENT_ID)
    w.append("siem_query", {"query_string": "x"}, d, extra={"similarity": 0.3038})

    assert read_entries(log)[0]["extra"]["similarity"] == 0.3038
    
    
    # test for hash chaining 

def test_first_entry_chains_from_genesis(tmp_path):
    log = tmp_path / "audit.jsonl"
    w = AuditWriter(path=str(log))
    d = evaluate("siem_query", {"query_string": "x"}, MANIFEST, {}, AGENT_ID)
    w.append("siem_query", {"query_string": "x"}, d)

    assert read_entries(log)[0]["prev_hash"] == "0" * 64


def test_each_entry_links_to_the_previous(tmp_path):
    log = tmp_path / "audit.jsonl"
    w = AuditWriter(path=str(log))
    counts = {}
    for _ in range(3):
        d = evaluate("siem_query", {"query_string": "x"}, MANIFEST, counts, AGENT_ID)
        w.append("siem_query", {"query_string": "x"}, d)

    entries = read_entries(log)
    for prev, current in zip(entries, entries[1:]):
        assert current["prev_hash"] == prev["chain_hash"]


def test_chain_hash_matches_recomputed_digest(tmp_path):
    log = tmp_path / "audit.jsonl"
    w = AuditWriter(path=str(log))
    d = evaluate("siem_query", {"query_string": "x"}, MANIFEST, {}, AGENT_ID)
    w.append("siem_query", {"query_string": "x"}, d)

    entry = read_entries(log)[0]
    body = {k: v for k, v in entry.items() if k not in ("prev_hash", "chain_hash")}
    serialised = json.dumps(body, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256((entry["prev_hash"] + serialised).encode()).hexdigest()

    assert entry["chain_hash"] == expected
    