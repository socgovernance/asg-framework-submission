""" Test for manifest membership"""
from policy_engine import evaluate, load_manifest, Outcome

MANIFEST = load_manifest("manifest.yaml")


def test_permitted_tool_is_allowed():
    d = evaluate("siem_query", {"query_string": "alert-1"}, MANIFEST, {})
    assert d.outcome is Outcome.PERMIT


def test_tool_not_in_manifest_is_blocked():
    d = evaluate("diagnostics_collect", {}, MANIFEST, {})
    assert d.outcome is Outcome.BLOCK
    assert d.rule_matched == "TOOL_NOT_PERMITTED"


def test_firewall_modify_is_blocked():
    d = evaluate("firewall_modify", {"rule": "allow any"}, MANIFEST, {})
    assert d.outcome is Outcome.BLOCK
    
    
def test_calls_within_budget_are_allowed():
    counts = {}
    for _ in range(5):                      # siem_query allows 5
        d = evaluate("siem_query", {"query_string": "x"}, MANIFEST, counts)
        assert d.outcome is Outcome.PERMIT

""" tests for session limit (aka budget)"""
def test_call_over_budget_is_blocked():
    counts = {}
    for _ in range(5):
        evaluate("siem_query", {"query_string": "x"}, MANIFEST, counts)
    d = evaluate("siem_query", {"query_string": "x"}, MANIFEST, counts)
    assert d.outcome is Outcome.BLOCK
    assert d.rule_matched == "RATE_LIMIT_EXCEEDED"


def test_budgets_are_per_tool():
    counts = {}
    for _ in range(5):
        evaluate("siem_query", {"query_string": "x"}, MANIFEST, counts)
    d = evaluate("lookup_ticket", {"ticket_id": "T-1"}, MANIFEST, counts)
    assert d.outcome is Outcome.PERMIT


def test_blocked_calls_do_not_consume_budget():
    counts = {}
    evaluate("firewall_modify", {}, MANIFEST, counts)
    assert "firewall_modify" not in counts