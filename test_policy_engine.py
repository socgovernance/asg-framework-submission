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
    
    """ test/s for parameter validation"""
def test_missing_required_param_is_blocked():
    d = evaluate("siem_query", {}, MANIFEST, {})
    assert d.outcome is Outcome.BLOCK
    assert d.rule_matched == "MISSING_REQUIRED_PARAM"

def test_wrong_param_type_is_blocked():
    d = evaluate("siem_query", {"query_string": 12345}, MANIFEST, {})
    assert d.outcome is Outcome.BLOCK
    assert d.rule_matched == "PARAM_TYPE_MISMATCH"


def test_create_ticket_requires_both_params():
    d = evaluate("create_ticket", {"title": "Suspicious login"}, MANIFEST, {})
    assert d.outcome is Outcome.BLOCK
    assert d.rule_matched == "MISSING_REQUIRED_PARAM"


def test_failed_param_check_does_not_consume_budget():
    counts = {}
    evaluate("siem_query", {}, MANIFEST, counts)
    assert "siem_query" not in counts
    
def test_over_length_param_is_blocked():
    d = evaluate("siem_query", {"query_string": "x" * 301}, MANIFEST, {})
    assert d.outcome is Outcome.BLOCK
    assert d.rule_matched == "PARAM_TOO_LONG"


def test_param_at_exact_max_length_is_allowed():
    d = evaluate("siem_query", {"query_string": "x" * 300}, MANIFEST, {})
    assert d.outcome is Outcome.PERMIT


def test_disallowed_value_is_blocked():
    d = evaluate("create_ticket", {"title": "Login anomaly", "severity": "urgent"},
                 MANIFEST, {})
    assert d.outcome is Outcome.BLOCK
    assert d.rule_matched == "PARAM_VALUE_NOT_ALLOWED"


def test_allowed_value_is_case_insensitive():
    d = evaluate("create_ticket", {"title": "Login anomaly", "severity": "High"},
                 MANIFEST, {})
    assert d.outcome is Outcome.PERMIT
    
    
    
    