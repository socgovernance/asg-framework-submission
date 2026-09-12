""" 
Unit test for manifest membership

"""
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