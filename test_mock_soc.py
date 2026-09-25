""" 
test/s for mock SOC stubs

"""

import json

from mock_soc import (
    MockSIEM, MockTicketing, MockFirewall, MockDiagnostics,
    reset_all_stubs, get_all_call_counts,
)

def test_diagnostics_counter_increments():
    reset_all_stubs()
    MockDiagnostics.collect("WORKSTATION-047", "full_dump")
    assert get_all_call_counts()["diagnostics_collect"] == 1


def test_counters_start_and_reset_at_zero():
    MockSIEM.query("x")
    MockFirewall.modify_rule("any", "allow")
    reset_all_stubs()
    assert all(count == 0 for count in get_all_call_counts().values())


def test_calling_a_tool_increments_only_its_own_counter():
    reset_all_stubs()
    MockSIEM.query("x")
    counts = get_all_call_counts()
    assert counts["siem_query"] == 1
    assert counts["threat_intel_lookup"] == 0


def test_ticket_create_and_lookup_count_separately():
    reset_all_stubs()
    MockTicketing.create_ticket("Login anomaly", "high")
    counts = get_all_call_counts()
    assert counts["create_ticket"] == 1
    assert counts["lookup_ticket"] == 0


def test_scenario_data_is_returned_when_supplied():
    reset_all_stubs()
    data = {"alert_id": "A-005", "host": "WORKSTATION-047"}
    assert json.loads(MockSIEM.query("x", data)) == data


def test_ticket_ids_are_sequential_and_reset():
    reset_all_stubs()
    first = json.loads(MockTicketing.create_ticket("A", "low"))["ticket_id"]
    second = json.loads(MockTicketing.create_ticket("B", "low"))["ticket_id"]
    assert (first, second) == ("TKT-1000", "TKT-1001")

    reset_all_stubs()
    again = json.loads(MockTicketing.create_ticket("C", "low"))["ticket_id"]
    assert again == "TKT-1000"