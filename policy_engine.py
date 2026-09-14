"""
Layer 1 - policy engine (first entry point)

Before any tool call runs, it is checked strictly against the manifest (manifest.yaml). A step by step order is followedd.
Order as shown below - is tool allowed then,  is call budget ok theb, are parameters fine then,  permit.

"""
import yaml
""" this is to check manifest.yaml"""
import time
from dataclasses import dataclass
from enum import Enum


class Outcome(Enum):
    PERMIT = "PERMIT"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    rule_matched: str
    reason: str
    latency_ms: float


def load_manifest(path):
    with open(path) as f:
        return yaml.safe_load(f)


def _find_tool(tool_name, manifest):
    for tool in manifest.get("permitted_tools", []):
        if tool["tool_name"] == tool_name:
            return tool
    return None


def evaluate(tool_name, params, manifest, session_counts):
    start = time.monotonic()

    def elapsed():
        return round((time.monotonic() - start) * 1000, 3)

    # Deny by Default : so if the tool is not listed, it NOT allowed
    tool = _find_tool(tool_name, manifest)
    if tool is None:
        return Decision(
            Outcome.BLOCK,
            "TOOL_NOT_PERMITTED",
            f"'{tool_name}' is not in this agent's capability manifest.",
            elapsed(),
        )

    # Each tool has a session limit, but only allowed calls count against it
    # Blocked requests are free/not counted
    used = session_counts.get(tool_name, 0)
    limit = tool.get("max_calls_per_session")
    if limit is not None and used >= limit:
        return Decision(
            Outcome.BLOCK,
            "RATE_LIMIT_EXCEEDED",
            f"'{tool_name}' has reached its session limit of {limit} calls.",
            elapsed(),
        )
    
    # Parameters are checked - against the manifest.yaml one by one. if there is missing
    # required parameter or if the wrong type is supplied, the call does NOT run
    for spec in tool.get("params", []):
        name = spec["name"]
        value = params.get(name)
    
        if spec.get("required", True) and value is None:
            return Decision(
                Outcome.BLOCK,
                "MISSING_REQUIRED_PARAM",
                f"Required parameter '{name}' is missing.",
                elapsed(),
            )
    
        # If any optional parameters that was NOT supplied, there is nothing to check.
        if value is None:
            continue
    
        if spec.get("type", "str") == "str" and not isinstance(value, str):
            return Decision(
                Outcome.BLOCK,
                "PARAM_TYPE_MISMATCH",
                f"'{name}' expected type str, got {type(value).__name__}.",
                elapsed(),
            )
        
    session_counts[tool_name] = used + 1
    return Decision(Outcome.PERMIT, "MANIFEST_PERMIT", "All policy checks passed.", elapsed())