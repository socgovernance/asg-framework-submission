# ASG Framework

A governance framework for LLM-powered SOC agents. The framework sits
between the agent and the tools it can call, and enforces three layers of
control before any tool runs.

**Layer 1 — policy engine.** Every tool call is checked against a YAML
capability manifest: agent identity, tool permission, session call budget,
and parameter constraints. The first failed check blocks the call.

**Layer 2 — sanitisation.** Tool output is scanned for prompt injection,
first by pattern matching and then by semantic similarity against a library
of injection intents. Credentials in tool output are redacted before the
agent sees them.

**Layer 3 — audit trail.** Every decision is written to an append-only JSONL
log, each entry hash-chained to the one before it with SHA-256, so any
modification or removal of an intermediate record is detectable.

## Layout

| File | Purpose |
|---|---|
| `manifest.yaml` | The agent's capability contract |
| `policy_engine.py` | Layer 1 |
| `input_sanitiser.py` | Layer 2, injection detection |
| `output_sanitiser.py` | Layer 2, credential redaction |
| `audit_log.py` | Layer 3, writing the chained log |
| `verify_chain.py` | Layer 3, verifying it |
| `experiment_runner.py` | Evaluation harness |
| `mock_soc.py` | Stub SOC tools with call counters |
| `scenario_payloads.py` | The six scenarios' synthetic data |
| `compute_metrics.py` | Computes the metrics from the logs |
| `test_chain_integrity.py` | Chain integrity results |
| `logs/` | 90 evaluation logs |

## Verifying without an API key

Most of the evaluation can be checked without running the agent.

    pip install -r requirements.txt
    pytest -q

51 tests covering all three layers, including the exact semantic score for
the chained-injection payload and detection of tampered logs.

    python compute_metrics.py

Recomputes the metrics from the committed logs.

    python test_chain_integrity.py

Verifies all 90 logs, then demonstrates detection of a controlled
modification and a controlled deletion.

## Re-running the evaluation

Needs an OpenAI API key with credit:

    export OPENAI_API_KEY="sk-..."
    python experiment_runner.py S1 --guarded --runs 20
    python experiment_runner.py S2 --guarded --runs 10
    python experiment_runner.py S2 --unguarded --runs 10
    python experiment_runner.py S3 --guarded --runs 10
    python experiment_runner.py S4 --guarded --runs 10
    python experiment_runner.py S5 --guarded --runs 10
    python experiment_runner.py S6 --guarded --runs 10
    python experiment_runner.py S6 --unguarded --runs 10

Each run writes to `logs/`. **Move the existing logs aside first** — the
runner appends to files of the same name.

Results will not match exactly. The agent is not deterministic even at
temperature 0: in the committed runs, 13 of 20 S1 runs hit a parameter
constraint and 7 did not, and tool ordering varied between runs. The
guarded/unguarded outcomes were stable across all 90 runs.

## Environment

Developed and evaluated on an Intel Mac with Python 3.12. `torch==2.2.2`
is the last release with x86 macOS wheels; other platforms need a later
version, which may shift the semantic similarity scores slightly.

The evaluation used `gpt-4o-mini-2024-07-18`, pinned in
`experiment_runner.py`. If that snapshot is retired, the agent runs will
fail; the tests, metrics and chain verification are unaffected.

## Synthetic data

All evaluation data is researcher-constructed. IP addresses use the
RFC 5737 documentation ranges, domains use the reserved `.test` TLD, and
the credentials in scenario S4 are AWS's published example values. No real
organisational data, live credentials or real incident data appear anywhere.