# ASG Setup and Reproduction Guide

Everything runs from this directory. All SOC tools are local mocks with
synthetic data - no real infrastructure is touched.

## 1. Environment

```bash
python3 -m venv venv && source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

The semantic sanitiser downloads all-MiniLM-L6-v2 (~90MB) on first use.

`torch==2.2.2` is the last release with x86 macOS wheels. On Apple Silicon
or a newer platform a later version is needed - the similarity scores may
shift slightly as a result.

## 2. Unit tests

```bash
pytest -q
```

51 tests across the policy engine, both sanitisers, the audit log and its
verifier, and the mock SOC tools. No API key required.

## 3. Verify the committed evaluation data

No API key needed. These read the 90 logs in `logs/`.

```bash
python3 compute_metrics.py          # M1-M6, M8, M1b
python3 test_chain_integrity.py     # M9, M10, M11
```

Saved output from both is commited as `metrics_output_20260930.txt` and
`chain_integrity_output_20260929.txt`.

To inspect one log entry by entry:

```bash
python3 verify_chain.py logs/S3_guarded_run_01.jsonl
```

Each log entry carries its own timestamp and hash chain.The logs can be
checked for integrity, and provenance without re-running anything.

## 4. Re-run the evaluation (requires an API key)

This writes to `logs/`. Move the committed logs aside first if you want to
keep them.

```bash
export OPENAI_API_KEY="your-key-here"

python3 experiment_runner.py S1 --guarded   --runs 20
python3 experiment_runner.py S2 --guarded   --runs 10
python3 experiment_runner.py S2 --unguarded --runs 10
python3 experiment_runner.py S3 --guarded   --runs 10
python3 experiment_runner.py S4 --guarded   --runs 10
python3 experiment_runner.py S5 --guarded   --runs 10
python3 experiment_runner.py S6 --guarded   --runs 10
python3 experiment_runner.py S6 --unguarded --runs 10
```

The model (`gpt-4o-mini-2024-07-18`) and temperature (0) are set in
`experiment_runner.py`, not via environment variables. If that model
snapshot has been retired, the runs will fail; sections 2 and 3 are
unaffected.

## 5. Notes

- Scenario 1 : produces occasional blocks when the agent writes ticket titles
  over  150-character manifest limit. This is the policy engine working
  as specified. It is not a defect as the agent shortens the title and retries.
- Temperature 0 : reduces variation but does not eliminate it completely. Results
  will not match the committed logs exactly.
  
  
  
 