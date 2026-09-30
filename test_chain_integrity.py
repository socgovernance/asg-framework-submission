"""
test_chain_integrity.py -- Systematic M9/M10/M11 verification.

M9  -- chain integrity, unmodified: every real evaluation log passes
        verification cleanly.
M10 -- chain integrity, after modification: a deliberately altered copy
        of a real log is detected and the break correctly propagates.
M11 -- chain integrity, after deletion: a deliberately truncated copy
        of a real log is detected and the break correctly propagates.

Run with - python test_chain_integrity.py
"""
import json
import glob
import shutil
import os
from verify_chain import verify


def run_m9_all_real_logs():
    print("=" * 70)
    print("M9 -- Chain integrity across ALL real evaluation logs (unmodified)")
    print("=" * 70)

    all_logs = sorted(glob.glob("logs/*_run_*.jsonl"))
    passed = 0
    failed = []

    for path in all_logs:
        report = verify(path)
        if report["intact"]:
            passed += 1
        else:
            failed.append((path, report["break_at"]))

    total = len(all_logs)
    print(f"\nTotal logs checked: {total}")
    print(f"Intact (PASS): {passed}/{total}")
    if failed:
        print(f"Broken (unexpected): {len(failed)}")
        for path, break_at in failed:
            print(f"  *** {path} -- break at entry {break_at}")
    else:
        print("All real evaluation logs verified intact. M9 = PASS.")
    print()
    return passed, total


def run_m10_modification_test():
    print("=" * 70)
    print("M10 -- Chain integrity after deliberate MODIFICATION")
    print("=" * 70)

    source_candidates = sorted(glob.glob("logs/S3_guarded_run_*.jsonl"))
    if not source_candidates:
        print("No S3 guarded logs found to test against. Skipping M10.")
        return False

    source = source_candidates[0]
    test_copy = "test_m10_modified.jsonl"
    shutil.copy(source, test_copy)

    lines = open(test_copy).readlines()
    if len(lines) < 2:
        print("Source log too short for a meaningful modification test.")
        return False

    target_idx = 1
    entry = json.loads(lines[target_idx])
    original_outcome = entry.get("outcome")
    entry["outcome"] = "PERMIT" if original_outcome == "BLOCK" else "BLOCK"
    lines[target_idx] = json.dumps(entry) + "\n"
    with open(test_copy, "w") as f:
        f.writelines(lines)

    report = verify(test_copy)
    print(f"Source log: {source}")
    print(f"Modified entry {target_idx + 1}: outcome '{original_outcome}' -> '{entry['outcome']}'")
    print(f"Total entries: {report['entries']}")
    print(f"Chain intact: {report['intact']}")
    print(f"Break detected at entry: {report['break_at']}")

    success = (not report["intact"]) and (report["break_at"] == target_idx + 1)
    preceding_ok = all(
        r["ok"] for r in report["results"] if r["entry_number"] < report["break_at"]
        )

    # This stops at the first break instead of  continuing
    # Everything after a broken link chains from a hash that can no longer
    # be trusted, so "verified" would be a meaningless label for it. The
    # report records how many entries were checked before stopping.
    stopped_at_break = report["verified"] == report["break_at"]
    unverified = report["entries"] - report["verified"]
    
    print(f"Entries verified before the break: {report['verified']} of {report['entries']}")
    print(f"Entries left unverified after the break: {unverified}")
    print(f"Break correctly localised to the modified entry: {success}")
    print(f"Entries before the break remain verified OK: {preceding_ok}")
    print("M10 =", "PASS" if (success and preceding_ok and stopped_at_break) else "FAIL")
    print()

    os.remove(test_copy)
    return success and preceding_ok and stopped_at_break

def run_m11_deletion_test():
    print("=" * 70)
    print("M11 -- Chain integrity after deliberate DELETION")
    print("=" * 70)

    source_candidates = sorted(glob.glob("logs/S6_guarded_run_*.jsonl"))
    if not source_candidates:
        print("No S6 guarded logs found to test against. Skipping M11.")
        return False

    source = source_candidates[0]
    test_copy = "test_m11_deleted.jsonl"
    shutil.copy(source, test_copy)

    lines = open(test_copy).readlines()
    if len(lines) < 3:
        print("Source log too short for a meaningful deletion test.")
        return False

    target_idx = 1
    deleted_entry = json.loads(lines[target_idx])
    new_lines = lines[:target_idx] + lines[target_idx + 1:]
    with open(test_copy, "w") as f:
        f.writelines(new_lines)

    report = verify(test_copy)
    print(f"Source log: {source}")
    print(f"Deleted entry: #{deleted_entry.get('entry_number')} ({deleted_entry.get('tool_name')})")
    print(f"Entries remaining: {report['entries']} (was {len(lines)})")
    print(f"Chain intact: {report['intact']}")
    print(f"Break detected at (now-renumbered) position: {report['break_at']}")

    success = not report["intact"]

    print(f"Deletion correctly detected as a break: {success}")
    print("M11 =", "PASS" if success else "FAIL")
    print()

    os.remove(test_copy)
    return success

def run_truncation_demonstration():
    """Not a pre-registered metric. Removing trailing entries leaves a
    chain that still verifies, because nothing anchors the end of the
    file. Recorded here as evidence for the limitation."""
    print("=" * 70)
    print("Truncation -- a known limitation, demonstrated")
    print("=" * 70)

    source_candidates = sorted(glob.glob("logs/S6_guarded_run_*.jsonl"))
    if not source_candidates:
        print("No S6 guarded logs found. Skipping.")
        return

    source = source_candidates[0]
    test_copy = "test_truncated.jsonl"
    shutil.copy(source, test_copy)

    lines = open(test_copy).readlines()
    kept = lines[:-2]
    with open(test_copy, "w") as f:
        f.writelines(kept)

    report = verify(test_copy)
    print(f"Source log: {source}")
    print(f"Removed the last 2 of {len(lines)} entries")
    print(f"Chain intact: {report['intact']}")
    print("The remaining entries still form a valid chain, so removing them")
    print("from the end is not detectable by hash verification alone. Detecting")
    print("it would need a signed head record or an external anchor.")
    print()

    os.remove(test_copy)


if __name__ == "__main__":
    m9_passed, m9_total = run_m9_all_real_logs()
    m10_result = run_m10_modification_test()
    m11_result = run_m11_deletion_test()
    run_truncation_demonstration()

    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"M9  (unmodified, n={m9_total}): {m9_passed}/{m9_total} intact -- {'PASS' if m9_passed == m9_total else 'FAIL'}")
    print(f"M10 (modification detection):    {'PASS' if m10_result else 'FAIL'}")
    print(f"M11 (deletion detection):        {'PASS' if m11_result else 'FAIL'}")
