#!/usr/bin/env python3
"""
Evaluator for the "Ghost Data Still Exists" challenge.

WHAT IT DOES
    Compares a file of predicted answers (output.csv format) with a file of
    known-correct answers (default: dataset/sample_output.csv) and prints
    four separate scores:

        1. Status accuracy      - did we pick COMPLETE / INCOMPLETE / NOT_APPLICABLE?
        2. Step-level accuracy  - did we produce the right steps (no more, no less)?
        3. Field-level accuracy - inside the steps, are the individual fields right?
        4. Sequence accuracy    - are the steps in the right order?

    It also runs a FORMAT CHECK on the predictions file (valid JSON, numbering,
    allowed operations, ordering rule, evidence-id rules). Format problems are
    reported separately and never silently change the accuracy numbers.

HOW TO RUN (from the repository root)
    python3 code/evaluation/main.py --predictions data/sample_output.csv
    python3 code/evaluation/main.py --predictions my_sample_predictions.csv -v
    python3 code/evaluation/main.py --help

IMPORTANT LIMIT
    The only answers we have are for the 32 sample cases. A score here says how
    well we match THOSE cases. It is NOT an estimate of the score on the 518
    hidden cases.

This file uses only the Python standard library (no installs needed).
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

# --------------------------------------------------------------------------
# Part 1: the contract (copied from problem_statement.md, not from any data)
# --------------------------------------------------------------------------

# This file lives in <repo>/code/evaluation/, so the repo root is 2 levels up.
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EXPECTED = REPO_ROOT / "dataset" / "sample_output.csv"
DEFAULT_PREDICTIONS = REPO_ROOT / "output.csv"

HEADER = ["case_id", "deletion_status", "steps_json"]
STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}

# Every step must contain exactly these keys.
STEP_KEYS = ["step_no", "phase", "system_id", "resource_id",
             "operation", "state", "evidence_id"]

# The allowed (phase, operation, state) combinations, IN THE ORDER given by the
# "Allowed Operations" table. The position in this list is the sort order.
OPERATION_TABLE = [
    ("FINDING", "REPORT_REMAINING_RECORD", "PRESENT"),
    ("FINDING", "REPORT_EXPOSED_PII", "PRESENT"),
    ("FINDING", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
    ("FINDING", "REPORT_RESTORE_RISK", "ACTIVE"),
    ("REMEDIATION", "DISABLE_DATA_FLOW", "DISABLED"),
    ("REMEDIATION", "BLOCK_RESTORE", "BLOCKED"),
    ("REMEDIATION", "DELETE_RECORD", "ABSENT"),
    ("REMEDIATION", "REDACT_RECORD", "REDACTED"),
    ("REMEDIATION", "ANONYMIZE_RECORD", "ANONYMIZED"),
    ("VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT"),
    ("VERIFICATION", "VERIFY_RECORD_PRESENT", "PRESENT"),
    ("VERIFICATION", "VERIFY_RECORD_REDACTED", "REDACTED"),
    ("VERIFICATION", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
    ("VERIFICATION", "VERIFY_RESTORE_BLOCKED", "BLOCKED"),
]
VALID_TRIPLES = set(OPERATION_TABLE)
OPERATION_ORDER = {op: i for i, (_phase, op, _state) in enumerate(OPERATION_TABLE)}

# Fields we compare when judging a step. step_no is NOT compared on purpose:
# it is just "position + 1", so a wrong step_no is really a wrong ORDER or a
# missing step, which the step-level and sequence metrics already capture.
COMPARE_FIELDS = ["phase", "system_id", "resource_id",
                  "operation", "state", "evidence_id"]
# "Loose" view of a step: the same, but ignoring which evidence file was cited.
LOOSE_FIELDS = [f for f in COMPARE_FIELDS if f != "evidence_id"]

# A very large CSV cell limit so long steps_json values never crash the reader.
csv.field_size_limit(10 ** 8)


# --------------------------------------------------------------------------
# Part 2: reading a CSV file and checking its format
# --------------------------------------------------------------------------

def read_cases(path):
    """
    Read an output-style CSV.

    Returns (cases, issues):
      cases  = {case_id: {"status": str, "steps": [step dicts]}}
      issues = list of human-readable format problems (empty list = clean)
    """
    path = Path(path)
    if not path.is_file():
        raise SystemExit(f"File not found: {path}")

    cases = {}
    issues = []
    with open(path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.reader(handle)
        header = next(reader, None)
        if header != HEADER:
            issues.append(f"header is {header!r}, expected {HEADER!r}")

        previous_id = None
        reported_unsorted = False
        for line_no, row in enumerate(reader, start=2):
            if not row:
                continue  # ignore blank lines
            if len(row) != 3:
                issues.append(f"line {line_no}: expected 3 columns, found {len(row)}")
                continue
            case_id, status, steps_text = row
            if case_id in cases:
                issues.append(f"{case_id}: duplicate row (only the first is used)")
                continue
            if previous_id is not None and case_id < previous_id and not reported_unsorted:
                issues.append(f"rows are not sorted by case_id as plain text "
                              f"(first seen at {case_id}); NOTE: plain-text order is "
                              f"our assumption of 'sorted'")
                reported_unsorted = True
            previous_id = case_id

            steps, step_issues = parse_steps(case_id, status, steps_text)
            issues.extend(step_issues)
            cases[case_id] = {"status": status, "steps": steps}
    return cases, issues


def parse_steps(case_id, status, steps_text):
    """Turn the steps_json text into a list of step dicts and check its format."""
    try:
        raw_steps = json.loads(steps_text)
    except json.JSONDecodeError as error:
        return [], [f"{case_id}: steps_json is not valid JSON ({error.msg})"]
    if not isinstance(raw_steps, list):
        return [], [f"{case_id}: steps_json is not a JSON array"]

    issues = []
    steps = []
    for position, raw in enumerate(raw_steps, start=1):
        if not isinstance(raw, dict):
            issues.append(f"{case_id}: step {position} is not a JSON object")
            continue
        if set(raw) != set(STEP_KEYS):
            missing = sorted(set(STEP_KEYS) - set(raw))
            extra = sorted(set(raw) - set(STEP_KEYS))
            issues.append(f"{case_id}: step {position} has wrong keys "
                          f"(missing {missing}, unexpected {extra})")
        step = {key: raw.get(key) for key in STEP_KEYS}
        if step["evidence_id"] is None:       # treat null like ""
            step["evidence_id"] = ""
        steps.append(step)

    issues.extend(check_step_rules(case_id, status, steps))
    return steps, issues


def check_step_rules(case_id, status, steps):
    """Check the rules from the problem statement that need no data files."""
    issues = []
    if status not in STATUSES:
        issues.append(f"{case_id}: deletion_status {status!r} is not one of {sorted(STATUSES)}")
    if status == "NOT_APPLICABLE" and steps:
        issues.append(f"{case_id}: NOT_APPLICABLE must have steps_json = []")

    # step_no must be 1, 2, 3, ... in array order.
    numbers = [s["step_no"] for s in steps]
    if numbers != list(range(1, len(steps) + 1)):
        issues.append(f"{case_id}: step_no values are not 1..{len(steps)} in order")

    # Each (phase, operation, state) must be an allowed combination.
    all_valid = True
    for index, step in enumerate(steps, start=1):
        triple = (step["phase"], step["operation"], step["state"])
        if triple not in VALID_TRIPLES:
            all_valid = False
            issues.append(f"{case_id}: step {index} has a combination that is not allowed: {triple}")

    # Documented sort rule: operation order, then system_id, then resource_id.
    if all_valid:
        sort_keys = [(OPERATION_ORDER[s["operation"]], str(s["system_id"]), str(s["resource_id"]))
                     for s in steps]
        if sort_keys != sorted(sort_keys):
            issues.append(f"{case_id}: steps are not in the documented order "
                          f"(operation table order, then system_id, then resource_id)")

    # Evidence-id rules (which phases may / must cite evidence).
    if status == "COMPLETE":
        for index, step in enumerate(steps, start=1):
            if step["phase"] != "VERIFICATION":
                issues.append(f"{case_id}: COMPLETE cases may only contain VERIFICATION steps (step {index})")
            if not step["evidence_id"]:
                issues.append(f"{case_id}: COMPLETE verification step {index} has an empty evidence_id")
    elif status == "INCOMPLETE":
        for index, step in enumerate(steps, start=1):
            if step["phase"] == "FINDING" and not step["evidence_id"]:
                issues.append(f"{case_id}: finding step {index} has an empty evidence_id")
            if step["phase"] in ("REMEDIATION", "VERIFICATION") and step["evidence_id"]:
                issues.append(f"{case_id}: {step['phase'].lower()} step {index} should have an empty evidence_id")
    return issues


# --------------------------------------------------------------------------
# Part 3: small helper tools for comparing step lists
# --------------------------------------------------------------------------

def step_key(step, fields):
    """Reduce a step to a tuple of the chosen fields, so steps can be compared."""
    return tuple(step[field] for field in fields)


def count_matches(expected_keys, predicted_keys):
    """
    How many steps appear in BOTH lists? Order is ignored, duplicates are
    respected (if a step is expected twice, it can be matched at most twice).
    """
    return sum((Counter(expected_keys) & Counter(predicted_keys)).values())


def lcs_length(first, second):
    """
    Length of the Longest Common Subsequence: the longest run of items that
    appears in both lists in the SAME relative order (gaps allowed).
    Example: [A,B,C,D] vs [A,C,B,D] -> LCS is 3 (A,B,D or A,C,D).
    """
    if not first or not second:
        return 0
    previous = [0] * (len(second) + 1)
    for item_a in first:
        current = [0]
        for j, item_b in enumerate(second, start=1):
            if item_a == item_b:
                current.append(previous[j - 1] + 1)
            else:
                current.append(max(previous[j], current[j - 1]))
        previous = current
    return previous[-1]


def pair_steps(expected_steps, predicted_steps):
    """
    Pair each expected step with the predicted step that "means the same
    thing", so we can compare their individual fields.

    Pass 1: same (phase, system_id, resource_id, operation)  -> best match.
    Pass 2: same (phase, system_id, resource_id) among what is left -> the
            right record, but maybe the wrong operation/state.
    Anything expected but unpaired is MISSING; anything predicted but
    unpaired is EXTRA.
    Returns (pairs, missing, extra).
    """
    unused = list(range(len(predicted_steps)))
    pairs = []

    def pair_by(fields, still_unmatched):
        leftovers = []
        for expected in still_unmatched:
            wanted = step_key(expected, fields)
            found = None
            for index in unused:
                if step_key(predicted_steps[index], fields) == wanted:
                    found = index
                    break
            if found is None:
                leftovers.append(expected)
            else:
                unused.remove(found)
                pairs.append((expected, predicted_steps[found]))
        return leftovers

    leftovers = pair_by(["phase", "system_id", "resource_id", "operation"], expected_steps)
    leftovers = pair_by(["phase", "system_id", "resource_id"], leftovers)
    extra = [predicted_steps[index] for index in unused]
    return pairs, leftovers, extra


def describe(step):
    """Short one-line text for a step, used in the verbose report."""
    evidence = step["evidence_id"] or "-"
    return (f"{step['phase']:<12} {step['operation']:<26} "
            f"{step['system_id']}/{step['resource_id']} (evidence: {evidence})")


def ratio(numerator, denominator):
    """numerator/denominator, or None when there is nothing to divide by."""
    return None if denominator == 0 else numerator / denominator


# --------------------------------------------------------------------------
# Part 4: the scoring itself
# --------------------------------------------------------------------------

def evaluate(expected, predicted):
    """
    Compare predictions with expected answers.

    Only cases that appear in `expected` are scored. A case with no
    prediction row is scored as wrong everywhere (status wrong, every
    expected step missing, sequence not exact).

    Returns (totals, per_case):
      totals   = Counter of raw counts (the report turns them into percentages)
      per_case = one dict per case with the details used by --verbose
    """
    totals = Counter()
    per_case = []

    for case_id in sorted(expected):
        expected_case = expected[case_id]
        predicted_case = predicted.get(case_id)          # None if row is absent
        expected_steps = expected_case["steps"]
        predicted_steps = predicted_case["steps"] if predicted_case else []

        status_ok = (predicted_case is not None
                     and predicted_case["status"] == expected_case["status"])

        # --- step-level: count steps found in both lists (order ignored) ---
        strict_expected = [step_key(s, COMPARE_FIELDS) for s in expected_steps]
        strict_predicted = [step_key(s, COMPARE_FIELDS) for s in predicted_steps]
        loose_expected = [step_key(s, LOOSE_FIELDS) for s in expected_steps]
        loose_predicted = [step_key(s, LOOSE_FIELDS) for s in predicted_steps]
        strict_matched = count_matches(strict_expected, strict_predicted)
        loose_matched = count_matches(loose_expected, loose_predicted)

        # --- field-level: pair steps, then check each field ---
        pairs, missing, extra = pair_steps(expected_steps, predicted_steps)
        mismatches = []
        for expected_step, predicted_step in pairs:
            for field in COMPARE_FIELDS:
                if expected_step[field] == predicted_step[field]:
                    totals["field_correct:" + field] += 1
                else:
                    mismatches.append((expected_step, field,
                                       expected_step[field], predicted_step[field]))

        # --- sequence: use the loose keys, in array order ---
        lcs = lcs_length(loose_expected, loose_predicted)
        longest = max(len(loose_expected), len(loose_predicted))
        exact_sequence = predicted_case is not None and loose_expected == loose_predicted
        perfect = (status_ok and strict_expected == strict_predicted)

        totals["cases"] += 1
        totals["cases_without_row"] += predicted_case is None
        totals["status_correct"] += status_ok
        totals["expected_steps"] += len(expected_steps)
        totals["predicted_steps"] += len(predicted_steps)
        totals["strict_matched"] += strict_matched
        totals["loose_matched"] += loose_matched
        totals["lcs_sum"] += lcs
        totals["longest_sum"] += longest
        totals["exact_sequence_cases"] += exact_sequence
        totals["perfect_cases"] += perfect

        per_case.append({
            "case_id": case_id,
            "expected_status": expected_case["status"],
            "predicted_status": predicted_case["status"] if predicted_case else None,
            "status_ok": status_ok, "perfect": perfect,
            "missing": missing, "extra": extra, "mismatches": mismatches,
            "lcs": lcs, "loose_matched": loose_matched,
            "order_ok": loose_matched == 0 or lcs == loose_matched,
        })
    return totals, per_case


# --------------------------------------------------------------------------
# Part 5: printing the report
# --------------------------------------------------------------------------

def pct(numerator, denominator):
    """Format 'xx.x% (n/d)', or 'n/a' if there is nothing to measure."""
    value = ratio(numerator, denominator)
    if value is None:
        return "n/a (nothing to measure)"
    return f"{value * 100:6.1f}%  ({numerator}/{denominator})"


def f1_text(precision, recall):
    if precision is None or recall is None or (precision + recall) == 0:
        return "n/a"
    return f"{2 * precision * recall / (precision + recall) * 100:.1f}%"


def step_block(label, matched, expected_total, predicted_total):
    precision = ratio(matched, predicted_total)
    recall = ratio(matched, expected_total)
    print(f"  {label}")
    print(f"    recall    (expected steps we found) : {pct(matched, expected_total)}")
    print(f"    precision (our steps that are right): {pct(matched, predicted_total)}")
    print(f"    F1 (balance of the two)             : {f1_text(precision, recall)}")


def print_report(args, expected, predicted, format_issues, totals, per_case):
    cases = totals["cases"]
    ignored = len(set(predicted) - set(expected))

    print("=" * 66)
    print(" Ghost Data Still Exists - evaluator report")
    print("=" * 66)
    print(f"Expected answers : {args.expected}  ({len(expected)} cases)")
    print(f"Predictions      : {args.predictions}  ({len(predicted)} rows)")
    print(f"Cases scored     : {cases}")
    print(f"Prediction rows not in the expected file (ignored): {ignored}")
    print(f"Expected cases with no prediction row (scored wrong): {totals['cases_without_row']}")

    print("\n-- Format check of the predictions file (separate from accuracy) --")
    if not format_issues:
        print("  OK: no format problems found.")
    else:
        print(f"  {len(format_issues)} problem(s) found:")
        for issue in format_issues[:args.max_issues]:
            print("   -", issue)
        if len(format_issues) > args.max_issues:
            print(f"   ... and {len(format_issues) - args.max_issues} more (use --max-issues)")

    print("\n-- 1. STATUS accuracy --")
    print(f"  cases with the correct deletion_status: {pct(totals['status_correct'], cases)}")

    print("\n-- 2. STEP-LEVEL accuracy (does each case have the right steps?) --")
    step_block("strict: all 6 fields must match (including evidence_id)",
               totals["strict_matched"], totals["expected_steps"], totals["predicted_steps"])
    step_block("loose : ignoring evidence_id",
               totals["loose_matched"], totals["expected_steps"], totals["predicted_steps"])

    print("\n-- 3. FIELD-LEVEL accuracy (inside the steps) --")
    print("  Each expected step is paired with our step for the same record;")
    print("  a missing step counts as wrong for every field.")
    all_correct = 0
    for field in COMPARE_FIELDS:
        correct = totals["field_correct:" + field]
        all_correct += correct
        print(f"    {field:<12}: {pct(correct, totals['expected_steps'])}")
    print(f"    {'all fields':<12}: {pct(all_correct, totals['expected_steps'] * len(COMPARE_FIELDS))}")

    print("\n-- 4. SEQUENCE accuracy (is the order right?) --")
    print(f"  cases whose step order is exactly right        : {pct(totals['exact_sequence_cases'], cases)}")
    print(f"  sequence score (longest in-order run / longer list): {pct(totals['lcs_sum'], totals['longest_sum'])}")
    print(f"  order score (of the steps we found, how many are in the right relative order): "
          f"{pct(totals['lcs_sum'], totals['loose_matched'])}")

    print("\n-- Overall --")
    print(f"  perfect cases (status + every step identical, in order): {pct(totals['perfect_cases'], cases)}")

    if args.verbose:
        print("\n-- Per-case details (cases that are not perfect) --")
        imperfect = [c for c in per_case if not c["perfect"]]
        if not imperfect:
            print("  every case is perfect.")
        for case in imperfect:
            print(f"  {case['case_id']}: status expected={case['expected_status']} "
                  f"predicted={case['predicted_status']}")
            for step in case["missing"]:
                print("      MISSING :", describe(step))
            for step in case["extra"]:
                print("      EXTRA   :", describe(step))
            for step, field, want, got in case["mismatches"]:
                print(f"      FIELD   : {step['system_id']}/{step['resource_id']} "
                      f"{field}: expected {want!r}, got {got!r}")
            if not case["order_ok"]:
                print(f"      ORDER   : only {case['lcs']} of {case['loose_matched']} "
                      f"matching steps are in the right relative order")

    print("\nSCOPE NOTE: these numbers only describe agreement on the "
          f"{cases} cases in the expected file.")
    print("They are NOT an estimate of accuracy on the hidden 518-case answers.")


# --------------------------------------------------------------------------
# Part 6: command-line entry point
# --------------------------------------------------------------------------

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Score a predictions CSV against known-correct answers.")
    parser.add_argument("--expected", type=Path, default=DEFAULT_EXPECTED,
                        help="correct answers (default: dataset/sample_output.csv)")
    parser.add_argument("--predictions", type=Path, default=DEFAULT_PREDICTIONS,
                        help="our answers (default: output.csv in the repo root)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="list every missing / extra / wrong step per case")
    parser.add_argument("--max-issues", type=int, default=10,
                        help="how many format problems to print (default 10)")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    expected, expected_issues = read_cases(args.expected)
    predicted, format_issues = read_cases(args.predictions)
    if expected_issues:
        print(f"WARNING: the expected file has {len(expected_issues)} format "
              f"problem(s); first: {expected_issues[0]}", file=sys.stderr)
    totals, per_case = evaluate(expected, predicted)
    print_report(args, expected, predicted, format_issues, totals, per_case)
    return 0


if __name__ == "__main__":
    sys.exit(main())
