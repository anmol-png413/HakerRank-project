"""
Small tests for the evaluator. Run from the repository root with:

    python3 code/evaluation/test_evaluator.py -v

The tests use tiny INVENTED cases (ids like "t1"), so they check the scoring
logic itself and do not depend on any dataset file, except the last test,
which is skipped automatically when the dataset folder is not present.
"""

import csv
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

# Load code/evaluation/main.py as a module (the folder has no __init__.py).
_spec = importlib.util.spec_from_file_location(
    "evaluator", Path(__file__).resolve().parent / "main.py")
ev = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ev)


def step(n, phase, op, state, system, resource, evidence=""):
    return {"step_no": n, "phase": phase, "system_id": system,
            "resource_id": resource, "operation": op, "state": state,
            "evidence_id": evidence}


def finding(n, resource, evidence="evidence_01"):
    return step(n, "FINDING", "REPORT_REMAINING_RECORD", "PRESENT",
                "search_service", resource, evidence)


def delete(n, resource):
    return step(n, "REMEDIATION", "DELETE_RECORD", "ABSENT", "search_service", resource)


def verify(n, resource):
    return step(n, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT", "search_service", resource)


def case(status, steps):
    return {"status": status, "steps": steps}


# A 3-step INCOMPLETE case used as the "correct answer" in most tests.
GOOD = [finding(1, "search_1"), delete(2, "search_1"), verify(3, "search_1")]


def score(expected, predicted):
    totals, per_case = ev.evaluate(expected, predicted)
    return totals, per_case


class EvaluatorTests(unittest.TestCase):

    def test_identical_answers_score_100_percent(self):
        exp = {"t1": case("INCOMPLETE", GOOD), "t2": case("NOT_APPLICABLE", [])}
        totals, _ = score(exp, exp)
        self.assertEqual(totals["status_correct"], 2)
        self.assertEqual(totals["strict_matched"], 3)
        self.assertEqual(totals["perfect_cases"], 2)
        self.assertEqual(totals["exact_sequence_cases"], 2)
        self.assertEqual(totals["lcs_sum"], totals["longest_sum"])

    def test_missing_step_lowers_recall_not_precision(self):
        exp = {"t1": case("INCOMPLETE", GOOD)}
        pred = {"t1": case("INCOMPLETE", [GOOD[0], GOOD[2]])}
        totals, per_case = score(exp, pred)
        self.assertEqual(ev.ratio(totals["strict_matched"], totals["expected_steps"]), 2 / 3)
        self.assertEqual(ev.ratio(totals["strict_matched"], totals["predicted_steps"]), 1.0)
        self.assertEqual(len(per_case[0]["missing"]), 1)
        self.assertEqual(totals["perfect_cases"], 0)

    def test_extra_step_lowers_precision_not_recall(self):
        exp = {"t1": case("INCOMPLETE", GOOD)}
        pred = {"t1": case("INCOMPLETE", GOOD + [verify(4, "search_9")])}
        totals, per_case = score(exp, pred)
        self.assertEqual(ev.ratio(totals["strict_matched"], totals["expected_steps"]), 1.0)
        self.assertEqual(ev.ratio(totals["strict_matched"], totals["predicted_steps"]), 3 / 4)
        self.assertEqual(len(per_case[0]["extra"]), 1)

    def test_wrong_order_keeps_step_scores_but_lowers_sequence(self):
        exp = {"t1": case("INCOMPLETE", GOOD)}
        pred = {"t1": case("INCOMPLETE", [GOOD[1], GOOD[0], GOOD[2]])}
        totals, per_case = score(exp, pred)
        self.assertEqual(totals["strict_matched"], 3)         # same steps...
        self.assertEqual(totals["exact_sequence_cases"], 0)   # ...wrong order
        self.assertEqual(totals["lcs_sum"], 2)                # only 2 stay in order
        self.assertFalse(per_case[0]["order_ok"])

    def test_wrong_evidence_id_hurts_strict_but_not_loose(self):
        exp = {"t1": case("INCOMPLETE", GOOD)}
        wrong = [finding(1, "search_1", evidence="evidence_99"), GOOD[1], GOOD[2]]
        totals, _ = score(exp, {"t1": case("INCOMPLETE", wrong)})
        self.assertEqual(totals["strict_matched"], 2)
        self.assertEqual(totals["loose_matched"], 3)
        self.assertEqual(totals["field_correct:evidence_id"], 2)
        self.assertEqual(totals["field_correct:operation"], 3)
        self.assertEqual(totals["exact_sequence_cases"], 1)   # sequence ignores evidence

    def test_wrong_operation_on_same_record_is_a_field_error(self):
        exp = {"t1": case("INCOMPLETE", GOOD)}
        redact = step(2, "REMEDIATION", "REDACT_RECORD", "REDACTED", "search_service", "search_1")
        totals, per_case = score(exp, {"t1": case("INCOMPLETE", [GOOD[0], redact, GOOD[2]])})
        self.assertEqual(totals["field_correct:resource_id"], 3)   # record was found
        self.assertEqual(totals["field_correct:operation"], 2)     # operation was wrong
        self.assertEqual(totals["field_correct:state"], 2)
        self.assertEqual(len(per_case[0]["missing"]), 0)

    def test_wrong_status_is_counted(self):
        exp = {"t1": case("INCOMPLETE", GOOD)}
        pred = {"t1": case("COMPLETE", GOOD)}
        totals, _ = score(exp, pred)
        self.assertEqual(totals["status_correct"], 0)
        self.assertEqual(totals["perfect_cases"], 0)

    def test_missing_prediction_row_is_wrong_everywhere(self):
        exp = {"t1": case("INCOMPLETE", GOOD)}
        totals, _ = score(exp, {})
        self.assertEqual(totals["cases_without_row"], 1)
        self.assertEqual(totals["status_correct"], 0)
        self.assertEqual(totals["strict_matched"], 0)
        self.assertEqual(totals["exact_sequence_cases"], 0)

    def test_extra_prediction_rows_are_ignored(self):
        exp = {"t1": case("INCOMPLETE", GOOD)}
        pred = {"t1": case("INCOMPLETE", GOOD), "other": case("NOT_APPLICABLE", [])}
        totals, _ = score(exp, pred)
        self.assertEqual(totals["cases"], 1)

    def test_not_applicable_has_no_steps_to_measure(self):
        exp = {"t1": case("NOT_APPLICABLE", [])}
        totals, _ = score(exp, exp)
        self.assertEqual(totals["status_correct"], 1)
        self.assertIsNone(ev.ratio(totals["strict_matched"], totals["expected_steps"]))

    def test_lcs_length(self):
        self.assertEqual(ev.lcs_length(list("ABCD"), list("ACBD")), 3)
        self.assertEqual(ev.lcs_length([], list("AB")), 0)
        self.assertEqual(ev.lcs_length(list("AB"), list("AB")), 2)

    def test_format_check_catches_common_mistakes(self):
        broken = [finding(1, "s1"), finding(3, "s2")]             # step_no jumps 1 -> 3
        issues = ev.check_step_rules("t1", "INCOMPLETE", broken)
        self.assertTrue(any("step_no" in text for text in issues))
        issues = ev.check_step_rules("t2", "NOT_APPLICABLE", GOOD)
        self.assertTrue(any("NOT_APPLICABLE" in text for text in issues))
        bad_json, issues = ev.parse_steps("t3", "INCOMPLETE", "{not json")
        self.assertEqual(bad_json, [])
        self.assertTrue(any("not valid JSON" in text for text in issues))
        out_of_order = [verify(1, "s1"), finding(2, "s1", "evidence_01")]
        issues = ev.check_step_rules("t4", "INCOMPLETE", out_of_order)
        self.assertTrue(any("documented order" in text for text in issues))

    def test_reading_a_csv_round_trip_and_header_only_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "out.csv"
            with open(path, "w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle)
                writer.writerow(ev.HEADER)
                writer.writerow(["t1", "INCOMPLETE", json.dumps(GOOD)])
            cases, issues = ev.read_cases(path)
            self.assertEqual(issues, [])
            self.assertEqual(cases["t1"]["steps"], GOOD)

            empty = Path(folder) / "empty.csv"
            empty.write_text("case_id,deletion_status,steps_json\n", encoding="utf-8")
            cases, issues = ev.read_cases(empty)
            self.assertEqual((cases, issues), ({}, []))

    def test_real_sample_file_matches_itself(self):
        if not ev.DEFAULT_EXPECTED.is_file():
            self.skipTest("dataset/sample_output.csv not present")
        cases, issues = ev.read_cases(ev.DEFAULT_EXPECTED)
        self.assertEqual(issues, [])
        totals, _ = ev.evaluate(cases, cases)
        self.assertEqual(totals["perfect_cases"], totals["cases"])


if __name__ == "__main__":
    unittest.main()