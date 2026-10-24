# Evaluation report

Evaluator: `python3 code/evaluation/main.py --predictions <file>` against `dataset/sample_output.csv`.
Predictions for the 32 public samples: `python3 code/main.py --requests dataset/sample_deletion_requests.csv --output sample_pred.csv`.

**Scope:** these numbers cover the 32 public sample cases only. They are NOT an estimate for the 518 hidden answers
(the hidden cases include hand-built evidence families for which no expected answer is available to us).

## 1. Case-level deletion status
| Metric | Result |
|---|---|
| Correct `deletion_status` | **100.0% (32/32)** |

## 2. Step / row level (strict = all 6 fields incl. `evidence_id`)
| Metric | Strict | Loose (ignore evidence_id) |
|---|---|---|
| Recall | 97.4% (188/193) | 97.9% (189/193) |
| Precision | 99.5% (188/189) | 100.0% (189/189) |
| F1 | 98.4% | 99.0% |

## 3. Field level (paired steps)
| Field | Accuracy |
|---|---|
| phase / system_id / resource_id / operation / state | 97.9% (189/193) each |
| evidence_id | 97.4% (188/193) |
| all fields | 97.8% (1133/1158) |

## 4. Sequence
| Metric | Result |
|---|---|
| Cases with exactly correct step order | 90.6% (29/32) |
| Sequence score (longest in-order run / longer list) | 97.9% |
| Relative order of found steps | 100.0% |
| Perfect cases (status + all steps + order) | 87.5% (28/32) |

## 5. Format checks on the full submission
`output.csv`: header `case_id,deletion_status,steps_json`, 518 rows, one per request, sorted by `case_id`, valid JSON
arrays, steps numbered from 1, phase order FINDING -> REMEDIATION -> VERIFICATION, 0 format issues in the evaluator.
Status distribution: 354 INCOMPLETE, 154 COMPLETE, 10 NOT_APPLICABLE.

## 6. Additional cases created by us (`code/evaluation/custom_cases.py`, all PASS)
Each is a sample request with one factor changed.
| Case | Change | Expectation | Result |
|---|---|---|---|
| own_1 | Text asks for a copy of data and says not to close the account | `NOT_APPLICABLE`, `[]` | PASS |
| own_2 | `case_12` using the user's **historical** e-mail | Same status and steps as the current e-mail | PASS (INCOMPLETE, 5 steps) |
| own_3 | `audit_at` one minute after the request | No cited evidence captured after `audit_at` | PASS |
| own_4 | E-mail that matches no user | No crash, no invented findings | PASS (COMPLETE with 0 steps) |

Also `code/evaluation/test_evaluator.py` unit-tests the scoring code.
Limitation exposed by own_4: an unknown e-mail yields `COMPLETE` with no steps instead of a distinct outcome,
because the output contract has no "unknown subject" status.

## 7. Failures found and improvements made
| Failure | Improvement |
|---|---|
| Stale evidence from earlier cases of the same user produced false violations | State of a resource = latest observation with `requested_at <= t <= audit_at` |
| Evidence captured after `audit_at` leaked into findings | Only files with `captured_at <= audit_at` are cited or used for state |
| Expired export links counted as remaining data | Links with `expires_at <= audit_at` count as gone |
| Anonymized/redacted copies carry no identifiers, so they were missed | Link them via the activity stream (timing windows, constant 30 s offset signature, exclusivity, carrier-file co-occurrence) |
| Two accounts with near-identical timing were confused | Tie broken by co-occurrence in the same evidence file |
| "Worker reported result" (V-family) vs "Policy action completed" (P-family) chains mixed up | Offset signatures kept separate; V-chains do not get policy-completed copies |
| Replica drift: a record gone in the primary but present in a replica | All replicas/inventories are read as observations; latest state wins |
| Non-deletion requests treated as deletions | Multilingual intent classifier (518 requests -> exactly 10 NOT_APPLICABLE) |
| Hidden-case false INCOMPLETE from ambient sources | Checked: all 11 cases whose only violation is a profile record carry the subject's own identifiers |

## 8. Remaining known gaps
- 4 of 32 sample cases are not perfect (evidence_id or a missing/ordering step).
- Some audit-record and hand-built account IDs appear in no supplied evidence; they are not invented.
- Screenshots and PDFs were transcribed by hand (no OCR), so the hidden hand-built cases depend on that transcription.
