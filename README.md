# Ghost Data Still Exists - deletion-audit agent

For every request in `dataset/deletion_requests.csv` the agent decides whether deletion was requested, reconstructs
the state of the person's data at `audit_at`, applies `deletion_rules.csv`, and writes `output.csv`
(`case_id,deletion_status,steps_json`).

## Setup and run
1. Install Python 3.11+ (no `pip install` needed).
2. Clone this repo and put the challenge's `dataset/` folder (with `deletion_requests.csv`, `evidence/`, ...) in the repo root.
   The dataset is not stored in this repository.
3. Run the commands below from the repo root. The result is written to `output.csv`.
Requires Python 3.11+ (standard library only, including `sqlite3`). No API keys, no network, no model calls.

```bash
# from the repository root (the folder that contains dataset/ and code/)
python3 code/main.py                       # dataset/deletion_requests.csv -> ./output.csv
python3 code/main.py --requests dataset/sample_deletion_requests.csv --output sample_pred.csv
python3 code/evaluation/main.py --predictions sample_pred.csv -v     # score against dataset/sample_output.csv
python3 code/evaluation/custom_cases.py                              # our own extra cases
python3 code/evaluation/test_evaluator.py -v                         # evaluator unit tests
```

On Windows use `python` (or a portable/embeddable Python 3.11 if the installed one has a broken stdlib):
`D:\path\to\python.exe code\main.py`. Set `PYTHONIOENCODING=utf-8` if the console shows encoding errors.

## Design (`code/ghost/`)
| Module | Role |
|---|---|
| `intent.py` | Multilingual classifier: does `request_text` authorize deletion? Otherwise `NOT_APPLICABLE`. |
| `identity.py` | Resolves the request e-mail (current or historical) to a user, collecting past e-mails, phones, hashes from `user_audit_log.csv`. |
| `evidence.py`, `logparse.py` | Load SQL snapshots (replicas, inventory), JSON bundles/exports/lookups, logs and text records into uniform observations (`Obs`). |
| `transcripts.py` | Facts from screenshots/PDFs, transcribed once by hand (no OCR available); see limits. |
| `activity.py` | Indexes `system_activity.csv`; links anonymized/redacted copies that carry no identifiers via timing signatures. |
| `engine.py` | Resource discovery, state at `audit_at`, rules, step generation and ordering. |

Method: resources are found through identifiers; state is the latest observation with
`requested_at <= t <= audit_at` taken only from evidence files captured at or before `audit_at`. Workflow status and
activity results are treated as claims. Policy: profile/search/export/attachment/marketing present -> remaining record
(delete); support message, tombstone or analytics with identifiers -> exposed PII (redact / anonymize); enabled flow ->
active data flow; allowed restore -> restore risk. Audit and legal records must remain. Output is
FINDING -> REMEDIATION (flows/restores first) -> VERIFICATION, with empty `evidence_id` for future work.
Everything is deterministic.

## Results and limits
Sample set (32 cases): status 100%, strict step recall 97.4%, precision 99.5% - see
`code/evaluation/evaluation_report.md`. This is not an estimate for the hidden 518 cases. Known limits: screenshot/PDF
content is hand-transcribed; some audit/account IDs appear in no evidence and are not invented; an unknown e-mail gives
`COMPLETE` with no steps. Token usage: none (`code/evaluation/usage_report.md`).
