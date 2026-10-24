"""Own evaluation cases (derived from public sample requests by changing one factor).

Run from the repo root:  python3 code/evaluation/custom_cases.py
Each case states what is expected; the script prints PASS/FAIL.
"""
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "code"))
from ghost.engine import Engine  # noqa: E402

DS = ROOT / "dataset"
rows = {r["case_id"]: r for r in csv.DictReader(open(DS / "sample_deletion_requests.csv", encoding="utf-8"))}
audit = list(csv.DictReader(open(DS / "user_audit_log.csv", encoding="utf-8")))
ident = {r["user_id"]: r for r in csv.DictReader(open(DS / "user_identities.csv", encoding="utf-8"))}


def variant(base, cid, **kw):
    r = dict(rows[base])
    r.update(kw, case_id=cid)
    return r


cases = []
# 1. access request, not deletion
cases.append((variant("case_01", "own_1", request_text="Could you send me a copy of the personal data you hold about me? I do not want the account closed."),
              lambda st, steps: st == "NOT_APPLICABLE" and steps == []))
# 2. historical e-mail of sample user_12 (case_12) must give the same audit as the current e-mail
hist = next(a for a in audit if a["field_name"] == "email" and a["user_id"] == "user_12")
cases.append((variant("case_12", "own_2", email=hist["old_value"]), "SAME_AS:case_12"))
# 3. audit_at one minute after the request: evidence captured later must never be cited
early = variant("case_01", "own_3", audit_at="2026-08-18T09:15:00Z")
cases.append((early, "NO_LATE_EVIDENCE"))
# 4. unknown e-mail: nobody to audit; must not crash and must not invent resources
cases.append((variant("case_01", "own_4", email="nobody.at.all@example.org"),
              lambda st, steps: steps == [] or all(s["phase"] != "FINDING" for s in steps)))

eng = Engine(DS)
res = eng.audit_all([c[0] for c in cases] + [r for r in rows.values()])
ok = True
for req, check in cases:
    st, steps = res[req["case_id"]]
    if check == "NO_LATE_EVIDENCE":
        cap = {r["file_id"]: r["captured_at"] for r in csv.DictReader(open(DS / "evidence_files.csv", encoding="utf-8"))}
        good = all(s["evidence_id"] not in cap or cap[s["evidence_id"]] <= req["audit_at"] for s in steps)
    elif isinstance(check, str):
        base = res[check.split(":")[1]]
        good = (st, [{k: v for k, v in s.items()} for s in steps]) == (base[0], base[1])
    else:
        good = check(st, steps)
    ok &= good
    print(("PASS" if good else "FAIL"), req["case_id"], st, len(steps))
sys.exit(0 if ok else 1)
