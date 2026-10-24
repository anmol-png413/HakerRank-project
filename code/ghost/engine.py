"""Case engine: identity -> evidence state at ``audit_at`` -> findings / plan / checks."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .activity import (ACCOUNT_WINDOWS, MOD_P, MOD_V, P_SLOTS, ActivityIndex, mod30, parse_t)
from .evidence import (ANALYTICS, AUDIT, BACKUP, EXPORT, FLOW, LEGAL, MARKETING, OBJECT, PROFILE, SEARCH,
                       SUPPORT_ATT, SUPPORT_MSG, SYSTEM_OF, TOMBSTONE, Evidence)
from .identity import IdentityIndex
from .intent import authorizes_deletion

# Operation order = the order of the "Allowed Operations" table.
OP_ORDER = {
    "REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1, "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 4, "BLOCK_RESTORE": 5, "DELETE_RECORD": 6, "REDACT_RECORD": 7,
    "ANONYMIZE_RECORD": 8,
    "VERIFY_RECORD_ABSENT": 9, "VERIFY_RECORD_PRESENT": 10, "VERIFY_RECORD_REDACTED": 11,
    "VERIFY_RECORD_ANONYMIZED": 12, "VERIFY_DATA_FLOW_DISABLED": 13, "VERIFY_RESTORE_BLOCKED": 14,
}
STATE_OF = {
    "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE", "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED", "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED", "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED", "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}
PHASE_OF = {op: ("FINDING" if i < 4 else "REMEDIATION" if i < 9 else "VERIFICATION")
            for op, i in OP_ORDER.items()}
STEP_KEYS = ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]

PREFIX_TYPE = {"account_": PROFILE, "search_": SEARCH, "support_": SUPPORT_MSG, "analytics_": ANALYTICS,
               "export_": EXPORT, "data_flow_": FLOW, "backup_": BACKUP, "audit_record_": AUDIT,
               "legal_hold_": LEGAL, "tombstone_": TOMBSTONE, "marketing_": MARKETING}


def rtype_from_rid(rid):
    for p, t in PREFIX_TYPE.items():
        if rid.startswith(p):
            return t
    return None


@dataclass
class State:
    present: bool | None = True
    pii: bool | None = None
    active: bool | None = None


def judge(rtype, st: State):
    """Apply deletion_rules.csv -> (violation, finding, remedy, verify)."""
    if rtype in (PROFILE, SEARCH, SUPPORT_ATT, EXPORT, MARKETING, OBJECT):
        if st.present:
            return True, "REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"
        return False, None, None, "VERIFY_RECORD_ABSENT"
    if rtype in (SUPPORT_MSG, TOMBSTONE):
        if st.pii:
            return True, "REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"
        return False, None, None, "VERIFY_RECORD_REDACTED"
    if rtype == ANALYTICS:
        if st.pii:
            return True, "REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"
        return False, None, None, "VERIFY_RECORD_ANONYMIZED"
    if rtype == FLOW:
        if st.active:
            return True, "REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"
        return False, None, None, "VERIFY_DATA_FLOW_DISABLED"
    if rtype == BACKUP:
        if st.active:
            return True, "REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"
        return False, None, None, "VERIFY_RESTORE_BLOCKED"
    if rtype in (AUDIT, LEGAL):
        return False, None, None, "VERIFY_RECORD_PRESENT"
    return False, None, None, "VERIFY_RECORD_ABSENT"


@dataclass
class Case:
    req: dict
    sub: object = None
    R: float = 0.0
    rids: dict = field(default_factory=dict)      # rid -> (system, rtype)
    t_acc: float | None = None
    acc_rid: str | None = None
    linked: set = field(default_factory=set)       # rids attached through activity


class Engine:
    def __init__(self, dataset: Path):
        self.dataset = dataset
        self.ev = Evidence(dataset)
        self.ix = IdentityIndex(dataset)
        self.act = ActivityIndex(dataset)
        self.captured = {fid: r["captured_at"] for fid, r in self.ev.files.items()}
        self.obs_by_rid = {}
        self.rid_users = {}
        for o in self.ev.obs:
            self.obs_by_rid.setdefault(o.rid, []).append(o)
            for i in o.ids:
                for u in self.ix.by_id.get(i, ()):
                    self.rid_users.setdefault(o.rid, set()).add(u)
        self.claimed = {}                        # activity_id -> case_id

    # ------------------------------------------------------------------ discovery
    def discover(self, case: Case):
        req, sub = case.req, case.sub
        for o in self.ev.obs:
            if o.t and o.t >= req["requested_at"] and (o.ids & sub.ids):
                case.rids.setdefault(o.rid, (o.system, o.rtype))

    def link_accounts(self, cases):
        """Attach the primary account of every case (and its policy-completed chain)."""
        # pass 1: accounts that identifiers already give us
        for c in cases:
            for rid, (system, rtype) in c.rids.items():
                if rtype == PROFILE:
                    e = self.act.account_event(rid, c.R)
                    if e and c.t_acc is None:
                        c.t_acc, c.acc_rid = e.t, rid
                        self.claimed[e.activity_id] = c.req["case_id"]
        # pass 2..n: resolve the rest from timing signature + exclusivity
        todo = [c for c in cases if c.t_acc is None]
        for _ in range(4):
            progressed = False
            for c in list(todo):
                cands = self.account_candidates(c)
                if len(cands) == 1:
                    self.assign_account(c, cands[0][1])
                    todo.remove(c)
                    progressed = True
            if not progressed:
                break
        for c in todo:                                       # unresolved ties: deterministic pick
            cands = self.account_candidates(c, loose=True)
            if cands:
                self.assign_account(c, cands[0][1])

    def chain_events(self, c):
        """Grounded events of the case (excluding the account) as (time, is_policy)."""
        out = []
        for rid in c.rids:
            if rid == c.acc_rid or rid.startswith(("audit_record_", "account_")):
                continue
            for e in self.act.by_rid.get(rid, ()):
                if e.etype in ("SYNC_RECORD", "RETAIN_RECORD") and not e.policy:
                    continue
                if abs(e.t - c.R) < 9000:
                    out.append((e.t, e.policy))
        return out

    def carrier_files(self, c):
        """Usable evidence files that mention the person (by identifier)."""
        req = c.req
        files = set()
        for rid in c.rids:
            for o in self.obs_by_rid.get(rid, ()):
                if o.ids & c.sub.ids and o.t and req["requested_at"] <= o.t <= req["audit_at"]                         and self.captured[o.file_id] <= req["audit_at"]:
                    files.add(o.file_id)
        return files

    def in_carrier(self, rid, files):
        return any(o.file_id in files for o in self.obs_by_rid.get(rid, ()))

    def account_candidates(self, c, loose=False):
        chain = self.chain_events(c)
        files = self.carrier_files(c)
        scored = []
        for e in self.act.accounts:
            if e.activity_id in self.claimed:
                continue
            off = e.t - c.R
            if not any(lo <= off <= hi for lo, hi in ACCOUNT_WINDOWS):
                continue
            users = self.rid_users.get(e.rid, set())
            if users and c.sub.user_id not in users:
                continue
            ok = True
            score = 0
            for t, pol in chain:
                m = mod30(t - e.t)
                if m in (MOD_P if pol else MOD_V):
                    score += 1
                else:
                    ok = False
            if not chain:
                # no grounded chain: require a plausible analytics 'policy' event for this account
                has = any(self.fits_p(e.t, c.R, key) for key in [("ANONYMIZE_RECORD", "analytics_platform")])
                score = 0.5 if has else 0
            if self.in_carrier(e.rid, files):
                score += 2
            if ok or loose:
                scored.append((-score, e, ok))
        if not scored:
            return []
        best = min(s[0] for s in scored)
        top = [(s[0], s[1]) for s in scored if s[0] == best]
        top.sort(key=lambda x: x[1].t)
        return top

    def fits_p(self, t_acc, R, key):
        lo, hi = P_SLOTS[key]
        for e in self.act.p_events:
            if (e.etype, e.target) != key or e.activity_id in self.claimed:
                continue
            if lo <= e.t - R <= hi and mod30(e.t - t_acc) in MOD_P:
                return True
        return False

    def assign_account(self, c, e):
        c.t_acc, c.acc_rid = e.t, e.rid
        self.claimed[e.activity_id] = c.req["case_id"]
        c.rids.setdefault(e.rid, ("account_service", PROFILE))
        c.linked.add(e.rid)

    def link_chain(self, c):
        """Policy-completed copies (anonymized analytics, redacted support, ...) without identifiers."""
        if c.t_acc is None:
            return
        have = {rtype for _, rtype in c.rids.values()}
        if any(not pol for _, pol in self.chain_events(c)):
            return                      # a "worker reported result" chain: no policy-completed copies
        files = self.carrier_files(c)
        for key, (lo, hi) in P_SLOTS.items():
            rtype = {"analytics_platform": ANALYTICS, "legal_service": LEGAL, "identity_service": TOMBSTONE,
                     "support_platform": SUPPORT_MSG, "integration_service": FLOW,
                     "backup_service": BACKUP}[key[1]]
            if rtype in have or rtype == LEGAL:
                continue
            cands = []
            for e in self.act.p_events:
                if (e.etype, e.target) != key or e.activity_id in self.claimed:
                    continue
                if not (lo <= e.t - c.R <= hi):
                    continue
                m = mod30(e.t - c.t_acc)
                if m not in MOD_P:
                    continue
                users = self.rid_users.get(e.rid, set())
                if users and c.sub.user_id not in users:
                    continue
                cands.append((0 if self.in_carrier(e.rid, files) else 1, abs(m - 10), e.t, e))
            if cands:
                cands.sort(key=lambda x: x[:3])
                e = cands[0][3]
                self.claimed[e.activity_id] = c.req["case_id"]
                c.rids.setdefault(e.rid, (e.target, rtype))
                c.linked.add(e.rid)

    # ------------------------------------------------------------------ states
    def state_of(self, c, rid, rtype):
        """Latest usable observation of the resource -> (State, obs|None)."""
        req = c.req
        audit_at, requested_at = req["audit_at"], req["requested_at"]
        best = None
        for o in self.obs_by_rid.get(rid, ()):
            if not o.t or o.t < requested_at or o.t > audit_at or self.captured[o.file_id] > audit_at:
                continue
            if best is None or (o.t, self.captured[o.file_id]) >= (best.t, self.captured[best.file_id]):
                best = o
        if best is None:
            return None, None
        present = best.present
        if best.expires and best.expires <= audit_at:
            present = False                      # export link already expired at audit time
        return State(present, best.pii, best.active), best

    def default_state(self, rtype):
        if rtype == PROFILE:
            return State(present=False)
        if rtype in (ANALYTICS, SUPPORT_MSG, TOMBSTONE):
            return State(present=True, pii=False)
        if rtype in (FLOW, BACKUP):
            return State(present=True, active=False)
        if rtype in (AUDIT, LEGAL):
            return State(present=True)
        return State(present=False)

    def coverage_file(self, system, req, case_file):
        """File whose snapshot covers ``system`` (used to prove a record is absent)."""
        if case_file and any(o.file_id == case_file and o.system == system for o in self.ev.obs):
            return case_file
        best = None
        for o in self.ev.obs:
            if o.system != system or self.captured[o.file_id] > req["audit_at"] or                     not (req["requested_at"] <= o.t <= req["audit_at"]):
                continue
            if best is None or self.captured[o.file_id] > self.captured[best]:
                best = o.file_id
        return best or case_file or ""

    # ------------------------------------------------------------------ run
    def audit_all(self, requests):
        cases = []
        for req in requests:
            c = Case(req)
            if authorizes_deletion(req["request_text"]):
                c.sub = self.ix.resolve(req["email"])
                c.R = parse_t(req["reported_at"])
                if c.sub:
                    self.discover(c)
            cases.append(c)
        active = [c for c in cases if c.sub and authorizes_deletion(c.req["request_text"])]
        self.link_accounts(active)
        for c in active:
            self.link_chain(c)
        return {c.req["case_id"]: self.build(c) for c in cases}

    def build(self, c: Case):
        req = c.req
        if not authorizes_deletion(req["request_text"]):
            return "NOT_APPLICABLE", []
        resources = []
        for rid, (system, rtype) in c.rids.items():
            st, obs = self.state_of(c, rid, rtype)
            if obs is not None:
                rtype = obs.rtype
                system = obs.system
            if st is None:
                st = self.default_state(rtype)
                obs_file = None
            else:
                obs_file = obs.file_id
            viol, fnd, rem, ver = judge(rtype, st)
            resources.append({"system": system, "rid": rid, "rtype": rtype, "viol": viol, "fnd": fnd,
                              "rem": rem, "ver": ver, "file": obs_file})
        status = "INCOMPLETE" if any(r["viol"] for r in resources) else "COMPLETE"
        # citation file: the usable file carrying most of the case's resources
        count = {}
        for r in resources:
            for o in self.obs_by_rid.get(r["rid"], ()):
                if self.captured[o.file_id] <= req["audit_at"] and o.t and o.t <= req["audit_at"] \
                        and o.t >= req["requested_at"]:
                    count[o.file_id] = count.get(o.file_id, 0) + 0  # placeholder to create key
            for f in {o.file_id for o in self.obs_by_rid.get(r["rid"], ())
                      if self.captured[o.file_id] <= req["audit_at"] and o.t and
                      req["requested_at"] <= o.t <= req["audit_at"]}:
                count[f] = count.get(f, 0) + 1
        case_file = max(count, key=lambda f: (count[f], self.captured[f])) if count else None

        def cite(r):
            files = {o.file_id for o in self.obs_by_rid.get(r["rid"], ())
                     if self.captured[o.file_id] <= req["audit_at"] and o.t and
                     req["requested_at"] <= o.t <= req["audit_at"]}
            if case_file in files:
                return case_file
            if r["file"]:
                return r["file"]
            return self.coverage_file(r["system"], req, case_file)

        steps = []

        def add(op, r, evidence):
            steps.append({"phase": PHASE_OF[op], "system_id": r["system"], "resource_id": r["rid"],
                          "operation": op, "state": STATE_OF[op], "evidence_id": evidence})

        key = lambda pair: (OP_ORDER[pair[0]], pair[1]["system"], pair[1]["rid"])
        if status == "INCOMPLETE":
            for op, r in sorted(((r["fnd"], r) for r in resources if r["viol"]), key=key):
                add(op, r, cite(r))
            for op, r in sorted(((r["rem"], r) for r in resources if r["viol"]), key=key):
                add(op, r, "")
            for op, r in sorted(((r["ver"], r) for r in resources), key=key):
                add(op, r, "")
        else:
            for op, r in sorted(((r["ver"], r) for r in resources), key=key):
                add(op, r, cite(r))
        out = []
        for i, s in enumerate(steps, 1):
            s["step_no"] = i
            out.append({k: s[k] for k in STEP_KEYS})
        return status, out
