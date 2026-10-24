"""Activity-stream linking.

``system_activity.csv`` names resources but never the person.  A deletion
worker run for one request leaves a *chain* of events around the request's
``reported_at``; the events of one chain share a sub-minute timing signature
(the offsets between them are constant modulo 30 seconds, one value for
"worker reported a (possibly failed) result" events and another for
"policy action completed" events).  We use that signature, the time windows
and exclusivity (a resource can belong to one request only) to attach
resources that no evidence file ties to the person by identifier - the
primary account that is already gone, and anonymized / redacted copies that
no longer carry an identifier.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

FMT = "%Y-%m-%dT%H:%M:%SZ"


def parse_t(s: str) -> float:
    return datetime.strptime(s, FMT).timestamp()


@dataclass
class Event:
    activity_id: str
    t: float
    etype: str
    target: str
    rid: str
    result: str
    policy: bool          # "Policy action completed" = the action really happened


# Windows of each chain slot relative to reported_at (seconds), learned from
# requests whose chain is fully identifiable by identifiers.
ACCOUNT_WINDOWS = [(-4700, -2400), (-450, 700)]    # mass chains / short hand-built chains
P_SLOTS = {            # (event_type, target_system): window of the "policy completed" event
    ("ANONYMIZE_RECORD", "analytics_platform"): (-1800, -1640),
    ("RETAIN_RECORD", "legal_service"): (-1800, -1640),
    ("REDACT_RECORD", "identity_service"): (-1800, -1640),
    ("REDACT_RECORD", "support_platform"): (-1400, -850),
    ("DISABLE_DATA_FLOW", "integration_service"): (-950, -420),
    ("BLOCK_RESTORE", "backup_service"): (-520, -150),
}
# offset (event - account) mod 30s: "worker reported result" vs "policy action completed"
MOD_V = (20, 21, 22, 23)
MOD_P = (8, 9, 10, 11, 12)


class ActivityIndex:
    def __init__(self, dataset: Path):
        self.events = []
        self.by_rid = {}
        with open(dataset / "system_activity.csv", encoding="utf-8", newline="") as fh:
            for r in csv.DictReader(fh):
                e = Event(r["activity_id"], parse_t(r["event_time"]), r["event_type"], r["target_system"],
                          r["resource_id"], r["reported_result"], "policy action completed" in
                          r["details"].lower())
                self.events.append(e)
                self.by_rid.setdefault(e.rid, []).append(e)
        self.accounts = [e for e in self.events if e.etype == "DELETE_RECORD" and e.target == "account_service"]
        self.p_events = [e for e in self.events if e.policy and (e.etype, e.target) in P_SLOTS]

    def account_event(self, rid, R):
        for e in self.by_rid.get(rid, ()):
            if e.etype == "DELETE_RECORD" and e.target == "account_service" and \
                    any(lo <= e.t - R <= hi for lo, hi in ACCOUNT_WINDOWS):
                return e
        return None


def mod30(x: float) -> int:
    return int(round(x)) % 30
