"""Identity resolution: request email -> user, plus every historical identifier."""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path

from .evidence import norm_id


@dataclass
class Subject:
    user_id: str
    name: str
    current_email: str
    ids: set = field(default_factory=set)       # normalized identifiers (emails, phones, hashes, user id)
    old_emails: set = field(default_factory=set)
    audit_ids: list = field(default_factory=list)


class IdentityIndex:
    def __init__(self, dataset: Path):
        self.users = {}
        self.by_id = {}                          # identifier -> user_id
        with open(dataset / "user_identities.csv", encoding="utf-8", newline="") as fh:
            for r in csv.DictReader(fh):
                s = Subject(r["user_id"], r["name"], r["email"].lower())
                for v in (r["email"], r["phone"], r["email_hash"], r["user_id"]):
                    n = norm_id(v)
                    if n:
                        s.ids.add(n)
                self.users[r["user_id"]] = s
        with open(dataset / "user_audit_log.csv", encoding="utf-8", newline="") as fh:
            for r in csv.DictReader(fh):
                s = self.users.get(r["user_id"])
                if not s:
                    continue
                s.audit_ids.append(r["audit_id"])
                for v in (r["old_value"], r["new_value"]):
                    n = norm_id(v)
                    if n:
                        s.ids.add(n)
                if r["field_name"] == "email":
                    s.old_emails.add(r["old_value"].lower())
        for uid, s in self.users.items():
            for i in s.ids:
                self.by_id.setdefault(i, set()).add(uid)

    def resolve(self, email: str):
        """Return the subject whose current or historical email matches."""
        e = email.strip().lower()
        hits = self.by_id.get(e, set())
        if len(hits) == 1:
            return self.users[next(iter(hits))]
        if hits:
            for uid in hits:
                if self.users[uid].current_email == e:
                    return self.users[uid]
            return self.users[sorted(hits)[0]]
        return None
