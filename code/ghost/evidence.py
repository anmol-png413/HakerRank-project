"""Evidence loaders: turn every structured evidence file into normalized
observations (``Obs``).

An observation says: "in file F, at time T, resource R of system S was seen
in state X, mentioning identifiers I".  Everything downstream (identity
linking, state at ``audit_at``, citation) is built on this one shape.
"""
from __future__ import annotations

import csv
import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from .logparse import parse_line

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
USER_RE = re.compile(r"^user_\d+$")

# resource types
PROFILE, SEARCH, SUPPORT_MSG, SUPPORT_ATT, ANALYTICS, EXPORT, FLOW, BACKUP, AUDIT, LEGAL, TOMBSTONE, \
    MARKETING, OBJECT = ("PROFILE", "SEARCH", "SUPPORT_MSG", "SUPPORT_ATT", "ANALYTICS", "EXPORT",
                         "FLOW", "BACKUP", "AUDIT", "LEGAL", "TOMBSTONE", "MARKETING", "OBJECT")

SYSTEM_OF = {PROFILE: "account_service", SEARCH: "search_service", SUPPORT_MSG: "support_platform",
             SUPPORT_ATT: "support_platform", ANALYTICS: "analytics_platform", EXPORT: "export_service",
             FLOW: "integration_service", BACKUP: "backup_service", AUDIT: "security_service",
             LEGAL: "legal_service", TOMBSTONE: "identity_service", MARKETING: "marketing_platform",
             OBJECT: "object_storage"}
RTYPE_OF_SYSTEM = {v: k for k, v in SYSTEM_OF.items() if k != SUPPORT_ATT}
RECORD_TYPE = {"USER_PROFILE": PROFILE, "SEARCH_INDEX_ENTRY": SEARCH, "SUPPORT_MESSAGE": SUPPORT_MSG,
               "SUPPORT_ATTACHMENT": SUPPORT_ATT, "ANALYTICS_PROFILE": ANALYTICS, "USER_EXPORT": EXPORT,
               "DATA_FLOW": FLOW, "BACKUP_ARCHIVE": BACKUP, "SECURITY_AUDIT_LOG": AUDIT,
               "LEGAL_HOLD_RECORD": LEGAL, "ACCOUNT_TOMBSTONE": TOMBSTONE,
               "MARKETING_PROFILE": MARKETING}


@dataclass
class Obs:
    file_id: str
    t: str                      # ISO timestamp of the observation
    system: str
    rid: str
    rtype: str
    present: bool | None = True  # record exists
    pii: bool | None = None      # direct identifiers still exposed
    active: bool | None = None   # flow enabled / restore allowed
    ids: frozenset = frozenset()
    fam: str = ""
    note: str = ""
    expires: str = ""            # export links stop working at this time


def norm_id(v):
    """Normalise one identifier-like value; returns None when unusable."""
    if v is None:
        return None
    s = str(v).strip()
    if not s or s.lower() in ("null", "none", "n/a", "no direct identifier", "[redacted]", "redacted"):
        return None
    if "@" in s:
        return s.lower()
    if HASH_RE.match(s.lower()):
        return s.lower()
    if USER_RE.match(s):
        return s
    digits = re.sub(r"\D", "", s)
    if s.startswith("+") and len(digits) >= 7:
        return "p:" + digits
    return None


def ids_of(*vals, text: str | None = None):
    out = set()
    for v in vals:
        n = norm_id(v)
        if n:
            out.add(n)
    if text:
        for m in EMAIL_RE.findall(text):
            out.add(m.lower())
    return frozenset(out)


def truthy(v) -> bool:
    return str(v).strip().lower() in ("true", "1", "yes")


# --------------------------------------------------------------------------
# record_lookup style ({system, resource_id, record_type, result, subject})
# --------------------------------------------------------------------------
def lookup_obs(file_id, t, system, rid, record_type, result, subject, fam):
    rtype = RECORD_TYPE.get(record_type)
    if rtype is None:
        return None
    result = (result or "").upper()
    present, pii, active = True, None, None
    if result in ("NOT_FOUND", "ABSENT", "DELETED"):
        present = False
    elif result == "IDENTIFIABLE":
        pii = True
    elif result in ("REDACTED", "ANONYMIZED"):
        pii = False
    elif result == "ACTIVE":
        active = True
    elif result in ("DISABLED", "BLOCKED"):
        active = False
    return Obs(file_id, t, system or SYSTEM_OF[rtype], rid, rtype, present, pii, active,
               ids_of(subject), fam)


# --------------------------------------------------------------------------
# collection records (bundle snapshots, SQL replica record_json)
# --------------------------------------------------------------------------
def collection_obs(file_id, t, store, coll, rec, fam):
    rid = rec.get("resource_id")
    if not rid:
        return None
    if coll == "operational_record_history":
        return lookup_obs(file_id, rec.get("recorded_at", t), rec.get("system"), rid,
                          rec.get("record_type"), rec.get("result"), rec.get("lookup_value"), fam)
    if coll == "customer_profiles":
        return Obs(file_id, t, "account_service", rid, PROFILE, True, None, None,
                   ids_of(rec.get("customer_reference"), rec.get("email"), rec.get("phone"),
                          rec.get("email_hash")), fam)
    if coll == "customer_search_documents":
        d = rec.get("document") or {}
        return Obs(file_id, t, "search_service", rid, SEARCH, True, None, None,
                   ids_of(d.get("customer_reference"), d.get("email"), d.get("phone"),
                          d.get("email_hash")), fam)
    if coll == "customer_analytics_reports":
        ids = ids_of(rec.get("user_id"), rec.get("email"), rec.get("phone"), rec.get("email_hash"))
        return Obs(file_id, t, "analytics_platform", rid, ANALYTICS, True, bool(ids), None, ids, fam)
    if coll == "backup_catalog":
        return Obs(file_id, t, "backup_service", rid, BACKUP, True, None, bool(rec.get("restore_allowed")),
                   ids_of(rec.get("subject_reference")), fam)
    if coll == "customer_export_jobs":
        o = Obs(file_id, t, "export_service", rid, EXPORT, bool(rec.get("download_available", True)),
                None, None, ids_of(rec.get("owner_email")), fam)
        o.expires = rec.get("expires_at") or ""
        return o
    if coll == "deleted_customer_references":
        pii = any(rec.get(k) for k in ("name", "email", "phone", "email_hash"))
        ids = ids_of(rec.get("email"), rec.get("phone"), rec.get("email_hash"), rec.get("subject_reference"))
        return Obs(file_id, t, "identity_service", rid, TOMBSTONE, True, pii, None, ids, fam)
    if coll == "connector_configurations":
        return Obs(file_id, t, "integration_service", rid, FLOW, True, None, bool(rec.get("enabled")),
                   ids_of(rec.get("subject_selector")), fam)
    if coll == "retained_order_records":
        return Obs(file_id, t, "legal_service", rid, LEGAL, True, None, None,
                   ids_of(rec.get("subject_reference")), fam)
    if coll == "security_audit_events":
        return Obs(file_id, t, "security_service", rid, AUDIT, True, None, None,
                   ids_of(rec.get("subject_reference")), fam)
    if coll == "support_conversations":
        text = rec.get("message_text") or ""
        emails = EMAIL_RE.findall(text)
        return Obs(file_id, t, "support_platform", rid, SUPPORT_MSG, True, bool(emails), None,
                   ids_of(rec.get("subject_reference"), text=text), fam)
    if coll == "ticket_attachments":
        return Obs(file_id, t, "support_platform", rid, SUPPORT_ATT, True, None, None,
                   ids_of(rec.get("uploaded_by")), fam)
    return None


def load_sql(file_id, path: Path, captured_at: str):
    text = path.read_text(encoding="utf-8-sig")
    con = sqlite3.connect(":memory:")
    con.executescript(text)
    tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
    obs = []
    scope = {}
    if "snapshot_scope" in tables:
        scope = {r[0]: r[1] for r in con.execute("select origin_system, captured_at from snapshot_scope")}
    for tb in tables:
        cols = [r[1] for r in con.execute(f"pragma table_info({tb})")]
        rows = [dict(zip(cols, r)) for r in con.execute(f"select * from {tb}")]
        if tb == "snapshot_scope":
            continue
        if "record_json" in cols:                       # customer_data_* topology tables
            for r in rows:
                rec = json.loads(r["record_json"])
                o = collection_obs(file_id, r["updated_at"], r["origin_system"], r["collection_name"], rec,
                                   "sql_replica")
                if o:
                    o.note = tb
                    obs.append(o)
        else:
            obs.extend(inventory_obs(file_id, tb, rows))
    return obs, scope


def inventory_obs(file_id, tb, rows):
    out = []
    fam = "sql_inventory"
    for r in rows:
        t = r.get("updated_at") or r.get("indexed_at")
        rid = r.get("resource_id")
        if tb in ("customer_profiles_failover_replica", "customer_profiles_primary"):
            out.append(Obs(file_id, t, "account_service", rid, PROFILE, True, None, None,
                           ids_of(r.get("user_id"), r.get("email"), r.get("phone")), fam, tb))
        elif tb == "customer_profiles":
            out.append(Obs(file_id, t, "account_service", rid, PROFILE, True, None, None,
                           ids_of(r.get("customer_reference"), r.get("email"), r.get("phone"),
                                  r.get("email_hash")), fam, tb))
        elif tb == "customer_search_documents":
            out.append(Obs(file_id, t, "search_service", rid, SEARCH, True, None, None,
                           ids_of(r.get("customer_reference"), r.get("email"), r.get("phone"),
                                  r.get("email_hash")), fam, tb))
        elif tb == "search_documents_primary":
            out.append(Obs(file_id, t, "search_service", rid, SEARCH, True, None, None,
                           ids_of(r.get("email")), fam, tb))
        elif tb == "customer_analytics_profiles":
            ids = ids_of(r.get("customer_reference"), r.get("email"), r.get("phone"), r.get("email_hash"))
            out.append(Obs(file_id, t, "analytics_platform", rid, ANALYTICS, True, bool(ids), None, ids,
                           fam, tb))
        elif tb == "support_records":
            ids = ids_of(r.get("requester_email"), r.get("requester_phone"))
            out.append(Obs(file_id, t, "support_platform", rid, SUPPORT_MSG, True, bool(ids), None,
                           ids | ids_of(r.get("customer_reference")), fam, tb))
        elif tb == "customer_exports":
            out.append(Obs(file_id, t, "export_service", rid, EXPORT, True, None, None,
                           ids_of(r.get("customer_reference"), r.get("owner_email"), r.get("owner_phone")),
                           fam, tb))
        elif tb == "connector_subscriptions":
            out.append(Obs(file_id, t, "integration_service", rid, FLOW, True, None,
                           bool(int(r.get("enabled") or 0)),
                           ids_of(r.get("customer_reference"), r.get("customer_email")), fam, tb))
        elif tb == "backup_restore_entries":
            out.append(Obs(file_id, t, "backup_service", rid, BACKUP, True, None,
                           bool(int(r.get("restore_allowed") or 0)),
                           ids_of(r.get("customer_reference"), r.get("customer_email")), fam, tb))
        elif tb == "security_audit_records":
            out.append(Obs(file_id, t, "security_service", rid, AUDIT, True, None, None,
                           ids_of(r.get("subject_reference")), fam, tb))
    return out


def load_bundle(file_id, j):
    obs = []
    scope = []
    for s in j.get("snapshots", []):
        t = s.get("captured_at") or j.get("exported_at")
        scope.append((s["data_store"], s["collection"], t))
        for rec in s.get("records", []):
            o = collection_obs(file_id, t, s["data_store"], s["collection"], rec, "bundle")
            if o:
                obs.append(o)
    return obs, scope


def load_service_export(file_id, j):
    obs = []
    fam = "service_export"
    for svc, d in j.get("service_exports", {}).items():
        for lk, lst in d.items():
            for it in lst:
                t = it.get("observed_at") or j.get("exported_at")
                rid = it.get("resource_id")
                if svc == "account_service":
                    p = it.get("profile") or {}
                    present = it.get("status_code") == 200
                    ids = ids_of(p.get("customer_reference"), p.get("email"), p.get("phone"),
                                 p.get("email_hash")) if present else frozenset()
                    obs.append(Obs(file_id, t, svc, rid, PROFILE, present, None, None, ids, fam))
                elif svc == "analytics_platform":
                    ids = ids_of(it.get("customer_reference"), it.get("email"), it.get("phone"),
                                 it.get("email_hash"))
                    obs.append(Obs(file_id, t, svc, rid, ANALYTICS, True, bool(ids), None, ids, fam))
                elif svc == "backup_service":
                    obs.append(Obs(file_id, t, svc, rid, BACKUP, True, None, bool(it.get("restore_allowed")),
                                   ids_of(it.get("customer_reference"), it.get("customer_email")), fam))
                elif svc == "export_service":
                    obs.append(Obs(file_id, t, svc, rid, EXPORT, True, None, None,
                                   ids_of(it.get("customer_reference"), it.get("owner_email"),
                                          it.get("owner_phone")), fam))
                elif svc == "integration_service":
                    obs.append(Obs(file_id, t, svc, rid, FLOW, True, None, bool(it.get("enabled")),
                                   ids_of(it.get("customer_reference"), it.get("customer_email")), fam))
                elif svc == "search_service":
                    docs = (it.get("hits") or {}).get("documents") or []
                    present = bool(docs) or (it.get("hits") or {}).get("total", 0) > 0
                    ids = frozenset()
                    for d in docs:
                        ids |= ids_of(d.get("customer_reference"), d.get("email"), d.get("phone"),
                                      d.get("email_hash"))
                    ids |= ids_of(it.get("query"))
                    obs.append(Obs(file_id, t, svc, rid, SEARCH, present, None, None, ids, fam))
                elif svc == "security_service":
                    obs.append(Obs(file_id, t, svc, rid, AUDIT, True, None, None,
                                   ids_of(it.get("subject_reference")), fam))
                elif svc == "support_platform":
                    ids = ids_of(it.get("requester_email"), it.get("requester_phone"))
                    obs.append(Obs(file_id, t, svc, rid, SUPPORT_MSG, True, bool(ids), None,
                                   ids | ids_of(it.get("customer_reference")), fam))
    return obs


def load_lookup_json(file_id, j):
    obs = []
    for r in j.get("records", []):
        if "record_type" in r:
            o = lookup_obs(file_id, r.get("recorded_at") or j.get("exported_at"), r.get("system"),
                           r["resource_id"], r["record_type"], r.get("result"),
                           r.get("subject_reference"), "lookup_json")
            if o:
                obs.append(o)
    return obs


def load_collection_json(file_id, j):
    """analytics report / export jobs files: {captured_at, collection, records}."""
    obs = []
    coll = j.get("collection")
    t = j.get("captured_at")
    for rec in j.get("records", []):
        o = collection_obs(file_id, t, j.get("source"), coll, rec, "collection_json")
        if o is None and coll == "customer_analytics_reports":
            o = None
        if o:
            obs.append(o)
    return obs


def load_txt(file_id, text):
    obs = []
    for line in text.splitlines():
        if not line.startswith("- "):
            continue
        p = [x.strip() for x in line[2:].split("|")]
        if len(p) < 6:
            continue
        o = lookup_obs(file_id, p[0], p[1], p[2], p[3], p[4], p[5], "txt_lookup")
        if o:
            obs.append(o)
    return obs


# --------------------------------------------------------------------------
# logs
# --------------------------------------------------------------------------
KEYS_LOOKUP = ("lookup_key", "match_key", "subject_key", "scan_key", "owner_key", "subject_ref",
               "correlation_key")


def load_log(file_id, text):
    obs = []
    groups: dict = {}
    order = []
    for raw in text.splitlines():
        r = parse_line(raw)
        if not r:
            continue
        ts, fl = r
        ev = fl.get("event")
        if ev == "record_lookup":
            o = lookup_obs(file_id, ts, fl.get("system"), fl.get("resource_id"), fl.get("record_type"),
                           fl.get("result"), fl.get("subject_reference"), "log_lookup")
            if o:
                obs.append(o)
            continue
        key = fl.get("trace_id") or ("line%d" % len(order))
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append((ts, fl))
    for key in order:
        merged: dict = {}
        ts_last = None
        for ts, fl in groups[key]:
            merged.update({k: v for k, v in fl.items() if not (k == "resource_id" and k in merged and
                                                               fl.get("event", "").endswith("_started") and False)})
            ts_last = ts
        o = trace_obs(file_id, ts_last, merged, groups[key])
        obs.extend(o)
    return obs


def trace_obs(file_id, ts, f, lines):
    svc = f.get("service")
    rid = f.get("resource_id")
    if not rid:
        return []
    keys = [f.get(k) for k in KEYS_LOOKUP]
    base_ids = ids_of(*keys, f.get("matched_value"), f.get("email"), f.get("customer_email"),
                      f.get("customer_reference"), f.get("owner_email"), f.get("requester_email"),
                      f.get("requester_phone"), f.get("subject_reference"), f.get("phone"),
                      f.get("email_hash"))
    fam = "log_trace"
    events = {fl.get("event") for _, fl in lines}
    if svc in ("account_service", "profile_service") and "profile_lookup_completed" in events:
        present = f.get("rows") not in ("0",) and f.get("http_status") != "404"
        return [Obs(file_id, ts, "account_service", rid, PROFILE, present, None, None,
                    base_ids if present else base_ids, fam)]
    if svc == "search_service" and "index_query_completed" in events:
        present = f.get("result") == "hit" or f.get("total_hits") not in (None, "0")
        return [Obs(file_id, ts, svc, rid, SEARCH, present, None, None, base_ids, fam)]
    if svc == "support_platform":
        if "message_pii_scan" in events:
            return [Obs(file_id, ts, svc, rid, SUPPORT_MSG, True, True, None, base_ids, fam)]
        if "attachment_pii_scan" in events:
            return [Obs(file_id, ts, svc, rid, SUPPORT_ATT, True, True, None, base_ids, fam)]
        if "support_ticket_read_completed" in events:
            has = bool(ids_of(f.get("requester_email"), f.get("requester_phone")))
            return [Obs(file_id, ts, svc, rid, SUPPORT_MSG, True, has, None, base_ids, fam)]
        if "message_read" in events:
            has = bool(EMAIL_RE.findall(f.get("message_text") or ""))
            return [Obs(file_id, ts, svc, rid, SUPPORT_MSG, True, has,
                        None, base_ids | ids_of(text=f.get("message_text")), fam)]
        return []
    if svc == "support_replica" and "contact_query_completed" in events:
        return [Obs(file_id, ts, "support_platform", rid, SUPPORT_ATT, True, None, None, base_ids, fam)]
    if svc == "analytics_platform":
        if "analytics_identity_scan" in events:
            return [Obs(file_id, ts, svc, rid, ANALYTICS, True, True, None, base_ids, fam)]
        if "analytics_profile_read" in events:
            pii = f.get("direct_identifiers") not in (None, "0")
            return [Obs(file_id, ts, svc, rid, ANALYTICS, True, pii, None, base_ids, fam)]
        if "analytics_profile_read_completed" in events:
            ids = ids_of(f.get("customer_reference"), f.get("email"), f.get("phone"), f.get("email_hash"))
            return [Obs(file_id, ts, svc, rid, ANALYTICS, True, bool(ids), None, base_ids, fam)]
        if "contact_lookup_completed" in events:     # marketing contact record kept in analytics
            return [Obs(file_id, ts, svc, rid, MARKETING, True, None, None, base_ids, fam)]
        return []
    if svc == "backup_service":
        if "restore_policy_read_completed" in events:
            return [Obs(file_id, ts, svc, rid, BACKUP, True, None, truthy(f.get("restore_allowed")),
                        base_ids, fam)]
        if "restore_authorization_completed" in events:
            return [Obs(file_id, ts, svc, rid, BACKUP, True, None, f.get("decision") == "allow",
                        base_ids, fam)]
        if "restore_candidate_evaluated" in events:
            act = truthy(f.get("eligible")) and not truthy(f.get("deletion_block"))
            return [Obs(file_id, ts, svc, rid, BACKUP, True, None, act, base_ids, fam)]
        return []
    if svc == "export_service":
        if "export_download_check_completed" in events or "export_metadata_read_completed" in events:
            return [Obs(file_id, ts, svc, rid, EXPORT, True, None, None, base_ids, fam)]
        return []
    if svc == "integration_service":
        if "connector_config_read_completed" in events or "connector_config_loaded" in events \
                or "connector_heartbeat" in events:
            return [Obs(file_id, ts, svc, rid, FLOW, True, None, truthy(f.get("enabled")), base_ids, fam)]
        return []
    if svc == "security_service" and ("audit_record_read_completed" in events):
        return [Obs(file_id, ts, svc, rid, AUDIT, True, None, None, base_ids, fam)]
    if svc == "legal_service" and "retained_order_loaded" in events:
        return [Obs(file_id, ts, svc, rid, LEGAL, True, None, None, base_ids, fam)]
    return []


# --------------------------------------------------------------------------
class Evidence:
    def __init__(self, dataset: Path):
        self.dataset = dataset
        self.files = {}          # file_id -> dict(path, origin, captured_at)
        self.obs: list[Obs] = []
        self.scopes = {}         # file_id -> coverage info
        self._load()

    def _load(self):
        with open(self.dataset / "evidence_files.csv", encoding="utf-8", newline="") as fh:
            for r in csv.DictReader(fh):
                self.files[r["file_id"]] = r
        for fid, r in self.files.items():
            path = self.dataset / r["file_path"]
            ext = path.suffix.lower()
            obs = []
            try:
                if ext == ".sql":
                    obs, scope = load_sql(fid, path, r["captured_at"])
                    self.scopes[fid] = scope
                elif ext == ".json":
                    j = json.loads(path.read_text(encoding="utf-8-sig"))
                    if "snapshots" in j:
                        obs, scope = load_bundle(fid, j)
                        self.scopes[fid] = scope
                    elif "service_exports" in j:
                        obs = load_service_export(fid, j)
                    elif "origin" in j and "records" in j:
                        obs = load_lookup_json(fid, j)
                    elif "collection" in j:
                        obs = load_collection_json(fid, j)
                elif ext == ".log":
                    obs = load_log(fid, path.read_text(encoding="utf-8-sig"))
                elif ext == ".txt":
                    obs = load_txt(fid, path.read_text(encoding="utf-8-sig"))
            except Exception as exc:  # noqa: BLE001 - keep loading other files
                print(f"warning: could not parse {fid}: {exc}")
            self.obs.extend(obs)
        from .transcripts import transcript_obs
        self.obs.extend(transcript_obs(self.dataset, self.files))
