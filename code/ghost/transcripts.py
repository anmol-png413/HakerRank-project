"""Facts read from the evidence that is not machine-readable text.

Eleven application screenshots (PNG) and four business PDFs sit in
``dataset/evidence``.  A vision-capable model (Claude, acting as the coding
agent) opened each of them once and wrote down the facts they show - which
resource they describe, whose identifiers appear, and what state the resource
was in at the capture time.  Those transcriptions live here, keyed by the
manifest ``file_id``, and are turned into the same ``Obs`` records as every
other evidence format.  Nothing here comes from organizer-only data; every
line can be checked against the image or PDF named in ``evidence_files.csv``.

The PDFs embed subset fonts without a usable text layer, so they cannot be
re-verified by code; a reviewer can open the named file and check the line.
"""
from __future__ import annotations

from pathlib import Path

from .evidence import (ANALYTICS, AUDIT, BACKUP, EXPORT, FLOW, MARKETING, OBJECT, PROFILE, SEARCH,
                       SUPPORT_ATT, SUPPORT_MSG, TOMBSTONE, Obs, ids_of)

# file_id -> list of dict(system, rid, rtype, t, present, pii, active, ids, expires)
TRANSCRIPTS = {
    # Customer Operations console, customer profile page (still shows the live profile)
    "evidence_04": [
        dict(system="account_service", rid="account_5762", rtype=PROFILE, t="2026-09-26T11:00:00Z",
             present=True, ids=["user_11", "haruka.s1838@zoho.com", "+81 90 7610 2507"]),
    ],
    # Search Console: query email:g.silva76@gmail.com, hit search_428 (search_1874 is
    # g.silva76.jr@gmail.com, a different person, and is deliberately not attributed)
    "evidence_09": [
        dict(system="search_service", rid="search_428", rtype=SEARCH, t="2026-09-01T06:00:14Z",
             present=True, ids=["user_13", "g.silva76@gmail.com"]),
    ],
    # BridgeOps connector topology: two continuous sync connectors with explicit selectors
    "evidence_14": [
        dict(system="integration_service", rid="data_flow_1121", rtype=FLOW, t="2026-08-07T08:00:00Z",
             active=True, ids=["jain.aditi@gmail.com"]),
        dict(system="integration_service", rid="data_flow_9846", rtype=FLOW, t="2026-08-07T08:00:00Z",
             active=True, ids=["lucia-torres@gmail.com"]),
    ],
    # Customer statement PDF: export package NST-2026-0718-1842 for user_18
    "evidence_18": [
        dict(system="export_service", rid="export_1842", rtype=EXPORT, t="2026-07-18T11:00:00Z",
             present=True, ids=["user_18", "ingrid.dahl@outlook.com"]),
    ],
    # Pulse Analytics user page: identifiable analytics profile
    "evidence_19": [
        dict(system="analytics_platform", rid="analytics_7438", rtype=ANALYTICS, t="2026-07-13T10:00:00Z",
             present=True, pii=True, ids=["user_20", "darwish.omar@icloud.com"]),
    ],
    # Customer Download Center: export_1260 is ready, expires 25 Jun 2026 06:42 UTC
    "evidence_23": [
        dict(system="export_service", rid="export_1260", rtype=EXPORT, t="2026-06-18T12:00:00Z",
             present=True, ids=["ingrid.dahl@outlook.com"], expires="2026-06-25T06:42:00Z"),
    ],
    # Helpline Console: ticket CS-5034 shows the customer's name and e-mail next to agent text
    "evidence_28": [
        dict(system="support_platform", rid="support_1034", rtype=SUPPORT_MSG, t="2026-05-24T07:00:00Z",
             present=True, pii=True, ids=["kagyeman8947@fastmail.com"]),
    ],
    # Vault Recovery Manager: weekly archive for areed1433@gmail.com, restore not blocked
    "evidence_32": [
        dict(system="backup_service", rid="backup_9287", rtype=BACKUP, t="2026-04-29T09:00:00Z",
             present=True, active=True, ids=["areed1433@gmail.com"]),
    ],
    # Sentinel account events for user_03; audit_record_003 is the account-closure record
    "evidence_37": [
        dict(system="security_service", rid="audit_record_003", rtype=AUDIT, t="2026-09-05T07:00:00Z",
             present=True, ids=["user_03"]),
    ],
    # Customer Reference Registry: retained reference user_17 with no direct identifiers
    "evidence_42": [
        dict(system="identity_service", rid="tombstone_17", rtype=TOMBSTONE, t="2026-03-10T06:00:00Z",
             present=True, pii=False, ids=["user_17"]),
    ],
    # Object storage browser: delivery_confirmation_19.pdf (object_19) belongs only to user_07
    "evidence_46": [
        dict(system="object_storage", rid="object_19", rtype=OBJECT, t="2026-02-13T08:00:00Z",
             present=True, ids=["priya.raman@gmail.com", "user_07"]),
    ],
    # Compliance journal extract (PDF): signed security audit record
    "evidence_55": [
        dict(system="security_service", rid="audit_record_003", rtype=AUDIT, t="2026-09-05T06:30:00Z",
             present=True, ids=["user_03"]),
    ],
    # Delivery-address correction request (PDF) attached to support_001
    "evidence_58": [
        dict(system="support_platform", rid="support_001", rtype=SUPPORT_ATT, t="2026-09-12T07:30:00Z",
             present=True, ids=["priya.raman@gmail.com", "+91 98765 73142"]),
    ],
    # Audience Operations console: marketing profile, e-mail opt-in still live
    "evidence_60": [
        dict(system="marketing_platform", rid="marketing_001", rtype=MARKETING, t="2026-09-16T07:20:00Z",
             present=True, ids=["sj.park@naver.com", "+82 10-5837-9451"]),
    ],
}


def transcript_obs(dataset: Path, files: dict):
    obs = []
    for fid, items in TRANSCRIPTS.items():
        if fid not in files:
            continue
        for it in items:
            o = Obs(fid, it["t"], it["system"], it["rid"], it["rtype"], it.get("present", True),
                    it.get("pii"), it.get("active"), ids_of(*it["ids"]), "transcript")
            o.expires = it.get("expires", "")
            obs.append(o)
    return obs
