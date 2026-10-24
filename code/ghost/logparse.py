"""Generic parser for the many log syntaxes found in dataset/evidence/logs.

Every line is reduced to ``(timestamp, fields)`` where ``fields`` is a flat
dict of strings.  Supported syntaxes (all begin with an ISO timestamp):

* ``ts level=X service=Y k=v k="v" ...``
* ``ts {json}``
* ``ts [LEVEL] [service] [trace] event: k="v" ...``
* ``ts | LEVEL | service | trace | event | k="v" ...``
* ``ts <pri>1 node service trace - - level=X k="v" ...``
* ``ts requestId=.. level=.. function=svc message="k=\\"v\\" ..."``
"""
from __future__ import annotations

import json
import re

TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s+(.*)$")
KV_RE = re.compile(r'([A-Za-z_][\w]*)=("([^"]*)"|[^\s"]+)')


def _kv(text: str) -> dict:
    out = {}
    for m in KV_RE.finditer(text):
        val = m.group(3) if m.group(3) is not None else m.group(2)
        out[m.group(1)] = val
    return out


def parse_line(line: str):
    line = line.strip()
    m = TS_RE.match(line)
    if not m:
        return None
    ts, rest = m.group(1), m.group(2)
    fields: dict = {}
    if rest.startswith("{"):
        try:
            obj = json.loads(rest)
        except ValueError:
            return None
        fields = {k: ("null" if v is None else str(v)) for k, v in obj.items()}
        if "logger" in fields and "service" not in fields:
            fields["service"] = fields["logger"]
        if "severity" in fields:
            fields["level"] = fields["severity"]
    elif rest.startswith("["):
        mm = re.match(r"\[(\w+)\]\s+\[(\w+)\]\s+\[([^\]]+)\]\s+(\w+):\s*(.*)$", rest)
        if not mm:
            return None
        fields = {"level": mm.group(1), "service": mm.group(2),
                  "trace_id": mm.group(3), "event": mm.group(4)}
        fields.update(_kv(mm.group(5)))
    elif rest.startswith("<"):
        mm = re.match(r"<\d+>1\s+(\S+)\s+(\w+)\s+(\S+)\s+-\s+-\s+(.*)$", rest)
        if not mm:
            return None
        fields = {"node": mm.group(1), "service": mm.group(2), "trace_id": mm.group(3)}
        fields.update(_kv(mm.group(4)))
    elif rest.startswith("|"):
        parts = [p.strip() for p in rest.lstrip("| ").split(" | ", 4)]
        if len(parts) < 5:
            return None
        fields = {"level": parts[0], "service": parts[1], "trace_id": parts[2],
                  "event": parts[3]}
        fields.update(_kv(parts[4]))
    else:
        if 'message="' in rest:
            head, _, msg = rest.partition('message="')
            msg = msg.rstrip('"').replace('\\"', '"')
            fields = _kv(head)
            fields.update(_kv(msg))
            if "requestId" in fields:
                fields["trace_id"] = fields.pop("requestId")
            if "function" in fields and "service" not in fields:
                fields["service"] = fields.pop("function")
        else:
            fields = _kv(rest)
    return ts, fields


def parse_log(text: str):
    out = []
    for raw in text.splitlines():
        r = parse_line(raw)
        if r:
            out.append(r)
    return out
