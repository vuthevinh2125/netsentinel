"""Read-only investigation tools the triage agent can call.

Every tool returns a small JSON-serialisable dict, never raw log dumps, so the agent's
context stays short and the same tools work for the LLM agent and the offline analyst.
"""
from __future__ import annotations

import datetime as dt

import pandas as pd

from .. import mitre
from ..detect import DetectionResult
from ..features import internal_mask, is_internal, set_home_hosts
from ..simulate import LabData

TZ = dt.timezone(dt.timedelta(hours=7))


def fmt(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, TZ).strftime("%d/%m %H:%M")


class Workspace:
    def __init__(self, data: LabData, result: DetectionResult):
        self.data = data
        self.result = result
        self.alerts = {a.alert_id: a for a in result.alerts}
        self.incidents = {i.incident_id: i for i in result.incidents}
        self.hosts = data.hosts.set_index("ip")
        self.baseline_end = result.config["baseline_end"]

    # ---------------------------------------------------------------- tools
    def get_incident(self, incident_id: str) -> dict:
        inc = self.incidents.get(incident_id)
        if inc is None:
            return {"error": f"No incident {incident_id}"}
        alerts = [self.alerts[a] for a in inc.alert_ids]
        return {
            **inc.to_dict(),
            "start_local": fmt(inc.start), "end_local": fmt(inc.end),
            "alerts": [{"alert_id": a.alert_id, "detector": a.detector, "technique": a.technique, "title": a.title,
                        "severity": a.severity, "score": a.score, "src_ip": a.src_ip, "targets": a.targets[:8],
                        "start": a.start, "end": a.end,
                        "start_local": fmt(a.start), "end_local": fmt(a.end), "evidence": a.evidence} for a in alerts],
        }

    def host_profile(self, ip: str) -> dict:
        info = self.hosts.loc[ip].to_dict() if ip in self.hosts.index else {"hostname": "external", "role": "internet host"}
        f = self.data.flows
        days = float(self.data.meta.get("baseline_days") or 0)
        no_baseline = days <= 0
        # Real captures have no clean baseline: describe the whole capture instead, and say so.
        base = f[f.src_ip == ip] if no_baseline else f[(f.src_ip == ip) & (f.ts < self.baseline_end)]
        if no_baseline:
            days = max(1e-9, (f.ts.max() - f.ts.min()) / 86400)
        a = self.data.auth
        accounts = sorted(a[(a.src_ip == ip) & (no_baseline | (a.ts < self.baseline_end))].user.unique().tolist())
        return {
            "ip": ip, **info,
            "note": "No clean baseline exists: these figures cover the whole capture, including any malicious activity." if no_baseline else "",
            "baseline": {
                "connections_per_day": round(len(base) / days),
                "usual_ports": base.dst_port.value_counts().head(6).index.tolist(),
                "internal_peers": sorted(base.loc[internal_mask(base.dst_ip), "dst_ip"].unique().tolist())[:10],
                "external_destinations": int(base.loc[~internal_mask(base.dst_ip), "dst_ip"].nunique()),
                "accounts_used": accounts[:8],
            },
            "first_seen_in_baseline": not base.empty or ip in self.hosts.index,
        }

    def query_flows(self, ip: str, start: float | None = None, end: float | None = None, direction: str = "out", limit: int = 8) -> dict:
        f = self.data.flows
        col = "src_ip" if direction == "out" else "dst_ip"
        q = f[f[col] == ip]
        if start is not None:
            q = q[q.ts >= start]
        if end is not None:
            q = q[q.ts <= end]
        other = "dst_ip" if direction == "out" else "src_ip"
        g = q.groupby([other, "dst_port"]).agg(connections=("ts", "size"), bytes_out=("bytes_out", "sum"),
                                                bytes_in=("bytes_in", "sum"), first=("ts", "min"), last=("ts", "max"))
        g = g.sort_values("bytes_out", ascending=False).head(limit).reset_index()
        rows = [{"peer": r[other], "port": int(r.dst_port), "connections": int(r.connections),
                 "mb_out": round(r.bytes_out / 1e6, 2), "mb_in": round(r.bytes_in / 1e6, 2),
                 "first": fmt(r["first"]), "last": fmt(r["last"])} for _, r in g.iterrows()]
        return {"ip": ip, "direction": direction, "total_connections": int(len(q)), "top": rows}

    def auth_events(self, ip: str, start: float | None = None, end: float | None = None) -> dict:
        a = self.data.auth
        q = a[(a.src_ip == ip) | (a.dst_ip == ip)]
        if start is not None:
            q = q[q.ts >= start]
        if end is not None:
            q = q[q.ts <= end]
        g = q.groupby(["src_ip", "dst_ip", "user", "service", "result"]).size().reset_index(name="count")
        g = g.sort_values("count", ascending=False).head(10)
        return {"ip": ip, "events": int(len(q)), "summary": g.to_dict("records")}

    def dns_queries(self, ip: str, start: float | None = None, end: float | None = None) -> dict:
        d = self.data.dns
        q = d[d.src_ip == ip]
        if start is not None:
            q = q[q.ts >= start]
        if end is not None:
            q = q[q.ts <= end]
        dom = q["query"].str.split(".").str[-2:].str.join(".")
        top = dom.value_counts().head(6)
        longest = q.loc[q["query"].str.len().sort_values(ascending=False).index[:3], "query"].tolist() if len(q) else []
        return {"ip": ip, "queries": int(len(q)), "top_domains": top.to_dict(), "longest_queries": longest}

    def destination_context(self, ip: str, src: str | None = None) -> dict:
        """What an analyst checks about a peer: its DNS names, who talks to it, on which ports, how regularly."""
        f = self.data.flows
        q = f[f.dst_ip == ip]
        if src:
            q = q[q.src_ip == src]
        names: list[str] = []
        d = self.data.dns
        if "answers" in d.columns and len(d):
            hit = d[d["answers"].str.contains(ip, regex=False, na=False)]
            names = hit["query"].value_counts().head(5).index.tolist()
        out = {"ip": ip, "dns_names": names, "connections": int(len(q))}
        if q.empty:
            return out
        gaps = q.ts.sort_values().diff().dropna()
        gaps = gaps[gaps > 0]
        med = float(gaps.median()) if len(gaps) else None
        jitter = float((gaps - med).abs().median() / med) if med else None
        out.update({
            "internal_sources": int(q.loc[internal_mask(q.src_ip), "src_ip"].nunique()),
            "ports": q.dst_port.value_counts().head(5).to_dict(),
            "protocols": q.proto.value_counts().head(3).to_dict(),
            "median_interval_s": round(med, 1) if med else None,
            "interval_jitter": round(jitter, 3) if jitter is not None else None,
            "median_bytes_out": int(q.bytes_out.median()), "median_bytes_in": int(q.bytes_in.median()),
            "share_unanswered": round(float(((q.bytes_in == 0) & (q.packets <= 3)).mean()), 3),
            "first": fmt(q.ts.min()), "last": fmt(q.ts.max()),
            "hours_active": int(((q.ts - q.ts.min()) // 3600).nunique()),
        })
        return out

    def lookup_mitre(self, technique_id: str) -> dict:
        return mitre.lookup(technique_id)

    # tool registry ---------------------------------------------------------
    def call(self, name: str, args: dict) -> dict:
        # The home network is per capture; set it before every call so workspaces can be mixed.
        set_home_hosts(self.data.meta.get("home_hosts", ()))
        fn = TOOL_FUNCS.get(name)
        if fn is None:
            return {"error": f"Unknown tool {name}"}
        try:
            return fn(self, **args)
        except TypeError as e:
            return {"error": f"Bad arguments for {name}: {e}"}


TOOL_FUNCS = {
    "get_incident": Workspace.get_incident,
    "host_profile": Workspace.host_profile,
    "query_flows": Workspace.query_flows,
    "auth_events": Workspace.auth_events,
    "dns_queries": Workspace.dns_queries,
    "lookup_mitre": Workspace.lookup_mitre,
    "destination_context": Workspace.destination_context,
}

_TIME = {"type": "number", "description": "Unix timestamp (seconds). Optional."}

TOOL_SCHEMAS = [
    {"name": "get_incident", "description": "Get an incident with all of its alerts and their evidence.",
     "input_schema": {"type": "object", "properties": {"incident_id": {"type": "string"}}, "required": ["incident_id"]}},
    {"name": "host_profile", "description": "Who a host is (name, role) and how it behaved during the clean baseline: usual ports, internal peers, accounts.",
     "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}}, "required": ["ip"]}},
    {"name": "query_flows", "description": "Summarise network connections from (direction=out) or to (direction=in) a host, grouped by peer and port, largest first.",
     "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}, "start": _TIME, "end": _TIME,
                                                       "direction": {"type": "string", "enum": ["out", "in"]},
                                                       "limit": {"type": "integer", "minimum": 1, "maximum": 20}}, "required": ["ip"]}},
    {"name": "auth_events", "description": "Summarise logins made by or against a host: who, which account, which service, success or failure.",
     "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}, "start": _TIME, "end": _TIME}, "required": ["ip"]}},
    {"name": "dns_queries", "description": "Summarise DNS queries made by a host: top domains and the longest names.",
     "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}, "start": _TIME, "end": _TIME}, "required": ["ip"]}},
    {"name": "destination_context", "description": "Context on a remote peer: DNS names that resolved to it, how many internal hosts talk to it, ports, protocols, connection rhythm (median interval, jitter), typical bytes, share of unanswered attempts, active hours. Pass src to limit to one source host.",
     "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}, "src": {"type": "string"}}, "required": ["ip"]}},
    {"name": "lookup_mitre", "description": "Look up a MITRE ATT&CK technique: tactic, what it means, how to respond.",
     "input_schema": {"type": "object", "properties": {"technique_id": {"type": "string"}}, "required": ["technique_id"]}},
    {"name": "submit_report", "description": "Finish the investigation with a structured incident report. Call exactly once, last.",
     "input_schema": {"type": "object", "properties": {
         "verdict": {"type": "string", "enum": ["true_positive", "benign", "needs_review"]},
         "confidence": {"type": "number", "minimum": 0, "maximum": 1},
         "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
         "summary": {"type": "string", "description": "3-5 sentences a SOC lead can read in 20 seconds."},
         "attack_chain": {"type": "array", "items": {"type": "string"}, "description": "Ordered steps, each with time, host and technique ID."},
         "affected_hosts": {"type": "array", "items": {"type": "string"}},
         "techniques": {"type": "array", "items": {"type": "string"}},
         "actions": {"type": "array", "items": {"type": "string"}, "description": "Concrete next steps, most urgent first."},
     }, "required": ["verdict", "confidence", "severity", "summary", "actions"]}},
]
