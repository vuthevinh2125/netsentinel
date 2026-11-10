"""Grade analyst reports against the lab's ground truth.

Seven checks per incident, so the playbook analyst and an LLM analyst can be compared on
the same footing:

1. verdict      - true_positive for incidents that contain injected attacks, benign otherwise
2. severity     - high/critical for real attacks, low/medium for benign ones
3. iocs         - every attacker IP, domain and abused account appears in the report
4. mitre        - lookup_mitre was called for every technique in the incident
5. method       - the investigation started with get_incident
6. containment  - for real attacks, the first action contains the threat (isolate, block, disable)
7. language     - the report is written in the requested language
"""
from __future__ import annotations

import re

from ..detect import DetectionResult
from ..features import is_internal
from ..simulate import LabData
from .analyst import Report
from .tools import Workspace

_VI = re.compile(r"[ăâđêôơưàáảãạằắẳẵặầấẩẫậèéẻẽẹềếểễệìíỉĩịòóỏõọồốổỗộờớởỡợùúủũụừứửữựỳýỷỹỵ]", re.I)
_CONTAIN = ("isolate", "block", "disable", "cách ly", "chặn", "khoá", "khóa")


def ground_truth(data: LabData, result: DetectionResult) -> dict[str, dict]:
    truth = {}
    by_id = {a.alert_id: a for a in result.alerts}
    for inc in result.incidents:
        # an incident is real if one of its alerts comes from an attack's actor with that attack's technique
        sources = {(by_id[i].src_ip, by_id[i].technique, by_id[i].evidence.get("likely_technique")) for i in inc.alert_ids}
        attacks = [a for a in data.attacks if any(s == a.src_ip and a.technique in (t, h) for s, t, h in sources)]
        iocs: set[str] = set()
        for a in attacks:
            iocs |= {t for t in a.targets if not is_internal(t)}   # C2 IPs, exfil hosts, tunnel domains
            if not is_internal(a.src_ip):
                iocs.add(a.src_ip)                                  # internet attacker
            used = data.auth[(data.auth.attack_id == a.attack_id) & (data.auth.result == "success")].user.unique()
            iocs |= set(used)
        truth[inc.incident_id] = {"verdict": "true_positive" if attacks else "benign", "iocs": sorted(iocs),
                                  "techniques": inc.techniques, "attacks": [a.attack_id for a in attacks]}
    return truth


def grade(report: Report, truth: dict) -> dict:
    text = " ".join([report.summary, *report.actions, *report.attack_chain]).lower()
    tools = [t["tool"] for t in report.trace]
    looked_up = {t["input"].get("technique_id") for t in report.trace if t["tool"] == "lookup_mitre"}
    tp = truth["verdict"] == "true_positive"
    checks = {
        "verdict": report.verdict == truth["verdict"],
        "severity": (report.severity in ("high", "critical")) if tp else (report.severity in ("low", "medium")),
        "iocs": all(i.lower() in text for i in truth["iocs"]),
        "mitre": set(truth["techniques"]) <= looked_up,
        "method": bool(tools) and tools[0] == "get_incident",
        "containment": (bool(report.actions) and report.actions[0].lower().startswith(_CONTAIN)) if tp else True,
        "language": bool(_VI.search(report.summary)) == (report.language == "vi"),
    }
    missing = [i for i in truth["iocs"] if i.lower() not in text]
    return {"incident_id": report.incident_id, "expected": truth["verdict"], "verdict": report.verdict,
            "checks": checks, "passed": sum(checks.values()), "total": len(checks), "missing_iocs": missing,
            "tool_calls": len(tools), "seconds": report.seconds}


def run_eval(analyst, data: LabData, result: DetectionResult, languages=("en", "vi")) -> dict:
    ws = Workspace(data, result)
    truth = ground_truth(data, result)
    rows, reports = [], []
    for lang in languages:
        for inc in result.incidents:
            rep = analyst.investigate(ws, inc.incident_id, lang)
            reports.append(rep)
            rows.append({**grade(rep, truth[inc.incident_id]), "language": lang})
    passed = sum(r["passed"] for r in rows)
    total = sum(r["total"] for r in rows)
    by_check: dict[str, list[bool]] = {}
    for r in rows:
        for k, v in r["checks"].items():
            by_check.setdefault(k, []).append(v)
    return {
        "analyst": analyst.name,
        "cases": len(rows),
        "score": round(passed / total, 3) if total else 0,
        "verdict_accuracy": round(sum(r["checks"]["verdict"] for r in rows) / len(rows), 3),
        "by_check": {k: round(sum(v) / len(v), 3) for k, v in by_check.items()},
        "rows": rows,
        "reports": [r.to_dict() for r in reports],
    }
