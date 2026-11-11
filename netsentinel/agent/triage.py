"""Alert triage on real, labelled traffic: can an analyst close the false alarms without closing real attacks?

Every alert the detectors raise on a real capture becomes one case. The analyst investigates it with
the same read-only tools as in the lab and returns a verdict. The lab's own flow labels, which the
analyst never sees, decide whether the alert was a real attack.

The two numbers that matter to a SOC:
  noise_closed   share of false alerts the analyst closed as benign      (higher is better)
  attacks_closed share of real attacks the analyst closed as benign      (must stay near 0)
Anything the analyst escalates (true_positive or needs_review) goes to a human, which is safe.
"""
from __future__ import annotations

import copy
import random
import time

from .. import detect
from ..datasets import realeval
from .tools import Workspace


class EscalateAll:
    """No triage at all: every alert goes to a human. The floor any analyst must beat."""
    name = "escalate-all"

    def investigate(self, ws, incident_id, language="en"):
        from .analyst import Report
        return Report(incident_id, self.name, "needs_review", 0.5, "medium", "Escalated without investigation.")


def single_alert_result(result: detect.DetectionResult) -> detect.DetectionResult:
    """One incident per alert, so each case is judged on its own."""
    r = copy.copy(result)
    incs = []
    for a in result.alerts:
        if a.suppressed:
            continue
        incs.append(detect.Incident(incident_id=f"T-{a.alert_id}", alert_ids=[a.alert_id], hosts=sorted({a.src_ip, *a.targets[:3]}),
                                    start=a.start, end=a.end, severity=a.severity, techniques=[a.technique],
                                    title=a.title, score=a.score))
    r.incidents = incs
    return r


def build_cases(loader_items, sample_per_class: int | None = None, seed: int = 7) -> list[dict]:
    """loader_items: iterable of LabData. Returns cases with their workspace and hidden label."""
    cases = []
    for data in loader_items:
        res = detect.run(data)
        truth = {r["alert_id"]: r for r in realeval.score_capture(data, res)["alerts_detail"]}
        ws = Workspace(data, single_alert_result(res))
        for inc in ws.result.incidents:
            t = truth[inc.alert_ids[0]]
            cases.append({"ws": ws, "incident_id": inc.incident_id, "capture": data.meta.get("capture"),
                          "family": data.meta.get("family"), "detector": t["detector"],
                          "malicious": bool(t["tp"]), "malicious_share": t["malicious_share"]})
    if sample_per_class:
        rng = random.Random(seed)
        out = []
        for cls in (True, False):
            pool = [c for c in cases if c["malicious"] is cls]
            out += pool if len(pool) <= sample_per_class else rng.sample(pool, sample_per_class)
        cases = out
    return cases


def run(analyst, cases: list[dict], language: str = "en", verbose: bool = False,
        checkpoint=None, done: dict | None = None) -> dict:
    """checkpoint(rows) is called after every case; done maps (capture, incident_id) to rows from an earlier run."""
    rows = []
    done = done or {}
    for i, c in enumerate(cases, 1):
        key = (c["capture"], c["incident_id"])
        if key in done:
            rows.append(done[key])
            continue
        t0 = time.time()
        try:
            rep = analyst.investigate(c["ws"], c["incident_id"], language)
            verdict, conf, ntools, summary = rep.verdict, rep.confidence, len(rep.trace), rep.summary
        except Exception as e:                      # one failed case is escalated, never fatal for the run
            verdict, conf, ntools, summary = "error", 0.0, 0, f"{type(e).__name__}: {str(e)[:300]}"
        closed = verdict == "benign"
        rows.append({k: c[k] for k in ("capture", "family", "detector", "malicious", "malicious_share", "incident_id")}
                    | {"verdict": verdict, "closed": closed, "confidence": conf,
                       "tools_used": ntools, "seconds": round(time.time() - t0, 1), "summary": summary})
        if checkpoint:
            checkpoint(rows)
        rep_verdict = verdict
        if verbose:
            mark = "!! " if (closed and c["malicious"]) else "   "
            print(f"  [{i:3d}/{len(cases)}] {mark}{c['capture'][:20]:20s} {c['detector']:18s} "
                  f"truth={'attack' if c['malicious'] else 'false-alarm':11s} verdict={rep_verdict} "
                  f"({rows[-1]['seconds']:.0f}s)", flush=True)
    mal = [r for r in rows if r["malicious"]]
    ben = [r for r in rows if not r["malicious"]]
    by_det = {}
    for r in rows:
        d = by_det.setdefault(r["detector"], {"cases": 0, "false_alarms": 0, "false_alarms_closed": 0, "attacks": 0, "attacks_closed": 0})
        d["cases"] += 1
        if r["malicious"]:
            d["attacks"] += 1
            d["attacks_closed"] += int(r["closed"])
        else:
            d["false_alarms"] += 1
            d["false_alarms_closed"] += int(r["closed"])
    return {
        "analyst": getattr(analyst, "name", "?"), "model": getattr(analyst, "model", None),
        "cases": len(rows), "attacks": len(mal), "false_alarms": len(ben),
        "noise_closed": round(sum(r["closed"] for r in ben) / len(ben), 3) if ben else None,
        "attacks_closed": round(sum(r["closed"] for r in mal) / len(mal), 3) if mal else None,
        "analyst_queue_after_triage": sum(not r["closed"] for r in rows),
        "errors": sum(r["verdict"] == "error" for r in rows),
        "by_detector": by_det, "rows": rows,
    }
