"""Score detections on real labelled captures using the dataset's own per-flow labels.

An alert is a true positive when most of the traffic it points at is labelled Malicious
by the lab. Nothing here looks at labels while detecting: labels are only read to grade.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .. import detect
from ..simulate import LabData


def supporting(data: LabData, a: detect.Alert) -> tuple[pd.DataFrame, str]:
    """The records an alert is about, and which log they come from."""
    if a.detector == "rule:dns-tunnel":
        d = data.dns
        return d[(d.src_ip == a.src_ip) & (d.ts >= a.start) & (d.ts <= a.end)], "dns"
    f = data.flows
    m = (f.src_ip == a.src_ip) & (f.ts >= a.start - 1) & (f.ts <= a.end + 1)
    if a.targets and a.detector in ("beaconing", "rule:large-upload"):
        m &= f.dst_ip.isin(a.targets)
    return f[m], "conn"


def score_capture(data: LabData, result: detect.DetectionResult) -> dict:
    f = data.flows
    mal = f.label == "malicious"
    rows, covered = [], np.zeros(len(f), dtype=bool)
    for a in result.alerts:
        if a.suppressed:
            continue
        sup, src = supporting(data, a)
        share = float((sup.label == "malicious").mean()) if len(sup) else 0.0
        tp = share >= 0.5
        if tp and src == "conn":
            covered[sup.index.to_numpy()] = True
        rows.append({"alert_id": a.alert_id, "detector": a.detector, "technique": a.technique, "src_ip": a.src_ip,
                     "targets": a.targets[:3], "records": int(len(sup)), "malicious_share": round(share, 3), "tp": tp,
                     "start": a.start})
    n_alerts = len(rows)
    tp = sum(r["tp"] for r in rows)
    first_mal = float(f.loc[mal, "ts"].min()) if mal.any() else None
    first_tp = min((r["start"] for r in rows if r["tp"]), default=None)
    hours = max(1e-9, float(f.ts.max() - f.ts.min()) / 3600)
    infected = f.loc[mal & f.src_ip.isin(data.hosts.ip), "src_ip"].value_counts()
    return {
        **{k: data.meta.get(k) for k in ("capture", "kind", "family", "original_name")},
        "hours": round(hours, 1),
        "flows": int(len(f)), "malicious_flows": int(mal.sum()),
        "outbound_malware": bool(len(infected)),
        "alerts": n_alerts, "true_alerts": int(tp), "false_alerts": int(n_alerts - tp),
        "detected": bool(tp > 0) if mal.any() else None,
        "malicious_flows_covered": round(float(covered[mal.to_numpy()].mean()), 3) if mal.any() else None,
        "minutes_to_first_true_alert": round((first_tp - first_mal) / 60, 1) if (first_tp is not None and first_mal is not None) else None,
        "false_alerts_per_day": round((n_alerts - tp) / hours * 24, 2),
        "model_ran": result.config.get("model_ran"),
        "by_detector": pd.DataFrame(rows).groupby("detector").tp.agg(["size", "sum"]).rename(
            columns={"size": "alerts", "sum": "true"}).astype(int).to_dict("index") if rows else {},
        "alerts_detail": rows,
    }


def summarise(scores: list[dict]) -> dict:
    infected = [s for s in scores if s["outbound_malware"]]
    attacked = [s for s in scores if not s["outbound_malware"] and s["malicious_flows"] > 0]
    clean = [s for s in scores if s["malicious_flows"] == 0]
    alerts = sum(s["alerts"] for s in scores)
    true = sum(s["true_alerts"] for s in scores)
    hours = sum(s["hours"] for s in scores)

    def rate(xs):
        return round(sum(bool(s["detected"]) for s in xs) / len(xs), 3) if xs else None

    by_det: dict[str, dict] = {}
    for s in scores:
        for k, v in s["by_detector"].items():
            d = by_det.setdefault(k, {"alerts": 0, "true": 0})
            d["alerts"] += v["alerts"]
            d["true"] += v["true"]
    fam: dict[str, dict] = {}
    for s in infected:
        f = fam.setdefault(s["family"], {"hosts": 0, "detected": 0, "alerts": 0, "true_alerts": 0})
        f["hosts"] += 1
        f["detected"] += int(bool(s["detected"]))
        f["alerts"] += s["alerts"]
        f["true_alerts"] += s["true_alerts"]
    return {
        "by_family": fam,
        "captures": len(scores), "hours": round(hours, 1), "flows": sum(s["flows"] for s in scores),
        "infected_hosts": len(infected), "infected_detected": rate(infected),
        "attacked_hosts": len(attacked), "attacked_detected": rate(attacked),
        "clean_hosts": len(clean),
        "alerts": alerts, "alert_precision": round(true / alerts, 3) if alerts else None,
        "false_alerts_per_day": round((alerts - true) / hours * 24, 2) if hours else None,
        "false_alerts_per_day_clean_hosts": round(sum(s["false_alerts"] for s in clean) / max(1e-9, sum(s["hours"] for s in clean)) * 24, 2) if clean else None,
        "median_minutes_to_detect": float(np.median([s["minutes_to_first_true_alert"] for s in infected
                                                      if s["minutes_to_first_true_alert"] is not None])) if infected else None,
        "by_detector": by_det,
    }


def run_all(root, verbose: bool = False) -> dict:
    from . import stratosphere as S
    scores = []
    caps = S.captures(root)
    # Several captures are later days of the same infection; name them after the family
    # given for any day of that original capture.
    fam_of = {}
    for c in caps:
        info = S.describe(c)
        if info["original_name"] and not info["family"].startswith("Unnamed"):
            fam_of[info["original_name"]] = info["family"]
    for c in caps:
        data = S.load(c)
        if data.meta["family"].startswith("Unnamed") and data.meta["original_name"] in fam_of:
            data.meta["family"] = fam_of[data.meta["original_name"]]
        result = detect.run(data)
        s = score_capture(data, result)
        scores.append(s)
        if verbose:
            print(f"  {s['capture']:22s} {s['family'][:24]:24s} alerts={s['alerts']:3d} true={s['true_alerts']:3d} "
                  f"detected={s['detected']}", flush=True)
    return {"dataset": "Stratosphere Laboratory labelled Zeek captures (CTU Prague)",
            "source": "https://github.com/stratosphereips/security-datasets-for-testing",
            "summary": summarise(scores),
            "captures": [{k: v for k, v in s.items() if k != "alerts_detail"} for s in scores]}


def markdown(res: dict) -> str:
    s = res["summary"]
    out = ["| Malware family | Infected host-days | Detected | Alerts | True alerts |", "|---|---|---|---|---|"]
    for fam, v in sorted(s["by_family"].items(), key=lambda kv: (-kv[1]["hosts"], kv[0])):
        out.append(f"| {fam} | {v['hosts']} | {v['detected']}/{v['hosts']} | {v['alerts']} | {v['true_alerts']} |")
    out.append("")
    out.append(f"{s['captures']} captures, {s['hours']:.0f} hours, {s['flows']:,} flows. "
               f"Infected host-days detected: {s['infected_detected']:.0%}. Alert precision: {s['alert_precision']:.0%}. "
               f"False alerts per day: {s['false_alerts_per_day']}.")
    return "\n".join(out)
