"""Score detection against the injected ground truth."""
from __future__ import annotations

import numpy as np

from . import detect
from .simulate import DAY, LabData, generate

PAD = 300  # seconds of slack when matching an alert to an attack


def _overlaps(alert: detect.Alert, attack) -> bool:
    """An alert detects an attack if it names the same actor, overlaps in time, and reports the
    same technique (for anomaly alerts: the technique its top deviating behaviour points to)."""
    same_actor = alert.src_ip == attack.src_ip
    same_kind = alert.technique == attack.technique or (
        alert.technique == "anomaly" and alert.evidence.get("likely_technique") == attack.technique)
    in_time = alert.start <= attack.end + PAD and alert.end >= attack.start - PAD
    return same_actor and same_kind and in_time


def score(data: LabData, result: detect.DetectionResult) -> dict:
    live = [a for a in result.alerts if not a.suppressed]
    per_attack = []
    for atk in data.attacks:
        hits = [a for a in live if _overlaps(a, atk)]
        first = min((max(a.start, atk.start) for a in hits), default=None)
        per_attack.append({
            "attack_id": atk.attack_id,
            "technique": atk.technique,
            "name": atk.name,
            "detected": bool(hits),
            "detectors": sorted({a.detector for a in hits}),
            "time_to_detect_s": None if first is None else round(first - atk.start, 1),
        })
    matched = {a.alert_id for a in live for atk in data.attacks if _overlaps(a, atk)}
    false_alerts = [a for a in live if a.alert_id not in matched]
    detect_days = data.meta["days"] - data.meta["baseline_days"]
    attack_hosts = {atk.src_ip for atk in data.attacks}
    false_incidents = [i for i in result.incidents if not (set(i.hosts) & attack_hosts)]
    recall = sum(p["detected"] for p in per_attack) / len(per_attack)
    precision = len(matched) / len(live) if live else 1.0
    return {
        "attacks": per_attack,
        "attack_recall": round(recall, 3),
        "alert_precision": round(precision, 3),
        "alerts": len(live),
        "suppressed_alerts": sum(a.suppressed for a in result.alerts),
        "false_alerts": len(false_alerts),
        "false_alerts_per_day": round(len(false_alerts) / detect_days, 2),
        "incidents": len(result.incidents),
        "false_incidents": len(false_incidents),
    }


CONFIGS = {
    "rules only": dict(use_rules=True, use_model=False, use_beacon=False),
    "model only": dict(use_rules=False, use_model=True, use_beacon=False),
    "rules + beaconing": dict(use_rules=True, use_model=False, use_beacon=True),
    "hybrid (all)": dict(use_rules=True, use_model=True, use_beacon=True),
}


def compare(seeds=(7, 11, 23, 42, 99), days: int = 7) -> dict:
    """Run every detector configuration on several independently generated networks."""
    rows = {name: [] for name in CONFIGS}
    for seed in seeds:
        data = generate(seed=seed, days=days)
        for name, cfg in CONFIGS.items():
            rows[name].append(score(data, detect.run(data, **cfg)))
    out = {}
    for name, runs in rows.items():
        out[name] = {
            "attack_recall": round(float(np.mean([r["attack_recall"] for r in runs])), 3),
            "alert_precision": round(float(np.mean([r["alert_precision"] for r in runs])), 3),
            "false_alerts_per_day": round(float(np.mean([r["false_alerts_per_day"] for r in runs])), 2),
            "false_incidents": round(float(np.mean([r["false_incidents"] for r in runs])), 2),
            "per_technique_recall": _per_technique(runs),
        }
    return {"seeds": list(seeds), "days": days, "configs": out}


def _per_technique(runs: list[dict]) -> dict:
    acc: dict[str, list[bool]] = {}
    for r in runs:
        for a in r["attacks"]:
            key = f'{a["attack_id"]} {a["name"]}'
            acc.setdefault(key, []).append(a["detected"])
    return {k: round(sum(v) / len(v), 2) for k, v in acc.items()}


def markdown_table(cmp: dict) -> str:
    names = list(cmp["configs"])
    techs = list(cmp["configs"][names[0]]["per_technique_recall"])
    lines = ["| Metric | " + " | ".join(names) + " |", "|---|" + "---|" * len(names)]
    for key, label in [("attack_recall", "Attacks detected"), ("alert_precision", "Alert precision"),
                       ("false_alerts_per_day", "False alerts / day"), ("false_incidents", "False incidents / run")]:
        vals = []
        for n in names:
            v = cmp["configs"][n][key]
            vals.append(f"{v:.0%}" if key in ("attack_recall", "alert_precision") else f"{v:g}")
        lines.append(f"| {label} | " + " | ".join(vals) + " |")
    for t in techs:
        lines.append(f"| {t} | " + " | ".join(f'{cmp["configs"][n]["per_technique_recall"][t]:.0%}' for n in names) + " |")
    return "\n".join(lines)
