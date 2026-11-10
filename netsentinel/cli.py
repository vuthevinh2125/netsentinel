"""Command line: python -m netsentinel <command>

  run         simulate the lab, detect, investigate every incident, write a JSON bundle
  compare     score rules / model / beaconing / hybrid on several seeds
  agent-eval  grade an analyst (playbook, or Claude if ANTHROPIC_API_KEY is set)
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

from . import __version__, detect, evaluate, mitre
from .agent import evals
from .agent.analyst import ClaudeAnalyst, PlaybookAnalyst
from .agent.tools import Workspace, fmt
from .simulate import DAY, TECHNIQUES, generate


def _analyst(name: str):
    if name == "claude" or (name == "auto" and ClaudeAnalyst.available()):
        return ClaudeAnalyst()
    return PlaybookAnalyst()


def _py(o):
    """JSON fallback for numpy scalars and arrays."""
    if isinstance(o, np.generic):
        return o.item()
    if isinstance(o, np.ndarray):
        return o.tolist()
    return str(o)


def build_bundle(seed: int = 7, days: int = 7, analyst: str = "auto", with_compare: bool = True) -> dict:
    t0 = time.time()
    data = generate(seed=seed, days=days)
    result = detect.run(data)
    score = evaluate.score(data, result)
    ws = Workspace(data, result)
    an = _analyst(analyst)
    reports = {}
    for inc in result.incidents:
        reports[inc.incident_id] = {lang: an.investigate(ws, inc.incident_id, lang).to_dict() for lang in ("en", "vi")}
    agent_eval = evals.run_eval(an, data, result)
    agent_eval.pop("reports")

    start = data.meta["start_ts"]
    hours = np.arange(start, start + days * DAY, 3600)
    def per_hour(ts):
        return np.histogram(ts, bins=np.append(hours, hours[-1] + 3600))[0].tolist()

    by_alert = {a.alert_id: a for a in result.alerts}
    incident_of = {aid: inc.incident_id for inc in result.incidents for aid in inc.alert_ids}
    hosts = data.hosts.to_dict("records")
    bundle = {
        "version": __version__,
        "generated_in_s": None,
        "meta": {**data.meta, "end_ts": start + days * DAY, "baseline_end": result.config["baseline_end"],
                 "analyst": an.name, "model": getattr(an, "model", None)},
        "counts": {"flows": int(len(data.flows)), "auth": int(len(data.auth)), "dns": int(len(data.dns)),
                   "hosts": int(len(data.hosts)), "windows": int(len(result.windows))},
        "hosts": hosts,
        "series": {
            "hours": [int(h) for h in hours],
            "flows": per_hour(data.flows.ts.to_numpy()),
            "auth_fail": per_hour(data.auth.loc[data.auth.result == "failure", "ts"].to_numpy()),
            "dns": per_hour(data.dns.ts.to_numpy()),
        },
        "incidents": [{**i.to_dict(), "start_local": fmt(i.start), "end_local": fmt(i.end)} for i in result.incidents],
        "alerts": [{**a.to_dict(), "start_local": fmt(a.start), "end_local": fmt(a.end),
                    "incident_id": incident_of.get(a.alert_id)} for a in result.alerts],
        "reports": reports,
        "attacks": [{"attack_id": a.attack_id, "technique": a.technique, "name": a.name, "src_ip": a.src_ip,
                     "start": a.start, "start_local": fmt(a.start), "note": a.note} for a in data.attacks],
        "score": score,
        "agent_eval": agent_eval,
        "mitre": {t: mitre.lookup(t) for t in TECHNIQUES},
    }
    if with_compare:
        cmp = evaluate.compare()
        bundle["compare"] = cmp
    bundle["generated_in_s"] = round(time.time() - t0, 1)
    del by_alert
    return json.loads(json.dumps(bundle, default=_py))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="netsentinel", description="AI-assisted mini SOC for a lab network")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="simulate, detect, investigate, write a JSON bundle")
    r.add_argument("--seed", type=int, default=7)
    r.add_argument("--days", type=int, default=7)
    r.add_argument("--analyst", choices=["auto", "playbook", "claude"], default="auto")
    r.add_argument("--no-compare", action="store_true", help="skip the multi-seed detector comparison")
    r.add_argument("--out", default="docs/data/demo.json")
    c = sub.add_parser("compare", help="compare detector configurations across seeds")
    c.add_argument("--seeds", default="7,11,23,42,99")
    e = sub.add_parser("agent-eval", help="grade an analyst on the lab incidents")
    e.add_argument("--analyst", choices=["auto", "playbook", "claude"], default="auto")
    e.add_argument("--seed", type=int, default=7)
    a = p.parse_args(argv)

    if a.cmd == "run":
        b = build_bundle(a.seed, a.days, a.analyst, not a.no_compare)
        out = Path(a.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(b, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        s = b["score"]
        print(f"{len(b['incidents'])} incidents, {s['alerts']} alerts, attacks detected {s['attack_recall']:.0%}, "
              f"false alerts/day {s['false_alerts_per_day']}, analyst {b['meta']['analyst']} "
              f"score {b['agent_eval']['score']:.0%} -> {out} ({out.stat().st_size // 1024} KB, {b['generated_in_s']} s)")
    elif a.cmd == "compare":
        cmp = evaluate.compare(seeds=tuple(int(x) for x in a.seeds.split(",")))
        print(evaluate.markdown_table(cmp))
    elif a.cmd == "agent-eval":
        data = generate(seed=a.seed)
        result = detect.run(data)
        res = evals.run_eval(_analyst(a.analyst), data, result)
        print(f"analyst={res['analyst']} cases={res['cases']} score={res['score']:.0%} verdicts={res['verdict_accuracy']:.0%}")
        for k, v in res["by_check"].items():
            print(f"  {k:12s} {v:.0%}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
