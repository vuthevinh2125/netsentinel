"""Command line: python -m netsentinel <command>

  run         simulate the lab, detect, investigate every incident, write a JSON bundle
  compare     score rules / model / beaconing / hybrid on several seeds
  agent-eval  grade an analyst (playbook, or Claude if ANTHROPIC_API_KEY is set)
  real-eval   run the detectors on real labelled captures (Stratosphere Lab, CTU Prague)
  triage-eval let an analyst triage every alert on the real captures, graded by the lab's labels
  kb-eval     does the knowledge search find the right ATT&CK technique for each alert
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import numpy as np

from . import __version__, detect, evaluate, mitre
from .agent import evals
from .agent.analyst import ClaudeAnalyst, OpenAICompatAnalyst, PlaybookAnalyst
from .agent.tools import Workspace, fmt
from .simulate import DAY, TECHNIQUES, generate


def _analyst(name: str):
    if name == "openai":
        return OpenAICompatAnalyst()
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
    rv = sub.add_parser("real-eval", help="evaluate on real labelled Zeek captures")
    rv.add_argument("--data", default="data/stratosphere", help="folder from scripts/fetch_stratosphere.sh")
    rv.add_argument("--iot23", default=None, help="IoT-23 folder (scripts/fetch_iot23.sh) for the blind test")
    rv.add_argument("--out", default="docs/data/real.json")
    tr = sub.add_parser("triage-eval", help="grade an analyst's alert triage on real labelled captures")
    tr.add_argument("--data", default="data/stratosphere")
    tr.add_argument("--iot23", default=None)
    tr.add_argument("--analyst", choices=["auto", "playbook", "claude", "openai", "escalate-all"], default="auto",
                    help="openai = any OpenAI-compatible API (Gemini free tier, Ollama, Groq...)")
    tr.add_argument("--sample", type=int, default=None, help="at most N attacks and N false alarms (cost control)")
    tr.add_argument("--language", choices=["en", "vi"], default="en")
    tr.add_argument("--out", default="docs/data/triage.json")
    tr.add_argument("--resume", action="store_true", help="skip cases already in --out and continue")
    tr.add_argument("--rag", action="store_true", help="give the analyst search_knowledge (MITRE ATT&CK + Sigma)")
    kv = sub.add_parser("kb-eval", help="retrieval quality of the knowledge base on lab (and real) alerts")
    kv.add_argument("--data", default=None, help="Stratosphere folder, optional")
    kv.add_argument("--iot23", default=None)
    kv.add_argument("--out", default="docs/data/kb_eval.json")
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
    elif a.cmd == "real-eval":
        from .datasets import realeval
        res = realeval.run_all(a.data, verbose=True)
        if a.iot23:
            res["blind"] = realeval.run_iot23(a.iot23, verbose=True)
        out = Path(a.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(res, ensure_ascii=False, indent=1, default=_py), encoding="utf-8")
        print(realeval.markdown(res))
        if "blind" in res:
            print("\nBlind test, IoT-23:")
            print(realeval.markdown(res["blind"], unit="Infected devices"))
        print(f"-> {out}")
    elif a.cmd == "kb-eval":
        from .knowledge.evaluate import evaluate
        sets = {"lab": []}
        for seed in (7, 11, 23, 42, 99):
            d = generate(seed=seed)
            sets["lab"] += [x for x in detect.run(d).alerts if not x.suppressed]
        if a.data or a.iot23:
            from .datasets import iot23, stratosphere
            sets["real"] = []
            for c in (stratosphere.captures(a.data) if a.data else []):
                d = stratosphere.load(c)
                sets["real"] += [x for x in detect.run(d).alerts if not x.suppressed]
            for path, n in (iot23.captures(a.iot23) if a.iot23 else []):
                d = iot23.load(path, n)
                sets["real"] += [x for x in detect.run(d).alerts if not x.suppressed]
        res = {}
        for name, alerts in sets.items():
            for th in (False, True):
                r = evaluate(alerts, use_thesaurus=th)
                r.pop("rows")
                res[f"{name}_{'thesaurus' if th else 'plain'}"] = r
                print(f"{name:4s} {'thesaurus' if th else 'plain':9s} alerts={r['alerts']:4d}  "
                      f"technique family in top 5 (macro) {r['macro_family@5']:.0%}  right tactic in top 5 (macro) {r['macro_tactic@5']:.0%}")
        out = Path(a.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(res, indent=1), encoding="utf-8")
    elif a.cmd == "triage-eval":
        from .agent import triage
        from .datasets import iot23, stratosphere

        def items():
            for c in stratosphere.captures(a.data):
                yield stratosphere.load(c)
            if a.iot23:
                for path, n in iot23.captures(a.iot23):
                    yield iot23.load(path, n)
        cases = triage.build_cases(items(), sample_per_class=a.sample, rag=a.rag)
        an = triage.EscalateAll() if a.analyst == "escalate-all" else _analyst(a.analyst)
        if a.analyst == "openai":
            missing = [v for v in ("NETSENTINEL_OPENAI_URL", "NETSENTINEL_OPENAI_KEY", "NETSENTINEL_MODEL") if not os.environ.get(v)]
            if missing:
                print("Missing: " + ", ".join(missing) + ". Set them with export before running.")
                return 2
        print(f"{len(cases)} alerts ({sum(c['malicious'] for c in cases)} attacks, "
              f"{sum(not c['malicious'] for c in cases)} false alarms), analyst={an.name}, rag={a.rag}", flush=True)
        out = Path(a.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        done = {}
        if a.resume and out.exists():
            prev = json.loads(out.read_text(encoding="utf-8"))
            done = {(r["capture"], r["incident_id"]): r for r in prev.get("rows", []) if r["verdict"] != "error"}
            print(f"resuming: {len(done)} cases already done", flush=True)

        def checkpoint(rows):
            out.write_text(json.dumps({"analyst": an.name, "partial": True, "rows": rows}, ensure_ascii=False,
                                      indent=1, default=_py), encoding="utf-8")
        res = triage.run(an, cases, a.language, verbose=True, checkpoint=checkpoint, done=done)
        out.write_text(json.dumps(res, ensure_ascii=False, indent=1, default=_py), encoding="utf-8")
        pct = lambda v: "n/a" if v is None else f"{v:.0%}"
        print(f"false alarms closed: {pct(res['noise_closed'])}   real attacks wrongly closed: {pct(res['attacks_closed'])}   "
              f"queue {res['cases']} -> {res['analyst_queue_after_triage']}   errors {res['errors']}   -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
