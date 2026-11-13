"""Build the knowledge base from MITRE ATT&CK (STIX) and Sigma network rules.

  python -m netsentinel.knowledge.build --attack enterprise-attack.json --sigma sigma/ --out netsentinel/knowledge/kb.jsonl.gz

Sources and licences
  MITRE ATT&CK  https://github.com/mitre-attack/attack-stix-data
                © The MITRE Corporation. Reproduced and distributed with the permission of The MITRE Corporation.
  Sigma         https://github.com/SigmaHQ/sigma, Detection Rule License (DRL) 1.1; each rule keeps its author and link.
"""
from __future__ import annotations

import argparse
import gzip
import json
import re
from collections import defaultdict
from pathlib import Path

CITE_RE = re.compile(r"\(Citation:[^)]*\)")
LINK_RE = re.compile(r"\[([^\]]+)\]\(https?://attack\.mitre\.org/[^)]*\)")


def clean(text: str) -> str:
    text = LINK_RE.sub(r"\1", text or "")
    text = CITE_RE.sub("", text)
    text = re.sub(r"<code>|</code>", "`", text)
    return re.sub(r"[ \t]+", " ", text).strip()


def ext_id(o: dict) -> tuple[str, str]:
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id", ""), r.get("url", "")
    return "", ""


def attack_docs(path: str) -> list[dict]:
    objs = json.load(open(path, encoding="utf-8"))["objects"]
    live = {o["id"]: o for o in objs if not o.get("revoked") and not o.get("x_mitre_deprecated")}
    version = next((o.get("x_mitre_version") for o in objs if o["type"] == "x-mitre-collection"), "?")

    rel = defaultdict(list)                       # (type, target) -> [(source, description)]
    for r in objs:
        if r["type"] != "relationship" or r.get("revoked") or r.get("x_mitre_deprecated"):
            continue
        if r["source_ref"] in live and r["target_ref"] in live:
            rel[(r["relationship_type"], r["target_ref"])].append((r["source_ref"], r.get("description", "")))

    docs = []
    for o in live.values():
        if o["type"] != "attack-pattern":
            continue
        tid, url = ext_id(o)
        tactics = [p["phase_name"].replace("-", " ") for p in o.get("kill_chain_phases", [])]
        detect = []
        for strat_id, _ in rel[("detects", o["id"])]:
            strat = live[strat_id]
            for aref in strat.get("x_mitre_analytic_refs", []):
                an = live.get(aref)
                if an and (set(an.get("x_mitre_platforms", [])) & {"Network Devices", "Linux", "Windows", "macOS", "ESXi"}):
                    detect.append(clean(an.get("description", "")))
        users = []
        for src, desc in rel[("uses", o["id"])]:
            s = live[src]
            if s["type"] in ("malware", "tool") and desc:
                users.append(clean(desc))
        mitig = [clean(live[src].get("name", "")) for src, _ in rel[("mitigates", o["id"])]]
        text = (f"{tid} {o['name']}. Tactics: {', '.join(tactics)}. Platforms: {', '.join(o.get('x_mitre_platforms', []))}.\n"
                f"{clean(o.get('description', ''))}\n"
                + (f"Detection: {' '.join(dict.fromkeys(detect))[:2500]}\n" if detect else "")
                + (f"Seen in malware: {' '.join(users[:12])[:1500]}\n" if users else "")
                + (f"Mitigations: {', '.join(mitig[:8])}" if mitig else ""))
        docs.append({"id": tid, "kind": "technique", "title": f"{tid} {o['name']}", "url": url, "text": text,
                     "source": f"MITRE ATT&CK v{version}"})

    for o in live.values():
        if o["type"] not in ("malware", "tool"):
            continue
        sid, url = ext_id(o)
        docs.append({"id": sid, "kind": o["type"], "title": f"{sid} {o['name']}", "url": url,
                     "text": f"{o['name']} ({o['type']}). Also known as: {', '.join(o.get('x_mitre_aliases', [])[:6])}.\n"
                             f"{clean(o.get('description', ''))}", "source": f"MITRE ATT&CK v{version}",
                     "_stix": o["id"]})
    # procedure examples: what each malware does, by technique
    by_src = defaultdict(list)
    for (rtype, target), lst in rel.items():
        if rtype != "uses":
            continue
        t = live[target]
        if t["type"] != "attack-pattern":
            continue
        tid, _ = ext_id(t)
        for src, desc in lst:
            if desc:
                by_src[src].append(f"[{tid}] {clean(desc)}")
    for d in docs:
        stix = d.pop("_stix", None)
        if stix and by_src.get(stix):
            d["text"] += "\nBehaviour: " + " ".join(by_src[stix])[:3000]
    return docs


def sigma_docs(root: str) -> list[dict]:
    import yaml

    docs = []
    for p in sorted(Path(root).rglob("*.yml")):
        try:
            r = yaml.safe_load(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(r, dict) or "title" not in r:
            continue
        tags = [t for t in r.get("tags", []) if isinstance(t, str)]
        techs = [t.split(".", 1)[1].upper() for t in tags if re.match(r"attack\.t\d{4}", t)]
        ls = r.get("logsource", {}) or {}
        fps = r.get("falsepositives") or []
        rel = p.as_posix().split("sigma/", 1)[-1]
        docs.append({
            "id": f"SIGMA-{r.get('id', p.stem)[:8]}", "kind": "sigma", "title": r["title"],
            "url": f"https://github.com/SigmaHQ/sigma/blob/master/{rel}",
            "text": (f"Sigma rule: {r['title']}. Log source: {ls.get('product', '')} {ls.get('service', '')} {ls.get('category', '')}.\n"
                     f"{r.get('description', '')}\nTechniques: {', '.join(techs)}.\n"
                     f"Known false positives: {'; '.join(str(x) for x in fps) if fps else 'none listed'}.\n"
                     f"Level: {r.get('level', '')}. Author: {r.get('author', '')}."),
            "techniques": techs, "source": "SigmaHQ (DRL 1.1)",
        })
    return docs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", required=True)
    ap.add_argument("--sigma", required=True)
    ap.add_argument("--out", default=str(Path(__file__).with_name("kb.jsonl.gz")))
    a = ap.parse_args(argv)
    docs = attack_docs(a.attack) + sigma_docs(a.sigma)
    with gzip.open(a.out, "wt", encoding="utf-8") as fh:
        for d in docs:
            fh.write(json.dumps(d, ensure_ascii=False) + "\n")
    kinds = defaultdict(int)
    for d in docs:
        kinds[d["kind"]] += 1
    print(f"{len(docs)} documents {dict(kinds)} -> {a.out} ({Path(a.out).stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
