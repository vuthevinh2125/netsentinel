"""Does the knowledge search find the right ATT&CK technique for an alert?

The query is built only from what the analyst sees: the alert title and its evidence (field names
and values), with any technique ID removed. A hit means the alert's technique (exact, or its
parent / sub-technique) is in the top k results.
"""
from __future__ import annotations

import re

from .search import KnowledgeBase, default_kb

TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)


FEATURE_WORDS = {"n_dst_ports": "distinct ports", "n_zero_reply": "unanswered probes",
                 "n_internal_dst": "internal hosts touched", "smb_dsts": "hosts reached over SMB",
                 "ext_new_dst": "new external destinations", "auth_fail": "failed logins",
                 "dns_long_q": "long random DNS names"}


def query_from_alert(alert) -> str:
    parts = [alert.title]
    for k, v in (alert.evidence or {}).items():
        if k in ("likely_technique",):
            continue
        parts.append(k.replace("_", " "))
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, (list, tuple)):
            parts.extend(str(x) for x in v[:5])
        elif isinstance(v, dict):
            parts.extend(FEATURE_WORDS.get(str(x), str(x).replace("_", " ")) for x in list(v)[:5])
        elif isinstance(v, int) and k in ("dst_port", "port"):
            parts.append(f"port {v}")
    return TID.sub("", " ".join(parts))


def family(tid: str) -> str:
    return tid.split(".")[0]


def tactics_of(kb: KnowledgeBase, tid: str) -> set[str]:
    d = kb.by_id.get(tid) or kb.by_id.get(family(tid))
    if not d:
        return set()
    m = re.search(r"Tactics: ([^.]*)\.", d["text"])
    return {t.strip() for t in m.group(1).split(",")} if m else set()


def rank_of(kb: KnowledgeBase, query: str, technique: str, k: int = 10, kinds=("technique",),
            use_thesaurus: bool = True) -> tuple[int | None, int | None]:
    """(exact rank, family rank, same-tactic rank), 1-based, None when not in the top k."""
    hits = [d["id"] for _, d in kb.search(query, k, kinds, use_thesaurus)]
    exact = next((i + 1 for i, h in enumerate(hits) if h == technique), None)
    fam = next((i + 1 for i, h in enumerate(hits) if family(h) == family(technique)), None)
    want = tactics_of(kb, technique)
    tac = next((i + 1 for i, h in enumerate(hits) if want & tactics_of(kb, h)), None)
    return exact, fam, tac


def evaluate(alerts, kb: KnowledgeBase | None = None, kinds=("technique",), use_thesaurus: bool = True) -> dict:
    kb = kb or default_kb()
    rows = []
    for a in alerts:
        tech = a.technique if TID.fullmatch(a.technique or "") else (a.evidence or {}).get("likely_technique")
        if not tech or not TID.fullmatch(tech):
            continue
        q = query_from_alert(a)
        exact, fam, tac = rank_of(kb, q, tech, 10, kinds, use_thesaurus)
        rows.append({"detector": a.detector, "technique": tech, "query": q[:160], "exact_rank": exact,
                     "family_rank": fam, "tactic_rank": tac})

    def at(key, k):
        return round(sum(1 for r in rows if r[key] and r[key] <= k) / len(rows), 3) if rows else None

    by_det = {}
    for r in rows:
        d = by_det.setdefault(r["detector"], {"alerts": 0, "family@5": 0, "tactic@5": 0})
        d["alerts"] += 1
        d["family@5"] += int(bool(r["family_rank"] and r["family_rank"] <= 5))
        d["tactic@5"] += int(bool(r["tactic_rank"] and r["tactic_rank"] <= 5))
    for d in by_det.values():
        d["family@5"] = round(d["family@5"] / d["alerts"], 3)
        d["tactic@5"] = round(d["tactic@5"] / d["alerts"], 3)
    # macro average: every detector counts once, so one chatty detector cannot dominate
    macro = lambda key: round(sum(d[key] for d in by_det.values()) / len(by_det), 3) if by_det else None
    return {"alerts": len(rows), "detectors": len(by_det),
            "family@1": at("family_rank", 1), "family@5": at("family_rank", 5), "tactic@5": at("tactic_rank", 5),
            "macro_family@5": macro("family@5"), "macro_tactic@5": macro("tactic@5"),
            "by_detector": by_det, "rows": rows}
