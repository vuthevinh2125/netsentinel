"""Knowledge base (MITRE ATT&CK + Sigma) and the RAG tool."""
from netsentinel import detect, mitre
from netsentinel.agent.tools import Workspace
from netsentinel.knowledge.evaluate import evaluate, query_from_alert
from netsentinel.knowledge.search import default_kb, expand
from netsentinel.simulate import generate


def test_kb_has_all_parts_and_sources():
    kb = default_kb()
    kinds = {d["kind"] for d in kb.docs}
    assert {"technique", "malware", "tool", "sigma"} <= kinds
    assert len([d for d in kb.docs if d["kind"] == "technique"]) > 600
    assert all(d["url"].startswith("https://") and d["source"] for d in kb.docs)


def test_search_finds_the_obvious_ones():
    kb = default_kb()
    top = lambda q, kinds=("technique",): [d["id"] for _, d in kb.search(q, 3, kinds)]
    assert "T1110" in {t.split(".")[0] for t in top("many failed ssh logins then a success")}
    assert "T1071" in {t.split(".")[0] for t in top("regular beaconing every 9 seconds to one IP")}
    assert top("port 449 trickbot", ("malware",))[0] == "S0266"


def test_thesaurus_only_adds_words():
    q = "regular call-home traffic"
    assert expand(q).startswith(q) and "command" in expand(q)


def test_full_attack_lookup_fallback():
    assert mitre.lookup("T1568.002")["name"].startswith("Domain Generation")
    assert "error" in mitre.lookup("T9999")


def test_rag_tool_is_switchable_and_cites():
    data = generate(seed=7, days=7)
    res = detect.run(data)
    off, on = Workspace(data, res), Workspace(data, res, rag=True)
    assert "search_knowledge" not in {t["name"] for t in off.tool_schemas()}
    assert "search_knowledge" in {t["name"] for t in on.tool_schemas()}
    hits = on.call("search_knowledge", {"query": "DNS tunnelling long random subdomains TXT", "kind": "technique"})["results"]
    assert hits and all(h["url"] and h["source"] and h["excerpt"] for h in hits)
    assert any(h["id"].startswith("T1071") or h["id"].startswith("T1572") or h["id"].startswith("T1568") for h in hits)


def test_retrieval_eval_on_lab_alerts():
    data = generate(seed=7, days=7)
    alerts = [a for a in detect.run(data).alerts if not a.suppressed]
    assert all("T1" not in query_from_alert(a) for a in alerts)      # no technique id leaks into the query
    r = evaluate(alerts)
    assert r["macro_tactic@5"] >= 0.9 and r["macro_family@5"] >= 0.6
