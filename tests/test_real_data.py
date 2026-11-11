"""Real-data adapter and scoring, on a tiny Zeek fixture shaped like the Stratosphere captures."""
from pathlib import Path

from netsentinel import detect
from netsentinel.datasets import realeval, stratosphere
from netsentinel.datasets.zeek import read_zeek
from netsentinel.features import is_external, is_internal, set_home_hosts

FIX = Path(__file__).parent / "fixtures"


def test_address_classes():
    set_home_hosts([])
    assert is_internal("192.168.1.5") and is_internal("10.0.2.28") and is_internal("fd2d::1")
    assert not is_internal("8.8.8.8") and is_external("8.8.8.8")
    # multicast / link-local are neither the company network nor the Internet
    for ip in ("ff02::1:ff00:1", "239.255.255.250", "224.0.0.251", "255.255.255.255"):
        assert not is_external(ip), ip
    set_home_hosts(["147.32.85.12"])
    assert is_internal("147.32.85.12") and not is_external("147.32.85.12")
    set_home_hosts([])
    assert not is_internal("147.32.85.12")


def test_read_zeek_tsv():
    df = read_zeek(FIX / "000-zeek-malicious" / "data" / "conn.log.labeled")
    assert len(df) == 140
    assert {"ts", "id.orig_h", "id.resp_h", "label"} <= set(df.columns)


def test_load_and_score():
    data = stratosphere.load(FIX / "000-zeek-malicious")
    assert data.meta["family"] == "TestBot"
    assert data.meta["home_hosts"] == ["192.168.1.50"]
    assert (data.flows.label == "malicious").sum() == 40
    result = detect.run(data)
    assert result.config["model_ran"] is False          # no clean baseline in a capture that starts infected
    s = realeval.score_capture(data, result)
    assert s["detected"] is True
    assert s["false_alerts"] == 0                        # neighbour discovery is not beaconing
    beacons = [a for a in result.alerts if a.detector == "beaconing"]
    assert [a.targets for a in beacons] == [["93.184.216.34"]]


def test_run_all_summary():
    res = realeval.run_all(FIX)
    s = res["summary"]
    assert s["captures"] == 1 and s["infected_detected"] == 1.0 and s["alert_precision"] == 1.0
    assert "TestBot" in s["by_family"]


def test_iot23_csv_blind_path():
    from netsentinel.datasets import iot23
    caps = iot23.captures(FIX / "iot23")
    assert [n for _, n in caps] == [34]
    data = iot23.load(*caps[0])
    assert data.meta["family"] == "Mirai" and data.meta["truncated"] is True
    assert (data.flows.label == "malicious").sum() == 400 and data.flows.attack_id.iloc[0] == "PartOfAHorizontalPortScan"
    res = realeval.run_iot23(FIX / "iot23")
    assert res["summary"]["infected_detected"] == 1.0
    assert res["summary"]["by_detector"]["rule:port-scan"]["true"] == 1


def test_zeek_space_separated_labels(tmp_path):
    # IoT-23 logs put the last three columns after runs of spaces, not tabs
    src = (FIX / "000-zeek-malicious" / "data" / "conn.log.labeled").read_text().splitlines()
    out = [l if l.startswith("#") else l.rsplit("\t", 2)[0] + "   " + "   ".join(l.rsplit("\t", 2)[1:]) for l in src]
    p = tmp_path / "conn.log.labeled"
    p.write_text("\n".join(out) + "\n")
    df = read_zeek(p)
    assert len(df) == 140 and set(df.label) == {"Malicious", "Benign"}


def test_triage_eval_with_scripted_claude():
    """The Claude loop runs on a real-data case: tools resolve, and closing a real attack is counted against it."""
    from netsentinel.agent import triage
    from netsentinel.agent.analyst import ClaudeAnalyst

    cases = triage.build_cases([stratosphere.load(FIX / "000-zeek-malicious")])
    assert len(cases) == 1 and cases[0]["malicious"] is True

    def transport(payload):
        msgs = payload["messages"]
        assert "real capture" in payload["system"]
        if len(msgs) == 1:
            iid = cases[0]["incident_id"]
            return {"content": [{"type": "tool_use", "id": "t1", "name": "get_incident", "input": {"incident_id": iid}},
                                {"type": "tool_use", "id": "t2", "name": "destination_context", "input": {"ip": "93.184.216.34"}}]}
        ctx = [c for c in msgs[-1]["content"] if c["tool_use_id"] == "t2"][0]["content"]
        assert '"median_interval_s": 60' in ctx      # the rhythm the analyst needs is there
        return {"content": [{"type": "tool_use", "id": "t3", "name": "submit_report",
                             "input": {"verdict": "benign", "confidence": 0.6, "severity": "low",
                                       "summary": "Looks like telemetry.", "actions": ["Close"]}}]}

    res = triage.run(ClaudeAnalyst(transport=transport), cases)
    assert res["attacks_closed"] == 1.0 and res["noise_closed"] is None
    assert res["rows"][0]["tools_used"] == 3


def test_triage_survives_a_failing_case():
    from netsentinel.agent import triage

    class Broken:
        name = "broken"
        def investigate(self, *a, **k):
            raise TimeoutError("read timed out")

    cases = triage.build_cases([stratosphere.load(FIX / "000-zeek-malicious")])
    saved = []
    res = triage.run(Broken(), cases, checkpoint=lambda rows: saved.append(len(rows)))
    assert res["errors"] == 1 and res["attacks_closed"] == 0.0 and saved == [1]
    again = triage.run(Broken(), cases, done={(r["capture"], r["incident_id"]): r for r in res["rows"]})
    assert again["cases"] == 1
