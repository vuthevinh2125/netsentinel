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
