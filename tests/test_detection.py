import numpy as np
import pandas as pd
import pytest

from netsentinel import detect, evaluate
from netsentinel.simulate import START_TS, entropy, generate


@pytest.fixture(scope="module")
def lab():
    data = generate(seed=7)
    return data, detect.run(data)


def test_generation_is_reproducible():
    a, b = generate(seed=3, days=3), generate(seed=3, days=3)
    pd.testing.assert_frame_equal(a.flows, b.flows)
    assert len(a.attacks) == len(b.attacks)


def test_every_attack_is_labelled(lab):
    data, _ = lab
    labelled = set(data.flows.attack_id) | set(data.auth.attack_id) | set(data.dns.attack_id)
    assert {a.attack_id for a in data.attacks} <= labelled


def test_entropy():
    assert entropy("aaaa") == 0
    assert entropy("ab") == pytest.approx(1.0)
    assert entropy("k3j9x2m7q1z8w4v6") > 3.5


def test_authorised_scanner_is_suppressed(lab):
    _, result = lab
    scans = [a for a in result.alerts if a.detector == "rule:port-scan"]
    assert any(a.suppressed and a.src_ip == "10.10.2.50" for a in scans)
    assert any(not a.suppressed and a.src_ip == "10.10.1.37" for a in scans)


def test_brute_force_rule_flags_success_as_critical():
    rows = [(START_TS + i * 2, "1.2.3.4", "10.10.2.10", "root", "ssh", "failure", "x", "") for i in range(30)]
    rows.append((START_TS + 70, "1.2.3.4", "10.10.2.10", "deploy", "ssh", "success", "x", ""))
    auth = pd.DataFrame(rows, columns=["ts", "src_ip", "dst_ip", "user", "service", "result", "label", "attack_id"])
    alerts = detect.rule_brute_force(auth, detect._Ids())
    assert len(alerts) == 1
    assert alerts[0].severity == "critical"
    assert alerts[0].evidence["successful_user"] == "deploy"


def test_brute_force_ignores_a_few_typos():
    rows = [(START_TS + i * 30, "10.10.1.11", "10.10.2.10", "admin11", "ssh", "failure", "x", "") for i in range(3)]
    auth = pd.DataFrame(rows, columns=["ts", "src_ip", "dst_ip", "user", "service", "result", "label", "attack_id"])
    assert detect.rule_brute_force(auth, detect._Ids()) == []


def _flows(times, src, dst):
    return pd.DataFrame({"ts": times, "src_ip": src, "dst_ip": dst, "dst_port": 443, "proto": "tcp",
                         "bytes_out": 300, "bytes_in": 400, "packets": 1, "duration": 0.2, "label": "x", "attack_id": ""})


def test_beaconing_catches_a_steady_rhythm_but_not_human_browsing():
    rng = np.random.default_rng(0)
    steady = START_TS + np.cumsum(60 + rng.uniform(-5, 5, 200))
    human = START_TS + np.cumsum(rng.exponential(60, 200))
    flows = pd.concat([_flows(steady, "10.10.1.37", "45.77.1.1"), _flows(human, "10.10.1.20", "45.77.2.2")])
    alerts = detect.detect_beaconing(flows, set(), detect._Ids())
    assert [a.src_ip for a in alerts] == ["10.10.1.37"]


def test_campaign_is_one_incident_and_brute_force_is_separate(lab):
    _, result = lab
    campaign = [i for i in result.incidents if "T1048" in i.techniques]
    assert len(campaign) == 1
    assert {"10.10.1.37", "10.10.2.20"} <= set(campaign[0].hosts)   # pivot ws37 -> db01 exfil
    assert {"T1071.001", "T1046", "T1021.002"} <= set(campaign[0].techniques)
    assert "10.10.1.11" not in campaign[0].hosts       # the admin's software push stays out
    brute = next(i for i in result.incidents if "T1110" in i.techniques)
    assert "10.10.1.37" not in brute.hosts


def test_hybrid_detects_every_attack_with_few_false_alerts(lab):
    data, result = lab
    s = evaluate.score(data, result)
    assert s["attack_recall"] == 1.0
    assert s["false_alerts_per_day"] <= 1.0


def test_model_alone_catches_the_slow_scan_that_rules_miss():
    data = generate(seed=7)
    rules = evaluate.score(data, detect.run(data, use_model=False, use_beacon=False))
    model = evaluate.score(data, detect.run(data, use_rules=False, use_beacon=False))
    slow = lambda s: next(a for a in s["attacks"] if a["attack_id"] == "A3")["detected"]
    assert not slow(rules)
    assert slow(model)
