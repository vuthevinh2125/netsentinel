import json
import pytest

from netsentinel import detect
from netsentinel.agent import evals
from netsentinel.agent.analyst import ClaudeAnalyst, PlaybookAnalyst
from netsentinel.agent.tools import Workspace
from netsentinel.simulate import generate


@pytest.fixture(scope="module")
def ws():
    data = generate(seed=7)
    result = detect.run(data)
    return Workspace(data, result)


def scripted(turns):
    """A fake Messages API that replays assistant turns and records what it was sent."""
    sent = []

    def transport(payload):
        sent.append(payload)
        return {"content": turns[len(sent) - 1], "stop_reason": "tool_use"}

    return transport, sent


def test_claude_loop_runs_tools_and_returns_the_submitted_report(ws):
    inc = ws.result.incidents[0].incident_id
    transport, sent = scripted([
        [{"type": "text", "text": "Looking at the incident."},
         {"type": "tool_use", "id": "t1", "name": "get_incident", "input": {"incident_id": inc}}],
        [{"type": "tool_use", "id": "t2", "name": "lookup_mitre", "input": {"technique_id": "T1048"}},
         {"type": "tool_use", "id": "t3", "name": "host_profile", "input": {"ip": "10.10.1.37"}}],
        [{"type": "tool_use", "id": "t4", "name": "submit_report", "input": {
            "verdict": "true_positive", "confidence": 0.9, "severity": "critical",
            "summary": "ws37 beacons to 45.77.163.120 and db01 sent data to 103.97.125.18.",
            "actions": ["Isolate 10.10.1.37", "Block 45.77.163.120"]}}],
    ])
    rep = ClaudeAnalyst(transport=transport).investigate(ws, inc)
    assert rep.verdict == "true_positive" and rep.severity == "critical"
    assert [t["tool"] for t in rep.trace] == ["get_incident", "lookup_mitre", "host_profile", "submit_report"]
    # tool results go back with the right ids, in one user turn per assistant turn
    second_call = sent[1]["messages"]
    assert second_call[-1]["role"] == "user"
    assert second_call[-1]["content"][0]["tool_use_id"] == "t1"
    assert {c["tool_use_id"] for c in sent[2]["messages"][-1]["content"]} == {"t2", "t3"}
    assert sent[0]["tools"][-1]["name"] == "submit_report"


def test_claude_loop_without_a_report_needs_review(ws):
    inc = ws.result.incidents[0].incident_id
    transport, _ = scripted([[{"type": "text", "text": "I am not sure."}]])
    rep = ClaudeAnalyst(transport=transport).investigate(ws, inc)
    assert rep.verdict == "needs_review"


def test_unknown_tool_is_reported_not_raised(ws):
    assert "error" in ws.call("delete_everything", {})
    assert "error" in ws.call("host_profile", {"wrong": 1})


@pytest.mark.parametrize("seed", [7, 11])
def test_playbook_analyst_passes_every_check(seed):
    data = generate(seed=seed)
    result = detect.run(data)
    res = evals.run_eval(PlaybookAnalyst(), data, result)
    assert res["verdict_accuracy"] == 1.0
    assert res["score"] == 1.0


def test_benign_incidents_are_recognised(ws):
    truth = evals.ground_truth(ws.data, ws.result)
    benign = [k for k, v in truth.items() if v["verdict"] == "benign"]
    assert len(benign) == 2   # the monitoring heartbeat and the admin's software push
    for inc in benign:
        assert PlaybookAnalyst().investigate(ws, inc).verdict == "benign"


def test_openai_compatible_analyst_loop():
    """Same investigation over an OpenAI-style API (Gemini, Ollama...): tool calls resolve, report parsed."""
    from netsentinel.agent.analyst import OpenAICompatAnalyst
    from netsentinel.agent.tools import Workspace
    from netsentinel import detect
    from netsentinel.simulate import generate

    data = generate(seed=7, days=7)
    ws = Workspace(data, detect.run(data))
    iid = next(iter(ws.incidents))
    seen = []

    def transport(payload):
        msgs = payload["messages"]
        seen.append(len(msgs))
        assert payload["tools"][0]["type"] == "function"
        if len(msgs) == 2:
            return {"choices": [{"message": {"content": None, "tool_calls": [
                {"id": "c1", "type": "function", "function": {"name": "get_incident", "arguments": json.dumps({"incident_id": iid})}}]}}]}
        assert msgs[-1]["role"] == "tool" and iid in msgs[-1]["content"]
        return {"choices": [{"message": {"content": "", "tool_calls": [
            {"id": "c2", "type": "function", "function": {"name": "submit_report", "arguments": json.dumps(
                {"verdict": "true_positive", "confidence": 0.9, "severity": "high", "summary": "ok", "actions": ["isolate"]})}}]}}]}

    rep = OpenAICompatAnalyst(model="test-model", base_url="http://x", transport=transport).investigate(ws, iid)
    assert rep.verdict == "true_positive" and rep.analyst == "openai-compatible:test-model"
    assert [t["tool"] for t in rep.trace] == ["get_incident", "submit_report"] and seen == [2, 4]
