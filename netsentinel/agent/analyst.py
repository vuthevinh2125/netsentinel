"""Two analysts that investigate an incident with the same tools and return the same report shape.

* ClaudeAnalyst  - an LLM tool-use loop over the Anthropic Messages API (or a compatible proxy).
* PlaybookAnalyst - a deterministic, offline analyst that follows fixed playbooks. It needs no
  API key, keeps the pipeline usable anywhere, and is the baseline the LLM is compared against.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field

from .. import mitre
from ..features import is_internal
from .tools import TOOL_SCHEMAS, Workspace, fmt

LAB_NETWORK = "a small company network (10.10.1.0/24 workstations, 10.10.2.0/24 servers, 10.10.3.0/24 IoT). Local time is UTC+7"

SYSTEM_PROMPT = """You are a tier-2 SOC analyst investigating one incident raised by NetSentinel, a detection system watching {network}.

Investigate with the tools before you conclude:
1. Call get_incident first.
2. Check the source host with host_profile, look up remote peers with destination_context (their DNS names and connection rhythm), and pull the flows, logins or DNS queries that prove or disprove each alert.
3. Call lookup_mitre for every technique you report.
4. Read any data_notes a tool returns: missing data is only evidence when the data could have shown it. Weigh the host's whole picture (host_peer_summary) before calling one destination rare.
5. Decide a verdict. Detection systems raise false alarms: regular traffic that already existed during the baseline, or an admin doing admin work from their usual workstation in office hours, is usually benign. New behaviour, rare destinations, stolen accounts and success after brute force are not.
6. Finish by calling submit_report exactly once. Name concrete IPs, accounts and domains in the summary and actions. Put containment actions first.

Write the summary and actions in {language}. Keep technique IDs, IPs, hostnames and account names as they are."""


@dataclass
class Report:
    incident_id: str
    analyst: str
    verdict: str
    confidence: float
    severity: str
    summary: str
    attack_chain: list[str] = field(default_factory=list)
    affected_hosts: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    trace: list[dict] = field(default_factory=list)
    seconds: float = 0.0
    language: str = "en"

    def to_dict(self) -> dict:
        return asdict(self)


def _preview(obj: dict, n: int = 240) -> str:
    s = json.dumps(obj, ensure_ascii=False, default=str)
    return s if len(s) <= n else s[:n] + "…"


# ------------------------------------------------------------------ LLM analyst
class ClaudeAnalyst:
    """Tool-use loop. `transport` is injectable so tests can replay scripted model turns."""

    name = "claude"

    def __init__(self, model: str | None = None, api_key: str | None = None, base_url: str | None = None,
                 transport=None, max_turns: int = 14):
        self.model = model or os.environ.get("NETSENTINEL_MODEL", "claude-sonnet-5-5")
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        # NETSENTINEL_LLM_URL lets you point at your own proxy (e.g. a Cloudflare Worker that holds the key)
        self.base_url = (base_url or os.environ.get("NETSENTINEL_LLM_URL", "https://api.anthropic.com")).rstrip("/")
        self.transport = transport or self._http
        self.max_turns = max_turns

    @staticmethod
    def available() -> bool:
        return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("NETSENTINEL_LLM_URL"))

    def _http(self, payload: dict) -> dict:
        import requests

        headers = {"content-type": "application/json", "anthropic-version": "2023-06-01"}
        if self.api_key:
            headers["x-api-key"] = self.api_key
        r = requests.post(f"{self.base_url}/v1/messages", headers=headers, json=payload, timeout=120)
        r.raise_for_status()
        return r.json()

    def investigate(self, ws: Workspace, incident_id: str, language: str = "en") -> Report:
        t0 = time.time()
        lang = "Vietnamese" if language == "vi" else "English"
        messages = [{"role": "user", "content": f"Investigate incident {incident_id} and submit your report."}]
        trace: list[dict] = []
        for turn in range(self.max_turns):
            resp = self.transport({"model": self.model, "max_tokens": 4096, "system": SYSTEM_PROMPT.format(language=lang, network=ws.data.meta.get("network_description", LAB_NETWORK)),
                                   "tools": TOOL_SCHEMAS, "messages": list(messages)})
            content = resp.get("content", [])
            messages.append({"role": "assistant", "content": content})
            uses = [c for c in content if c.get("type") == "tool_use"]
            if not uses:
                text = " ".join(c.get("text", "") for c in content if c.get("type") == "text").strip()
                return Report(incident_id, self.name, "needs_review", 0.3, ws.incidents[incident_id].severity,
                              text or "The model stopped without submitting a report.", trace=trace,
                              seconds=round(time.time() - t0, 1), language=language)
            results = []
            for u in uses:
                if u["name"] == "submit_report":
                    trace.append({"step": len(trace) + 1, "tool": "submit_report", "input": u["input"], "output": "report submitted"})
                    r = u["input"]
                    return Report(incident_id, self.name, r.get("verdict", "needs_review"), float(r.get("confidence", 0.5)),
                                  r.get("severity", "medium"), r.get("summary", ""), r.get("attack_chain", []),
                                  r.get("affected_hosts", []), r.get("techniques", []), r.get("actions", []), trace,
                                  round(time.time() - t0, 1), language)
                out = ws.call(u["name"], u.get("input", {}))
                trace.append({"step": len(trace) + 1, "tool": u["name"], "input": u.get("input", {}), "output": _preview(out)})
                results.append({"type": "tool_result", "tool_use_id": u["id"], "content": json.dumps(out, ensure_ascii=False, default=str)})
            messages.append({"role": "user", "content": results})
        return Report(incident_id, self.name, "needs_review", 0.3, ws.incidents[incident_id].severity,
                      "Investigation hit the step limit before a report was submitted.", trace=trace,
                      seconds=round(time.time() - t0, 1), language=language)


# ------------------------------------------------------- OpenAI-compatible analyst
class OpenAICompatAnalyst:
    """The same tool-use loop over any OpenAI-compatible /chat/completions endpoint:
    Gemini (Google AI Studio free tier), Ollama on your own machine, Groq, OpenRouter and others.

    NETSENTINEL_OPENAI_URL  base URL, e.g. https://generativelanguage.googleapis.com/v1beta/openai
                            or http://localhost:11434/v1 for Ollama
    NETSENTINEL_OPENAI_KEY  API key (any non-empty string for Ollama)
    NETSENTINEL_MODEL       model name
    """

    def __init__(self, model: str | None = None, api_key: str | None = None, base_url: str | None = None,
                 transport=None, max_turns: int = 14, min_interval_s: float | None = None):
        self.model = model or os.environ.get("NETSENTINEL_MODEL", "")
        self.api_key = api_key or os.environ.get("NETSENTINEL_OPENAI_KEY", "")
        self.base_url = (base_url or os.environ.get("NETSENTINEL_OPENAI_URL", "")).rstrip("/")
        self.name = f"openai-compatible:{self.model}" if self.model else "openai-compatible"
        self.transport = transport or self._http
        self.max_turns = max_turns
        # free tiers limit requests per minute: space calls out instead of failing
        self.min_interval_s = float(os.environ.get("NETSENTINEL_MIN_INTERVAL", min_interval_s if min_interval_s is not None else 0))
        # optional: "none" / "low" / "medium" / "high" for models that think before answering (faster when low)
        self.reasoning = os.environ.get("NETSENTINEL_REASONING", "")
        self.timeout_s = float(os.environ.get("NETSENTINEL_TIMEOUT", 120))
        self._last = 0.0

    @staticmethod
    def available() -> bool:
        return bool(os.environ.get("NETSENTINEL_OPENAI_URL") and os.environ.get("NETSENTINEL_MODEL"))

    def _http(self, payload: dict) -> dict:
        import requests

        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        last_err = None
        r = None
        for attempt in range(6):
            wait = self.min_interval_s - (time.time() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.time()
            try:
                r = requests.post(f"{self.base_url}/chat/completions", headers=headers, json=payload, timeout=self.timeout_s)
            except (requests.Timeout, requests.ConnectionError) as e:   # slow or dropped: wait and try again
                last_err = e
                time.sleep(min(60, 5 * 2 ** attempt))
                continue
            if r.status_code in (429, 500, 502, 503, 504):   # rate limited or busy: back off and retry
                time.sleep(min(60, 5 * 2 ** attempt))
                continue
            if r.status_code >= 400:
                raise RuntimeError(f"{r.status_code} from {self.base_url}/chat/completions (model={self.model!r}): "
                                   f"{r.text[:400]}\nCheck NETSENTINEL_MODEL against the provider's model list.")
            return r.json()
        if r is None:
            raise RuntimeError(f"No response from {self.base_url} after retries: {last_err}")
        raise RuntimeError(f"Still failing after retries ({r.status_code}): {r.text[:300]}")

    @staticmethod
    def _tools() -> list[dict]:
        return [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                   "parameters": t["input_schema"]}} for t in TOOL_SCHEMAS]

    def investigate(self, ws: Workspace, incident_id: str, language: str = "en") -> Report:
        t0 = time.time()
        lang = "Vietnamese" if language == "vi" else "English"
        system = SYSTEM_PROMPT.format(language=lang, network=ws.data.meta.get("network_description", LAB_NETWORK))
        messages = [{"role": "system", "content": system},
                    {"role": "user", "content": f"Investigate incident {incident_id} and submit your report."}]
        trace: list[dict] = []
        sev = ws.incidents[incident_id].severity
        for _ in range(self.max_turns):
            payload = {"model": self.model, "messages": list(messages), "tools": self._tools(),
                       "tool_choice": "auto", "temperature": 0}
            if self.reasoning:
                payload["reasoning_effort"] = self.reasoning
            resp = self.transport(payload)
            msg = (resp.get("choices") or [{}])[0].get("message", {}) or {}
            calls = msg.get("tool_calls") or []
            messages.append({"role": "assistant", "content": msg.get("content") or "", **({"tool_calls": calls} if calls else {})})
            if not calls:
                return Report(incident_id, self.name, "needs_review", 0.3, sev,
                              (msg.get("content") or "The model stopped without submitting a report.").strip(),
                              trace=trace, seconds=round(time.time() - t0, 1), language=language)
            for c in calls:
                fn = c.get("function", {})
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                if fn.get("name") == "submit_report":
                    trace.append({"step": len(trace) + 1, "tool": "submit_report", "input": args, "output": "report submitted"})
                    v = args.get("verdict", "needs_review")
                    v = v if v in ("true_positive", "benign", "needs_review") else "needs_review"
                    return Report(incident_id, self.name, v, float(args.get("confidence", 0.5) or 0.5),
                                  args.get("severity", "medium"), args.get("summary", ""), args.get("attack_chain", []) or [],
                                  args.get("affected_hosts", []) or [], args.get("techniques", []) or [],
                                  args.get("actions", []) or [], trace, round(time.time() - t0, 1), language)
                out = ws.call(fn.get("name", ""), args)
                trace.append({"step": len(trace) + 1, "tool": fn.get("name"), "input": args, "output": _preview(out)})
                messages.append({"role": "tool", "tool_call_id": c.get("id", ""), "name": fn.get("name", ""),
                                 "content": json.dumps(out, ensure_ascii=False, default=str)})
        return Report(incident_id, self.name, "needs_review", 0.3, sev,
                      "Investigation hit the step limit before a report was submitted.", trace=trace,
                      seconds=round(time.time() - t0, 1), language=language)


# ------------------------------------------------------------- offline analyst
_T = {
    "en": {
        "benign_beacon": "Regular traffic from {host} ({name}) to {dst} every ~{gap:.0f} s. It was already running during the baseline, the destination is not new, and the host is a server: this matches a monitoring or telemetry agent, not new malware.",
        "benign_admin": "{account} reached {n} hosts over SMB from {host} ({name}), a workstation this account normally uses, during office hours. This matches an IT software push, not stolen credentials.",
        "tp_intro": "{n_alerts} alert{s1} on {n_hosts} host{s2} between {start} and {end} form{s3} one {kind}.",
        "multi": "multi-stage intrusion", "single": "attack",
        "beacon": "{src} beacons to {dst} every ~{gap:.0f} s ({conn} connections, a destination no other host uses).",
        "scan": "{src} scanned {targets} hosts / {ports} ports with {noreply:.0%} of probes unanswered.",
        "slow": "{src} also probed hosts slowly ({obs}), below the per-window scan rule; the anomaly model caught it.",
        "lateral": "{src} used account {account} over SMB to reach {n} hosts in 15 minutes; this account was never used from {src} before.",
        "brute": "{src} made {fails} failed {svc} logins against {dst}, then logged in as '{user}'.",
        "brute_nosuccess": "{src} made {fails} failed {svc} logins against {dst}; no success seen.",
        "dns": "{src} sent {q} DNS queries with {uniq} unique {len:.0f}-character random subdomains of {dom} ({types}).",
        "exfil": "{src} uploaded {gb} GB to {dst}:{port} at {hour}, a destination never seen before.",
        "anomaly": "{src} deviated from its own baseline ({obs}).",
        "act_isolate": "Isolate {host} from the network and collect memory and disk images",
        "act_block": "Block {ioc} at the firewall, proxy and DNS resolver",
        "act_reset": "Reset the password of '{account}', revoke its sessions and review where it logged in",
        "act_disable": "Disable account '{account}' on {host} and review its shell history",
        "act_ssh": "Turn off SSH password login on {host}; allow keys from the admin VLAN only",
        "act_hunt": "Search all hosts for connections to {ioc}",
        "act_rotate": "Rotate credentials stored on {host} and identify the data that left",
        "act_check": "Check {n} hosts reached by {account} for new services, scheduled tasks or admin-share files",
        "act_confirm_beacon": "Confirm with the owner of {host} that {dst} is their monitoring service, then allowlist this pair",
        "act_confirm_admin": "Match the activity to an IT change ticket, then allowlist software pushes from {host}",
        "act_review": "Review the host's recent activity with its owner",
    },
    "vi": {
        "benign_beacon": "{host} ({name}) gửi kết nối đều đặn tới {dst} khoảng mỗi {gap:.0f} giây. Hoạt động này đã có từ giai đoạn baseline, đích không mới và đây là máy chủ: khớp với agent giám sát hoặc telemetry, không phải mã độc mới.",
        "benign_admin": "Tài khoản {account} truy cập {n} máy qua SMB từ {host} ({name}), là máy tài khoản này vẫn dùng, trong giờ hành chính. Khớp với việc IT đẩy phần mềm, không phải tài khoản bị đánh cắp.",
        "tp_intro": "{n_alerts} cảnh báo trên {n_hosts} máy từ {start} đến {end} tạo thành một {kind}.",
        "multi": "cuộc xâm nhập nhiều giai đoạn", "single": "cuộc tấn công",
        "beacon": "{src} gọi về {dst} khoảng mỗi {gap:.0f} giây ({conn} kết nối, đích không máy nào khác dùng).",
        "scan": "{src} quét {targets} máy / {ports} cổng, {noreply:.0%} gói dò không được trả lời.",
        "slow": "{src} còn dò chậm ({obs}), dưới ngưỡng của luật quét cổng; mô hình bất thường đã phát hiện.",
        "lateral": "{src} dùng tài khoản {account} qua SMB để vào {n} máy trong 15 phút; tài khoản này chưa từng dùng trên {src}.",
        "brute": "{src} đăng nhập {svc} thất bại {fails} lần vào {dst}, sau đó đăng nhập thành công bằng '{user}'.",
        "brute_nosuccess": "{src} đăng nhập {svc} thất bại {fails} lần vào {dst}; chưa thấy lần thành công.",
        "dns": "{src} gửi {q} truy vấn DNS với {uniq} subdomain ngẫu nhiên dài {len:.0f} ký tự của {dom} ({types}).",
        "exfil": "{src} tải lên {gb} GB tới {dst}:{port} lúc {hour}, một đích chưa từng thấy.",
        "anomaly": "{src} lệch khỏi baseline của chính nó ({obs}).",
        "act_isolate": "Cách ly {host} khỏi mạng, thu bản sao bộ nhớ và ổ đĩa",
        "act_block": "Chặn {ioc} trên firewall, proxy và DNS resolver",
        "act_reset": "Đặt lại mật khẩu '{account}', thu hồi phiên đăng nhập và rà soát nơi tài khoản đã đăng nhập",
        "act_disable": "Khoá tài khoản '{account}' trên {host} và rà soát lịch sử lệnh",
        "act_ssh": "Tắt đăng nhập SSH bằng mật khẩu trên {host}; chỉ cho phép khoá từ VLAN quản trị",
        "act_hunt": "Tìm kết nối tới {ioc} trên toàn bộ các máy",
        "act_rotate": "Thay toàn bộ thông tin đăng nhập lưu trên {host} và xác định dữ liệu đã bị lấy",
        "act_check": "Kiểm tra {n} máy mà {account} đã vào: dịch vụ mới, tác vụ lập lịch, file trên admin share",
        "act_confirm_beacon": "Xác nhận với người phụ trách {host} rằng {dst} là dịch vụ giám sát, rồi đưa cặp này vào danh sách cho phép",
        "act_confirm_admin": "Đối chiếu với phiếu thay đổi của IT, rồi cho phép việc đẩy phần mềm từ {host}",
        "act_review": "Rà soát hoạt động gần đây của máy cùng người dùng",
    },
}


FEATURE_LABEL = {
    "en": {"n_dst_ports": "distinct ports", "n_zero_reply": "unanswered probes", "n_internal_dst": "internal hosts touched",
           "smb_dsts": "hosts reached over SMB", "ext_new_dst": "new external destinations", "auth_fail": "failed logins",
           "dns_long_q": "long random DNS names"},
    "vi": {"n_dst_ports": "cổng khác nhau", "n_zero_reply": "gói dò không trả lời", "n_internal_dst": "máy nội bộ bị chạm",
           "smb_dsts": "máy truy cập qua SMB", "ext_new_dst": "đích bên ngoài mới", "auth_fail": "lần đăng nhập lỗi",
           "dns_long_q": "tên DNS dài ngẫu nhiên"},
}


class PlaybookAnalyst:
    name = "playbook"

    def investigate(self, ws: Workspace, incident_id: str, language: str = "en") -> Report:
        t0 = time.time()
        L = _T[language]
        trace: list[dict] = []

        def call(tool, **args):
            out = ws.call(tool, args)
            trace.append({"step": len(trace) + 1, "tool": tool, "input": args, "output": _preview(out)})
            return out

        inc = call("get_incident", incident_id=incident_id)   # also selects this capture's home network
        alerts = inc["alerts"]
        src = alerts[0]["src_ip"]
        prof = call("host_profile", ip=src) if is_internal(src) else {"hostname": "external", "role": "internet host"}
        for t in inc["techniques"]:
            call("lookup_mitre", technique_id=t)

        # ---- benign playbooks
        if len(alerts) == 1 and alerts[0]["detector"] == "beaconing" and alerts[0]["evidence"].get("active_since_baseline"):
            a = alerts[0]
            call("query_flows", ip=src, direction="out")
            ev = a["evidence"]
            summary = L["benign_beacon"].format(host=src, name=prof.get("hostname"), dst=a["targets"][0], gap=ev["median_interval_s"])
            return Report(incident_id, self.name, "benign", 0.75, "low", summary, [], [src], ["T1071.001"],
                          [L["act_confirm_beacon"].format(host=src, dst=a["targets"][0])], trace, round(time.time() - t0, 2), language)
        if len(alerts) == 1 and alerts[0]["detector"] == "rule:smb-fan-out" and alerts[0]["evidence"].get("account_seen_on_this_host_before"):
            a = alerts[0]
            call("auth_events", ip=src, start=inc["start"] - 3600, end=inc["end"] + 3600)
            ev = a["evidence"]
            summary = L["benign_admin"].format(account=ev["account"], n=ev["hosts_reached_15min"], host=src, name=prof.get("hostname"))
            return Report(incident_id, self.name, "benign", 0.7, "low", summary, [], [src], ["T1021.002"],
                          [L["act_confirm_admin"].format(host=src)], trace, round(time.time() - t0, 2), language)

        # ---- true-positive playbook: one sentence and concrete actions per alert
        chain, actions, iocs = [], [], []
        rule_alerts = [x for x in alerts if x["detector"] != "anomaly-model"]
        for a in sorted(alerts, key=lambda x: x["start"]):
            ev, s = a["evidence"], a["src_ip"]
            if a["detector"] == "anomaly-model":
                hint = ev.get("likely_technique")
                # the model agreeing with a rule on the same activity is corroboration, not a new step
                if any(r["src_ip"] == s and r["technique"] == hint and r["start"] <= a["end"] + 300 and r["end"] >= a["start"] - 300
                       for r in rule_alerts):
                    continue
            tgt = a["targets"][0] if a["targets"] else ""
            if a["detector"] == "beaconing":
                line = L["beacon"].format(src=s, dst=tgt, gap=ev["median_interval_s"], conn=ev["connections"])
                actions += [L["act_isolate"].format(host=s), L["act_block"].format(ioc=tgt)]
                iocs.append(tgt)
            elif a["detector"] == "rule:port-scan":
                line = L["scan"].format(src=s, targets=ev["distinct_targets"], ports=ev["distinct_ports"], noreply=ev["no_reply_share"])
                actions.append(L["act_isolate"].format(host=s))
            elif a["detector"] == "rule:smb-fan-out":
                call("auth_events", ip=s, start=None, end=None)
                line = L["lateral"].format(src=s, account=ev["account"], n=ev["hosts_reached_15min"])
                actions += [L["act_reset"].format(account=ev["account"]), L["act_check"].format(n=ev["hosts_reached_15min"], account=ev["account"])]
            elif a["detector"] == "rule:brute-force":
                call("auth_events", ip=tgt)
                if ev.get("successful_user"):
                    line = L["brute"].format(src=s, fails=ev["failed_logins"], svc=ev["service"].upper(), dst=tgt, user=ev["successful_user"])
                    actions += [L["act_disable"].format(account=ev["successful_user"], host=tgt), L["act_block"].format(ioc=s),
                                L["act_ssh"].format(host=tgt)]
                else:
                    line = L["brute_nosuccess"].format(src=s, fails=ev["failed_logins"], svc=ev["service"].upper(), dst=tgt)
                    actions.append(L["act_block"].format(ioc=s))
                iocs.append(s)
            elif a["detector"] == "rule:dns-tunnel":
                call("dns_queries", ip=s)
                line = L["dns"].format(src=s, q=ev["queries"], uniq=ev["unique_subdomains"], len=ev["mean_label_length"],
                                       dom=tgt, types="/".join(ev["record_types"]))
                actions += [L["act_isolate"].format(host=s), L["act_block"].format(ioc=tgt)]
                iocs.append(tgt)
            elif a["detector"] == "rule:large-upload":
                call("query_flows", ip=s, direction="out")
                line = L["exfil"].format(src=s, gb=ev["gigabytes"], dst=tgt, port=ev["dst_port"], hour=a["start_local"])
                actions += [L["act_block"].format(ioc=tgt), L["act_rotate"].format(host=s), L["act_isolate"].format(host=s)]
                iocs.append(tgt)
            else:  # anomaly model
                obs = ", ".join(f"~{round(v)} {FEATURE_LABEL[language].get(k, k)}" for k, v in ev.get("observed", {}).items() if v)
                obs += " / 5 min"
                hint = ev.get("likely_technique")
                line = (L["slow"] if hint == "T1046" else L["anomaly"]).format(src=s, obs=obs)
            chain.append(f'{a["start_local"]} · {s} · {a["technique"] if a["technique"] != "anomaly" else (ev.get("likely_technique") or "anomaly")} · {line}')
        for ioc in dict.fromkeys(iocs):
            if not is_internal(ioc):
                actions.append(L["act_hunt"].format(ioc=ioc))
        actions = list(dict.fromkeys(actions))  # dedupe, keep order
        # containment first
        actions.sort(key=lambda x: 0 if x.startswith(("Isolate", "Cách ly", "Block", "Chặn", "Disable", "Khoá")) else 1)
        kind = L["multi"] if len(inc["techniques"]) >= 3 else L["single"]
        n_a, n_h = len(alerts), len(inc["hosts"])
        intro = L["tp_intro"].format(n_alerts=n_a, n_hosts=n_h, start=inc["start_local"], end=inc["end_local"], kind=kind,
                                     s1="" if n_a == 1 else "s", s2="" if n_h == 1 else "s", s3="s" if n_a == 1 else "")
        sentences = [c.split(" · ", 3)[-1] for c in chain]
        summary = " ".join([intro] + sentences[:5])
        hosts = sorted({a["src_ip"] for a in alerts} | {t for a in alerts for t in a["targets"] if is_internal(t)})
        return Report(incident_id, self.name, "true_positive", round(min(0.98, inc["score"]), 2), inc["severity"], summary, chain,
                      hosts, inc["techniques"], actions[:10], trace, round(time.time() - t0, 2), language)


def default_analyst():
    return ClaudeAnalyst() if ClaudeAnalyst.available() else PlaybookAnalyst()
