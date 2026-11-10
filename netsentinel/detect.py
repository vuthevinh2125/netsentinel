"""Detection engine: rules, a per-host anomaly model, a beaconing detector, and incident grouping.

Every detector returns Alert objects. Alerts are then grouped into incidents: alerts
from the same host, and alerts that "pivot" (a later alert starts from a host an
earlier alert touched), end up in one incident so an analyst sees the whole story.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from .features import MODEL_FEATURES, WINDOW, host_windows, is_internal
from .simulate import DAY, TECHNIQUES, LabData, entropy

SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Hosts allowed to scan the network (the IT vulnerability scanner)
AUTHORISED_SCANNERS = {"10.10.2.50"}


@dataclass
class Alert:
    alert_id: str
    detector: str            # rule name, "anomaly-model" or "beaconing"
    technique: str           # MITRE technique ID, or "anomaly"
    title: str
    severity: str
    score: float             # 0..1 confidence
    src_ip: str
    targets: list[str]
    start: float
    end: float
    evidence: dict = field(default_factory=dict)
    suppressed: bool = False
    suppress_reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Incident:
    incident_id: str
    title: str
    severity: str
    hosts: list[str]
    techniques: list[str]
    start: float
    end: float
    alert_ids: list[str]
    score: float

    def to_dict(self) -> dict:
        return asdict(self)


class _Ids:
    def __init__(self):
        self.n = 0

    def next(self) -> str:
        self.n += 1
        return f"AL-{self.n:04d}"


# ---------------------------------------------------------------- rules
def rule_port_scan(flows: pd.DataFrame, ids: _Ids) -> list[Alert]:
    f = flows.copy()
    f["win"] = (f.ts // WINDOW * WINDOW).astype("int64")
    f["pair"] = f.dst_ip + ":" + f.dst_port.astype(str)
    g = f.groupby(["src_ip", "win"]).agg(pairs=("pair", "nunique"), ports=("dst_port", "nunique"),
                                         dsts=("dst_ip", "nunique"), zero=("bytes_in", lambda x: (x == 0).mean()),
                                         t0=("ts", "min"), t1=("ts", "max"))
    hits = g[(g.pairs >= 60) & (g.zero >= 0.7)].reset_index()
    alerts = []
    for src, grp in hits.groupby("src_ip"):
        # merge consecutive windows into one alert
        grp = grp.sort_values("win")
        runs, cur = [], [grp.iloc[0]]
        for _, row in grp.iloc[1:].iterrows():
            if row.win - cur[-1].win <= WINDOW * 2:
                cur.append(row)
            else:
                runs.append(cur)
                cur = [row]
        runs.append(cur)
        for run in runs:
            r = pd.DataFrame(run)
            sub = f[(f.src_ip == src) & (f.ts >= r.t0.min()) & (f.ts <= r.t1.max())]
            a = Alert(ids.next(), "rule:port-scan", "T1046", "Port scan", "high", 0.9, src,
                      sorted(sub.dst_ip.unique().tolist())[:20], float(r.t0.min()), float(r.t1.max()),
                      {"probes": int(len(sub)), "distinct_ports": int(sub.dst_port.nunique()),
                       "distinct_targets": int(sub.dst_ip.nunique()), "no_reply_share": round(float((sub.bytes_in == 0).mean()), 3)})
            if src in AUTHORISED_SCANNERS:
                a.suppressed, a.suppress_reason, a.severity = True, "Authorised IT vulnerability scanner (scan01)", "low"
            alerts.append(a)
    return alerts


def rule_brute_force(auth: pd.DataFrame, ids: _Ids) -> list[Alert]:
    alerts = []
    a = auth.sort_values("ts")
    for (src, dst), grp in a.groupby(["src_ip", "dst_ip"]):
        fails = grp[grp.result == "failure"]
        if len(fails) < 20:
            continue
        # sliding 10-minute count of failures
        t = fails.ts.to_numpy()
        j, best, best_i = 0, 0, 0
        for i in range(len(t)):
            while t[i] - t[j] > 600:
                j += 1
            if i - j + 1 > best:
                best, best_i = i - j + 1, i
        if best < 20:
            continue
        start = float(fails.ts.iloc[0])
        end = float(fails.ts.iloc[-1])
        later_ok = grp[(grp.result == "success") & (grp.ts > start)]
        success = not later_ok.empty
        if success:
            end = float(later_ok.ts.iloc[0])
        alerts.append(Alert(ids.next(), "rule:brute-force", "T1110",
                            "Brute force followed by a successful login" if success else "Brute force",
                            "critical" if success else "medium", 0.95 if success else 0.7, src, [dst], start, end,
                            {"failed_logins": int(len(fails)), "peak_failures_10min": int(best),
                             "usernames_tried": sorted(fails.user.unique().tolist())[:10],
                             "service": grp.service.iloc[0],
                             "successful_user": later_ok.user.iloc[0] if success else None}))
    return alerts


def rule_lateral_smb(auth: pd.DataFrame, baseline_end: float, ids: _Ids) -> list[Alert]:
    """Account used over SMB to reach many hosts, from a host it does not normally use."""
    alerts = []
    a = auth[(auth.service == "smb") & (auth.result == "success")].sort_values("ts")
    usual = auth[auth.ts < baseline_end].groupby("user").src_ip.agg(set).to_dict()
    for (src, user), grp in a.groupby(["src_ip", "user"]):
        t = grp.ts.to_numpy()
        dsts = grp.dst_ip.to_numpy()
        for i in range(len(t)):
            j = np.searchsorted(t, t[i] + 900)
            reach = set(dsts[i:j])
            if len(reach) >= 5:
                window = grp.iloc[i:j]
                unusual = src not in usual.get(user, set())
                alerts.append(Alert(ids.next(), "rule:smb-fan-out", "T1021.002", "Lateral movement over SMB",
                                    "critical" if unusual else "high", 0.92 if unusual else 0.75, src, sorted(reach),
                                    float(window.ts.iloc[0]), float(window.ts.iloc[-1]),
                                    {"account": user, "hosts_reached_15min": len(reach),
                                     "account_seen_on_this_host_before": not unusual}))
                break
    return alerts


def rule_dns_tunnel(dns: pd.DataFrame, ids: _Ids) -> list[Alert]:
    d = dns.copy()
    d["win"] = (d.ts // WINDOW * WINDOW).astype("int64")
    parts = d["query"].str.split(".")
    d["first"] = parts.str[0]
    d["domain"] = parts.str[-2] + "." + parts.str[-1]
    d["flen"] = d["first"].str.len()
    d["fent"] = d["first"].map(entropy)
    g = d.groupby(["src_ip", "domain", "win"]).agg(q=("query", "size"), uniq=("first", "nunique"),
                                                   flen=("flen", "mean"), fent=("fent", "mean"),
                                                   t0=("ts", "min"), t1=("ts", "max"))
    hits = g[(g.q >= 20) & (g.uniq >= 0.8 * g.q) & (g.flen >= 30) & (g.fent >= 3.5)].reset_index()
    alerts = []
    for (src, dom), grp in hits.groupby(["src_ip", "domain"]):
        sub = d[(d.src_ip == src) & (d.domain == dom)]
        alerts.append(Alert(ids.next(), "rule:dns-tunnel", "T1071.004", f"DNS tunnelling to {dom}", "high", 0.9, src, [dom],
                            float(grp.t0.min()), float(grp.t1.max()),
                            {"queries": int(len(sub)), "unique_subdomains": int(sub["first"].nunique()),
                             "mean_label_length": round(float(sub.flen.mean()), 1),
                             "mean_label_entropy_bits": round(float(sub.fent.mean()), 2),
                             "record_types": sorted(sub.qtype.unique().tolist()),
                             "example": sub["query"].iloc[0]}))
    return alerts


def rule_exfil(flows: pd.DataFrame, known_external: set[str], ids: _Ids) -> list[Alert]:
    big = flows[(flows.bytes_out >= 100_000_000) & (~flows.dst_ip.map(is_internal))]
    alerts = []
    for _, r in big.iterrows():
        new_dst = r.dst_ip not in known_external
        hour = ((r.ts + 7 * 3600) % DAY) / 3600
        night = hour < 6 or hour >= 22
        sev = "critical" if new_dst and night else "high" if new_dst else "medium"
        alerts.append(Alert(ids.next(), "rule:large-upload", "T1048", "Large upload to the internet", sev,
                            0.95 if new_dst else 0.6, r.src_ip, [r.dst_ip], float(r.ts), float(r.ts + r.duration),
                            {"bytes_out": int(r.bytes_out), "gigabytes": round(r.bytes_out / 1e9, 2), "dst_port": int(r.dst_port),
                             "destination_seen_before": not new_dst, "local_hour": round(hour, 2)}))
    return alerts


# ------------------------------------------------------------ beaconing
def detect_beaconing(flows: pd.DataFrame, known_external: set[str], ids: _Ids, baseline_end: float | None = None) -> list[Alert]:
    """Regular call-home traffic: many small connections to one rare external host at a steady rhythm."""
    f = flows[flows.src_ip.map(is_internal) & ~flows.dst_ip.map(is_internal)]
    pop = f.groupby("dst_ip").src_ip.nunique()
    alerts = []
    for (src, dst), grp in f.groupby(["src_ip", "dst_ip"]):
        if len(grp) < 30 or pop.get(dst, 0) > 3:
            continue
        t = np.sort(grp.ts.to_numpy())
        gaps = np.diff(t)
        med = float(np.median(gaps))
        mad = float(np.median(np.abs(gaps - med)))
        cv = mad / med if med > 0 else 9
        if med > 3600 or cv > 0.2:
            continue
        mean_bytes = float((grp.bytes_out + grp.bytes_in).mean())
        score = min(1.0, 0.5 + (0.2 - cv) * 2 + (0.2 if dst not in known_external else 0))
        # Already happening while the baseline was learned: long-standing behaviour, not a new compromise.
        pre_existing = bool(baseline_end is not None and t[0] < baseline_end)
        severity = "medium" if pre_existing else "high"
        if pre_existing:
            score *= 0.6
        alerts.append(Alert(ids.next(), "beaconing", "T1071.001",
                            "Regular call-home traffic (present since baseline)" if pre_existing else "C2 beaconing to a rare host",
                            severity, round(score, 3),
                            src, [dst], float(t[0]), float(t[-1]),
                            {"connections": int(len(grp)), "median_interval_s": round(med, 1),
                             "jitter_ratio": round(cv, 3), "mean_bytes_per_connection": round(mean_bytes),
                             "hosts_talking_to_destination": int(pop.get(dst, 0)),
                             "destination_seen_before": dst in known_external,
                             "active_since_baseline": pre_existing}))
    return alerts


# ---------------------------------------------------------- anomaly model
# Which technique a deviating feature most likely points to (a hint for the analyst).
FEATURE_HINT = {
    "n_dst_ports": "T1046", "n_zero_reply": "T1046", "n_internal_dst": "T1046",
    "smb_dsts": "T1021.002", "auth_fail": "T1110", "dns_long_q": "T1071.004",
    "ext_new_dst": "T1071.001",
}

def anomaly_model(win: pd.DataFrame, baseline_end: float, ids: _Ids, quantile: float = 0.9995,
                  min_effect: float = 6.0, strong_effect: float = 10.0) -> tuple[list[Alert], pd.DataFrame]:
    """Isolation Forest on features scaled against each host's own baseline (robust z-scores)."""
    w = win.copy()
    F = MODEL_FEATURES
    base = w[w.win < baseline_end]
    med = base.groupby("src_ip")[F].median()
    mad = base.groupby("src_ip")[F].agg(lambda x: (x - x.median()).abs().median()) * 1.4826
    gmed = base[F].median()
    gmad = (base[F] - gmed).abs().median() * 1.4826
    m = med.reindex(w.src_ip).fillna(gmed).to_numpy()
    s = mad.reindex(w.src_ip).fillna(gmad).to_numpy()
    s = np.maximum(s, 1.0)  # counts: a deviation of one is never alarming on its own
    z = (w[F].to_numpy() - m) / s
    z = np.clip(z, -50, 50)
    model = IsolationForest(n_estimators=300, random_state=0, contamination="auto")
    # Learn "normal" from the baseline days, without the authorised scanner's sweeps.
    in_train = (w.win.to_numpy() < baseline_end) & (~w.src_ip.isin(AUTHORISED_SCANNERS).to_numpy())
    train = z[in_train]
    model.fit(train)
    score = -model.score_samples(z)
    thr = float(np.quantile(-model.score_samples(train), quantile))
    peak_z = np.abs(z).max(axis=1)
    w["anomaly_score"] = score
    w["threshold"] = thr
    w["peak_z"] = peak_z
    zdf = pd.DataFrame(z, columns=F, index=w.index)
    alerts = []
    # Alert when the model finds the window unusual AND at least one behaviour moved
    # by MIN_EFFECT robust standard deviations; very large shifts alert on their own.
    flag = (w.win >= baseline_end) & ~w.src_ip.isin(AUTHORISED_SCANNERS) & (
        ((w.anomaly_score > thr) & (w.peak_z >= min_effect)) | (w.peak_z >= strong_effect))
    hits = w[flag].sort_values(["src_ip", "win"])
    for src, grp in hits.groupby("src_ip"):
        # merge windows less than 30 min apart
        rows = grp.to_dict("records")
        idx = grp.index.tolist()
        runs, cur, cur_i = [], [rows[0]], [idx[0]]
        for row, i in zip(rows[1:], idx[1:]):
            if row["win"] - cur[-1]["win"] <= 1800:
                cur.append(row)
                cur_i.append(i)
            else:
                runs.append((cur, cur_i))
                cur, cur_i = [row], [i]
        runs.append((cur, cur_i))
        for run, ri in runs:
            zmean = zdf.loc[ri].mean()
            top = zmean.abs().sort_values(ascending=False).head(3)
            hint = FEATURE_HINT.get(top.index[0], "")
            if top.index[0] in ("n_dst_ports", "n_zero_reply", "n_internal_dst") and zmean.get("smb_dsts", 0) >= 6:
                hint = "T1021.002"
            peak = max(r["anomaly_score"] for r in run)
            effect = max(r["peak_z"] for r in run)
            conf = float(min(1.0, 0.45 + max(0.0, peak - thr) * 3 + min(effect, 30) / 60))
            alerts.append(Alert(ids.next(), "anomaly-model", "anomaly", "Behaviour unlike this host's baseline",
                                "medium" if conf < 0.8 else "high", round(conf, 3), src, [],
                                float(run[0]["win"]), float(run[-1]["win"] + WINDOW),
                                {"windows": len(run), "peak_score": round(float(peak), 4), "threshold": round(thr, 4),
                                 "peak_deviation_sigma": round(float(effect), 1),
                                 "likely_technique": hint,
                                 "top_deviations": {k: round(float(zmean[k]), 1) for k in top.index},
                                 "observed": {k: round(float(np.mean([r[k] for r in run])), 2) for k in top.index}}))
    return alerts, w


# ------------------------------------------------------------- incidents
def group_incidents(alerts: list[Alert]) -> list[Incident]:
    live = [a for a in alerts if not a.suppressed]
    live.sort(key=lambda a: a.start)
    parent = list(range(len(live)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i, j):
        parent[find(i)] = find(j)

    first_seen: dict[str, float] = {}
    for x in live:
        if not x.evidence.get("active_since_baseline"):
            first_seen[x.src_ip] = min(first_seen.get(x.src_ip, x.start), x.start)
    for i, a in enumerate(live):
        for j in range(i):
            b = live[j]
            if a.evidence.get("active_since_baseline") or b.evidence.get("active_since_baseline"):
                continue  # long-standing behaviour is reviewed on its own, not chained to new activity
            same_src = a.src_ip == b.src_ip and abs(a.start - b.end) < 3 * DAY
            # Pivot: b touched a.src, and a.src only started misbehaving after that.
            pivot = (is_internal(a.src_ip) and a.src_ip in b.targets and is_internal(b.src_ip)
                     and first_seen.get(a.src_ip, a.start) >= b.start)
            if same_src or pivot:
                union(i, j)
    groups: dict[int, list[Alert]] = {}
    for i, a in enumerate(live):
        groups.setdefault(find(i), []).append(a)
    incidents = []
    for k, grp in enumerate(sorted(groups.values(), key=lambda g: min(a.start for a in g)), 1):
        sev = max(grp, key=lambda a: SEVERITY[a.severity]).severity
        techs = sorted({a.technique for a in grp if a.technique != "anomaly"})
        hosts = sorted({a.src_ip for a in grp} | {t for a in grp for t in a.targets if is_internal(t)})
        if len(techs) >= 3:
            title = "Multi-stage intrusion: " + " → ".join(TECHNIQUES.get(t, t).split(":")[0] for t in _kill_chain_order(techs))
        elif techs:
            title = " + ".join(TECHNIQUES.get(t, t) for t in techs)
        else:
            title = "Anomalous host behaviour"
        bonus = min(0.2, 0.05 * (len(grp) - 1))
        score = min(1.0, max(a.score for a in grp) + bonus)
        incidents.append(Incident(f"INC-{k:03d}", title, sev, hosts[:25], techs, min(a.start for a in grp),
                                  max(a.end for a in grp), [a.alert_id for a in grp], round(score, 3)))
    incidents.sort(key=lambda i: (-SEVERITY[i.severity], -i.score))
    return incidents


_ORDER = ["T1071.001", "T1046", "T1110", "T1021.002", "T1071.004", "T1048"]


def _kill_chain_order(techs: list[str]) -> list[str]:
    return sorted(techs, key=lambda t: _ORDER.index(t) if t in _ORDER else 99)


# --------------------------------------------------------------- pipeline
@dataclass
class DetectionResult:
    alerts: list[Alert]
    incidents: list[Incident]
    windows: pd.DataFrame
    config: dict


def run(data: LabData, use_rules: bool = True, use_model: bool = True, use_beacon: bool = True) -> DetectionResult:
    baseline_end = data.meta["start_ts"] + data.meta["baseline_days"] * DAY
    known_external = set(data.flows.loc[data.flows.ts < baseline_end, "dst_ip"])
    known_external = {ip for ip in known_external if not is_internal(ip)}
    ids = _Ids()
    alerts: list[Alert] = []
    if use_rules:
        alerts += rule_port_scan(data.flows, ids)
        alerts += rule_brute_force(data.auth, ids)
        alerts += rule_lateral_smb(data.auth, baseline_end, ids)
        alerts += rule_dns_tunnel(data.dns, ids)
        alerts += rule_exfil(data.flows, known_external, ids)
    if use_beacon:
        alerts += detect_beaconing(data.flows, known_external, ids, baseline_end)
    win = host_windows(data.flows, data.auth, data.dns, known_external)
    if use_model:
        model_alerts, win = anomaly_model(win, baseline_end, ids)
        alerts += model_alerts
    alerts.sort(key=lambda a: a.start)
    incidents = group_incidents(alerts)
    cfg = {"rules": use_rules, "model": use_model, "beaconing": use_beacon, "baseline_end": baseline_end}
    return DetectionResult(alerts, incidents, win, cfg)
