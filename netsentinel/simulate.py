"""Synthetic enterprise network with labelled attacks.

Generates three log streams for a small company network over N days:

* flows  - NetFlow-like records (one row per connection)
* auth   - authentication events (SSH, SMB/NTLM, Kerberos)
* dns    - DNS queries sent to the domain controller

Benign traffic follows office hours, and includes "hard negatives" that look
suspicious but are legitimate: the nightly database backup (large transfer at
02:00), the IT vulnerability scanner (weekly scan), admins mistyping SSH
passwords, and software updates at night.

Attacks are injected with MITRE ATT&CK technique IDs as labels, so detection can
be scored. Everything is driven by one seed, so a run is reproducible.
"""
from __future__ import annotations

import math
import random
import string
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

DAY = 86_400
# 2026-11-02 00:00 Asia/Ho_Chi_Minh (UTC+7) as a Unix timestamp
START_TS = 1793552400

USER_NET = "10.10.1."
SERVER_NET = "10.10.2."
IOT_NET = "10.10.3."

SERVERS = {
    "dc01": SERVER_NET + "5",     # AD / DNS / Kerberos
    "web01": SERVER_NET + "10",   # public web, SSH open to the internet
    "db01": SERVER_NET + "20",    # database
    "file01": SERVER_NET + "30",  # SMB file server, backup target
    "mail01": SERVER_NET + "40",
    "scan01": SERVER_NET + "50",  # IT vulnerability scanner (benign scanning)
}
ADMIN_HOSTS = [USER_NET + "11", USER_NET + "12"]

POPULAR_EXTERNAL = [
    "142.250.66.78", "142.250.199.14", "157.240.15.35", "13.107.42.14", "52.98.152.162",
    "104.18.32.47", "172.217.24.110", "23.215.0.136", "151.101.1.69", "20.205.243.166",
    "203.162.4.191", "125.212.226.69", "118.69.110.4", "210.245.31.38", "14.225.254.100",
]
UPDATE_SERVERS = ["91.189.91.83", "185.125.190.36", "13.107.4.50"]
BENIGN_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "outlook.office365.com", "teams.microsoft.com",
    "vnexpress.net", "tuoitre.vn", "zalo.me", "github.com", "stackoverflow.com", "docs.python.org",
    "vtv.vn", "shopee.vn", "microsoft.com", "windowsupdate.com", "slack.com", "zoom.us",
    "corp.local", "fileserver.corp.local", "mail.corp.local",
]

# MITRE ATT&CK techniques used by the injected attacks
TECHNIQUES = {
    "T1046": "Network Service Discovery",
    "T1110": "Brute Force",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1071.001": "Application Layer Protocol: Web Protocols (C2 beaconing)",
    "T1071.004": "Application Layer Protocol: DNS (tunnelling)",
    "T1048": "Exfiltration Over Alternative Protocol",
}


@dataclass
class Attack:
    """Ground truth for one injected attack."""
    attack_id: str
    technique: str
    name: str
    src_ip: str
    targets: list[str]
    start: float
    end: float
    note: str = ""


@dataclass
class LabData:
    flows: pd.DataFrame
    auth: pd.DataFrame
    dns: pd.DataFrame
    attacks: list[Attack]
    hosts: pd.DataFrame
    meta: dict = field(default_factory=dict)


class _Gen:
    def __init__(self, seed: int, days: int):
        self.rng = random.Random(seed)
        self.np = np.random.default_rng(seed)
        self.days = days
        self.flows: list[tuple] = []
        self.auth: list[tuple] = []
        self.dns: list[tuple] = []
        self.attacks: list[Attack] = []

    # -- primitives ---------------------------------------------------
    def flow(self, ts, src, dst, port, proto="tcp", out=500, inn=1500, dur=0.5, label="benign", aid=""):
        pkts = max(1, int((out + inn) / 900))
        self.flows.append((float(ts), src, dst, int(port), proto, int(out), int(inn), pkts, float(dur), label, aid))

    def auth_ev(self, ts, src, dst, user, service, ok, label="benign", aid=""):
        self.auth.append((float(ts), src, dst, user, service, "success" if ok else "failure", label, aid))

    def dns_q(self, ts, src, query, qtype="A", resp=90, label="benign", aid=""):
        self.dns.append((float(ts), src, query, qtype, int(resp), label, aid))

    def office_activity(self, hour: float, weekday: bool) -> float:
        """Relative activity level 0..1 for a workstation at a local hour."""
        if not weekday:
            return 0.05
        if 8 <= hour < 12 or 13.5 <= hour < 18:
            return 1.0
        if 12 <= hour < 13.5:
            return 0.45
        if 18 <= hour < 21:
            return 0.15
        return 0.02


def _hosts() -> pd.DataFrame:
    rows = []
    for name, ip in SERVERS.items():
        rows.append((ip, name, "server"))
    for i in range(11, 51):
        role = "admin-workstation" if USER_NET + str(i) in ADMIN_HOSTS else "workstation"
        rows.append((USER_NET + str(i), f"ws{i:02d}", role))
    for i in range(10, 18):
        rows.append((IOT_NET + str(i), f"iot{i:02d}", "iot"))
    return pd.DataFrame(rows, columns=["ip", "hostname", "role"])


def _benign(g: _Gen, hosts: pd.DataFrame) -> None:
    ws = hosts[hosts.role.str.contains("workstation")].ip.tolist()
    iot = hosts[hosts.role == "iot"].ip.tolist()
    dc, web, db, fs, mail, scanner = (SERVERS[k] for k in ("dc01", "web01", "db01", "file01", "mail01", "scan01"))
    users = {ip: f"user{ip.split('.')[-1]}" for ip in ws}
    for ip in ADMIN_HOSTS:
        users[ip] = f"admin{ip.split('.')[-1]}"
    rng = g.rng

    for d in range(g.days):
        day0 = START_TS + d * DAY
        weekday = (d % 7) < 5
        # Workstations: web, DNS, file shares, mail, Kerberos, a little SSH for admins
        for ip in ws:
            # each host gets a personal baseline intensity
            base = 0.6 + (int(ip.split(".")[-1]) % 7) / 10
            for slot in range(0, DAY, 600):  # 10-minute slots
                hour = slot / 3600
                lam = g.office_activity(hour, weekday) * base * 5
                n = g.np.poisson(lam)
                for _ in range(n):
                    t = day0 + slot + rng.random() * 600
                    r = rng.random()
                    if r < 0.62:
                        dst = rng.choice(POPULAR_EXTERNAL)
                        g.dns_q(t - 0.05, ip, rng.choice(BENIGN_DOMAINS))
                        blocked = rng.random() < 0.015  # some sites are blocked by the proxy: no reply
                        g.flow(t, ip, dst, 443, out=rng.randint(600, 4000), inn=0 if blocked else rng.randint(5_000, 900_000), dur=rng.uniform(0.2, 30))
                    elif r < 0.80:
                        g.flow(t, ip, fs, 445, out=rng.randint(2_000, 60_000), inn=rng.randint(5_000, 4_000_000), dur=rng.uniform(0.5, 20))
                    elif r < 0.90:
                        g.flow(t, ip, mail, 993, out=rng.randint(500, 5_000), inn=rng.randint(2_000, 200_000), dur=rng.uniform(0.3, 5))
                    elif r < 0.97:
                        g.flow(t, ip, dc, 88, proto="udp", out=rng.randint(300, 1500), inn=rng.randint(300, 1500), dur=0.05)
                        g.auth_ev(t, ip, dc, users[ip], "kerberos", True)
                    else:
                        g.flow(t, ip, dc, 389, out=rng.randint(300, 2_000), inn=rng.randint(300, 8_000), dur=0.2)
            # morning logon
            if weekday:
                t = day0 + 8 * 3600 + rng.uniform(-1800, 3600)
                ok = rng.random() > 0.04
                g.auth_ev(t, ip, dc, users[ip], "kerberos", ok)
                if not ok:  # typo then success
                    g.auth_ev(t + 6, ip, dc, users[ip], "kerberos", True)

        # Admins map the file share from their own workstation every morning
        if weekday:
            for ip in ADMIN_HOSTS:
                g.auth_ev(day0 + rng.uniform(8, 9) * 3600, ip, fs, users[ip], "smb", True)

        # Admins SSH into servers during the day, with the occasional typo
        if weekday:
            for ip in ADMIN_HOSTS:
                for _ in range(rng.randint(3, 8)):
                    t = day0 + rng.uniform(9, 17.5) * 3600
                    srv = rng.choice([web, db, fs, mail])
                    for k in range(rng.choice([0, 0, 0, 1, 2])):
                        g.auth_ev(t + k * 4, ip, srv, users[ip], "ssh", False)
                    g.auth_ev(t + 10, ip, srv, users[ip], "ssh", True)
                    g.flow(t + 10, ip, srv, 22, out=rng.randint(5_000, 80_000), inn=rng.randint(20_000, 400_000), dur=rng.uniform(60, 1800))

        # Internet background noise: a few random SSH probes against web01 (failures, low rate)
        for _ in range(rng.randint(15, 40)):
            t = day0 + rng.random() * DAY
            src = f"{rng.randint(30, 220)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
            for k in range(rng.randint(1, 4)):
                g.auth_ev(t + k * 3, src, web, rng.choice(["root", "admin", "ubuntu", "test"]), "ssh", False)
                g.flow(t + k * 3, src, web, 22, out=rng.randint(200, 900), inn=rng.randint(200, 1500), dur=0.8)

        # Public web traffic to web01 from many internet clients
        for _ in range(rng.randint(900, 1400)):
            t = day0 + rng.random() * DAY
            src = f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
            g.flow(t, src, web, 443, out=rng.randint(400, 3_000), inn=rng.randint(5_000, 300_000), dur=rng.uniform(0.1, 4))

        # Servers: app traffic web -> db, nightly backup db -> file01 (hard negative), updates
        for slot in range(0, DAY, 300):
            n = g.np.poisson(3 if 7 <= slot / 3600 < 22 else 1)
            for _ in range(n):
                t = day0 + slot + rng.random() * 300
                g.flow(t, web, db, 5432, out=rng.randint(500, 4_000), inn=rng.randint(2_000, 90_000), dur=rng.uniform(0.01, 0.4))
        t = day0 + 2 * 3600 + rng.uniform(0, 600)
        g.flow(t, db, fs, 445, out=rng.randint(1_400_000_000, 1_900_000_000), inn=rng.randint(200_000, 900_000), dur=rng.uniform(900, 1500))
        g.auth_ev(t - 2, db, fs, "svc_backup", "smb", True)
        for srv in (web, db, mail, fs, dc):
            t = day0 + rng.uniform(1, 4) * 3600
            g.dns_q(t - 0.1, srv, "archive.ubuntu.com")
            g.flow(t, srv, rng.choice(UPDATE_SERVERS), 443, out=rng.randint(2_000, 20_000), inn=rng.randint(5_000_000, 90_000_000), dur=rng.uniform(20, 200))

        # Monitoring agent on db01 posts a heartbeat to a SaaS endpoint every minute (hard negative:
        # perfectly regular, single host, external)
        t = day0 + rng.uniform(0, 30)
        while t < day0 + DAY:
            g.flow(t, db, "34.120.177.193", 443, out=rng.randint(700, 900), inn=rng.randint(200, 300), dur=0.2)
            t += 60 + rng.uniform(-0.8, 0.8)

        # Thursday: IT admin pushes a software update to many workstations over SMB, from the admin's
        # own workstation (hard negative for lateral-movement detection)
        if d == 3:
            t = day0 + 15 * 3600 + rng.uniform(0, 1800)
            admin_ws = ADMIN_HOSTS[0]
            for target in rng.sample([h for h in ws if h not in ADMIN_HOSTS], 9):
                g.auth_ev(t, admin_ws, target, users[admin_ws], "smb", True)
                g.flow(t, admin_ws, target, 445, out=rng.randint(30_000_000, 60_000_000), inn=rng.randint(50_000, 200_000), dur=rng.uniform(20, 60))
                t += rng.uniform(20, 70)

        # IoT: printers and cameras chatting with the file server and NTP
        for ip in iot:
            for slot in range(0, DAY, 1800):
                t = day0 + slot + rng.random() * 1800
                g.flow(t, ip, dc, 123, proto="udp", out=90, inn=90, dur=0.01)

        # IT vulnerability scanner: weekly authorised scan on day 1 (Tuesday) 22:00 (hard negative)
        if d == 1:
            t0 = day0 + 22 * 3600
            for k, port in enumerate(range(1, 1025)):
                for target in (web, db, fs, mail, dc):
                    g.flow(t0 + k * 0.6 + rng.random() * 0.2, scanner, target, port, out=60, inn=0 if rng.random() < 0.97 else 60, dur=0.001)


def _attacks(g: _Gen) -> None:
    rng = g.rng
    victim = USER_NET + "37"            # phished workstation, start of the campaign
    tunnel_host = USER_NET + "52"       # second, unrelated infection doing DNS tunnelling
    c2 = "45.77.163.120"
    exfil_dst = "103.97.125.18"
    brute_src = "185.220.101.47"
    web, db = SERVERS["web01"], SERVERS["db01"]

    def day(d, h, m=0):
        return START_TS + d * DAY + h * 3600 + m * 60

    # A1: C2 beaconing from the phished host, day 2 09:40 -> end. Interval and jitter vary per run.
    s, e = day(2, 9, 40), START_TS + g.days * DAY - 60
    period = rng.choice([30, 60, 120, 300])
    jitter = rng.uniform(0.05, 0.4)
    t = s
    while t < e:
        g.flow(t, victim, c2, 443, out=rng.randint(180, 420), inn=rng.randint(150, 600), dur=rng.uniform(0.1, 0.4), label="T1071.001", aid="A1")
        t += period * (1 + rng.uniform(-jitter, jitter))
    g.attacks.append(Attack("A1", "T1071.001", "C2 beaconing", victim, [c2], s, e,
                            f"Implant on ws37 calls home over HTTPS every ~{period} s with {jitter:.0%} jitter."))

    # A2: fast internal port scan of the server VLAN, day 3 14:05
    s = day(3, 14, 5)
    t = s
    for port in range(1, 1025):
        for target in (SERVER_NET + "5", web, db, SERVER_NET + "30"):
            g.flow(t, victim, target, port, out=60, inn=0 if port not in (22, 53, 88, 389, 443, 445, 5432) else 60, dur=0.001, label="T1046", aid="A2")
            t += rng.uniform(0.02, 0.08)
    g.attacks.append(Attack("A2", "T1046", "Port scan (fast)", victim, [SERVER_NET + "5", web, db, SERVER_NET + "30"], s, t,
                            "Full 1-1024 TCP scan of four servers in a few minutes."))

    # A3: slow, stealthy scan, day 3 16:00-18:00 against workstations
    slow_gap = rng.uniform(20, 75)
    s = day(3, 16)
    t = s
    targets = [USER_NET + str(i) for i in range(13, 51) if i != 37]
    ports = [22, 135, 139, 445, 3389, 5985]
    while t < s + 2 * 3600:
        g.flow(t, victim, rng.choice(targets), rng.choice(ports), out=60, inn=0, dur=0.001, label="T1046", aid="A3")
        t += rng.uniform(0.6, 1.4) * slow_gap
    g.attacks.append(Attack("A3", "T1046", "Port scan (slow, low-and-slow)", victim, targets, s, t,
                            f"One probe every ~{slow_gap:.0f} s for two hours, below the per-window rule threshold."))

    # A4: SSH brute force from the internet against web01, day 4 02:10, then a success
    s = day(4, 2, 10)
    t = s
    for k in range(420):
        g.auth_ev(t, brute_src, web, rng.choice(["root", "admin", "deploy", "ubuntu", "www"]), "ssh", False, "T1110", "A4")
        g.flow(t, brute_src, web, 22, out=rng.randint(300, 900), inn=rng.randint(300, 1200), dur=0.6, label="T1110", aid="A4")
        t += rng.uniform(1.5, 4)
    g.auth_ev(t, brute_src, web, "deploy", "ssh", True, "T1110", "A4")
    g.flow(t, brute_src, web, 22, out=40_000, inn=900_000, dur=600, label="T1110", aid="A4")
    g.attacks.append(Attack("A4", "T1110", "SSH brute force with success", brute_src, [web], s, t,
                            "420 failed SSH logins in ~20 min, then the 'deploy' account gets in."))

    # A5: lateral movement over SMB with a stolen admin account, day 5 10:30
    s = day(5, 10, 30)
    t = s
    hops = [USER_NET + str(i) for i in rng.sample(range(13, 51), 16) if i != 37]
    for h in hops:
        g.auth_ev(t, victim, h, "admin11", "smb", True, "T1021.002", "A5")
        g.flow(t, victim, h, 445, out=rng.randint(200_000, 1_500_000), inn=rng.randint(20_000, 90_000), dur=rng.uniform(2, 8), label="T1021.002", aid="A5")
        t += rng.uniform(8, 25)
    g.auth_ev(t, victim, db, "admin11", "smb", True, "T1021.002", "A5")
    g.flow(t, victim, db, 445, out=900_000, inn=40_000, dur=5, label="T1021.002", aid="A5")
    g.attacks.append(Attack("A5", "T1021.002", "Lateral movement over SMB", victim, hops + [db], s, t,
                            "Stolen admin11 credentials used from a normal workstation to touch 16 hosts and db01."))

    # A6: DNS tunnelling from a second host, day 5 21:00-22:00
    s = day(5, 21)
    t = s
    alphabet = string.ascii_lowercase + string.digits
    lo = rng.randint(26, 45)
    gap = rng.uniform(3, 15)
    while t < s + 3600:
        label = "".join(rng.choice(alphabet) for _ in range(rng.randint(lo, lo + 15)))
        g.dns_q(t, tunnel_host, f"{label}.cdn-sync-update.xyz", "TXT", rng.randint(180, 250), "T1071.004", "A6")
        t += rng.uniform(0.5, 1.5) * gap
    g.attacks.append(Attack("A6", "T1071.004", "DNS tunnelling", tunnel_host, ["cdn-sync-update.xyz"], s, t,
                            "Long random TXT queries to one rare domain, about 15 per minute."))

    # A7: data exfiltration from db01 to an unknown internet host, day 6 03:12
    s = day(6, rng.randint(0, 4), rng.randint(0, 59))
    size = rng.randint(150_000_000, 2_000_000_000)
    g.flow(s, db, exfil_dst, 8443, out=size, inn=300_000, dur=size / 1.3e6, label="T1048", aid="A7")
    g.attacks.append(Attack("A7", "T1048", "Exfiltration to rare external host", db, [exfil_dst], s, s + size / 1.3e6,
                            f"{size / 1e9:.2f} GB leaves db01 at night to an IP never seen before."))


def generate(seed: int = 7, days: int = 7) -> LabData:
    """Build the lab dataset. Days 0-1 are clean and used as the learning baseline."""
    g = _Gen(seed, days)
    hosts = _hosts()
    _benign(g, hosts)
    _attacks(g)
    flows = pd.DataFrame(g.flows, columns=["ts", "src_ip", "dst_ip", "dst_port", "proto", "bytes_out", "bytes_in", "packets", "duration", "label", "attack_id"]).sort_values("ts", ignore_index=True)
    auth = pd.DataFrame(g.auth, columns=["ts", "src_ip", "dst_ip", "user", "service", "result", "label", "attack_id"]).sort_values("ts", ignore_index=True)
    dns = pd.DataFrame(g.dns, columns=["ts", "src_ip", "query", "qtype", "resp_size", "label", "attack_id"]).sort_values("ts", ignore_index=True)
    meta = {"seed": seed, "days": days, "start_ts": START_TS, "baseline_days": 2, "timezone": "Asia/Ho_Chi_Minh"}
    return LabData(flows, auth, dns, g.attacks, hosts, meta)


def entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())
