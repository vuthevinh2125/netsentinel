"""IoT-23 (Stratosphere Laboratory, CTU Prague): labelled traffic of IoT devices infected with
Mirai, Torii, Hajime, Okiru and other Linux botnets → LabData.

Reads either an original ``conn.log.labeled`` or the CSV export (first 100,000 flows of each
scenario) that several public repositories mirror. Labels are used only for grading.
"""
from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

from ..features import is_internal, set_home_hosts
from ..simulate import LabData
from .stratosphere import AUTH_COLUMNS, _label, _num
from .zeek import read_zeek

# Official list: https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/
FAMILY = {1: "Hide and Seek", 3: "Muhstik", 7: "Mirai", 8: "Hakai", 9: "Hajime", 17: "Kenjiro", 20: "Torii",
          21: "Torii", 33: "Kenjiro", 34: "Mirai", 35: "Mirai", 36: "Okiru", 39: "IRCBot", 42: "Trojan",
          43: "Mirai", 44: "Mirai", 48: "Mirai", 49: "Mirai", 52: "Mirai", 60: "Gagfyt"}


def _read(path: Path) -> pd.DataFrame:
    if path.suffix == ".csv":
        df = pd.read_csv(path, dtype=str, keep_default_na=False)
        df = df.drop(columns=[c for c in df.columns if c.startswith("Unnamed") or c == ""], errors="ignore")
        # "(empty)   Malicious   PartOfAHorizontalPortScan" → tunnel_parents, label, detailed label
        parts = df["label"].str.split(r"\s{2,}", n=2, regex=True, expand=True).reindex(columns=[0, 1, 2])
        df["label"], df["detailedlabel"] = parts[1].fillna(""), parts[2].fillna("")
        return df.replace({"-": None, "(empty)": None})
    return read_zeek(path)


def load(path: str | Path, capture: int) -> LabData:
    path = Path(path)
    c = _read(path)
    flows = pd.DataFrame({
        "ts": _num(c["ts"]).astype(float),
        "src_ip": c["id.orig_h"].astype(str),
        "dst_ip": c["id.resp_h"].astype(str),
        "dst_port": _num(c["id.resp_p"]).astype(int),
        "proto": c["proto"].fillna("").astype(str),
        "bytes_out": _num(c["orig_bytes"]).astype("int64"),
        "bytes_in": _num(c["resp_bytes"]).astype("int64"),
        "packets": (_num(c["orig_pkts"]) + _num(c["resp_pkts"])).astype(int),
        "duration": _num(c["duration"]).astype(float),
        "label": _label(c["label"]),
        "attack_id": c.get("detailedlabel", pd.Series([""] * len(c))).fillna("").astype(str),
    }).sort_values("ts", ignore_index=True)
    dns = pd.DataFrame(columns=["ts", "src_ip", "query", "qtype", "resp_size", "label", "attack_id", "rcode"])
    home = pd.concat([flows.src_ip, flows.dst_ip]).value_counts().index[0]
    set_home_hosts([home])
    internal = sorted({ip for ip in pd.unique(flows.src_ip) if is_internal(ip)})
    hosts = pd.DataFrame({"ip": internal, "hostname": [f"host-{ip}" for ip in internal], "role": "iot"})
    meta = {"capture": f"CTU-IoT-Malware-Capture-{capture}-1", "kind": "malicious", "family": FAMILY.get(capture, "Unknown"),
            "original_name": f"CTU-IoT-Malware-Capture-{capture}-1", "start_ts": float(flows.ts.min()),
            "days": float((flows.ts.max() - flows.ts.min()) / 86400), "baseline_days": 0, "home_hosts": [home],
            "timezone": "UTC", "source": "IoT-23, Stratosphere Laboratory, CTU Prague",
            "truncated": path.suffix == ".csv",
            "network_description": ("a real capture of one Linux IoT device (IoT-23, Stratosphere Laboratory, CTU Prague). "
                                    "There is no clean baseline period and no DNS log. Times are shown in UTC+7")}
    return LabData(flows, pd.DataFrame(columns=AUTH_COLUMNS), dns, [], hosts, meta)


def captures(root: str | Path) -> list[tuple[Path, int]]:
    """Find IoT-23 scenarios: dfN.csv files, or folders named like CTU-IoT-Malware-Capture-N-1."""
    root = Path(root)
    found: dict[int, Path] = {}
    for p in sorted(root.rglob("*")):
        m = re.fullmatch(r"df(\d+)\.csv", p.name) or (re.search(r"Capture-(\d+)-1", str(p)) if p.name == "conn.log.labeled" else None)
        if m and int(m.group(1)) in FAMILY:
            n = int(m.group(1))
            if n not in found or p.name == "conn.log.labeled":   # prefer the full log over the 100k-row export
                found[n] = p
    return [(found[n], n) for n in sorted(found)]
