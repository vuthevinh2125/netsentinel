"""Stratosphere Laboratory (CTU Prague) labelled Zeek captures → LabData.

Source: https://github.com/stratosphereips/security-datasets-for-testing
Each capture is about 24 hours of real traffic from one Windows host that was either
infected with a known malware family (Dridex, Trickbot, Kovter, Bladabindi RAT, ...)
or left benign on the Internet and attacked from outside. Every flow carries the
lab's own label (Malicious / Benign / Background), assigned with their NetflowLabeler.
"""
from __future__ import annotations

import re
from pathlib import Path

import numpy as np
import pandas as pd

from ..features import is_internal, set_home_hosts
from ..simulate import LabData
from .zeek import read_zeek

AUTH_COLUMNS = ["ts", "src_ip", "dst_ip", "user", "service", "result", "label", "attack_id"]

# Captures that duplicate another one byte for byte (032 is a copy of 014).
DUPLICATES = {"032-zeek-malicious": "014-zeek-malicious"}


def _num(s: pd.Series) -> pd.Series:
    return pd.to_numeric(s, errors="coerce").fillna(0)


def _label(s: pd.Series) -> pd.Series:
    return s.fillna("").str.strip().str.lower().map(lambda x: "malicious" if x == "malicious" else
                                                    "benign" if x == "benign" else "background")


def describe(capture_dir: Path) -> dict:
    """Malware family and original capture name from the capture's README."""
    readme = capture_dir / "README.md"
    text = readme.read_text(encoding="utf-8", errors="replace") if readme.exists() else ""
    fam = re.search(r"Probable Name:\s*([^\n]+)", text)
    orig = re.search(r"(CTU-[A-Za-z0-9-]+)", text)
    kind = "mixed" if "mixed" in capture_dir.name else "malicious"
    return {"capture": capture_dir.name, "kind": kind,
            "family": (fam.group(1).strip().rstrip("?").strip() if fam else
                       "Benign host attacked from the Internet" if kind == "mixed" else "Unnamed malware"),
            "original_name": orig.group(1) if orig else ""}


def load(capture_dir: str | Path) -> LabData:
    d = Path(capture_dir)
    conn_path = next(iter(sorted(d.glob("data/conn.log.labeled"))), None)
    if conn_path is None:
        raise FileNotFoundError(f"{d}: no data/conn.log.labeled")
    c = read_zeek(conn_path)
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

    dns_path = d / "data" / "dns.log.labeled"
    if dns_path.exists() and dns_path.stat().st_size > 200:
        z = read_zeek(dns_path)
        dns = pd.DataFrame({
            "ts": _num(z["ts"]).astype(float),
            "src_ip": z["id.orig_h"].astype(str),
            "query": z["query"].fillna("").astype(str),
            "qtype": z.get("qtype_name", pd.Series(["A"] * len(z))).fillna("").astype(str),
            "resp_size": 0,
            "label": _label(z["label"]) if "label" in z else "background",
            "attack_id": "",
            "rcode": z.get("rcode_name", pd.Series([""] * len(z))).fillna("").astype(str),
        })
        dns = dns[dns["query"] != ""].sort_values("ts", ignore_index=True)
    else:
        dns = pd.DataFrame(columns=["ts", "src_ip", "query", "qtype", "resp_size", "label", "attack_id", "rcode"])

    auth = pd.DataFrame(columns=AUTH_COLUMNS)
    # The monitored machine is the address that takes part in the most connections.
    # Some captures give it a public university address, so it is declared as a home host,
    # the way a SOC lists its own ranges. Worked out from traffic only, never from labels.
    home = pd.concat([flows.src_ip, flows.dst_ip]).value_counts().index[0]
    set_home_hosts([home])
    internal = sorted({ip for ip in pd.unique(flows.src_ip) if is_internal(ip)})
    hosts = pd.DataFrame({"ip": internal, "hostname": [f"host-{ip}" for ip in internal], "role": "workstation"})
    info = describe(d)
    meta = {**info, "start_ts": float(flows.ts.min()), "days": float((flows.ts.max() - flows.ts.min()) / 86400),
            "baseline_days": 0, "home_hosts": [home], "timezone": "UTC", "source": "Stratosphere Laboratory, CTU Prague"}
    return LabData(flows, auth, dns, [], hosts, meta)


def captures(root: str | Path) -> list[Path]:
    root = Path(root)
    out = [p for p in sorted(root.iterdir()) if p.is_dir() and (p / "data" / "conn.log.labeled").exists()
           and p.name not in DUPLICATES]
    return out
