"""Turn raw logs into per-host, per-window behaviour features."""
from __future__ import annotations

import ipaddress
from functools import lru_cache

import numpy as np
import pandas as pd

from .simulate import entropy

WINDOW = 300  # seconds

FEATURES = [
    "n_flows",          # connections started
    "n_dst_ips",        # distinct destinations
    "n_dst_ports",      # distinct destination ports
    "n_pairs",          # distinct (destination, port) pairs
    "zero_reply_frac",  # share of connections that got no bytes back (failed / filtered)
    "n_zero_reply",     # connections that got no bytes back
    "n_internal_dst",   # distinct internal destinations
    "smb_dsts",         # distinct hosts reached on 445
    "log_bytes_out",    # log10 of bytes sent
    "ext_new_dst",      # external destinations never seen in the baseline
    "auth_fail",        # failed logins made by this host
    "dns_q",            # DNS queries
    "dns_mean_len",     # mean length of the first DNS label
    "dns_entropy",      # mean entropy of the first DNS label
    "dns_long_q",       # queries whose first label is 25+ characters and high-entropy
]

# The anomaly model uses structural signals only. Raw volume (how many connections,
# how many bytes) swings a lot for normal users, so it is shown to analysts but not
# used to decide what is anomalous.
# Counts rather than ratios, so a quiet window with one failed connection is not "100% failures".
MODEL_FEATURES = [
    "n_dst_ports", "n_zero_reply", "n_internal_dst", "smb_dsts",
    "ext_new_dst", "auth_fail", "dns_long_q",
]


# Addresses that belong to the monitored network even though they are publicly routable
# (the equivalent of HOME_NET in Suricata / Zeek's Site::local_nets).
HOME_HOSTS: frozenset[str] = frozenset()


def set_home_hosts(hosts) -> None:
    global HOME_HOSTS
    new = frozenset(hosts or ())
    if new != HOME_HOSTS:
        HOME_HOSTS = new
        is_internal.cache_clear()
        is_external.cache_clear()


@lru_cache(maxsize=200_000)
def is_internal(ip: str) -> bool:
    """Private address space (RFC 1918, IPv6 unique-local / link-local) and declared home hosts."""
    if ip in HOME_HOSTS:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private and not (a.is_loopback or a.is_multicast or a.is_unspecified or a.is_reserved)


@lru_cache(maxsize=200_000)
def is_external(ip: str) -> bool:
    """A real Internet host: globally routable unicast. Multicast, broadcast and
    link-local traffic (mDNS, SSDP, IPv6 neighbour discovery) is neither inside nor outside."""
    if ip in HOME_HOSTS:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global and not a.is_multicast


def external_mask(ips) -> pd.Series:
    s = pd.Series(ips)
    return pd.Series(np.fromiter((is_external(str(x)) for x in s), dtype=bool, count=len(s)), index=s.index)


def internal_mask(ips) -> pd.Series:
    """Boolean mask of internal addresses (works with any pandas string dtype)."""
    s = pd.Series(ips)
    return pd.Series(np.fromiter((is_internal(str(x)) for x in s), dtype=bool, count=len(s)), index=s.index)


def window_of(ts: pd.Series) -> pd.Series:
    return (ts // WINDOW * WINDOW).astype("int64")


def host_windows(flows: pd.DataFrame, auth: pd.DataFrame, dns: pd.DataFrame, known_external: set[str]) -> pd.DataFrame:
    """One row per (internal source host, 5-minute window) with behaviour features."""
    f = flows[internal_mask(flows.src_ip)].copy()
    f["win"] = window_of(f.ts)
    f["internal_dst"] = internal_mask(f.dst_ip)
    f["zero"] = (f.bytes_in == 0).astype(int)
    f["pair"] = f.dst_ip + ":" + f.dst_port.astype(str)
    f["ext_new"] = external_mask(f.dst_ip) & (~f.dst_ip.isin(known_external))
    g = f.groupby(["src_ip", "win"])
    internal = f[f.internal_dst].groupby(["src_ip", "win"]).dst_ip.nunique()
    smb = f[f.dst_port == 445].groupby(["src_ip", "win"]).dst_ip.nunique()
    ext_new = f[f.ext_new].groupby(["src_ip", "win"]).dst_ip.nunique()
    feat = pd.DataFrame({
        "n_flows": g.size(),
        "n_dst_ips": g.dst_ip.nunique(),
        "n_dst_ports": g.dst_port.nunique(),
        "n_pairs": g.pair.nunique(),
        "zero_reply_frac": g.zero.mean(),
        "n_zero_reply": g.zero.sum(),
        "n_internal_dst": internal,
        "smb_dsts": smb,
        "log_bytes_out": np.log10(g.bytes_out.sum() + 1),
        "ext_new_dst": ext_new,
    }).fillna(0.0)

    a = auth[internal_mask(auth.src_ip)].copy()
    a["win"] = window_of(a.ts)
    af = a[a.result == "failure"].groupby(["src_ip", "win"]).size().rename("auth_fail")

    d = dns.copy()
    d["win"] = window_of(d.ts)
    d["first"] = d["query"].str.split(".").str[0]
    d["flen"] = d["first"].str.len()
    d["fent"] = d["first"].map(entropy)
    dg = d.groupby(["src_ip", "win"])
    d["long"] = ((d.flen >= 25) & (d.fent >= 3.5)).astype(int)
    df = pd.DataFrame({"dns_q": dg.size(), "dns_mean_len": dg.flen.mean(), "dns_entropy": dg.fent.mean(),
                       "dns_long_q": d.groupby(["src_ip", "win"])["long"].sum()})

    out = feat.join(af, how="outer").join(df, how="outer").fillna(0.0)
    out = out.reset_index()
    return out[["src_ip", "win"] + FEATURES]
