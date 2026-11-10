"""Read Zeek logs (TSV with #fields header, or JSON lines), including Stratosphere's labelled variants."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd


def read_zeek(path: str | Path) -> pd.DataFrame:
    path = Path(path)
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        first = fh.readline()
    if first.lstrip().startswith("{"):
        rows = [json.loads(l) for l in path.open(encoding="utf-8", errors="replace") if l.strip()]
        return pd.DataFrame(rows)
    fields, unset, empty, sep = None, "-", "(empty)", "\t"
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.startswith("#"):
                break
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
            elif line.startswith("#unset_field"):
                unset = line.rstrip("\n").split("\t")[1]
            elif line.startswith("#empty_field"):
                empty = line.rstrip("\n").split("\t")[1]
    if fields is None:
        raise ValueError(f"{path}: no #fields header")
    with path.open(encoding="utf-8", errors="replace") as fh:
        sample = next((l for l in fh if not l.startswith("#")), "")
    src = path
    if sample and sample.count("\t") + 1 < len(fields):
        # IoT-23 writes its last three columns separated by runs of spaces instead of tabs:
        # split only the final tab-separated field, so spaces elsewhere are left alone.
        import io
        import re
        n = len(fields)
        out = []
        for line in path.open(encoding="utf-8", errors="replace"):
            if line.startswith("#"):
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) < n:
                parts = parts[:-1] + re.split(r" {2,}", parts[-1], maxsplit=n - len(parts))
            out.append("\t".join(parts[:n]))
        src = io.StringIO("\n".join(out))
    df = pd.read_csv(src, sep="\t", comment="#", names=fields, header=None, dtype=str,
                     na_values=[unset, empty], keep_default_na=False, quoting=3, engine="c")
    if "detailed-label" in df.columns and "detailedlabel" not in df.columns:
        df = df.rename(columns={"detailed-label": "detailedlabel"})
    return df
