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
    df = pd.read_csv(path, sep="\t", comment="#", names=fields, header=None, dtype=str,
                     na_values=[unset, empty], keep_default_na=False, quoting=3, engine="c")
    return df
