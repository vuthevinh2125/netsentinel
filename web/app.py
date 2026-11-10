"""Local live mode: serve the dashboard and rebuild the data for any seed.

    python web/app.py            # http://localhost:8000
    ANTHROPIC_API_KEY=... python web/app.py   # reports written by the Claude tool-use analyst

GET /api/bundle?seed=11  simulates a fresh network with that seed, runs detection and the
analyst, and returns the same JSON the static demo uses.
"""
from __future__ import annotations

import os
import sys
from functools import lru_cache
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from netsentinel.cli import build_bundle  # noqa: E402

DOCS = ROOT / "docs"
app = Flask(__name__)


@lru_cache(maxsize=8)
def bundle(seed: int) -> dict:
    return build_bundle(seed=seed, with_compare=False)


@app.get("/")
def index():
    html = (DOCS / "index.html").read_text(encoding="utf-8")
    seed = request.args.get("seed", "7")
    inject = f'<script>window.NETSENTINEL_DATA_URL = "/api/bundle?seed={int(seed)}";</script>'
    return html.replace("<script>\n(function(){", inject + "\n<script>\n(function(){", 1)


@app.get("/api/bundle")
def api_bundle():
    b = dict(bundle(int(request.args.get("seed", 7))))
    static = DOCS / "data" / "demo.json"
    if static.exists() and "compare" not in b:
        import json
        b["compare"] = json.loads(static.read_text(encoding="utf-8")).get("compare")
    return jsonify(b)


@app.get("/data/<path:name>")
def data(name):
    return send_from_directory(DOCS / "data", name)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 8000)))
