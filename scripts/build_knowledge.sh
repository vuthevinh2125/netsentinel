#!/usr/bin/env bash
# Rebuild netsentinel/knowledge/kb.jsonl.gz from the latest MITRE ATT&CK and Sigma network rules.
set -euo pipefail
tmp=$(mktemp -d)
curl -sfL -o "$tmp/enterprise-attack.json" \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
git clone -q --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma "$tmp/sigma"
git -C "$tmp/sigma" sparse-checkout set rules/network
python -m netsentinel.knowledge.build --attack "$tmp/enterprise-attack.json" --sigma "$tmp/sigma/rules"
rm -rf "$tmp"
