#!/usr/bin/env bash
# IoT-23 for the blind test (about 260 MB).
# The official site (mcfp.felk.cvut.cz) hosts the full dataset; these are public GitHub mirrors:
#  - the first 100,000 flows of the 20 malware scenarios, as CSV (ctd2401/iot23)
#  - the complete conn.log.labeled of scenario 3-1 (ahmetnaimdemir/CTU-IoT-Malware-Capture-3-1)
# The CSV rows were checked against the original log of scenario 3-1: same flows, same labels.
set -euo pipefail
DEST=${1:-data/iot23}
mkdir -p "$DEST/CTU-IoT-Malware-Capture-3-1/data"
for n in 1 3 7 8 9 17 20 21 33 34 35 36 39 42 43 44 48 49 52 60; do
  curl -sfL "https://raw.githubusercontent.com/ctd2401/iot23/HEAD/ioT23_dataset-main/Data%20Preprocessing/df$n.csv" -o "$DEST/df$n.csv"
  echo "  df$n.csv"
done
curl -sfL "https://raw.githubusercontent.com/ahmetnaimdemir/CTU-IoT-Malware-Capture-3-1/HEAD/bro/conn.log.labeled" \
  -o "$DEST/CTU-IoT-Malware-Capture-3-1/data/conn.log.labeled"
echo "Saved to $DEST"
