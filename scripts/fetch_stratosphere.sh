#!/usr/bin/env bash
# Download the labelled Zeek captures used by `python -m netsentinel real-eval`
# from the Stratosphere Laboratory's public repository (about 120 MB).
set -euo pipefail
REPO=stratosphereips/security-datasets-for-testing
DEST=${1:-data/stratosphere}
mkdir -p "$DEST"
tmp=$(mktemp -d)
git clone -q --depth 1 --filter=blob:none --no-checkout "https://github.com/$REPO" "$tmp/repo"
cd "$tmp/repo"
files=$(git ls-tree -r --name-only HEAD | grep -E '^0[0-9]{2}-zeek-(malicious|mixed)/(README.md|data/(conn|dns)\.log\.labeled)$')
cd - >/dev/null
for f in $files; do
  mkdir -p "$DEST/$(dirname "$f")"
  if [[ "$f" == *README.md ]]; then
    curl -sfL "https://raw.githubusercontent.com/$REPO/main/$f" -o "$DEST/$f"
  else
    curl -sfL "https://media.githubusercontent.com/media/$REPO/main/$f" -o "$DEST/$f"   # Git LFS
  fi
  echo "  $f"
done
rm -rf "$tmp"
echo "Saved to $DEST"
