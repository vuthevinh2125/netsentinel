#!/usr/bin/env bash
# One command: ask for a Gemini key (hidden), find a model that answers, run the triage eval.
# Usage:  bash scripts/run_triage_gemini.sh [sample_per_class] [output.json]
set -uo pipefail
SAMPLE=${1:-30}
OUT=${2:-docs/data/triage.json}
URL=https://generativelanguage.googleapis.com/v1beta/openai
cd "$(dirname "$0")/.."

if [ -z "${NETSENTINEL_OPENAI_KEY:-}" ]; then
  echo "Paste your Gemini API key (from aistudio.google.com/apikey), then press Enter."
  echo "Nothing will show while you paste: that is normal."
  read -rs NETSENTINEL_OPENAI_KEY
  echo
fi
NETSENTINEL_OPENAI_KEY=$(printf '%s' "$NETSENTINEL_OPENAI_KEY" | tr -d '[:space:]')
if [ ${#NETSENTINEL_OPENAI_KEY} -lt 20 ]; then
  echo "That key looks empty or too short (${#NETSENTINEL_OPENAI_KEY} characters). Run the script again."; exit 1
fi

echo "Looking for a model that answers..."
MODEL=""
for m in gemini-flash-latest gemini-2.5-flash gemini-3.8-flash gemini-3.7-flash gemini-3.1-flash-lite gemini-flash-lite-latest; do
  code=$(curl -s -o /tmp/ns_probe.json -m 60 -w "%{http_code}" "$URL/chat/completions" \
    -H "Authorization: Bearer $NETSENTINEL_OPENAI_KEY" -H "Content-Type: application/json" \
    -d "{\"model\":\"$m\",\"messages\":[{\"role\":\"user\",\"content\":\"Say OK\"}]}")
  printf "  %-26s HTTP %s\n" "$m" "$code"
  if [ "$code" = "200" ]; then MODEL=$m; break; fi
  if [ "$code" = "400" ] && grep -qi "api key" /tmp/ns_probe.json; then
    echo "Google says the API key is not valid. Create a new one at aistudio.google.com/apikey and run again."; exit 1
  fi
done
rm -f /tmp/ns_probe.json
[ -z "$MODEL" ] && { echo "No model answered. Send a screenshot of the lines above."; exit 1; }

echo "Using $MODEL. Each case takes about 30-90 s; the run saves after every case."
echo "If it stops, run this script again: it continues where it left off."
export NETSENTINEL_OPENAI_URL=$URL NETSENTINEL_OPENAI_KEY NETSENTINEL_MODEL=$MODEL
export NETSENTINEL_MIN_INTERVAL=${NETSENTINEL_MIN_INTERVAL:-6} NETSENTINEL_REASONING=${NETSENTINEL_REASONING:-low}
PY=python; command -v winpty >/dev/null 2>&1 && [ -t 1 ] && PY="winpty python"
$PY -m netsentinel triage-eval --analyst openai --sample "$SAMPLE" --resume --out "$OUT" ${NETSENTINEL_RAG:+--rag}
