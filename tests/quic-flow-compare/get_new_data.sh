#!/bin/bash
# Downloads the pcaps of a QUIC interop runner run into <dest>/<date>/.
#
#   ./get_new_data.sh [run-id|latest] [dest]
#
# WAIT_TIMEOUT (seconds, default 0): keep retrying until the run is complete.
# TESTCASES (space separated, default: all): only download these test cases,
#   e.g. "handshake retry". A full run is >20 GB, mostly transfer-like tests.
# Exits with 3 if the run is not available. Prints the target directory.
set -euo pipefail

RUN="${1:-latest}"
DEST="${2:-.}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-0}"
TESTCASES="${TESTCASES:-}"
URL="https://interop.seemann.io/logs/quic/$RUN"

# result.json only exists once a run has finished.
deadline=$(( $(date +%s) + WAIT_TIMEOUT ))
until curl -sf -o /dev/null "$URL/result.json"; do
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "run '$RUN' not available" >&2
    exit 3
  fi
  sleep 300
done

# Run ids contain ":", which breaks make, so only the date is used.
if [ "$RUN" = latest ]; then DIR="$DEST/$(date -u +%F)"; else DIR="$DEST/${RUN%%T*}"; fi
mkdir -p "$DIR"
curl -sf -o "$DIR/result.json" "$URL/result.json"

pairs=$(curl -sf "$URL/" | grep -oE 'href="\./[^"/]+_[^"/]+/"' | sed -E 's|^href="\./||; s|/"$||')
for pair in $pairs; do
  if [ -z "$TESTCASES" ]; then echo "$pair"; else for tc in $TESTCASES; do echo "$pair/$tc"; done; fi
done \
  | xargs -P 16 -I{} wget -q -nc -r -np -nH --cut-dirs=3 -P "$DIR" -A "*.pcap" "$URL/{}/" \
  || true  # single missing test cases are not fatal

[ -n "$(find "$DIR" -name '*.pcap' -print -quit)" ] || { echo "error: no pcaps downloaded" >&2; exit 1; }
echo "$DIR"
